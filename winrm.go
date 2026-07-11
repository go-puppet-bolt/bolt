// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// WinRMTransport runs actions on a Windows target over WinRM, mirroring Bolt's
// winrm transport. It speaks WS-Management (SOAP 1.2 with WS-Addressing over
// HTTP/HTTPS) driving the MS-WSMV shell protocol: Create shell → Command →
// Send (stdin) → Receive (stdout/stderr/CommandState/ExitCode) → Signal
// (terminate) → Delete shell.
//
// It honours the target's effective config.winrm block (host, port, user,
// password, ssl, ssl-verify, cacert, transport, realm, cert/key, tmpdir,
// connect-timeout, path) and implements the full [Transport] surface:
//
//   - RunCommand runs a command line through the remote shell.
//   - RunScript uploads the script to a remote temp dir, runs it (PowerShell for
//     .ps1, directly otherwise) with arguments, then removes it.
//   - RunTask uploads the task executable, feeds parameters by the task's
//     input_method (stdin JSON, PT_-prefixed shell environment, PowerShell named
//     arguments, or both), runs it, then removes it.
//   - Upload writes a local file to a destination by streaming base64 to a
//     PowerShell decoder over stdin.
//
// Authentication is selected by the transport field: "basic" sends HTTP Basic
// credentials, "negotiate" (the default) performs NTLM via the pure-Go
// github.com/Azure/go-ntlmssp round-tripper, and "ssl" uses TLS client-
// certificate authentication. Kerberos is not implemented.
//
// It is pure Go and CGO-free, so it works on every 64-bit Go target. Every code
// path is exercised in tests against an in-process WS-Management HTTP server
// (see winrmserver_test.go), so no real Windows host or network is needed.
type WinRMTransport struct {
	// NewDoer builds the HTTP client used to reach a target. It defaults to
	// [buildWinRMClient]. Tests inject a doer that reaches an in-process WS-Man
	// server (and can force connect/auth failures).
	NewDoer func(c winrmConfig) (httpDoer, error)
}

// NewWinRMTransport returns a WinRMTransport using the default HTTP client.
func NewWinRMTransport() *WinRMTransport { return &WinRMTransport{} }

// httpDoer is the seam through which the WinRM transport performs HTTP requests.
// The default implementation is an *http.Client; tests inject a fake.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func (t *WinRMTransport) newDoer(c winrmConfig) (httpDoer, error) {
	if t.NewDoer != nil {
		return t.NewDoer(c)
	}
	return buildWinRMClient(c)
}

// winrmConfig is the resolved connection configuration for one target, derived
// from its uri and effective config.winrm block.
type winrmConfig struct {
	host           string
	port           int
	user           string
	password       string
	ssl            bool
	sslVerify      bool
	caCert         string // path to a CA certificate PEM (custom trust root)
	transport      string // "negotiate" (default) | "basic" | "ssl" | "kerberos"
	realm          string // Kerberos realm (unsupported)
	clientCert     string // client certificate PEM (transport "ssl")
	clientKey      string // client private-key PEM (transport "ssl")
	connectTimeout time.Duration
	tmpdir         string
	path           string // WS-Man endpoint path (default "/wsman")
}

// resolveWinRMConfig builds a winrmConfig from a target's uri and config.winrm.
func resolveWinRMConfig(t *Target) (winrmConfig, error) {
	c := winrmConfig{
		transport:      "negotiate",
		ssl:            true,
		sslVerify:      true,
		tmpdir:         `C:\Windows\Temp`,
		path:           "/wsman",
		connectTimeout: 60 * time.Second,
	}
	c.host = hostFromURI(t.URI)
	if u := userFromURI(t.URI); u != "" {
		c.user = u
	}
	if p := portFromURI(t.URI); p != 0 {
		c.port = p
	}
	if wm, ok := asMap(effectiveConfig(t)["winrm"]); ok {
		applyWinRMConfig(&c, wm)
	}
	if c.transport == "ssl" {
		c.ssl = true
	}
	if c.host == "" {
		return c, fmt.Errorf("winrm: target %q has no host", t.Name)
	}
	if c.port == 0 {
		if c.ssl {
			c.port = 5986
		} else {
			c.port = 5985
		}
	}
	return c, nil
}

// applyWinRMConfig overlays a config.winrm mapping onto c.
func applyWinRMConfig(c *winrmConfig, wm map[string]any) {
	if v, ok := asString(wm["host"]); ok && v != "" {
		c.host = v
	}
	if p, ok := asInt(wm["port"]); ok {
		c.port = p
	}
	if v, ok := asString(wm["user"]); ok && v != "" {
		c.user = v
	}
	if v, ok := asString(wm["password"]); ok {
		c.password = v
	}
	if v, ok := asBool(wm["ssl"]); ok {
		c.ssl = v
	}
	if v, ok := asBool(wm["ssl-verify"]); ok {
		c.sslVerify = v
	}
	if v, ok := asString(wm["cacert"]); ok && v != "" {
		c.caCert = v
	}
	if v, ok := asString(wm["transport"]); ok && v != "" {
		c.transport = v
	}
	if v, ok := asString(wm["realm"]); ok {
		c.realm = v
	}
	if v, ok := asString(wm["cert"]); ok {
		c.clientCert = v
	}
	if v, ok := asString(wm["key"]); ok {
		c.clientKey = v
	}
	if v, ok := asInt(wm["connect-timeout"]); ok {
		c.connectTimeout = time.Duration(v) * time.Second
	}
	if v, ok := asString(wm["tmpdir"]); ok && v != "" {
		c.tmpdir = v
	}
	if v, ok := asString(wm["path"]); ok && v != "" {
		c.path = v
	}
}

// endpointURL builds the WS-Man endpoint URL for the target.
func (c winrmConfig) endpointURL() string {
	scheme := "http"
	if c.ssl {
		scheme = "https"
	}
	path := c.path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, c.host, c.port, path)
}

// authBasic reports whether requests carry HTTP Basic credentials. Both "basic"
// and "negotiate" set them (go-ntlmssp reads the Basic header and upgrades it to
// NTLM); "ssl" authenticates with a client certificate instead.
func (c winrmConfig) authBasic() bool {
	return c.transport == "basic" || c.transport == "negotiate"
}

// buildWinRMClient builds the default HTTP client for a resolved config.
func buildWinRMClient(c winrmConfig) (httpDoer, error) {
	switch c.transport {
	case "negotiate", "basic", "ssl":
	case "kerberos":
		return nil, fmt.Errorf("winrm: kerberos auth (realm %q) is not supported; use negotiate, basic or ssl", c.realm)
	default:
		return nil, fmt.Errorf("winrm: unknown transport %q", c.transport)
	}
	tr := &http.Transport{}
	if c.ssl {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if !c.sslVerify {
			tlsCfg.InsecureSkipVerify = true
		}
		if c.caCert != "" {
			pemBytes, err := os.ReadFile(c.caCert)
			if err != nil {
				return nil, fmt.Errorf("winrm: reading cacert %q: %w", c.caCert, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pemBytes) {
				return nil, fmt.Errorf("winrm: cacert %q contains no certificates", c.caCert)
			}
			tlsCfg.RootCAs = pool
		}
		if c.transport == "ssl" {
			if c.clientCert == "" || c.clientKey == "" {
				return nil, fmt.Errorf("winrm: transport ssl requires cert and key")
			}
			cert, err := tls.LoadX509KeyPair(c.clientCert, c.clientKey)
			if err != nil {
				return nil, fmt.Errorf("winrm: loading client certificate: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		tr.TLSClientConfig = tlsCfg
	} else if c.transport == "ssl" {
		return nil, fmt.Errorf("winrm: transport ssl requires ssl: true")
	}
	var rt http.RoundTripper = tr
	if c.transport == "negotiate" {
		rt = ntlmssp.Negotiator{RoundTripper: tr}
	}
	return &http.Client{Transport: rt, Timeout: c.connectTimeout}, nil
}

// RunCommand runs command on the target through the remote shell.
func (t *WinRMTransport) RunCommand(target *Target, command string) Result {
	return t.withShell(target, "command", command, nil, func(s *winrmSession) Result {
		stdout, stderr, code, err := s.run(command, nil, "")
		return commandResult(target, "command", command, stdout, stderr, code, err)
	})
}

// RunScript uploads the script to the remote temp dir, runs it with args, and
// removes it afterwards.
func (t *WinRMTransport) RunScript(target *Target, scriptPath string, args []string) Result {
	body, err := os.ReadFile(scriptPath)
	if err != nil {
		return Result{Target: target.Name, Action: "script", Object: scriptPath,
			Err: fmt.Errorf("winrm: reading script %q: %w", scriptPath, err)}
	}
	base := baseName(scriptPath)
	return t.withShell(target, "script", scriptPath, nil, func(s *winrmSession) Result {
		remote := winrmTempPath(s.cfg, base)
		if err := s.upload(body, remote); err != nil {
			return Result{Target: target.Name, Action: "script", Object: scriptPath, Err: err}
		}
		defer s.remove(remote)
		cmd, argv := winrmInvoke(remote, args)
		stdout, stderr, code, err := s.run(cmd, argv, "")
		return commandResult(target, "script", scriptPath, stdout, stderr, code, err)
	})
}

// RunTask uploads the task executable, feeds it parameters by its input method,
// runs it, then removes it. A JSON object printed on stdout is merged into the
// result (matching Bolt and the other transports).
func (t *WinRMTransport) RunTask(target *Target, task *Task, params map[string]any) Result {
	if task.File == "" {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q has no executable file", task.Name)}
	}
	body, err := os.ReadFile(task.File)
	if err != nil {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("winrm: reading task file %q: %w", task.File, err)}
	}
	stdin, env, taskArgs, err := winrmTaskInput(inputMethod(task), params)
	if err != nil {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q: %w", task.Name, err)}
	}
	base := baseName(task.File)
	return t.withShell(target, "task", task.Name, env, func(s *winrmSession) Result {
		remote := winrmTempPath(s.cfg, base)
		if err := s.upload(body, remote); err != nil {
			return Result{Target: target.Name, Action: "task", Object: task.Name, Err: err}
		}
		defer s.remove(remote)
		cmd, argv := winrmInvoke(remote, taskArgs)
		stdout, stderr, code, err := s.run(cmd, argv, stdin)
		res := commandResult(target, "task", task.Name, stdout, stderr, code, err)
		if res.Err == nil && stdout != "" {
			var obj map[string]any
			if json.Unmarshal([]byte(stdout), &obj) == nil {
				for k, v := range obj {
					res.Value[k] = v
				}
			}
		}
		return res
	})
}

// Upload copies the local file at src to dst on the target.
func (t *WinRMTransport) Upload(target *Target, src, dst string) Result {
	body, err := os.ReadFile(src)
	if err != nil {
		return Result{Target: target.Name, Action: "upload", Object: dst,
			Err: fmt.Errorf("winrm: reading %q: %w", src, err)}
	}
	return t.withShell(target, "upload", dst, nil, func(s *winrmSession) Result {
		if err := s.upload(body, dst); err != nil {
			return Result{Target: target.Name, Action: "upload", Object: dst, Err: err}
		}
		return Result{Target: target.Name, Action: "upload", Object: dst,
			Value: map[string]any{"_output": fmt.Sprintf("uploaded %s to %s", src, dst)}}
	})
}

// withShell resolves the target's winrm config, builds the HTTP client, opens a
// remote shell (with the given shell environment), runs fn, then deletes the
// shell. A config, client or shell-open failure yields a transport-error Result.
func (t *WinRMTransport) withShell(target *Target, action, object string, env map[string]string, fn func(*winrmSession) Result) Result {
	c, err := resolveWinRMConfig(target)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	doer, err := t.newDoer(c)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	s := &winrmSession{doer: doer, cfg: c, endpoint: c.endpointURL()}
	if err := s.openShell(env); err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	defer s.closeShell()
	return fn(s)
}

// winrmSession drives one WS-Man shell for a target.
type winrmSession struct {
	doer     httpDoer
	cfg      winrmConfig
	endpoint string
	shellID  string
}

// WS-Management / MS-WSMV constants.
const (
	nsAddressing = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
	nsShell      = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	resourceCmd  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"

	actionCreate  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
	actionDelete  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
	actionCommand = nsShell + "/Command"
	actionSend    = nsShell + "/Send"
	actionReceive = nsShell + "/Receive"
	actionSignal  = nsShell + "/Signal"
	signalTerm    = nsShell + "/signal/terminate"
)

// openShell creates the remote shell and records its ShellId.
func (s *winrmSession) openShell(env map[string]string) error {
	env2 := ""
	if len(env) > 0 {
		var b strings.Builder
		b.WriteString("<rsp:Environment>")
		for _, k := range sortedStringKeys(env) {
			fmt.Fprintf(&b, "<rsp:Variable Name=%q>%s</rsp:Variable>", k, esc(env[k]))
		}
		b.WriteString("</rsp:Environment>")
		env2 = b.String()
	}
	body := "<rsp:Shell>" + env2 +
		"<rsp:InputStreams>stdin</rsp:InputStreams>" +
		"<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>" +
		"</rsp:Shell>"
	env0, err := s.do("create", actionCreate, "", body)
	if err != nil {
		return err
	}
	id := extractShellID(env0)
	if id == "" {
		return fmt.Errorf("winrm: create: response carried no ShellId")
	}
	s.shellID = id
	return nil
}

// command starts command with args and returns its CommandId.
func (s *winrmSession) command(command string, args []string) (string, error) {
	var b strings.Builder
	b.WriteString("<rsp:CommandLine><rsp:Command>")
	b.WriteString(esc(command))
	b.WriteString("</rsp:Command>")
	for _, a := range args {
		b.WriteString("<rsp:Arguments>")
		b.WriteString(esc(a))
		b.WriteString("</rsp:Arguments>")
	}
	b.WriteString("</rsp:CommandLine>")
	env, err := s.do("command", actionCommand, s.shellID, b.String())
	if err != nil {
		return "", err
	}
	if env.Body.CommandResponse == nil || env.Body.CommandResponse.CommandID == "" {
		return "", fmt.Errorf("winrm: command: response carried no CommandId")
	}
	return env.Body.CommandResponse.CommandID, nil
}

// send writes stdin to the command's stdin stream.
func (s *winrmSession) send(cmdID, stdin string) error {
	b64 := base64.StdEncoding.EncodeToString([]byte(stdin))
	body := fmt.Sprintf(`<rsp:Send><rsp:Stream Name="stdin" CommandId=%q End="true">%s</rsp:Stream></rsp:Send>`, cmdID, b64)
	_, err := s.do("send", actionSend, s.shellID, body)
	return err
}

// receive collects the command's stdout/stderr and exit code, looping until the
// command reports Done.
func (s *winrmSession) receive(cmdID string) (string, string, int, error) {
	var stdout, stderr strings.Builder
	for {
		body := fmt.Sprintf(`<rsp:Receive><rsp:DesiredStream CommandId=%q>stdout stderr</rsp:DesiredStream></rsp:Receive>`, cmdID)
		env, err := s.do("receive", actionReceive, s.shellID, body)
		if err != nil {
			return "", "", -1, err
		}
		rr := env.Body.ReceiveResponse
		if rr == nil {
			return "", "", -1, fmt.Errorf("winrm: receive: response carried no ReceiveResponse")
		}
		for _, st := range rr.Streams {
			data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(st.Data))
			if err != nil {
				return "", "", -1, fmt.Errorf("winrm: receive: decoding %s stream: %w", st.Name, err)
			}
			if st.Name == "stderr" {
				stderr.Write(data)
			} else {
				stdout.Write(data)
			}
		}
		if strings.HasSuffix(rr.CommandState.State, "/Done") {
			code, err := strconv.Atoi(strings.TrimSpace(rr.CommandState.ExitCode))
			if err != nil {
				return "", "", -1, fmt.Errorf("winrm: receive: parsing exit code %q: %w", rr.CommandState.ExitCode, err)
			}
			return stdout.String(), stderr.String(), code, nil
		}
	}
}

// signal terminates the command (best-effort).
func (s *winrmSession) signal(cmdID string) {
	body := fmt.Sprintf(`<rsp:Signal CommandId=%q><rsp:Code>%s</rsp:Code></rsp:Signal>`, cmdID, signalTerm)
	_, _ = s.do("signal", actionSignal, s.shellID, body)
}

// closeShell deletes the remote shell (best-effort).
func (s *winrmSession) closeShell() {
	if s.shellID == "" {
		return
	}
	_, _ = s.do("delete", actionDelete, s.shellID, "")
}

// run executes command with args, feeds stdin, and returns the captured output
// with the remote exit code. A non-zero exit is not an error.
func (s *winrmSession) run(command string, args []string, stdin string) (string, string, int, error) {
	cmdID, err := s.command(command, args)
	if err != nil {
		return "", "", -1, err
	}
	if stdin != "" {
		if err := s.send(cmdID, stdin); err != nil {
			return "", "", -1, err
		}
	}
	stdout, stderr, code, err := s.receive(cmdID)
	s.signal(cmdID)
	return stdout, stderr, code, err
}

// upload writes content to dst by streaming base64 to a PowerShell decoder.
func (s *winrmSession) upload(content []byte, dst string) error {
	b64 := base64.StdEncoding.EncodeToString(content)
	ps := fmt.Sprintf(`$in=[Console]::In.ReadToEnd();[IO.File]::WriteAllBytes(%s,[Convert]::FromBase64String($in))`, psSingleQuote(dst))
	_, stderr, code, err := s.run("powershell.exe", []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps}, b64)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("winrm: writing %s: exit %d: %s", dst, code, strings.TrimSpace(stderr))
	}
	return nil
}

// remove deletes a remote file (best-effort).
func (s *winrmSession) remove(dst string) {
	_, _, _, _ = s.run("cmd.exe", []string{"/c", "del", "/f", "/q", dst}, "")
}

// do sends a SOAP request for action and returns the parsed response envelope.
func (s *winrmSession) do(step, action, shellID, body string) (*winrmEnvelope, error) {
	envelope := s.envelope(action, shellID, body)
	req, err := http.NewRequest(http.MethodPost, s.endpoint, strings.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("winrm: %s: building request: %w", step, err)
	}
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	if s.cfg.authBasic() {
		req.SetBasicAuth(s.cfg.user, s.cfg.password)
	}
	resp, err := s.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("winrm: %s: %w", step, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("winrm: %s: reading response: %w", step, err)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("winrm: %s: authentication failed (HTTP 401)", step)
	}
	var env winrmEnvelope
	perr := xml.Unmarshal(data, &env)
	if env.Body.Fault != nil {
		return nil, fmt.Errorf("winrm: %s: soap fault: %s", step, env.Body.Fault.text())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("winrm: %s: HTTP %d", step, resp.StatusCode)
	}
	if perr != nil {
		return nil, fmt.Errorf("winrm: %s: parsing response: %w", step, perr)
	}
	return &env, nil
}

// envelope wraps a body in a SOAP envelope with the WS-Man/WS-Addressing header
// for action, optionally selecting a shell.
func (s *winrmSession) envelope(action, shellID, body string) string {
	selector := ""
	if shellID != "" {
		selector = fmt.Sprintf(`<w:SelectorSet><w:Selector Name="ShellId">%s</w:Selector></w:SelectorSet>`, esc(shellID))
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"` +
		` xmlns:a="` + nsAddressing + `"` +
		` xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"` +
		` xmlns:rsp="` + nsShell + `">` +
		`<s:Header>` +
		`<a:To>` + esc(s.endpoint) + `</a:To>` +
		`<w:ResourceURI s:mustUnderstand="true">` + resourceCmd + `</w:ResourceURI>` +
		`<a:ReplyTo><a:Address s:mustUnderstand="true">` +
		`http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous` +
		`</a:Address></a:ReplyTo>` +
		`<a:Action s:mustUnderstand="true">` + action + `</a:Action>` +
		`<w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>` +
		`<a:MessageID>uuid:` + newUUID() + `</a:MessageID>` +
		`<w:Locale xml:lang="en-US" s:mustUnderstand="false"/>` +
		`<w:OperationTimeout>PT60S</w:OperationTimeout>` +
		selector +
		`</s:Header>` +
		`<s:Body>` + body + `</s:Body>` +
		`</s:Envelope>`
}

// winrmEnvelope is the parse target for a WS-Man SOAP response. Element tags use
// bare local names so they match regardless of namespace prefix.
type winrmEnvelope struct {
	XMLName xml.Name
	Body    struct {
		Fault           *winrmFault    `xml:"Fault"`
		Shell           *winrmShell    `xml:"Shell"`
		ResourceCreated *winrmCreated  `xml:"ResourceCreated"`
		CommandResponse *winrmCmdResp  `xml:"CommandResponse"`
		ReceiveResponse *winrmRecvResp `xml:"ReceiveResponse"`
	} `xml:"Body"`
}

type winrmFault struct {
	Reason struct {
		Text string `xml:"Text"`
	} `xml:"Reason"`
	Code struct {
		Subcode struct {
			Value string `xml:"Value"`
		} `xml:"Subcode"`
	} `xml:"Code"`
}

func (f *winrmFault) text() string {
	if t := strings.TrimSpace(f.Reason.Text); t != "" {
		return t
	}
	if v := strings.TrimSpace(f.Code.Subcode.Value); v != "" {
		return v
	}
	return "unknown fault"
}

type winrmShell struct {
	ShellID string `xml:"ShellId"`
}

type winrmCreated struct {
	Selectors []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"ReferenceParameters>SelectorSet>Selector"`
}

type winrmCmdResp struct {
	CommandID string `xml:"CommandId"`
}

type winrmRecvResp struct {
	Streams []struct {
		Name string `xml:"Name,attr"`
		End  string `xml:"End,attr"`
		Data string `xml:",chardata"`
	} `xml:"Stream"`
	CommandState struct {
		State    string `xml:"State,attr"`
		ExitCode string `xml:"ExitCode"`
	} `xml:"CommandState"`
}

// extractShellID pulls the ShellId out of a create response, tolerating both the
// rsp:Shell/ShellId form and a ResourceCreated selector named ShellId.
func extractShellID(env *winrmEnvelope) string {
	if env.Body.Shell != nil && env.Body.Shell.ShellID != "" {
		return strings.TrimSpace(env.Body.Shell.ShellID)
	}
	if env.Body.ResourceCreated != nil {
		for _, sel := range env.Body.ResourceCreated.Selectors {
			if sel.Name == "ShellId" {
				return strings.TrimSpace(sel.Value)
			}
		}
	}
	return ""
}

// winrmTaskInput builds the stdin payload, shell environment and command
// arguments for a task run given its input method:
//   - "environment" exports each parameter as PT_<name> in the shell environment.
//   - "powershell" passes each parameter as a named -Name Value argument.
//   - "both" exports PT_<name> and also feeds a JSON object on stdin.
//   - "stdin" (the default) feeds a JSON object on stdin.
func winrmTaskInput(method string, params map[string]any) (stdin string, env map[string]string, args []string, err error) {
	switch method {
	case "environment":
		env = ptEnv(params)
	case "both":
		env = ptEnv(params)
		if stdin, err = jsonParams(params); err != nil {
			return "", nil, nil, err
		}
	case "powershell":
		for _, k := range sortedParamKeys(params) {
			args = append(args, "-"+k, envValue(params[k]))
		}
	default: // "" or "stdin"
		if stdin, err = jsonParams(params); err != nil {
			return "", nil, nil, err
		}
	}
	return stdin, env, args, nil
}

func ptEnv(params map[string]any) map[string]string {
	env := map[string]string{}
	for k, v := range params {
		env["PT_"+k] = envValue(v)
	}
	return env
}

func jsonParams(params map[string]any) (string, error) {
	enc, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("encoding parameters: %w", err)
	}
	return string(enc), nil
}

// winrmInvoke builds the command and arguments to run a remote file: PowerShell
// for .ps1, the file directly otherwise.
func winrmInvoke(remote string, args []string) (string, []string) {
	if strings.EqualFold(winrmExt(remote), ".ps1") {
		return "powershell.exe", append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", remote}, args...)
	}
	return remote, args
}

// winrmTempPath builds a unique-enough remote path under the configured tmpdir.
func winrmTempPath(c winrmConfig, base string) string {
	dir := strings.TrimRight(c.tmpdir, `\`)
	return fmt.Sprintf(`%s\bolt_%d_%s`, dir, time.Now().UnixNano(), base)
}

// winrmExt returns the extension (including the dot) of the last element of a
// Windows or Unix path, independent of the host OS separator.
func winrmExt(p string) string {
	base := p
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndex(base, "."); i >= 0 {
		return base[i:]
	}
	return ""
}

// baseName returns the last element of a Windows or Unix path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// psSingleQuote single-quotes s for a PowerShell single-quoted string literal.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// esc XML-escapes s for use in text or double-quoted attribute content.
func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// newUUID returns a random RFC-4122 version-4 UUID string.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedParamKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
