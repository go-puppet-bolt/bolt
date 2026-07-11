// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- helpers ---

// winrmTarget builds a target whose config.winrm points at fake (plain HTTP,
// basic transport) with the given extra winrm config overlaid.
func winrmTarget(f *fakeWSMan, extra map[string]any) *Target {
	host, portStr := f.hostPort()
	port, _ := strconv.Atoi(portStr)
	wm := map[string]any{
		"host":      host,
		"port":      port,
		"ssl":       false,
		"transport": "basic",
		"user":      "u",
		"password":  "p",
	}
	for k, v := range extra {
		wm[k] = v
	}
	return &Target{Name: "win1", URI: "win1", Config: map[string]any{"winrm": wm}}
}

// doerFunc adapts a function to the httpDoer seam.
type doerFunc func(*http.Request) (*http.Response, error)

func (d doerFunc) Do(r *http.Request) (*http.Response, error) { return d(r) }

func httpResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, fmt.Errorf("read boom") }
func (errReadCloser) Close() error             { return nil }

// scriptDoer returns a canned valid response per WS-Man action, letting a test
// override a single step to inject a fault/malformed response.
type scriptDoer struct {
	on map[string]func() (*http.Response, error)
}

func (d scriptDoer) Do(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	m := actionRE.FindSubmatch(body)
	action := ""
	if m != nil {
		action = string(m[1])
	}
	if fn, ok := d.on[action]; ok {
		return fn()
	}
	return httpResp(200, cannedResponse(action)), nil
}

func cannedResponse(action string) string {
	var inner string
	switch action {
	case actionCreate:
		inner = `<rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell>`
	case actionCommand:
		inner = `<rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse>`
	case actionReceive:
		inner = fmt.Sprintf(`<rsp:ReceiveResponse><rsp:CommandState State="%s/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`, nsShell)
	default: // send, signal, delete
		inner = `<rsp:Response/>`
	}
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="%s"><s:Body>%s</s:Body></s:Envelope>`, nsShell, inner)
}

func mustResult(t *testing.T, r Result) map[string]any {
	t.Helper()
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	return r.Value
}

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// genCertKey writes a self-signed cert/key pair to temp files and returns their
// paths plus the PEM-encoded certificate.
func genCertKey(t *testing.T) (certPath, keyPath string, certPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, certPEM
}

// --- happy-path operations against the in-process WS-Man server ---

func TestWinRMRunCommand(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	tr := NewWinRMTransport()
	r := tr.RunCommand(winrmTarget(f, nil), "ipconfig")
	v := mustResult(t, r)
	if v["stdout"] != "ipconfig\n" {
		t.Fatalf("stdout = %q", v["stdout"])
	}
	if v["exit_code"] != 0 {
		t.Fatalf("exit_code = %v", v["exit_code"])
	}
	if !r.Ok() {
		t.Fatal("want Ok")
	}
}

func TestWinRMRunCommandNonZeroExit(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmd, stdin string) (string, string, int) { return "", "nope\n", 3 }
	})
	r := NewWinRMTransport().RunCommand(winrmTarget(f, nil), "badcmd")
	v := mustResult(t, r)
	if v["exit_code"] != 3 || v["stderr"] != "nope\n" {
		t.Fatalf("result = %#v", v)
	}
	if r.Ok() {
		t.Fatal("non-zero exit must not be Ok")
	}
}

func TestWinRMRunCommandNegotiate(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) { f.requireNTLM = true })
	r := NewWinRMTransport().RunCommand(winrmTarget(f, map[string]any{"transport": "negotiate"}), "whoami")
	v := mustResult(t, r)
	if v["stdout"] != "whoami\n" {
		t.Fatalf("stdout = %q", v["stdout"])
	}
}

func TestWinRMRunCommandBasicAuth(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) { f.user, f.password = "u", "p" })
	r := NewWinRMTransport().RunCommand(winrmTarget(f, nil), "hostname")
	mustResult(t, r)
}

func TestWinRMAuthFailure(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) { f.user, f.password = "real", "secret" })
	r := NewWinRMTransport().RunCommand(winrmTarget(f, nil), "hostname")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "401") {
		t.Fatalf("want 401 auth error, got %v", r.Err)
	}
}

func TestWinRMTLS(t *testing.T) {
	f := startFakeWSMan(t, true, nil)
	tgt := winrmTarget(f, map[string]any{"ssl": true, "ssl-verify": false})
	r := NewWinRMTransport().RunCommand(tgt, "dir")
	mustResult(t, r)
}

func TestWinRMTLSClientCert(t *testing.T) {
	f := startFakeWSMan(t, true, nil)
	cert, key, _ := genCertKey(t)
	tgt := winrmTarget(f, map[string]any{
		"transport": "ssl", "ssl-verify": false, "cert": cert, "key": key,
	})
	r := NewWinRMTransport().RunCommand(tgt, "dir")
	mustResult(t, r)
}

func TestWinRMTLSCACert(t *testing.T) {
	// Trust the fake TLS server through an explicit cacert file.
	f := startFakeWSMan(t, true, nil)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	caPath := writeTemp(t, "ca.pem", string(certPEM))
	tgt := winrmTarget(f, map[string]any{"ssl": true, "cacert": caPath})
	r := NewWinRMTransport().RunCommand(tgt, "dir")
	mustResult(t, r)
}

func TestWinRMRunScriptPowerShell(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmd, stdin string) (string, string, int) { return "ran\n", "", 0 }
	})
	sp := writeTemp(t, "hello.ps1", "Write-Output hi")
	r := NewWinRMTransport().RunScript(winrmTarget(f, nil), sp, []string{"a", "b"})
	mustResult(t, r)
	if !anyContains(f.allCommands, "powershell.exe -NoProfile -ExecutionPolicy Bypass -File") {
		t.Fatalf("expected powershell invocation, got %q", f.allCommands)
	}
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestWinRMRunScriptExe(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	sp := writeTemp(t, "tool.bat", "echo hi")
	r := NewWinRMTransport().RunScript(winrmTarget(f, nil), sp, []string{"x"})
	mustResult(t, r)
	if strings.Contains(f.lastCommand, "powershell") {
		t.Fatalf("non-ps1 must run directly, got %q", f.lastCommand)
	}
}

func TestWinRMRunScriptReadError(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	r := NewWinRMTransport().RunScript(winrmTarget(f, nil), "/no/such/script.ps1", nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading script") {
		t.Fatalf("want read error, got %v", r.Err)
	}
}

func TestWinRMRunTaskStdin(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmd, stdin string) (string, string, int) { return `{"result":"ok"}`, "", 0 }
	})
	tf := writeTemp(t, "task.rb", "#!/usr/bin/env ruby")
	task := &Task{Name: "t", File: tf}
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), task, map[string]any{"n": 5})
	v := mustResult(t, r)
	if v["result"] != "ok" {
		t.Fatalf("merged output missing: %#v", v)
	}
	if f.lastStdin != `{"n":5}` {
		t.Fatalf("stdin = %q", f.lastStdin)
	}
}

func TestWinRMRunTaskEnvironment(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	tf := writeTemp(t, "task.ps1", "param()")
	task := &Task{Name: "t", File: tf, Metadata: &TaskMetadata{InputMethod: "environment"}}
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), task, map[string]any{"name": "bob", "num": 2})
	mustResult(t, r)
	want := []envPair{{"PT_name", "bob"}, {"PT_num", "2"}}
	if fmt.Sprint(f.lastEnv) != fmt.Sprint(want) {
		t.Fatalf("env = %v want %v", f.lastEnv, want)
	}
}

func TestWinRMRunTaskBoth(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	tf := writeTemp(t, "task.rb", "code")
	task := &Task{Name: "t", File: tf, Metadata: &TaskMetadata{InputMethod: "both"}}
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), task, map[string]any{"k": "v"})
	mustResult(t, r)
	if f.lastStdin != `{"k":"v"}` {
		t.Fatalf("stdin = %q", f.lastStdin)
	}
	if len(f.lastEnv) != 1 || f.lastEnv[0] != (envPair{"PT_k", "v"}) {
		t.Fatalf("env = %v", f.lastEnv)
	}
}

func TestWinRMRunTaskPowerShell(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	tf := writeTemp(t, "task.ps1", "param($Name,$Num)")
	task := &Task{Name: "t", File: tf, Metadata: &TaskMetadata{InputMethod: "powershell"}}
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), task, map[string]any{"Name": "bob", "Num": 4})
	mustResult(t, r)
	var joined string
	for _, a := range f.allArgs {
		joined += strings.Join(a, " ") + "\n"
	}
	if !strings.Contains(joined, "-Name bob") || !strings.Contains(joined, "-Num 4") {
		t.Fatalf("args = %v", f.allArgs)
	}
}

func TestWinRMRunTaskNoFile(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), &Task{Name: "t"}, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no executable file") {
		t.Fatalf("want no-file error, got %v", r.Err)
	}
}

func TestWinRMRunTaskReadError(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), &Task{Name: "t", File: "/no/such/task"}, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading task file") {
		t.Fatalf("want read error, got %v", r.Err)
	}
}

func TestWinRMRunTaskEncodeError(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	tf := writeTemp(t, "task.rb", "code")
	task := &Task{Name: "t", File: tf}
	r := NewWinRMTransport().RunTask(winrmTarget(f, nil), task, map[string]any{"bad": make(chan int)})
	if r.Err == nil || !strings.Contains(r.Err.Error(), "encoding parameters") {
		t.Fatalf("want encode error, got %v", r.Err)
	}
}

func TestWinRMUpload(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	src := writeTemp(t, "src.txt", "payload-bytes")
	r := NewWinRMTransport().Upload(winrmTarget(f, nil), src, `C:\dst.txt`)
	v := mustResult(t, r)
	if !strings.Contains(fmt.Sprint(v["_output"]), "uploaded") {
		t.Fatalf("output = %#v", v)
	}
	if f.lastStdin == "" {
		t.Fatal("expected base64 payload on stdin")
	}
}

func TestWinRMUploadReadError(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	r := NewWinRMTransport().Upload(winrmTarget(f, nil), "/no/such/src", `C:\dst`)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading") {
		t.Fatalf("want read error, got %v", r.Err)
	}
}

func TestWinRMUploadWriteFailure(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.output = func(cmd, stdin string) (string, string, int) { return "", "denied\n", 1 }
	})
	src := writeTemp(t, "src.txt", "data")
	r := NewWinRMTransport().Upload(winrmTarget(f, nil), src, `C:\dst`)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "writing") {
		t.Fatalf("want write failure, got %v", r.Err)
	}
}

func TestWinRMReceiveMultipleChunks(t *testing.T) {
	f := startFakeWSMan(t, false, func(f *fakeWSMan) {
		f.receiveChunks = 3
		f.output = func(cmd, stdin string) (string, string, int) { return "abcdef", "", 0 }
	})
	r := NewWinRMTransport().RunCommand(winrmTarget(f, nil), "x")
	v := mustResult(t, r)
	if v["stdout"] != "abcdef" {
		t.Fatalf("reassembled stdout = %q", v["stdout"])
	}
}

// --- config resolution ---

func TestResolveWinRMConfig(t *testing.T) {
	t.Run("uri only, no winrm block", func(t *testing.T) {
		c, err := resolveWinRMConfig(&Target{Name: "w", URI: "winrm://admin@host.example:9999"})
		if err != nil {
			t.Fatal(err)
		}
		if c.host != "host.example" || c.user != "admin" || c.port != 9999 {
			t.Fatalf("c = %#v", c)
		}
	})
	t.Run("missing host", func(t *testing.T) {
		_, err := resolveWinRMConfig(&Target{Name: "w"})
		if err == nil || !strings.Contains(err.Error(), "no host") {
			t.Fatalf("want no-host error, got %v", err)
		}
	})
	t.Run("default port http", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "host", Config: map[string]any{
			"winrm": map[string]any{"ssl": false}}})
		if c.port != 5985 {
			t.Fatalf("port = %d", c.port)
		}
	})
	t.Run("default port https", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "host"})
		if c.port != 5986 || !c.ssl {
			t.Fatalf("c = %#v", c)
		}
	})
	t.Run("full config overlay", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "orig", Config: map[string]any{
			"winrm": map[string]any{
				"host": "h2", "port": 1234, "user": "adm", "password": "pw",
				"ssl": true, "ssl-verify": false, "cacert": "/ca", "transport": "basic",
				"realm": "R", "cert": "/c", "key": "/k", "connect-timeout": 5,
				"tmpdir": `D:\tmp`, "path": "wsman2",
			}}})
		if c.host != "h2" || c.port != 1234 || c.user != "adm" || c.password != "pw" ||
			c.sslVerify || c.caCert != "/ca" || c.realm != "R" || c.clientCert != "/c" ||
			c.clientKey != "/k" || c.connectTimeout != 5*time.Second || c.tmpdir != `D:\tmp` ||
			c.path != "wsman2" {
			t.Fatalf("c = %#v", c)
		}
	})
	t.Run("transport ssl forces ssl", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "host", Config: map[string]any{
			"winrm": map[string]any{"ssl": false, "transport": "ssl"}}})
		if !c.ssl {
			t.Fatal("transport ssl must force ssl=true")
		}
	})
}

func TestWinRMEndpointURL(t *testing.T) {
	c := winrmConfig{host: "h", port: 5985, ssl: false, path: "wsman"}
	if got := c.endpointURL(); got != "http://h:5985/wsman" {
		t.Fatalf("endpoint = %q", got)
	}
	c = winrmConfig{host: "h", port: 5986, ssl: true, path: "/wsman"}
	if got := c.endpointURL(); got != "https://h:5986/wsman" {
		t.Fatalf("endpoint = %q", got)
	}
}

// --- default HTTP client builder ---

func TestBuildWinRMClient(t *testing.T) {
	t.Run("negotiate", func(t *testing.T) {
		if _, err := buildWinRMClient(winrmConfig{transport: "negotiate"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("basic", func(t *testing.T) {
		if _, err := buildWinRMClient(winrmConfig{transport: "basic"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ssl with cert", func(t *testing.T) {
		cert, key, _ := genCertKey(t)
		_, err := buildWinRMClient(winrmConfig{transport: "ssl", ssl: true, sslVerify: false, clientCert: cert, clientKey: key})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("ssl missing cert", func(t *testing.T) {
		_, err := buildWinRMClient(winrmConfig{transport: "ssl", ssl: true})
		if err == nil || !strings.Contains(err.Error(), "requires cert and key") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("ssl bad cert file", func(t *testing.T) {
		bad := writeTemp(t, "bad.pem", "not a cert")
		_, err := buildWinRMClient(winrmConfig{transport: "ssl", ssl: true, clientCert: bad, clientKey: bad})
		if err == nil || !strings.Contains(err.Error(), "loading client certificate") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("ssl without ssl", func(t *testing.T) {
		_, err := buildWinRMClient(winrmConfig{transport: "ssl", ssl: false})
		if err == nil || !strings.Contains(err.Error(), "requires ssl: true") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("kerberos unsupported", func(t *testing.T) {
		_, err := buildWinRMClient(winrmConfig{transport: "kerberos", realm: "R"})
		if err == nil || !strings.Contains(err.Error(), "kerberos") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unknown transport", func(t *testing.T) {
		_, err := buildWinRMClient(winrmConfig{transport: "bogus"})
		if err == nil || !strings.Contains(err.Error(), "unknown transport") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cacert read error", func(t *testing.T) {
		_, err := buildWinRMClient(winrmConfig{transport: "basic", ssl: true, sslVerify: true, caCert: "/no/such/ca"})
		if err == nil || !strings.Contains(err.Error(), "reading cacert") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cacert bad pem", func(t *testing.T) {
		bad := writeTemp(t, "ca.pem", "garbage")
		_, err := buildWinRMClient(winrmConfig{transport: "basic", ssl: true, caCert: bad})
		if err == nil || !strings.Contains(err.Error(), "no certificates") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("cacert ok", func(t *testing.T) {
		_, _, certPEM := genCertKey(t)
		ca := writeTemp(t, "ca.pem", string(certPEM))
		if _, err := buildWinRMClient(winrmConfig{transport: "basic", ssl: true, caCert: ca}); err != nil {
			t.Fatal(err)
		}
	})
}

// --- NewDoer seam / error paths ---

func TestWinRMNewDoerError(t *testing.T) {
	tr := &WinRMTransport{NewDoer: func(winrmConfig) (httpDoer, error) {
		return nil, fmt.Errorf("build boom")
	}}
	r := tr.RunCommand(&Target{Name: "w", URI: "host"}, "x")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "build boom") {
		t.Fatalf("want build error, got %v", r.Err)
	}
}

func TestWinRMConfigError(t *testing.T) {
	r := NewWinRMTransport().RunCommand(&Target{Name: "w"}, "x")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no host") {
		t.Fatalf("want config error, got %v", r.Err)
	}
}

func TestWinRMConnectError(t *testing.T) {
	tr := &WinRMTransport{NewDoer: func(winrmConfig) (httpDoer, error) {
		return doerFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial refused")
		}), nil
	}}
	r := tr.RunCommand(&Target{Name: "w", URI: "host"}, "x")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "dial refused") {
		t.Fatalf("want connect error, got %v", r.Err)
	}
}

func TestWinRMBodyReadError(t *testing.T) {
	tr := &WinRMTransport{NewDoer: func(winrmConfig) (httpDoer, error) {
		return doerFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: errReadCloser{}, Header: http.Header{}}, nil
		}), nil
	}}
	r := tr.RunCommand(&Target{Name: "w", URI: "host"}, "x")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading response") {
		t.Fatalf("want read error, got %v", r.Err)
	}
}

// stepTransport runs one command through a scriptDoer with the given overrides.
func stepTransport(on map[string]func() (*http.Response, error)) *WinRMTransport {
	return &WinRMTransport{NewDoer: func(winrmConfig) (httpDoer, error) {
		return scriptDoer{on: on}, nil
	}}
}

func override(status int, body string) func() (*http.Response, error) {
	return func() (*http.Response, error) { return httpResp(status, body), nil }
}

func envBody(inner string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="%s"><s:Body>%s</s:Body></s:Envelope>`, nsShell, inner)
}

func faultBody(inner string) string {
	return fmt.Sprintf(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>%s</s:Body></s:Envelope>`, inner)
}

func runStepCmd(t *testing.T, tr *WinRMTransport) Result {
	t.Helper()
	return tr.RunCommand(&Target{Name: "w", URI: "host", Config: map[string]any{
		"winrm": map[string]any{"transport": "basic", "ssl": false}}}, "x")
}

func TestWinRMShellNoShellID(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(200, envBody(`<rsp:Shell></rsp:Shell>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no ShellId") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMShellIDFromSelector(t *testing.T) {
	created := envBody(`<x:ResourceCreated xmlns:x="urn"><a:ReferenceParameters xmlns:a="urn"><w:SelectorSet xmlns:w="urn"><w:Selector Name="ShellId">S9</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated>`)
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(200, created),
	})
	r := runStepCmd(t, tr)
	mustResult(t, r)
}

func TestWinRMCommandNoID(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCommand: override(200, envBody(`<rsp:CommandResponse></rsp:CommandResponse>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no CommandId") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMReceiveNoResponse(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionReceive: override(200, envBody(`<rsp:Nothing/>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no ReceiveResponse") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMReceiveBadBase64(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionReceive: override(200, envBody(fmt.Sprintf(
			`<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="C1">!!!not-base64!!!</rsp:Stream><rsp:CommandState State="%s/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`, nsShell))),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "decoding") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMReceiveBadExitCode(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionReceive: override(200, envBody(fmt.Sprintf(
			`<rsp:ReceiveResponse><rsp:CommandState State="%s/CommandState/Done"><rsp:ExitCode>notanumber</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`, nsShell))),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "parsing exit code") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMFaultWithReason(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(500, faultBody(`<s:Fault><s:Reason><s:Text>access denied</s:Text></s:Reason></s:Fault>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "access denied") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMFaultSubcodeFallback(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(500, faultBody(`<s:Fault><s:Code><s:Subcode><s:Value>w:AccessDenied</s:Value></s:Subcode></s:Code></s:Fault>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "w:AccessDenied") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMFaultUnknown(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(500, faultBody(`<s:Fault></s:Fault>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "unknown fault") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMHTTPErrorNoFault(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(503, envBody(`<rsp:Nothing/>`)),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "HTTP 503") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMParseError(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){
		actionCreate: override(200, "<<< not xml >>>"),
	})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "parsing response") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMRequestBuildError(t *testing.T) {
	s := &winrmSession{
		doer:     doerFunc(func(*http.Request) (*http.Response, error) { return httpResp(200, ""), nil }),
		cfg:      winrmConfig{transport: "basic"},
		endpoint: "http://bad\x7fhost/wsman",
	}
	if err := s.openShell(nil); err == nil || !strings.Contains(err.Error(), "building request") {
		t.Fatalf("want build-request error, got %v", err)
	}
}

// --- small pure helpers ---

func TestWinRMHelpers(t *testing.T) {
	if winrmExt(`C:\a\b.PS1`) != ".PS1" {
		t.Fatalf("winrmExt = %q", winrmExt(`C:\a\b.PS1`))
	}
	if winrmExt(`C:\a\noext`) != "" {
		t.Fatalf("winrmExt noext = %q", winrmExt(`C:\a\noext`))
	}
	if baseName(`C:\a\b.txt`) != "b.txt" || baseName("plain") != "plain" {
		t.Fatal("baseName")
	}
	if psSingleQuote(`a'b`) != `'a''b'` {
		t.Fatalf("psSingleQuote = %q", psSingleQuote(`a'b`))
	}
	if esc("<a&b>") != "&lt;a&amp;b&gt;" {
		t.Fatalf("esc = %q", esc("<a&b>"))
	}
	if u := newUUID(); len(u) != 36 {
		t.Fatalf("uuid = %q", u)
	}
	c := winrmConfig{tmpdir: `C:\Temp\`}
	if p := winrmTempPath(c, "x.ps1"); !strings.HasPrefix(p, `C:\Temp\bolt_`) || !strings.HasSuffix(p, "x.ps1") {
		t.Fatalf("tempPath = %q", p)
	}
}

func stepErr() func() (*http.Response, error) {
	return func() (*http.Response, error) { return nil, fmt.Errorf("step boom") }
}

func TestWinRMCommandStepError(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){actionCommand: stepErr()})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "step boom") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMReceiveStepError(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){actionReceive: stepErr()})
	r := runStepCmd(t, tr)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "step boom") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMSendStepError(t *testing.T) {
	// Upload streams stdin, so a Send failure surfaces through run -> upload.
	tr := stepTransport(map[string]func() (*http.Response, error){actionSend: stepErr()})
	src := writeTemp(t, "src.txt", "data")
	r := tr.Upload(&Target{Name: "w", URI: "host", Config: map[string]any{
		"winrm": map[string]any{"transport": "basic", "ssl": false}}}, src, `C:\dst`)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "step boom") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMRunScriptUploadError(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){actionCommand: stepErr()})
	sp := writeTemp(t, "s.ps1", "x")
	r := tr.RunScript(&Target{Name: "w", URI: "host", Config: map[string]any{
		"winrm": map[string]any{"transport": "basic", "ssl": false}}}, sp, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "step boom") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMRunTaskUploadError(t *testing.T) {
	tr := stepTransport(map[string]func() (*http.Response, error){actionCommand: stepErr()})
	tf := writeTemp(t, "task.rb", "x")
	r := tr.RunTask(&Target{Name: "w", URI: "host", Config: map[string]any{
		"winrm": map[string]any{"transport": "basic", "ssl": false}}}, &Task{Name: "t", File: tf}, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "step boom") {
		t.Fatalf("got %v", r.Err)
	}
}

func TestWinRMTaskInputBothEncodeError(t *testing.T) {
	_, _, _, err := winrmTaskInput("both", map[string]any{"bad": make(chan int)})
	if err == nil || !strings.Contains(err.Error(), "encoding parameters") {
		t.Fatalf("got %v", err)
	}
}

func TestWinRMCloseShellNoop(t *testing.T) {
	(&winrmSession{}).closeShell() // empty ShellId is a no-op
}

func TestWinRMImplementsTransport(t *testing.T) {
	var _ Transport = NewWinRMTransport()
}
