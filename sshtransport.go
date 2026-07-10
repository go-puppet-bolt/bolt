// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// SSHTransport runs actions on a target over SSH, mirroring Bolt's ssh
// transport. It honours the target's effective `config.ssh` block (user, port,
// private-key/password, host-key-check, run-as/sudo, tty, tmpdir, connect
// timeout) and implements the full [Transport] surface:
//
//   - RunCommand runs a command through the login shell.
//   - RunScript uploads the script to a remote temp dir, makes it executable,
//     runs it with arguments, then removes it.
//   - RunTask uploads the task executable, feeds parameters by the task's
//     input_method (stdin JSON, PT_-prefixed environment, PowerShell, or both),
//     runs it, then removes it.
//   - Upload copies a local file to a destination via a stdin-streamed write.
//
// It is pure Go (golang.org/x/crypto/ssh) and CGO-free, so it works on every
// 64-bit Go target. Every code path is exercised in tests against an in-process
// SSH server (see sshtransport_test.go), so no real host or network is needed.
type SSHTransport struct {
	// Dialer establishes the transport-level connection. It defaults to a
	// net.Dialer honouring the target's connect-timeout. Tests inject a dialer
	// that reaches an in-process server (and can force connect failures).
	Dialer func(network, addr string, timeout time.Duration) (net.Conn, error)
	// KnownHostsFile is consulted when a target enables host-key-check. Empty
	// means host-key-check requires an explicit known-hosts path in config.
	KnownHostsFile string
}

// NewSSHTransport returns an SSHTransport using a real TCP dialer.
func NewSSHTransport() *SSHTransport { return &SSHTransport{} }

// sshConfig is the resolved connection configuration for one target, derived
// from its uri and effective config.ssh block.
type sshConfig struct {
	host           string
	port           int
	user           string
	password       string
	privateKey     []byte
	passphrase     string
	hostKeyCheck   bool
	knownHostsFile string
	runAs          string
	sudoPassword   string
	tty            bool
	tmpdir         string
	connectTimeout time.Duration
}

// resolveSSHConfig builds an sshConfig from a target's uri and config.ssh.
func resolveSSHConfig(t *Target, knownHostsFallback string) (sshConfig, error) {
	c := sshConfig{port: 22, user: "root", tmpdir: "/tmp", connectTimeout: 10 * time.Second}
	c.host = hostFromURI(t.URI)
	if u := userFromURI(t.URI); u != "" {
		c.user = u
	}
	if p := portFromURI(t.URI); p != 0 {
		c.port = p
	}
	ssh, _ := asMap(effectiveConfig(t)["ssh"])
	if ssh == nil {
		if c.host == "" {
			return c, fmt.Errorf("ssh: target %q has no host", t.Name)
		}
		return c, nil
	}
	if v, ok := asString(ssh["host"]); ok && v != "" {
		c.host = v
	}
	if p, ok := asInt(ssh["port"]); ok {
		c.port = p
	}
	if v, ok := asString(ssh["user"]); ok && v != "" {
		c.user = v
	}
	if v, ok := asString(ssh["password"]); ok {
		c.password = v
	}
	if v, ok := asString(ssh["private-key"]); ok && v != "" {
		key, err := os.ReadFile(v)
		if err != nil {
			return c, fmt.Errorf("ssh: reading private-key %q: %w", v, err)
		}
		c.privateKey = key
	}
	if km, ok := asMap(ssh["private-key"]); ok {
		if data, ok := asString(km["key-data"]); ok {
			c.privateKey = []byte(data)
		}
	}
	if v, ok := asString(ssh["passphrase"]); ok {
		c.passphrase = v
	}
	// host-key-check defaults to false (Bolt's own default for the ssh
	// transport when no known_hosts management is configured).
	if v, ok := ssh["host-key-check"].(bool); ok {
		c.hostKeyCheck = v
	}
	if v, ok := asString(ssh["known-hosts"]); ok && v != "" {
		c.knownHostsFile = v
	} else {
		c.knownHostsFile = knownHostsFallback
	}
	if v, ok := asString(ssh["run-as"]); ok {
		c.runAs = v
	}
	if v, ok := asString(ssh["sudo-password"]); ok {
		c.sudoPassword = v
	}
	if v, ok := ssh["tty"].(bool); ok {
		c.tty = v
	}
	if v, ok := asString(ssh["tmpdir"]); ok && v != "" {
		c.tmpdir = v
	}
	if v, ok := asInt(ssh["connect-timeout"]); ok {
		c.connectTimeout = time.Duration(v) * time.Second
	}
	if c.host == "" {
		return c, fmt.Errorf("ssh: target %q has no host", t.Name)
	}
	return c, nil
}

// effectiveConfig returns a target's effective config, tolerating a target that
// is not attached to any inventory.
func effectiveConfig(t *Target) map[string]any {
	if t.inv != nil {
		return t.EffectiveConfig()
	}
	if t.Config != nil {
		return t.Config
	}
	return map[string]any{}
}

func hostFromURI(uri string) string {
	h, _, _ := splitURI(uri)
	return h
}

func userFromURI(uri string) string {
	if u, err := url.Parse(withScheme(uri)); err == nil && u.User != nil {
		return u.User.Username()
	}
	return ""
}

func portFromURI(uri string) int {
	_, p, _ := splitURI(uri)
	return p
}

// splitURI extracts host and port from a target uri, which may or may not carry
// an ssh:// scheme and user info.
func splitURI(uri string) (host string, port int, ok bool) {
	u, err := url.Parse(withScheme(uri))
	if err != nil || u.Host == "" {
		return "", 0, false
	}
	host = u.Hostname()
	if ps := u.Port(); ps != "" {
		if p, err := strconv.Atoi(ps); err == nil {
			port = p
		}
	}
	return host, port, true
}

func withScheme(uri string) string {
	if strings.Contains(uri, "://") {
		return uri
	}
	return "ssh://" + uri
}

// dial opens an ssh.Client to the configured target.
func (s *SSHTransport) dial(c sshConfig) (*ssh.Client, error) {
	auth, err := sshAuthMethods(c)
	if err != nil {
		return nil, err
	}
	hkc, err := s.hostKeyCallback(c)
	if err != nil {
		return nil, err
	}
	cc := &ssh.ClientConfig{
		User:            c.user,
		Auth:            auth,
		HostKeyCallback: hkc,
		Timeout:         c.connectTimeout,
	}
	addr := net.JoinHostPort(c.host, strconv.Itoa(c.port))
	conn, err := s.dialer()("tcp", addr, c.connectTimeout)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cc)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh: handshake %s: %w", addr, err)
	}
	return ssh.NewClient(sc, chans, reqs), nil
}

func (s *SSHTransport) dialer() func(string, string, time.Duration) (net.Conn, error) {
	if s.Dialer != nil {
		return s.Dialer
	}
	return func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(network, addr, timeout)
	}
}

func sshAuthMethods(c sshConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if len(c.privateKey) > 0 {
		var (
			signer ssh.Signer
			err    error
		)
		if c.passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(c.privateKey, []byte(c.passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(c.privateKey)
		}
		if err != nil {
			return nil, fmt.Errorf("ssh: parsing private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if c.password != "" {
		methods = append(methods, ssh.Password(c.password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("ssh: no authentication configured (need private-key or password)")
	}
	return methods, nil
}

func (s *SSHTransport) hostKeyCallback(c sshConfig) (ssh.HostKeyCallback, error) {
	if !c.hostKeyCheck {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	if c.knownHostsFile == "" {
		return nil, fmt.Errorf("ssh: host-key-check enabled but no known-hosts file configured")
	}
	cb, err := knownhosts.New(c.knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("ssh: loading known-hosts %q: %w", c.knownHostsFile, err)
	}
	return cb, nil
}

// RunCommand runs command on the target through its login shell.
func (s *SSHTransport) RunCommand(target *Target, command string) Result {
	return s.withClient(target, "command", command, func(client *ssh.Client, c sshConfig) Result {
		stdout, stderr, code, err := runAsRemote(client, c, command, "")
		return commandResult(target, "command", command, stdout, stderr, code, err)
	})
}

// RunScript uploads the script to the remote temp dir, executes it with args,
// and removes it afterwards.
func (s *SSHTransport) RunScript(target *Target, scriptPath string, args []string) Result {
	body, err := os.ReadFile(scriptPath)
	if err != nil {
		return Result{Target: target.Name, Action: "script", Object: scriptPath,
			Err: fmt.Errorf("ssh: reading script %q: %w", scriptPath, err)}
	}
	return s.withClient(target, "script", scriptPath, func(client *ssh.Client, c sshConfig) Result {
		remote := remoteTempPath(c, filepath.Base(scriptPath))
		if err := uploadBytes(client, c, body, remote, true); err != nil {
			return Result{Target: target.Name, Action: "script", Object: scriptPath, Err: err}
		}
		defer removeRemote(client, c, remote)
		cmd := shellJoin(append([]string{remote}, args...))
		stdout, stderr, code, err := runAsRemote(client, c, cmd, "")
		return commandResult(target, "script", scriptPath, stdout, stderr, code, err)
	})
}

// RunTask uploads the task executable, feeds it parameters by its input method,
// runs it, then removes it. A JSON object printed on stdout is merged into the
// result (matching Bolt and [LocalTransport.RunTask]).
func (s *SSHTransport) RunTask(target *Target, task *Task, params map[string]any) Result {
	if task.File == "" {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q has no executable file", task.Name)}
	}
	body, err := os.ReadFile(task.File)
	if err != nil {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("ssh: reading task file %q: %w", task.File, err)}
	}
	method := inputMethod(task)
	stdin, env, err := taskInput(method, params)
	if err != nil {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q: %w", task.Name, err)}
	}
	return s.withClient(target, "task", task.Name, func(client *ssh.Client, c sshConfig) Result {
		remote := remoteTempPath(c, filepath.Base(task.File))
		if err := uploadBytes(client, c, body, remote, true); err != nil {
			return Result{Target: target.Name, Action: "task", Object: task.Name, Err: err}
		}
		defer removeRemote(client, c, remote)
		cmd := envPrefix(env) + shellQuote(remote)
		stdout, stderr, code, err := runAsRemote(client, c, cmd, stdin)
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
func (s *SSHTransport) Upload(target *Target, src, dst string) Result {
	body, err := os.ReadFile(src)
	if err != nil {
		return Result{Target: target.Name, Action: "upload", Object: dst,
			Err: fmt.Errorf("ssh: reading %q: %w", src, err)}
	}
	return s.withClient(target, "upload", dst, func(client *ssh.Client, c sshConfig) Result {
		if err := uploadBytes(client, c, body, dst, false); err != nil {
			return Result{Target: target.Name, Action: "upload", Object: dst, Err: err}
		}
		return Result{Target: target.Name, Action: "upload", Object: dst,
			Value: map[string]any{"_output": fmt.Sprintf("uploaded %s to %s", src, dst)}}
	})
}

// withClient resolves the target's ssh config, dials, and runs fn with the open
// client, returning a transport-error Result if config or dial fails.
func (s *SSHTransport) withClient(target *Target, action, object string, fn func(*ssh.Client, sshConfig) Result) Result {
	c, err := resolveSSHConfig(target, s.KnownHostsFile)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	client, err := s.dial(c)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	defer client.Close()
	return fn(client, c)
}

// runRemote runs command on client, feeding stdin, and returns captured output
// with the remote exit status. A non-zero exit is not an error; err is only for
// failures to establish the session or run the command at all.
func runRemote(client *ssh.Client, c sshConfig, command, stdin string) (string, string, int, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", "", -1, fmt.Errorf("ssh: new session: %w", err)
	}
	defer sess.Close()
	if c.tty {
		// Best-effort PTY; a server that refuses it must not fail the command.
		_ = sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{})
	}
	var out, errBuf strings.Builder
	sess.Stdout = &out
	sess.Stderr = &errBuf
	sess.Stdin = strings.NewReader(stdin)
	err = sess.Run(command)
	if err == nil {
		return out.String(), errBuf.String(), 0, nil
	}
	if ee, ok := err.(*ssh.ExitError); ok {
		return out.String(), errBuf.String(), ee.ExitStatus(), nil
	}
	return out.String(), errBuf.String(), -1, fmt.Errorf("ssh: running command: %w", err)
}

// execCheck runs cmd (feeding stdin) and turns both a transport error and a
// non-zero exit into a single descriptive error.
func execCheck(client *ssh.Client, c sshConfig, cmd, stdin, desc string) error {
	_, stderr, code, err := runRemote(client, c, cmd, stdin)
	if err != nil {
		return fmt.Errorf("ssh: %s: %w", desc, err)
	}
	if code != 0 {
		return fmt.Errorf("ssh: %s: exit %d: %s", desc, code, stderr)
	}
	return nil
}

// uploadBytes writes body to the remote path dst by streaming it to a
// `cat > dst` sink over an exec session, optionally chmod +x afterwards.
func uploadBytes(client *ssh.Client, c sshConfig, body []byte, dst string, executable bool) error {
	if base := path.Dir(dst); base != "." && base != "/" {
		if err := execCheck(client, c, "mkdir -p "+shellQuote(base), "", "preparing "+base); err != nil {
			return err
		}
	}
	if err := execCheck(client, c, "cat > "+shellQuote(dst), string(body), "uploading to "+dst); err != nil {
		return err
	}
	if executable {
		if err := execCheck(client, c, "chmod +x "+shellQuote(dst), "", "chmod "+dst); err != nil {
			return err
		}
	}
	return nil
}

func removeRemote(client *ssh.Client, c sshConfig, dst string) {
	_, _, _, _ = runRemote(client, c, "rm -f "+shellQuote(dst), "")
}

// remoteTempPath builds a unique-enough remote path under the configured tmpdir.
func remoteTempPath(c sshConfig, base string) string {
	return path.Join(c.tmpdir, fmt.Sprintf("bolt_%d_%s", time.Now().UnixNano(), base))
}

// runAsRemote runs command, applying run-as (sudo) escalation when configured.
// When a sudo-password is set the password is prepended to stdin so `sudo -S`
// can read it before the command's own input (Bolt's behaviour).
func runAsRemote(client *ssh.Client, c sshConfig, command, stdin string) (string, string, int, error) {
	if c.runAs == "" {
		return runRemote(client, c, command, stdin)
	}
	flag := "-H"
	if c.sudoPassword != "" {
		flag = "-S -H"
		stdin = c.sudoPassword + "\n" + stdin
	}
	wrapped := fmt.Sprintf("sudo %s -u %s sh -c %s", flag, shellQuote(c.runAs), shellQuote(command))
	return runRemote(client, c, wrapped, stdin)
}

// taskInput builds the stdin payload and environment for a task run given its
// input method: "stdin" (default) feeds a JSON object; "environment" exports
// each parameter as PT_<name>; "both" does both; "powershell" is treated as
// stdin JSON (the pure-Go transport does not synthesise a PowerShell wrapper).
func taskInput(method string, params map[string]any) (stdin string, env map[string]string, err error) {
	wantStdin := method == "" || method == "stdin" || method == "both" || method == "powershell"
	wantEnv := method == "environment" || method == "both"
	if wantStdin {
		enc, e := json.Marshal(params)
		if e != nil {
			return "", nil, fmt.Errorf("encoding parameters: %w", e)
		}
		stdin = string(enc)
	}
	if wantEnv {
		env = map[string]string{}
		for k, v := range params {
			env["PT_"+k] = envValue(v)
		}
	}
	return stdin, env, nil
}

// envValue renders a task parameter for an environment variable: strings pass
// through, everything else is JSON-encoded (Bolt's behaviour).
func envValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	enc, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(enc)
}

// envPrefix renders an environment map as a deterministic `env K=V ...` prefix.
func envPrefix(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("env ")
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(shellQuote(env[k]))
		b.WriteByte(' ')
	}
	return b.String()
}

// shellJoin quotes and joins argv into a single shell word list.
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = shellQuote(a)
	}
	return strings.Join(out, " ")
}

// shellQuote single-quotes s for POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
