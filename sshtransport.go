// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	remoteexec "github.com/go-remoteexec/transport"
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
// The connection itself (dial, auth, host-key verification, exec/upload wire
// protocol, sudo/su/doas escalation) is github.com/go-remoteexec/transport,
// shared with go-ansible; this file only resolves Bolt's own config shape and
// layers Bolt's task-input-method conventions on top.
type SSHTransport struct {
	// Dialer establishes the transport-level connection. It defaults to a
	// net.Dialer honouring the target's connect-timeout. Tests inject a dialer
	// that reaches an in-process server (and can force connect failures).
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	// KnownHostsFile is consulted when a target enables host-key-check. Empty
	// means host-key-check requires an explicit known-hosts path in config.
	KnownHostsFile string
}

// NewSSHTransport returns an SSHTransport using a real TCP dialer.
func NewSSHTransport() *SSHTransport { return &SSHTransport{} }

// sshRunAs is the resolved run-as/escalation portion of a target's ssh
// config — kept separate from [remoteexec.SSHConfig] because escalation
// is a decorator ([remoteexec.Become]) applied over a connection, not a
// dial-time setting.
type sshRunAs struct {
	user     string
	password string
}

// resolveSSHConfig builds a [remoteexec.SSHConfig] (plus any run-as
// config) from a target's uri and effective config.ssh.
func resolveSSHConfig(t *Target, knownHostsFallback string) (remoteexec.SSHConfig, sshRunAs, error) {
	c := remoteexec.SSHConfig{
		Port: 22, User: "root", TempDir: "/tmp", Timeout: 10 * time.Second,
	}
	var runAs sshRunAs

	c.Host = hostFromURI(t.URI)
	if u := userFromURI(t.URI); u != "" {
		c.User = u
	}
	if p := portFromURI(t.URI); p != 0 {
		c.Port = p
	}
	ssh, _ := asMap(effectiveConfig(t)["ssh"])
	if ssh == nil {
		if c.Host == "" {
			return c, runAs, fmt.Errorf("ssh: target %q has no host", t.Name)
		}
		return c, runAs, nil
	}
	if v, ok := asString(ssh["host"]); ok && v != "" {
		c.Host = v
	}
	if p, ok := asInt(ssh["port"]); ok {
		c.Port = p
	}
	if v, ok := asString(ssh["user"]); ok && v != "" {
		c.User = v
	}
	if v, ok := asString(ssh["password"]); ok {
		c.Password = v
	}
	if v, ok := asString(ssh["private-key"]); ok && v != "" {
		key, err := os.ReadFile(v)
		if err != nil {
			return c, runAs, fmt.Errorf("ssh: reading private-key %q: %w", v, err)
		}
		c.PrivateKeyBytes = key
	}
	if km, ok := asMap(ssh["private-key"]); ok {
		if data, ok := asString(km["key-data"]); ok {
			c.PrivateKeyBytes = []byte(data)
		}
	}
	if v, ok := asString(ssh["passphrase"]); ok {
		c.PrivateKeyPassphrase = v
	}
	// host-key-check defaults to false (Bolt's own default for the ssh
	// transport when no known_hosts management is configured).
	if v, ok := ssh["host-key-check"].(bool); ok {
		c.HostKeyCheck = v
	}
	if v, ok := asString(ssh["known-hosts"]); ok && v != "" {
		c.KnownHostsFile = v
	} else {
		c.KnownHostsFile = knownHostsFallback
	}
	if v, ok := asString(ssh["run-as"]); ok {
		runAs.user = v
	}
	if v, ok := asString(ssh["sudo-password"]); ok {
		runAs.password = v
	}
	if v, ok := ssh["tty"].(bool); ok {
		c.TTY = v
	}
	if v, ok := asString(ssh["tmpdir"]); ok && v != "" {
		c.TempDir = v
	}
	if v, ok := asInt(ssh["connect-timeout"]); ok {
		c.Timeout = time.Duration(v) * time.Second
	}
	if c.Host == "" {
		return c, runAs, fmt.Errorf("ssh: target %q has no host", t.Name)
	}
	// The shared transport silently falls back to ~/.ssh/known_hosts
	// when host-key-check is on but no path was given (matching plain
	// ssh/scp); Bolt requires an explicit path instead, so callers never
	// unknowingly verify against the invoking user's own known_hosts.
	if c.HostKeyCheck && c.KnownHostsFile == "" {
		return c, runAs, fmt.Errorf("ssh: target %q: host-key-check is enabled but no known-hosts file is configured", t.Name)
	}
	return c, runAs, nil
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

// dial resolves target's config and opens a connection, wrapping it in
// [remoteexec.Become] when run-as is configured.
func (s *SSHTransport) dial(ctx context.Context, target *Target) (remoteexec.Connection, error) {
	cfg, runAs, err := resolveSSHConfig(target, s.KnownHostsFile)
	if err != nil {
		return nil, err
	}
	if s.Dialer != nil {
		cfg.Dialer = s.Dialer
	}
	conn, err := remoteexec.DialSSH(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if runAs.user == "" {
		return conn, nil
	}
	return remoteexec.Become(conn, remoteexec.BecomeConfig{
		Method: remoteexec.BecomeSudo, User: runAs.user, Password: runAs.password,
	}), nil
}

// RunCommand runs command on the target through its login shell.
func (s *SSHTransport) RunCommand(target *Target, command string) Result {
	return s.withConn(target, "command", command, func(conn remoteexec.Connection) Result {
		res, err := conn.Exec(context.Background(), command, nil)
		return fromRemoteResult(target, "command", command, res, err)
	})
}

// RunScript uploads the script to the remote temp dir, executes it with args,
// and removes it afterwards.
func (s *SSHTransport) RunScript(target *Target, scriptPath string, args []string) Result {
	return s.withConn(target, "script", scriptPath, func(conn remoteexec.Connection) Result {
		remote := conn.TempPath(filepath.Base(scriptPath))
		if err := conn.Put(context.Background(), scriptPath, remote, remoteexec.PutOptions{Executable: true, MkdirParents: true}); err != nil {
			return Result{Target: target.Name, Action: "script", Object: scriptPath, Err: err}
		}
		defer conn.Remove(context.Background(), remote)
		cmd := shellJoin(append([]string{remote}, args...))
		res, err := conn.Exec(context.Background(), cmd, nil)
		return fromRemoteResult(target, "script", scriptPath, res, err)
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
	method := inputMethod(task)
	stdin, env, err := taskInput(method, params)
	if err != nil {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q: %w", task.Name, err)}
	}
	return s.withConn(target, "task", task.Name, func(conn remoteexec.Connection) Result {
		remote := conn.TempPath(filepath.Base(task.File))
		if err := conn.Put(context.Background(), task.File, remote, remoteexec.PutOptions{Executable: true, MkdirParents: true}); err != nil {
			return Result{Target: target.Name, Action: "task", Object: task.Name, Err: err}
		}
		defer conn.Remove(context.Background(), remote)
		cmd := envPrefix(env) + shellQuote(remote)
		res, err := conn.Exec(context.Background(), cmd, strings.NewReader(stdin))
		result := fromRemoteResult(target, "task", task.Name, res, err)
		if result.Err == nil && result.Value["stdout"] != "" {
			var obj map[string]any
			if json.Unmarshal([]byte(result.Value["stdout"].(string)), &obj) == nil {
				for k, v := range obj {
					result.Value[k] = v
				}
			}
		}
		return result
	})
}

// Upload copies the local file at src to dst on the target.
func (s *SSHTransport) Upload(target *Target, src, dst string) Result {
	return s.withConn(target, "upload", dst, func(conn remoteexec.Connection) Result {
		if _, err := os.Stat(src); err != nil {
			return Result{Target: target.Name, Action: "upload", Object: dst,
				Err: fmt.Errorf("ssh: reading %q: %w", src, err)}
		}
		if err := conn.Put(context.Background(), src, dst, remoteexec.PutOptions{MkdirParents: true}); err != nil {
			return Result{Target: target.Name, Action: "upload", Object: dst, Err: err}
		}
		return Result{Target: target.Name, Action: "upload", Object: dst,
			Value: map[string]any{"_output": fmt.Sprintf("uploaded %s to %s", src, dst)}}
	})
}

// withConn resolves the target, dials (with run-as applied), runs fn, and
// closes the connection, returning a transport-error Result if resolution or
// dial fails.
func (s *SSHTransport) withConn(target *Target, action, object string, fn func(remoteexec.Connection) Result) Result {
	conn, err := s.dial(context.Background(), target)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	defer conn.Close()
	return fn(conn)
}

// fromRemoteResult builds a [Result] from a [remoteexec.Connection] exec
// outcome, matching the shape [commandResult] has always produced.
func fromRemoteResult(target *Target, action, object string, res remoteexec.Result, err error) Result {
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	return Result{
		Target: target.Name,
		Action: action,
		Object: object,
		Value: map[string]any{
			"stdout":    res.Stdout,
			"stderr":    res.Stderr,
			"exit_code": res.RC,
		},
	}
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
