// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	remoteexec "github.com/go-remoteexec/transport"
)

// WinRMTransport runs actions on a Windows target over WinRM, mirroring Bolt's
// winrm transport. It honours the target's effective config.winrm block (host,
// port, user, password, ssl, ssl-verify, cacert, transport, realm, cert/key,
// tmpdir, connect-timeout, path) and implements the full [Transport] surface:
//
//   - RunCommand runs a command line through the remote shell.
//   - RunScript uploads the script to a remote temp dir, runs it (PowerShell for
//     .ps1, directly otherwise) with arguments, then removes it.
//   - RunTask uploads the task executable, feeds parameters by the task's
//     input_method (stdin JSON, PT_-prefixed shell environment, PowerShell named
//     arguments, or both), runs it, then removes it.
//   - Upload writes a local file to a destination.
//
// The connection itself (WS-Management wire protocol, NTLM/basic/TLS-client-cert
// auth) is github.com/go-remoteexec/transport, shared with go-ansible; this file
// only resolves Bolt's own config shape and layers Bolt's task-input-method
// conventions on top.
type WinRMTransport struct {
	// NewDoer builds the HTTP client used to reach a target. Defaults to
	// the shared transport's own client. Tests inject a doer that reaches
	// an in-process WS-Man server (and can force connect/auth failures).
	NewDoer func(remoteexec.WinRMConfig) (remoteexec.HTTPDoer, error)
}

// NewWinRMTransport returns a WinRMTransport using the default HTTP client.
func NewWinRMTransport() *WinRMTransport { return &WinRMTransport{} }

// resolveWinRMConfig builds a [remoteexec.WinRMConfig] from a target's uri
// and effective config.winrm. env, if non-empty, is set on the connection's
// shell at creation time (Bolt's "environment"/"both" task input methods).
func resolveWinRMConfig(t *Target, env map[string]string) (remoteexec.WinRMConfig, error) {
	c := remoteexec.WinRMConfig{
		Transport:      "negotiate",
		SSL:            true,
		SSLVerify:      true,
		TempDir:        `C:\Windows\Temp`,
		Path:           "/wsman",
		ConnectTimeout: 60 * time.Second,
		Environment:    env,
	}
	c.Host = hostFromURI(t.URI)
	if u := userFromURI(t.URI); u != "" {
		c.User = u
	}
	if p := portFromURI(t.URI); p != 0 {
		c.Port = p
	}
	if wm, ok := asMap(effectiveConfig(t)["winrm"]); ok {
		applyWinRMConfig(&c, wm)
	}
	if c.Transport == "ssl" {
		c.SSL = true
	}
	if c.Host == "" {
		return c, fmt.Errorf("winrm: target %q has no host", t.Name)
	}
	if c.Port == 0 {
		if c.SSL {
			c.Port = 5986
		} else {
			c.Port = 5985
		}
	}
	return c, nil
}

// applyWinRMConfig overlays a config.winrm mapping onto c.
func applyWinRMConfig(c *remoteexec.WinRMConfig, wm map[string]any) {
	if v, ok := asString(wm["host"]); ok && v != "" {
		c.Host = v
	}
	if p, ok := asInt(wm["port"]); ok {
		c.Port = p
	}
	if v, ok := asString(wm["user"]); ok && v != "" {
		c.User = v
	}
	if v, ok := asString(wm["password"]); ok {
		c.Password = v
	}
	if v, ok := asBool(wm["ssl"]); ok {
		c.SSL = v
	}
	if v, ok := asBool(wm["ssl-verify"]); ok {
		c.SSLVerify = v
	}
	if v, ok := asString(wm["cacert"]); ok && v != "" {
		c.CACert = v
	}
	if v, ok := asString(wm["transport"]); ok && v != "" {
		c.Transport = v
	}
	if v, ok := asString(wm["cert"]); ok {
		c.ClientCert = v
	}
	if v, ok := asString(wm["key"]); ok {
		c.ClientKey = v
	}
	if v, ok := asInt(wm["connect-timeout"]); ok {
		c.ConnectTimeout = time.Duration(v) * time.Second
	}
	if v, ok := asString(wm["tmpdir"]); ok && v != "" {
		c.TempDir = v
	}
	if v, ok := asString(wm["path"]); ok && v != "" {
		c.Path = v
	}
}

// RunCommand runs command on the target through the remote shell.
func (t *WinRMTransport) RunCommand(target *Target, command string) Result {
	return t.withConn(target, "command", command, nil, func(conn *remoteexec.WinRM) Result {
		res, err := conn.Exec(context.Background(), command, nil)
		return fromRemoteResult(target, "command", command, res, err)
	})
}

// RunScript uploads the script to the remote temp dir, runs it with args, and
// removes it afterwards.
func (t *WinRMTransport) RunScript(target *Target, scriptPath string, args []string) Result {
	return t.withConn(target, "script", scriptPath, nil, func(conn *remoteexec.WinRM) Result {
		remote := conn.TempPath(baseName(scriptPath))
		if err := conn.Put(context.Background(), scriptPath, remote, remoteexec.PutOptions{}); err != nil {
			return Result{Target: target.Name, Action: "script", Object: scriptPath, Err: err}
		}
		defer conn.Remove(context.Background(), remote)
		cmd, argv := winrmInvoke(remote, args)
		res, err := conn.ExecArgv(context.Background(), cmd, argv, nil)
		return fromRemoteResult(target, "script", scriptPath, res, err)
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
	stdin, env, taskArgs, err := winrmTaskInput(inputMethod(task), params)
	if err != nil {
		return Result{Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q: %w", task.Name, err)}
	}
	return t.withConn(target, "task", task.Name, env, func(conn *remoteexec.WinRM) Result {
		remote := conn.TempPath(baseName(task.File))
		if err := conn.Put(context.Background(), task.File, remote, remoteexec.PutOptions{}); err != nil {
			return Result{Target: target.Name, Action: "task", Object: task.Name, Err: err}
		}
		defer conn.Remove(context.Background(), remote)
		cmd, argv := winrmInvoke(remote, taskArgs)
		var stdinReader = strings.NewReader(stdin)
		res, err := conn.ExecArgv(context.Background(), cmd, argv, stdinReader)
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
func (t *WinRMTransport) Upload(target *Target, src, dst string) Result {
	return t.withConn(target, "upload", dst, nil, func(conn *remoteexec.WinRM) Result {
		if _, err := os.Stat(src); err != nil {
			return Result{Target: target.Name, Action: "upload", Object: dst,
				Err: fmt.Errorf("winrm: reading %q: %w", src, err)}
		}
		if err := conn.Put(context.Background(), src, dst, remoteexec.PutOptions{}); err != nil {
			return Result{Target: target.Name, Action: "upload", Object: dst, Err: err}
		}
		return Result{Target: target.Name, Action: "upload", Object: dst,
			Value: map[string]any{"_output": fmt.Sprintf("uploaded %s to %s", src, dst)}}
	})
}

// withConn resolves the target (with env applied at shell-creation time),
// dials, runs fn, and closes the connection.
func (t *WinRMTransport) withConn(target *Target, action, object string, env map[string]string, fn func(*remoteexec.WinRM) Result) Result {
	cfg, err := resolveWinRMConfig(target, env)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	if t.NewDoer != nil {
		cfg.NewDoer = t.NewDoer
	}
	conn, err := remoteexec.DialWinRM(context.Background(), cfg)
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	defer conn.Close()
	return fn(conn)
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

func sortedParamKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
