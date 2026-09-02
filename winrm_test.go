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
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	remoteexec "github.com/go-remoteexec/transport"
)

// This file tests only Bolt's own logic: resolving a Target's
// config.winrm block into a remoteexec.WinRMConfig, and layering the
// task input-method conventions (stdin/environment/both/powershell) on
// top of the shared transport's Exec/ExecArgv/Put. The WS-Management
// wire protocol itself (SOAP envelopes, shell/command/receive state
// machine, NTLM/basic/TLS auth) lives in and is tested by
// github.com/go-remoteexec/transport — see winrmserver_test.go here for
// the fake WS-Man server this file drives it against.

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

// doerFunc adapts a function to the remoteexec.HTTPDoer seam.
type doerFunc func(*http.Request) (*http.Response, error)

func (d doerFunc) Do(r *http.Request) (*http.Response, error) { return d(r) }

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
// paths.
func genCertKey(t *testing.T) (certPath, keyPath string) {
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
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
	return certPath, keyPath
}

func anyContains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// --- happy-path operations against the in-process WS-Man server ---

func TestWinRMRunCommand(t *testing.T) {
	f := startFakeWSMan(t, false, nil)
	tr := NewWinRMTransport()
	r := tr.RunCommand(winrmTarget(f, nil), "ipconfig")
	v := mustResult(t, r)
	// RunCommand goes through cmd.exe /c (the shared transport's Exec),
	// so the fake server's echo reflects the full invocation, not the
	// bare command.
	if !strings.Contains(v["stdout"].(string), "ipconfig") {
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
	if !strings.Contains(v["stdout"].(string), "whoami") {
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
	cert, key := genCertKey(t)
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
	if r.Err == nil {
		t.Fatalf("want read error, got nil")
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
	want := map[string]string{"PT_name": "bob", "PT_num": "2"}
	got := map[string]string{}
	for _, p := range f.lastEnv {
		got[p.Name] = p.Value
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("env = %v want %v", got, want)
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
	if r.Err == nil {
		t.Fatalf("want read error, got nil")
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
	if r.Err == nil {
		t.Fatalf("want write failure, got nil")
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
		c, err := resolveWinRMConfig(&Target{Name: "w", URI: "winrm://admin@host.example:9999"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.Host != "host.example" || c.User != "admin" || c.Port != 9999 {
			t.Fatalf("c = %#v", c)
		}
	})
	t.Run("missing host", func(t *testing.T) {
		_, err := resolveWinRMConfig(&Target{Name: "w"}, nil)
		if err == nil || !strings.Contains(err.Error(), "no host") {
			t.Fatalf("want no-host error, got %v", err)
		}
	})
	t.Run("default port http", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "host", Config: map[string]any{
			"winrm": map[string]any{"ssl": false}}}, nil)
		if c.Port != 5985 {
			t.Fatalf("port = %d", c.Port)
		}
	})
	t.Run("default port https", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "host"}, nil)
		if c.Port != 5986 || !c.SSL {
			t.Fatalf("c = %#v", c)
		}
	})
	t.Run("full config overlay", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "orig", Config: map[string]any{
			"winrm": map[string]any{
				"host": "h2", "port": 1234, "user": "adm", "password": "pw",
				"ssl": true, "ssl-verify": false, "cacert": "/ca", "transport": "basic",
				"cert": "/c", "key": "/k", "connect-timeout": 5,
				"tmpdir": `D:\tmp`, "path": "wsman2",
			}}}, nil)
		if c.Host != "h2" || c.Port != 1234 || c.User != "adm" || c.Password != "pw" ||
			c.SSLVerify || c.CACert != "/ca" || c.ClientCert != "/c" ||
			c.ClientKey != "/k" || c.ConnectTimeout != 5*time.Second || c.TempDir != `D:\tmp` ||
			c.Path != "wsman2" {
			t.Fatalf("c = %#v", c)
		}
	})
	t.Run("transport ssl forces ssl", func(t *testing.T) {
		c, _ := resolveWinRMConfig(&Target{Name: "w", URI: "host", Config: map[string]any{
			"winrm": map[string]any{"ssl": false, "transport": "ssl"}}}, nil)
		if !c.SSL {
			t.Fatal("transport ssl must force ssl=true")
		}
	})
	t.Run("environment carried through", func(t *testing.T) {
		env := map[string]string{"PT_x": "1"}
		c, err := resolveWinRMConfig(&Target{Name: "w", URI: "host"}, env)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(c.Environment) != fmt.Sprint(env) {
			t.Fatalf("Environment = %v, want %v", c.Environment, env)
		}
	})
}

// --- transport-level error paths, exercised through WinRMTransport.NewDoer ---

func TestWinRMNewDoerError(t *testing.T) {
	tr := &WinRMTransport{NewDoer: func(remoteexec.WinRMConfig) (remoteexec.HTTPDoer, error) {
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
	tr := &WinRMTransport{NewDoer: func(remoteexec.WinRMConfig) (remoteexec.HTTPDoer, error) {
		return doerFunc(func(*http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("dial refused")
		}), nil
	}}
	r := tr.RunCommand(&Target{Name: "w", URI: "host"}, "x")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "dial refused") {
		t.Fatalf("want connect error, got %v", r.Err)
	}
}

// --- Bolt's own task-input-method logic (independent of any transport) ---

func TestWinRMTaskInputBothEncodeError(t *testing.T) {
	_, _, _, err := winrmTaskInput("both", map[string]any{"bad": make(chan int)})
	if err == nil || !strings.Contains(err.Error(), "encoding parameters") {
		t.Fatalf("got %v", err)
	}
}

func TestWinRMTaskInputStdinDefault(t *testing.T) {
	stdin, env, args, err := winrmTaskInput("", map[string]any{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if stdin != `{"a":1}` || env != nil || args != nil {
		t.Fatalf("stdin=%q env=%v args=%v", stdin, env, args)
	}
}

func TestWinRMExtAndBaseNameBareFilename(t *testing.T) {
	if got := winrmExt("noslash.ps1"); got != ".ps1" {
		t.Fatalf("winrmExt(bare) = %q", got)
	}
	if got := winrmExt("noext"); got != "" {
		t.Fatalf("winrmExt(no ext) = %q", got)
	}
	if got := baseName("bare.exe"); got != "bare.exe" {
		t.Fatalf("baseName(bare) = %q", got)
	}
}

func TestWinRMInvokePowerShellVsDirect(t *testing.T) {
	cmd, args := winrmInvoke(`C:\t\script.ps1`, []string{"a"})
	if cmd != "powershell.exe" || len(args) == 0 || args[len(args)-1] != "a" {
		t.Fatalf("cmd=%q args=%v", cmd, args)
	}
	cmd2, args2 := winrmInvoke(`C:\t\tool.exe`, []string{"a"})
	if cmd2 != `C:\t\tool.exe` || len(args2) != 1 {
		t.Fatalf("cmd2=%q args2=%v", cmd2, args2)
	}
}

func TestWinRMImplementsTransport(t *testing.T) {
	var _ Transport = NewWinRMTransport()
}
