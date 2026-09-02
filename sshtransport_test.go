// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

// sshTarget builds an ad-hoc target pointing at srv, merging extra ssh config.
func sshTarget(srv *testSSHServer, extra map[string]any) *Target {
	cfg := map[string]any{"host": srv.host, "port": srv.port, "host-key-check": false, "password": "pw"}
	for k, v := range extra {
		if v == nil {
			delete(cfg, k)
			continue
		}
		cfg[k] = v
	}
	return &Target{Name: "h", URI: "h", Config: map[string]any{"ssh": cfg}}
}

// pwServer starts a server that accepts password "pw".
func pwServer(t *testing.T) *testSSHServer {
	return startTestSSHServer(t, func(s *testSSHServer) { s.password = "pw" })
}

func TestSSHRunCommandSuccess(t *testing.T) {
	srv := pwServer(t)
	tr := NewSSHTransport()
	r := tr.RunCommand(sshTarget(srv, map[string]any{"user": "deploy", "tmpdir": "/tmp", "connect-timeout": 5}), "echo hi")
	if !r.Ok() {
		t.Fatalf("not ok: %#v", r)
	}
	if r.Value["stdout"] != "hi\n" {
		t.Fatalf("stdout=%q", r.Value["stdout"])
	}
}

func TestSSHRunCommandNonZero(t *testing.T) {
	srv := pwServer(t)
	r := NewSSHTransport().RunCommand(sshTarget(srv, nil), "false")
	if r.Err != nil {
		t.Fatalf("unexpected transport err: %v", r.Err)
	}
	if code, _ := r.ExitCode(); code != 1 || r.Ok() {
		t.Fatalf("want exit 1, got %#v", r)
	}
}

func TestSSHPublicKeyAuthFromFile(t *testing.T) {
	keyPEM, pub := genClientKey(t)
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.authorizedKey = pub })
	keyFile := writeFile(t, "id_ed25519", string(keyPEM))
	tgt := sshTarget(srv, map[string]any{"password": nil, "private-key": keyFile})
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if !r.Ok() {
		t.Fatalf("pubkey auth failed: %#v", r)
	}
}

func TestSSHPublicKeyAuthFromKeyData(t *testing.T) {
	keyPEM, pub := genClientKey(t)
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.authorizedKey = pub })
	tgt := sshTarget(srv, map[string]any{"password": nil, "private-key": map[string]any{"key-data": string(keyPEM)}})
	if r := NewSSHTransport().RunCommand(tgt, "echo hi"); !r.Ok() {
		t.Fatalf("key-data auth failed: %#v", r)
	}
}

func TestSSHEncryptedKeyWithPassphrase(t *testing.T) {
	keyPEM, pub := genEncryptedClientKey(t, "secret")
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.authorizedKey = pub })
	tgt := sshTarget(srv, map[string]any{
		"password":    nil,
		"private-key": map[string]any{"key-data": string(keyPEM)},
		"passphrase":  "secret",
	})
	if r := NewSSHTransport().RunCommand(tgt, "echo hi"); !r.Ok() {
		t.Fatalf("encrypted-key auth failed: %#v", r)
	}
}

func TestSSHAuthFailure(t *testing.T) {
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.password = "right" })
	r := NewSSHTransport().RunCommand(sshTarget(srv, map[string]any{"password": "wrong"}), "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "handshake") {
		t.Fatalf("want handshake error, got %#v", r)
	}
}

func TestSSHConnectError(t *testing.T) {
	srv := pwServer(t)
	tr := &SSHTransport{Dialer: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no route")
	}}
	r := tr.RunCommand(sshTarget(srv, nil), "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "dial") {
		t.Fatalf("want dial error, got %#v", r)
	}
}

func TestSSHNoAuthConfigured(t *testing.T) {
	srv := pwServer(t)
	// A bare target (no inventory, no config) reaches the "no auth" branch.
	r := NewSSHTransport().RunCommand(&Target{Name: "h", URI: srv.host}, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "authentication") {
		t.Fatalf("want no-auth error, got %#v", r)
	}
}

func TestSSHParseKeyError(t *testing.T) {
	srv := pwServer(t)
	tgt := sshTarget(srv, map[string]any{"password": nil, "private-key": map[string]any{"key-data": "not a key"}})
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "loading private key") {
		t.Fatalf("want parse error, got %#v", r)
	}
}

func TestSSHPrivateKeyFileMissing(t *testing.T) {
	srv := pwServer(t)
	tgt := sshTarget(srv, map[string]any{"private-key": filepath.Join(t.TempDir(), "absent")})
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading private-key") {
		t.Fatalf("want key-file error, got %#v", r)
	}
}

func TestSSHHostKeyCheckKnownHosts(t *testing.T) {
	srv := pwServer(t)
	addr := knownhosts.Normalize(net.JoinHostPort(srv.host, strconv.Itoa(srv.port)))
	line := knownhosts.Line([]string{addr}, srv.hostSigner.PublicKey())
	khFile := writeFile(t, "known_hosts", line+"\n")
	tgt := sshTarget(srv, map[string]any{"host-key-check": true, "known-hosts": khFile})
	if r := NewSSHTransport().RunCommand(tgt, "echo hi"); !r.Ok() {
		t.Fatalf("known-hosts verify failed: %#v", r)
	}
}

func TestSSHHostKeyCheckNoFile(t *testing.T) {
	srv := pwServer(t)
	tgt := sshTarget(srv, map[string]any{"host-key-check": true})
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no known-hosts file") {
		t.Fatalf("want no-known-hosts error, got %#v", r)
	}
}

func TestSSHHostKeyCheckBadFile(t *testing.T) {
	srv := pwServer(t)
	tgt := sshTarget(srv, map[string]any{"host-key-check": true, "known-hosts": filepath.Join(t.TempDir(), "absent")})
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading known_hosts") {
		t.Fatalf("want known-hosts load error, got %#v", r)
	}
}

func TestSSHHostKeyCheckFromTransportFallback(t *testing.T) {
	srv := pwServer(t)
	addr := knownhosts.Normalize(net.JoinHostPort(srv.host, strconv.Itoa(srv.port)))
	khFile := writeFile(t, "known_hosts", knownhosts.Line([]string{addr}, srv.hostSigner.PublicKey())+"\n")
	tr := &SSHTransport{KnownHostsFile: khFile}
	tgt := sshTarget(srv, map[string]any{"host-key-check": true})
	if r := tr.RunCommand(tgt, "echo hi"); !r.Ok() {
		t.Fatalf("fallback known-hosts failed: %#v", r)
	}
}

func TestSSHRunScript(t *testing.T) {
	srv := pwServer(t)
	script := writeFile(t, "s.sh", "#args\n")
	r := NewSSHTransport().RunScript(sshTarget(srv, nil), script, []string{"a", "b c"})
	if !r.Ok() {
		t.Fatalf("script failed: %#v", r)
	}
	if got := r.Value["stdout"].(string); !strings.Contains(got, "a") || !strings.Contains(got, "b c") {
		t.Fatalf("args not passed: %q", got)
	}
}

func TestSSHRunScriptReadError(t *testing.T) {
	srv := pwServer(t)
	r := NewSSHTransport().RunScript(sshTarget(srv, nil), filepath.Join(t.TempDir(), "absent.sh"), nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no such file") {
		t.Fatalf("want read error, got %#v", r)
	}
}

func TestSSHRunScriptMkdirFail(t *testing.T) {
	srv := pwServer(t)
	script := writeFile(t, "s.sh", "#args\n")
	r := NewSSHTransport().RunScript(sshTarget(srv, map[string]any{"tmpdir": "/faildir"}), script, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "preparing") {
		t.Fatalf("want mkdir error, got %#v", r)
	}
}

func TestSSHRunScriptCatFail(t *testing.T) {
	srv := pwServer(t)
	script := writeFile(t, "failcat.sh", "#args\n")
	r := NewSSHTransport().RunScript(sshTarget(srv, nil), script, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "put") {
		t.Fatalf("want cat error, got %#v", r)
	}
}

func TestSSHRunScriptChmodFail(t *testing.T) {
	srv := pwServer(t)
	script := writeFile(t, "failchmod.sh", "#args\n")
	r := NewSSHTransport().RunScript(sshTarget(srv, nil), script, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "chmod") {
		t.Fatalf("want chmod error, got %#v", r)
	}
}

func TestSSHRunScriptUploadExecError(t *testing.T) {
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.password = "pw"; s.rejectExec = true })
	script := writeFile(t, "s.sh", "#args\n")
	r := NewSSHTransport().RunScript(sshTarget(srv, nil), script, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "preparing") {
		t.Fatalf("want exec error on mkdir, got %#v", r)
	}
}

func TestSSHRunTaskStdin(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", `#emit {"answer":42}`+"\n")
	task := &Task{Name: "t", File: taskFile, Metadata: &TaskMetadata{InputMethod: "stdin"}}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, map[string]any{"x": 1})
	if !r.Ok() {
		t.Fatalf("task failed: %#v", r)
	}
	if got, _ := asInt(r.Value["answer"]); got != 42 {
		t.Fatalf("merged output: %#v", r.Value)
	}
}

func TestSSHRunTaskEnvironment(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", "#printenv PT_name\n")
	task := &Task{Name: "t", File: taskFile, Metadata: &TaskMetadata{InputMethod: "environment"}}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, map[string]any{"name": "alice"})
	if !r.Ok() || strings.TrimSpace(r.Value["stdout"].(string)) != "alice" {
		t.Fatalf("environment input failed: %#v", r)
	}
}

func TestSSHRunTaskBothNonStringParam(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", "#printenv PT_n\n")
	task := &Task{Name: "t", File: taskFile, Metadata: &TaskMetadata{InputMethod: "both"}}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, map[string]any{"n": 5})
	if !r.Ok() || strings.TrimSpace(r.Value["stdout"].(string)) != "5" {
		t.Fatalf("both input failed: %#v", r)
	}
}

func TestSSHRunTaskEnvValueMarshalFallback(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", "#args\n")
	task := &Task{Name: "t", File: taskFile, Metadata: &TaskMetadata{InputMethod: "environment"}}
	// A channel cannot be JSON-encoded; envValue falls back to fmt.Sprint.
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, map[string]any{"bad": make(chan int)})
	if !r.Ok() {
		t.Fatalf("env fallback run failed: %#v", r)
	}
}

func TestSSHRunTaskNoFile(t *testing.T) {
	srv := pwServer(t)
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), &Task{Name: "t"}, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no executable file") {
		t.Fatalf("want no-file error, got %#v", r)
	}
}

func TestSSHRunTaskFileReadError(t *testing.T) {
	srv := pwServer(t)
	task := &Task{Name: "t", File: filepath.Join(t.TempDir(), "absent")}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no such file") {
		t.Fatalf("want read error, got %#v", r)
	}
}

func TestSSHRunTaskMarshalError(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", "#emit {}\n")
	task := &Task{Name: "t", File: taskFile}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, map[string]any{"bad": make(chan int)})
	if r.Err == nil || !strings.Contains(r.Err.Error(), "encoding parameters") {
		t.Fatalf("want marshal error, got %#v", r)
	}
}

func TestSSHRunTaskUploadError(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "failcat", "#emit {}\n")
	task := &Task{Name: "t", File: taskFile}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, nil)
	if r.Err == nil || !strings.Contains(r.Err.Error(), "put") {
		t.Fatalf("want upload error, got %#v", r)
	}
}

func TestSSHRunTaskNonJSONOutput(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", "plain text\n")
	task := &Task{Name: "t", File: taskFile}
	r := NewSSHTransport().RunTask(sshTarget(srv, nil), task, nil)
	if !r.Ok() {
		t.Fatalf("task failed: %#v", r)
	}
	if _, merged := r.Value["answer"]; merged {
		t.Fatal("plain output should not merge")
	}
}

func TestSSHUpload(t *testing.T) {
	srv := pwServer(t)
	src := writeFile(t, "payload.txt", "content-here")
	r := NewSSHTransport().Upload(sshTarget(srv, nil), src, "/dest/out.txt")
	if !r.Ok() {
		t.Fatalf("upload failed: %#v", r)
	}
	got, err := os.ReadFile(srv.mapPath("/dest/out.txt"))
	if err != nil || string(got) != "content-here" {
		t.Fatalf("uploaded content = %q err=%v", got, err)
	}
}

func TestSSHUploadReadError(t *testing.T) {
	srv := pwServer(t)
	r := NewSSHTransport().Upload(sshTarget(srv, nil), filepath.Join(t.TempDir(), "absent"), "/x")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "reading") {
		t.Fatalf("want read error, got %#v", r)
	}
}

func TestSSHUploadMkdirError(t *testing.T) {
	srv := pwServer(t)
	src := writeFile(t, "p.txt", "x")
	r := NewSSHTransport().Upload(sshTarget(srv, nil), src, "/faildir/out.txt")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "preparing") {
		t.Fatalf("want mkdir error, got %#v", r)
	}
}

func TestSSHUploadToRootLevelPaths(t *testing.T) {
	srv := pwServer(t)
	src := writeFile(t, "p.txt", "top")
	tr := NewSSHTransport()
	// path.Dir("/onlyroot") == "/" -> mkdir skipped.
	if r := tr.Upload(sshTarget(srv, nil), src, "/onlyroot"); !r.Ok() {
		t.Fatalf("root upload failed: %#v", r)
	}
	// path.Dir("bare") == "." -> mkdir skipped.
	if r := tr.Upload(sshTarget(srv, nil), src, "bare"); !r.Ok() {
		t.Fatalf("bare upload failed: %#v", r)
	}
}

func TestSSHRunAs(t *testing.T) {
	srv := pwServer(t)
	r := NewSSHTransport().RunCommand(sshTarget(srv, map[string]any{"run-as": "alice"}), "echo hi")
	if !r.Ok() || r.Value["stdout"] != "hi\n" {
		t.Fatalf("run-as failed: %#v", r)
	}
}

func TestSSHRunAsSudoPassword(t *testing.T) {
	srv := pwServer(t)
	tgt := sshTarget(srv, map[string]any{"run-as": "alice", "sudo-password": "s3cr3t"})
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if !r.Ok() || r.Value["stdout"] != "hi\n" {
		t.Fatalf("run-as+sudo-password failed: %#v", r)
	}
}

func TestSSHRunAsTaskWithStdin(t *testing.T) {
	srv := pwServer(t)
	taskFile := writeFile(t, "t", "#stdin\n")
	task := &Task{Name: "t", File: taskFile}
	tgt := sshTarget(srv, map[string]any{"run-as": "alice", "sudo-password": "pw2"})
	r := NewSSHTransport().RunTask(tgt, task, map[string]any{"k": "v"})
	if !r.Ok() || !strings.Contains(r.Value["stdout"].(string), `"k":"v"`) {
		t.Fatalf("run-as task stdin failed: %#v", r)
	}
}

func TestSSHTTY(t *testing.T) {
	srv := pwServer(t)
	r := NewSSHTransport().RunCommand(sshTarget(srv, map[string]any{"tty": true}), "echo hi")
	if !r.Ok() {
		t.Fatalf("tty run failed: %#v", r)
	}
}

func TestSSHNewSessionError(t *testing.T) {
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.password = "pw"; s.rejectSession = true })
	r := NewSSHTransport().RunCommand(sshTarget(srv, nil), "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "opening ssh session") {
		t.Fatalf("want new-session error, got %#v", r)
	}
}

func TestSSHExecRequestError(t *testing.T) {
	srv := startTestSSHServer(t, func(s *testSSHServer) { s.password = "pw"; s.rejectExec = true })
	r := NewSSHTransport().RunCommand(sshTarget(srv, nil), "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "ssh exec") {
		t.Fatalf("want run error, got %#v", r)
	}
}

func TestSSHNoHost(t *testing.T) {
	// No inventory, no config, empty uri -> host is empty.
	r := NewSSHTransport().RunCommand(&Target{Name: "h", URI: ""}, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no host") {
		t.Fatalf("want no-host error, got %#v", r)
	}
}

func TestSSHNoHostWithSSHConfig(t *testing.T) {
	tgt := &Target{Name: "h", URI: "", Config: map[string]any{"ssh": map[string]any{"user": "x"}}}
	r := NewSSHTransport().RunCommand(tgt, "echo hi")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "no host") {
		t.Fatalf("want no-host error, got %#v", r)
	}
}

func TestSSHURIWithUserAndPort(t *testing.T) {
	srv := pwServer(t)
	uri := fmt.Sprintf("ssh://bob@%s:%d", srv.host, srv.port)
	tgt := &Target{Name: "h", URI: uri, Config: map[string]any{"ssh": map[string]any{
		"host-key-check": false, "password": "pw",
	}}}
	if r := NewSSHTransport().RunCommand(tgt, "echo hi"); !r.Ok() {
		t.Fatalf("uri user/port failed: %#v", r)
	}
}

func TestSSHInventoryEffectiveConfig(t *testing.T) {
	srv := pwServer(t)
	doc := fmt.Sprintf(`
version: 2
config:
  ssh:
    host-key-check: false
    password: pw
targets:
  - uri: %s
    config:
      ssh:
        port: %d
`, srv.host, srv.port)
	inv, err := ParseInventory([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	tgt, _ := inv.Target(srv.host)
	if tgt == nil {
		t.Fatal("target not found")
	}
	if r := NewSSHTransport().RunCommand(tgt, "echo hi"); !r.Ok() {
		t.Fatalf("inventory-config run failed: %#v", r)
	}
}
