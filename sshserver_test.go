// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testSSHServer is an in-process SSH server built on golang.org/x/crypto/ssh. It
// is a real SSH endpoint (real handshake, auth, channels, exec requests and
// exit-status), so the transport is exercised end-to-end with no network peer.
// The "operating system" behind an exec request is a small, portable Go
// interpreter (see run) that understands exactly the command grammar the
// transport emits, so the suite runs identically on Linux, macOS and Windows
// without depending on /bin/sh.
type testSSHServer struct {
	ln         net.Listener
	host       string
	port       int
	hostSigner ssh.Signer

	// root sandboxes the fake remote filesystem so uploads/reads are portable
	// and isolated.
	root string

	// auth policy
	password      string
	authorizedKey ssh.PublicKey

	// fault injection
	rejectSession bool // reject session channel opens -> NewSession error
	rejectExec    bool // reply false to exec requests -> sess.Run error
}

// startTestSSHServer launches a server on 127.0.0.1 with an ephemeral port.
func startTestSSHServer(t *testing.T, configure func(*testSSHServer)) *testSSHServer {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	srv := &testSSHServer{ln: ln, host: host, port: port, hostSigner: signer, root: t.TempDir()}
	if configure != nil {
		configure(srv)
	}
	go srv.serve()
	t.Cleanup(func() { ln.Close() })
	return srv
}

func (s *testSSHServer) serverConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{}
	if s.password != "" {
		cfg.PasswordCallback = func(_ ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) == s.password {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("password rejected")
		}
	}
	if s.authorizedKey != nil {
		cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), s.authorizedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("key rejected")
		}
	}
	cfg.AddHostKey(s.hostSigner)
	return cfg
}

func (s *testSSHServer) serve() {
	cfg := s.serverConfig()
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(nc, cfg)
	}
}

func (s *testSSHServer) handleConn(nc net.Conn, cfg *ssh.ServerConfig) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		nc.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" || s.rejectSession {
			_ = nch.Reject(ssh.Prohibited, "no session")
			continue
		}
		ch, requests, err := nch.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, requests)
	}
}

func (s *testSSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env":
			_ = req.Reply(true, nil)
		case "exec":
			if s.rejectExec {
				_ = req.Reply(false, nil)
				continue
			}
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)
			// Always drain stdin fully before running and closing the channel;
			// otherwise closing early races the client's stdin-copy goroutine and
			// surfaces as a run error.
			data, _ := io.ReadAll(ch)
			stdin := func() string { return string(data) }
			out, errOut, code := s.exec(payload.Command, stdin)
			_, _ = io.WriteString(ch, out)
			_, _ = io.WriteString(ch.Stderr(), errOut)
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
			_ = ch.Close()
			return
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// mapPath sandboxes an absolute remote path under the server's root.
func (s *testSSHServer) mapPath(p string) string {
	return filepath.Join(s.root, filepath.FromSlash(p))
}

// exec tokenises and interprets one command line.
func (s *testSSHServer) exec(cmdline string, stdin func() string) (string, string, int) {
	return s.run(tokenize(cmdline), stdin)
}

// run interprets a tokenised command, honouring a single `> file` redirection.
func (s *testSSHServer) run(toks []string, stdin func() string) (string, string, int) {
	var redirect string
	var argv []string
	for i := 0; i < len(toks); i++ {
		if toks[i] == ">" && i+1 < len(toks) {
			redirect = toks[i+1]
			i++
			continue
		}
		argv = append(argv, toks[i])
	}
	if len(argv) == 0 {
		return "", "", 0
	}
	switch argv[0] {
	case "env":
		env := map[string]string{}
		j := 1
		for j < len(argv) && strings.Contains(argv[j], "=") {
			k, v, _ := strings.Cut(argv[j], "=")
			env[k] = v
			j++
		}
		return s.runProgram(argv[j:], env, stdin)
	case "sudo":
		return s.runSudo(argv, stdin)
	case "sh":
		if len(argv) >= 3 && argv[1] == "-c" {
			return s.exec(argv[2], stdin)
		}
		return "", "sh: usage", 2
	case "mkdir":
		dir := argv[len(argv)-1]
		if strings.Contains(dir, "faildir") {
			return "", "mkdir: denied", 1
		}
		_ = os.MkdirAll(s.mapPath(dir), 0o755)
		return "", "", 0
	case "chmod":
		target := argv[len(argv)-1]
		if strings.Contains(target, "failchmod") {
			return "", "chmod: denied", 1
		}
		return "", "", 0
	case "rm":
		_ = os.Remove(s.mapPath(argv[len(argv)-1]))
		return "", "", 0
	case "cat":
		data := stdin()
		if redirect != "" {
			if strings.Contains(redirect, "failcat") {
				return "", "cat: denied", 1
			}
			_ = os.WriteFile(s.mapPath(redirect), []byte(data), 0o644)
			return "", "", 0
		}
		return data, "", 0
	case "echo":
		return strings.Join(argv[1:], " ") + "\n", "", 0
	case "false":
		return "", "", 1
	default:
		return s.runProgram(argv, nil, stdin)
	}
}

func (s *testSSHServer) runSudo(argv []string, stdin func() string) (string, string, int) {
	consumePw := false
	j := 1
	for j < len(argv) && strings.HasPrefix(argv[j], "-") {
		switch argv[j] {
		case "-S":
			consumePw = true
		case "-u":
			j++ // skip the user argument
		}
		j++
	}
	sin := stdin
	if consumePw {
		full := stdin()
		_, rest, _ := strings.Cut(full, "\n") // strip the sudo password line
		sin = func() string { return rest }
	}
	return s.run(argv[j:], sin)
}

// runProgram executes an "uploaded" file by interpreting its first line as a
// directive, so scripts and tasks behave deterministically and portably.
func (s *testSSHServer) runProgram(argv []string, env map[string]string, stdin func() string) (string, string, int) {
	if len(argv) == 0 {
		return "", "", 0
	}
	body, err := os.ReadFile(s.mapPath(argv[0]))
	if err != nil {
		return "", argv[0] + ": not found", 127
	}
	line := strings.TrimRight(string(body), "\n")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", 0
	}
	switch fields[0] {
	case "#emit": // print the remainder (used for task JSON output)
		return strings.TrimPrefix(line, "#emit ") + "\n", "", 0
	case "#args": // print the arguments the script received
		return strings.Join(argv[1:], " ") + "\n", "", 0
	case "#stdin": // echo what arrived on stdin
		return "got:" + stdin(), "", 0
	case "#printenv": // print a named environment variable
		return env[fields[1]] + "\n", "", 0
	case "#exit": // exit with a code, writing to both streams
		n, _ := strconv.Atoi(fields[1])
		return "out\n", "err\n", n
	default:
		return line + "\n", "", 0
	}
}

// tokenize splits a command line into words, honouring POSIX single-quoting and
// backslash escaping outside quotes (the inverse of shellQuote). Adjacent
// quoted and unquoted runs concatenate into one word.
func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	inWord := false
	i := 0
	for i < len(s) {
		ch := s[i]
		switch {
		case ch == ' ' || ch == '\t':
			if inWord {
				toks = append(toks, cur.String())
				cur.Reset()
				inWord = false
			}
			i++
		case ch == '\'':
			inWord = true
			i++
			for i < len(s) && s[i] != '\'' {
				cur.WriteByte(s[i])
				i++
			}
			i++ // closing quote
		case ch == '\\' && i+1 < len(s):
			inWord = true
			cur.WriteByte(s[i+1])
			i += 2
		default:
			inWord = true
			cur.WriteByte(ch)
			i++
		}
	}
	if inWord {
		toks = append(toks, cur.String())
	}
	return toks
}

// --- key material helpers for tests ---

// genClientKey returns an unencrypted OpenSSH private-key PEM and its public key.
func genClientKey(t *testing.T) (pemBytes []byte, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

// genEncryptedClientKey returns a passphrase-encrypted private-key PEM and pub.
func genEncryptedClientKey(t *testing.T, passphrase string) (pemBytes []byte, pub ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block), signer.PublicKey()
}

// writeFile writes content to a fresh file in a temp dir and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
