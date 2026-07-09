// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHelperProcess is the subprocess entry point used to exercise OSRunner
// portably (it is the test binary re-invoked with GO_WANT_HELPER=1).
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	switch {
	case len(args) == 0:
		os.Exit(0)
	case args[0] == "echo-stdout":
		os.Stdout.WriteString("hello-out")
		os.Exit(0)
	case args[0] == "echo-stdin":
		data, _ := io.ReadAll(os.Stdin)
		os.Stdout.Write(data)
		os.Exit(0)
	case args[0] == "json":
		os.Stdout.WriteString(`{"answer":42}`)
		os.Exit(0)
	case args[0] == "fail":
		os.Stderr.WriteString("nope")
		os.Exit(3)
	default:
		os.Exit(0)
	}
}

func helperArgs(sub string) (string, []string) {
	return os.Args[0], []string{"-test.run=TestHelperProcess", "--", sub}
}

// withHelperEnv marks the process so a re-exec of the test binary runs the
// helper switch, then probes that the binary can re-exec itself. Under qemu-user
// emulation without a binfmt handler a foreign-arch re-exec fails; there we skip
// (the 100% coverage gate runs natively, where the probe always succeeds).
func withHelperEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GO_WANT_HELPER", "1")
	name, args := helperArgs("noop")
	if _, _, _, err := (OSRunner{}).Run(name, args, ""); err != nil {
		t.Skipf("self-exec unsupported in this environment: %v", err)
	}
}

func TestOSRunnerSuccess(t *testing.T) {
	withHelperEnv(t)
	name, args := helperArgs("echo-stdout")
	out, _, code, err := OSRunner{}.Run(name, args, "")
	if err != nil || code != 0 || !strings.Contains(out, "hello-out") {
		t.Fatalf("out=%q code=%d err=%v", out, code, err)
	}
}

func TestOSRunnerStdin(t *testing.T) {
	withHelperEnv(t)
	name, args := helperArgs("echo-stdin")
	out, _, code, err := OSRunner{}.Run(name, args, "piped-input")
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(out, "piped-input") {
		t.Fatalf("stdin not echoed: %q", out)
	}
}

func TestOSRunnerNonZero(t *testing.T) {
	withHelperEnv(t)
	name, args := helperArgs("fail")
	_, errOut, code, err := OSRunner{}.Run(name, args, "")
	if err != nil {
		t.Fatalf("exit-error should not surface as err: %v", err)
	}
	if code != 3 || !strings.Contains(errOut, "nope") {
		t.Fatalf("code=%d errOut=%q", code, errOut)
	}
}

func TestOSRunnerStartError(t *testing.T) {
	_, _, code, err := OSRunner{}.Run(filepath.Join(t.TempDir(), "does-not-exist"), nil, "")
	if err == nil || code != -1 {
		t.Fatalf("want start error, code=%d err=%v", code, err)
	}
}

func TestOSFileCopier(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (OSFileCopier{}).Copy(src, dst); err != nil {
		t.Fatalf("copy: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "payload" {
		t.Fatalf("copied = %q", got)
	}

	// open error: missing source
	if err := (OSFileCopier{}).Copy(filepath.Join(dir, "missing"), dst); err == nil {
		t.Fatal("want open error")
	}
	// create error: destination in nonexistent directory
	if err := (OSFileCopier{}).Copy(src, filepath.Join(dir, "no", "such", "dst")); err == nil {
		t.Fatal("want create error")
	}
	// io.Copy error: reading a directory as source
	if err := (OSFileCopier{}).Copy(dir, filepath.Join(dir, "dir-copy")); err == nil {
		t.Fatal("want io.Copy error copying a directory")
	}
}

func TestLocalTransportCommandAndScript(t *testing.T) {
	fr := &fakeRunner{resp: func(name string, args []string, stdin string) (string, string, int, error) {
		return "out", "err", 0, nil
	}}
	lt := localWith(fr)
	tgt := &Target{Name: "host"}

	r := lt.RunCommand(tgt, "ls -l")
	if !r.Ok() || r.Value["stdout"] != "out" || r.Action != "command" {
		t.Fatalf("command result: %#v", r)
	}
	if fr.calls[0].name != "sh" || fr.calls[0].args[0] != "-c" || fr.calls[0].args[1] != "ls -l" {
		t.Fatalf("shell call: %#v", fr.calls[0])
	}

	r = lt.RunScript(tgt, "/s.sh", []string{"a"})
	if !r.Ok() || r.Action != "script" || r.Object != "/s.sh" {
		t.Fatalf("script result: %#v", r)
	}
}

func TestLocalTransportCustomShell(t *testing.T) {
	fr := &fakeRunner{}
	lt := &LocalTransport{Runner: fr, Shell: "bash", ShellFlag: "-lc"}
	lt.RunCommand(&Target{Name: "h"}, "echo hi")
	if fr.calls[0].name != "bash" || fr.calls[0].args[0] != "-lc" {
		t.Fatalf("custom shell: %#v", fr.calls[0])
	}
}

func TestLocalTransportDefaults(t *testing.T) {
	lt := NewLocalTransport()
	if _, ok := lt.runner().(OSRunner); !ok {
		t.Fatal("default runner")
	}
	if _, ok := lt.copier().(OSFileCopier); !ok {
		t.Fatal("default copier")
	}
	// zero-value transport falls back to OS defaults too
	empty := &LocalTransport{}
	if _, ok := empty.runner().(OSRunner); !ok {
		t.Fatal("fallback runner")
	}
	if _, ok := empty.copier().(OSFileCopier); !ok {
		t.Fatal("fallback copier")
	}
}

func TestLocalTransportRunTaskStdin(t *testing.T) {
	fr := &fakeRunner{resp: func(name string, args []string, stdin string) (string, string, int, error) {
		return `{"answer":42}`, "", 0, nil
	}}
	lt := localWith(fr)
	task := &Task{Name: "t", File: "/bin/t", Metadata: &TaskMetadata{InputMethod: "stdin"}}
	r := lt.RunTask(&Target{Name: "h"}, task, map[string]any{"x": 1})
	if !r.Ok() {
		t.Fatalf("task result: %#v", r)
	}
	if !strings.Contains(fr.calls[0].stdin, `"x":1`) {
		t.Fatalf("stdin params: %q", fr.calls[0].stdin)
	}
	if got, _ := asInt(r.Value["answer"]); got != 42 {
		t.Fatalf("merged output: %#v", r.Value)
	}
}

func TestLocalTransportRunTaskEnvironment(t *testing.T) {
	fr := &fakeRunner{}
	lt := localWith(fr)
	task := &Task{Name: "t", File: "/bin/t", Metadata: &TaskMetadata{InputMethod: "environment"}}
	lt.RunTask(&Target{Name: "h"}, task, map[string]any{"x": 1})
	if fr.calls[0].stdin != "" {
		t.Fatalf("environment method should not use stdin: %q", fr.calls[0].stdin)
	}
}

func TestLocalTransportRunTaskNoFile(t *testing.T) {
	lt := localWith(&fakeRunner{})
	task := &Task{Name: "t"} // no File
	r := lt.RunTask(&Target{Name: "h"}, task, nil)
	if r.Ok() || r.Err == nil {
		t.Fatal("want no-file error")
	}
}

func TestLocalTransportRunTaskMarshalError(t *testing.T) {
	lt := localWith(&fakeRunner{})
	task := &Task{Name: "t", File: "/bin/t"}
	r := lt.RunTask(&Target{Name: "h"}, task, map[string]any{"bad": make(chan int)})
	if r.Ok() || r.Err == nil {
		t.Fatal("want marshal error")
	}
}

func TestLocalTransportRunTaskRunnerError(t *testing.T) {
	fr := &fakeRunner{resp: func(string, []string, string) (string, string, int, error) {
		return "", "", -1, errors.New("cannot start")
	}}
	lt := localWith(fr)
	task := &Task{Name: "t", File: "/bin/t"}
	r := lt.RunTask(&Target{Name: "h"}, task, nil)
	if r.Ok() || r.Err == nil {
		t.Fatal("want runner error")
	}
}

func TestLocalTransportRunTaskNonJSONOutput(t *testing.T) {
	fr := &fakeRunner{resp: func(string, []string, string) (string, string, int, error) {
		return "plain text", "", 0, nil
	}}
	lt := localWith(fr)
	task := &Task{Name: "t", File: "/bin/t"}
	r := lt.RunTask(&Target{Name: "h"}, task, nil)
	if !r.Ok() {
		t.Fatalf("result: %#v", r)
	}
	if _, merged := r.Value["answer"]; merged {
		t.Fatal("plain output should not merge")
	}
}

func TestLocalTransportRunTaskEmptyOutput(t *testing.T) {
	fr := &fakeRunner{} // empty stdout
	lt := localWith(fr)
	task := &Task{Name: "t", File: "/bin/t"}
	r := lt.RunTask(&Target{Name: "h"}, task, nil)
	if !r.Ok() {
		t.Fatalf("result: %#v", r)
	}
}

func TestLocalTransportUpload(t *testing.T) {
	fc := &fakeCopier{}
	lt := &LocalTransport{Runner: &fakeRunner{}, Copier: fc}
	r := lt.Upload(&Target{Name: "h"}, "/a", "/b")
	if !r.Ok() || r.Action != "upload" || len(fc.calls) != 1 {
		t.Fatalf("upload: %#v", r)
	}
	// error path
	fc2 := &fakeCopier{err: errors.New("disk full")}
	lt2 := &LocalTransport{Runner: &fakeRunner{}, Copier: fc2}
	r = lt2.Upload(&Target{Name: "h"}, "/a", "/b")
	if r.Ok() || r.Err == nil {
		t.Fatal("want upload error")
	}
}

func TestInputMethod(t *testing.T) {
	if inputMethod(&Task{}) != "" {
		t.Fatal("no metadata => empty")
	}
	if inputMethod(&Task{Metadata: &TaskMetadata{InputMethod: "environment"}}) != "environment" {
		t.Fatal("metadata method")
	}
}
