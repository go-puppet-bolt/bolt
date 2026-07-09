// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Transport runs actions on a target. v1 ships only [LocalTransport]; SSH and
// WinRM transports are deferred, and this interface is their extension point.
type Transport interface {
	// RunCommand runs a shell command on the target.
	RunCommand(target *Target, command string) Result
	// RunScript uploads and runs a script with arguments on the target.
	RunScript(target *Target, scriptPath string, args []string) Result
	// RunTask runs a task with parameters on the target.
	RunTask(target *Target, task *Task, params map[string]any) Result
	// Upload copies a local file/directory to a destination on the target.
	Upload(target *Target, src, dst string) Result
}

// CommandRunner is the seam through which [LocalTransport] executes processes.
// The default implementation ([OSRunner]) uses os/exec; tests inject a fake so
// no real process runs. stdin is fed to the process; the returned exit code is
// the process exit status (non-zero is not an error — err is only for failures
// to start or run the process).
type CommandRunner interface {
	Run(name string, args []string, stdin string) (stdout, stderr string, exitCode int, err error)
}

// FileCopier is the seam through which [LocalTransport.Upload] copies files. The
// default ([OSFileCopier]) uses the filesystem.
type FileCopier interface {
	Copy(src, dst string) error
}

// OSRunner is the default [CommandRunner]; it shells out through os/exec.
type OSRunner struct{}

// Run executes name with args, feeding stdin, and returns captured output.
func (OSRunner) Run(name string, args []string, stdin string) (string, string, int, error) {
	cmd := exec.Command(name, args...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.String(), errBuf.String(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return out.String(), errBuf.String(), -1, err
	}
	return out.String(), errBuf.String(), 0, nil
}

// OSFileCopier is the default [FileCopier]; it copies via the filesystem.
type OSFileCopier struct{}

// Copy copies the file at src to dst.
func (OSFileCopier) Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// LocalTransport runs actions on the host itself. It drives a [CommandRunner]
// and a [FileCopier] so behaviour is deterministic and injectable in tests.
type LocalTransport struct {
	Runner CommandRunner
	Copier FileCopier
	// Shell is the shell used for command steps; defaults to "sh -c".
	Shell     string
	ShellFlag string
}

// NewLocalTransport returns a LocalTransport using the OS runner and copier.
func NewLocalTransport() *LocalTransport {
	return &LocalTransport{Runner: OSRunner{}, Copier: OSFileCopier{}}
}

func (l *LocalTransport) runner() CommandRunner {
	if l.Runner != nil {
		return l.Runner
	}
	return OSRunner{}
}

func (l *LocalTransport) copier() FileCopier {
	if l.Copier != nil {
		return l.Copier
	}
	return OSFileCopier{}
}

func (l *LocalTransport) shell() (string, string) {
	sh, flag := l.Shell, l.ShellFlag
	if sh == "" {
		sh, flag = "sh", "-c"
	}
	return sh, flag
}

// RunCommand runs command through the configured shell.
func (l *LocalTransport) RunCommand(target *Target, command string) Result {
	sh, flag := l.shell()
	stdout, stderr, code, err := l.runner().Run(sh, []string{flag, command}, "")
	return commandResult(target, "command", command, stdout, stderr, code, err)
}

// RunScript runs the script at scriptPath with args.
func (l *LocalTransport) RunScript(target *Target, scriptPath string, args []string) Result {
	stdout, stderr, code, err := l.runner().Run(scriptPath, args, "")
	return commandResult(target, "script", scriptPath, stdout, stderr, code, err)
}

// RunTask runs task with params. Parameters are passed by the task's input
// method: "environment" exports each parameter as PT_<name>; anything else
// (the default "stdin"/"both") feeds a JSON object on stdin.
func (l *LocalTransport) RunTask(target *Target, task *Task, params map[string]any) Result {
	if task.File == "" {
		return Result{
			Target: target.Name, Action: "task", Object: task.Name,
			Err: fmt.Errorf("task %q has no executable file", task.Name),
		}
	}
	stdin := ""
	if inputMethod(task) != "environment" {
		enc, err := json.Marshal(params)
		if err != nil {
			return Result{
				Target: target.Name, Action: "task", Object: task.Name,
				Err: fmt.Errorf("task %q: encoding parameters: %w", task.Name, err),
			}
		}
		stdin = string(enc)
	}
	stdout, stderr, code, err := l.runner().Run(task.File, nil, stdin)
	res := commandResult(target, "task", task.Name, stdout, stderr, code, err)
	// A task that emits JSON on stdout has that object merged into the result.
	if res.Err == nil && stdout != "" {
		var obj map[string]any
		if json.Unmarshal([]byte(stdout), &obj) == nil {
			for k, v := range obj {
				res.Value[k] = v
			}
		}
	}
	return res
}

// Upload copies src to dst on the host.
func (l *LocalTransport) Upload(target *Target, src, dst string) Result {
	if err := l.copier().Copy(src, dst); err != nil {
		return Result{
			Target: target.Name, Action: "upload", Object: dst,
			Err: fmt.Errorf("upload %s -> %s: %w", src, dst, err),
		}
	}
	return Result{
		Target: target.Name, Action: "upload", Object: dst,
		Value: map[string]any{"_output": fmt.Sprintf("uploaded %s to %s", src, dst)},
	}
}

func inputMethod(task *Task) string {
	if task.Metadata != nil {
		return task.Metadata.InputMethod
	}
	return ""
}

// commandResult builds a Result from a runner invocation.
func commandResult(target *Target, action, object, stdout, stderr string, code int, err error) Result {
	if err != nil {
		return Result{Target: target.Name, Action: action, Object: object, Err: err}
	}
	return Result{
		Target: target.Name,
		Action: action,
		Object: object,
		Value: map[string]any{
			"stdout":    stdout,
			"stderr":    stderr,
			"exit_code": code,
		},
	}
}
