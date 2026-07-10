// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"fmt"
)

// ErrWinRMUnsupported is returned by every [WinRMTransport] action. See the type
// documentation for why the WinRM transport is a documented stub rather than a
// working implementation.
var ErrWinRMUnsupported = errors.New("bolt: winrm transport is not implemented (see WinRMTransport docs)")

// WinRMTransport is a placeholder implementation of the [Transport] interface
// for Windows targets over WinRM.
//
// # Status: documented stub — NOT implemented
//
// Unlike the ssh transport (fully implemented in [SSHTransport], exercised
// end-to-end against an in-process SSH server), the WinRM transport is a stub.
// Every method returns [ErrWinRMUnsupported]. This is deliberate and reported
// honestly rather than faked:
//
//   - WinRM speaks WS-Management: SOAP 1.2 envelopes with WS-Addressing headers
//     over HTTP(S), driving the MS-WSMV shell protocol (Create shell → Command
//     → Receive stdout/stderr streams and CommandState/ExitCode → Signal →
//     Delete). A faithful, differentially-tested port is a substantial protocol
//     implementation on both the client and — to keep the org's 100% coverage
//     gate honest with an in-process test server — the server side.
//   - Real deployments authenticate with Negotiate/Kerberos or NTLM, neither of
//     which is in the pure-Go stdlib; Basic-over-HTTPS alone is not
//     representative of production WinRM.
//
// Rather than ship a partial or untestable implementation, this transport is a
// clearly-labelled stub. The [Transport] interface is the extension point: a
// future pure-Go WS-Management client (with a matching in-process WS-Man test
// server) can replace this type without touching the executor or plan runner.
// On Windows, prefer the ssh transport, which the modern OpenSSH-for-Windows
// server supports and which is fully implemented here.
type WinRMTransport struct{}

// NewWinRMTransport returns a WinRMTransport stub.
func NewWinRMTransport() *WinRMTransport { return &WinRMTransport{} }

func winrmResult(target *Target, action, object string) Result {
	return Result{Target: target.Name, Action: action, Object: object,
		Err: fmt.Errorf("%s %s: %w", action, object, ErrWinRMUnsupported)}
}

// RunCommand is not implemented; it returns [ErrWinRMUnsupported].
func (*WinRMTransport) RunCommand(target *Target, command string) Result {
	return winrmResult(target, "command", command)
}

// RunScript is not implemented; it returns [ErrWinRMUnsupported].
func (*WinRMTransport) RunScript(target *Target, scriptPath string, _ []string) Result {
	return winrmResult(target, "script", scriptPath)
}

// RunTask is not implemented; it returns [ErrWinRMUnsupported].
func (*WinRMTransport) RunTask(target *Target, task *Task, _ map[string]any) Result {
	return winrmResult(target, "task", task.Name)
}

// Upload is not implemented; it returns [ErrWinRMUnsupported].
func (*WinRMTransport) Upload(target *Target, _, dst string) Result {
	return winrmResult(target, "upload", dst)
}
