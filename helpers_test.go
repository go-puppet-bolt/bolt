// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

// fakeRunner is a deterministic CommandRunner for tests: it records every call
// and delegates to resp (or returns a zero-exit empty result when resp is nil).
type fakeRunner struct {
	calls []fakeCall
	resp  func(name string, args []string, stdin string) (string, string, int, error)
}

type fakeCall struct {
	name  string
	args  []string
	stdin string
}

func (f *fakeRunner) Run(name string, args []string, stdin string) (string, string, int, error) {
	f.calls = append(f.calls, fakeCall{name, args, stdin})
	if f.resp != nil {
		return f.resp(name, args, stdin)
	}
	return "", "", 0, nil
}

// fakeCopier is a deterministic FileCopier for tests.
type fakeCopier struct {
	err   error
	calls [][2]string
}

func (f *fakeCopier) Copy(src, dst string) error {
	f.calls = append(f.calls, [2]string{src, dst})
	return f.err
}

// localWith builds a LocalTransport driven by the given runner.
func localWith(r CommandRunner) *LocalTransport {
	return &LocalTransport{Runner: r, Copier: &fakeCopier{}}
}
