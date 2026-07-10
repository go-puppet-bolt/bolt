// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"testing"
)

func TestWinRMTransportStub(t *testing.T) {
	var tr Transport = NewWinRMTransport()
	tgt := &Target{Name: "win1"}
	results := []Result{
		tr.RunCommand(tgt, "dir"),
		tr.RunScript(tgt, "c:\\s.ps1", []string{"a"}),
		tr.RunTask(tgt, &Task{Name: "pkg"}, map[string]any{"x": 1}),
		tr.Upload(tgt, "local", "c:\\dst"),
	}
	for _, r := range results {
		if r.Ok() || !errors.Is(r.Err, ErrWinRMUnsupported) {
			t.Fatalf("want ErrWinRMUnsupported, got %#v", r)
		}
		if r.Target != "win1" {
			t.Fatalf("target = %q", r.Target)
		}
	}
}
