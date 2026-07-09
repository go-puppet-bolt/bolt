// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"testing"
)

func TestResultOkAndExitCode(t *testing.T) {
	// zero exit => ok
	r := Result{Value: map[string]any{"exit_code": 0}}
	if !r.Ok() {
		t.Fatal("zero exit should be ok")
	}
	if c, ok := r.ExitCode(); !ok || c != 0 {
		t.Fatalf("exit code = %d,%v", c, ok)
	}
	// non-zero exit => not ok
	r = Result{Value: map[string]any{"exit_code": 2}}
	if r.Ok() {
		t.Fatal("non-zero exit should not be ok")
	}
	// transport error => not ok
	r = Result{Err: errors.New("boom")}
	if r.Ok() || r.Error() == nil {
		t.Fatal("error result")
	}
	// no exit code and no error => ok
	r = Result{Value: map[string]any{"_output": "hi"}}
	if !r.Ok() {
		t.Fatal("no exit code should be ok")
	}
	// nil value
	r = Result{}
	if _, ok := r.ExitCode(); ok {
		t.Fatal("nil value should have no exit code")
	}
	if !r.Ok() {
		t.Fatal("empty result ok")
	}
	// exit_code present but wrong type
	r = Result{Value: map[string]any{"exit_code": "x"}}
	if _, ok := r.ExitCode(); ok {
		t.Fatal("string exit code should not parse")
	}
	if !r.Ok() { // no parseable exit code, no error => ok
		t.Fatal("unparseable exit code => ok")
	}
}

func TestResultSet(t *testing.T) {
	empty := NewResultSet()
	if !empty.Empty() || empty.Count() != 0 || !empty.Ok() {
		t.Fatal("empty set")
	}

	ok1 := Result{Target: "a", Value: map[string]any{"exit_code": 0}}
	bad1 := Result{Target: "b", Value: map[string]any{"exit_code": 1}}
	rs := NewResultSet(ok1, bad1)

	if rs.Count() != 2 || rs.Empty() {
		t.Fatal("count/empty")
	}
	if rs.Ok() {
		t.Fatal("set with failure should not be ok")
	}
	if rs.OkSet().Count() != 1 || rs.ErrorSet().Count() != 1 {
		t.Fatalf("ok/error split: %d/%d", rs.OkSet().Count(), rs.ErrorSet().Count())
	}
	if got := rs.Names(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("names = %v", got)
	}
	if r, ok := rs.Find("b"); !ok || r.Target != "b" {
		t.Fatal("find existing")
	}
	if _, ok := rs.Find("zzz"); ok {
		t.Fatal("find missing")
	}
	if len(rs.Results()) != 2 {
		t.Fatal("results copy")
	}

	allOk := NewResultSet(ok1)
	if !allOk.Ok() {
		t.Fatal("all-ok set")
	}
}
