// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"testing"
)

// newExec builds an Executor over a LocalTransport driven by resp, with task
// and plan loaders wired to the given functions.
func newExec(resp func(string, []string, string) (string, string, int, error)) *Executor {
	return &Executor{Transport: localWith(&fakeRunner{resp: resp})}
}

func okRunner(string, []string, string) (string, string, int, error) { return "", "", 0, nil }
func failRunner(string, []string, string) (string, string, int, error) {
	return "", "boom", 1, nil
}

func targets(names ...string) []*Target {
	ts := make([]*Target, len(names))
	for i, n := range names {
		ts[i] = &Target{Name: n}
	}
	return ts
}

func TestExecutorRunCommandScript(t *testing.T) {
	e := newExec(okRunner)
	rs := e.RunCommand(targets("a", "b"), "ls")
	if rs.Count() != 2 || !rs.Ok() {
		t.Fatalf("command set: %#v", rs)
	}
	rs = e.RunScript(targets("a"), "/s.sh", []string{"x"})
	if rs.Count() != 1 || !rs.Ok() {
		t.Fatalf("script set: %#v", rs)
	}
}

func TestExecutorRunTask(t *testing.T) {
	e := newExec(okRunner)
	task := &Task{Name: "t", File: "/bin/t"}
	rs, err := e.RunTask(targets("a"), task, nil)
	if err != nil || rs.Count() != 1 {
		t.Fatalf("run task: %v %#v", err, rs)
	}

	// validation error short-circuits before running
	bad := &Task{Name: "t", Metadata: &TaskMetadata{Parameters: map[string]TaskParameter{
		"req": {Type: "String"},
	}}}
	if _, err := e.RunTask(targets("a"), bad, nil); err == nil {
		t.Fatal("want validation error")
	}
}

func TestTargetFor(t *testing.T) {
	inv := mustInventory(t, richInventory)
	e := &Executor{Inventory: inv}
	if e.targetFor("web1").Name != "web1" {
		t.Fatal("inventory-backed")
	}
	e2 := &Executor{}
	if e2.targetFor("adhoc").Name != "adhoc" {
		t.Fatal("ad-hoc")
	}
}

func TestBindPlanParams(t *testing.T) {
	p := &YAMLPlan{
		Parameters: map[string]PlanParameter{
			"name":  {Type: "String"},
			"count": {Type: "Integer", Default: 5, HasDefault: true},
			"opt":   {Type: "Optional[String]"},
		},
		ParamOrder: []string{"count", "name", "opt"},
	}
	scope, err := bindPlanParams(p, map[string]any{"name": "x"})
	if err != nil {
		t.Fatalf("bind: %v", err)
	}
	if scope["name"] != "x" || scope["count"] != 5 || scope["opt"] != nil {
		t.Fatalf("scope = %#v", scope)
	}

	if _, err := bindPlanParams(p, map[string]any{"bogus": 1}); err == nil {
		t.Fatal("want unknown-param error")
	}
	if _, err := bindPlanParams(p, map[string]any{}); err == nil {
		t.Fatal("want missing-required error")
	}
	if _, err := bindPlanParams(p, map[string]any{"name": 42}); err == nil {
		t.Fatal("want type error")
	}
}

const runnablePlan = `
parameters:
  nodes:
    type: TargetSpec
steps:
  - name: c
    command: echo hi
    targets: $nodes
  - name: s
    script: /s.sh
    targets: [n1]
    arguments: [a, $c]
  - name: t
    task: mytask
    targets: $nodes
    parameters:
      x: 1
  - name: ev
    eval: $nodes
  - name: msg
    message: done
  - name: sub
    plan: other
return: $c
`

func TestRunYAMLPlanHappy(t *testing.T) {
	e := newExec(okRunner)
	e.TaskLoader = func(name string) (*Task, error) {
		return &Task{Name: name, File: "/bin/" + name}, nil
	}
	e.PlanLoader = func(name string) (*YAMLPlan, error) {
		sub, _ := ParsePlan([]byte("steps:\n  - message: from-sub\n"))
		return sub, nil
	}
	p, err := ParsePlan([]byte(runnablePlan))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	res, err := e.RunYAMLPlan(p, map[string]any{"nodes": []any{"n1", "n2"}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Messages) != 2 || res.Messages[0] != "done" || res.Messages[1] != "from-sub" {
		t.Fatalf("messages = %#v", res.Messages)
	}
	if _, ok := res.Value.(ResultSet); !ok {
		t.Fatalf("return value type %T", res.Value)
	}
}

func TestRunYAMLPlanBindError(t *testing.T) {
	e := newExec(okRunner)
	p := &YAMLPlan{
		Parameters: map[string]PlanParameter{"n": {Type: "String"}},
		ParamOrder: []string{"n"},
	}
	if _, err := e.RunYAMLPlan(p, nil); err == nil {
		t.Fatal("want bind error")
	}
}

func TestRunYAMLPlanStepError(t *testing.T) {
	e := newExec(failRunner) // command exits non-zero
	p, _ := ParsePlan([]byte("steps:\n  - command: nope\n    targets: [n1]\n"))
	if _, err := e.RunYAMLPlan(p, nil); err == nil {
		t.Fatal("want step failure error")
	}
}

func TestRunYAMLPlanReturnError(t *testing.T) {
	e := newExec(okRunner)
	p, _ := ParsePlan([]byte("steps: []\nreturn: $missing\n"))
	if _, err := e.RunYAMLPlan(p, nil); err == nil {
		t.Fatal("want return-resolve error")
	}
}

func TestRunStepKinds(t *testing.T) {
	e := newExec(okRunner)
	scope := map[string]any{"v": "val"}

	// eval undefined var
	if _, _, err := e.runStep(Step{Kind: StepEval, Eval: "$missing"}, scope); err == nil {
		t.Fatal("eval undefined")
	}
	// message resolve error
	if _, _, err := e.runStep(Step{Kind: StepMessage, Message: "$missing"}, scope); err == nil {
		t.Fatal("message undefined")
	}
	// message ok
	v, msgs, err := e.runStep(Step{Kind: StepMessage, Message: "$v"}, scope)
	if err != nil || v != "val" || len(msgs) != 1 {
		t.Fatalf("message ok: %v %v %v", v, msgs, err)
	}
	// resources step with no targets => targets error
	if _, _, err := e.runStep(Step{Kind: StepResources}, scope); err == nil {
		t.Fatal("resources without targets should error")
	}
	// script with bad argument var
	if _, _, err := e.runStep(Step{Kind: StepScript, Script: "/s", Targets: "n1", Arguments: []any{"$missing"}}, scope); err == nil {
		t.Fatal("script bad arg")
	}
}

func TestRunTargetedStepTargetsError(t *testing.T) {
	e := newExec(okRunner)
	// command step with no targets
	if _, _, err := e.runStep(Step{Kind: StepCommand, Command: "x"}, map[string]any{}); err == nil {
		t.Fatal("want missing-targets error")
	}
}

func TestRunTaskStep(t *testing.T) {
	scope := map[string]any{}

	// no loader
	e := newExec(okRunner)
	if _, _, err := e.runTaskStep(Step{Task: "t", Targets: "n1"}, scope); err == nil {
		t.Fatal("no loader")
	}

	// loader error
	e.TaskLoader = func(string) (*Task, error) { return nil, errors.New("nope") }
	if _, _, err := e.runTaskStep(Step{Task: "t", Targets: "n1"}, scope); err == nil {
		t.Fatal("loader error")
	}

	// resolveParams error
	e.TaskLoader = func(name string) (*Task, error) { return &Task{Name: name, File: "/b"}, nil }
	if _, _, err := e.runTaskStep(Step{Task: "t", Targets: "n1", Parameters: map[string]any{"p": "$x"}}, scope); err == nil {
		t.Fatal("param resolve error")
	}

	// resolveTargets error
	if _, _, err := e.runTaskStep(Step{Task: "t"}, scope); err == nil {
		t.Fatal("targets error")
	}

	// validation error
	e.TaskLoader = func(name string) (*Task, error) {
		return &Task{Name: name, Metadata: &TaskMetadata{Parameters: map[string]TaskParameter{"req": {Type: "String"}}}}, nil
	}
	if _, _, err := e.runTaskStep(Step{Task: "t", Targets: "n1"}, scope); err == nil {
		t.Fatal("validation error")
	}

	// run failure (non-zero)
	ef := newExec(failRunner)
	ef.TaskLoader = func(name string) (*Task, error) { return &Task{Name: name, File: "/b"}, nil }
	if _, _, err := ef.runTaskStep(Step{Task: "t", Targets: "n1"}, scope); err == nil {
		t.Fatal("run failure")
	}

	// ok
	eok := newExec(okRunner)
	eok.TaskLoader = func(name string) (*Task, error) { return &Task{Name: name, File: "/b"}, nil }
	if _, _, err := eok.runTaskStep(Step{Task: "t", Targets: "n1"}, scope); err != nil {
		t.Fatalf("ok task step: %v", err)
	}
}

func TestRunPlanStep(t *testing.T) {
	scope := map[string]any{}
	e := newExec(okRunner)

	// no loader
	if _, _, err := e.runPlanStep(Step{Plan: "p"}, scope); err == nil {
		t.Fatal("no loader")
	}
	// loader error
	e.PlanLoader = func(string) (*YAMLPlan, error) { return nil, errors.New("nope") }
	if _, _, err := e.runPlanStep(Step{Plan: "p"}, scope); err == nil {
		t.Fatal("loader error")
	}
	// resolveParams error
	e.PlanLoader = func(string) (*YAMLPlan, error) { return &YAMLPlan{}, nil }
	if _, _, err := e.runPlanStep(Step{Plan: "p", Parameters: map[string]any{"a": "$missing"}}, scope); err == nil {
		t.Fatal("param resolve error")
	}
	// sub-plan run error (unknown param passed to empty sub-plan)
	e.PlanLoader = func(string) (*YAMLPlan, error) { return &YAMLPlan{}, nil }
	if _, _, err := e.runPlanStep(Step{Plan: "p", Parameters: map[string]any{"a": "x"}}, scope); err == nil {
		t.Fatal("sub-plan run error")
	}
	// ok
	e.PlanLoader = func(string) (*YAMLPlan, error) {
		sub, _ := ParsePlan([]byte("steps:\n  - message: hi\n"))
		return sub, nil
	}
	_, msgs, err := e.runPlanStep(Step{Plan: "p"}, scope)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("ok sub-plan: %v %v", msgs, err)
	}
}

func TestResolveTargetSpecs(t *testing.T) {
	scope := map[string]any{
		"one":   "n1",
		"many":  []any{"n2", "n3"},
		"strs":  []string{"n4"},
		"empty": []any{},
	}
	// nil raw
	if _, err := resolveTargetSpecs(nil, scope); err == nil {
		t.Fatal("nil raw")
	}
	// literal string
	if s, err := resolveTargetSpecs("host", scope); err != nil || len(s) != 1 {
		t.Fatalf("literal: %v %v", s, err)
	}
	// $var undefined
	if _, err := resolveTargetSpecs("$nope", scope); err == nil {
		t.Fatal("undefined var")
	}
	// $var string
	if s, err := resolveTargetSpecs("$one", scope); err != nil || s[0] != "n1" {
		t.Fatalf("var string: %v %v", s, err)
	}
	// []any
	if s, err := resolveTargetSpecs([]any{"a", "$one"}, scope); err != nil || len(s) != 2 {
		t.Fatalf("list: %v %v", s, err)
	}
	// []any with invalid element
	if _, err := resolveTargetSpecs([]any{5}, scope); err == nil {
		t.Fatal("invalid element")
	}
	// $var []string
	if s, err := resolveTargetSpecs("$strs", scope); err != nil || s[0] != "n4" {
		t.Fatalf("var []string: %v %v", s, err)
	}
	// invalid top-level type
	if _, err := resolveTargetSpecs(5, scope); err == nil {
		t.Fatal("invalid type")
	}
	// resolves to no targets
	if _, err := resolveTargetSpecs("$empty", scope); err == nil {
		t.Fatal("empty resolution")
	}
}

func TestResolveScalarAndParams(t *testing.T) {
	scope := map[string]any{"x": 7}
	if v, _ := resolveScalar(5, scope); v != 5 {
		t.Fatal("non-string")
	}
	if v, _ := resolveScalar("plain", scope); v != "plain" {
		t.Fatal("plain string")
	}
	if v, _ := resolveScalar("$x", scope); v != 7 {
		t.Fatal("var ref")
	}
	if _, err := resolveScalar("$missing", scope); err == nil {
		t.Fatal("undefined")
	}

	// resolveParams
	if m, err := resolveParams(nil, scope); err != nil || m != nil {
		t.Fatal("nil params")
	}
	if _, err := resolveParams(map[string]any{"a": "$missing"}, scope); err == nil {
		t.Fatal("param error")
	}
	if m, err := resolveParams(map[string]any{"a": "$x"}, scope); err != nil || m["a"] != 7 {
		t.Fatalf("param ok: %v %v", m, err)
	}

	// resolveArgs
	if _, err := resolveArgs([]any{"$missing"}, scope); err == nil {
		t.Fatal("arg error")
	}
	if a, err := resolveArgs([]any{"lit", "$x"}, scope); err != nil || a[1] != "7" {
		t.Fatalf("args ok: %v %v", a, err)
	}
}
