// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-puppet/puppet/catalog"
)

// fakeTransport is a deterministic Transport for plan-dispatch tests. When fail
// is set every action reports a non-zero exit so run-failure paths trigger.
type fakeTransport struct {
	fail     bool
	commands []string
	scripts  []string
	tasks    []string
	uploads  [][2]string
}

func (f *fakeTransport) code() int {
	if f.fail {
		return 1
	}
	return 0
}

func (f *fakeTransport) RunCommand(t *Target, command string) Result {
	f.commands = append(f.commands, command)
	return Result{Target: t.Name, Action: "command", Object: command,
		Value: map[string]any{"stdout": "ok", "exit_code": f.code()}}
}

func (f *fakeTransport) RunScript(t *Target, path string, args []string) Result {
	f.scripts = append(f.scripts, path+" "+strings.Join(args, " "))
	return Result{Target: t.Name, Action: "script", Object: path,
		Value: map[string]any{"exit_code": f.code()}}
}

func (f *fakeTransport) RunTask(t *Target, task *Task, params map[string]any) Result {
	f.tasks = append(f.tasks, task.Name)
	return Result{Target: t.Name, Action: "task", Object: task.Name,
		Value: map[string]any{"exit_code": f.code()}}
}

func (f *fakeTransport) Upload(t *Target, src, dst string) Result {
	f.uploads = append(f.uploads, [2]string{src, dst})
	return Result{Target: t.Name, Action: "upload", Object: dst}
}

func TestRunPuppetPlanCommand(t *testing.T) {
	ft := &fakeTransport{}
	e := &Executor{Transport: ft}
	src := `plan test::main(String $node) {
  notice("running")
  return run_command("echo hi", $node)
}`
	res, err := e.RunPuppetPlan(src, "test::main", map[string]any{"node": "n1"})
	if err != nil {
		t.Fatalf("plan error: %v", err)
	}
	rs, ok := res.Value.([]any)
	if !ok || len(rs) != 1 {
		t.Fatalf("return value: %#v", res.Value)
	}
	got := rs[0].(map[string]any)
	if got["status"] != "success" || got["target"] != "n1" {
		t.Fatalf("result hash: %#v", got)
	}
	if len(ft.commands) != 1 || ft.commands[0] != "echo hi" {
		t.Fatalf("commands: %#v", ft.commands)
	}
	if len(res.Messages) != 1 || res.Messages[0] != "running" {
		t.Fatalf("messages: %#v", res.Messages)
	}
}

func TestRunPuppetPlanScript(t *testing.T) {
	ft := &fakeTransport{}
	e := &Executor{Transport: ft}
	src := `plan test::s(String $node) {
  return run_script("/opt/s.sh", $node, {"arguments" => ["a", "b"]})
}`
	if _, err := e.RunPuppetPlan(src, "test::s", map[string]any{"node": "n1"}); err != nil {
		t.Fatalf("plan error: %v", err)
	}
	if len(ft.scripts) != 1 || !strings.Contains(ft.scripts[0], "/opt/s.sh a b") {
		t.Fatalf("scripts: %#v", ft.scripts)
	}
}

func TestRunPuppetPlanTask(t *testing.T) {
	ft := &fakeTransport{}
	e := &Executor{
		Transport:  ft,
		TaskLoader: func(name string) (*Task, error) { return &Task{Name: name, File: "/bin/" + name}, nil },
	}
	src := `plan test::t(String $node) {
  return run_task("pkg::install", $node, {"name" => "nginx"})
}`
	if _, err := e.RunPuppetPlan(src, "test::t", map[string]any{"node": "n1"}); err != nil {
		t.Fatalf("plan error: %v", err)
	}
	if len(ft.tasks) != 1 || ft.tasks[0] != "pkg::install" {
		t.Fatalf("tasks: %#v", ft.tasks)
	}
}

func TestRunPuppetPlanTaskNoLoader(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	src := `plan test::t(String $node) { return run_task("pkg", $node) }`
	_, err := e.RunPuppetPlan(src, "test::t", map[string]any{"node": "n1"})
	if err == nil || !strings.Contains(err.Error(), "no task loader") {
		t.Fatalf("want no-loader error, got %v", err)
	}
}

func TestRunPuppetPlanTaskLoaderError(t *testing.T) {
	e := &Executor{
		Transport:  &fakeTransport{},
		TaskLoader: func(string) (*Task, error) { return nil, errors.New("not found") },
	}
	src := `plan test::t(String $node) { return run_task("pkg", $node) }`
	_, err := e.RunPuppetPlan(src, "test::t", map[string]any{"node": "n1"})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want loader error, got %v", err)
	}
}

func TestRunPuppetPlanTaskValidationError(t *testing.T) {
	md := &TaskMetadata{Parameters: map[string]TaskParameter{"name": {Type: "String"}}}
	e := &Executor{
		Transport:  &fakeTransport{},
		TaskLoader: func(name string) (*Task, error) { return &Task{Name: name, File: "/bin/x", Metadata: md}, nil },
	}
	src := `plan test::t(String $node) { return run_task("pkg", $node, {"bogus" => 1}) }`
	_, err := e.RunPuppetPlan(src, "test::t", map[string]any{"node": "n1"})
	if err == nil || !strings.Contains(err.Error(), "unknown parameter") {
		t.Fatalf("want validation error, got %v", err)
	}
}

func TestRunPuppetPlanGetTargets(t *testing.T) {
	ft := &fakeTransport{}
	e := &Executor{Transport: ft}
	src := `plan test::g() {
  $ts = get_targets("web1")
  return run_command("uptime", $ts)
}`
	if _, err := e.RunPuppetPlan(src, "test::g", nil); err != nil {
		t.Fatalf("plan error: %v", err)
	}
	if len(ft.commands) != 1 {
		t.Fatalf("commands: %#v", ft.commands)
	}
}

func TestRunPuppetPlanApply(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	src := `plan test::a(String $node) {
  return apply($node) {
    file { "/tmp/x": ensure => "present" }
    package { "nginx": ensure => "installed" }
  }
}`
	res, err := e.RunPuppetPlan(src, "test::a", map[string]any{"node": "n1"})
	if err != nil {
		t.Fatalf("plan error: %v", err)
	}
	rs := res.Value.([]any)
	report := rs[0].(map[string]any)["value"].(map[string]any)["report"].(map[string]any)
	if report["resource_count"].(int) != 2 {
		t.Fatalf("resource_count: %#v", report)
	}
}

func TestRunPuppetPlanRunFailure(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{fail: true}}
	src := `plan test::f(String $node) { return run_command("boom", $node) }`
	_, err := e.RunPuppetPlan(src, "test::f", map[string]any{"node": "n1"})
	if err == nil || !strings.Contains(err.Error(), "failed on 1 of 1") {
		t.Fatalf("want run failure, got %v", err)
	}
}

func TestRunPuppetPlanParseError(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	if _, err := e.RunPuppetPlan("plan {{{ bad", "x", nil); err == nil {
		t.Fatal("want parse error")
	}
}

func TestRunPuppetPlanUnknownPlan(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	src := `plan test::main() { return 1 }`
	if _, err := e.RunPuppetPlan(src, "does::not::exist", nil); err == nil {
		t.Fatal("want unknown-plan error")
	}
}

// --- unit-level tests for the adapter helpers ---

func TestSpecsFromValue(t *testing.T) {
	cases := []struct {
		in   any
		want []string
	}{
		{"a", []string{"a"}},
		{[]any{"a", "b"}, []string{"a", "b"}},
		{[]string{"c"}, []string{"c"}},
		{map[string]any{"uri": "u1"}, []string{"u1"}},
		{map[string]any{"name": "n1"}, []string{"n1"}},
		{map[string]any{"other": "x"}, nil},
		{42, nil},
	}
	for _, c := range cases {
		got := specsFromValue(c.in)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("specsFromValue(%#v) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestGetTargetsEmpty(t *testing.T) {
	a := planExecAdapter{&Executor{Transport: &fakeTransport{}}}
	if _, err := a.GetTargets(42); err == nil {
		t.Fatal("want empty-spec error")
	}
}

func TestResultValueVariants(t *testing.T) {
	ok := resultValue(Result{Target: "t", Action: "command", Object: "c",
		Value: map[string]any{"exit_code": 0}})
	if ok["status"] != "success" {
		t.Fatalf("ok status: %#v", ok)
	}
	if _, has := ok["error"]; has {
		t.Fatal("success should have no error key")
	}
	bad := resultValue(Result{Target: "t", Action: "task", Object: "x", Err: errors.New("boom")})
	if bad["status"] != "failure" || bad["error"] != "boom" {
		t.Fatalf("failure hash: %#v", bad)
	}
	if _, has := bad["value"]; has {
		t.Fatal("nil value should be omitted")
	}
}

func TestApplyCatalogEmpty(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	rs := e.ApplyCatalog([]*Target{{Name: "n1"}}, catalog.New("empty"))
	if rs.Ok() {
		t.Fatal("empty catalog should not be Ok")
	}
	r, _ := rs.Find("n1")
	if r.Err == nil || !strings.Contains(r.Err.Error(), "empty catalog") {
		t.Fatalf("want empty-catalog error, got %#v", r)
	}
}

func TestResourcesToCatalog(t *testing.T) {
	items := []any{
		map[string]any{"type": "file", "title": "/tmp/a", "parameters": map[string]any{"ensure": "present"}},
		map[string]any{"type": "package", "title": "nginx"},
	}
	cat, err := resourcesToCatalog("apply", items)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(cat.Resources()) != 2 {
		t.Fatalf("resources: %d", len(cat.Resources()))
	}
}

func TestResourcesToCatalogErrors(t *testing.T) {
	cases := map[string][]any{
		"not a mapping": {42},
		"missing type":  {map[string]any{"title": "x"}},
		"missing title": {map[string]any{"type": "file"}},
		"bad params":    {map[string]any{"type": "file", "title": "x", "parameters": 5}},
		"duplicate": {
			map[string]any{"type": "file", "title": "x"},
			map[string]any{"type": "file", "title": "x"},
		},
	}
	for name, items := range cases {
		if _, err := resourcesToCatalog("apply", items); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}

func TestMessagesFromLogsEmpty(t *testing.T) {
	if messagesFromLogs(nil) != nil {
		t.Fatal("empty logs => nil messages")
	}
}

// TestYAMLResourcesStepApply exercises the YAML `resources` step through the
// executor, which now compiles a catalog and applies it.
func TestYAMLResourcesStepApply(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	doc := "steps:\n" +
		"  - name: web\n" +
		"    targets: n1\n" +
		"    resources:\n" +
		"      - type: package\n" +
		"        title: nginx\n"
	p, err := ParsePlan([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.RunYAMLPlan(p, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_ = res
}

func TestYAMLResourcesStepEmptyFails(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	// Unnamed step (name fallback) with an empty catalog (apply-failure branch).
	doc := "steps:\n  - targets: n1\n    resources: []\n"
	p, err := ParsePlan([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.RunYAMLPlan(p, nil); err == nil || !strings.Contains(err.Error(), "apply failed") {
		t.Fatalf("want apply-failed error, got %v", err)
	}
}

func TestYAMLResourcesStepBadResource(t *testing.T) {
	e := &Executor{Transport: &fakeTransport{}}
	doc := "steps:\n  - targets: n1\n    resources:\n      - type: package\n"
	p, err := ParsePlan([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	// missing title => resourcesToCatalog error
	if _, err := e.RunYAMLPlan(p, nil); err == nil {
		t.Fatal("want resource error")
	}
}
