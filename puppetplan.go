// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"fmt"

	"github.com/go-puppet/puppet/catalog"
	"github.com/go-puppet/puppet/eval"
)

// RunPuppetPlan runs a Puppet-language (.pp) plan. src is the plan source
// (`plan name(...) { ... }`); planName is the fully-qualified plan to invoke;
// params are its arguments. The plan's run_task / run_command / run_script /
// get_targets / apply functions are dispatched through this executor's
// [Transport] and [Inventory] against real targets, so a `.pp` plan orchestrates
// exactly like a YAML plan does.
//
// It returns the plan's return value plus any messages logged by notice()/
// warning()/… during the run. Task steps require a [Executor.TaskLoader]; a
// plan that calls run_task without one fails with a descriptive error.
func (e *Executor) RunPuppetPlan(src, planName string, params map[string]any) (PlanResult, error) {
	v, logs, err := eval.EvalPlanString(src, planName, params, eval.WithPlanExecutor(planExecAdapter{e}))
	if err != nil {
		return PlanResult{}, err
	}
	return PlanResult{Value: v, Messages: messagesFromLogs(logs)}, nil
}

// messagesFromLogs projects evaluator log entries to plan messages.
func messagesFromLogs(logs []eval.LogEntry) []string {
	if len(logs) == 0 {
		return nil
	}
	out := make([]string, len(logs))
	for i, l := range logs {
		out[i] = l.Message
	}
	return out
}

// planExecAdapter wires an [Executor] into github.com/go-puppet/puppet's
// eval.PlanExecutor seam so `.pp` plan functions reach Bolt's transports.
type planExecAdapter struct{ e *Executor }

// RunCommand runs command on the resolved targets, returning a ResultSet value.
func (a planExecAdapter) RunCommand(command string, targets []string) (eval.Value, error) {
	ts := a.e.targetsFromSpecs(targets)
	rs := a.e.RunCommand(ts, command)
	return resultSetValue(rs), runFailure("command", command, rs)
}

// RunScript uploads and runs script with args on the resolved targets.
func (a planExecAdapter) RunScript(script string, targets []string, args []any) (eval.Value, error) {
	ts := a.e.targetsFromSpecs(targets)
	sargs := make([]string, len(args))
	for i, v := range args {
		sargs[i] = scalarString(v)
	}
	rs := a.e.RunScript(ts, script, sargs)
	return resultSetValue(rs), runFailure("script", script, rs)
}

// RunTask loads task by name, validates params and runs it on the targets.
func (a planExecAdapter) RunTask(task string, targets []string, params map[string]any) (eval.Value, error) {
	if a.e.TaskLoader == nil {
		return nil, fmt.Errorf("run_task(%q): no task loader configured", task)
	}
	loaded, err := a.e.TaskLoader(task)
	if err != nil {
		return nil, fmt.Errorf("run_task(%q): %w", task, err)
	}
	ts := a.e.targetsFromSpecs(targets)
	rs, err := a.e.RunTask(ts, loaded, params)
	if err != nil {
		return nil, fmt.Errorf("run_task(%q): %w", task, err)
	}
	return resultSetValue(rs), runFailure("task", task, rs)
}

// GetTargets resolves a target spec to Target hashes the plan can pass around.
func (a planExecAdapter) GetTargets(spec eval.Value) (eval.Value, error) {
	specs := specsFromValue(spec)
	if len(specs) == 0 {
		return nil, fmt.Errorf("get_targets: no targets in %#v", spec)
	}
	ts := a.e.targetsFromSpecs(specs)
	out := make([]any, len(ts))
	for i, t := range ts {
		out[i] = targetValue(t)
	}
	return out, nil
}

// ApplyCatalog applies a compiled catalog to the targets, returning an apply
// ResultSet value. See [Executor.ApplyCatalog] for the execution boundary.
func (a planExecAdapter) ApplyCatalog(targets []string, cat *catalog.Catalog) (eval.Value, error) {
	ts := a.e.targetsFromSpecs(targets)
	rs := a.e.ApplyCatalog(ts, cat)
	return resultSetValue(rs), runFailure("apply", "catalog", rs)
}

// targetsFromSpecs turns target-spec strings into [Target]s via the inventory
// (when configured) or ad-hoc targets otherwise.
func (e *Executor) targetsFromSpecs(specs []string) []*Target {
	out := make([]*Target, len(specs))
	for i, s := range specs {
		out[i] = e.targetFor(s)
	}
	return out
}

// ApplyCatalog applies cat to each target and returns a per-target [ResultSet].
//
// Execution boundary: this pure-Go port compiles the catalog (done by
// github.com/go-puppet/puppet before this point) and produces an apply result
// describing what would be enforced — the resource references and count — for
// each target. It does not remotely enforce resources: real enforcement needs a
// Puppet agent on the target (Bolt's apply_prep model), which is out of scope
// for the agentless core. The ResultSet is Ok when the catalog is non-empty.
func (e *Executor) ApplyCatalog(targets []*Target, cat *catalog.Catalog) ResultSet {
	refs := make([]any, 0, len(cat.Resources()))
	for _, r := range cat.Resources() {
		refs = append(refs, r.Ref())
	}
	rs := make([]Result, 0, len(targets))
	for _, t := range targets {
		report := map[string]any{
			"resources":      refs,
			"resource_count": len(refs),
			"status":         "compiled",
			"catalog":        cat.JSON(),
		}
		res := Result{Target: t.Name, Action: "apply", Object: "catalog",
			Value: map[string]any{"report": report}}
		if len(refs) == 0 {
			res.Err = fmt.Errorf("apply: empty catalog for target %q", t.Name)
		}
		rs = append(rs, res)
	}
	return ResultSet{results: rs}
}

// runFailure reports the standard plan error when any target's result failed.
func runFailure(verb, object string, rs ResultSet) error {
	if rs.Ok() {
		return nil
	}
	return fmt.Errorf("run_%s(%q) failed on %d of %d targets", verb, object, rs.ErrorSet().Count(), rs.Count())
}

// resultSetValue renders a [ResultSet] as the Array-of-Hashes value a plan
// function returns, mirroring Bolt's ResultSet data shape.
func resultSetValue(rs ResultSet) eval.Value {
	out := make([]any, 0, rs.Count())
	for _, r := range rs.Results() {
		out = append(out, resultValue(r))
	}
	return out
}

// resultValue renders one [Result] as a Bolt-style result Hash.
func resultValue(r Result) map[string]any {
	status := "success"
	if !r.Ok() {
		status = "failure"
	}
	h := map[string]any{
		"target": r.Target,
		"action": r.Action,
		"object": r.Object,
		"status": status,
	}
	if r.Value != nil {
		h["value"] = r.Value
	}
	if r.Err != nil {
		h["error"] = r.Err.Error()
	}
	return h
}

// targetValue renders a [Target] as a Target Hash for get_targets.
func targetValue(t *Target) map[string]any {
	return map[string]any{"name": t.Name, "uri": t.URI}
}

// specsFromValue coerces a get_targets argument (String, Array, or Target Hash)
// into target-spec strings.
func specsFromValue(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, specsFromValue(e)...)
		}
		return out
	case []string:
		return x
	case map[string]any:
		if s, ok := asString(x["uri"]); ok && s != "" {
			return []string{s}
		}
		if s, ok := asString(x["name"]); ok && s != "" {
			return []string{s}
		}
	}
	return nil
}

// resourcesToCatalog builds a catalog from a YAML `resources` step's list. Each
// item is a mapping with `type`, `title` and optional `parameters`.
func resourcesToCatalog(name string, items []any) (*catalog.Catalog, error) {
	cat := catalog.New(name)
	for i, item := range items {
		m, ok := asMap(item)
		if !ok {
			return nil, fmt.Errorf("resource %d: must be a mapping", i)
		}
		typ, err := reqString(m, "type")
		if err != nil {
			return nil, fmt.Errorf("resource %d: %w", i, err)
		}
		title, err := reqString(m, "title")
		if err != nil {
			return nil, fmt.Errorf("resource %d: %w", i, err)
		}
		params, err := optMap(m, "parameters")
		if err != nil {
			return nil, fmt.Errorf("resource %d: %w", i, err)
		}
		r := &catalog.Resource{Type: typ, Title: title, Parameters: params}
		if err := cat.Add(r); err != nil {
			return nil, fmt.Errorf("resource %d: %w", i, err)
		}
	}
	return cat, nil
}
