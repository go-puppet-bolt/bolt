// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

// Result is the outcome of one action (command, script, task or upload) on one
// target, mirroring Bolt's Result. Value holds the structured output
// (stdout / stderr / exit_code for a command, or the task's own JSON output);
// Err is set when the action could not run at all (e.g. the transport failed)
// as opposed to running and exiting non-zero.
type Result struct {
	Target string
	Action string // "command" | "script" | "task" | "upload"
	Object string // the command line, script path or task name
	Value  map[string]any
	Err    error
}

// Ok reports whether the action ran and succeeded: no transport error and,
// when an exit code is present, a zero exit code.
func (r Result) Ok() bool {
	if r.Err != nil {
		return false
	}
	if code, present := r.exitCode(); present {
		return code == 0
	}
	return true
}

// Error returns the transport error, if any.
func (r Result) Error() error { return r.Err }

// ExitCode returns the action's exit code and whether one was recorded.
func (r Result) ExitCode() (int, bool) { return r.exitCode() }

func (r Result) exitCode() (int, bool) {
	if r.Value == nil {
		return 0, false
	}
	v, ok := r.Value["exit_code"]
	if !ok {
		return 0, false
	}
	code, ok := asInt(v)
	return code, ok
}

// ResultSet aggregates the per-target [Result]s of running one action across
// several targets.
type ResultSet struct {
	results []Result
}

// NewResultSet builds a ResultSet from results.
func NewResultSet(results ...Result) ResultSet {
	return ResultSet{results: results}
}

// Results returns the underlying results in target order.
func (rs ResultSet) Results() []Result {
	out := make([]Result, len(rs.results))
	copy(out, rs.results)
	return out
}

// Count returns the number of results.
func (rs ResultSet) Count() int { return len(rs.results) }

// Empty reports whether the set has no results.
func (rs ResultSet) Empty() bool { return len(rs.results) == 0 }

// Ok reports whether every result in the set succeeded. An empty set is Ok.
func (rs ResultSet) Ok() bool {
	for _, r := range rs.results {
		if !r.Ok() {
			return false
		}
	}
	return true
}

// OkSet returns the subset of results that succeeded.
func (rs ResultSet) OkSet() ResultSet {
	var out []Result
	for _, r := range rs.results {
		if r.Ok() {
			out = append(out, r)
		}
	}
	return ResultSet{results: out}
}

// ErrorSet returns the subset of results that failed.
func (rs ResultSet) ErrorSet() ResultSet {
	var out []Result
	for _, r := range rs.results {
		if !r.Ok() {
			out = append(out, r)
		}
	}
	return ResultSet{results: out}
}

// Names returns the target names in the set, in order.
func (rs ResultSet) Names() []string {
	out := make([]string, len(rs.results))
	for i, r := range rs.results {
		out[i] = r.Target
	}
	return out
}

// Find returns the result for the named target and whether it was present.
func (rs ResultSet) Find(target string) (Result, bool) {
	for _, r := range rs.results {
		if r.Target == target {
			return r, true
		}
	}
	return Result{}, false
}

// PlanResult is the outcome of running a plan: its return value plus any
// messages emitted by message steps.
type PlanResult struct {
	Value    any
	Messages []string
}
