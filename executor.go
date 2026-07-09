// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"errors"
	"fmt"
	"strings"
)

// ErrApplyUnsupported is returned by the plan runner for a `resources` step:
// applying a resource catalog to a target is deferred in v1.
var ErrApplyUnsupported = errors.New("bolt: apply / resources steps are not supported in v1")

// Executor runs actions on targets through a [Transport] and executes YAML
// plans. Inventory (optional) resolves plan target-specs into [Target]s;
// TaskLoader and PlanLoader resolve the task and sub-plan steps of a plan.
type Executor struct {
	Transport Transport
	Inventory *Inventory
	// TaskLoader resolves a task-step's task by name. Required to run task steps.
	TaskLoader func(name string) (*Task, error)
	// PlanLoader resolves a plan-step's sub-plan by name. Required to run plan
	// steps.
	PlanLoader func(name string) (*YAMLPlan, error)
}

// RunCommand runs command on every target, collecting a [ResultSet].
func (e *Executor) RunCommand(targets []*Target, command string) ResultSet {
	rs := make([]Result, 0, len(targets))
	for _, t := range targets {
		rs = append(rs, e.Transport.RunCommand(t, command))
	}
	return ResultSet{results: rs}
}

// RunScript runs the script at path with args on every target.
func (e *Executor) RunScript(targets []*Target, path string, args []string) ResultSet {
	rs := make([]Result, 0, len(targets))
	for _, t := range targets {
		rs = append(rs, e.Transport.RunScript(t, path, args))
	}
	return ResultSet{results: rs}
}

// RunTask validates params against the task's declared parameters, then runs the
// task on every target. A validation error is returned before anything runs.
func (e *Executor) RunTask(targets []*Target, task *Task, params map[string]any) (ResultSet, error) {
	if err := task.ValidateParams(params); err != nil {
		return ResultSet{}, err
	}
	rs := make([]Result, 0, len(targets))
	for _, t := range targets {
		rs = append(rs, e.Transport.RunTask(t, task, params))
	}
	return ResultSet{results: rs}, nil
}

// targetFor turns a target-spec string into a [Target], using the inventory
// when one is configured and an ad-hoc target otherwise.
func (e *Executor) targetFor(spec string) *Target {
	if e.Inventory != nil {
		return e.Inventory.GetOrCreateTarget(spec)
	}
	return &Target{Name: spec, URI: spec}
}

// RunYAMLPlan executes a parsed YAML plan with the given arguments. It binds
// parameters (applying defaults and type-checking), runs each step in order,
// binds each named step's result into the plan scope, and returns the resolved
// `return` expression plus any message-step output.
func (e *Executor) RunYAMLPlan(p *YAMLPlan, params map[string]any) (PlanResult, error) {
	scope, err := bindPlanParams(p, params)
	if err != nil {
		return PlanResult{}, err
	}
	var messages []string
	for i, step := range p.Steps {
		val, msgs, err := e.runStep(step, scope)
		if err != nil {
			return PlanResult{}, fmt.Errorf("step %d (%s): %w", i, step.Kind, err)
		}
		messages = append(messages, msgs...)
		if step.Name != "" {
			scope[step.Name] = val
		}
	}
	res := PlanResult{Messages: messages}
	if p.HasReturn {
		rv, err := resolveScalar(p.Return, scope)
		if err != nil {
			return PlanResult{}, fmt.Errorf("return: %w", err)
		}
		res.Value = rv
	}
	return res, nil
}

// bindPlanParams builds the initial plan scope: every provided argument must be
// a declared parameter; declared parameters absent from the arguments fall back
// to their default (else error); provided values are type-checked.
func bindPlanParams(p *YAMLPlan, params map[string]any) (map[string]any, error) {
	for name := range params {
		if _, ok := p.Parameters[name]; !ok {
			return nil, fmt.Errorf("unknown plan parameter %q", name)
		}
	}
	scope := map[string]any{}
	for _, name := range p.ParamOrder {
		pp := p.Parameters[name]
		v, provided := params[name]
		if !provided {
			if pp.HasDefault {
				scope[name] = pp.Default
				continue
			}
			if isOptionalType(pp.Type) {
				scope[name] = nil
				continue
			}
			return nil, fmt.Errorf("missing required plan parameter %q", name)
		}
		if pp.Type != "" {
			if err := checkType(pp.Type, v); err != nil {
				return nil, fmt.Errorf("plan parameter %q: %w", name, err)
			}
		}
		scope[name] = v
	}
	return scope, nil
}

// runStep executes one step, returning the value to bind to the step's name,
// any messages it produced, and an error.
func (e *Executor) runStep(step Step, scope map[string]any) (any, []string, error) {
	switch step.Kind {
	case StepCommand:
		return e.runTargetedStep(step, scope, func(ts []*Target) ResultSet {
			return e.RunCommand(ts, step.Command)
		})
	case StepScript:
		args, err := resolveArgs(step.Arguments, scope)
		if err != nil {
			return nil, nil, err
		}
		return e.runTargetedStep(step, scope, func(ts []*Target) ResultSet {
			return e.RunScript(ts, step.Script, args)
		})
	case StepTask:
		return e.runTaskStep(step, scope)
	case StepEval:
		v, err := resolveScalar(step.Eval, scope)
		return v, nil, err
	case StepMessage:
		v, err := resolveScalar(step.Message, scope)
		if err != nil {
			return nil, nil, err
		}
		msg := scalarString(v)
		return msg, []string{msg}, nil
	case StepPlan:
		return e.runPlanStep(step, scope)
	default: // StepResources
		return nil, nil, ErrApplyUnsupported
	}
}

// runTargetedStep resolves the step's targets, runs the action, and fails the
// plan if any target's result failed.
func (e *Executor) runTargetedStep(step Step, scope map[string]any, run func([]*Target) ResultSet) (any, []string, error) {
	targets, err := e.resolveTargets(step.Targets, scope)
	if err != nil {
		return nil, nil, err
	}
	rs := run(targets)
	if !rs.Ok() {
		return rs, nil, fmt.Errorf("action failed on %d of %d targets", rs.ErrorSet().Count(), rs.Count())
	}
	return rs, nil, nil
}

func (e *Executor) runTaskStep(step Step, scope map[string]any) (any, []string, error) {
	if e.TaskLoader == nil {
		return nil, nil, fmt.Errorf("cannot run task %q: no task loader configured", step.Task)
	}
	task, err := e.TaskLoader(step.Task)
	if err != nil {
		return nil, nil, fmt.Errorf("loading task %q: %w", step.Task, err)
	}
	params, err := resolveParams(step.Parameters, scope)
	if err != nil {
		return nil, nil, err
	}
	targets, err := e.resolveTargets(step.Targets, scope)
	if err != nil {
		return nil, nil, err
	}
	rs, err := e.RunTask(targets, task, params)
	if err != nil {
		return nil, nil, err
	}
	if !rs.Ok() {
		return rs, nil, fmt.Errorf("task %q failed on %d of %d targets", step.Task, rs.ErrorSet().Count(), rs.Count())
	}
	return rs, nil, nil
}

func (e *Executor) runPlanStep(step Step, scope map[string]any) (any, []string, error) {
	if e.PlanLoader == nil {
		return nil, nil, fmt.Errorf("cannot run sub-plan %q: no plan loader configured", step.Plan)
	}
	sub, err := e.PlanLoader(step.Plan)
	if err != nil {
		return nil, nil, fmt.Errorf("loading plan %q: %w", step.Plan, err)
	}
	params, err := resolveParams(step.Parameters, scope)
	if err != nil {
		return nil, nil, err
	}
	res, err := e.RunYAMLPlan(sub, params)
	if err != nil {
		return nil, nil, err
	}
	return res.Value, res.Messages, nil
}

// resolveTargets turns a step's targets field into concrete [Target]s.
func (e *Executor) resolveTargets(raw any, scope map[string]any) ([]*Target, error) {
	specs, err := resolveTargetSpecs(raw, scope)
	if err != nil {
		return nil, err
	}
	targets := make([]*Target, 0, len(specs))
	for _, s := range specs {
		targets = append(targets, e.targetFor(s))
	}
	return targets, nil
}

// resolveTargetSpecs flattens a targets field (string, list, or "$var"
// references to either) into a list of target-spec strings.
func resolveTargetSpecs(raw any, scope map[string]any) ([]string, error) {
	if raw == nil {
		return nil, fmt.Errorf("step requires targets")
	}
	var out []string
	var add func(v any) error
	add = func(v any) error {
		switch t := v.(type) {
		case string:
			if strings.HasPrefix(t, "$") {
				val, ok := scope[strings.TrimPrefix(t, "$")]
				if !ok {
					return fmt.Errorf("undefined variable %s", t)
				}
				return add(val)
			}
			out = append(out, t)
			return nil
		case []any:
			for _, e := range t {
				if err := add(e); err != nil {
					return err
				}
			}
			return nil
		case []string:
			out = append(out, t...)
			return nil
		default:
			return fmt.Errorf("invalid target spec %#v", v)
		}
	}
	if err := add(raw); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("step resolved to no targets")
	}
	return out, nil
}

// resolveScalar resolves a single plan value: a "$name" string yields the
// bound variable (error if undefined); anything else is returned verbatim.
func resolveScalar(v any, scope map[string]any) (any, error) {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "$") {
		return v, nil
	}
	name := strings.TrimPrefix(s, "$")
	val, ok := scope[name]
	if !ok {
		return nil, fmt.Errorf("undefined variable %s", s)
	}
	return val, nil
}

// resolveParams resolves each value of a parameter mapping through resolveScalar.
func resolveParams(in map[string]any, scope map[string]any) (map[string]any, error) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		rv, err := resolveScalar(v, scope)
		if err != nil {
			return nil, err
		}
		out[k] = rv
	}
	return out, nil
}

// resolveArgs resolves each element of a script's arguments list.
func resolveArgs(in []any, scope map[string]any) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, v := range in {
		rv, err := resolveScalar(v, scope)
		if err != nil {
			return nil, err
		}
		out = append(out, scalarString(rv))
	}
	return out, nil
}
