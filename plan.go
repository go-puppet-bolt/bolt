// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"fmt"
	"sort"
)

// StepKind identifies the action a plan step performs.
type StepKind string

// The supported YAML-plan step kinds.
const (
	StepTask      StepKind = "task"
	StepCommand   StepKind = "command"
	StepScript    StepKind = "script"
	StepEval      StepKind = "eval"
	StepPlan      StepKind = "plan"
	StepResources StepKind = "resources"
	StepMessage   StepKind = "message"
)

// stepActionKeys are the keys that select a step's kind; exactly one must be
// present in a step mapping.
var stepActionKeys = []StepKind{
	StepTask, StepCommand, StepScript, StepEval, StepPlan, StepResources, StepMessage,
}

// YAMLPlan is a parsed Bolt YAML plan (plan.yaml).
type YAMLPlan struct {
	Description string
	Parameters  map[string]PlanParameter
	ParamOrder  []string
	Steps       []Step
	// Return is the plan's return expression (a literal or a "$var" reference),
	// or nil when the plan has no return key.
	Return    any
	HasReturn bool
}

// PlanParameter describes one declared plan parameter.
type PlanParameter struct {
	Type        string
	Description string
	Default     any
	HasDefault  bool
}

// Step is one step of a YAML plan. Only the fields relevant to Kind are set.
type Step struct {
	Name    string
	Kind    StepKind
	Targets any // string, []string, or "$var" — resolved at run time

	Task       string         // Kind == StepTask
	Command    string         // Kind == StepCommand
	Script     string         // Kind == StepScript
	Plan       string         // Kind == StepPlan
	Message    any            // Kind == StepMessage
	Eval       any            // Kind == StepEval
	Parameters map[string]any // task/plan parameters
	Arguments  []any          // script arguments
	Resources  []any          // Kind == StepResources
}

// ParsePlan parses a plan.yaml document.
func ParsePlan(src []byte) (*YAMLPlan, error) {
	v, err := decodeYAML(src)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, fmt.Errorf("plan: document is empty")
	}
	root, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("plan: top level must be a mapping")
	}
	p := &YAMLPlan{}
	if p.Description, err = optString(root, "description"); err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	if err := parsePlanParameters(p, root); err != nil {
		return nil, err
	}
	if err := parsePlanSteps(p, root); err != nil {
		return nil, err
	}
	if ret, present := root["return"]; present {
		p.Return = ret
		p.HasReturn = true
	}
	return p, nil
}

func parsePlanParameters(p *YAMLPlan, root map[string]any) error {
	raw, present := root["parameters"]
	if !present {
		return nil
	}
	pm, ok := asMap(raw)
	if !ok {
		return fmt.Errorf("plan: parameters must be a mapping")
	}
	p.Parameters = make(map[string]PlanParameter, len(pm))
	names := make([]string, 0, len(pm))
	for name := range pm {
		names = append(names, name)
	}
	sort.Strings(names)
	p.ParamOrder = names
	for _, name := range names {
		body, ok := asMap(pm[name])
		if !ok {
			return fmt.Errorf("plan: parameter %q must be a mapping", name)
		}
		pp := PlanParameter{}
		var err error
		if pp.Type, err = optString(body, "type"); err != nil {
			return fmt.Errorf("plan: parameter %q: %w", name, err)
		}
		if pp.Description, err = optString(body, "description"); err != nil {
			return fmt.Errorf("plan: parameter %q: %w", name, err)
		}
		if dv, present := body["default"]; present {
			pp.Default = dv
			pp.HasDefault = true
		}
		p.Parameters[name] = pp
	}
	return nil
}

func parsePlanSteps(p *YAMLPlan, root map[string]any) error {
	raw, present := root["steps"]
	if !present {
		return nil
	}
	list, ok := asSlice(raw)
	if !ok {
		return fmt.Errorf("plan: steps must be a sequence")
	}
	for i, item := range list {
		m, ok := asMap(item)
		if !ok {
			return fmt.Errorf("plan: step %d must be a mapping", i)
		}
		step, err := parseStep(m)
		if err != nil {
			return fmt.Errorf("plan: step %d: %w", i, err)
		}
		p.Steps = append(p.Steps, step)
	}
	return nil
}

func parseStep(m map[string]any) (Step, error) {
	kind, err := stepKind(m)
	if err != nil {
		return Step{}, err
	}
	step := Step{Kind: kind, Targets: m["targets"]}
	if step.Name, err = optString(m, "name"); err != nil {
		return Step{}, err
	}
	switch kind {
	case StepTask:
		if step.Task, err = reqString(m, string(StepTask)); err != nil {
			return Step{}, err
		}
		if step.Parameters, err = optMap(m, "parameters"); err != nil {
			return Step{}, err
		}
	case StepCommand:
		if step.Command, err = reqString(m, string(StepCommand)); err != nil {
			return Step{}, err
		}
	case StepScript:
		if step.Script, err = reqString(m, string(StepScript)); err != nil {
			return Step{}, err
		}
		if raw, present := m["arguments"]; present {
			args, ok := asSlice(raw)
			if !ok {
				return Step{}, fmt.Errorf("arguments must be a sequence")
			}
			step.Arguments = args
		}
	case StepPlan:
		if step.Plan, err = reqString(m, string(StepPlan)); err != nil {
			return Step{}, err
		}
		if step.Parameters, err = optMap(m, "parameters"); err != nil {
			return Step{}, err
		}
	case StepEval:
		step.Eval = m[string(StepEval)]
	case StepMessage:
		step.Message = m[string(StepMessage)]
	case StepResources:
		raw := m[string(StepResources)]
		list, ok := asSlice(raw)
		if !ok {
			return Step{}, fmt.Errorf("resources must be a sequence")
		}
		step.Resources = list
	}
	return step, nil
}

// stepKind determines a step's kind by finding exactly one action key.
func stepKind(m map[string]any) (StepKind, error) {
	var found []StepKind
	for _, k := range stepActionKeys {
		if _, ok := m[string(k)]; ok {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("step has no action key (one of task/command/script/eval/plan/resources/message)")
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("step has conflicting action keys %v", found)
	}
}

func reqString(m map[string]any, key string) (string, error) {
	s, ok := asString(m[key])
	if !ok {
		return "", fmt.Errorf("%q must be a string", key)
	}
	return s, nil
}
