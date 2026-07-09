// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import "testing"

const richPlan = `
description: deploy the app
parameters:
  nodes:
    type: TargetSpec
    description: the nodes
  version:
    type: String
    default: "1.0"
steps:
  - name: pkg
    task: package
    targets: $nodes
    parameters:
      name: app
      action: install
  - name: restart
    command: systemctl restart app
    targets: $nodes
  - name: seed
    script: /scripts/seed.sh
    targets: $nodes
    arguments: [--force, $version]
  - name: note
    eval: $version
  - name: hello
    message: "deployment done"
  - name: sub
    plan: app::migrate
    parameters:
      to: $version
return: $restart
`

func TestParsePlanRich(t *testing.T) {
	p, err := ParsePlan([]byte(richPlan))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Description != "deploy the app" {
		t.Fatalf("desc = %q", p.Description)
	}
	if len(p.Parameters) != 2 || len(p.ParamOrder) != 2 {
		t.Fatalf("params: %#v", p.Parameters)
	}
	if p.Parameters["version"].Default != "1.0" || !p.Parameters["version"].HasDefault {
		t.Fatalf("version default: %#v", p.Parameters["version"])
	}
	if len(p.Steps) != 6 {
		t.Fatalf("steps = %d", len(p.Steps))
	}
	kinds := []StepKind{StepTask, StepCommand, StepScript, StepEval, StepMessage, StepPlan}
	for i, k := range kinds {
		if p.Steps[i].Kind != k {
			t.Fatalf("step %d kind = %s want %s", i, p.Steps[i].Kind, k)
		}
	}
	if !p.HasReturn || p.Return != "$restart" {
		t.Fatalf("return: %v %v", p.HasReturn, p.Return)
	}
	if len(p.Steps[2].Arguments) != 2 {
		t.Fatalf("script args: %#v", p.Steps[2].Arguments)
	}
}

func TestParsePlanResourcesStep(t *testing.T) {
	p, err := ParsePlan([]byte("steps:\n  - resources:\n      - type: package\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Steps[0].Kind != StepResources || len(p.Steps[0].Resources) != 1 {
		t.Fatalf("resources step: %#v", p.Steps[0])
	}
}

func TestParsePlanMinimal(t *testing.T) {
	p, err := ParsePlan([]byte("steps: []\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Steps) != 0 || p.HasReturn {
		t.Fatalf("minimal: %#v", p)
	}
}

func TestParsePlanErrors(t *testing.T) {
	cases := map[string]string{
		"tab":                "a:\n\tb: 1\n",
		"empty doc":          "",
		"not mapping":        "- 1\n",
		"description bad":    "description: [1]\n",
		"parameters not map": "parameters: 5\n",
		"param body not map": "parameters:\n  p: 5\n",
		"param type bad":     "parameters:\n  p:\n    type: [1]\n",
		"param desc bad":     "parameters:\n  p:\n    description: [1]\n",
		"steps not seq":      "steps: 5\n",
		"step not map":       "steps:\n  - 5\n",
		"step no action":     "steps:\n  - name: x\n",
		"step conflict":      "steps:\n  - task: a\n    command: b\n",
		"step name bad":      "steps:\n  - command: c\n    name: [1]\n",
		"task not string":    "steps:\n  - task: [1]\n",
		"task params bad":    "steps:\n  - task: t\n    parameters: 5\n",
		"command not string": "steps:\n  - command: [1]\n",
		"script not string":  "steps:\n  - script: [1]\n",
		"script args bad":    "steps:\n  - script: s\n    arguments: 5\n",
		"plan not string":    "steps:\n  - plan: [1]\n",
		"plan params bad":    "steps:\n  - plan: p\n    parameters: 5\n",
		"resources not seq":  "steps:\n  - resources: 5\n",
	}
	for name, src := range cases {
		if _, err := ParsePlan([]byte(src)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestParsePlanParamWithDefaultOnly(t *testing.T) {
	p, err := ParsePlan([]byte("parameters:\n  x:\n    default: 7\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Parameters["x"].HasDefault {
		t.Fatal("default not captured")
	}
}
