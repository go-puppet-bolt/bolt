// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import "testing"

// Reference methodology: Puppet Bolt is Ruby (MRI). Its equivalent operations
// run through the Ruby interpreter and, for `.pp` plans and apply blocks, the
// Puppet compiler — so a like-for-like wall-clock comparison requires a Bolt
// install and is dominated by interpreter start-up and per-step Ruby object
// churn (tens of milliseconds per step is typical for `bolt plan run`). These
// benchmarks measure the pure-Go core in isolation (no process spawn: the
// transport is a fake), so they report the orchestration overhead this port
// adds on top of the transport itself — the quantity that must stay small
// relative to real remote round-trips. Run with:
//
//	go test -bench=. -benchmem ./...

// benchYAMLPlan is a small multi-step YAML plan reused across benchmarks.
var benchYAMLPlan = []byte(`
parameters:
  node:
    type: String
steps:
  - command: echo one
    targets: $node
  - command: echo two
    targets: $node
  - command: echo three
    targets: $node
  - eval: done
    name: last
return: $last
`)

func BenchmarkYAMLPlanDispatch(b *testing.B) {
	p, err := ParsePlan(benchYAMLPlan)
	if err != nil {
		b.Fatal(err)
	}
	e := &Executor{Transport: &fakeTransport{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.RunYAMLPlan(p, map[string]any{"node": "n1"}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPuppetPlanDispatch(b *testing.B) {
	e := &Executor{Transport: &fakeTransport{}}
	src := `plan bench(String $node) {
  run_command("echo one", $node)
  run_command("echo two", $node)
  run_command("echo three", $node)
  return "done"
}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.RunPuppetPlan(src, "bench", map[string]any{"node": "n1"}); err != nil {
			b.Fatal(err)
		}
	}
}

var benchInventory = []byte(`
version: 2
groups:
  - name: web
    targets:
      - uri: web1.example.com
      - uri: web2.example.com
      - uri: web3.example.com
    config:
      ssh:
        user: deploy
  - name: db
    targets:
      - uri: db1.example.com
    config:
      ssh:
        user: postgres
`)

func BenchmarkInventoryParse(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseInventory(benchInventory); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInventoryResolution(b *testing.B) {
	inv, err := ParseInventory(benchInventory)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ts, err := TargetsForQuery(inv, "web,db")
		if err != nil {
			b.Fatal(err)
		}
		for _, t := range ts {
			_ = t.EffectiveConfig()
		}
	}
}
