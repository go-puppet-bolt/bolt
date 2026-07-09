// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

// Package bolt is a pragmatic, pure-Go (cgo-free) port of the core of Puppet
// Bolt — the agentless orchestrator — covering the pieces that are fully
// deterministic and stdlib-expressible:
//
//   - Inventory (inventory.yaml v2): targets, nested groups, per-group and
//     per-target config / facts / vars / features, target uri / name / alias,
//     effective-value resolution through the group hierarchy, and target
//     selection by name, alias, group or glob ([Inventory], [Group], [Target]).
//   - Tasks: task metadata (the Bolt task *.json shape — typed parameters,
//     input_method, supports_noop, implementations, files) plus validation of a
//     set of arguments against the declared parameter types ([Task],
//     [TaskMetadata], [TaskParameter]).
//   - Plans: YAML plans (plan.yaml — parameters and an ordered list of task /
//     command / script / eval / plan / resources / message steps, targets and a
//     return expression), parsed and executed by a step runner ([YAMLPlan],
//     [Step], [Executor.RunYAMLPlan]).
//   - A transport abstraction ([Transport]) with a host-local transport
//     ([LocalTransport]) driven through an injectable [CommandRunner] seam so it
//     runs deterministically in tests without spawning real processes.
//   - An executor that runs a command, script or task across a set of targets,
//     collecting a per-target [Result] into a [ResultSet].
//
// # Scope and deferrals (v1)
//
// The following are deliberately deferred and documented rather than silently
// capped:
//
//   - SSH and WinRM transports. Only the host-local transport ships; the
//     [Transport] interface is the extension point for remote transports.
//   - Puppet-language (.pp) plans. Running a `plan name(...) { run_task(...) }`
//     manifest needs a Bolt-aware evaluator (a `plan` keyword and the
//     run_task / run_command / apply plan functions), which the pure-Go
//     github.com/go-puppet/puppet catalog compiler does not provide; only YAML
//     plans run here.
//   - apply blocks / the `resources` plan step. Parsed and represented, but
//     applying a resource catalog to a target is not implemented; a resources
//     step returns [ErrApplyUnsupported].
//   - PuppetDB and other plugin resolvers (`_plugin` inventory references).
//
// Everything here is pure Go with no cgo, so it cross-compiles to and runs on
// every 64-bit Go target and links into a static binary by default. The only
// non-stdlib dependency is github.com/go-ruby-yaml/yaml, the fleet's pure-Go
// YAML loader, used to parse inventory and plan documents.
package bolt
