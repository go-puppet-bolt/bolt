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
//     [Step], [Executor.RunYAMLPlan]); and Puppet-language (.pp) plans, run
//     through github.com/go-puppet/puppet with the run_task / run_command /
//     run_script / get_targets / apply plan functions dispatched to real
//     targets ([Executor.RunPuppetPlan]).
//   - Transports ([Transport]): a host-local transport ([LocalTransport]) driven
//     through an injectable [CommandRunner] seam; a full SSH transport
//     ([SSHTransport], pure-Go over golang.org/x/crypto/ssh) that honours the
//     target's config.ssh (user, port, key/password auth, host-key-check,
//     run-as/sudo, tty, tmpdir) and uploads-then-runs scripts and tasks; and a
//     full WinRM transport ([WinRMTransport], pure-Go WS-Management/MS-WSMV over
//     net/http with basic, NTLM-negotiate and TLS-client-certificate auth) that
//     honours config.winrm and uploads-then-runs scripts and tasks on Windows.
//   - apply blocks and the YAML `resources` step: the manifest is compiled to a
//     catalog via github.com/go-puppet/puppet and an apply [ResultSet] is
//     produced ([Executor.ApplyCatalog]).
//   - An executor that runs a command, script or task across a set of targets,
//     collecting a per-target [Result] into a [ResultSet].
//
// # Scope and boundaries
//
// The following are honestly bounded rather than silently capped:
//
//   - apply execution: [Executor.ApplyCatalog] compiles the catalog and reports
//     what would be enforced (resource references and count) per target. It does
//     not remotely enforce resources — real enforcement needs a Puppet agent on
//     the target (Bolt's apply_prep model), which is out of scope for the
//     agentless core.
//   - WinRM Kerberos/CredSSP authentication: only basic, NTLM-negotiate and
//     TLS-client-certificate auth are implemented (transport "basic",
//     "negotiate" and "ssl"). Kerberos ("realm") is rejected with a clear error.
//   - PuppetDB and other plugin resolvers (`_plugin` inventory references).
//
// Everything here is pure Go with no cgo, so it cross-compiles to and runs on
// every 64-bit Go target and links into a static binary by default. Non-stdlib
// dependencies are all pure Go: github.com/go-ruby-yaml/yaml (inventory/plan
// YAML), golang.org/x/crypto/ssh (the ssh transport),
// github.com/Azure/go-ntlmssp (WinRM NTLM negotiate) and
// github.com/go-puppet/puppet (the .pp plan evaluator and catalog compiler).
package bolt
