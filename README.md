# bolt — go-puppet-bolt

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)
[![CGO](https://img.shields.io/badge/cgo-0-informational)](#)

A pragmatic, **pure-Go (CGO=0)** port of the core of [Puppet Bolt](https://www.puppet.com/docs/bolt/latest/bolt.html) —
the agentless orchestrator. It parses Bolt inventory, tasks and plans, and runs
them through a pluggable transport, with no Ruby runtime and no cgo, so it
cross-compiles to every 64-bit Go target and links into a static binary.

The only non-stdlib dependency is [`github.com/go-ruby-yaml/yaml`](https://github.com/go-ruby-yaml/yaml),
the fleet's pure-Go YAML loader, used to parse inventory and plan documents.

## What it does (v1)

- **Inventory** (`inventory.yaml` v2) — targets, nested groups, per-group and
  per-target `config` / `facts` / `vars` / `features`, target `uri` / `name` /
  `alias`, effective-value resolution through the group hierarchy (deep merge,
  closest group wins, target overrides all), and target selection by name,
  alias, group or glob (`TargetsForQuery`).
- **Tasks** — parses the Bolt task `*.json` metadata shape (typed `parameters`
  with `type` / `description` / `sensitive` / `default`, `input_method`,
  `supports_noop`, `implementations`, `files`) and validates arguments against
  the declared parameter types (a pragmatic subset of the Puppet type system).
- **YAML plans** (`plan.yaml`) — `parameters` and an ordered list of
  `task` / `command` / `script` / `eval` / `plan` / `resources` / `message`
  steps, with `targets`, per-step `parameters`, and a `return` expression,
  parsed and executed by a step runner.
- **Transports** — a `Transport` interface with a host-local transport
  (`LocalTransport`) driven through an injectable `CommandRunner` seam.
- **Execution** — an `Executor` runs a command, script or task across a set of
  targets, collecting a per-target `Result` into a `ResultSet`.

## Deferred (documented, not silently capped)

| Area | Status |
| --- | --- |
| SSH / WinRM transports | **Deferred.** Only `LocalTransport` ships; `Transport` is the extension point. |
| Puppet-language (`.pp`) plans | **Deferred.** Needs a Bolt-aware evaluator (`plan` keyword + `run_task`/`apply` plan functions); the pure-Go `go-puppet/puppet` catalog compiler does not provide it. Only YAML plans run. |
| `apply` blocks / `resources` steps | **Deferred.** Parsed and represented; a `resources` step returns `ErrApplyUnsupported`. |
| PuppetDB / `_plugin` inventory references | **Deferred.** |
| Full pcore type parser | Basic type checks only (String/Integer/Float/Numeric/Boolean/Array/Hash/Optional/Enum/Pattern/Variant/…). |

## Example

```go
inv, _ := bolt.ParseInventory(invBytes)
targets, _ := bolt.TargetsForQuery(inv, "web,db1.example.com")

exec := &bolt.Executor{
    Transport: bolt.NewLocalTransport(),
    Inventory: inv,
}
rs := exec.RunCommand(targets, "uptime")
fmt.Println(rs.Ok(), rs.Names())
```

## Tests & coverage

Pure Go, stdlib test tooling, deterministic (no real processes, no network):

```sh
go test -race -coverprofile=cover.out ./...
go tool cover -func=cover.out   # 100.0%
```

CI builds and tests on all six 64-bit arches
(amd64, arm64, riscv64, loong64, ppc64le, s390x).

## License

BSD-3-Clause © the go-puppet-bolt/bolt authors.
