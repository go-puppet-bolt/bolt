# bolt — go-puppet-bolt

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)
[![CGO](https://img.shields.io/badge/cgo-0-informational)](#)

A pragmatic, **pure-Go (CGO=0)** port of the core of [Puppet Bolt](https://www.puppet.com/docs/bolt/latest/bolt.html) —
the agentless orchestrator. It parses Bolt inventory, tasks and plans, and runs
them through a pluggable transport, with no Ruby runtime and no cgo, so it
cross-compiles to every 64-bit Go target and links into a static binary.

Non-stdlib dependencies are all pure Go:
[`github.com/go-ruby-yaml/yaml`](https://github.com/go-ruby-yaml/yaml) (inventory
/ plan YAML), [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh)
(the SSH transport) and [`github.com/go-puppet/puppet`](https://github.com/go-puppet/puppet)
(the `.pp` plan evaluator and catalog compiler).

## What it does

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
  steps, with `targets`, per-step `parameters`, and a `return` expression.
- **Puppet-language (`.pp`) plans** — `plan name(...) { ... }` manifests run
  through `github.com/go-puppet/puppet`; the `run_task` / `run_command` /
  `run_script` / `get_targets` / `apply` plan functions dispatch through this
  executor's transports and inventory to real targets (`RunPuppetPlan`).
- **Transports** — a `Transport` interface with a host-local transport
  (`LocalTransport`) and a full **SSH transport** (`SSHTransport`, pure-Go over
  `golang.org/x/crypto/ssh`): key/password auth, `host-key-check`, `run-as`
  (sudo), `tty`, and upload-then-run for scripts and tasks, honouring
  `config.ssh`.
- **`apply` blocks & `resources` steps** — the manifest is compiled to a catalog
  via `go-puppet/puppet` and an apply `ResultSet` is produced (`ApplyCatalog`).
- **Execution** — an `Executor` runs a command, script or task across a set of
  targets, collecting a per-target `Result` into a `ResultSet`.

## Boundaries (documented, not silently capped)

| Area | Status |
| --- | --- |
| SSH transport | **Done.** Pure-Go over `x/crypto/ssh`; tested end-to-end against an in-process SSH server (auth, exec, upload, run-as, exit codes). |
| WinRM transport | **Documented stub** (`WinRMTransport`). Every method returns `ErrWinRMUnsupported`. WinRM's WS-Management (SOAP) protocol + Negotiate/NTLM auth are a substantial, separately-testable undertaking; use the SSH transport on Windows (OpenSSH-for-Windows). |
| `apply` execution | **Compile + report.** `ApplyCatalog` compiles the catalog and reports the resources it would enforce per target; it does not remotely enforce resources (that needs a Puppet agent — Bolt's `apply_prep` model — out of scope for the agentless core). |
| PuppetDB / `_plugin` inventory references | Not implemented. |
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

Over SSH, running a Puppet-language plan:

```go
exec := &bolt.Executor{
    Transport:  bolt.NewSSHTransport(),
    Inventory:  inv,
    TaskLoader: loadTask, // resolve a task by name
}
src := `plan deploy(TargetSpec $nodes) {
  run_command('systemctl stop app', $nodes)
  run_task('app::deploy', $nodes, {'version' => '1.2.3'})
  return apply($nodes) {
    service { 'app': ensure => running, enable => true }
  }
}`
res, err := exec.RunPuppetPlan(src, "deploy", map[string]any{"nodes": "web"})
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
