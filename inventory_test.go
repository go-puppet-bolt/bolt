// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"testing"
)

const richInventory = `
version: 2
config:
  transport: local
facts:
  domain: example.com
vars:
  env: base
features:
  - root
targets:
  - top-a
groups:
  - name: web
    config:
      ssh:
        user: deploy
      port: 22
    facts:
      role: web
    vars:
      env: prod
    features:
      - puppet-agent
    targets:
      - uri: web1.example.com
        name: web1
        alias: [w1, wone]
        config:
          ssh:
            user: root
          port: 2222
        facts:
          rack: r1
        vars:
          env: web-override
        features:
          - fast
      - web2.example.com
    groups:
      - name: web-canary
        vars:
          canary: true
        targets:
          - web1
  - name: db
    targets:
      - db1.example.com
`

func mustInventory(t *testing.T, src string) *Inventory {
	t.Helper()
	inv, err := ParseInventory([]byte(src))
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}
	return inv
}

func TestParseInventoryRich(t *testing.T) {
	inv := mustInventory(t, richInventory)
	if inv.Version != 2 {
		t.Fatalf("version %d", inv.Version)
	}
	if len(inv.Root.Groups) != 2 {
		t.Fatalf("root groups %d", len(inv.Root.Groups))
	}
	web1, ok := inv.Target("web1")
	if !ok {
		t.Fatal("web1 missing")
	}
	// alias lookup
	if a, ok := inv.Target("w1"); !ok || a != web1 {
		t.Fatal("alias w1")
	}
	// uri lookup fallthrough
	if a, ok := inv.Target("web2.example.com"); !ok || a.Name != "web2.example.com" {
		t.Fatal("web2 by uri")
	}
	// web1 has name "web1" but uri "web1.example.com": look up by uri hits the
	// URI-scan branch of lookup (uri differs from the registered name).
	if a, ok := inv.Target("web1.example.com"); !ok || a != web1 {
		t.Fatal("web1 by uri")
	}
	if _, ok := inv.Target("nope"); ok {
		t.Fatal("unexpected target")
	}
}

func TestEffectiveResolution(t *testing.T) {
	inv := mustInventory(t, richInventory)
	web1, _ := inv.Target("web1")

	cfg := web1.EffectiveConfig()
	// deep-merged nested map: target ssh.user overrides group; port overridden
	ssh, _ := asMap(cfg["ssh"])
	if ssh["user"] != "root" {
		t.Fatalf("ssh.user = %v", ssh["user"])
	}
	if p, _ := asInt(cfg["port"]); p != 2222 {
		t.Fatalf("port = %v", cfg["port"])
	}
	if cfg["transport"] != "local" { // from root "all"
		t.Fatalf("transport = %v", cfg["transport"])
	}

	facts := web1.EffectiveFacts()
	if facts["role"] != "web" || facts["rack"] != "r1" || facts["domain"] != "example.com" {
		t.Fatalf("facts = %#v", facts)
	}

	vars := web1.EffectiveVars()
	// target override beats group and root; canary from subgroup present
	if vars["env"] != "web-override" {
		t.Fatalf("env = %v", vars["env"])
	}
	if vars["canary"] != true {
		t.Fatalf("canary = %v", vars["canary"])
	}

	feats := web1.EffectiveFeatures()
	want := map[string]bool{"root": true, "puppet-agent": true, "fast": true}
	if len(feats) != len(want) {
		t.Fatalf("features = %#v", feats)
	}
	for _, f := range feats {
		if !want[f] {
			t.Fatalf("unexpected feature %q", f)
		}
	}
}

func TestDeepMergeNewNested(t *testing.T) {
	// group has a scalar where target introduces a nested map => new-map branch
	src := `
version: 2
groups:
  - name: g
    config:
      db: plain
    targets:
      - uri: n1
        config:
          db:
            host: h
`
	inv := mustInventory(t, src)
	n1, _ := inv.Target("n1")
	cfg := n1.EffectiveConfig()
	m, ok := asMap(cfg["db"])
	if !ok || m["host"] != "h" {
		t.Fatalf("db = %#v", cfg["db"])
	}
}

func TestGroupsAndQueries(t *testing.T) {
	inv := mustInventory(t, richInventory)

	if _, ok := inv.Group("web"); !ok {
		t.Fatal("group web")
	}
	if _, ok := inv.Group("ghost"); ok {
		t.Fatal("ghost group")
	}

	ts, err := inv.GroupTargets("web")
	if err != nil {
		t.Fatalf("GroupTargets: %v", err)
	}
	// web1, web2 (web1 also in web-canary but deduped)
	if len(ts) != 2 {
		t.Fatalf("web targets = %d (%v)", len(ts), names(ts))
	}
	if _, err := inv.GroupTargets("ghost"); err == nil {
		t.Fatal("want unknown group error")
	}

	// TargetsForQuery: group + target name + skip empty part
	q, err := TargetsForQuery(inv, "db, web1, ")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(q) != 2 {
		t.Fatalf("query result = %v", names(q))
	}
	// glob
	g, err := TargetsForQuery(inv, "web*")
	if err != nil {
		t.Fatalf("glob query: %v", err)
	}
	if len(g) == 0 {
		t.Fatal("glob matched nothing")
	}
	// glob no match
	if _, err := TargetsForQuery(inv, "zzz*"); err == nil {
		t.Fatal("want glob-no-match error")
	}
	// unknown
	if _, err := TargetsForQuery(inv, "mystery"); err == nil {
		t.Fatal("want unknown error")
	}
	// bad glob pattern
	if _, err := TargetsForQuery(inv, "["); err == nil {
		t.Fatal("want bad glob error")
	}
}

func TestGetOrCreateTargetAndTargets(t *testing.T) {
	inv := mustInventory(t, richInventory)
	before := len(inv.Targets())
	t1 := inv.GetOrCreateTarget("web1") // existing
	if t1.Name != "web1" {
		t.Fatal("existing")
	}
	adhoc := inv.GetOrCreateTarget("brand.new")
	if adhoc.Name != "brand.new" {
		t.Fatal("adhoc")
	}
	if len(inv.Targets()) != before+1 {
		t.Fatal("registry not grown by one")
	}
}

func TestParseInventoryEmptyAndDefaults(t *testing.T) {
	inv := mustInventory(t, "")
	if inv.Version != 2 || len(inv.Targets()) != 0 {
		t.Fatalf("empty inventory: %#v", inv)
	}
}

func TestStringTargetReferenceAcrossGroups(t *testing.T) {
	// web1 defined in group a, referenced by string in group b => single target,
	// linked to both groups (link branch + already-linked branch when repeated).
	src := `
version: 2
groups:
  - name: a
    targets:
      - uri: node1
        name: node1
  - name: b
    targets:
      - node1
      - node1
`
	inv := mustInventory(t, src)
	n1, _ := inv.Target("node1")
	if len(n1.groups) != 2 {
		t.Fatalf("node1 groups = %d", len(n1.groups))
	}
	if len(inv.Targets()) != 1 {
		t.Fatalf("targets = %d", len(inv.Targets()))
	}
}

func TestTargetMapDedupAcrossGroups(t *testing.T) {
	src := `
version: 2
groups:
  - name: a
    targets:
      - name: shared
        uri: shared.host
  - name: b
    targets:
      - name: shared
        uri: shared.host
`
	inv := mustInventory(t, src)
	if len(inv.Targets()) != 1 {
		t.Fatalf("targets = %d", len(inv.Targets()))
	}
}

func TestParseInventoryErrors(t *testing.T) {
	cases := map[string]string{
		"tab":                   "a:\n\tb: 1\n",
		"not a mapping":         "- 1\n- 2\n",
		"version not int":       "version: abc\n",
		"unsupported ver":       "version: 1\n",
		"config not map":        "config: [1]\n",
		"facts not map":         "facts: 5\n",
		"vars not map":          "vars: 5\n",
		"features bad":          "features:\n  k: v\n",
		"targets not seq":       "targets:\n  k: v\n",
		"groups not seq":        "groups: 5\n",
		"subgroup not map":      "groups:\n  - foo\n",
		"subgroup no name":      "groups:\n  - config: {}\n",
		"subgroup empty name":   "groups:\n  - name: ''\n",
		"subgroup name not str": "groups:\n  - name: [1]\n",
		"subgroup bad body":     "groups:\n  - name: g\n    config: 5\n",
		"empty string target":   "targets:\n  - ''\n",
		"target wrong type":     "targets:\n  - 5\n",
		"target uri bad":        "targets:\n  - uri: [1]\n",
		"target name bad":       "targets:\n  - name: [1]\n",
		"target no id":          "targets:\n  - config: {}\n",
		"target alias bad":      "targets:\n  - name: n\n    alias: {a: b}\n",
		"target config bad":     "targets:\n  - name: n\n    config: 5\n",
		"target facts bad":      "targets:\n  - name: n\n    facts: 5\n",
		"target vars bad":       "targets:\n  - name: n\n    vars: 5\n",
		"target features bad":   "targets:\n  - name: n\n    features:\n      k: v\n",
	}
	for name, src := range cases {
		if _, err := ParseInventory([]byte(src)); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

func TestAliasCollision(t *testing.T) {
	src := `
version: 2
targets:
  - name: first
    alias: [dup]
  - name: second
    alias: [dup]
`
	if _, err := ParseInventory([]byte(src)); err == nil {
		t.Fatal("want alias collision error")
	}
}

func TestTargetNoAliasBranch(t *testing.T) {
	// exercises optTargetAliases absent branch
	inv := mustInventory(t, "version: 2\ntargets:\n  - name: solo\n")
	if _, ok := inv.Target("solo"); !ok {
		t.Fatal("solo")
	}
}

func names(ts []*Target) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Name
	}
	return out
}
