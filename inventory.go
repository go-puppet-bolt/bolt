// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"fmt"
	"path"
	"sort"
	"strings"
)

// Inventory is a parsed Bolt inventory (inventory.yaml v2): a tree of groups
// rooted at a synthetic "all" group, plus a registry of the targets they
// reference. Targets are deduplicated by name across the whole inventory, so a
// target listed in several groups is a single [Target] linked to each.
type Inventory struct {
	Version int
	// Root is the implicit top-level "all" group holding the inventory's
	// top-level targets, groups, config, facts, vars and features.
	Root *Group

	targets map[string]*Target // by canonical name
	order   []*Target          // registration order
}

// Group is a named collection of targets and nested subgroups, carrying config,
// facts, vars and features inherited by the targets beneath it.
type Group struct {
	Name     string
	Targets  []*Target
	Groups   []*Group
	Config   map[string]any
	Facts    map[string]any
	Vars     map[string]any
	Features []string

	parent *Group
	inv    *Inventory
}

// Target is a single node the orchestrator can act on. Config, Facts, Vars and
// Features hold the target's own declared data; the Effective* methods resolve
// the values seen after group inheritance.
type Target struct {
	Name     string
	URI      string
	Aliases  []string
	Config   map[string]any
	Facts    map[string]any
	Vars     map[string]any
	Features []string

	inv    *Inventory
	groups []*Group // groups that directly list this target
}

// ParseInventory parses an inventory.yaml v2 document.
func ParseInventory(src []byte) (*Inventory, error) {
	v, err := decodeYAML(src)
	if err != nil {
		return nil, err
	}
	if v == nil {
		v = map[string]any{} // an empty document is an empty inventory
	}
	root, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("inventory: top level must be a mapping")
	}
	inv := &Inventory{Version: 2, targets: map[string]*Target{}}
	if rawVer, present := root["version"]; present {
		ver, ok := asInt(rawVer)
		if !ok {
			return nil, fmt.Errorf("inventory: version must be an integer")
		}
		if ver != 2 {
			return nil, fmt.Errorf("inventory: unsupported version %d (only 2 is supported)", ver)
		}
		inv.Version = ver
	}
	g, err := inv.parseGroup("all", root)
	if err != nil {
		return nil, err
	}
	inv.Root = g
	return inv, nil
}

// parseGroup parses a group body (also used for the root document).
func (inv *Inventory) parseGroup(name string, body map[string]any) (*Group, error) {
	g := &Group{Name: name, inv: inv}
	var err error
	if g.Config, err = optMap(body, "config"); err != nil {
		return nil, err
	}
	if g.Facts, err = optMap(body, "facts"); err != nil {
		return nil, err
	}
	if g.Vars, err = optMap(body, "vars"); err != nil {
		return nil, err
	}
	if g.Features, err = optStringList(body, "features"); err != nil {
		return nil, err
	}
	if err := inv.parseGroupTargets(g, body); err != nil {
		return nil, err
	}
	if err := inv.parseSubgroups(g, body); err != nil {
		return nil, err
	}
	return g, nil
}

func (inv *Inventory) parseGroupTargets(g *Group, body map[string]any) error {
	raw, present := body["targets"]
	if !present {
		return nil
	}
	list, ok := asSlice(raw)
	if !ok {
		return fmt.Errorf("group %q: targets must be a sequence", g.Name)
	}
	for _, item := range list {
		t, err := inv.parseTarget(g, item)
		if err != nil {
			return err
		}
		g.Targets = append(g.Targets, t)
	}
	return nil
}

func (inv *Inventory) parseSubgroups(g *Group, body map[string]any) error {
	raw, present := body["groups"]
	if !present {
		return nil
	}
	list, ok := asSlice(raw)
	if !ok {
		return fmt.Errorf("group %q: groups must be a sequence", g.Name)
	}
	for _, item := range list {
		m, ok := asMap(item)
		if !ok {
			return fmt.Errorf("group %q: each subgroup must be a mapping", g.Name)
		}
		nameRaw, present := m["name"]
		if !present {
			return fmt.Errorf("group %q: a subgroup is missing its name", g.Name)
		}
		subName, ok := asString(nameRaw)
		if !ok || subName == "" {
			return fmt.Errorf("group %q: subgroup name must be a non-empty string", g.Name)
		}
		sub, err := inv.parseGroup(subName, m)
		if err != nil {
			return err
		}
		sub.parent = g
		g.Groups = append(g.Groups, sub)
	}
	return nil
}

// parseTarget parses one entry of a group's targets sequence: either a bare
// string (a uri, or a reference to an already-registered target) or a mapping.
func (inv *Inventory) parseTarget(g *Group, item any) (*Target, error) {
	switch it := item.(type) {
	case string:
		if it == "" {
			return nil, fmt.Errorf("group %q: target string must not be empty", g.Name)
		}
		if existing := inv.lookup(it); existing != nil {
			inv.linkTarget(g, existing)
			return existing, nil
		}
		t := &Target{Name: it, URI: it, inv: inv}
		inv.register(t)
		inv.linkTarget(g, t)
		return t, nil
	case map[string]any:
		return inv.parseTargetMap(g, it)
	default:
		return nil, fmt.Errorf("group %q: a target must be a string or mapping", g.Name)
	}
}

func (inv *Inventory) parseTargetMap(g *Group, m map[string]any) (*Target, error) {
	uri, err := optString(m, "uri")
	if err != nil {
		return nil, err
	}
	name, err := optString(m, "name")
	if err != nil {
		return nil, err
	}
	if uri == "" && name == "" {
		return nil, fmt.Errorf("group %q: a target requires at least one of name or uri", g.Name)
	}
	canonical := name
	if canonical == "" {
		canonical = uri
	}
	if existing := inv.lookup(canonical); existing != nil {
		inv.linkTarget(g, existing)
		return existing, nil
	}
	t := &Target{Name: canonical, URI: uri, inv: inv}
	if t.Aliases, err = optTargetAliases(m); err != nil {
		return nil, err
	}
	if t.Config, err = optMap(m, "config"); err != nil {
		return nil, err
	}
	if t.Facts, err = optMap(m, "facts"); err != nil {
		return nil, err
	}
	if t.Vars, err = optMap(m, "vars"); err != nil {
		return nil, err
	}
	if t.Features, err = optStringList(m, "features"); err != nil {
		return nil, err
	}
	for _, a := range t.Aliases {
		if other := inv.lookup(a); other != nil && other != t {
			return nil, fmt.Errorf("target %q: alias %q already refers to target %q", t.Name, a, other.Name)
		}
	}
	inv.register(t)
	inv.linkTarget(g, t)
	return t, nil
}

func (inv *Inventory) register(t *Target) {
	inv.targets[t.Name] = t
	for _, a := range t.Aliases {
		inv.targets[a] = t
	}
	inv.order = append(inv.order, t)
}

func (inv *Inventory) linkTarget(g *Group, t *Target) {
	for _, existing := range t.groups {
		if existing == g {
			return
		}
	}
	t.groups = append(t.groups, g)
}

// lookup resolves a target by canonical name, alias or uri; nil if unknown.
func (inv *Inventory) lookup(key string) *Target {
	if t, ok := inv.targets[key]; ok {
		return t
	}
	for _, t := range inv.order {
		if t.URI == key {
			return t
		}
	}
	return nil
}

// Targets returns every registered target in declaration order.
func (inv *Inventory) Targets() []*Target {
	out := make([]*Target, len(inv.order))
	copy(out, inv.order)
	return out
}

// Target resolves a single target by name, alias or uri.
func (inv *Inventory) Target(key string) (*Target, bool) {
	t := inv.lookup(key)
	return t, t != nil
}

// GetOrCreateTarget resolves a target by name/alias/uri, registering an ad-hoc
// target (attached to no group) when none exists. It is how a plan turns a bare
// target-spec string into a [Target].
func (inv *Inventory) GetOrCreateTarget(spec string) *Target {
	if t := inv.lookup(spec); t != nil {
		return t
	}
	t := &Target{Name: spec, URI: spec, inv: inv}
	inv.register(t)
	return t
}

// Group finds a group by name anywhere in the tree (depth-first, "all"
// included).
func (inv *Inventory) Group(name string) (*Group, bool) {
	var found *Group
	inv.walk(func(g *Group) {
		if found == nil && g.Name == name {
			found = g
		}
	})
	return found, found != nil
}

// walk visits every group depth-first starting at the root.
func (inv *Inventory) walk(fn func(*Group)) {
	var rec func(g *Group)
	rec = func(g *Group) {
		fn(g)
		for _, sub := range g.Groups {
			rec(sub)
		}
	}
	rec(inv.Root)
}

// GroupTargets returns every target in the named group, including those in its
// subgroups, deduplicated in first-seen order.
func (inv *Inventory) GroupTargets(name string) ([]*Target, error) {
	g, ok := inv.Group(name)
	if !ok {
		return nil, fmt.Errorf("unknown group %q", name)
	}
	return g.collectTargets(), nil
}

// collectTargets returns every target in g and its subgroups, deduplicated in
// first-seen order.
func (g *Group) collectTargets() []*Target {
	seen := map[*Target]bool{}
	var out []*Target
	var rec func(g *Group)
	rec = func(g *Group) {
		for _, t := range g.Targets {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
		for _, sub := range g.Groups {
			rec(sub)
		}
	}
	rec(g)
	return out
}

// TargetsForQuery resolves a Bolt-style target query: a comma-separated list of
// group names, target names/aliases/uris, or globs (matched against target
// names with path.Match). Results are deduplicated in first-seen order.
func TargetsForQuery(inv *Inventory, query string) ([]*Target, error) {
	seen := map[*Target]bool{}
	var out []*Target
	add := func(t *Target) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, part := range strings.Split(query, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if g, ok := inv.Group(part); ok {
			for _, t := range g.collectTargets() {
				add(t)
			}
			continue
		}
		if t := inv.lookup(part); t != nil {
			add(t)
			continue
		}
		if strings.ContainsAny(part, "*?[") {
			matched, err := inv.globTargets(part)
			if err != nil {
				return nil, err
			}
			if len(matched) == 0 {
				return nil, fmt.Errorf("no target matches glob %q", part)
			}
			for _, t := range matched {
				add(t)
			}
			continue
		}
		return nil, fmt.Errorf("unknown target or group %q", part)
	}
	return out, nil
}

func (inv *Inventory) globTargets(pattern string) ([]*Target, error) {
	var out []*Target
	for _, t := range inv.order {
		ok, err := path.Match(pattern, t.Name)
		if err != nil {
			return nil, fmt.Errorf("bad glob %q: %w", pattern, err)
		}
		if ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// ancestryGroups returns the groups affecting a target, ordered least-specific
// (the root "all") to most-specific (the deepest group directly listing it).
// Deeper groups therefore override shallower ones during resolution.
func (t *Target) ancestryGroups() []*Group {
	type gd struct {
		g     *Group
		depth int
	}
	var chain []gd
	seen := map[*Group]bool{}
	for _, g := range t.groups {
		for cur := g; cur != nil; cur = cur.parent {
			if seen[cur] {
				continue
			}
			seen[cur] = true
			chain = append(chain, gd{cur, depthOf(cur)})
		}
	}
	sort.SliceStable(chain, func(i, j int) bool { return chain[i].depth < chain[j].depth })
	out := make([]*Group, len(chain))
	for i, c := range chain {
		out[i] = c.g
	}
	return out
}

func depthOf(g *Group) int {
	d := 0
	for cur := g.parent; cur != nil; cur = cur.parent {
		d++
	}
	return d
}

// EffectiveConfig resolves the target's config after group inheritance: group
// data merged from least- to most-specific (deep merge of nested mappings),
// then the target's own config on top.
func (t *Target) EffectiveConfig() map[string]any {
	return t.resolve(func(g *Group) map[string]any { return g.Config }, t.Config)
}

// EffectiveFacts resolves the target's facts after group inheritance.
func (t *Target) EffectiveFacts() map[string]any {
	return t.resolve(func(g *Group) map[string]any { return g.Facts }, t.Facts)
}

// EffectiveVars resolves the target's vars after group inheritance.
func (t *Target) EffectiveVars() map[string]any {
	return t.resolve(func(g *Group) map[string]any { return g.Vars }, t.Vars)
}

func (t *Target) resolve(pick func(*Group) map[string]any, own map[string]any) map[string]any {
	acc := map[string]any{}
	for _, g := range t.ancestryGroups() {
		deepMerge(acc, pick(g))
	}
	deepMerge(acc, own)
	return acc
}

// EffectiveFeatures resolves the union of the target's own features and those of
// every group affecting it, in first-seen order.
func (t *Target) EffectiveFeatures() []string {
	seen := map[string]bool{}
	var out []string
	add := func(fs []string) {
		for _, f := range fs {
			if !seen[f] {
				seen[f] = true
				out = append(out, f)
			}
		}
	}
	for _, g := range t.ancestryGroups() {
		add(g.Features)
	}
	add(t.Features)
	return out
}

// deepMerge merges src into dst in place: nested mappings merge recursively;
// every other value (scalars, sequences) replaces.
func deepMerge(dst, src map[string]any) {
	for k, sv := range src {
		if sm, ok := asMap(sv); ok {
			if dm, ok := asMap(dst[k]); ok {
				deepMerge(dm, sm)
				continue
			}
			nm := map[string]any{}
			deepMerge(nm, sm)
			dst[k] = nm
			continue
		}
		dst[k] = sv
	}
}

// --- small typed-field helpers over a decoded mapping ---

func optMap(m map[string]any, key string) (map[string]any, error) {
	raw, present := m[key]
	if !present {
		return nil, nil
	}
	mm, ok := asMap(raw)
	if !ok {
		return nil, fmt.Errorf("%q must be a mapping", key)
	}
	return mm, nil
}

func optString(m map[string]any, key string) (string, error) {
	raw, present := m[key]
	if !present {
		return "", nil
	}
	s, ok := asString(raw)
	if !ok {
		return "", fmt.Errorf("%q must be a string", key)
	}
	return s, nil
}

func optStringList(m map[string]any, key string) ([]string, error) {
	raw, present := m[key]
	if !present {
		return nil, nil
	}
	list, ok := asStringList(raw)
	if !ok {
		return nil, fmt.Errorf("%q must be a string or list of strings", key)
	}
	return list, nil
}

func optTargetAliases(m map[string]any) ([]string, error) {
	raw, present := m["alias"]
	if !present {
		return nil, nil
	}
	list, ok := asStringList(raw)
	if !ok {
		return nil, fmt.Errorf("alias must be a string or list of strings")
	}
	return list, nil
}
