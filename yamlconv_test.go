// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"math/big"
	"testing"

	yaml "github.com/go-ruby-yaml/yaml"
)

func TestDecodeYAML(t *testing.T) {
	v, err := decodeYAML([]byte("a: 1\nb:\n  - x\n  - y\n"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	m, ok := asMap(v)
	if !ok {
		t.Fatalf("want map, got %T", v)
	}
	if got, _ := asInt(m["a"]); got != 1 {
		t.Fatalf("a = %v", m["a"])
	}
	s, ok := asSlice(m["b"])
	if !ok || len(s) != 2 {
		t.Fatalf("b = %#v", m["b"])
	}
}

func TestDecodeYAMLError(t *testing.T) {
	if _, err := decodeYAML([]byte("a:\n\tb: 1\n")); err == nil {
		t.Fatal("want error for tab indentation")
	}
}

func TestKeyString(t *testing.T) {
	if got := keyString("k"); got != "k" {
		t.Fatalf("string key: %q", got)
	}
	if got := keyString(yaml.Symbol("sym")); got != "sym" {
		t.Fatalf("symbol key: %q", got)
	}
	if got := keyString(int64(7)); got != "7" {
		t.Fatalf("int key: %q", got)
	}
}

func TestScalarAccessors(t *testing.T) {
	if _, ok := asMap(5); ok {
		t.Fatal("asMap non-map")
	}
	if _, ok := asSlice(5); ok {
		t.Fatal("asSlice non-slice")
	}
	if s, ok := asString("x"); !ok || s != "x" {
		t.Fatal("asString")
	}
	if _, ok := asString(5); ok {
		t.Fatal("asString non-string")
	}
	if b, ok := asBool(true); !ok || !b {
		t.Fatal("asBool")
	}
	if _, ok := asBool("x"); ok {
		t.Fatal("asBool non-bool")
	}
}

func TestAsStringList(t *testing.T) {
	if l, ok := asStringList("a"); !ok || len(l) != 1 || l[0] != "a" {
		t.Fatalf("single: %#v", l)
	}
	if l, ok := asStringList([]any{"a", "b"}); !ok || len(l) != 2 {
		t.Fatalf("list: %#v", l)
	}
	if _, ok := asStringList([]any{"a", 3}); ok {
		t.Fatal("list with non-string")
	}
	if _, ok := asStringList(42); ok {
		t.Fatal("non-list")
	}
}

func TestAsInt(t *testing.T) {
	cases := []struct {
		v    any
		want int
		ok   bool
	}{
		{int(3), 3, true},
		{int64(4), 4, true},
		{float64(5), 5, true},
		{float64(5.5), 0, false},
		{"x", 0, false},
	}
	for _, c := range cases {
		got, ok := asInt(c.v)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("asInt(%#v) = %d,%v want %d,%v", c.v, got, ok, c.want, c.ok)
		}
	}
}

func TestScalarString(t *testing.T) {
	if scalarString("s") != "s" {
		t.Fatal("string")
	}
	if scalarString(true) != "true" {
		t.Fatal("bool")
	}
	if scalarString(nil) != "" {
		t.Fatal("nil")
	}
	if scalarString(big.NewInt(9)) != "9" {
		t.Fatal("default")
	}
}
