// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"math/big"
	"testing"
)

func TestCheckType(t *testing.T) {
	ok := []struct {
		expr string
		val  any
	}{
		{"Any", 1},
		{"Data", "x"},
		{"TargetSpec", "n"},
		{"Undef", nil},
		{"NotUndef", 1},
		{"String", "s"},
		{"Boolean", true},
		{"Integer", int64(3)},
		{"Integer", big.NewInt(3)},
		{"Float", 1.5},
		{"Numeric", int64(2)},
		{"Numeric", 2.5},
		{"Array", []any{1, 2}},
		{"Array[Integer]", []any{int64(1)}},
		{"Hash", map[string]any{"a": 1}},
		{"Hash[String,Integer]", map[string]any{"a": int64(1)}},
		{"Optional[String]", nil},
		{"Optional[String]", "x"},
		{"Enum[a,b]", "b"},
		{"Enum['a','b']", "a"},
		{`Pattern[/^a.*z$/]`, "abcz"},
		{"Variant[String,Integer]", int64(4)},
	}
	for _, c := range ok {
		if err := checkType(c.expr, c.val); err != nil {
			t.Errorf("checkType(%q, %#v) unexpected err: %v", c.expr, c.val, err)
		}
	}

	bad := []struct {
		expr string
		val  any
	}{
		{"", 1},
		{"Foo[bar", 1},                 // malformed
		{"X[a]]", 1},                   // splitArgs error
		{"Undef", 1},                   //
		{"NotUndef", nil},              //
		{"String", 1},                  //
		{"Boolean", "x"},               //
		{"Integer", "x"},               //
		{"Float", "x"},                 //
		{"Numeric", "x"},               //
		{"Array", 5},                   //
		{"Array[Integer]", []any{"x"}}, // element mismatch
		{"Hash", 5},                    //
		{"Hash[String,Integer]", map[string]any{"a": "x"}}, // value mismatch
		{"Optional[String,Integer]", "x"},                  // wrong arg count
		{"Optional[Integer]", "x"},                         // delegate mismatch
		{"Enum[]", "x"},                                    // no values
		{"Enum[a]", 5},                                     // not string
		{"Enum[a]", "b"},                                   // no match
		{"Pattern[]", "x"},                                 // no regexp
		{"Pattern[/(/]", "x"},                              // bad regexp
		{"Pattern[/a/]", 5},                                // not string
		{"Pattern[/^z/]", "a"},                             // no match
		{"Variant[]", 1},                                   // empty
		{"Variant[String]", 5},                             // no match
		{"Foo", 1},                                         // unsupported
	}
	for _, c := range bad {
		if err := checkType(c.expr, c.val); err == nil {
			t.Errorf("checkType(%q, %#v) want error", c.expr, c.val)
		}
	}
}

func TestSplitType(t *testing.T) {
	base, args, err := splitType("String")
	if err != nil || base != "String" || args != nil {
		t.Fatalf("bare: %q %v %v", base, args, err)
	}
	base, args, err = splitType("Array[Integer]")
	if err != nil || base != "Array" || len(args) != 1 || args[0] != "Integer" {
		t.Fatalf("param: %q %v %v", base, args, err)
	}
	if _, _, err := splitType("Foo[bar"); err == nil {
		t.Fatal("want unbalanced error")
	}
	if _, _, err := splitType("X[a]]"); err == nil {
		t.Fatal("want splitArgs error")
	}
}

func TestSplitArgs(t *testing.T) {
	got, err := splitArgs("String,Integer")
	if err != nil || len(got) != 2 {
		t.Fatalf("comma: %#v %v", got, err)
	}
	got, err = splitArgs("Hash[String,Integer]")
	if err != nil || len(got) != 1 {
		t.Fatalf("nested: %#v %v", got, err)
	}
	got, err = splitArgs("/a,b/")
	if err != nil || len(got) != 1 || got[0] != "/a,b/" {
		t.Fatalf("regexp: %#v %v", got, err)
	}
	got, err = splitArgs("a,")
	if err != nil || len(got) != 2 {
		t.Fatalf("trailing comma: %#v %v", got, err)
	}
	if _, err := splitArgs(""); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if _, err := splitArgs("[a"); err == nil {
		t.Fatal("want depth error")
	}
	if _, err := splitArgs("a]"); err == nil {
		t.Fatal("want negative depth error")
	}
	if _, err := splitArgs("/a"); err == nil {
		t.Fatal("want open regexp error")
	}
}

func TestUnquote(t *testing.T) {
	if unquote("'x'") != "x" {
		t.Fatal("single")
	}
	if unquote(`"y"`) != "y" {
		t.Fatal("double")
	}
	if unquote("z") != "z" {
		t.Fatal("bare")
	}
	if unquote("a") != "a" {
		t.Fatal("short")
	}
}

func TestNumericPredicates(t *testing.T) {
	if !isInteger(int(1)) || !isInteger(int64(1)) || !isInteger(big.NewInt(1)) || !isInteger(2.0) {
		t.Fatal("isInteger true cases")
	}
	if isInteger(2.5) || isInteger("x") {
		t.Fatal("isInteger false cases")
	}
	if !isFloat(1.0) || isFloat(1) {
		t.Fatal("isFloat")
	}
}
