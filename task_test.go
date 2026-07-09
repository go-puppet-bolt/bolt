// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"reflect"
	"testing"
)

const taskJSON = `{
  "description": "manage a package",
  "parameters": {
    "name":    {"type": "String", "description": "package name"},
    "action":  {"type": "Enum[install,uninstall]"},
    "version": {"type": "Optional[String]"},
    "retries": {"type": "Integer", "default": 3},
    "token":   {"type": "String", "sensitive": true}
  },
  "input_method": "stdin",
  "supports_noop": true,
  "implementations": [
    {"name": "run.sh", "requirements": ["shell"], "input_method": "stdin", "files": ["m/lib/x"]}
  ],
  "files": ["m/lib/util.sh"]
}`

func TestParseTaskMetadata(t *testing.T) {
	md, err := ParseTaskMetadata([]byte(taskJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if md.Description != "manage a package" || md.InputMethod != "stdin" || !md.SupportsNoop {
		t.Fatalf("scalars: %#v", md)
	}
	if len(md.Files) != 1 || md.Files[0] != "m/lib/util.sh" {
		t.Fatalf("files: %#v", md.Files)
	}
	if len(md.Implementations) != 1 || md.Implementations[0].Name != "run.sh" {
		t.Fatalf("impls: %#v", md.Implementations)
	}
	retries := md.Parameters["retries"]
	if !retries.HasDefault {
		t.Fatal("retries default missing")
	}
	if got, _ := asInt(retries.Default); got != 3 {
		t.Fatalf("retries default = %v", retries.Default)
	}
	if !md.Parameters["token"].Sensitive {
		t.Fatal("token sensitive")
	}
	if !reflect.DeepEqual(md.ParameterNames(), []string{"action", "name", "retries", "token", "version"}) {
		t.Fatalf("names = %v", md.ParameterNames())
	}
}

func TestParseTaskMetadataMinimal(t *testing.T) {
	md, err := ParseTaskMetadata([]byte(`{"description":"x"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if md.Parameters != nil {
		t.Fatal("expected nil parameters")
	}
	if len(md.ParameterNames()) != 0 {
		t.Fatal("expected no names")
	}
}

func TestParseTaskMetadataErrors(t *testing.T) {
	if _, err := ParseTaskMetadata([]byte("{not json")); err == nil {
		t.Fatal("want json error")
	}
	if _, err := ParseTaskMetadata([]byte(`{"parameters":{"p":5}}`)); err == nil {
		t.Fatal("want parameter decode error")
	}
}

func TestValidateParams(t *testing.T) {
	md, _ := ParseTaskMetadata([]byte(taskJSON))
	task := &Task{Name: "package", Metadata: md}

	// valid: required provided, optional/defaulted omitted
	if err := task.ValidateParams(map[string]any{
		"name":   "nginx",
		"action": "install",
		"token":  "secret",
	}); err != nil {
		t.Fatalf("valid: %v", err)
	}

	// unknown parameter
	if err := task.ValidateParams(map[string]any{"name": "x", "action": "install", "token": "t", "bogus": 1}); err == nil {
		t.Fatal("want unknown-param error")
	}
	// missing required
	if err := task.ValidateParams(map[string]any{"name": "x", "action": "install"}); err == nil {
		t.Fatal("want missing-required error")
	}
	// type mismatch
	if err := task.ValidateParams(map[string]any{"name": 5, "action": "install", "token": "t"}); err == nil {
		t.Fatal("want type error")
	}
	// enum mismatch
	if err := task.ValidateParams(map[string]any{"name": "x", "action": "explode", "token": "t"}); err == nil {
		t.Fatal("want enum error")
	}
}

func TestValidateParamsNoMetadata(t *testing.T) {
	// no metadata at all
	task := &Task{Name: "free"}
	if err := task.ValidateParams(map[string]any{"anything": 1}); err != nil {
		t.Fatalf("no metadata: %v", err)
	}
	// metadata but no parameters block
	task2 := &Task{Name: "free2", Metadata: &TaskMetadata{}}
	if err := task2.ValidateParams(map[string]any{"anything": 1}); err != nil {
		t.Fatalf("no params: %v", err)
	}
}

func TestValidateParamsUntypedParam(t *testing.T) {
	// a declared parameter with no type accepts any provided value
	md := &TaskMetadata{Parameters: map[string]TaskParameter{"x": {}}}
	task := &Task{Name: "t", Metadata: md}
	if err := task.ValidateParams(map[string]any{"x": 123}); err != nil {
		t.Fatalf("untyped: %v", err)
	}
}

func TestIsOptionalType(t *testing.T) {
	if !isOptionalType("Optional[String]") {
		t.Fatal("optional")
	}
	if isOptionalType("String") {
		t.Fatal("non-optional")
	}
	if isOptionalType("Optional[") { // splitType error path
		t.Fatal("malformed should be false")
	}
}
