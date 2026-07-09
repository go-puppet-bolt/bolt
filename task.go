// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Task is a Bolt task: a named executable file plus optional metadata declaring
// its parameters, input method and implementations.
type Task struct {
	// Name is the task's fully-qualified name (e.g. "package" or "mymod::run").
	Name string
	// File is the path to the executable this task runs (the implementation
	// selected for the local platform). Empty means the task carries metadata
	// only.
	File string
	// Metadata is the parsed *.json metadata; nil if the task has none.
	Metadata *TaskMetadata
}

// TaskMetadata is the parsed content of a task's *.json metadata file.
type TaskMetadata struct {
	Description     string
	Parameters      map[string]TaskParameter
	InputMethod     string
	SupportsNoop    bool
	Implementations []Implementation
	Files           []string
}

// TaskParameter describes one declared task parameter.
type TaskParameter struct {
	Type        string
	Description string
	Sensitive   bool
	Default     any
	HasDefault  bool
}

// Implementation is one platform-specific implementation of a task.
type Implementation struct {
	Name         string
	Requirements []string
	InputMethod  string
	Files        []string
}

// jsonMetadata mirrors the on-disk metadata shape for decoding. Parameters are
// decoded from a raw object so an omitted "default" is distinguishable from an
// explicit null.
type jsonMetadata struct {
	Description     string                     `json:"description"`
	Parameters      map[string]json.RawMessage `json:"parameters"`
	InputMethod     string                     `json:"input_method"`
	SupportsNoop    bool                       `json:"supports_noop"`
	Implementations []jsonImplementation       `json:"implementations"`
	Files           []string                   `json:"files"`
}

type jsonImplementation struct {
	Name         string   `json:"name"`
	Requirements []string `json:"requirements"`
	InputMethod  string   `json:"input_method"`
	Files        []string `json:"files"`
}

type jsonParameter struct {
	Type        string          `json:"type"`
	Description string          `json:"description"`
	Sensitive   bool            `json:"sensitive"`
	Default     json.RawMessage `json:"default"`
}

// ParseTaskMetadata parses a task's *.json metadata.
func ParseTaskMetadata(src []byte) (*TaskMetadata, error) {
	var jm jsonMetadata
	if err := json.Unmarshal(src, &jm); err != nil {
		return nil, fmt.Errorf("task metadata: %w", err)
	}
	md := &TaskMetadata{
		Description:  jm.Description,
		InputMethod:  jm.InputMethod,
		SupportsNoop: jm.SupportsNoop,
		Files:        jm.Files,
	}
	if len(jm.Parameters) > 0 {
		md.Parameters = make(map[string]TaskParameter, len(jm.Parameters))
	}
	for name, raw := range jm.Parameters {
		var jp jsonParameter
		if err := json.Unmarshal(raw, &jp); err != nil {
			return nil, fmt.Errorf("task metadata: parameter %q: %w", name, err)
		}
		p := TaskParameter{Type: jp.Type, Description: jp.Description, Sensitive: jp.Sensitive}
		if len(jp.Default) > 0 {
			var dv any
			// jp.Default is a fragment of an already-validated JSON document, so
			// re-decoding it into any cannot fail.
			_ = json.Unmarshal(jp.Default, &dv)
			p.Default = dv
			p.HasDefault = true
		}
		md.Parameters[name] = p
	}
	for _, ji := range jm.Implementations {
		md.Implementations = append(md.Implementations, Implementation{
			Name:         ji.Name,
			Requirements: ji.Requirements,
			InputMethod:  ji.InputMethod,
			Files:        ji.Files,
		})
	}
	return md, nil
}

// ParameterNames returns the declared parameter names in sorted order.
func (md *TaskMetadata) ParameterNames() []string {
	names := make([]string, 0, len(md.Parameters))
	for n := range md.Parameters {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ValidateParams checks a set of task arguments against the task's declared
// parameters: it rejects unknown parameters, reports missing required ones
// (declared, without a default), and type-checks provided values. A task
// without metadata (or without a parameters block) accepts any arguments.
func (t *Task) ValidateParams(params map[string]any) error {
	if t.Metadata == nil || t.Metadata.Parameters == nil {
		return nil
	}
	decl := t.Metadata.Parameters
	for name := range params {
		if _, ok := decl[name]; !ok {
			return fmt.Errorf("task %q: unknown parameter %q", t.Name, name)
		}
	}
	for _, name := range sortedKeys(decl) {
		p := decl[name]
		v, provided := params[name]
		if !provided {
			if p.HasDefault || isOptionalType(p.Type) {
				continue
			}
			return fmt.Errorf("task %q: missing required parameter %q", t.Name, name)
		}
		if p.Type == "" {
			continue
		}
		if err := checkType(p.Type, v); err != nil {
			return fmt.Errorf("task %q: parameter %q: %w", t.Name, name, err)
		}
	}
	return nil
}

func sortedKeys(m map[string]TaskParameter) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isOptionalType(expr string) bool {
	base, _, err := splitType(expr)
	return err == nil && base == "Optional"
}
