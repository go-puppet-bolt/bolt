// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"fmt"
	"strconv"

	yaml "github.com/go-ruby-yaml/yaml"
)

// decodeYAML loads a YAML document and normalises it to plain Go values:
// mappings become map[string]any (keys stringified), sequences become []any,
// and scalars are left as loaded (string, int64, float64, bool, nil, …).
func decodeYAML(src []byte) (any, error) {
	v, err := yaml.Load(string(src))
	if err != nil {
		return nil, err
	}
	return normalize(v), nil
}

// normalize recursively converts the go-ruby-yaml value model into plain Go
// maps and slices.
func normalize(v any) any {
	switch t := v.(type) {
	case *yaml.Map:
		m := make(map[string]any, t.Len())
		for _, p := range t.Pairs() {
			m[keyString(p.Key)] = normalize(p.Val)
		}
		return m
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = normalize(e)
		}
		return out
	default:
		return v
	}
}

// keyString renders a mapping key as a string.
func keyString(k any) string {
	switch s := k.(type) {
	case string:
		return s
	case yaml.Symbol:
		return string(s)
	default:
		return fmt.Sprint(k)
	}
}

// asMap returns v as a string-keyed map, and whether it was one.
func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// asSlice returns v as a slice, and whether it was one.
func asSlice(v any) ([]any, bool) {
	s, ok := v.([]any)
	return s, ok
}

// asString returns v as a string, and whether it was one.
func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// asBool returns v as a bool, and whether it was one.
func asBool(v any) (bool, bool) {
	b, ok := v.(bool)
	return b, ok
}

// asStringList coerces v into a []string. It accepts a single string (wrapped
// in a one-element slice) or a sequence whose every element is a string.
func asStringList(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		return []string{t}, true
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

// asInt returns v as an int, accepting the integer scalar shapes the YAML and
// JSON loaders produce.
func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		// JSON numbers decode as float64; accept only whole values.
		if n == float64(int64(n)) {
			return int(n), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// scalarString renders a scalar value the way a plan message or command
// interpolation would print it.
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		return fmt.Sprint(t)
	}
}
