// SPDX-License-Identifier: BSD-3-Clause
//
// Copyright (c) 2026, the go-puppet-bolt/bolt authors

package bolt

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// checkType reports whether val conforms to the Puppet type expression expr.
// It implements a pragmatic subset of the Puppet type system sufficient for
// task-parameter and plan-parameter validation:
//
//	Any, Data, Undef, NotUndef, String, Integer, Float, Numeric, Boolean,
//	Array[T], Hash[K,V], Optional[T], Enum[a,b,…], Pattern[/re/,…],
//	Variant[A,B,…], Target, TargetSpec
//
// Parametric bounds beyond element/value types (e.g. Integer[min,max],
// String length) are accepted structurally: an Integer[…] matches any integer.
// Unsupported or malformed type names yield an error so validation surfaces
// them rather than silently passing. Full pcore type parsing is deferred.
func checkType(expr string, val any) error {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return fmt.Errorf("empty type expression")
	}
	base, args, err := splitType(expr)
	if err != nil {
		return err
	}
	switch base {
	case "Any", "Data", "TargetSpec", "Target", "Callable", "Type":
		// Accept broadly; TargetSpec/Target are string-or-array target names.
		return nil
	case "Undef":
		if val == nil {
			return nil
		}
		return typeMismatch(expr, val)
	case "NotUndef":
		if val == nil {
			return typeMismatch(expr, val)
		}
		return nil
	case "String":
		if _, ok := val.(string); ok {
			return nil
		}
		return typeMismatch(expr, val)
	case "Boolean":
		if _, ok := val.(bool); ok {
			return nil
		}
		return typeMismatch(expr, val)
	case "Integer":
		if isInteger(val) {
			return nil
		}
		return typeMismatch(expr, val)
	case "Float":
		if isFloat(val) {
			return nil
		}
		return typeMismatch(expr, val)
	case "Numeric":
		if isInteger(val) || isFloat(val) {
			return nil
		}
		return typeMismatch(expr, val)
	case "Array":
		return checkArray(expr, args, val)
	case "Hash":
		return checkHash(expr, args, val)
	case "Optional":
		if val == nil {
			return nil
		}
		if len(args) != 1 {
			return fmt.Errorf("Optional expects one type argument, got %d", len(args))
		}
		return checkType(args[0], val)
	case "Enum":
		return checkEnum(expr, args, val)
	case "Pattern":
		return checkPattern(expr, args, val)
	case "Variant":
		return checkVariant(expr, args, val)
	default:
		return fmt.Errorf("unsupported type %q", base)
	}
}

func checkArray(expr string, args []string, val any) error {
	s, ok := val.([]any)
	if !ok {
		return typeMismatch(expr, val)
	}
	if len(args) == 0 {
		return nil
	}
	elemT := args[0]
	for i, e := range s {
		if err := checkType(elemT, e); err != nil {
			return fmt.Errorf("element %d: %w", i, err)
		}
	}
	return nil
}

func checkHash(expr string, args []string, val any) error {
	m, ok := val.(map[string]any)
	if !ok {
		return typeMismatch(expr, val)
	}
	// Hash[K,V]: check values against V (index 1). Keys are strings here.
	if len(args) < 2 {
		return nil
	}
	valT := args[1]
	for k, v := range m {
		if err := checkType(valT, v); err != nil {
			return fmt.Errorf("value for key %q: %w", k, err)
		}
	}
	return nil
}

func checkEnum(expr string, args []string, val any) error {
	if len(args) == 0 {
		return fmt.Errorf("Enum requires at least one value")
	}
	s, ok := val.(string)
	if !ok {
		return typeMismatch(expr, val)
	}
	for _, a := range args {
		if unquote(a) == s {
			return nil
		}
	}
	return typeMismatch(expr, val)
}

func checkPattern(expr string, args []string, val any) error {
	if len(args) == 0 {
		return fmt.Errorf("Pattern requires at least one regexp")
	}
	s, ok := val.(string)
	if !ok {
		return typeMismatch(expr, val)
	}
	for _, a := range args {
		pat := strings.Trim(strings.TrimSpace(a), "/")
		re, err := regexp.Compile(pat)
		if err != nil {
			return fmt.Errorf("bad Pattern regexp %q: %w", a, err)
		}
		if re.MatchString(s) {
			return nil
		}
	}
	return typeMismatch(expr, val)
}

func checkVariant(expr string, args []string, val any) error {
	if len(args) == 0 {
		return fmt.Errorf("Variant requires at least one type")
	}
	for _, a := range args {
		if err := checkType(a, val); err == nil {
			return nil
		}
	}
	return typeMismatch(expr, val)
}

// splitType splits "Base[a, b[c]]" into base name and top-level argument
// expressions. A bare "Base" yields no arguments.
func splitType(expr string) (base string, args []string, err error) {
	open := strings.IndexByte(expr, '[')
	if open < 0 {
		return expr, nil, nil
	}
	if !strings.HasSuffix(expr, "]") {
		return "", nil, fmt.Errorf("malformed type %q: unbalanced brackets", expr)
	}
	base = strings.TrimSpace(expr[:open])
	inner := expr[open+1 : len(expr)-1]
	parts, err := splitArgs(inner)
	if err != nil {
		return "", nil, fmt.Errorf("in type %q: %w", expr, err)
	}
	return base, parts, nil
}

// splitArgs splits a bracket body on top-level commas, respecting nested
// brackets and slash-delimited regexps.
func splitArgs(s string) ([]string, error) {
	var out []string
	depth := 0
	inRe := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '/' && !inRe:
			inRe = true
		case c == '/' && inRe:
			inRe = false
		case inRe:
			// inside a regexp literal: ignore brackets/commas
		case c == '[':
			depth++
		case c == ']':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced brackets")
			}
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if depth != 0 || inRe {
		return nil, fmt.Errorf("unbalanced brackets")
	}
	last := strings.TrimSpace(s[start:])
	if last != "" || len(out) > 0 {
		out = append(out, last)
	}
	return out, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isInteger(v any) bool {
	switch n := v.(type) {
	case int, int64, *big.Int:
		return true
	case float64:
		return n == float64(int64(n))
	default:
		return false
	}
}

func isFloat(v any) bool {
	_, ok := v.(float64)
	return ok
}

func typeMismatch(expr string, val any) error {
	return fmt.Errorf("value %#v does not match type %s", val, expr)
}
