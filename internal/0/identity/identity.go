// Package identity reads scalar fields from a person's local identity.toml — the
// canonical mechanism papi#38 centralizes so eng consumers stop hand-rolling
// nix-eval/grep reads of ~/.config/identity.toml.
//
// It is MECHANISM, not schema. It parses TOML, walks a dotted key path, coerces
// a scalar, and resolves the file's XDG location — but it attaches NO meaning to
// any field. The set, types, and defaults of identity.toml's keys are the
// consumer's (eng's) concern; this package reads whatever path it is handed and
// reports absence so the caller can apply its own default. The one papi-semantic
// key, papi.domain, is read through the same generic Lookup (see FDR-0009); papi
// carries no built-in domain literal.
package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// ErrNotScalar is returned by Lookup when a dotted path resolves to a TOML table
// or array rather than a scalar. Per FDR-0009 this is a caller bug (the wrong
// path), distinct from an absent key — the caller's default does NOT apply.
var ErrNotScalar = errors.New("identity: path resolves to a table or array, not a scalar")

// FileName is the fixed basename papi reads under the XDG config dir.
const FileName = "identity.toml"

// DefaultPath returns the conventional identity.toml location:
// $XDG_CONFIG_HOME/identity.toml, falling back to ~/.config/identity.toml when
// XDG_CONFIG_HOME is unset or blank. It does NOT check existence — an absent
// file is a valid (default-yielding) Lookup input, not an error here.
func DefaultPath() (string, error) {
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, FileName), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir for %s: %w", FileName, err)
	}
	return filepath.Join(home, ".config", FileName), nil
}

// Lookup reads the scalar at the dotted TOML path in the file at path.
//
// The (value, found, err) contract (FDR-0009):
//
//	file absent                    → ("", false, nil)        caller applies its default
//	file present, key absent       → ("", false, nil)        caller applies its default
//	key present, scalar (incl. "") → (formatted, true, nil)
//	key present, table/array       → ("", false, ErrNotScalar)
//	file present but unreadable/bad → ("", false, err)
//
// A present empty string is returned as-is with found=true — the default does
// not fire for it; only true absence yields found=false. An absent FILE is not
// an error (it is the default case); an unreadable or malformed file is.
func Lookup(path, dotted string) (value string, found bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil // absent file → caller's default
		}
		return "", false, fmt.Errorf("read %s: %w", path, err)
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return "", false, fmt.Errorf("parse %s: %w", path, err)
	}
	v, ok := traverse(doc, dotted)
	if !ok {
		return "", false, nil // absent key → caller's default
	}
	s, err := formatScalar(v)
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

// traverse walks doc by the dot-separated key path, returning the value at the
// leaf and whether every component resolved. A component naming a missing key,
// or one that tries to descend through a non-table (e.g. papi.domain.foo when
// papi.domain is a string), reports not-found — the caller treats that as absent
// and applies its default.
func traverse(doc map[string]any, dotted string) (any, bool) {
	var cur any = doc
	for _, part := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// formatScalar renders a decoded TOML scalar the way `nix eval --raw` would: a
// string verbatim, a bool as true/false, integers/floats in canonical lexical
// form. A table or array is ErrNotScalar; any other leaf (e.g. a TOML datetime)
// is stringified.
func formatScalar(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		return "", ErrNotScalar
	}
	return fmt.Sprintf("%v", v), nil
}
