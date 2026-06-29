package identity

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fixture is a representative identity.toml: a top-level array (before any
// table), a [host] table with str/bool/int/float/empty scalars, and the
// papi-semantic [papi] domain.
const fixture = `
top-array = [1, 2, 3]

[host]
privilege-escalation = "sudo"
enable-linux-builder = true
port = 22
ratio = 1.5
empty = ""

[papi]
domain = "linenisgreat.com"
`

// writeFixture writes content to a temp identity.toml and returns its path.
func writeFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identity.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLookupScalars(t *testing.T) {
	path := writeFixture(t, fixture)
	cases := []struct {
		dotted string
		want   string
	}{
		{"host.privilege-escalation", "sudo"},
		{"host.enable-linux-builder", "true"},
		{"host.port", "22"},
		{"host.ratio", "1.5"},
		{"papi.domain", "linenisgreat.com"},
	}
	for _, tc := range cases {
		t.Run(tc.dotted, func(t *testing.T) {
			got, found, err := Lookup(path, tc.dotted)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !found {
				t.Fatalf("expected found for %q", tc.dotted)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLookupAbsentFileIsNotAnError(t *testing.T) {
	got, found, err := Lookup(filepath.Join(t.TempDir(), "nope.toml"), "papi.domain")
	if err != nil {
		t.Fatalf("absent file must not error: %v", err)
	}
	if found {
		t.Fatal("absent file must report found=false")
	}
	if got != "" {
		t.Fatalf("absent file must yield empty value, got %q", got)
	}
}

func TestLookupAbsentKey(t *testing.T) {
	path := writeFixture(t, fixture)
	_, found, err := Lookup(path, "host.does-not-exist")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("absent key must report found=false")
	}
}

func TestLookupEmptyStringIsPresent(t *testing.T) {
	path := writeFixture(t, fixture)
	got, found, err := Lookup(path, "host.empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found {
		t.Fatal("a present empty string must report found=true (default must NOT fire)")
	}
	if got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestLookupNonScalarIsError(t *testing.T) {
	path := writeFixture(t, fixture)
	for _, dotted := range []string{"host", "top-array", "papi"} {
		t.Run(dotted, func(t *testing.T) {
			_, found, err := Lookup(path, dotted)
			if !errors.Is(err, ErrNotScalar) {
				t.Fatalf("expected ErrNotScalar for %q, got err=%v found=%v", dotted, err, found)
			}
		})
	}
}

func TestLookupDescendThroughScalarIsAbsent(t *testing.T) {
	path := writeFixture(t, fixture)
	// papi.domain is a string; papi.domain.foo cannot resolve → absent, not error.
	_, found, err := Lookup(path, "papi.domain.foo")
	if err != nil {
		t.Fatalf("descending through a scalar must be absent, not error: %v", err)
	}
	if found {
		t.Fatal("papi.domain.foo must report found=false")
	}
}

func TestLookupMalformedFileIsError(t *testing.T) {
	path := writeFixture(t, "this is = not [valid toml")
	_, _, err := Lookup(path, "papi.domain")
	if err == nil {
		t.Fatal("a malformed file must error")
	}
	if errors.Is(err, ErrNotScalar) {
		t.Fatal("a parse error must not be reported as ErrNotScalar")
	}
}

func TestDefaultPath(t *testing.T) {
	t.Run("XDG set", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/xdg/conf")
		got, err := DefaultPath()
		if err != nil {
			t.Fatal(err)
		}
		if want := "/xdg/conf/identity.toml"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
	t.Run("XDG unset falls back to ~/.config", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "/home/tester")
		got, err := DefaultPath()
		if err != nil {
			t.Fatal(err)
		}
		if want := "/home/tester/.config/identity.toml"; got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}
