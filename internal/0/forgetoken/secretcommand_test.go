package forgetoken

import (
	"context"
	"strings"
	"testing"
)

// The mirror of internal/bravo/inspect's TestRunDecryptOutputRules, on identical
// inputs. Both flags take a shell command that prints a secret, and papi#78 was that
// they read its output differently with nothing saying so — so an operator could
// point one wrapper script at --password-command and --decrypt-cmd and get two
// different secrets.
//
// The shared rule is FIRST LINE ONLY, with only the line ending removed. The
// duplication here is deliberate: a change to either runner fails the other's test,
// which is the cheapest thing that keeps them honest without moving code across a
// package tier. They stay separate functions because runDecrypt must pipe stdin and
// this one must not.
//
// If you change either, change both, and expect the mirror to fail first.
func TestSecretFromCommandOutputRules(t *testing.T) {
	ctx := context.Background()

	t.Run("no stdin is provided to the command", func(t *testing.T) {
		// The one deliberate difference from runDecrypt: nothing is piped in, so a
		// command that reads stdin gets nothing and produces nothing.
		if _, err := SecretFromCommand(ctx, "cat </dev/null"); err == nil {
			t.Fatal("a command given no input and printing nothing must error")
		}
	})

	t.Run("first line only", func(t *testing.T) {
		got, err := SecretFromCommand(ctx, `printf 'a\nb\n'`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "a" {
			t.Fatalf("got %q, want only the first line", got)
		}
	})

	t.Run("trailing newlines are stripped", func(t *testing.T) {
		got, err := SecretFromCommand(ctx, `printf 'x\n\n'`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "x" {
			t.Fatalf("got %q, want %q", got, "x")
		}
	})

	t.Run("a CRLF line ending is stripped", func(t *testing.T) {
		got, err := SecretFromCommand(ctx, `printf 'x\r\n'`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "x" {
			t.Fatalf("got %q, want the CR removed with the LF", got)
		}
	})

	t.Run("surrounding spaces are KEPT", func(t *testing.T) {
		// This is the behaviour change papi#78 bought: an earlier TrimSpace here
		// silently corrupted any secret carrying leading or trailing whitespace.
		got, err := SecretFromCommand(ctx, `printf '  x   \n'`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "  x   " {
			t.Fatalf("got %q, want the surrounding spaces preserved", got)
		}
	})

	t.Run("whitespace-only output is not an error", func(t *testing.T) {
		got, err := SecretFromCommand(ctx, `printf '   \n'`)
		if err != nil {
			t.Fatalf("whitespace-only output should succeed, got %v", err)
		}
		if got != "   " {
			t.Fatalf("got %q, want three spaces", got)
		}
	})

	t.Run("empty output is an error", func(t *testing.T) {
		if _, err := SecretFromCommand(ctx, "true"); err == nil {
			t.Fatal("expected an error for a command that prints nothing")
		}
	})

	t.Run("a failing command reports its stderr", func(t *testing.T) {
		_, err := SecretFromCommand(ctx, `echo "agent locked" >&2; exit 3`)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "agent locked") {
			t.Fatalf("error should carry the command's stderr, got %v", err)
		}
	})
}
