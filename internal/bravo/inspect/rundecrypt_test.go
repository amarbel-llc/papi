package inspect

import (
	"context"
	"strings"
	"testing"
)

// runDecrypt and forgetoken.SecretFromCommand both turn "a shell command that prints
// a secret" into that secret, and they used to disagree — on multi-line output, on
// leading and trailing whitespace, and on whether whitespace-only output was an error
// — with nothing in either flag's help saying so. An operator pointing one wrapper
// script at both --decrypt-cmd and --password-command got different answers (papi#78).
//
// They now share one rule: FIRST LINE ONLY, with only the line ending removed. This
// file and internal/0/forgetoken/secretcommand_test.go assert that rule on identical
// inputs, deliberately duplicated so a change to one runner fails the other's test
// too. They are separate functions because this one must pipe stdin and that one must
// not; the shared behaviour is how the OUTPUT is read.
//
// If you change either, change both, and expect the mirror to fail first.
func TestRunDecryptOutputRules(t *testing.T) {
	ctx := context.Background()

	t.Run("stdin is piped to the command", func(t *testing.T) {
		// The one deliberate difference from SecretFromCommand: the ebox has to
		// reach the decrypt command somehow.
		got, err := runDecrypt(ctx, "cat", "the-ebox")
		if err != nil {
			t.Fatal(err)
		}
		if got != "the-ebox" {
			t.Fatalf("got %q, want the piped input back", got)
		}
	})

	t.Run("first line only", func(t *testing.T) {
		got, err := runDecrypt(ctx, `printf 'a\nb\n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "a" {
			t.Fatalf("got %q, want only the first line", got)
		}
	})

	t.Run("trailing newlines are stripped", func(t *testing.T) {
		got, err := runDecrypt(ctx, `printf 'x\n\n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "x" {
			t.Fatalf("got %q, want %q", got, "x")
		}
	})

	t.Run("a CRLF line ending is stripped", func(t *testing.T) {
		got, err := runDecrypt(ctx, `printf 'x\r\n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "x" {
			t.Fatalf("got %q, want the CR removed with the LF", got)
		}
	})

	t.Run("surrounding spaces are KEPT", func(t *testing.T) {
		// Only the line ending goes. A secret may legitimately carry leading or
		// trailing whitespace, and trimming it would corrupt it silently.
		got, err := runDecrypt(ctx, `printf '  x   \n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "  x   " {
			t.Fatalf("got %q, want the surrounding spaces preserved", got)
		}
	})

	t.Run("whitespace-only output is not an error", func(t *testing.T) {
		// Follows from the rule above: a line of spaces is a secret this code has
		// no business second-guessing. Only a genuinely empty line is an error.
		got, err := runDecrypt(ctx, `printf '   \n'`, "")
		if err != nil {
			t.Fatalf("whitespace-only output should succeed, got %v", err)
		}
		if got != "   " {
			t.Fatalf("got %q, want three spaces", got)
		}
	})

	t.Run("empty output is an error", func(t *testing.T) {
		if _, err := runDecrypt(ctx, "true", ""); err == nil {
			t.Fatal("expected an error for a command that prints nothing")
		}
	})

	t.Run("a failing command reports its stderr", func(t *testing.T) {
		_, err := runDecrypt(ctx, `echo "card locked" >&2; exit 3`, "")
		if err == nil {
			t.Fatal("expected an error")
		}
		if !strings.Contains(err.Error(), "card locked") {
			t.Fatalf("error should carry the command's stderr, got %v", err)
		}
	})
}
