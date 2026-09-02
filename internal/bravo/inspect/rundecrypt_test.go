package inspect

import (
	"context"
	"strings"
	"testing"
)

// runDecrypt had no direct test: it was only ever reached through the §5 handshake
// tests, whose --decrypt-cmd fixtures ("base64 -d", "cat") produce single-line
// output — so none of the behaviour below was exercised by anything.
//
// These are CHARACTERIZATION tests. They assert what runDecrypt does today, not
// what it ought to do, because papi#78 proposes unifying it with
// forgetoken.SecretFromCommand and the two differ in ways nothing currently
// catches. Each case marked DIVERGES is a behaviour the other runner does NOT
// share; its mirror lives in internal/0/forgetoken/secretcommand_test.go, on the
// same inputs. Whichever semantic that consolidation picks, one of the two files
// MUST change — that is the point of writing them down.
func TestRunDecryptCharacterization(t *testing.T) {
	ctx := context.Background()

	t.Run("stdin is piped to the command", func(t *testing.T) {
		// DIVERGES: SecretFromCommand passes no stdin at all.
		got, err := runDecrypt(ctx, "cat", "the-ebox")
		if err != nil {
			t.Fatal(err)
		}
		if got != "the-ebox" {
			t.Fatalf("got %q, want the piped input back", got)
		}
	})

	t.Run("multi-line output is returned whole", func(t *testing.T) {
		// DIVERGES: SecretFromCommand keeps only the first line.
		got, err := runDecrypt(ctx, `printf 'a\nb\n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "a\nb" {
			t.Fatalf("got %q, want both lines with the trailing newline stripped", got)
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

	t.Run("trailing spaces are KEPT", func(t *testing.T) {
		// DIVERGES: TrimRight(out, "\r\n") cuts only line endings, so spaces
		// survive; SecretFromCommand's TrimSpace removes them. A wrapper script
		// that emits a stray trailing space yields a different secret from each.
		got, err := runDecrypt(ctx, `printf 'x   \n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "x   " {
			t.Fatalf("got %q, want the trailing spaces preserved", got)
		}
	})

	t.Run("leading whitespace is KEPT", func(t *testing.T) {
		// DIVERGES: SecretFromCommand trims it.
		got, err := runDecrypt(ctx, `printf '  x\n'`, "")
		if err != nil {
			t.Fatal(err)
		}
		if got != "  x" {
			t.Fatalf("got %q, want the leading spaces preserved", got)
		}
	})

	t.Run("whitespace-only output is NOT an error", func(t *testing.T) {
		// DIVERGES, and this is the sharpest one: only line endings are trimmed,
		// so "   " is a non-empty result here and an error in the other runner.
		got, err := runDecrypt(ctx, `printf '   \n'`, "")
		if err != nil {
			t.Fatalf("whitespace-only output currently succeeds; got error %v", err)
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
