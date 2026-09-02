package forgetoken

import (
	"context"
	"strings"
	"testing"
)

// The mirror of internal/bravo/inspect's TestRunDecryptCharacterization, on the
// SAME inputs. papi#78 proposes unifying these two shell-secret runners; read the
// two files side by side to see exactly what "unifying" would have to decide.
//
// The operator-visible consequence: one wrapper script handed to both
// --password-command (this runner) and --decrypt-cmd (the other) does not
// necessarily yield the same secret, and neither flag's help says so.
//
// Characterization, not specification — these assert today's behaviour so the
// consolidation is a visible decision rather than an accident.
func TestSecretFromCommandCharacterization(t *testing.T) {
	ctx := context.Background()

	t.Run("no stdin is provided to the command", func(t *testing.T) {
		// DIVERGES: runDecrypt pipes its ebox in, so `cat` echoes it back there.
		// Here `cat` sees the inherited stdin, which under `go test` is empty, so
		// the command produces nothing and that is an error.
		if _, err := SecretFromCommand(ctx, "cat </dev/null"); err == nil {
			t.Fatal("a command given no input and printing nothing must error")
		}
	})

	t.Run("multi-line output keeps only the first line", func(t *testing.T) {
		// DIVERGES: runDecrypt returns "a\nb".
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

	t.Run("trailing spaces are STRIPPED", func(t *testing.T) {
		// DIVERGES: runDecrypt preserves them.
		got, err := SecretFromCommand(ctx, `printf 'x   \n'`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "x" {
			t.Fatalf("got %q, want the trailing spaces trimmed", got)
		}
	})

	t.Run("leading whitespace is STRIPPED", func(t *testing.T) {
		// DIVERGES: runDecrypt preserves it.
		got, err := SecretFromCommand(ctx, `printf '  x\n'`)
		if err != nil {
			t.Fatal(err)
		}
		if got != "x" {
			t.Fatalf("got %q, want the leading spaces trimmed", got)
		}
	})

	t.Run("whitespace-only output IS an error", func(t *testing.T) {
		// DIVERGES, sharpest case: runDecrypt returns "   " successfully.
		if _, err := SecretFromCommand(ctx, `printf '   \n'`); err == nil {
			t.Fatal("whitespace-only output must error here")
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
