package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// runForgeToken drives `papi forge token …` with no credential configured. That is
// deliberate: every case below is decided by argument validation, which runs BEFORE
// any client is built, so these stay hermetic — no forge, no network, no card.
func runForgeToken(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newForgeTokenCmd()
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

// `revoke` takes two mutually exclusive selectors: --session revokes everything papi
// minted for a session, --id revokes exactly one token by number. They are different
// operations and silently preferring one would be a nasty surprise, so the command
// insists on exactly one.
func TestForgeTokenRevokeSelectorIsExclusive(t *testing.T) {
	t.Run("neither is refused", func(t *testing.T) {
		_, err := runForgeToken(t, "revoke")
		if err == nil {
			t.Fatal("revoke with no selector must fail")
		}
		for _, want := range []string{"--session", "--id"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should name %s, got %v", want, err)
			}
		}
	})

	t.Run("both is refused", func(t *testing.T) {
		_, err := runForgeToken(t, "revoke", "--session", "papi/x", "--id", "42")
		if err == nil {
			t.Fatal("revoke with both selectors must fail rather than pick one")
		}
		if !strings.Contains(err.Error(), "pass one") {
			t.Errorf("got %v", err)
		}
	})

	// Each selector alone must get PAST validation — otherwise the two cases above
	// would pass even if validation rejected everything. Resolving the forge endpoint
	// is the next step, so its complaint is the proof the selector was accepted.
	for _, args := range [][]string{
		{"revoke", "--session", "papi/x"},
		{"revoke", "--id", "42"},
	} {
		t.Run(strings.Join(args[1:], " ")+" reaches the endpoint step", func(t *testing.T) {
			_, err := runForgeToken(t, args...)
			if err == nil {
				t.Fatal("expected to fail on the missing forge endpoint")
			}
			if !strings.Contains(err.Error(), "forge API endpoint") {
				t.Fatalf("expected to get past selector validation, got %v", err)
			}
		})
	}
}

// --id is the ONLY way to reach a token papi did not mint: --session and sweep match
// on papi's own naming and cannot see foreign tokens, a guard added after a sweep
// revoked thousands of unrelated ones. Pin that --id is documented as the deliberate,
// single-token exception, so nobody later "simplifies" the two selectors together.
func TestForgeTokenRevokeDocumentsTheIDException(t *testing.T) {
	revoke := func() string {
		for _, sub := range newForgeTokenCmd().Commands() {
			if sub.Name() == "revoke" {
				return sub.Long
			}
		}
		t.Fatal("no revoke subcommand")
		return ""
	}()
	for _, want := range []string{"did not mint", "sweep"} {
		if !strings.Contains(revoke, want) {
			t.Errorf("revoke's help should explain the --id exception (%q missing)", want)
		}
	}
}
