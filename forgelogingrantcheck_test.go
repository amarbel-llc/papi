package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signGrantFile signs a grant with the fake card (clock fixed at 2026-11-11T12:00Z by
// withFakeCard) and returns its path.
func signGrantFile(t *testing.T, expires string) string {
	t.Helper()
	dir := t.TempDir()
	keyFile := writePubKey(t, dir, newMintPub(t), "")
	out := filepath.Join(dir, "grant")
	if _, _, err := runForgeGrant(t, "sign", "--principal", "nikulin-session", "--key-file", keyFile,
		"--domain", "forge.example", "--not-before", "2026-11-11T00:00:00Z", "--expires", expires,
		"--out", out); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return out
}

func setGrantClock(t *testing.T, at time.Time) {
	t.Helper()
	orig := grantSignNow
	grantSignNow = func() time.Time { return at }
	t.Cleanup(func() { grantSignNow = orig })
}

func TestForgeGrantCheck(t *testing.T) {
	withFakeCard(t)
	grant := signGrantFile(t, "2026-11-18T00:00:00Z")

	tests := []struct {
		name     string
		now      time.Time
		args     []string
		wantErr  string
		wantOut  string
		wantFail bool
	}{
		{"plenty of time", time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), nil, "", "PASS: expires in 144h0m0s", false},
		{"inside the 48h window", time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), nil, "under the 48h0m0s warning window", "principal nikulin-session", true},
		{"custom window passes", time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC), []string{"--warn-within", "24h"}, "", "PASS", false},
		{"expired", time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), nil, "grant has expired", "", true},
		{"not yet valid", time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC), nil, "not yet valid", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setGrantClock(t, tc.now)
			stdout, _, err := runForgeGrant(t, append([]string{"check", grant}, tc.args...)...)
			if tc.wantFail != (err != nil) {
				t.Fatalf("err = %v, want failure=%v", err, tc.wantFail)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantErr)
			}
			if !strings.Contains(stdout, tc.wantOut) {
				t.Errorf("stdout %q lacks %q", stdout, tc.wantOut)
			}
		})
	}
}

func TestForgeGrantCheckRefusals(t *testing.T) {
	withFakeCard(t)
	bad := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(bad, []byte("not a grant\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"malformed":       {"check", bad},
		"missing file":    {"check", filepath.Join(t.TempDir(), "nope")},
		"negative window": {"check", bad, "--warn-within", "-1h"},
		"no argument":     {"check"},
	} {
		if _, _, err := runForgeGrant(t, args...); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
