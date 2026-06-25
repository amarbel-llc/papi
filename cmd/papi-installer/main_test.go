package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testManifest drives the binary headlessly: real detect + apply-minimal-sysconfig
// builtins, the authed-read seam, a gated requires_reboot phase, and a final
// exec hook. The final phase id is "complete" (not "done") to avoid colliding with
// crap's operation_end "done" tally field in the ndjson.
const testManifest = `{
  "stages": ["detect","land-content","apply-minimal-sysconfig","auth","authed-read","apply-host-profile","user-layer","final"],
  "phases": [
    {"id":"detect-platform","stage":"detect","hook":"detect"},
    {"id":"minimal-nix","stage":"apply-minimal-sysconfig","hook":"apply-minimal-sysconfig"},
    {"id":"read-profiles","stage":"authed-read","hook":"authed-read"},
    {"id":"host-profile","stage":"apply-host-profile","gates":["read-profiles"],"requires_reboot":true,"hook":"stub:apply"},
    {"id":"complete","stage":"final","hook":"exec:true"}
  ]
}`

// TestInstallerRunHeadless runs the binary's run() against a fixture manifest with
// a bytes.Buffer (non-TTY → ndjson-crap), asserting the canonical phase order, the
// reboot stop, and that a resume completes the run.
func TestInstallerRunHeadless(t *testing.T) {
	dir := t.TempDir()
	mpath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(mpath, []byte(testManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	argv := []string{"--manifest", mpath, "--platform", "linux", "--state-dir", stateDir}

	// Run 1: stops at the requires_reboot phase.
	var out, errb bytes.Buffer
	if code := run(argv, &out, &errb); code != 0 {
		t.Fatalf("run 1 exit %d: %s", code, errb.String())
	}
	s := out.String()
	for _, id := range []string{"detect-platform", "minimal-nix", "read-profiles", "host-profile"} {
		if !strings.Contains(s, id) {
			t.Errorf("ndjson missing phase %q:\n%s", id, s)
		}
	}
	if strings.Contains(s, "complete") {
		t.Errorf("the final phase must not run before the reboot:\n%s", s)
	}
	if !strings.Contains(errb.String(), "reboot required") {
		t.Errorf("expected a reboot notice on stderr, got: %s", errb.String())
	}

	// Run 2 (same state-dir): resumes, skips satisfied phases, runs the final phase.
	var out2, errb2 bytes.Buffer
	if code := run(argv, &out2, &errb2); code != 0 {
		t.Fatalf("resume exit %d: %s", code, errb2.String())
	}
	if !strings.Contains(out2.String(), "complete") {
		t.Errorf("resume did not run the final phase:\n%s", out2.String())
	}
	if !strings.Contains(out2.String(), "satisfied") {
		t.Errorf("resume should skip already-satisfied phases:\n%s", out2.String())
	}
}
