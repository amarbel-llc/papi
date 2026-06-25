package installer

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/amarbel-llc/crap/go-crap/v2/crap"
)

func TestOrderedPhasesGatesAndPlatform(t *testing.T) {
	m := Manifest{
		Stages: append([]string(nil), CanonicalStages...),
		Phases: []Phase{
			{ID: "host", Stage: "apply-host-profile", Hook: "stub:x", Gates: []string{"read"}},
			{ID: "read", Stage: "authed-read", Hook: "stub:x"},
			{ID: "detect", Stage: "detect", Hook: "detect"},
			{ID: "nixos-only", Stage: "apply-minimal-sysconfig", Hook: "stub:x", Platforms: []string{"nixos"}},
		},
	}
	r := NewRunner(PlatformLinux, &RunState{Stamps: map[string]Stamp{}}, DefaultHooks())
	var ids []string
	for _, p := range r.orderedPhases(m) {
		ids = append(ids, p.ID)
	}
	// nixos-only is filtered out on linux; detect leads; read precedes host (stage + gate).
	if got := strings.Join(ids, ","); got != "detect,read,host" {
		t.Fatalf("order = %q, want detect,read,host", got)
	}
}

func rebootManifest() Manifest {
	return Manifest{
		Stages: append([]string(nil), CanonicalStages...),
		Phases: []Phase{
			{ID: "detect", Stage: "detect", Hook: "detect"},
			{ID: "land", Stage: "land-content", Hook: "stub:land"},
			{ID: "reboot-me", Stage: "apply-host-profile", Hook: "stub:apply", RequiresReboot: true},
			{ID: "after", Stage: "final", Hook: "stub:final"},
		},
	}
}

func TestRunResumeAcrossReboot(t *testing.T) {
	dir := t.TempDir()
	state, _ := LoadState(dir)
	r := NewRunner(PlatformLinux, state, DefaultHooks())

	err := r.Run(rebootManifest(), crap.NewReporter(io.Discard, crap.ReporterOptions{}), RunOpts{})
	if !errors.Is(err, ErrResumeRequired) {
		t.Fatalf("run 1 err = %v, want ErrResumeRequired", err)
	}
	for _, id := range []string{"detect", "land", "reboot-me"} {
		if _, ok := state.Stamps[id]; !ok {
			t.Errorf("phase %q should have run before the reboot", id)
		}
	}
	if _, ok := state.Stamps["after"]; ok {
		t.Error("phase \"after\" must NOT run before the reboot")
	}

	// Resume: reload the persisted state and re-run — satisfied phases skip, "after" runs.
	state2, _ := LoadState(dir)
	r2 := NewRunner(PlatformLinux, state2, DefaultHooks())
	var buf bytes.Buffer
	if err := r2.Run(rebootManifest(), crap.NewReporter(&buf, crap.ReporterOptions{}), RunOpts{}); err != nil {
		t.Fatalf("resume run err = %v", err)
	}
	if _, ok := state2.Stamps["after"]; !ok {
		t.Error("phase \"after\" should run on resume")
	}
	if !strings.Contains(buf.String(), "satisfied") {
		t.Error("resume run should skip already-satisfied phases")
	}
}

func TestRunHaltsOnFailure(t *testing.T) {
	state, _ := LoadState(t.TempDir())
	m := Manifest{
		Stages: append([]string(nil), CanonicalStages...),
		Phases: []Phase{
			{ID: "ok", Stage: "detect", Hook: "detect"},
			{ID: "boom", Stage: "land-content", Hook: "exec:false"},
			{ID: "never", Stage: "final", Hook: "stub:final"},
		},
	}
	r := NewRunner(PlatformLinux, state, DefaultHooks())
	err := r.Run(m, crap.NewReporter(io.Discard, crap.ReporterOptions{}), RunOpts{})
	if err == nil {
		t.Fatal("expected the failing hook to halt the run")
	}
	if _, ok := state.Stamps["ok"]; !ok {
		t.Error("the phase before the failure should have run")
	}
	if _, ok := state.Stamps["never"]; ok {
		t.Error("a phase after a failure must not run")
	}
}

func TestRunSkipsSatisfied(t *testing.T) {
	dir := t.TempDir()
	m := Manifest{
		Stages: append([]string(nil), CanonicalStages...),
		Phases: []Phase{
			{ID: "detect", Stage: "detect", Hook: "detect"},
			{ID: "land", Stage: "land-content", Hook: "stub:land"},
		},
	}
	state, _ := LoadState(dir)
	r := NewRunner(PlatformLinux, state, DefaultHooks())
	if err := r.Run(m, crap.NewReporter(io.Discard, crap.ReporterOptions{}), RunOpts{}); err != nil {
		t.Fatal(err)
	}

	state2, _ := LoadState(dir)
	var buf bytes.Buffer
	r2 := NewRunner(PlatformLinux, state2, DefaultHooks())
	if err := r2.Run(m, crap.NewReporter(&buf, crap.ReporterOptions{}), RunOpts{}); err != nil {
		t.Fatal(err)
	}
	if c := strings.Count(buf.String(), "satisfied"); c < 2 {
		t.Errorf("second run should skip both satisfied phases, saw %d skips:\n%s", c, buf.String())
	}
}
