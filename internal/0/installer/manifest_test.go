package installer

import (
	"strings"
	"testing"
)

func goodManifest() Manifest {
	return Manifest{
		Stages: append([]string(nil), CanonicalStages...),
		Phases: []Phase{
			{ID: "a", Stage: "detect", Hook: "detect"},
			{ID: "b", Stage: "authed-read", Hook: "authed-read"},
			{ID: "c", Stage: "apply-host-profile", Hook: "stub:apply", Gates: []string{"b"}},
		},
	}
}

func TestValidateGood(t *testing.T) {
	if err := goodManifest().Validate(); err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
		want   string
	}{
		{"non-canonical stages", func(m *Manifest) { m.Stages = []string{"detect", "final"} }, "canonical stage set"},
		{"duplicate id", func(m *Manifest) {
			m.Phases = append(m.Phases, Phase{ID: "a", Stage: "final", Hook: "stub:x"})
		}, "duplicate phase id"},
		{"unknown stage", func(m *Manifest) { m.Phases[0].Stage = "bogus" }, "unknown stage"},
		{"empty hook", func(m *Manifest) { m.Phases[0].Hook = "" }, "empty hook"},
		{"bad frequency", func(m *Manifest) { m.Phases[0].Frequency = "hourly" }, "unknown frequency"},
		{"dangling gate", func(m *Manifest) { m.Phases[0].Gates = []string{"nope"} }, "unknown phase"},
		{"gate cycle", func(m *Manifest) {
			m.Phases[0].Gates = []string{"c"} // a → c, and c → a below: a cycle
			m.Phases[2].Gates = []string{"a"}
		}, "cycle"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := goodManifest()
			tc.mutate(&m)
			err := m.Validate()
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	m, err := Parse([]byte(`{"stages":["detect","land-content","apply-minimal-sysconfig","auth","authed-read","apply-host-profile","user-layer","final"],"phases":[{"id":"d","stage":"detect","hook":"detect"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("parsed manifest invalid: %v", err)
	}
	if len(m.Phases) != 1 || m.Phases[0].ID != "d" {
		t.Fatalf("decoded = %+v", m)
	}
}
