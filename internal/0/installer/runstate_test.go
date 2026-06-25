package installer

import "testing"

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Stamps) != 0 {
		t.Fatalf("fresh state should be empty, got %v", s.Stamps)
	}
	p := Phase{ID: "a", Stage: "detect", Hook: "detect"}
	s.Platform = PlatformNixOS
	s.Record(p, "boot1")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Platform != PlatformNixOS {
		t.Errorf("platform = %q, want nixos", got.Platform)
	}
	if !got.Satisfied(p, "boot2") {
		t.Error("a per-instance stamp should be satisfied across boots")
	}
}

func TestSatisfiedFrequency(t *testing.T) {
	s := &RunState{dir: t.TempDir(), Stamps: map[string]Stamp{}}

	perBoot := Phase{ID: "pb", Stage: "detect", Hook: "detect", Frequency: FrequencyPerBoot}
	if s.Satisfied(perBoot, "b1") {
		t.Error("unstamped phase should not be satisfied")
	}
	s.Record(perBoot, "b1")
	if !s.Satisfied(perBoot, "b1") {
		t.Error("per-boot satisfied for the same boot")
	}
	if s.Satisfied(perBoot, "b2") {
		t.Error("per-boot must NOT be satisfied for a new boot")
	}

	once := Phase{ID: "o", Stage: "detect", Hook: "detect", Frequency: FrequencyOnce}
	s.Record(once, "b1")
	if !s.Satisfied(once, "b2") {
		t.Error("once must be satisfied across boots")
	}
}
