package installer

import "testing"

func TestParsePlatform(t *testing.T) {
	for _, ok := range []string{"nixos", "linux", "darwin"} {
		if _, err := ParsePlatform(ok); err != nil {
			t.Errorf("ParsePlatform(%q) failed: %v", ok, err)
		}
	}
	if _, err := ParsePlatform("windows"); err == nil {
		t.Error("ParsePlatform(windows) should fail")
	}
}

func TestAppliesToPlatform(t *testing.T) {
	all := Phase{ID: "x", Stage: "detect", Hook: "detect"}
	if !appliesToPlatform(all, PlatformLinux) {
		t.Error("a phase with no platform tokens should apply to all")
	}
	nixosOnly := Phase{ID: "y", Stage: "detect", Hook: "detect", Platforms: []string{"nixos"}}
	if !appliesToPlatform(nixosOnly, PlatformNixOS) {
		t.Error("nixos phase should apply on nixos")
	}
	if appliesToPlatform(nixosOnly, PlatformLinux) {
		t.Error("nixos phase should NOT apply on linux")
	}
}
