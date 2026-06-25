package installer

import (
	"fmt"
	"os"
	"runtime"
)

// Platform is a resolved host platform token (RFC-0003 §2).
type Platform string

const (
	PlatformNixOS  Platform = "nixos"
	PlatformLinux  Platform = "linux"
	PlatformDarwin Platform = "darwin"
)

// Detect resolves the host platform once (RFC-0003 §2): darwin by GOOS, nixos by
// the canonical NixOS markers, otherwise plain linux.
func Detect() Platform {
	if runtime.GOOS == "darwin" {
		return PlatformDarwin
	}
	if isNixOS() {
		return PlatformNixOS
	}
	return PlatformLinux
}

// isNixOS reports whether the host is NixOS by its canonical markers.
func isNixOS() bool {
	for _, p := range []string{"/etc/NIXOS", "/run/current-system/nixos-version"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// ParsePlatform validates a platform override token (RFC-0003 §2).
func ParsePlatform(s string) (Platform, error) {
	switch Platform(s) {
	case PlatformNixOS, PlatformLinux, PlatformDarwin:
		return Platform(s), nil
	default:
		return "", fmt.Errorf("unknown platform %q (want nixos|linux|darwin)", s)
	}
}

// appliesToPlatform reports whether p runs on platform (RFC-0003 §2): a phase
// with no platform tokens applies to all platforms.
func appliesToPlatform(p Phase, platform Platform) bool {
	if len(p.Platforms) == 0 {
		return true
	}
	for _, t := range p.Platforms {
		if Platform(t) == platform {
			return true
		}
	}
	return false
}
