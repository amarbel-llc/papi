// Package installer implements the FDR-0006 staged host installer engine: it
// parses an RFC-0003 phase manifest, validates it, orders phases by the canonical
// stage set + gates, and runs each with frequency-based idempotency and run-state
// persistence, rendering progress as crap (ndjson on a pipe, a live viewport on a
// TTY). It is the engine only — the binary (cmd/papi-installer) wires the platform
// detector, the papi datasource, and the crap presentation.
//
// Scope (FDR-0006 first increment): the engine + the genuinely-runnable early
// phases (detect, apply-minimal-sysconfig). The host/hardware-gated phases (real
// §5 auth, nixos-rebuild apply, the reboot boot-anchored unit) are typed seams;
// slot-9A signing is out of scope (FDR-0008).
package installer

// CanonicalStages is the installer-owned, non-configurable stage order
// (RFC-0003 §5). A manifest binds phases to these stages; it MUST NOT add,
// remove, or reorder them — the order encodes the system-config-before-build
// correctness invariant.
var CanonicalStages = []string{
	"detect",
	"land-content",
	"apply-minimal-sysconfig",
	"auth",
	"authed-read",
	"apply-host-profile",
	"user-layer",
	"final",
}

// stageIndex returns stage's position in CanonicalStages, or -1 if unknown.
func stageIndex(stage string) int {
	for i, s := range CanonicalStages {
		if s == stage {
			return i
		}
	}
	return -1
}

// isCanonicalStages reports whether stages is exactly CanonicalStages — the v0
// compatibility guard (RFC-0003 §3): a manifest may not introduce, remove, or
// reorder stages.
func isCanonicalStages(stages []string) bool {
	if len(stages) != len(CanonicalStages) {
		return false
	}
	for i, s := range stages {
		if s != CanonicalStages[i] {
			return false
		}
	}
	return true
}
