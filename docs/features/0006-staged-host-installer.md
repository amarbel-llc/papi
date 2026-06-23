---
status: proposed
date: 2026-06-23
promotion-criteria: >
  proposed → experimental: the installer binary builds from the papi flake, links
  the internal/0/papi client + the crap TUI, and drives RFC-0003's phases on a
  non-cold host (e.g. a re-provision) rendering per-phase progress; gated on
  FDR-0003 reaching accepted (iter 1 proves the bash path end-to-end first).
  experimental → testing: a real cold host (the fanless Framework board)
  provisions end to end through the binary — including the NixOS
  apply-minimal-sysconfig → build → apply-host-profile ordering and at least one
  reboot-and-resume — selecting a host profile from profiles[] after card-auth.
  testing → accepted: a second cold host on a different platform (a non-NixOS
  Linux box) provisions end to end with no manual steps, and the RFC-0003 stage
  set / phase contract needs no change for two weeks.
---

# Staged host installer (papi-built, cloud-init-shaped)

## Problem Statement

A cold host today self-bootstraps via a single POSIX-sh shim (FDR-0003's
`provision.sh`): it clones eng and runs a linear provisioner with no progress
visibility, no platform-aware phase ordering (NixOS daemon settings are an
unsequenced manual prerequisite), and no way to survive a reboot mid-run. As
provisioning grows — NixOS system configuration, per-host profiles, reboots
between kernel-level changes — a flat script cannot *enforce* ordering, show
staged progress, or resume after a reboot. The staged installer replaces the
shim's body with a signed static binary that drives provisioning as ordered,
observable, idempotent, resumable phases.

## Interface

The installer is a **static binary** built by `amarbel-llc/papi` (it links the
`internal/0/papi` client and the crap TUI), signed by the subject's PIV slot-9A
key and served from the subject's PAPI instance. The cold-host entrypoint is
unchanged — `curl -fsSL https://<domain>/papi/bootstrap | sh` — but the served
body now fetches, verifies, and execs the binary (the signing and endpoint
evolution are tracked separately; see More Information).

The binary is the **framework** specified by RFC-0003: it owns platform
detection, stage ordering and gating, idempotency, reboot/resume, PAPI-datasource
access, and progress rendering; the per-phase work is content supplied by a
host-config repository (eng). Observable behavior:

- **Staged provisioning with live progress.** The binary runs the RFC-0003 stage
  set — detect → land-content → apply-minimal-sysconfig → build-and-auth →
  authed-read → apply-host-profile → user-layer → final — and renders each phase's
  status (start / ok / fail) through the crap TUI. On a non-TTY it emits
  ndjson-crap records instead of an interactive display.
- **Public→authenticated transition.** It stages a host far enough to authenticate
  with the **local PIV card directly** (via `pivy-box`; no piggy agent service
  required), then reads the subject's PAPI as a datasource: identity (RFC-0001
  §12), nix caches (§11), and host profiles (§13).
- **Host-profile selection.** After the authenticated read, the TUI presents the
  visible `profiles[]` for the operator to choose; `--profile <id>` selects one
  non-interactively. The chosen entry's `flakeref` is activated (`nixos-rebuild`
  for a `nixosConfigurations` profile, `home-manager switch` for a
  `homeConfigurations` one). On NixOS a profile is a **pair** — the binary applies
  the `nixosConfiguration` (system) and then the entry's `home_flakeref`, the
  host's **standalone** `homeConfiguration`, via `home-manager` (not the NixOS
  module).
- **Platform-aware, no self-skip.** The framework detects the platform (`nixos` /
  `linux` / `darwin`) once and selects + orders phases from manifest conditions;
  phase content never self-detects or self-skips.
- **Build-capable nix is produced, not presumed.** The apply-minimal-sysconfig
  phase installs nix (Determinate) on a host that lacks it, or applies the base
  module via a minimal `nixos-rebuild` on NixOS — and gates the build phase.
- **Substitutes early.** The binary configures the subject's **public** nix caches
  (RFC-0001 §11) as soon as nix is installed (apply-minimal-sysconfig), so the
  first build pulls closures instead of compiling from source; any gated caches are
  added after card-auth. Cache keys are honored only against a verified §10
  document signature.
- **Reboot-and-resume.** A phase may require a reboot; the framework persists run
  state and resumes at the next phase on the subsequent boot. On NixOS the resume
  is carried by a boot-anchored unit that exists only in the transient bootstrap
  generation and is gone once the real host configuration activates.

## Examples

    # Cold host, only a provisioned YubiKey + network — interactive:
    $ curl -fsSL https://linenisgreat.com/papi/bootstrap | sh
    # → fetches + verifies the signed installer, then a TUI stages the host:
    #   ✓ detect (nixos)   ✓ land-content   ✓ apply-minimal-sysconfig
    #   ✓ build-and-auth   → insert card / touch to authenticate
    #   ? select host profile:  [framework-laptop]  server-headless
    #   ✓ apply-host-profile (reboot required) … resuming after reboot …
    #   ✓ user-layer   ✓ final

    # Non-interactive (pin the profile, no TUI prompt):
    $ curl -fsSL https://linenisgreat.com/papi/bootstrap | sh -s -- \
        --profile framework-laptop

## Limitations

- **Not yet implemented.** This FDR is the design; the binary does not exist. Its
  build is gated on FDR-0003 reaching accepted (iteration 1 proves the bash
  `provision.sh` path end-to-end first), so the bash path remains the live
  cold-host entrypoint until the binary path is proven.
- **Framework, not content.** The binary owns ordering and execution; the work
  each phase performs lives in eng (RFC-0003 §3). Reboot-resume on NixOS depends
  on eng's apply-host-profile module emitting the resume unit per the RFC-0003 §7
  contract.
- **Signing and serving are separate.** Producing, signing (slot-9A), and serving
  the binary, and the `/papi/bootstrap` body evolution that fetches it, are
  tracked apart from this FDR.
- **macOS is partial.** Profile activation via `home-manager` is in scope; native
  `codesign` of the binary for macOS is a later phase (papi#28 v2).
- **Authed reads need a live §5 box backend.** `profiles[]` (and the identity
  decrypt) ride the slot-9D §5 path; the reference server's box backend is
  currently absent/503 (papi#8), so the authed-read stage — and thus
  apply-host-profile — is gated on that backend going live. Known iteration-2
  operational dependency.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| run-state / stamp path | a fixed root-owned dir (e.g. `/var/lib/<installer>/`) | stable across reboots; not group/world-writable (RFC-0003 §7 security) | a platform needs a different stable location |
| non-interactive ambiguity | fail with the visible `id`s when >1 profile and no `--profile` | never guess which host a machine should become (RFC-0003 §4) | operators want a documented default profile |
| TUI vs ndjson-crap | auto by TTY | interactive when a human watches, parseable when piped | a need for forced-interactive or forced-stream |

## More Information

- RFC-0003 (`docs/rfcs/0003-staged-installer-phase-contract.md`) — the normative
  phase-manifest contract this binary implements (the framework side).
- RFC-0001 §11 (`caches[]`), §12 (identity-bootstrap consumption), §13 +
  Amendment 11 (`profiles[]`) — the PAPI datasource this consumes.
- FDR-0003 (`0003-papi-self-bootstrap-endpoint.md`) — the bash `provision.sh`
  self-bootstrap path this is the iteration-2 evolution of (supersedes once the
  binary path is proven; not yet).
- papi#28 — the installer signing strategy (slot-9A binary signature + nix-closure
  Ed25519); the `/papi/bootstrap` body evolution that fetches the signed binary.
- [cloud-init] — the boot-anchored-stages / frequencies / datasource model this
  framework adapts.
- eng: `bin/provision.sh` (the staging content the framework's phases wrap),
  `nixosModules`, eng#201 / eng `docs/features/0006` (the unified provisioner).
