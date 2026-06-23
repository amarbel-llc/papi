---
status: proposed
date: 2026-06-23
---

# Staged Installer Phase-Manifest Contract

## Abstract

The staged installer is a signed static binary that brings a cold host into a
subject's configuration by running an ordered sequence of phases. This document
specifies the contract between that **framework** binary and the **phase
content** it executes: a cloud-init-inspired model of ordered, idempotent,
optionally boot-anchored stages whose ordering, platform detection, gating, and
reboot-and-resume are owned by the framework, while the per-phase work is
supplied as content. It defines the phase manifest, the platform-detection and
datasource-read model (PAPI as the installer's datasource), the
system-config-before-build ordering invariant and the cycle it breaks, and the
reboot/resume mechanism by which a phase may require a reboot and the run
continues afterward.

## Introduction

The host bootstrap is evolving from a single POSIX-sh shim (FDR-0003's
`provision.sh`, fetched via `GET /papi/bootstrap`) into a **staged installer**: a
static binary, built by `amarbel-llc/papi`, embedding the PAPI client and a TUI,
signed by the subject's PIV slot-9A key and served from the subject's PAPI
instance. The binary mediates a public→authenticated transition — it stages a
host far enough to authenticate with the local PIV card directly, then reads the
subject's PAPI as a **datasource** (identity, RFC-0001 §12; nix caches, §11; host
profiles, §13) to select and activate a host profile.

This RFC specifies the seam between the framework and the phase content a
host-config repository supplies, so that:

- the **framework** (the binary) can execute any conformant phase set, and
- a **host-config repository** can supply conformant phase content and have its
  ordering, platform applicability, and reboot behavior honored.

Two requirements drive the model:

1. **Ordering invariant.** A host's system configuration MUST be applied before
   anything is built or activated against it.
2. **Reboot-and-resume.** A phase MAY require a reboot (e.g. a cold NixOS host
   whose system-config phase changes kernel/initrd), and the run MUST resume on
   the subsequent boot.

The model adopts the **semantics** of cloud-init [cloud-init] — ordered stages,
per-phase frequencies as the idempotency primitive, a datasource abstraction,
and up-front platform/datasource detection (the `ds-identify` analog) — with an
**installer-specific stage set**, not cloud-init's literal
`Local`/`Network`/`Config`/`Final`.

Out of scope: the binary's build and signing (a separate concern), the
`profiles[]` wire resource (RFC-0001 §13), and a host-config repository's
specific phase content.

> **Editorial note — §2 and §3 ownership.** Detection (§2) is framework-owned.
> For §3, the user steer and the eng-side review converged: the **stage set and
> ordering** (which encode the §5 correctness invariant) are **framework-owned**
> and defined by this RFC, while a host-config repository supplies the **per-stage
> content**. What remains unsettled — and SHOULD be treated as not yet stable — is
> the manifest's exact serialization and where the host-config content lives, not
> the ownership split.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### 1. Model and roles

The **framework** is the installer binary. It owns: platform detection (§2),
phase ordering and gating (§3, §5), idempotency (§6), reboot and resume (§7),
PAPI datasource access (§4), and progress rendering (§8). **Phase content** is
the work each phase performs, supplied by a host-config repository and invoked by
the framework through the hook contract (§8).

A **run** is one end-to-end execution toward an activated host profile. A run MAY
span multiple **boots** — the framework MUST make a run resumable across reboots
(§7). The framework MUST execute phases in the order the manifest and stage model
define (§3, §5); it MUST NOT delegate ordering decisions to phase content.

### 2. Platform detection

> Provisional — see the editorial note in the Introduction.

The framework MUST detect the host platform once per run, before executing any
platform-conditioned phase, and MUST expose the resolved platform to every phase
(§8). The defined platform tokens in v0 are:

- `nixos` — a NixOS host,
- `linux` — a non-NixOS Linux host,
- `darwin` — macOS.

Phase content MUST NOT perform its own platform detection to decide whether to
run, and MUST NOT self-skip based on platform. A phase's applicability is decided
by the framework from the manifest's platform conditions (§3) against the
resolved platform. This requirement exists to remove the self-skip anti-pattern
in which a phase silently no-ops on a platform, leaving an ordering dependency
unsequenced.

### 3. The phase manifest

> See the editorial note in the Introduction. The **stage set + ordering** (§5)
> are framework-owned (a shared correctness invariant — piggy-is-a-build-output
> holds for every consumer, not just one host-config repo); a host-config
> repository supplies the **per-stage content**. The manifest's exact
> serialization remains to be finalized.

The framework defines the canonical **stage set** and its order (§5); these are
not consumer-configurable, because the order encodes the §5 correctness invariant.
A **phase manifest** binds **phase content** to those framework-defined stages: it
declares the phases the framework runs, each assigned to a `stage`. A host-config
repository supplies the per-stage phases and MAY declare more than one phase
within a stage, but MUST NOT introduce, remove, or reorder stages. Each **phase
entry** MUST contain:

| Field   | Type   | Required | Meaning                                                                 |
| ------- | ------ | -------- | ----------------------------------------------------------------------- |
| `id`    | string | MUST     | Stable identifier, unique within the manifest.                          |
| `stage` | string | MUST     | The ordered stage this phase belongs to (§5).                           |
| `hook`  | string | MUST     | Reference to the phase content the framework invokes (§8).              |

and MAY contain:

| Field            | Type     | Meaning                                                                          |
| ---------------- | -------- | -------------------------------------------------------------------------------- |
| `platforms`      | string[] | Platform tokens (§2) this phase applies to; absent means all platforms.          |
| `gates`          | string[] | Phase `id`s that MUST complete before this phase runs (in addition to stage order). |
| `frequency`      | string   | Idempotency frequency (§6); absent defaults to `per-instance`.                   |
| `requires_reboot`| boolean  | Whether the run MUST reboot after this phase and resume at the next (§7).         |

Stages are ordered (§5); phases within a stage run in declared order. The
framework MUST refuse a manifest that contains a duplicate phase `id`, a phase
whose `stage` is not a defined stage token (§5), a `gates` entry referencing an
unknown phase `id`, or a `frequency` value it does not understand — it MUST fail
the run with a diagnostic rather than execute a partial or reordered set.

A conformant manifest fragment (illustrative):

    stages: [detect, land-content, apply-minimal-sysconfig, build-and-auth,
             authed-read, apply-host-profile, user-layer, final]
    phases:
      - id: minimal-nix-settings
        stage: apply-minimal-sysconfig
        platforms: [nixos]
        frequency: per-instance
        requires_reboot: false
        hook: phases/minimal-nix-settings
      - id: host-profile
        stage: apply-host-profile
        gates: [authed-profile-read]
        frequency: per-instance
        requires_reboot: true
        hook: phases/host-profile

### 4. Datasource (PAPI) and read timing

The framework consumes the subject's PAPI as the installer's **datasource**:
identity material (RFC-0001 §12), nix binary caches (§11), and host profiles
(§13, `profiles[]`).

Datasource reads fall into two tiers:

- **Anonymous reads** (public PAPI projection) MAY occur at any stage.
- **Authenticated reads** (a §5 session) MUST NOT occur before the
  `build-and-auth` stage (§5) has produced the build tooling and established a §5
  session. The framework satisfies the §5 challenge/response by **direct access
  to the local PIV card** (the slot-9D ECDH operation, e.g. via `pivy-box`),
  requiring only that the card is present and the build tooling (pivy) exists — it
  MUST NOT require the piggy **agent service**, which is itself a build /
  home-manager output and would deepen the build/auth cycle (§5). A running piggy
  agent, local or forwarded, MAY also satisfy the session but MUST NOT be a
  precondition.

`profiles[]` (§13) is an authenticated read. The framework MUST read it only
after the auth stage, select a profile (interactively via the TUI, or
non-interactively by a pinned `#id`), and pass the resolved profile `id` and
`flakeref` to subsequent phases (§8). A non-interactive run with more than one
visible profile and no pinned `#id` MUST fail with a diagnostic rather than
guess.

### 5. Stage ordering and the system-config split

**Ordering invariant.** The stage that applies system configuration MUST precede
the stage that builds or activates against it.

**The cycle.** The card-auth agent (piggy) is itself a build output, so the
authenticated datasource read (`profiles[]`) depends on piggy, which depends on
build/activate, which depends on the system configuration that makes the build
possible. A single, profile-driven system-config stage placed before the build
would therefore be circular.

**The break (normative).** System configuration MUST be split into two stages:

- a **minimal, pre-auth, profile-independent** stage that produces a
  **build-capable nix**: on a host without nix (a non-NixOS cold host) it installs
  nix (e.g. Determinate Nix) and applies the daemon settings the build requires
  (flakes, recursive-nix, dynamic-derivations); on NixOS it applies those settings
  via a minimal `nixos-rebuild` (the host-config's base NixOS module). It MUST NOT
  depend on `profiles[]` or any authenticated read, it MUST precede (gate) the
  build/activate stage, and the framework MUST orchestrate the nix install rather
  than presupposing nix already exists; and
- a **full, post-auth, profile-driven** stage that applies the selected host
  profile's `flakeref`. It MUST run only after the authenticated profile read
  (§4).

**Canonical stage order.** The framework MUST enforce the following stage order;
individual phases within each stage are platform-conditioned (§2, §3):

1. `detect` — resolve platform and datasource (§2, §4).
2. `land-content` — acquire the host-config repository.
3. `apply-minimal-sysconfig` — produce a build-capable nix (install nix on a host
   that lacks it) and apply the minimal daemon settings; **gates** the build stage.
4. `build-and-auth` — build the bootstrap tooling (pivy, the papi client) needed
   to authenticate against the card; the piggy agent service is NOT required here
   (§4).
5. `authed-read` — authenticate (§5) and read `profiles[]`; resolve the selected
   profile (§4).
6. `apply-host-profile` — apply the full, profile-driven system configuration.
7. `user-layer` — user-scoped configuration (identity, dotfiles, SSH key sync).
8. `final` — run completion; tear down any resume facility (§7).

Reboot anchoring (§7) is most relevant at stage 6, where boot-level configuration
(kernel/initrd) may change; the minimal stage 3 typically requires only a daemon
restart, not a reboot.

### 6. Execution and idempotency

Each phase has a **frequency** governing whether the framework re-runs it:

- `once` — run at most once per host, ever;
- `per-instance` — run once per install instance (the default);
- `per-boot` — run on every boot the run touches.

The framework MUST persist a completion **stamp** per phase, keyed by the phase
`id` and its frequency, in the run-state store (§7). Before running a phase, the
framework MUST consult the stamps and MUST NOT re-run a phase whose
frequency and stamp indicate it is already satisfied.

A phase MUST NOT start until every phase in its `gates` and every phase in
prior stages it depends on has completed successfully. A phase that exits
non-zero (§8) MUST halt the run — the framework MUST NOT execute downstream
phases — unless the manifest marks the phase non-fatal (a future OPTIONAL field).

### 7. Reboot and resume contract

A phase MAY set `requires_reboot`. After such a phase completes, the framework
MUST persist the run state — the per-phase stamps (§6), the resolved platform
(§2), and the selected profile (§4) — then trigger a reboot, and on the
subsequent boot **resume** at the next phase in order.

Resume requires the framework binary to be re-invoked after the reboot. The
framework defines the resume contract; the system-config content emits the
mechanism that honors it:

- The framework MUST persist its own binary (or be persisted) at a stable,
  root-owned path, and MUST record that path and the run-state location in the
  persisted run state.
- The re-invocation MUST be performed by a **boot-anchored unit**. On `nixos`,
  the bootstrap generation's NixOS module MUST declare a one-shot systemd unit
  that, on next boot, re-execs the persisted framework binary in resume mode
  against the recorded run state, ordered appropriately within boot.
- **Teardown is platform-specific and MUST NOT rely on a unit deleting itself** (a
  NixOS unit is declarative and cannot self-delete). On `nixos`, the resume unit
  MUST exist only in the transient bootstrap generation: the final host
  configuration applied by `apply-host-profile` MUST NOT declare it, so it
  disappears on the real activation. On `linux`/`darwin`, the framework MUST guard
  the unit by the run-state stamps so it no-ops once the run reaches `final`.
- The framework owns the contract — the persisted binary path, the resume-mode
  invocation, and the run-state/stamp location; the host-config repository's
  system-config module emits the unit conforming to it.

The run-state store and the persisted binary MUST live at a stable, root-owned
path that is not group- or world-writable. Resume MUST be idempotent: if the host
reboots unexpectedly mid-phase, re-invocation MUST re-enter at the correct phase
as determined by the stamps (§6), neither skipping an incomplete phase nor
re-running a completed `once`/`per-instance` phase.

### 8. Phase-hook invocation contract

The framework invokes each phase's `hook` with the resolved run context:

- the resolved platform token (§2),
- the selected profile `id` and `flakeref` when resolved (§4),
- a handle to the PAPI datasource and the established session (so a hook may
  perform further reads),
- the run-state/stamp directory (§7).

These MUST be passed by a stable, documented mechanism (environment variables);
the exact variable names are pinned by the framework's implementation and listed
in its reference documentation.

A hook MUST signal success with exit code 0 and failure with a non-zero exit code
(§6). A hook MAY emit structured progress on its standard output for the
framework to render via the TUI; the framework MUST render per-phase status
(start, success, failure) for every phase regardless of whether its hook emits
progress. Hooks that emit progress MUST flush each progress record so the TUI
reflects it promptly.

## Security Considerations

**Phase content runs as root.** The framework executes phase content with the
privilege required to apply system configuration and drive the nix daemon. The
trust anchors are that the installer binary is signed (the subject's PIV slot-9A
key) and the host-config repository is reviewed and version-controlled. The
framework SHOULD verify that the content it lands resolves into the reviewed
host-config source (e.g. the §13 `flakeref` resolves into the expected
repository) before invoking hooks.

**Authenticated datasource gating.** Authenticated reads require a §5 session
proven by control of a published recipient's PIV key; `profiles[]` projection
(§13.2) means a host only sees and activates the profiles its identity admits. A
host cannot escalate to another identity's profiles without that identity's card.

**Resume facility is a re-exec foothold.** The boot-anchored resume unit (§7)
re-execs a root binary at a recorded path. That path and the run-state directory
MUST be root-owned and not group- or world-writable; otherwise a local attacker
could substitute the resume binary or tamper with stamps to alter or replay
phases. The resume facility MUST NOT persist past `final` (§7: the NixOS final
generation omits the unit; the non-NixOS unit stamp-guards to a no-op), so it is
not a standing re-exec foothold after the run completes.

**Manifest integrity.** The manifest comes from the reviewed host-config source;
the framework MUST refuse a malformed manifest (§3) rather than guess, so a
corrupted or truncated manifest cannot silently reorder or drop a gating phase.

## Conformance Testing

The framework binary implements this specification; conformance tests live in the
framework binary's `zz-tests_bats/` directory (path finalized when the binary
lands in iter-2).

Tests use binary injection via `bats-emo`:

    require_bin FRAMEWORK <installer-binary-name>

### Covered Requirements

| Requirement | Description |
|-------------|-------------|
| §2, MUST | Resolved platform is exposed to phases; phase content cannot self-skip by platform. |
| §3, MUST | A malformed manifest (duplicate `id`, unknown `stage`/`frequency`, dangling `gates`) fails the run. |
| §4, MUST NOT | No authenticated datasource read (incl. `profiles[]`) occurs before the auth stage. |
| §5, MUST | `apply-minimal-sysconfig` precedes and gates the build; `apply-host-profile` runs only after the authed read. |
| §6, MUST NOT | A satisfied `once`/`per-instance` phase is not re-run; gated/failed phases halt downstream execution. |
| §7, MUST | A `requires_reboot` phase persists run state and resumes at the next phase; resume is idempotent across an unexpected reboot. |

## Compatibility

This is a new interface with no prior consumers. It coexists with FDR-0003's
`provision.sh` self-bootstrap shim: the bash path remains the live cold-host
entrypoint until the binary path is proven (the shim is iteration 1; this
framework is iteration 2). This document specifies the v0 phase-manifest
contract. Additive changes — new `frequency` values, new stage tokens, new
OPTIONAL phase fields — SHOULD be designed so that an older framework skips what
it does not understand rather than failing, following the skip-unknown discipline
of RFC-0001 (§1.1, §7.1 `kind`); changes to the canonical stage order (§5) or the
resume contract (§7) are breaking and would require a superseding revision.

## References

### Normative

- [RFC-0001] Personal API (PAPI) Wire Format and HTTP Interface — §5
  (authentication handshake), §11 (`caches[]`), §12 (identity-bootstrap
  consumption), §13 (`profiles[]`). `docs/rfcs/0001-personal-api-papi-wire-format.md`.

### Informative

- [cloud-init] cloud-init boot stages and modules — the staged, frequency-keyed,
  datasource-driven provisioning model this contract adapts.
  <https://docs.cloud-init.io/en/latest/explanation/boot.html>
- [FDR-0003] PAPI self-bootstrap endpoint (`GET /papi/bootstrap`) — the
  bash-shim path this framework supersedes. `docs/features/0003-papi-self-bootstrap-endpoint.md`.
- [eng-0006] eng's unified, idempotent `provision.sh` (the self-re-exec'ing
  provisioner the framework's `land-content`/staging model draws on).
