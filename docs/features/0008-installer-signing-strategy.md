---
status: proposed
date: 2026-06-25
promotion-criteria: >
  proposed → experimental: the papi-built installer binary (FDR-0006) carries a
  detached slot-9A (P-256) signature, and the evolved GET /papi/bootstrap body
  verifies that signature + a digest pin before exec on a non-cold host.
  experimental → testing: a cold host fetches, verifies (slot-9A detached sig +
  digest pin), and execs the binary end to end (regime A), and the closures it
  pulls post-Nix verify against an Ed25519 cache key advertised in caches[] §11
  (regime B) — both regimes exercised in one provisioning run.
  testing → accepted: both regimes hold on a second host on a different platform,
  and neither the signature format nor the two-key split changes for two weeks.
---

# Installer signing strategy (binary: slot-9A P-256 · closures: Ed25519)

## Problem Statement

The staged installer (FDR-0006) is a static binary fetched and run by a cold host
**before Nix exists**, and everything it pulls *after* it stages Nix is verified by
Nix's own store-path signing. These are two different trust problems with two
incompatible algorithm constraints, so **one key cannot cover both**:

- The **binary** runs pre-Nix, so it cannot use Nix-native signing; it needs a
  signature that travels beside a downloaded executable and is checked by a small
  embedded verifier before `exec`. The subject's PIV **slot-9A is ECDSA P-256**,
  which is fine here.
- **Nix store-path signing is Ed25519-only** (`nix key generate-secret` emits an
  Ed25519 secret; `nix store sign` takes `--key-file` only — no PKCS#11 / hardware
  option). slot-9A's P-256 key **cannot** produce Nix-verifiable signatures.

So: **two regimes, two keys.** Don't force one key to sign both.

## Interface

| Regime | Signs | Key / alg | Travels how | Verified by |
|---|---|---|---|---|
| **A — binary** | the standalone installer binary | **slot-9A P-256** detached sig | a sidecar beside the binary | a small embedded verifier, **pre-Nix**, before `exec` |
| **B — closures** | nix store paths | **Ed25519** cache key | the cache `.narinfo` `Sig:` field | `nix`, via `trusted-public-keys` = PAPI `caches[]` (RFC-0001 §11) |

### Regime A — the bootstrap binary (pre-Nix, detached signature)

- **v1, Linux (primary).** Linux has **no embedded-in-ELF, travels-with-the-binary**
  code-signing format for downloaded userspace executables (unlike PE/Authenticode
  or Mach-O's `LC_CODE_SIGNATURE`). Its native mechanisms — kernel module signing
  (the sig is appended *outside* the ELF container), IMA appraisal (`security.ima`
  xattr), fs-verity (Merkle digest + optional PKCS#7), dm-verity — are
  kernel/filesystem-bound and **don't survive a plain download**. So the signature
  is **detached**, carried beside the binary, made by slot-9A
  (`piggy sign-bytes --slot 9a`, P-256 raw `r‖s`); evaluate `piggy`-direct + a
  papi-side verify vs `cosign`/`minisign` driven over PKCS#11 (OpenSC/ykcs11). The
  evolved `GET /papi/bootstrap` body (its companion change, the FDR-0003 successor)
  fetches the binary and verifies the slot-9A signature **plus a digest pin**
  before `exec` — the signing format chosen here and that verify step MUST match.
- **v2, macOS (`codesign`).** Native Mach-O signing for Gatekeeper. Open: whether a
  PIV-backed Keychain identity (slot-9A via CryptoTokenKit) can drive `codesign`
  directly, and that notarized distribution needs an Apple Developer ID cert a bare
  PIV identity cannot substitute (the slot *could* potentially hold the Developer
  ID key — TBD).

### Regime B — Nix closures (post-Nix, Nix-native signing)

Once the binary stages Determinate Nix, everything it pulls afterward (Nix itself,
eng config, home-manager closures) is verified by Nix store-path signing, which
papi **already models** as `caches[].trusted_public_keys` (RFC-0001 §11;
`Cache.TrustedPublicKeys []string`). Nix signs the store-path **fingerprint** (NAR
hash + size + references), not the raw bytes; the signature rides in the cache
`.narinfo` `Sig:` field. The cache's Ed25519 **public** key is published in
`caches[]`; the **secret** is held by whatever capable host populates the cache,
never by the cold host. Cache keys are honored only against a verified §10 document
signature (FDR-0006).

## Examples

    # Regime A — sign the binary with slot-9A, publish the detached sidecar:
    $ piggy sign-bytes --slot 9a < papi-installer > papi-installer.sig
    # served beside the binary; /papi/bootstrap verifies sig + digest before exec.

    # Regime B — the cache's Ed25519 key signs closures; its public half is in caches[]:
    $ nix key generate-secret --key-name cache.<domain>-1 > cache.key
    # papi caches[].trusted_public_keys advertises the public half (RFC-0001 §11);
    # `nix` verifies pulled store paths against it via trusted-public-keys.

## Limitations

- **Not yet implemented; gated on the binary.** This FDR is the strategy; the
  installer binary (FDR-0006) does not exist yet, and iteration-1 (the bash path)
  was dropped. Regime A cannot be exercised until the binary is built and the
  `/papi/bootstrap` verify step lands.
- **Two keys, by necessity.** slot-9A (P-256) signs the binary; a **separate**
  Ed25519 cache key signs closures. They are not interchangeable — the collision
  (P-256 vs Ed25519) is the whole reason for the split.
- **Hardware-backed Nix signing is not free.** Putting an Ed25519 key on a YubiKey
  needs **firmware 5.7+** (Ed25519/X25519 are new-in-5.7 PIV); even then
  `nix store sign` is key-file-only, so hardware-backed regime-B signing would need
  out-of-band signature + `.narinfo` injection, or a Nix fork/patch — recorded as
  an option, not a commitment. The default is a software-held Ed25519 cache key.
- **macOS (v2) is open.** PIV-driven `codesign` and notarized (Developer ID)
  distribution are unresolved (Regime A v2).

## Cross-repo / open explorations

- **piggy: Ed25519 support.** piggy signs with slot-9A P-256 today; any Ed25519
  (hardware-backed regime B, or Ed25519 anywhere) needs piggy Ed25519 signing **and**
  an Ed25519 PIV slot (FW 5.7+). Likely a piggy-side issue if pursued.
- **piggy sops/age for the secrets leg.** How piggy's age mechanism
  (`age-plugin-piggy`, slot-9D ECDH decrypt) covers the AUTHED bootstrap's secrets
  retrieval (RFC-0001 §12.3 deferred SECRETS) — distinct from either signing
  regime; open.
- **Nix fork for PIV/PKCS#11 store-path signing.** Because `nix store sign` is
  key-file-only, hardware-backed Ed25519 Nix signing would need `.narinfo`
  injection or a Nix patch. High maintenance; examine, don't commit.
- **Out of scope (recorded):** Windows Authenticode (smart-card-backed) — noted
  for completeness; not planned.

## More Information

- papi#28 — the origin issue; this FDR consolidates it into the design tree.
- FDR-0006 (`0006-staged-host-installer.md`) — the binary this signs; regime-A
  verify is its pre-`exec` gate, and the heavy host-profile build is the regime-B
  consumer.
- FDR-0003 (`0003-papi-self-bootstrap-endpoint.md`) — the `GET /papi/bootstrap`
  body whose successor performs the regime-A verify + digest pin.
- RFC-0001 §11 (`caches[].trusted_public_keys`) — regime B's trust anchor; §10
  (document signature) — the slot-9A markl signatures gating the cache keys.
- Nix manual — `nix key generate-secret` (Ed25519; key format), `nix store sign`
  (`--key-file` only). Yubico — 5.7 firmware (Ed25519/X25519 new in PIV). kernel.org
  — module signing (appended outside the ELF container), fs-verity (no
  travels-with-the-binary ELF signature).
