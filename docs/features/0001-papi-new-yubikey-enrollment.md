---
status: proposed
date: 2026-06-21
promotion-criteria: >
  exploring → proposed: this document (full design drafted, cross-repo seams
  confirmed with piggy/site-linenisgreat/eng). proposed → experimental: `papi
  enroll` + `papi verify-receipt` land and produce/verify a receipt against a
  fibby card end-to-end. experimental → testing: one real new YubiKey enrolled
  into site-linenisgreat via the receipt, with the deploy-side verifier gating
  the publish. testing → accepted: a second card enrolled with no manual
  papi.json edit and no lever changes for two weeks.
---

# PAPI new-YubiKey enrollment (`papi enroll` + the card-enrollment receipt)

## Problem Statement

Adding a new YubiKey to an existing PAPI deployment is, today, a hand-edit: an
operator opens `site-linenisgreat`'s `api/protected/data/papi.json`, pastes a
slot-9D encryption recipient and a slot-9A `authorized_keys` line into the
`piggy` object by hand, commits, and rsyncs. Nothing generates that key
material, nothing checks that the two slots belong to the same card, and the
only trust boundary is "whoever has git write + SSH deploy access" — there is no
evidence that an *already-trusted* key authorized the addition. This feature
replaces the hand-edit with an interactive `papi` subcommand that provisions a
fresh card and emits a verifiable **enrollment receipt**, and adds a deploy-side
verifier so a new key is published only when an already-trusted key has attested
it.

## Interface

### Slot roles (the two keys a YubiKey contributes)

A PAPI identity spans two PIV slots; the enrollment provisions **both** and the
receipt carries **both**. They are distinct mechanisms and must not be conflated
(this corrects an early framing in the design discussion):

| Slot | PIV function | markl-id purpose | Algorithm | Used for |
|---|---|---|---|---|
| **9D** | Key Management (ECDH) | `piggy-recipient-v1@pivy_ecdh_p256_pub-…` | eccp256 (P-256) | The §5 auth handshake: the server encrypts a challenge nonce *to* this recipient; the card decrypts it (`pivy-box stream decrypt`). Lands in `piggy.encryption_recipients[]`. |
| **9A** | Authentication | `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…` | eccp256 (P-256) | The published SSH-auth/signing key: git clone via SSH agent, the §9.3 proof-claim signature (`papi-proof-sig-v1`), and the §10 document signature (`papi-doc-sig-v1`). Lands in `piggy.ssh_authorized_keys[]` (and `/papi/piggy-ids`). |

§5 is a **slot-9D box decrypt**; signing/attestation is always a **slot-9A**
operation (a 9D ECDH key cannot produce an ECDSA signature).

### Dependency direction: papi is downstream of piggy

papi **depends on piggy, never the reverse**, and piggy's interface stays
**low-level and papi-agnostic**: piggy knows nothing of enrollment receipts, the
`papi-*` markl purposes, or the §9.3/§10 claim and canonicalization rules. papi
calls only generic PIV/age primitives and composes the papi-specific artifact
itself. piggy (and the `pivy-tool` / `age-plugin-piggy` it fronts) exposes three
papi-agnostic primitives:

1. **generate** — provision slot 9D + 9A on a fresh card;
2. **read back** — emit the card's identity material (the slot-9D recipient id,
   the slot-9A `authorized_keys` line, the age recipient), keyed by GUID;
3. **sign** — produce a slot-9A ECDSA P-256 signature over *arbitrary bytes* for
   a given card GUID, returned as the raw `r‖s` (or SSH-wire papi strips to it).

papi owns everything papi-shaped: the claim strings, the `papi-proof-sig-v1` /
`papi-enroll-att-v1` markl-id wrapping, the `papi-enroll-receipt-v1` schema, and
the §10.2 canonicalization. The **sign** primitive signs bytes and returns a bare
signature — it does **not** mint a papi purpose or assemble a receipt; papi
decorates the raw signature with its own purpose afterward. This keeps
markl-purpose ownership (ADR-0006) and the layering aligned: **piggy mints keys
and signs bytes; papi gives those bytes their papi meaning.**

### The command: `papi enroll <domain>`

A new cobra subcommand alongside `validate`/`person`/`ssh-keys`/`repos`/`query`,
driving an interactive [huh](https://github.com/charmbracelet/huh) TUI. It runs
four steps over the low-level piggy primitives above and emits one artifact:

> **Implementation status.** Implemented papi-side: steps 2–4 (read-back,
> self-sign, attest) over an already-provisioned card, AND step 1 — a **huh card
> picker** (blank cards selectable, the provisioned trusted card shown but
> unselectable) → confirm → `piggy card init`. `papi enroll <domain>` shows the
> picker by default; `--new-guid <G>` enrolls an already-provisioned card,
> `--new-serial <N>` picks the blank one non-interactively, `--trusted-guid` (or
> the sole provisioned card) is the attester, and `--allow-reprovision`
> ([papi#18](https://github.com/amarbel-llc/papi/issues/18)) makes provisioned
> cards selectable too — choosing one resets it (destroys its keys) and
> re-provisions, behind a loud extra confirm (the explicit, opt-in escape hatch).
> **Gated on piggy** for the live
> data: the blank card only appears once `piggy list` lists unprovisioned cards
> (piggy#193) and is provisioned by piggy#194 (`piggy card init --serial`);
> papi is wired to both and works the moment they ship
> ([papi#17](https://github.com/amarbel-llc/papi/issues/17)). Card *selection*
> is by serial (piggy's enumeration), since `pivy-tool` has no serial selector.

1. **Generate the fresh card** (the *new* YubiKey) — papi shells out to the C
   `pivy-tool` binary (piggy has no fresh-card command; it exposes `pivy-tool`
   as an exec passthrough via `piggy tool <op>`). The scriptable building blocks:

       pivy-tool [-K <adminkey>] init                                  # GUID + CHUID on a blank card
       pivy-tool -K <adminkey> generate -a eccp256 -n <cn> [-i once] [-t cached] 9d
       pivy-tool -K <adminkey> generate -a eccp256 -n <cn> [-i once] [-t cached] 9a
       pivy-tool -P <oldpin> change-pin <newpin>                       # positional newpin avoids the TTY prompt
       pivy-tool change-puk <newpuk>
       pivy-tool set-admin <hex|@file>                                 # rotate the management key

   `generate` is non-interactive when `-K`/`-P` are supplied; only the PIN/PUK
   change prompts unless the new value is positional. The TUI collects the
   admin key, PIN/PUK, CN, PIN/touch policy, and (when more than one card is
   attached) the target GUID, and runs these steps with a progress view. The
   `pivy-tool setup` one-shot is deliberately **not** used — it is YubiKey-only,
   also provisions 9C(RSA2048)/9E, uses default policies, and is interactive.

2. **Read back the new card's identity material** (read-only, PIN-free), keyed
   by the card GUID:

       age-plugin-piggy generate --guid <GUID>      # age recipient (age1piggy…)
       piggy list --format=ndjson                   # slot-9D record's "id" = the markl recipient
       piggy list --format=ssh                      # slot-9A authorized_keys line (filter slot=9A guid=<GUID>)

   (`piggy pass recipients list-available --format=ndjson` is the recipient-only
   variant.) papi always passes `--format=ndjson` explicitly so a piped capture
   never falls back to the human format.

3. **Self-sign the binding** — papi builds the `self_proof` claim (naming both
   the new card's 9D recipient id and 9A key id) and calls the generic slot-9A
   **sign** primitive on the *new* card (`piggy sign-bytes --slot 9a --guid
   <new-guid> --format raw`, direct PCSC) over the claim bytes, then wraps the
   returned raw `r‖s` in a `papi-proof-sig-v1` markl-id. piggy signs bytes; papi
   owns the purpose.

4. **Authenticate the trusted card and attest** — the TUI prompts the operator to
   present the *already-bootstrapped* YubiKey; papi computes the receipt's
   canonical bytes (§10.2, `attestation` stripped), calls the same generic slot-9A
   **sign** primitive on the *trusted* card (`piggy sign-bytes --slot 9a --guid
   <trusted-guid> --format raw`), and wraps the result in a `papi-enroll-att-v1`
   markl-id. The receipt now binds the new key (self_proof) and is authorized by
   an existing trusted key (attestation).

The slot-9A **sign** primitive is the merged, fibby-verified `piggy sign-bytes
--slot 9a [--guid X] --format raw` (piggy#190): it signs stdin verbatim (SHA-256
intrinsic), GUID-selectable, direct-PCSC, and returns the **raw 64-byte `r‖s`** —
exactly the markl `ecdsa_p256_sig` payload, so papi needs no DER/SSH-wire parse.
papi never asks piggy to mint a `papi-*` purpose or assemble a receipt — it drives
**both** signatures itself (the existing `piggy papi prove`/`piggy papi sign` are
claim/doc signers with piggy's own strip rules, so papi does not reuse them for
the receipt).

#### The enrollment receipt (`papi-enroll-receipt-v1`)

`papi enroll` writes one JSON file. Its `recipient` and `ssh` blocks use
`site-linenisgreat`'s `papi.json` field names **verbatim** so a deploy step can
splice them into `piggy.encryption_recipients[]` / `piggy.ssh_authorized_keys[]`
with no reshaping (PersonalApi.php reads those fields positionally):

    {
      "schema": "papi-enroll-receipt-v1",
      "domain": "linenisgreat.com",
      "guid": "<HEX>",
      "created": 1750000000,
      "recipient": {                              // → piggy.encryption_recipients[]
        "visibility": "public",
        "label": "yubikey-9d-<guid8>",
        "scheme": "piggy-recipient-v1",
        "id": "piggy-recipient-v1@pivy_ecdh_p256_pub-…",
        "note": "enrolled <date>"
      },
      "ssh": {                                    // → piggy.ssh_authorized_keys[]
        "visibility": "public",
        "label": "yubikey-9a-<guid8>",
        "id": "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…",
        "purpose": "piggy-piv_auth-v1",
        "key_type": "ecdsa-sha2-nistp256",
        "line": "ecdsa-sha2-nistp256 AAAA… piggy slot=9A guid=<HEX> cn=<name>"
      },
      "age_recipient": "age1piggy…",              // convenience; not consumed by the site
      "self_proof": {                             // new card binds its own 9D ↔ 9A (reuses §9.3)
        "claim": "papi-enroll-receipt-v1 binds piggy-recipient-v1@…<9D> to piggy-piv_auth-v1@…<9A>",
        "sig": "papi-proof-sig-v1@ecdsa_p256_sig-…"   // new card's slot-9A over claim bytes
      },
      "attestation": {                            // trusted card authorizes the new key
        "key": "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…",  // an already-PUBLISHED slot-9A key
        "sig": "papi-enroll-att-v1@ecdsa_p256_sig-…",         // trusted card's slot-9A over the receipt's JCS bytes
        "created": 1750000000
      }
    }

- **`self_proof`** reuses the §9.3 `papi-proof-sig-v1` purpose: the *new* card's
  slot-9A key signs a claim string that names both of its own slot ids, proving
  the 9D recipient and 9A key are the same card/holder.
- **`attestation`** is the trust upgrade. The *trusted* (already-bootstrapped)
  card's slot-9A key signs the receipt's canonical (RFC 8785 JCS) bytes with the
  `attestation` member removed — exactly the §10.2 strip-and-canonicalize
  discipline, applied to the receipt. It uses a **new papi-owned markl purpose**,
  `papi-enroll-att-v1@ecdsa_p256_sig`, registered per ADR-0006 (so a §10
  document-signature verifier never mistakes a receipt attestation for a document
  signature). It is a natural third sibling to `papi-doc-sig-v1` (over doc JCS)
  and `papi-proof-sig-v1` (over the §9.3 claim) under the same format; the
  blech32 body is purpose-independent, so the new purpose costs only a fixture
  row. Confirmed in design with piggy (piggy#190/#187): register it **papi-side**
  (the papi#10 framework-adoption home), *not* in piggy's transitional go/markl
  block. The verifying `key` MUST already be published on the target domain's
  `/papi/piggy-ids` — i.e. an existing, trusted card vouches for the new one.

papi already owns the verification machinery (`internal/0/markl`,
`internal/alfa/inspect`: `markl.Parse`, `ecdsaVerifyRaw`, slot-9A point matching
against `/papi/piggy-ids` + `ssh_authorized_keys[]`). `papi enroll` self-checks
the receipt it just produced before writing it.

### The companion verifier: `papi verify-receipt <receipt-file> --domain <domain>`

A second subcommand that re-runs the receipt's checks against the **live**
domain: the `self_proof` signature verifies against the receipt's own 9A key;
the `attestation` signature verifies against a slot-9A key **already published**
on `https://<domain>/papi/piggy-ids`; and the markl-ids are well-formed. Exit
non-zero on any failure. This is what the deploy side calls.

### Deploy-side: site-linenisgreat gains a verifier

`site-linenisgreat` has **no signature verifier today** — `PersonalApi.php`
echoes `signatures[]` verbatim and treats the markl `key`/`sig` as opaque
strings. This feature adds net-new verification there (owned by
`site-linenisgreat`, tracked separately):

- A new `just papi-verify-keys` recipe runs `papi verify-receipt` (hard-fail) as
  a **`deploy-prod` prerequisite**: a new `piggy.*` entry is published only if a
  receipt attesting it verifies against an already-published slot-9A key.
- This verifier MUST stay **off** the hermetic `test-papi-unit` lane (and thus
  off the spinclass pre-merge gate): signature verification needs the piggy
  toolchain and a live `/papi/piggy-ids`, the same constraint that makes the
  challenge/response lane a skip-without-toolchain lane. `test-papi-unit` keeps
  doing only schema/projection sanity on the committed document.

### End-to-end flow

    operator (two cards)         papi enroll <domain>            artifact
    ────────────────────         ────────────────────            ────────
    new card    ─ generate ───▶  pivy-tool init/generate 9d,9a
                ─ readback ──▶   piggy list / age-plugin-piggy ─▶ recipient+ssh+age
                ─ self-proof ─▶  new 9A signs claim ───────────▶ self_proof
    trusted card─ attest ─────▶  trusted 9A signs receipt ─────▶ attestation
                                                                 └─▶ receipt.json
    operator → site-linenisgreat: splice recipient/ssh into papi.json,
        `just papi-verify-keys` (papi verify-receipt, hard-fail), `just deploy-prod`
    site re-signs the served document with §10 papi-doc-sig-v1 (existing flow, now used)

## Examples

Provision a new card and emit a receipt targeting `linenisgreat.com`:

    $ papi enroll linenisgreat.com
    # TUI: present NEW card → admin key / PIN / CN / policies → generate 9D+9A
    #      present TRUSTED card → attest
    # → wrote enroll-receipt-55C3439D.json (self_proof ✓, attestation ✓ vs linenisgreat.com)

Verify a receipt before deploying (the site's `deploy-prod` prerequisite):

    $ papi verify-receipt enroll-receipt-55C3439D.json --domain linenisgreat.com
    self_proof:  verified — new 9A signs the 9D↔9A binding (§9.3)
    attestation: verified — papi-enroll-att-v1 signs the receipt; key published on /papi/piggy-ids
    OK

Non-interactive generation building block (what the TUI runs under the hood):

    $ pivy-tool -K @admin.key -P 123456 generate -a eccp256 -n piv-auth@55C3439D -i once -t cached 9a

## Limitations

- **papi does not mutate the served document.** Per RFC-0001 §12.3, a
  state-mutating provisioning surface against a PAPI server is out of scope for
  `papi/v0` and would need its own RFC. `papi enroll` is a *client*: it emits a
  receipt; splicing it into `papi.json` and redeploying is `site-linenisgreat`'s
  out-of-band step (a commit + `deploy-prod`), not an API call.
- **piggy enumeration outputs are de-facto stable, not RFC-frozen.** The
  `piggy list --format=ndjson|ssh` and `age-plugin-piggy generate` shapes the
  receipt is built from are documented in source + man pages but not pinned by a
  versioned RFC (RFC-0003 covers the piggy-ids file, RFC-0005 the show-batch
  NDJSON). A pinned set of low-level, papi-agnostic piggy primitives (generate /
  readback / sign-bytes; see More Information) would replace this loose
  orchestration with stable contracts papi composes.
- **Single new card per run.** The TUI enrolls one card; bulk enrollment is out
  of scope.
- **No card generation in Go.** Key generation is the C `pivy-tool`; papi shells
  out. A Go/Rust pivy-tool port is piggy roadmap, not a dependency here.
- **The trusted card must already be published.** `attestation` verifies only
  against a slot-9A key already on the target's `/papi/piggy-ids`. Bootstrapping
  the *very first* card (no trusted key exists yet) is the existing manual path,
  not this flow.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| 9A PIN policy | `once` | one PIN entry per session for signing without re-prompting every op | operators want per-signature confirmation for a higher-trust card |
| 9A touch policy | `cached` | touch-to-sign without a touch per op inside a window | phishing-resistance review wants `always` |
| deploy-verify failure mode | hard-fail (`just papi-verify-keys`, off the hermetic gate) | a key that fails attestation must never publish; but crypto can't run on the hermetic pre-merge lane | site operators want a warn-only grace period during rollout |
| piggy primitives | signing via merged `piggy sign-bytes` (raw r‖s); readback via `piggy list`/`age-plugin-piggy`; generation still `pivy-tool` | piggy exposes only low-level, papi-agnostic ops; papi composes the receipt and owns the `papi-*` purposes | `piggy card init --serial` + blank-card `piggy list` (piggy#193/#194) land → papi drives those instead of `pivy-tool` for provisioning too |

## More Information

- **Issue:** [papi#15](https://github.com/amarbel-llc/papi/issues/15) — the feature request.
- **Deferred (v0):** [papi#17](https://github.com/amarbel-llc/papi/issues/17) —
  provisioning a blank fresh card (FDR step 1, generate) in `papi enroll`; the
  interactive huh TUI is also deferred. The shipped flag-driven command enrolls
  an already-provisioned card.
- **Companion feature:** PAPI-hosted self-bootstrap shim (a host with a
  provisioned card fetches a fetch-and-delegate script over PAPI and provisions
  itself against eng). Owned by `eng` (the real logic is `eng/bin/up.sh`); papi
  hosts the shim body at a new `/papi/bootstrap` endpoint. Tracked as
  [papi#16](https://github.com/amarbel-llc/papi/issues/16) and gated on this
  feature publishing the card a host then authenticates with.
- **RFC-0001** (`docs/rfcs/0001`): §5 auth handshake (slot-9D box), §9
  identity-ownership proofs (`papi-proof-sig-v1`), §10 document signature
  (`papi-doc-sig-v1`, §10.2 JCS canonicalization), §12 identity-bootstrap
  consumption, §12.3 (state-mutating provisioning deferred to `papi/v1`).
- **ADR-0006** — papi registers its own markl purposes (`papi-doc-sig-v1`,
  `papi-proof-sig-v1`); the proposed `papi-enroll-att-v1` follows the same rule.
- **piggy#187** — cross-domain fixture-assembly format being settled; the
  receipt format should align. Confirms the attestation-purpose decision: papi
  mints its own `papi-enroll-att-v1` rather than reusing `papi-doc-sig-v1`.
- **piggy#190** (MERGED) — the generic slot-9A **`piggy sign-bytes --slot 9a
  [--guid X] --format raw`**: signs stdin verbatim, returns raw 64-byte `r‖s`,
  fibby-verified on real card crypto. papi's signer uses it for both `self_proof`
  and `attestation`; papi composes the `papi-enroll-receipt-v1` and owns the
  `papi-*` purposes, piggy never learns papi's schema. The `pivy-tool` DER stopgap
  is dropped.
- **piggy#193 / piggy#194** — the blank-card provisioning piggy owns (papi#17):
  #193 surfaces unprovisioned cards in `piggy list` (so papi discovers the blank
  card's serial); #194 is `piggy card init --serial <N>` — deterministic
  single-card provisioning by serial (init + generate 9d/9a, piggy-compatible
  keys/certs), since `pivy-tool` has no serial/reader selector. papi drives these
  neutral primitives; the operator runs the (interactive, PIN-prompting)
  provisioning step.
- **site-linenisgreat** — deploy input is `api/protected/data/papi.json`'s
  `piggy` object; `PersonalApi.php` serves `/papi/piggy-ids` + `/papi/ssh-authorized-keys`.
  Adjacent: site #27 (request-time read-through), #32 (`_papi` DNS TXT backlink).
- **eng** — `bin/up.sh`, `bin/bootstrap-identity.mjs`, `bin/clone-papi-repos.bash`;
  `docs/features/0005` ("pivot to PAPI", with papi#8) — the identity.toml→PAPI
  migration the self-bootstrap shim rides.
