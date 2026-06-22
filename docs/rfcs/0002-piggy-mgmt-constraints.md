---
status: proposed
date: 2026-06-22
---

# papi Consumer Constraints on the piggy Management Command Protocol

## Abstract

piggy's [management command protocol][piggy-rfc-0007] (`piggy manage --jsonrpc`,
the JSON-RPC engine landed in piggy#201) lets an external program drive piggy
headless — card enumeration, provisioning, and signing as RPC methods, with the
[RFC 0006] interaction layer (PIN / confirm / progress) flowing back over the same
connection. papi is its motivating consumer (piggy#203): the
[`pass *` → papi migration epic (papi#22)][papi-22] has papi compose
password-store and recipient-template semantics caller-side on piggy's neutral
primitives, which requires papi to drive piggy **without spawning CLI
subprocesses**. This document records papi's constraints on the `piggy-mgmt/1`
method set: the exact piggy surface papi shells out to today, how each call maps
onto the v1 methods, and the four gaps that remain — so the schema can be refined
while piggy#201 is still malleable. It is papi-side input to [RFC 0007][piggy-rfc-0007],
not a competing specification; piggy owns the protocol.

## Introduction

The piggy-mgmt v1 method set is, by design, "the neutral primitives papi needs":
`card.list`, `card.init`, `sign_bytes` ([RFC 0007] §5). `recipients.*` and
`pass.*` are explicitly future work and "likely unnecessary in piggy, since papi
composes them." papi agrees with that boundary — see §5. The open question is
whether the **three** v1 methods, as currently shaped, cover every piggy call
papi makes today. They nearly do; four concrete gaps remain (§4), three of them
resolvable papi-side with no piggy change.

The neutral-primitive contract is the load-bearing principle: piggy signs bytes
and reads cards; papi owns all canonicalization and framing
(`papi-doc-sig-v1`, `papi-enroll-att-v1`, JCS over the enrollment-receipt
canonical input). Nothing papi-specific lives in piggy — which is exactly what
lets piggy#191 delete the in-piggy `papi` namespace. These constraints must not
erode that boundary: every ask below is for a **neutral** card primitive, never
for papi semantics.

## 1. papi's piggy surface today

papi (`internal/alfa/enroll/card.go`, `provision.go`) shells out to exactly these
six piggy/age-plugin-piggy invocations:

| # | Invocation | Purpose in papi |
|---|---|---|
| 1 | `piggy sign-bytes --slot 9a --format raw --guid <guid> [-P <pin>]` | Sign the enrollment receipt's `self_proof` (new card) and `attestation` (operator-presented trusted card). Returns raw 64-byte r‖s. |
| 2 | `piggy list --format=ndjson` | Enumerate cards/slots. papi parses per record: per-slot markl `id` (slot-9D ECDH recipient, slot-9A auth key), `guid`, `slot`, `cn`, `serial`, `reader`, `uninitialized`. |
| 3 | `piggy list --format=ssh` | The slot-9A OpenSSH authorized_keys line (`ecdsa-sha2-nistp256 <b64> slot=9A guid=… cn=…`) — the published-key form. |
| 4 | `age-plugin-piggy generate --guid <guid>` | The age recipient (`age1piggy…`) for the card's slot-9D ECDH key. |
| 5 | `piggy card init` (blank-card provision) | Provision a factory-blank card (generate 9D/9A). |
| 6 | `piggy card reset --serial <serial>` | Reset a provisioned card for re-provisioning (papi#15 `--allow-reprovision`). |

## 2. Mapping onto `piggy-mgmt/1`

| papi call | v1 method | Status |
|---|---|---|
| 1 `sign-bytes --slot 9a --format raw` | `sign_bytes {slot:"9a", format:"raw", guid, message}` | **Covered.** raw → 64-byte r‖s = the markl `ecdsa_p256_sig` payload directly; papi never needs DER. PIN via the `secret` interaction (§4.D). |
| 2 `list --format=ndjson` | `card.list {include_uninitialized}` → `{cards:[…]}` | **Covered iff the card record carries papi's fields** (§4.A). |
| 3 `list --format=ssh` | — | **Gap A.** No SSH-wire projection in v1. |
| 4 `age-plugin-piggy generate` | — | **Gap B.** Outside `piggy manage` (separate binary). |
| 5 `card init` | `card.init {serial?}` → `{guid, generated_management_key?}` | **Covered.** |
| 6 `card reset --serial` | — | **Gap C.** v1 provisions blank cards only. |

So `sign_bytes` and `card.init` are a clean fit. The remaining work is the
`card.list` record shape (A), the age recipient (B), and a reset path (C), plus
one cross-cutting interaction constraint (D).

## 3. Summary of asks

1. **`card.list` record shape (Gap A) — the one ask papi feels strongly about.**
   Pin the per-card / per-slot record to carry, at minimum: `guid`, `slot`, the
   per-slot markl `id`, `cn`, `serial`, `reader`, `uninitialized`. That is exactly
   today's `piggy list --format=ndjson` record, structured. Given the slot-9A
   markl id (`piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…`), papi reconstructs the
   OpenSSH wire line itself (it already owns markl parsing + P-256 decode + SSH
   marshaling) and applies its own `slot=`/`guid=`/`cn=` annotations — so **no
   `--format=ssh` equivalent is needed in the protocol** as long as the markl id
   is present. The neutral split holds: piggy emits the key id, papi frames the
   SSH line.

2. **Age recipient (Gap B) — papi-side, pending one confirmation.** `age1piggy…`
   and the slot-9D markl recipient (`piggy-recipient-v1@pivy_ecdh_p256_pub-…`)
   encode the same P-256 ECDH point, so papi can derive the age recipient from
   the slot-9D markl id returned by `card.list` (Gap A) with **no piggy change** —
   *provided* papi reproduces `age-plugin-piggy`'s exact `age1piggy` bech32
   encoding byte-for-byte. papi will verify that against a known card before
   committing to the derivation; if the encoding can't be reproduced safely,
   the fallback ask is for `card.list` to include the age recipient string
   directly (still neutral — it's a public key representation, not papi state).

3. **Reset path (Gap C).** papi's `--allow-reprovision` needs a headless
   reset-then-init. Either `card.reset {serial}` (destructive, MUST issue a
   `confirm` interaction — papi's preference, keeps `card.init` blank-only and
   clean) or a `card.init {serial, force:true}` that resets first. papi only
   needs *some* headless reset+reinit; the shape is piggy's call.

   **Resolved (2026-06-22, piggy#204).** Scoped to **case A only**: piggy ships
   `card init --allow-reprovision` (CLI + a manage `allow_reprovision` param) that
   re-initialises a CHUID-stamped card still at **factory-default creds** — with
   **no factory reset**. It fails fast at admin-auth on a card whose creds are
   already rotated (the state of any card papi has already enrolled). Re-rolling
   an already-enrolled card therefore routes through **revocation** (papi#26:
   revoke `superseded` → enroll a fresh card), *not* in-place reprovision. So the
   "reset-then-init" framing above is superseded — papi needs only the
   factory-cred re-init, never a destructive applet reset.

4. **Programmatic interaction answers (Gap D / cross-cutting).** papi runs both
   interactively (human PIN + YubiKey touch) and **non-interactively** (CI smoke
   tests, scripted enroll — today's `-P <pin>`). Under the manage API papi's
   client answers piggy's `secret.request` itself, so a scripted papi must be able
   to answer `secret.request` **programmatically** (pre-supplied PIN) with no
   human. [RFC 0006]'s model already makes the client the responder, so this is
   likely already satisfied — papi is asking only that the headless path be a
   tested, supported configuration, not an accident. (Touch is a hardware gesture
   outside the protocol's control; papi's non-interactive paths must use cards
   whose slot-9A policy does not require touch, or accept that touch-gated signing
   cannot be fully headless.)

## 4. Cross-cutting constraints (no schema change expected)

- **Multi-card addressing in one engine.** papi enroll signs with two different
  cards in one flow — the new card's `self_proof` and the operator-presented
  trusted card's `attestation` — against a single long-lived `piggy manage` engine
  that sees every attached card. papi addresses each by `guid`
  (`sign_bytes.guid`, `card.list[].guid`). Single-flight (§4 of [RFC 0007]) is
  fine because the two signings are sequential. v1 already supports this; recorded
  so it stays a tested case.
- **`raw` is the only signature format papi needs.** The 64-byte r‖s is the markl
  `ecdsa_p256_sig` payload; papi never parses DER or SSH-wire signatures. v1's
  `format` default `raw` is correct for papi.
- **papi owns canonicalization.** Restating the boundary: `sign_bytes` signs the
  exact bytes papi hands it; papi computes JCS / markl framing caller-side. piggy
  stays agnostic of `papi-doc-sig-v1` / receipt canonicalization.

## 5. What papi does NOT need from piggy

papi affirms [RFC 0007]'s scope decision: **no `pass.*` and no `recipients.*`
methods in piggy.** The migration's "piggy recipient templates → papi domains"
direction means papi resolves recipients from its own published domain documents
(`/papi/piggy-ids`, with a local cache for offline), and composes password-store
semantics in a forthcoming `papi pass` CLI group. Those live entirely papi-side.
piggy's role is reduced to card-present signing and enumeration — `card.list`,
`sign_bytes`, `card.init`, and the `card.init --allow-reprovision` re-init flag
(factory-cred cards only, no destructive reset — see §3) — which is the whole of
papi's dependency on the manage API.

## 6. Next steps

**Status (2026-06-22): asks 1–4 relayed to piggy#203 and resolved.** Ask 1 —
`card.list` already passes the per-slot markl-id ndjson record through verbatim,
so no `--format=ssh` projection is added; piggy pins the §5.1 record schema. Ask 2
— age recipient derives papi-side from the slot-9D markl id (no piggy change). Ask
3 — reprovision is case A re-init via `card init --allow-reprovision` (piggy#204);
no reset; re-rolls route through revocation (papi#26); see §3. Ask 4 — scripted
`secret.request` is exercised in piggy's `piggy_manage_fibby.bats` conformance lane.

Remaining papi-side work:

- papi-side spike: verify the `age1piggy` derivation from a slot-9D markl id
  against a real card (resolves Gap B's open question).
- When piggy#204 merges: repoint `enroll.Reset()` at `card init --allow-reprovision`
  and live-test the factory-cred reprovision path (tracked in the task list / papi#25).
- Sequenced after the schema firms up (do not build ahead of it): a piggy-mgmt
  Go client in papi (`internal/…`) behind the existing `enroll.Runner` seam, then
  the `papi pass` group — both tracked under [papi#22][papi-22].

## References

Normative:

- [RFC 0007][piggy-rfc-0007] — piggy Management Command Protocol (`piggy-mgmt/1`).
- [RFC 0006] — piggy Management Interaction Protocol (PIN / confirm / progress).

Informative:

- [papi#22][papi-22] — the `pass *` → papi migration epic this document's
  constraints serve.
- piggy#197 (management-API epic), piggy#201 (the protocol's implementation),
  piggy#203 (papi driving piggy headless), piggy#191 (removing `piggy papi`).
- piggy#190 (`sign-bytes`), #193 (card enumeration), #194 (`card init`) — the v1
  methods' CLI counterparts papi shells out to today.

[piggy-rfc-0007]: https://github.com/amarbel-llc/piggy/blob/master/docs/rfcs/0007-management-command-protocol.md
[RFC 0006]: https://github.com/amarbel-llc/piggy/blob/master/docs/rfcs/0006-management-interaction-protocol.md
[papi-22]: https://github.com/amarbel-llc/papi/issues/22
