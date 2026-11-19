# Pigpen signer pinning for `pigpen-resolver-papi-http` (papi#54 follow-up)

Status: DESIGN NOTE, nothing built. Written 2026-11-19 for operator review.
Owner of the code: papi (`internal/bravo/inspect/pigpen.go`, `cmd/pigpen-resolver-papi-http`).
Owner of the consumer contract: piggy (RFC 0008 pointer format, RFC 0010 resolver
contract). Facts from piggy's side are marked UNCONFIRMED until its session answers.

## 1. The gap, stated precisely

FDR 0013 records "no TOFU pinning yet". The weakness is sharper than "no pin":

- The resolver takes the signing key **from the document itself** (`findPigpenAuthKey`,
  first `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub` line) and checks it is *published* by
  fetching `/papi/piggy-ids` from **the same origin** (`verifyPigpenSelfSignature`).
- So the signature, the key, and the "is this key published" evidence all come from one
  origin. Whoever can serve `/papi/pigpen` can serve a document with their own recipients,
  their own 9A key, a matching `/papi/piggy-ids`, and a valid signature. The check then
  passes. Today the self-signature gives only **tamper-evidence of a cached copy against
  the signer's key as that origin currently claims it**: it is not a trust anchor.
- piggy adds no trust check of its own (RFC 0010 §6, per piggy's own session). What the
  resolver returns IS the recipient set for anything sealed under the pointer.
- The live document lists 2 slot-9A auth keys (per the coordinator's relay). The resolver
  uses only the **first** and ignores the rest. The signature line names no key id, so
  which of the two signed is not recorded in the document.

Consequence: "recipients come from a pigpen doc against papi" means "recipients are
whatever the PAPI origin's TLS endpoint says". Fine for a convenience; not fine for a
store whose seal protects a management key, unless the signer is pinned somewhere the
origin does not control.

## 2. What to pin

Pin the **signing slot-9A public key(s)**, not the recipient set.

- Pinning the set would make every legitimate rotation (add or revoke a card) look like an
  attack and defeats the purpose of fetching it.
- Pinning the signer means a rotation of recipients is accepted when the same card signs
  it, and a swap of the whole origin is rejected. The 9A key is the card the operator
  physically holds, which is also what already authenticates sessions (RFC-0001 §5).
- Pin a **set** of 9A key ids (the operator has 2 cards live), and accept the document if
  the signature verifies under **any pinned key that appears in the document**. This also
  fixes the "first line wins" limitation: try every in-document auth key that is in the
  pin set instead of only the first.
- A pinned key must still be in the document (`keyPublishedMarkl` against
  `/papi/piggy-ids` is kept as a second condition, not the trust root).

## 3. Where the pin lives: three options

**A. In the locator, i.e. in the pointer file (RECOMMENDED primary).**
`kind=papi-http`, `locator=api.example.com#signer=<markl-id>[,<markl-id>]`. The pointer
file is written by the operator and lives in the store, so the pin is carried by the same
operator-authored, version-controlled object that already says "trust this origin".
Stateless, no writable state dir, works confined and from CI, survives a new host.
Papi-side only if the locator string is the only channel piggy passes (question to
piggy, below). The locator grammar is papi's to define (RFC 0010 treats it as opaque).
First pin is obtained at a card sitting: read the key ids with `papi debug-cards`
(or the document, checked against the card) and write them into the pointer. That is a
**card-provided** pin, not trust-on-first-use.

**B. Trust on first use, per-origin pin file (optional fallback).**
`$XDG_STATE_HOME/papi/pigpen-pins/<origin>`: written on first successful resolution,
compared on every later one. Needs a writable state dir (unknown under piggy's
sandboxing, question 4), is per-host (every fleet host trusts whatever it sees first),
and a rotation needs an explicit re-pin verb. Matches RFC-0001 §14.2's SHOULD, but is
the weaker anchor. Offer only for the no-pin pointer, and only if the operator wants it.

**C. Pin in the sealed object itself.** The store records the signer next to the
sealed entry. Strongest binding, but that is piggy's format (RFC 0008/0009) and not
papi's to define; named here only so it is not forgotten.

## 4. Behaviour

| Situation | Result |
|---|---|
| Pinned, signature verifies under a pinned key present in the doc | success, bytes passed through (unchanged from today) |
| Pinned, doc is signed only by a key NOT in the pin set | **exit 1**, message `signer not pinned` plus the key id seen. No output, no fallback to unpinned |
| Pinned, doc unsigned | exit 1 (already so today) |
| No pin in the locator | today's behaviour, plus a stderr line `pigpen: unpinned origin (signer not verified against an operator pin)`. Visibility depends on piggy question 2 |
| Pin present but malformed | exit 1 at argv parse, before any fetch |

Never degrade a pinned locator to the unpinned path: a mismatch is a hard failure, with
the offending key id in the diagnostic so the operator can decide whether it is a
legitimate rotation (re-pin at a card sitting) or an attack.

## 5. Rotation and migration

- **Signer rotation** (new 9A key, e.g. card replacement): publish the document signed by
  the new key while the old is still valid, add the new id to the pointer's pin set, then
  drop the old id. Because the pin is a set, there is no flag day. The resolver needs no
  state change under option A.
- **Existing clients** (bare-domain locators) keep working unchanged: the pin is an
  optional suffix. Nothing breaks when this ships.
- **Rollout order:** (1) papi: pin parsing + any-pinned-key verification + the stderr
  notice for unpinned; (2) operator: add the pin to the pointer used for the management
  key at the next card sitting; (3) optional later: make an unpinned papi-http locator an
  error behind a flag, or by default once every pointer carries a pin.

## 6. What is papi's, what is piggy's

- papi: locator grammar for the papi-http kind, the verification change (pin set, any
  pinned key), the diagnostics, tests, README/FDR 0013 and RFC-0001 §14.2 text
  (§14.2's SHOULD-pin sentence becomes a described mechanism).
- piggy (UNCONFIRMED, asked piggy/green-larch): whether a pointer can carry more than
  `kind` + `locator`; whether resolver stderr reaches the operator on success; whether
  piggy caches the resolved document and re-runs the resolver each time; whether the
  resolver may write state or is sandboxed.

## 7. Questions for the operator

1. Is a **card-provided pin in the pointer file** (option A) acceptable, with the pin
   obtained at a card sitting? (My recommendation: yes. It is the only option that does
   not trust the origin on first use.)
2. Pin both live 9A keys, or only the primary? (Both is the safer rotation story; a
   single pin means the second card cannot sign until the pin is edited.)
3. Should a TOFU pin file (option B) exist at all, as a convenience for unpinned
   pointers, or should unpinned stay a warning only?
4. Should an unpinned papi-http locator eventually be an error? If so, after which
   milestone (e.g. once the management-key pointer carries a pin)?
5. Is pinning needed before the rotation that seals entries against piggy-ids, or may
   that rotation proceed on a plain piggy-ids file as ruled today and adopt the pointer
   afterwards?

## 8. Not decided here

- The exact locator syntax (`#signer=` vs a query string); decided with piggy's answer
  to question 1.
- Freshness/rollback protection (a replayed old signed document). The RFC notes a
  signature binds authorship, not freshness; a `created` check is a separate item.

## Provenance

Read from this repo at 2026-11-19: `internal/bravo/inspect/pigpen.go`,
`docs/features/0013-pigpen-resolver-papi-http.md`, RFC-0001 §14. Live-document facts (2
auth keys, 3 recipient keys, signed) come from the coordinator's relay of an anonymous
GET, not from my own fetch.
