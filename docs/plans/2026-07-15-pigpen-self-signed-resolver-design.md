# Design: self-signed pigpen doc + local pointer/resolver (papi#54)

> **Status update (2026-07-18):** The "Open, unresolved dependencies" section
> below is now stale. piggy RFC 0008 (pigpen pointer format), RFC 0009
> (production cutover), and RFC 0010 (resolver-dispatch protocol) have been
> implemented and landed — the pointer sniff, PATH-discovery/dispatch, cache
> TTL, and mutation-refusal are all real, merged Rust code wired into every
> real recipient-read/write path in piggy, and piggy#216 is closed. (Their own
> RFC documents' front matter still literally reads `status: draft` — that's
> piggy's formal-promotion bookkeeping, not a signal that the feature is
> unimplemented.) `pigpen-resolver-papi-http` (the actual resolver plugin RFC
> 0010 discovers and invokes) and the `papi pigpen resolve` CLI subcommand are
> both implemented and merged on papi's side too. For the current, accurate
> design and interface, see `docs/features/0013-pigpen-resolver-papi-http.md`.
> This document is left otherwise unchanged as a historical record of how the
> design evolved before piggy's RFCs landed.

## Status

Design approved by user 2026-07-15. Not yet implemented. Cross-repo
dependencies below are unresolved — this is a parallel-track design, not a
ready-to-build spec.

## Problem

[papi#54](https://forge.starbrandshoes.com/linenisgreat/papi/issues/54)
(the papi/publisher half of piggy#216/#217) asks papi to serve the
operator's encryption-recipient set as a **self-signed, payload-less pigpen
document** (piggy RFC 0008) at a stable hosted URL, so a cached/offline copy
is tamper-evident and a consumer can verify it with no papi-specific logic.

While scoping this, the user extended the requirement: they want a small
**pointer file on local disk** that *resolves*, against a live PAPI
instance, into the full recipient-set pigpen doc piggy actually uses — not
just a bare URL fetch. That implies pigpen's document model needs a
**pointer face** with pluggable resolution, not only a signed full-document
face.

## Why this took the shape it did

Three findings, established from source RFCs (not inference), reshaped the
design during brainstorming:

1. **piggy RFC 0008 (pigpen format) and RFC 0009 (its cutover) are both
   `status: draft`.** Piggy's own text: "Nothing in piggy reads or writes
   `pigpen-v1` documents in production until a follow-up cutover RFC
   promotes it." So nothing here is implementable end-to-end today; this
   design proceeds in parallel and lands once piggy ratifies.
2. **hyphence (the pigpen envelope) is a standalone module**
   (`linenisgreat/hyphence`, Go + Rust, RFC 0001) — not embedded in piggy,
   not embedded in madder (madder's old RFC 0001 was relocated there). Its
   Encoder Behavior section already mandates canonical line ordering, so —
   unlike JSON, which needs JCS (papi RFC-0001 §10.2) — a pigpen document's
   signing input needs no separate canonicalization step.
3. **Deciding what goes in the `! pigpen-v1` type-line's lock is piggy's
   call, not papi's or hyphence's.** hyphence RFC 0001 explicitly grants
   "the latitude ... to the type identified by the `!` line" for how
   existing prefixes are populated. papi can only propose the self-signature
   scheme via a cross-repo issue, mirroring the precedent already set in
   this repo by `docs/rfcs/0002-piggy-mgmt-constraints.md` ("papi-side input
   ... not a competing specification; piggy owns the protocol").

A live co-design conversation happened during this session with another
agent session scoping piggy#216/#217 (the consumer half) — see
`docs/rfcs/0002-piggy-mgmt-constraints.md`'s established "neutral primitive"
boundary, which governed every split below: piggy signs bytes / reads
cards / applies already-resolved bytes; papi (or whatever resolver) owns
canonicalization, framing, domain discovery, and trust policy.

## Architecture

Five pieces, split across two repos:

| Piece | Owner | What |
|---|---|---|
| Self-signed producer endpoint | papi RFC-0001 amendment | `GET /papi/pigpen`, projected exactly like the existing `/papi/piggy-ids` (§4.2), discovery-listed in `/.well-known/papi` only when implemented (mirrors `/papi/bootstrap`'s OPTIONAL treatment) |
| Pointer face + resolver-`kind` registry | piggy RFC 0008/0009 (cross-repo issue, **not** papi's to write) | A new pigpen face carrying a resolver `kind` + locator, structurally parallel to papi's own `templates[].kind` / `caches[].kind` (unknown kinds are skipped, not fatal) |
| Plugin discovery + invocation | piggy RFC 0008/0009 (cross-repo issue) | age-plugin-style: piggy reads the pointer's `kind`, discovers a like-named `pigpen-resolver-<kind>` binary on PATH (mirrors the existing `age-plugin-<name>` convention `age-plugin-piggy` already uses), and shells out to it. Proposed contract (papi's opinion, not piggy's ratified spec): a plain one-shot `pigpen-resolver-<kind> resolve <locator>` → resolved hyphence bytes on stdout — deliberately simpler than age-plugin's full stdin/stdout state machine, since resolution needs no bidirectional negotiation |
| `papi-http` resolver plugin | papi (new CLI surface) | `papi pigpen resolve <pointer-file>` — doubles as a human-runnable command and the plugin binary piggy invokes under whatever calling convention piggy's RFC ultimately pins. Fetches `/papi/pigpen`, verifies the self-signature (TOFU-pinned per the issue's own model, reusing papi RFC-0001 §8.1's HTTPS + same-or-subdomain host-scoping rule for the locator), and emits the resolved full pigpen doc |
| Go validator (experimental) | papi, provisional | Verifies the `!`-line lock signature against published slot-9A keys (reuses `fetchPiggyAuthIDs`/`keyPublishedMarkl` from `internal/alfa/inspect/signature.go`). Explicitly marked liable to break/be rewritten once piggy ratifies the lock-line scheme |

### Data flow

1. **Server-side (unchanged from the original ask).** papi builds the
   payload-less pigpen doc out-of-band (not per-request — slot-9A signing
   needs a live card, same as how `signatures[]` in the JSON `/papi`
   document is a static field, never computed live), canonicalizes it
   (hyphence's mandated canonical ordering — no JCS-equivalent step),
   signs those bytes via `piggy papi sign` gaining a hyphence-input mode
   (strip-self: sign without the lock present, mirroring RFC-0001 §10.2 /
   piggy RFC 0008 §4.6's "as if empty" recipe), and embeds the resulting
   signature markl-id into the `!`-line lock. Serves the result at
   `GET /papi/pigpen`.
2. **Local pointer.** A user has a small pigpen-pointer file on disk (piggy's
   format to define) naming `kind: papi-http` and a locator (domain or
   explicit URL).
3. **Resolution.** `papi pigpen resolve <pointer-file>` (invoked directly, or
   by piggy via the plugin-dispatch convention) reads the pointer,
   host-scope-checks the locator, fetches `/papi/pigpen`, verifies the
   lock's signature against a TOFU-pinned or already-known slot-9A key, and
   writes the resolved full pigpen doc.
4. **Consumption.** Piggy applies the resolved local bytes as its recipient
   set — no fetch, no domain knowledge, no papi awareness in piggy itself,
   preserving the RFC-0002 neutral-primitive boundary.

## Testing

- **RFC amendment:** worked examples in the doc text, mirroring the existing
  §6/§9 example blocks (a bare payload-less pigpen with no lock, and a
  self-signed one with the lock populated).
- **`papi pigpen resolve`:** integration-style tests against a fixture
  server (mirrors the existing `main_test.go` patterns for other papi
  endpoints), covering: valid self-signature, invalid signature, unpublished
  key, malformed lock, and the host-scoping rejection cases from §8.1.
- **Go validator:** deterministic unit fixtures (mirrors the existing
  `signed_doc_gen_test.go` pattern) — valid/invalid/unpublished-key/malformed
  cases. Tests self-consistency between papi's own producer and validator,
  not conformance to a ratified piggy spec, since none exists yet.

## Rollback

Purely additive at every layer — `/papi/piggy-ids` is untouched, the new
endpoint, CLI command, and validator check are all OPTIONAL. Rollback is
"don't advertise/implement the endpoint" or delete the new files; no
dual-architecture period is needed since nothing existing is being replaced.

## Tuning levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| Markl purpose name for the `!`-line self-signature lock | papi's own placeholder, unratified | Needed to draft/test against *something* while piggy RFC 0008/0009 is still draft | Piggy ratifies RFC 0008/0009 with a different name — rename immediately, this is expected, not a design failure |
| Resolver plugin CLI contract (`pigpen-resolver-<kind> resolve <locator>`) | papi's proposed shape, sent as input to the piggy-side co-design conversation | Deliberately simpler than the full age-plugin stdin/stdout protocol, since resolution is one-shot, not bidirectional | Piggy's RFC pins a different contract (e.g. needs streaming, or a richer negotiation phase) — adjust papi's plugin binary to match |

## Open, unresolved dependencies (blocking full implementation)

1. piggy RFC 0008 must leave `draft` (pigpen format itself).
2. piggy RFC 0009 (cutover) must define production dispatch, and now must
   additionally define the pointer face + resolver-kind registry +
   plugin-discovery mechanism — none of which existed in RFC 0009's original
   scope before this design session.
3. `piggy papi sign` needs a hyphence-input signing mode.
4. The exact `!`-line lock markl purpose name needs piggy ratification.

## Cross-repo coordination log

Three messages were exchanged during this design session with another agent
session scoping piggy#216/#217 (job/session id `f1cf0d20-466f-4dff-b970-db2e8da0ecbd`),
covering: (1) the neutral-primitive fetch boundary and structural-not-evaluative
trust hook, (2) the pointer/kind-dispatch pivot, (3) the age-plugin-style
invocation contract. See that session's transcript for the piggy-side
response once available.

## Next steps

1. File a cross-repo issue on `amarbel-llc/piggy` proposing the pointer face
   + resolver-kind registry + plugin-dispatch contract (this design doc's
   §Architecture rows 2–3), referencing this doc.
2. Draft the papi RFC-0001 amendment (producer endpoint + client-side
   resolution section, modeled on the existing §7/§8 templates[] pattern).
3. Implement `papi pigpen resolve` and the experimental Go validator check,
   both gated as provisional until piggy ratifies.
