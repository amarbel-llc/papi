---
status: experimental
date: 2026-07-18
promotion-criteria: >
  experimental (this binary, `papi pigpen resolve`, and Nix packaging are all
  merged) → testing when piggy actually PATH-discovers and invokes
  `pigpen-resolver-papi-http` end-to-end from a real piggy checkout (not just
  this repo's own fixture tests) and resolves a live `/papi/pigpen` document
  into piggy's recipient set. testing → accepted when TOFU pinning (the
  Limitations gap below) ships as a follow-up increment, or the project
  deliberately defers it again with a documented reason and a live consumer
  has run without it for two weeks.
---

# papi-http pigpen resolver plugin (`pigpen-resolver-papi-http`)

## Problem Statement

piggy#216/#217 asked papi to serve a self-signed, payload-less pigpen
document (RFC-0001 §14) so a cached or offline copy of the operator's
encryption-recipient set is tamper-evident and verifiable without
papi-specific logic. papi (this repo) is a client/conformance tool, not an
HTTP server — `GET /papi/pigpen` itself is implemented by each PAPI-conformant
operator's own server (e.g. linenisgreat's PHP API). What papi already
shipped was the *wire-format spec* (RFC-0001 §14) and the experimental
`papi validate` check that verifies a live server's implementation of it
(`pigpenSignaturePoints` in `internal/alfa/inspect/pigpen.go`). One piece was
itself missing until papi#54 Task D2: papi had the spec and the verifier, but
no command that actually produced a self-signed document for an operator's
own server to serve — `inspect.SignPigpen` and the `papi pigpen sign` CLI
subcommand close that gap (read an unsigned pigpen-v1 document on stdin, sign
it with the operator's slot-9A key, print the signed document on stdout), so
an operator's server-side tooling finally has a papi-native way to produce
something `papi pigpen resolve`/`pigpen-resolver-papi-http` below can verify.

What was still missing was the **consumer** side piggy itself needs: piggy
has since implemented and landed piggy RFC 0008 (the pigpen pointer format),
RFC 0009 (its production cutover), and RFC 0010 (the resolver-dispatch
protocol), and closed piggy#216 — though, as the Limitations section below
details, that means "implemented and exercised by piggy's own tests," not
"formally promoted out of `draft` status" (all three RFCs' own front matter
still reads `status: draft`), and none of the three actually ratifies or
even addresses a self-signature scheme for the document itself. RFC 0010
fixes a plugin contract — piggy
PATH-discovers a binary literally named `pigpen-resolver-<kind>` and invokes
it as `pigpen-resolver-<kind> resolve <locator>`, expecting either a bare
`pigpen-v1` document on stdout (success) or a diagnostic on stderr (failure).
Piggy performs **zero** trust evaluation of the locator or the returned
bytes itself — verification, if any, is entirely the resolver's job, done
before a single byte reaches stdout.

This feature is papi's `kind=papi-http` resolver: the actual binary artifact
piggy's RFC 0010 dispatch mechanism discovers and shells out to, fulfilling
papi's half of the piggy#216 contract.

## Interface

### The RFC-0010 artifact — `pigpen-resolver-papi-http`

```
pigpen-resolver-papi-http resolve <locator>
```

where `<locator>` is a bare domain or URL identifying the papi origin (the
same shape `papi.NewClient` accepts). This is the exact invocation shape
piggy RFC 0010 §6 fixes; papi does not get to choose it. Contract:

- **stdin**: never read.
- **stdout**: on success, the resolved `pigpen-v1` document bytes, verbatim,
  and nothing else.
- **stderr**: on any failure, a free-text diagnostic — not self-prefixed
  with `pigpen-resolver-papi-http:`, since piggy already wraps a failing
  resolver's stderr with its own `kind="papi-http"`/`locator="..."` context
  (mirroring `cmd/papi-verify-wasm`'s existing no-self-prefix convention).
- **exit codes**: `0` on success, `1` for every failure class (malformed
  argv, unreachable origin, missing or unverifiable `/papi/pigpen`, ...).
  A single exit code is deliberate: piggy's contract only discriminates
  zero/non-zero, so a finer-grained code would have no consumer.

The binary is a thin argv/exit-code shim (`cmd/pigpen-resolver-papi-http/main.go`)
around the actual work, which is entirely `internal/alfa/inspect.ResolvePigpen`:
fetch `/papi/pigpen`, verify the self-signature against whatever
`/papi/piggy-ids` currently publishes (the same crypto-critical core
`pigpenSignaturePoints` uses, factored out as `verifyPigpenSelfSignature` so
the validator and the resolver share one verification path), and on success
return the original fetched bytes unmodified — verify-then-passthrough, not
a re-encode. Passthrough is deliberate: reconstructing the signing input a
second time via hyphence's encoder would add an unnecessary dependency on
that encoder being lossless, and passthrough preserves an audit trail (a
later reader can see the doc *was* self-signed, signature line and all).
RFC 0010 §6 is explicit that piggy doesn't care either way.

### The human-facing convenience command — `papi pigpen resolve <locator>`

A separate, ordinary cobra subcommand on the `papi` binary itself, added for
manual/scripted use. It takes a bare locator (not a local pointer file —
piggy already parses the pointer file before ever invoking a resolver, so
papi re-implementing that parsing wasn't needed for v1) and shares the exact
same `ResolvePigpen` core as the plugin binary, so the two can never drift
in what counts as a valid pigpen document. **These are two distinct
artifacts, not one binary wearing two hats**: `pigpen-resolver-papi-http` is
the RFC-0010 plugin piggy actually discovers and shells out to;
`papi pigpen resolve` is a convenience wrapper for a human (or a script) who
wants the same resolution without piggy in the loop at all. Neither is a
substitute for the other in the RFC-0010 flow.

### Packaging

`pigpen-resolver-papi-http` ships in the **same** Nix output as `papi`
(`subPackages = [ "." "cmd/pigpen-resolver-papi-http" ]`) rather than a
separate derivation, so wherever a profile has `papi` installed, the
resolver binary rides along on the same `$out/bin` — the same `$PATH`
piggy's RFC-0010 discovery will search.

## Examples

Successful resolution — a domain serving a valid, self-signed pigpen doc:

```
$ pigpen-resolver-papi-http resolve example.com
- piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-<...>
- piggy-recipient-v1@<...>
- papi-pigpen-self-sig-v1@ecdsa_p256_sig-<...>
! pigpen-v1
...
$ echo $?
0
```

Failure — the origin has no `/papi/pigpen` (404), or its signature doesn't
verify:

```
$ pigpen-resolver-papi-http resolve example.com
pigpen: resolve https://example.com/papi/pigpen: not implemented (HTTP 404)
$ echo $?
1
```

The human-facing equivalent for the same locator:

```
$ papi pigpen resolve example.com
```

## Limitations

- **No TOFU pinning yet — a known, deliberate v1 gap, not an oversight.**
  RFC-0001 §14.2 says the resolver "SHOULD pin the signing slot-9A key on
  first fetch (trust-on-first-use) and verify it on every subsequent fetch,
  exactly as an operator would trust any other self-published key in this
  RFC." This resolver does not do that: every invocation is stateless — it
  re-fetches `/papi/piggy-ids` fresh and checks the signature against
  whatever key that fetch currently returns, with no persisted pin across
  invocations. This was a scoped decision (papi#54), not an accident: v1
  ships live verification only, and pinning is deferred to a future
  increment. Until then, a compromised origin that also controls its own
  `/papi/piggy-ids` response could rotate keys between invocations without
  this resolver noticing — the risk §14.2's SHOULD-pin language exists to
  reduce.
- **Unsigned documents are a hard failure — this resolver's own policy,
  not universal pigpen semantics.** RFC-0001 §14.2 makes the self-signature
  SHOULD, not MUST: a bare, unsigned `pigpen-v1` document is a fully
  conformant response, and `papi validate`'s `pigpenSignaturePoints` check
  treats an unsigned document as a graceful skip, never a failure. This
  resolver is stricter by choice: `ResolvePigpen` treats a missing signature
  as a hard error, because a resolver plugin has no "skip" concept to hand
  piggy — it can only succeed (bytes on stdout) or fail (diagnostic on
  stderr, non-zero exit), and this project decided an unverifiable trust
  set should not be silently accepted for that reason. A different
  `kind=...` resolver, or a future revision of this one, could reasonably
  choose to pass through an unsigned document instead; nothing in RFC-0001
  or piggy RFC 0010 mandates today's stricter choice.
- **The first matching auth-key line wins.** `findPigpenAuthKey` (in
  `internal/alfa/inspect/pigpen.go`) returns the *first*
  `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub` line it finds among the
  document's metadata lines. A document that (unusually) published more than
  one such line would have every later one silently ignored for
  self-signature verification purposes. RFC-0001 §14.3's worked examples
  only ever show one such line, so this hasn't mattered in practice, but
  it's a latent assumption worth naming if a future pigpen document design
  allows key rotation via multiple published auth keys.
- **No RFC-0001 §8.1 host-scoping on the locator.** Unlike `templates[]`
  (fetched from a remote, only-conditionally-trusted discovery document), a
  resolver's locator comes from a pointer file the operator wrote
  themselves — there's no remote-document-controls-the-target concern the
  host-scoping rule exists to guard against. `papi.Client` doesn't enforce
  §8.1 anywhere today for any caller, so adding it only here would be
  inconsistent rather than protective.
- **The self-signature *purpose name* remains papi's own invention; piggy
  has not standardized a dedicated self-signature concept.** piggy RFC 0008
  §2.2 documents exactly three pigpen faces — recipient set (no lock),
  sealed (wrap locks + a header-MAC lock on the `!` line), and pointer
  (`kind=`/`locator=` tags) — and none of them names anything resembling
  `papi-pigpen-self-sig-v1`. What IS now grounded, rather than assumed
  (see the next two bullets for how this was found and fixed), is that
  piggy's real recipient-set parser tolerates an unrecognized-purpose `-`
  line by design: an identifier the type system can't resolve degrades to a
  plain tag, not a decode error (hyphence content grammar §6.6,
  [linenisgreat/hyphence#6](https://code.linenisgreat.com/linenisgreat/hyphence/issues/6);
  piggy RFC 0008 §2.3/§10 as of commit `ff4eb12`, which added an explicit
  test and fixed a conformance-section bug that had said the opposite).
  Whether piggy ever standardizes an equivalent concept (and under what
  markl purpose) is still an open question this FDR does not resolve.
- **Superseded history: two earlier lock-shaped schemes, both abandoned —
  not because either shape was wrong, but because the `!`-line lock slot
  itself has no wire position for a payload-less self-signature at all.**
  The original scheme embedded the signature as a lock on the `!`-line
  (`! pigpen-v1@<markl-id>`), first as a full `purpose@format-payload`
  markl-id, then (after a real interop failure — piggy's
  `parse_type_line`/`decode_mac` only splits the `!`-line's value on ONE
  `@`, so the lock's own inner `@` broke its blech32 checksum) as a single
  atomic format tag (`papi_pigpen_self_sig_ecdsa_p256_v1`, empty purpose).
  Both were abandoned once piggy's RFC 0008 §2.6 was read closely: that
  section reserves the `!`-line lock *exclusively* for a sealed document's
  header MAC — the lock's mere presence there means "this document has
  ciphertext," which a payload-less self-signed document deliberately does
  not have. No `!`-line lock shape could have worked; the slot itself was
  wrong. See the next bullet for the scheme that replaced both.
- **Current scheme: the self-signature lives on its own `-` line, not the
  `!`-line, as an ordinary `purpose@format-payload` markl-id.** A fresh
  `papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>` markl-id is inserted as
  its own `-` line (immediately before the always-bare `! pigpen-v1` type
  line), the same shape as the recipient/auth-key lines already in the
  document — see `findPigpenSelfSig`/`SignPigpen`
  (`internal/alfa/inspect/pigpen.go`). This shape was verified, not assumed:
  piggy's real recipient-set parser required no production code change at
  all to tolerate it (see the first bullet above), confirmed by a
  piggy-side session reading `crates/piggy-pigpen/src/document.rs` directly
  and adding a test (`unrecognized_purpose_dash_line_tolerated`, commit
  `ff4eb12`) rather than by inspection alone.
  **Operational lesson (carried forward from the earlier interop bug that
  motivated this whole redesign):** `papi validate`/`papi pigpen resolve`
  succeeding is not sufficient evidence piggy can actually consume a signed
  document — neither path touches piggy's Rust parser. The only real
  end-to-end check is a real `piggy pass recipients sync`/`list` against a
  pointer-backed `piggy-ids`.

## More Information

- RFC-0001 §14 (`docs/rfcs/0001-personal-api-papi-wire-format.md`) — the
  `/papi/pigpen` document, its optionality (§14.1), the self-signature and
  TOFU-pinning language this FDR's Limitations section cites (§14.2), and
  the worked example format (§14.3).
- piggy RFC 0008 (pigpen pointer format), RFC 0009 (production cutover), and
  RFC 0010 (resolver-dispatch protocol) — external to this repo (piggy),
  ratified and landed as part of closing piggy#216; RFC 0010 §6 is the exact
  argv/exit-code contract this binary implements.
- `docs/plans/2026-07-17-pigpen-resolver-papi-http.md` — this feature's
  implementation plan (papi#54, piggy#216 follow-on), covering the six-task
  breakdown (extracting `verifyPigpenSelfSignature`, adding `ResolvePigpen`,
  this binary, the `papi pigpen resolve` subcommand, Nix packaging, and this
  FDR).
- `docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md` — the
  earlier parallel-track design written while piggy RFC 0008/0009/0010 were
  still draft and piggy#216 was still open. This FDR supersedes that
  document's "Open, unresolved dependencies" section, which is now stale
  (see the status-update note at the top of that doc).
- `internal/alfa/inspect/pigpen.go` — `ResolvePigpen`, `verifyPigpenSelfSignature`,
  and the shared crypto-critical verification core.
- `cmd/pigpen-resolver-papi-http/main.go` — the RFC-0010 binary's entry point.
