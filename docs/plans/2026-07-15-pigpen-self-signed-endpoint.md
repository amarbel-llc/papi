# Self-Signed Pigpen Document Endpoint (RFC amendment + experimental validator) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add RFC-0001 Amendment 23 (a new `GET /papi/pigpen` self-signed payload-less pigpen-document endpoint) and an experimental `papi validate` check that verifies the self-signature, against a provisional (piggy-unratified) wire scheme.

**Architecture:** Two independent slices. Slice A is pure documentation (the RFC amendment prose, worked examples, changelog entry — no code). Slice B adds `code.linenisgreat.com/hyphence/go/hyphence` as a dependency and a new `internal/alfa/inspect/pigpen.go` check, mirroring the existing `signature.go` §10 verification pattern (fetch → parse → verify against published slot-9A keys → report as a `point`), gated to skip (not fail) when the server doesn't implement the endpoint. Full design rationale, the cross-repo dependency chain, and why `papi pigpen resolve` is explicitly OUT of scope here: `docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md`.

**Tech Stack:** Go 1.26, `code.linenisgreat.com/hyphence/go/hyphence` (new dependency, no tagged release yet — pin a pseudo-version), existing `github.com/amarbel-llc/papi/internal/0/markl` machinery.

**Rollback:** N/A — purely additive. The new endpoint, discovery entry, and validator check are all OPTIONAL; a server or client that doesn't implement them is unaffected. Deleting the new file and reverting the RFC prose fully reverts this work.

**Out of scope (see design doc for why):** `papi pigpen resolve`, the pointer file format, and anything in piggy's RFC 0008/0009 — those need piggy's cross-repo ratification first.

---

## Slice A: RFC-0001 Amendment 23

### Task A1: Bump front matter and add the endpoint table row

**Files:**
- Modify: `docs/rfcs/0001-personal-api-papi-wire-format.md:1-6` (front matter)
- Modify: `docs/rfcs/0001-personal-api-papi-wire-format.md` (§4 HTTP Endpoints table, currently around line 217-233)

**Step 1: Read the current front matter and endpoint table**

Confirm the current values before editing — front matter should currently read `amended: 2026-07-05` / `amendments: 22`, and the endpoint table's last text-endpoint row is `/papi/piggy-ids`.

**Step 2: Bump front matter**

Change:
```
amended: 2026-07-05
amendments: 22
```
to:
```
amended: 2026-07-15
amendments: 23
```

**Step 3: Add the new endpoint row**

In the §4 HTTP Endpoints table, add a row immediately after the `/papi/piggy-ids` row:

```
| GET    | `/papi/pigpen`              | `text/vnd.pigpen` self-signed payload-less pigpen doc (OPTIONAL) | projected |
```

**Step 4: Commit**

```
git add docs/rfcs/0001-personal-api-papi-wire-format.md
git commit -m "docs(rfc): Amendment 23 scaffold — /papi/pigpen endpoint row"
```

---

### Task A2: Discovery document entry (§4.1)

**Files:**
- Modify: `docs/rfcs/0001-personal-api-papi-wire-format.md` §4.1 (discovery document section)

**Step 1: Add pigpen to the conditionally-advertised resources list**

In §4.1's `resources` bullet, add `/papi/pigpen` to the list of resources advertised "only when its public projection is non-empty" — same treatment as `/papi/templates`, `/papi/proofs`, `/papi/caches`, `/papi/profiles` (NOT the same as `/papi/bootstrap`, which is always-public and unconditional — pigpen is projected content like piggy-ids, so it follows the projected-resource rule, not the bootstrap rule).

Locate the existing sentence enumerating those four conditional resources and add pigpen to it, keeping the "only when non-empty" qualifier.

**Step 2: Commit**

```
git add docs/rfcs/0001-personal-api-papi-wire-format.md
git commit -m "docs(rfc): Amendment 23 — /papi/pigpen discovery entry"
```

---

### Task A3: New §14 — Self-Signed Encryption-Recipient Pigpen Document

**Files:**
- Modify: `docs/rfcs/0001-personal-api-papi-wire-format.md` (append new top-level section after §13 Profiles, before §"Examples"/Security Considerations — check the actual section ordering near the end of the file first)

**Step 1: Read the tail of the file to find the exact insertion point**

Read from around line 1600 to the end to find where §13 ends and what follows (Security Considerations, References, Changelog) so the new §14 is inserted in the right place — sections are numbered sequentially and §14 must land before any "Security Considerations"/"Changelog" section, not after.

**Step 2: Write the new section**

Insert (adjust the section number if the file's actual last numbered section isn't 13 by the time this runs — re-check first):

```markdown
### 14. Self-Signed Encryption-Recipient Pigpen Document

A PAPI server MAY additionally serve the operator's visible encryption
recipients and slot-9A auth ids — the same data `/papi/piggy-ids` (§4.2)
already emits as plain text — as a **payload-less pigpen document** (piggy
RFC 0008 §2.2), so a cached or offline copy is tamper-evident independent
of the host that served it. Like every OPTIONAL feature in this RFC, a
server that does not implement `/papi/pigpen` is fully conformant; a
document without it is unchanged for existing clients.

#### 14.1. `GET /papi/pigpen`

When implemented, `GET /papi/pigpen` MUST return the projected visible
recipients and slot-9A auth ids — identical in content and projection rule
to `/papi/piggy-ids` (§4.2) — encoded as a `pigpen-v1` payload-less hyphence
document (piggy RFC 0008 §2.2, §2.3) with `Content-Type: text/vnd.pigpen`.
Like `/papi/piggy-ids`, this endpoint MUST NOT use the §4.2 JSON envelope.

#### 14.2. Self-signature (RESERVED pending piggy ratification)

A served `/papi/pigpen` document SHOULD carry a self-signature binding the
document to the same published slot-9A key that signs the JSON document
(§10): a signature over the document's canonical hyphence bytes (hyphence
already mandates canonical line ordering in its Encoder Behavior — no
JCS-equivalent canonicalization step is needed, unlike §10.2's JSON case),
excluding the signature itself from the signed bytes (strip-self, mirroring
§10.2 and piggy RFC 0008 §4.6's "as if the value were empty" recipe).

**The exact in-document placement of this signature — which hyphence
metadata line and lock carries it, and under what markl purpose — is
piggy's to decide (piggy RFC 0008/0009), not this RFC's.** hyphence RFC
0001 grants "the latitude ... to the type identified by the `!` line" for
how existing prefixes are populated within a given type; `pigpen-v1` is
piggy's type. This section is intentionally non-normative on that point
until piggy ratifies it, mirroring the posture `docs/rfcs/0002-piggy-mgmt-constraints.md`
already takes toward piggy-owned protocol decisions.

**"Client" here means whatever entity fetches this HTTP endpoint directly —
e.g. a resolver such as `papi pigpen resolve` — not necessarily the final
consumer of the recipient set.** In the pointer/resolver architecture this
RFC does not otherwise define (piggy's to pin), a consumer like piggy never
calls this endpoint itself; it invokes a resolver, which fetches
`/papi/pigpen` and hands back already-resolved bytes. That resolver SHOULD
pin the signing slot-9A key on first fetch (trust-on-first-use) and verify
it on every subsequent fetch, exactly as an operator would trust any other
self-published key in this RFC. This RFC makes no claim about what a
downstream consumer receiving already-resolved bytes from a resolver does
or does not re-verify — that is the resolver-dispatch contract's concern,
not this endpoint's.

#### 14.3. Worked examples

A bare (unsigned) payload-less pigpen document — permitted, since the
self-signature is SHOULD not MUST:

    ---
    - piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # primary yubikey (9D)
    - piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-<blech32>
    ! pigpen-v1
    ---

A self-signed variant — shown with a placeholder lock, since the exact
markl purpose is RESERVED per §14.2:

    ---
    - piggy-recipient-v1@pivy_ecdh_p256_pub-<blech32>  # primary yubikey (9D)
    - piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-<blech32>
    ! pigpen-v1@<RESERVED-self-signature-markl-id>
    ---
```

**Step 3: Commit**

```
git add docs/rfcs/0001-personal-api-papi-wire-format.md
git commit -m "docs(rfc): Amendment 23 — §14 self-signed pigpen document"
```

---

### Task A4: Changelog entry

**Files:**
- Modify: `docs/rfcs/0001-personal-api-papi-wire-format.md` (Changelog section at the end of the file, following the existing Amendment 20/21/22 bullet-list pattern)

**Step 1: Add the changelog bullet**

Following the exact style of the existing entries (see the Amendment 22 entry for the precise format), append:

```
- **2026-07-15, Amendment 23 — self-signed pigpen document endpoint.** Added
  the OPTIONAL `GET /papi/pigpen` endpoint (§14): the same visible
  recipients `/papi/piggy-ids` already serves, encoded as a `pigpen-v1`
  payload-less hyphence document (piggy RFC 0008), so a cached/offline copy
  is tamper-evident. The in-document self-signature placement is left
  RESERVED pending piggy RFC 0008/0009 ratification — this RFC states the
  requirement, not the wire bytes. Additive and OPTIONAL — no version bump.
  papi#54.
```

**Step 2: Commit**

```
git add docs/rfcs/0001-personal-api-papi-wire-format.md
git commit -m "docs(rfc): Amendment 23 — changelog entry (papi#54)"
```

---

## Slice B: Experimental Go validator check

### Task B1: Add the hyphence dependency

**Files:**
- Modify: `go.mod`, `go.sum`

**Step 1: Check for a tagged release**

Run `go list -m -versions code.linenisgreat.com/hyphence/go` — as of this design session the repo had 0 releases, so this will likely need a pseudo-version pinned to a specific commit rather than a tag. Note the resolved version for the commit message.

**Step 2: Add the dependency**

Run: `go get code.linenisgreat.com/hyphence/go/hyphence@main` (or the resolved pseudo-version from Step 1)

**Step 3: Verify it builds**

Run: `go build ./...`
Expected: succeeds with no errors. This pulls in hyphence's own dependency on `github.com/amarbel-llc/purse-first/libs/dewey` transitively — confirm `go.sum` picked that up too.

**Step 4: Commit**

```
git add go.mod go.sum
git commit -m "chore: add hyphence dependency (experimental pigpen validator, papi#54)"
```

---

### Task B2: Research the hyphence metadata-decode API and write a minimal wrapper

The hyphence package (`code.linenisgreat.com/hyphence/go/hyphence`) does not expose a simple "parse bytes into a Document" function — its `Decoder[BLOB]`/`Reader` types are built around a streaming callback (`interfaces.DecoderFromBufferedReader[BLOB]`) that consumes metadata lines as they're read, not a one-shot parse-to-struct call. Do not guess at this API — read it directly from the now-vendored dependency before writing any code.

**Files:**
- Read (in the Go module cache, now that Task B1 added the dependency): the package source for `code.linenisgreat.com/hyphence/go/hyphence` — specifically `document.go` (the `Document`/`MetadataLine` types), `decoder.go` (the `Decoder[BLOB]` type), and `coder_metadata.go` (`MetadataStreamer`, the concrete callback hyphence's own `hyphence meta` CLI command uses).
- Also read `code.linenisgreat.com/hyphence/go/commands_hyphence` (`validate.go`) for a second concrete usage example — it builds a small local type that implements the metadata-decode callback interface and inspects lines as they arrive (tracking `SawAtLine` etc.).
- Create: `internal/alfa/inspect/pigpen.go`

**Step 1: Read the real API**

Use `go doc code.linenisgreat.com/hyphence/go/hyphence` and read the source files listed above (they're now in the local Go module cache after Task B1). Confirm: how to decode a `[]byte`/`io.Reader` hyphence document into a slice of `MetadataLine{Prefix, Value, LeadingComments}` — likely by implementing a small type satisfying whatever callback interface `Decoder.Metadata` expects (mirroring `MetadataStreamer`'s shape, but collecting lines into a slice instead of writing them to an `io.Writer`).

**Step 2: Write a failing test for the wrapper**

```go
package inspect

import "testing"

func TestParsePigpenMetadataLines(t *testing.T) {
	const doc = "---\n" +
		"- piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0jqqquk3lm\n" +
		"! pigpen-v1\n" +
		"---\n"
	lines, err := parsePigpenMetadataLines([]byte(doc))
	if err != nil {
		t.Fatalf("parsePigpenMetadataLines: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 metadata lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Prefix != '-' || lines[1].Prefix != '!' {
		t.Errorf("unexpected prefixes: %+v", lines)
	}
	if lines[1].Value != "pigpen-v1" {
		t.Errorf("want type line value %q, got %q", "pigpen-v1", lines[1].Value)
	}
}
```

**Step 3: Run it to confirm it fails**

Run: `just test-go` (or the repo's Go test recipe — check `justfile`/`just-us-agents` for the exact name before running)
Expected: FAIL — `parsePigpenMetadataLines` undefined.

**Step 4: Implement the minimal wrapper**

In `internal/alfa/inspect/pigpen.go`, implement `parsePigpenMetadataLines(data []byte) ([]hyphence.MetadataLine, error)` using whatever concrete API Step 1 found. Keep it minimal — just enough to get a `[]MetadataLine` out, no pigpen-specific interpretation yet.

**Step 5: Run the test to confirm it passes**

Run: `just test-go`
Expected: PASS

**Step 6: Commit**

```
git add internal/alfa/inspect/pigpen.go internal/alfa/inspect/pigpen_test.go
git commit -m "feat(inspect): parse hyphence metadata lines for pigpen (experimental, papi#54)"
```

---

### Task B3: Extract and verify the provisional self-signature lock

**Files:**
- Modify: `internal/alfa/inspect/pigpen.go`
- Test: `internal/alfa/inspect/pigpen_test.go`

This picks a **provisional, papi-invented** markl purpose for the `!`-line lock, since piggy hasn't ratified one (design doc §Tuning levers). Use `papi-pigpen-self-sig-v1` as the placeholder purpose — the `papi-` prefix makes clear at a glance that this is not a piggy-native purpose, so nobody mistakes it for ratified wire format. Expect this constant to be renamed the moment piggy's RFC 0008/0009 lands (see the design doc).

**Step 1: Write a failing test for extraction**

```go
func TestExtractPigpenTypeLock(t *testing.T) {
	lines := []hyphence.MetadataLine{
		{Prefix: '-', Value: "piggy-recipient-v1@pivy_ecdh_p256_pub-qqq..."},
		{Prefix: '!', Value: "pigpen-v1@papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>"},
	}
	lock, ok := extractPigpenTypeLock(lines)
	if !ok {
		t.Fatal("want a lock on the type line, got none")
	}
	if lock != "papi-pigpen-self-sig-v1@ecdsa_p256_sig-<blech32>" {
		t.Errorf("unexpected lock value: %q", lock)
	}

	noLock := []hyphence.MetadataLine{{Prefix: '!', Value: "pigpen-v1"}}
	if _, ok := extractPigpenTypeLock(noLock); ok {
		t.Error("bare type line (no @lock) must report ok=false")
	}
}
```

**Step 2: Run to confirm it fails**

Run: `just test-go`
Expected: FAIL — `extractPigpenTypeLock` undefined.

**Step 3: Implement `extractPigpenTypeLock`**

Find the `!`-prefixed `MetadataLine`, split its `Value` on the first `@` (the type identifier `pigpen-v1` vs. the lock markl-id), return the lock portion and whether one was present.

**Step 4: Run to confirm it passes**

Run: `just test-go`
Expected: PASS

**Step 5: Write a failing test for signature verification**

Reuse the fixture-generation pattern from `internal/alfa/inspect/signed_doc_gen_test.go` (a deterministic RNG-seeded key, so the fixture is reproducible) to produce: a canonical pigpen metadata section, sign it with a known test slot-9A key (strip-self: sign the bytes without the `!`-line lock present), and assemble the full document with the lock populated. Then:

```go
func TestPigpenSignatureVerification(t *testing.T) {
	// valid case: signed with the test key, that key is "published"
	// (passed in the authIDs slice) -> ok, signed-and-valid.
	// invalid case: same document, signature bytes flipped -> mustFail.
	// unpublished case: valid signature, but key not in authIDs -> skip/unverifiable.
	// malformed case: `!`-line lock isn't a parseable markl-id -> skip/unverifiable.
}
```

Mirror the four-case structure `signature_test.go` already uses for the JSON §10 check — same shape, different fixture.

**Step 6: Run to confirm it fails**

Run: `just test-go`
Expected: FAIL — the verification function doesn't exist yet.

**Step 7: Implement `pigpenSignaturePoints`**

In `internal/alfa/inspect/pigpen.go`, add a function mirroring `signaturePoints` from `signature.go`: fetch `/papi/pigpen`, parse metadata lines (Task B2), extract the type-line lock (Task B3 Step 3), parse it as a markl-id under the provisional `papi-pigpen-self-sig-v1` purpose, verify against published slot-9A keys — **reuse `fetchPiggyAuthIDs` and `keyPublishedMarkl` from `signature.go` as-is**, don't duplicate them. Report via the same `point`/`ok`/`mustFail`/`skip` helpers `signature.go` already uses.

Critically: skip (not fail) when `GET /papi/pigpen` returns 404 or the endpoint isn't implemented — this check must never fail a `papi validate` run against a server that simply doesn't have this OPTIONAL feature. Mirror how `templates`/`proofs`/`caches` checks skip on an empty/absent resource.

Add a doc comment on `pigpenSignaturePoints` marking it explicitly experimental:

```go
// pigpenSignaturePoints verifies the /papi/pigpen document's self-signature
// (RFC-0001 §14.2, papi#54) against papi's PROVISIONAL, piggy-unratified
// scheme (the "papi-pigpen-self-sig-v1" purpose is papi's own placeholder —
// see docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md). This
// WILL need rework once piggy RFC 0008/0009 pins the real lock-line
// semantics; do not treat this as a stable wire-format check.
```

**Step 8: Run to confirm it passes**

Run: `just test-go`
Expected: PASS

**Step 9: Commit**

```
git add internal/alfa/inspect/pigpen.go internal/alfa/inspect/pigpen_test.go
git commit -m "feat(inspect): experimental pigpen self-signature check (provisional, papi#54)"
```

---

### Task B4: Wire into `papi validate`

**Files:**
- Modify: `internal/alfa/inspect/inspect.go` (the `Run` function, where `signaturePoints`/`projectionChecks`/etc. are already appended — mirror that exact call-site pattern)

**Step 1: Write a failing integration test**

Mirror `TestProjectionCanonicalMissingMarker`'s style (an `httptest.Server` fixture): stand up a test server that serves a self-signed `/papi/pigpen` doc, run `inspect.Run`, assert the pigpen check's verdict appears in the output.

**Step 2: Run to confirm it fails**

Run: `just test-go`
Expected: FAIL — `pigpenSignaturePoints` not called from `Run`.

**Step 3: Wire it in**

In `Run`, add a call to `pigpenSignaturePoints` alongside the existing `signaturePoints(ctx, c)` call, following the same append-to-`pts` pattern already used there.

**Step 4: Run to confirm it passes**

Run: `just test-go`
Expected: PASS

**Step 5: Run the full test suite**

Run: `just test` (the repo's aggregate test recipe — confirm the exact name via `just-us-agents list-recipes` before running)
Expected: all tests pass, no regressions.

**Step 6: Commit**

```
git add internal/alfa/inspect/inspect.go internal/alfa/inspect/inspect_test.go
git commit -m "feat(inspect): wire experimental pigpen check into papi validate (papi#54)"
```

---

## After this plan

Per the design doc's "Next steps": file a cross-repo issue on `amarbel-llc/piggy` proposing the pointer face + resolver-kind registry + plugin-dispatch contract, referencing `docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md`. Not part of this plan (not a papi code/doc task) — confirm with the user before filing.
