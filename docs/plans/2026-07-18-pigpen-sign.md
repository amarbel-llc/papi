# `papi pigpen sign` — the missing producer/signing half of papi#54

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add `papi pigpen sign` — the producer/signing counterpart to the already-merged `papi pigpen resolve`/`pigpen-resolver-papi-http`/RFC-0001 §14 work. Without it, no server operator can actually produce the self-signed `/papi/pigpen` document the rest of papi#54 was built to consume — confirmed as a real, concrete blocker by the linenisgreat session's implementation of `GET /papi/pigpen`, which had to fall back to serving an unsigned document because this command didn't exist yet.

**Architecture:** Two tasks. D1 adds the crypto/library core (`inspect.SignPigpen`, inverting the already-merged `verifyPigpenSelfSignature`) with a round-trip test proving signed output actually verifies against the existing verifier. D2 adds the CLI subcommand, reusing the existing `signChallengeSigner` helper (`sign-challenge`'s signer-resolution logic) as-is — no new signer-resolution code, since papi has never had a document-signing producer command before and `sign-challenge`'s pattern (read bytes → resolve slot-9A signer via agent-or-PCSC → sign → emit markl-id) is the established, reusable one. Full design rationale in the plan file's own Context/Architecture sections below.

**Tech Stack:** Go 1.26, existing `internal/0/markl`, `internal/alfa/enroll` (signer implementations, unchanged), `github.com/amarbel-llc/hyphence/go/hyphence` (already a dependency). No new dependencies.

**Rollback:** N/A — purely additive. The new interface, function, and CLI subcommand don't touch any existing behavior. Deleting the new code fully reverts this work.

---

## Context

papi#54 shipped the consumer side of the self-signed pigpen feature:
`GET /papi/pigpen`'s wire format (RFC-0001 §14), the `pigpen-resolver-papi-http`
plugin (verifies + resolves), and the `papi pigpen resolve` CLI convenience.
All of that assumes SOMEONE can produce a signed document in the first place —
but papi never built that half. This surfaced as a real, concrete blocker: the
linenisgreat session building `GET /papi/pigpen` on the PHP/API side got as far
as emitting an *unsigned* `pigpen-v1` document (`just build-pigpen`) and is
explicitly waiting on `papi pigpen sign` to exist before it can commit a signed
static file and drop its unsigned-fallback path.

**Key finding from research:** papi has never had ANY document-signing
producer command before this — not even for its own `/papi` JSON document's
`signatures[]` (RFC-0001 §10). The only existing precedent is `sign-challenge`
(RFC-0001 §5.2, an ephemeral auth signature, not a document signature), which
already establishes the exact reusable pattern: read bytes needing a signature,
resolve a slot-9A signer (agent or direct-PCSC `piggy sign-bytes`), sign, emit
a markl-id. `papi pigpen sign` reuses this pattern directly rather than
inventing a new one.

## Architecture

| Piece | What |
|---|---|
| `inspect.PigpenSigner` (new, tiny interface) | `SignSlot9A(ctx, guid, msg) ([]byte, error)` — structurally identical to the existing `internal/alfa/signchallenge.Signer` and satisfied by the same `enroll.PiggySignBytesSigner`/`enroll.AgentSignBytesSigner` values already in use elsewhere. Defined locally in `inspect` (not imported from `signchallenge`) to avoid a cross-package dependency for a one-method interface — Go's structural typing means the SAME signer value main.go already builds via `signChallengeSigner(...)` satisfies both interfaces with zero adapter code. |
| `inspect.SignPigpen` (new, `internal/alfa/inspect/pigpen.go`) | `SignPigpen(ctx context.Context, signer PigpenSigner, guid string, data []byte) ([]byte, error)`. Inverts `verifyPigpenSelfSignature`: parse metadata → require the type line is a BARE `! pigpen-v1` (error if already locked — don't silently clobber an existing signature) → require an auth-key line exists (`findPigpenAuthKey`, stays unexported, called internally) → compute the existing `pigpenStripSelfBytes` signing input → `signer.SignSlot9A(ctx, guid, input)` (piggy hashes SHA-256 internally, matching how verification's own SHA-256 digest is computed) → `markl.Build(purposePigpenSelfSig, markl.FormatEcdsaP256Sig, raw)` → replace the type line's Value with `"pigpen-v1@" + lock` → re-serialize the FULL (now-locked) lines via hyphence's `FormatBodyEmitter` (same pattern `renderPigpenDoc`'s test helper already uses) → return the signed bytes. |
| `papi pigpen sign` (new CLI subcommand, `main.go`) | Sibling to the existing `resolve` under the `pigpen` parent command. Reads unsigned pigpen-v1 bytes from stdin, writes signed bytes to stdout — a Unix-pipe-friendly design matching exactly how linenisgreat's own `build-pigpen.php` doc comment already describes the expected usage (`just build-pigpen \| papi pigpen sign > data/pigpen.hyphence`, roughly). Flags: `--guid`, `--pin`, `--signer` (auto/agent/pcsc) — identical names/semantics to `sign-challenge`'s flags, and the RunE body reuses the existing `signChallengeSigner(ctx, signerMode, guid, pin, "")` helper as-is (no new signer-resolution code) since it already returns a value satisfying the structural `PigpenSigner` interface. |

### Round-trip regression test (the real correctness proof)

The strongest test for `SignPigpen` isn't asserting internal structure — it's
proving the signed output actually verifies: sign an unsigned fixture with a
known key, then feed the result through the EXISTING `verifyPigpenSelfSignature`
(already merged, already trusted) with that key published, and assert success.
This closes the loop between the new producer and the existing verifier
without re-deriving trust in a second, parallel crypto implementation.

### What's explicitly OUT of scope

- Signing the JSON `/papi` document's own `signatures[]` (RFC-0001 §10) — a
  separate, real gap (confirmed during research: no producer command exists
  for that either), but not part of papi#54 and not blocking linenisgreat's
  pigpen work. Worth its own future issue if the user wants it; not folding it
  into this plan.
- TOFU pinning, multi-signature documents, or anything not already scoped by
  the existing `docs/features/0013-pigpen-resolver-papi-http.md` FDR's stated
  limitations.

## Tasks

### D1: `inspect.SignPigpen` + round-trip test

**Files:**
- Modify: `internal/alfa/inspect/pigpen.go` — add the `PigpenSigner` interface and `SignPigpen` function, per the Architecture table above.
- Modify: `internal/alfa/inspect/pigpen_test.go` — new tests.

**Step 1: Write failing tests first (TDD).** Cases:
- **Round-trip (the main proof):** sign an unsigned fixture (reuse `newPigpenSigner`/`buildPigpenDoc(t, s, false, false)` for the unsigned doc, or construct the bare lines directly) with a fake `PigpenSigner` whose `SignSlot9A` does real ECDSA signing against a known test key (mirror the existing test key generation pattern already in this file), publish that key, then run the signed output through the EXISTING `pigpenSignaturePoints`/`verifyPigpenSelfSignature` and assert success.
- **Already-signed input is rejected:** feed `SignPigpen` a document whose type line already has a lock; assert a distinct, descriptive error (don't silently clobber).
- **No auth-key line is rejected:** feed a document with no `piggy-piv_auth-v1@...` line; assert a distinct error.
- **Signer failure propagates:** a `PigpenSigner` whose `SignSlot9A` returns an error; assert `SignPigpen` returns that error (wrapped or not, your call — be consistent with this file's existing error-wrapping style).

**Step 2:** Run `just test-go`, confirm failures (undefined symbols).

**Step 3:** Implement `PigpenSigner` and `SignPigpen` per the Architecture table.

**Step 4:** Run `just test-go`, confirm all pass. Run `just build-wasm` and `just build-wasm-client` — `pigpen.go` is behind the wasm-exclusion build tag from earlier work in this codebase; confirm both still succeed (this exact class of regression has bitten this codebase twice already — don't skip this check).

**Step 5:** Commit: `git add internal/alfa/inspect/pigpen.go internal/alfa/inspect/pigpen_test.go`, message `feat(inspect): add SignPigpen, the pigpen self-signature producer (papi#54)`.

### D2: `papi pigpen sign` CLI subcommand

**Files:**
- Modify: `main.go` — add `newPigpenSignCmd()`, register as a child of the existing `newPigpenCmd()` parent (alongside `resolve`).
- Modify: `main_test.go` — read `newSignChallengeCmd()`'s actual test coverage first (if any exists in this file) and mirror its scope exactly — don't build more CLI-level test infrastructure than that command has, since both share the same real-signer-resolution constraint (no card in CI).
- Modify: `docs/features/0013-pigpen-resolver-papi-http.md` — small edit noting the signing gap it currently lists as deferred is now closed (reference the new command); don't rewrite the doc.

**Step 1:** Read `newSignChallengeCmd()` (main.go, the existing `sign-challenge` command) in full for the exact flag names/help-text style/RunE shape to mirror.

**Step 2:** Implement `newPigpenSignCmd()`: `Use: "sign"`, reads unsigned bytes from `cmd.InOrStdin()`, resolves a signer via the existing `signChallengeSigner(ctx, signerMode, guid, pin, "")` helper (reused as-is, no changes to that function), calls `inspect.SignPigpen(ctx, signer, resolvedGUID, raw)`, writes the result to `cmd.OutOrStdout()`. Flags: `--guid`, `--pin`, `--signer` (default `"auto"`), matching `sign-challenge`'s exact flag definitions/help text style (adapted for pigpen instead of the auth challenge).

**Step 3:** Register `cmd.AddCommand(newPigpenSignCmd())` inside `newPigpenCmd()`.

**Step 4:** Write/adjust a test mirroring whatever `sign-challenge`'s own CLI test does (per Step 1's finding) — likely argument-validation-level coverage rather than a full real-signer end-to-end test.

**Step 5:** Run `just test-go`, `go build ./...`. Run `just build-wasm`/`just build-wasm-client` as a sanity check (root `main.go` isn't wasm-compiled, but confirm no regression per this codebase's established caution here).

**Step 6:** Manual smoke test: build the `papi` binary, run `papi pigpen sign --help` and confirm it renders sensibly under the `pigpen` command tree (`papi pigpen --help` should list both `resolve` and `sign`). If a real slot-9A card is available in this environment, do a real end-to-end sign of a small fixture document; otherwise this is optional.

**Step 7:** Update `docs/features/0013-pigpen-resolver-papi-http.md`'s note about the deferred signing gap.

**Step 8:** Commit: `git add main.go main_test.go docs/features/0013-pigpen-resolver-papi-http.md`, message `feat: add papi pigpen sign CLI subcommand (papi#54)`.

## After this plan

Message the linenisgreat session (`linenisgreat/rapid-sycamore`) once merged, so they can wire `papi pigpen sign` into `just build-pigpen` and commit a real signed static file, dropping their unsigned-fallback path. Not part of this plan (different repo) — a follow-up chat message, not a papi-repo task.
