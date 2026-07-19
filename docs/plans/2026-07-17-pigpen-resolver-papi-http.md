# papi-http pigpen resolver plugin (papi#54, piggy#216 follow-on)

> **For Claude:** REQUIRED SUB-SKILL: Use eng:subagent-driven-development to implement this plan task-by-task.

**Goal:** Build the `pigpen-resolver-papi-http` plugin binary papi's side of piggy#216 requires — piggy's now-landed, stable RFC 0010 resolver-dispatch protocol PATH-discovers and invokes a binary named exactly `pigpen-resolver-<kind>` as `resolve <locator>`. This ships `kind=papi-http`: fetch `/papi/pigpen`, verify its self-signature, emit the verified bytes on stdout.

**Architecture:** Six tasks. C1 is a pure refactor (extract the crypto-critical verification core out of the already-merged `pigpenSignaturePoints` so it isn't duplicated). C2 adds the new `ResolvePigpen` library function reusing that core. C3 is the actual RFC-0010 binary artifact. C4 is a human-facing CLI subcommand sharing C2's logic. C5 is Nix packaging + doc-drift. C6 is an FDR documenting the design and its one deliberate v1 gap (no TOFU pinning yet). Full design rationale and the real RFC 0008/0009/0010 contract this was researched against: see the plan file's own Context/Architecture sections below — this supersedes `docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md`, whose "Open, unresolved dependencies" are no longer blocking (piggy#216 is closed).

**Tech Stack:** Go 1.26, existing `code.linenisgreat.com/hyphence/go/hyphence` + `internal/0/markl` + `internal/0/papi` machinery (all already in the module graph from the earlier plan). No new dependencies.

**Rollback:** N/A — purely additive. The new binary, CLI subcommand, and library function are all new surface area; nothing existing is modified except C1's refactor (behavior-preserving, guarded by the existing test suite) and C5's `flake.nix`/`README.md` edits (mechanical, easily reverted). Deleting the new files and reverting C1's refactor + C5's edits fully reverts this work.

---

## Context

papi already ships (merged) a self-signed pigpen document endpoint (RFC-0001
§14, `GET /papi/pigpen`) and an experimental `papi validate` check
(`pigpenSignaturePoints` in `internal/alfa/inspect/pigpen.go`) that verifies
it. That work deliberately stopped short of `papi pigpen resolve` and
anything piggy-side, because piggy's pointer/resolver-dispatch design was
still unratified.

piggy has since landed and closed piggy#216: three new RFCs (0008's pointer
face, 0009's three-way sniff, 0010's resolver-dispatch protocol) plus a full
Rust implementation. The contract is now fixed and stable — piggy
PATH-discovers a binary literally named `pigpen-resolver-<kind>` and invokes
it as `pigpen-resolver-<kind> resolve <locator>`, expecting a bare
`pigpen-v1` recipient-set document on stdout (exit 0) or a diagnostic on
stderr (non-zero exit). Piggy performs **zero** trust evaluation of the
locator or the returned bytes — verification, if any, is entirely the
resolver's job, done before stdout is written.

This plan builds papi's side of that contract: the `pigpen-resolver-papi-http`
binary. Scope decision already made with the user: **v1 does live
verification only** (check the self-signature against whatever
`/papi/piggy-ids` currently publishes, same trust model
`pigpenSignaturePoints` already uses) — RFC-0001 §14.2's TOFU-pinning
language ("SHOULD pin... on first fetch") is a known, explicitly-documented
gap deferred to a future increment, not silently ignored.

## Architecture

| Piece | What |
|---|---|
| `ResolvePigpen` (new, `internal/alfa/inspect/pigpen.go`) | Fetch `/papi/pigpen`, verify the self-signature against live `/papi/piggy-ids`, return the original signed bytes unmodified (verify-then-passthrough) or a descriptive error. Requires a signature to be present — an unsigned bare `pigpen-v1` doc is a hard failure for this resolver (papi's own policy choice, stricter than the RFC's SHOULD-not-MUST; documented as such, not a flag). |
| `verifyPigpenSelfSignature` (new, refactor) | The crypto-critical core (parse lock → parse markl-id → find auth key → check published → verify signature) extracted out of the existing `pigpenSignaturePoints` so the same logic isn't duplicated between the validator and the resolver. `pigpenSignaturePoints` is refactored to call it; existing tests must pass unchanged. |
| `cmd/pigpen-resolver-papi-http/main.go` (new binary) | The actual RFC-0010 artifact. Argv: `resolve <locator>`. No cobra — mirrors `cmd/papi-verify-wasm`'s minimal `run(args, stdout, stderr) int` style. stdin never read. Single exit code (1) for every failure. |
| `papi pigpen resolve <locator>` (new CLI subcommand, `main.go`) | Thin cobra wrapper around the same `ResolvePigpen`, for human/manual use. Takes a bare locator directly, NOT a local pointer file (piggy already parses the pointer file before invoking a resolver; papi re-implementing that parsing isn't needed for v1 — cheap to add later if wanted). |
| Nix packaging (`flake.nix`) | `pigpen-resolver-papi-http` joins the **same** derivation/output as `papi` (`subPackages = [ "." "cmd/pigpen-resolver-papi-http" ]`) rather than a separate derivation like `papi-installer` — so wherever a profile has `papi` installed, the resolver binary rides along on the same `$out/bin`, landing on the same `$PATH` piggy will search. This is the first multi-binary `subPackages` output in this flake; call that out explicitly in the commit so it doesn't read as an oversight. |
| No RFC-0001 §8.1 host-scoping on the locator | Unlike `templates[]` (fetched from a remote, only-conditionally-trusted discovery doc), a pointer's locator lives in a local file the operator wrote themselves — no remote-document-controls-the-target concern. Also: `papi.Client` doesn't enforce §8.1 anywhere today for any caller, so adding it only here would be inconsistent, not protective. |

### Why verify-then-passthrough (not strip-then-reserialize)

Return `resp.Body` unmodified on success. Don't route it through
`pigpenStripSelfBytes`/`FormatBodyEmitter` a second time — that emitter
reconstructs a *signing input*, not a guaranteed byte-identical round-trip of
whatever the origin served. Piggy is explicitly indifferent to whether the
returned doc still carries the lock (RFC 0010 §6). Passthrough avoids a
second, unnecessary dependency on hyphence's encoder being lossless, and
preserves an audit trail (a later reader can see the doc *was* self-signed).

### Error messages

- `ResolvePigpen`'s returned error embeds the locator (`c.BaseURL`) so a bare
  human-run invocation is self-sufficient — piggy already adds
  `kind="papi-http"`/`locator="..."` context on its own side when it wraps
  the resolver's stderr, so the resolver's own messages shouldn't repeat
  that, just distinguish *which* failure occurred (distinct strings for:
  fetch failed, 404/not-implemented, unsigned, malformed lock, no auth-key
  line, key not published, signature invalid).
- No `"pigpen-resolver-papi-http:"` self-prefix on stderr — matches
  `cmd/papi-verify-wasm`'s established convention (no self-prefix there
  either).
- Single exit code (1) for every failure mode, including a malformed argv —
  piggy's contract only discriminates zero/non-zero, no finer-grained code
  has a consumer.

## Critical files

- `internal/alfa/inspect/pigpen.go` — add `verifyPigpenSelfSignature` (refactor) + `ResolvePigpen` (new)
- `internal/alfa/inspect/pigpen_test.go` — extend fixtures, add `ResolvePigpen` tests
- `cmd/pigpen-resolver-papi-http/main.go` (new) + `main_test.go` (new)
- `main.go` — add `newPigpenResolveCmd()`, register on root
- `flake.nix` — extend `papi` package's `subPackages`
- `README.md` — Layout section (add the new `cmd/` entry, matching the existing `cmd/papi-verify-wasm/` etc. bullets)
- `docs/features/` — new FDR documenting this resolver's design/interface/known-gaps (repo convention: `cmd/papi-verify-wasm` → FDR-0002, `cmd/papi-installer` → FDR-0006)
- `docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md` — its "Open, unresolved dependencies" section is now stale (piggy's RFCs are no longer draft/blocking); needs a short update note pointing at the new FDR rather than silently going out of date

## Tasks

### C1: Extract `verifyPigpenSelfSignature` from `pigpenSignaturePoints` (refactor)

Pure refactor, no behavior change. Signature: `verifyPigpenSelfSignature(lines []hyphence.MetadataLine, authIDs []string) (keyID string, err error)`, with distinguishable wrapped/sentinel errors for: no lock (unsigned), malformed lock, no auth-key line, key not published, signature invalid. Covers everything from "parse the lock" through "ecdsa verify" — NOT the HTTP fetch/status-check (that stays separate per-caller, since it's not crypto-critical). `pigpenSignaturePoints` is rewritten to call this and map outcomes to skip/ok/mustFail exactly as it does today. All existing `pigpen_test.go` tests (`TestPigpenSignatureVerification`'s 6 subtests, `TestRunIncludesPigpenCheck`) must pass unchanged — this is the regression gate for the refactor.

### C2: `ResolvePigpen` + tests

Add `ResolvePigpen(ctx context.Context, c *papi.Client) ([]byte, error)` to `pigpen.go`: fetch `/papi/pigpen` → on non-200 (esp. 404) return a descriptive error (not a skip — a resolver has no skip concept) → parse metadata → fetch `/papi/piggy-ids` via existing `fetchPiggyAuthIDs` → call `verifyPigpenSelfSignature` (C1) → on success return the **original fetched bytes unmodified**. Extract `pigpenPointsFor`'s inline mux-building into a shared `newPigpenFixtureServer(t, data, notFound, authIDs) *httptest.Server` helper, used by both the existing validator tests and new `ResolvePigpen` tests. Test cases (mirror `TestPigpenSignatureVerification`'s structure, assert on `(bytes, error)` instead of `point`): valid (assert `bytes.Equal(got, doc)` — pins passthrough, not just verification success), invalid signature, unpublished key, malformed lock, 404/absent endpoint, unsigned (now a hard error here, unlike the validator's skip).

### C3: `cmd/pigpen-resolver-papi-http` binary + tests

New `main.go`: `func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }`, `func run(args []string, stdout, stderr io.Writer) int` — validate `len(args) == 2 && args[0] == "resolve"` (else usage error to stderr, exit 1), `papi.NewClient(args[1])`, call `inspect.ResolvePigpen`, write result to stdout + return 0 on success, write `err.Error()` to stderr + return 1 on failure. New `main_test.go`, table-driven over: correct argv + valid doc → exit 0, stdout == doc bytes; wrong argv shape → exit 1, stderr has a usage diagnostic; resolve failure → exit 1, stderr contains the underlying reason. Use `httptest.NewServer` (via C2's shared fixture helper) with its URL as the locator arg.

### C4: `papi pigpen resolve <locator>` CLI subcommand

Add `newPigpenResolveCmd()` to `main.go`, mirroring `newPiggyIDsCmd()`'s shape (`cobra.ExactArgs(1)`, `papi.NewClient(args[0])`, `RunE` writes to `cmd.OutOrStdout()`, root's existing `fmt.Fprintln(os.Stderr, "papi:", err)` already prefixes errors — no extra wrapping needed). Register under a `pigpen` parent command (`papi pigpen resolve ...`) so future pigpen-related subcommands have a home. One test exercising `RunE` against a fixture server: stdout on success, propagated error on failure.

### C5: Nix packaging + doc-drift

- `flake.nix`: change `papi` package's `subPackages` from `[ "." ]` to `[ "." "cmd/pigpen-resolver-papi-http" ]`. Comment explaining this is the flake's first multi-binary output and why (PATH parity with `papi` for piggy's discovery). No `wrapProgram` changes needed — the resolver shells out to nothing.
- `README.md` Layout section: add `cmd/pigpen-resolver-papi-http/` alongside the existing `cmd/papi-verify-wasm/`, `cmd/papi-client-wasm/`, `cmd/papi-installer/` bullets, referencing the new FDR (C6).
- Verify: `just build-nix` (already in the default `build` chain — this is the existing regression gate, no new recipe needed) produces both `papi` and `pigpen-resolver-papi-http` in the same output's `bin/`.

### C6: FDR + supersede the stale design doc note

- New `docs/features/00NN-pigpen-resolver-papi-http.md` (next available FDR number under "experimental", per `docs/features/`'s existing numbering — check current highest before assigning) following the repo's FDR convention: design intent, interface (the exact RFC-0010 argv/exit-code contract this binary implements), and explicit limitations (no TOFU pinning yet — cites RFC-0001 §14.2's SHOULD-pin language by section, states this is a known, deliberate v1 gap, not an oversight; unsigned docs are a hard failure by this resolver's own policy, not universal pigpen semantics).
- `docs/plans/2026-07-15-pigpen-self-signed-resolver-design.md`: add a short "Status update" note at the top — piggy's RFC 0008/0009/0010 are no longer draft/blocking (contradicts the doc's own "Open, unresolved dependencies" list), point at the new FDR for the current, accurate design. Don't rewrite the whole doc — it's a historical record of how the design evolved; just flag that its blocking-dependencies section is now stale.

## Verification

- `just test-go` after each task — full regression gate, must stay green throughout (existing pigpen tests are the refactor's safety net for C1).
- `just build-wasm` / `just build-wasm-client` after C1/C2 (touching `pigpen.go`) — confirm the wasm build-tag boundary established in the earlier plan still holds; this is exactly the class of regression that bit that plan twice.
- `just build-nix` after C5 — confirms both binaries land in the Nix output.
- `just test` (full aggregate) before the final merge of the last task — no regressions across the whole repo.
- Manual smoke test after C3: run the built `pigpen-resolver-papi-http resolve <url>` against a real or test fixture and confirm stdout is a clean, re-parseable `pigpen-v1` document.
