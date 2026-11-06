# papi issue grooming (2026-11-06)

A read-only pass over the 54 open papi issues, requested by the operator via
circus/eager-holly/clarabell. No issue was changed: nothing was closed, edited,
labelled, commented on or filed. Every action below is a proposal for the
operator.

Method: each issue body was read (comments where the count or subject made them
matter), then checked against master at `c75d29d` with code search and
`git log`. "Fixed" is claimed only with a commit and a code location. Where the
evidence is partial the issue is marked "possibly fixed — verify". The state of
issues in other repos (piggy, crap, purse-first, spinclass, circus, smith) was
not checked; every such blocker is UNVERIFIED.

## Summary

| Class | Count | Issues |
|---|---|---|
| Fixed on master | 9 | #13 #15 #24 #25 #48 #51 #67 #68 #78 |
| Possibly fixed — verify | 5 | #17 #29 #54 #79 #85 |
| Duplicate | 0 | — |
| Stale / superseded | 4 | #23 #45 #52 #74 |
| Ready to work | 21 | #14 #26 #28 #33 #34 #35 #39 #40 #42 #59 #63 #64 #66 #69 #70 #71 #75 #76 #83 #86 #88 |
| Blocked | 15 | #9 #21 #22 #27 #30 #32 #37 #43 #49 #57 #82 #87 #89 #90 #91 |

No pair is a true duplicate. Close relatives: #89 and #91 share a root cause
(nothing runs the sweep); #33 and #90 (#90 is answered by implementing #33);
#51 and #33 (#51 asked for the FDR, #33 for the command).

## Proposed operator actions

Close as fixed:

- #13 — `repos` and `query` take `--recipient`/`--auth-key-id` (f6bdf21, fd49810; `main.go:2400`, `main.go:2608` register `authFlags`).
- #15 — `papi enroll` shipped with the huh picker (FDR-0001 6ec8c89, 5cee129; `main.go:2717`).
- #24 — the deliverable was an FDR; FDR-0004 landed in 6580894. The build is #32.
- #25 — `piggy card reset` is gone; reprovision runs `piggy card init --allow-reprovision` (1fc7f8a; `internal/bravo/enroll/provision.go:397-403,432-434`, test at `provision_test.go:174-203`). #83 shows the reset ran on a real card.
- #48 — `papi forge check` (d7d9f54; `main.go:831`; FDR-0010).
- #51 — the deliverable was an FDR; FDR-0012 landed in f7f8fac. Implementation is #33.
- #67, #68 — `/papi/bootstrap` and `/papi/pigpen` are now raw endpoints, not JSON (cf8e0b5; `internal/bravo/inspect/rawendpoints.go:13-19`, `check.go:35-36`).
- #78 — both runners take the first line with only the line ending removed (78537f2; `internal/0/forgetoken/forgetoken.go:121-132`, `internal/bravo/inspect/auth.go:342-352`).

Close after a check:

- #17 — blank-card provisioning exists (5cee129, 1fc7f8a). Verify that a blank card is listed by the pinned piggy (piggy#193) and that a live blank-card enroll works.
- #29 — FDR-0007 ships a js/wasm core and a TS wrapper with decode and §10 verify (219d94d, 9518955; `cmd/papi-client-wasm/dispatch.go:57-68`). The §5 handshake is not exposed. Close, or narrow to the handshake.
- #54 — papi's half is done: sign (79a160c, 9572ea7), resolve (5482ae9, c2478ee), validate (e9b4e8f). Serving is the reference server's job (405d4b). Confirm the live endpoint serves a signed document.
- #79 — four sites of five are unified (78537f2); the reporter left the last three open on purpose. Decide: close, or document the two flag spellings.
- #85 — papi's spec and CLI parts landed (be14fa2, 944645a, 8e7db35). What is left is in smith and circus. Close here and track those there.

Close as stale or superseded:

- #23 — superseded by FDR-0006, RFC-0003 and `cmd/papi-installer` (8b0a8fd).
- #74 — the capture is FDR-0015 (be22fc3); #75 carries the follow-up.
- #45 — likely superseded by per-session forge tokens (FDR-0016): a token with read access can call the repo API. Confirm with the spinclass `repoinfo` owner.
- #52 — papi now uses piggy's shared registry (`internal/0/markl/markl.go:26,38-40`, 5fd4b8d). The issue asked papi to own the registrations. Decide which model stands; if piggy's, close.

Relabel or rescope:

- #30 — make it a tracking issue: verifier done (986bf37); Level A producer is #34; Level B is unspecified; Level C waits on piggy#209.
- #69 — the validator's probe is malformed (see Bug candidates). Rescope from "deployment vs spec" to "validator probe".
- #89, #91 — one decision: schedule the sweep, run it once, or make it liveness-aware. #91's questions are answered in its comment.
- #9, #21, #49 — idea captures with no owner or design. Decide keep or close.

## Issues

| # | Class | Evidence / scope |
|---|---|---|
| 9 | Blocked (operator) | Explore home-manager config via PAPI. No design, no code. Needs a keep/close ruling. |
| 13 | Fixed | f6bdf21 (repos authed enumeration), fd49810 (query `--recipient`). `authFlags` registered at `main.go:2488`, `main.go:2653`. |
| 14 | Ready | `signaturePoints` reads only `GET /papi` (`internal/bravo/inspect/signature.go:31-72`). Test: a discovery doc echoing `signatures[]` gets verified, and a mismatch fails. Files: `signature.go`, `check.go`, tests. S. No ruling. |
| 15 | Fixed | `papi enroll` (`main.go:2717`); FDR-0001 6ec8c89; huh picker 5cee129. |
| 17 | Possibly fixed | `Provision` runs `piggy card init` (`provision.go:378-425`; 5cee129, 1fc7f8a). Blank cards are listed only once piggy#193 ships (`provision.go:58-60`). Verify with a live blank card. |
| 21 | Blocked (operator) | LocalSend receipt idea, "needs elaboration". Nothing to build until the operator says what it means. |
| 22 | Blocked (piggy#201) | Epic: move `piggy pass` into papi. Waits on piggy's JSON-RPC layer. UNVERIFIED piggy state. |
| 23 | Stale | Superseded by FDR-0006 (experimental), RFC-0003 and `cmd/papi-installer` (8b0a8fd). |
| 24 | Fixed | Deliverable was an FDR: FDR-0004 (6580894). |
| 25 | Fixed | 1fc7f8a: `ReprovisionCard` calls `card init --allow-reprovision` (`provision.go:427-434`); test asserts no `card reset` (`provision_test.go:174-203`). |
| 26 | Ready (ruling) | RFC-0001 revocation amendment. Comment fixes that re-roll goes revoke → enroll. Test: a revoked key in the document is rejected by `validate` and `verified-recipients`. Files: RFC-0001, `internal/bravo/inspect`, `internal/0/markl` (new purpose). L. Needs operator design ruling. |
| 27 | Blocked (crap#31) | Migrate `enroll` to the crap-TUI. UNVERIFIED whether crap#31 landed. |
| 28 | Ready | FDR-0008 is `proposed`; no signing code in `internal/0/installer` (no hits for signature/ed25519). Test: per FDR-0008 promotion criteria. L. Needs ruling on starting regime A. |
| 29 | Possibly fixed | FDR-0007 js/wasm core + TS wrapper (219d94d, 9518955). Exposes decode + verify (`dispatch.go:57-68`), not §5. |
| 30 | Blocked | Parent. Verifier landed (986bf37). Remaining: #34, Level B (spec RESERVED), Level C (piggy#209, UNVERIFIED). Relabel as tracking. |
| 32 | Blocked (design) | Headscale broker. FDR-0004 is `exploring`; needs a broker RFC and circus-side wiring. |
| 33 | Ready | No `auth` command (`main.go` command list). Test: `papi auth <domain>` prints a session and `expires_at` per FDR-0012. Files: `main.go`, `internal/bravo/inspect/auth.go`, a man page. M. FDR-0012 already scopes it. |
| 34 | Ready | No `co_location` in `internal/bravo/enroll` (only in `inspect/colocation.go`). Test: a fresh receipt carries a Level A proof that `validate` accepts. Files: `enroll/enroll.go`, `enroll/testdata/sample-receipt.json`, `alfa/papi/receipt.go`. M. Coordinate the receipt contract with the reference server. |
| 35 | Ready | `discoveryVerdicts` checks only required fields and URL scheme (`check.go:64-94`). Test: httptest fixtures for an advertised empty section (MUST fail) and an empty husk in `/papi` (SHOULD fail). Files: `check.go`, tests. M. |
| 37 | Blocked (operator) | Mobile pairing; deferred by operator until the desktop §5 signer is promoted. |
| 39 | Ready | §5.4 cert signer for `sign-challenge-serve`. Test: `--signer cert` signs with a provisioned SSH cert and a §5.4 verifier accepts it. Files: `internal/alfa/signchallenge`, `main.go`. M. |
| 40 | Ready (ruling) | `AllowGroups` still matches nothing (`internal/bravo/authproxy/verifier.go:47-51`). Pick option 1 (registry `groups=`) or 2 (remove). Test: either a group login passes, or the flag and nix option are gone. S. |
| 42 | Ready (ruling) | No allowed_signers emission anywhere. Needs an RFC amendment or FDR first. L. |
| 43 | Blocked (#42) | Host the HM signing module. Waits on #42 and eng#190 (UNVERIFIED). |
| 45 | Stale (verify) | Forgejo session bridge for spinclass `repoinfo`. Per-session forge tokens (FDR-0016) likely cover private-repo reads. Confirm with spinclass. |
| 48 | Fixed | d7d9f54 `papi forge check` (`main.go:831`); FDR-0010. The optional cron mode is not built. |
| 49 | Blocked (operator) | Host roles idea. No design. Keep/close ruling. |
| 51 | Fixed | FDR-0012 written (f7f8fac). Implementation tracked by #33. |
| 52 | Stale (verify) | papi imports `piggy/go/pkgs/markl_registrations` and says the three purposes are registered in piggy's registry (`internal/0/markl/markl.go:26,38-40`). The issue asked papi to own them. Ruling needed. |
| 54 | Possibly fixed | papi side: 79a160c, 9572ea7, 5482ae9, c2478ee, e9b4e8f, FDR-0013. Confirm the hosted signed document. |
| 57 | Blocked (operator) | No `created` on the pigpen self-signature, by design. Waits on a consumer that needs freshness. |
| 59 | Ready | Signed example fixed (RFC-0001 lines 1418-1423 use the `-` line). Still wrong: `# primary yubikey (9D)` at lines 1408 and 1419. Test: both examples parse under `just debug-grammar-parse`. S. |
| 63 | Ready | Tag kept, comment corrected (`internal/bravo/inspect/pigpen.go:1-17`). Test: measure both wasm sizes with and without the tag; drop it or record the delta. S. |
| 64 | Ready | No all-package init gate in the `test` aggregate (`justfile:99`). Test: a generated wasm init test fails on an init panic. Files: `justfile`, a generator. M. Prefer purse-first#179 shared tooling (UNVERIFIED). |
| 66 | Ready | Hidden `generate-man` still in `main.go:136`. Test: `cmd/papi-gen_man` produces the same pages; hidden subcommand removed. Files: `main.go` → new internal package, `flake.nix`, `justfile:327`. L. |
| 67 | Fixed | cf8e0b5 (`rawendpoints.go:16`). |
| 68 | Fixed | cf8e0b5 (`rawendpoints.go:17`). |
| 69 | Ready | The probe recipient is malformed, so 400 is a legitimate answer (see Bug candidates). Test: probe with a well-formed unknown recipient; 400 for it fails, 403/503 pass. File: `internal/bravo/inspect/check.go:227`. S. |
| 70 | Ready | Module sets `authorizedKeysFiles` at normal priority (`nix/nixos/papi-ssh-sync.nix:34`) with no assertion. Test: an eval test where a `mkForce` drops the fragments trips an assertion. Files: `nix/nixos/papi-ssh-sync.nix`, a new eval test, FDR-0005. S. |
| 71 | Ready (ruling) | fb49851 added `IdentityDoc` and `CheckIdentityDocQuorum` (`internal/alfa/papi/identity.go:195-209`), used only by tests. Left: RFC text, a verify CLI, publishing, and the recovery-root decision. M. Needs operator ruling on recovery root. |
| 74 | Stale | Captured as FDR-0015 (be22fc3). Follow-up is #75. |
| 75 | Ready | FDR-0015 has no baseline-profile or adoption-channel section (only §15.3 refs at lines 137-142). Test: the FDR names both jobs and cites the conformist profile RFC. Doc-only. S. |
| 76 | Ready | Fixed `http.Client{Timeout: 15s}` and no retry (`internal/alfa/papi/papi.go:44`). Test: httptest that fails once then succeeds; `ssh-sync` retries discovery and the keys fetch. Files: `papi.go`, `main.go:1308`, nix modules for the flag. M. Second ask (discovery fallback for split hosts) needs a ruling. |
| 78 | Fixed | 78537f2; mirrored tests in `rundecrypt_test.go` and `secretcommand_test.go`. |
| 79 | Possibly fixed | 78537f2 unified `authFlags` and `forgeTokenFlags` (`main.go:322-376`). Remaining three left on purpose. Operator decides. |
| 82 | Blocked (piggy#193) | Still keys by serial then GUID (`provision.go:73-80`); two serial-less blank cards with zero GUIDs collapse. |
| 83 | Ready | Readback runs once, no retry (`provision.go:405-418`). Test: a fake `list` runner that returns unprovisioned once, then provisioned; `cardInit` succeeds. S. |
| 85 | Possibly fixed | papi parts: be14fa2, 944645a, 8e7db35. smith and circus parts are out of repo. |
| 86 | Ready | `path_includes_identity` exists only in `main.go`, README, RFC; no check in `internal/bravo/inspect`. Test: httptest forge where the identity-free path 404s fails the check; skip when offline. Files: `inspect/forge.go` or a new file, tests. S–M. |
| 87 | Blocked (piggy) | No 9C support in papi. Needs piggy's 9C generate and attestation export, and spinclass FDR 0032. UNVERIFIED piggy state. |
| 88 | Ready (ruling) | Design note in `docs/plans/2026-10-26-forge-delegation-grant.md` (3cc1609) proposes `POST /auth/grant-mint` on the verifier. No code. L. Needs operator approval of the design. |
| 89 | Blocked (operator) | Nothing schedules the sweep (see #91). Also: the names in the report do not match `NamePrefix` `papi-forge-token-` (`internal/0/forgetoken/naming.go:20`); tokens from before a6a8699 used `papi-` and are now out of reach of `sweep` and `revoke --session`. UNVERIFIED against the live inventory. Cleanup may need `revoke --id`. |
| 90 | Blocked (#33) | No verb prints a session today. #33 (FDR-0012) answers it. |
| 91 | Blocked (operator) | Answered in the issue comment: sweep is one-shot, no timer, and ignores liveness (`internal/0/forgetoken/session.go`). Remaining: operator decision on scheduling and TTL. |

## Cleanup

No bare TODO/FIXME/XXX markers exist in the tree (only a test fixture string at
`internal/bravo/enroll/card_test.go:33`).

- `internal/0/forgetoken/naming.go:28-30` — layout comment says `papi-<escaped-session>-<deadline-unix>`. The prefix has been `papi-forge-token-` since a6a8699 (line 20, line 105).
- `internal/bravo/inspect/signature.go:53-71` and `106-121` — the same `signatures[]`-then-legacy dispatch is written twice. One helper taking the key list would serve both.
- `internal/alfa/papi/identity.go` — `IdentityDoc` and `CheckIdentityDocQuorum` have no non-test caller. Keep only if #71 continues; otherwise it is dead code.
- `justfile:474-491` (`debug-provision-blank`) — "INTERIM, until piggy#194's native `piggy card init`". papi now calls `piggy card init` (`provision.go:397-402`). The recipe looks obsolete.
- `justfile:302-305` vs `internal/bravo/enroll/provision.go:58-60` — the justfile says blank cards "show up via piggy#193"; the code says they appear only once piggy#193 ships. One is stale.
- `internal/bravo/inspect/pigpen.go:39` — "is Task B3" points at a finished plan step. `pigpen.go:76` still calls the self-signature "provisional" though RFC-0001 §14 and `pigpen sign` are shipped.
- Stale package paths after the 49dd02f reposition (`internal/alfa/inspect` → `internal/bravo/inspect`, `internal/0/papi` → `internal/alfa/papi`, `internal/alfa/enroll` → `internal/bravo/enroll`) in living docs: `docs/features/0001-papi-new-yubikey-enrollment.md:203`, `0002-papi-verify-wasm-module.md:35-36,46,165`, `0006-staged-host-installer.md:6,36,107`, `0007-papi-wasm-client.md:45,142`, `0010-forge-access-asserter.md:45,138`, `0011-papi-resources-consistent-projections.md:111`, `0013-pigpen-resolver-papi-http.md:27,81,175,226,259`, `docs/rfcs/0002-piggy-mgmt-constraints.md:44`.
- Ambiguous FDR numbers: papi has no FDR-0014, but `FDR-0014` (circus's) appears unqualified at `nix/hm/papi-oracle.nix:5,68,161`, `nix/nixos/papi-auth-verifier.nix:1,49,180`, `internal/bravo/authproxy/verifier.go:21`, `README.md:351,678`. Only `main.go:3205` says "circus FDR-0014". Likewise "FDR-0013 app-native verify oracle" at `verifier.go:30` and `justfile:425` collides with papi's own FDR-0013 (pigpen resolver).
- FDR status drift: FDR-0001 (`enroll`) and FDR-0005 (`ssh-sync`) are still `proposed` though both ship and run in the fleet (#83, #76). FDR-0002 is `proposed` though `build-wasm` gates it.
- `docs/rfcs/0001-personal-api-papi-wire-format.md:1408,1419` — `#` trailing comment that the hyphence grammar does not accept (#59).

## Bug candidates

Not filed. Each with evidence.

1. **The §5.1 unknown-recipient probe sends a malformed recipient.**
   `internal/bravo/inspect/check.go:227` posts
   `piggy-recipient-v1@pivy_ecdh_p256_pub-zzznonexistentprobe`. The payload
   contains `o`, `i` and `b`, which are not in the blech32 alphabet (the repo's
   own charset is at `internal/bravo/inspect/proofs.go:149`). A server that
   parses the recipient will reject it as malformed, and `check.go:209` says
   malformed requests MUST yield 400. `authUnknownPoint` (`check.go:249-260`)
   then fails 400 as a MUST violation. This is the likely cause of #69 ("got
   400"). Fix: probe with a well-formed recipient for a key that is not
   published. Could go on #69 as a comment instead of a new issue.

2. **Tokens minted before a6a8699 are silently unrevocable by session.**
   29c827d minted names with prefix `papi-`; a6a8699 changed `NamePrefix` to
   `papi-forge-token-` (`internal/0/forgetoken/naming.go:20`), and
   `ParseTokenName` rejects anything else (`naming.go:113-116`). So
   `revoke --session` and `sweep` no longer see older tokens. Revoking a
   session with no matching tokens succeeds (`doc/papi-forge-token.7.scd:84`),
   so a spinclass close for an older session reports success and leaves the
   token live. Only `revoke --id` (635830a) can reach them. This may account for
   some of #89's leftovers. UNVERIFIED against the live token list.
   On review this is not a new bug: the stricter prefix was a deliberate
   safety fix after the 2026-09-02 mass revocation (the `NamePrefix` comment,
   `naming.go:10-19`). Its cost is that older tokens are left for a one-time
   cleanup by id, which is #89's job. Proposed: note it on #89; nothing to
   file.

No new issues were filed in this pass. Item 1 is best recorded on #69.

3. Already filed, still present: #83 (no retry on the post-init readback,
   `provision.go:405-418`) and #82 (blank-card collapse, `provision.go:73-80`).
