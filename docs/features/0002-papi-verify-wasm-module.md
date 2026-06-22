---
status: proposed
date: 2026-06-22
promotion-criteria: >
  proposed → experimental: `just build-wasm` produces a wasip1 module and a
  WASI runtime (wasmtime/wazero) runs it against the real 2835305C receipt +
  linenisgreat's published ids, returning ok. experimental → testing:
  site-linenisgreat invokes the module from PHP (a php-wasm runtime) in place of
  shelling to the `papi` CLI, in an exploratory branch. testing → accepted: the
  module gates a real deploy on the site with no manual verification step for two
  weeks.
---

# papi receipt-verify as a WASM module (`papi-verify-wasm`)

## Problem Statement

site-linenisgreat (PHP) has no native way to verify a `papi-enroll-receipt-v1`
(FDR-0001) — it would have to shell out to the `papi` Go binary, which means
installing and trusting a native executable on the web host just to run a few
hundred lines of P-256 verification. The verification logic is pure crypto +
JSON parsing, so it should be packageable as a portable WASM module the site can
load through a php-wasm runtime and call directly. This feature exposes papi's
receipt verifier as a network-free, WASI-compatible module without disturbing the
native `papi verify-receipt` CLI.

## Interface

### Why only verification (and why it took a network-free API)

A `GOOS=wasip1 GOARCH=wasm` build of the **full** `papi` does not compile. The
blockers — `github.com/atotto/clipboard`, `github.com/muesli/termenv`,
`os/user` — all trace to one subtree: `charmbracelet/huh` (the `papi enroll`
TUI) → `termenv` → `xo/terminfo` → `os/user`. `huh` is imported in exactly one
file (`internal/alfa/enroll/provision.go`); the verify core
(`internal/0/markl`, `internal/0/papi`, `internal/alfa/inspect`) imports none of
it. So the verify core is already TUI-free at the package level — the only thing
that pulled the TUI into a WASM build was the single `papi` binary linking
`enroll`.

`papi verify-receipt` also *fetches* the domain's published slot-9A keys over
HTTP to confirm the attester is trusted. A php-wasm host has no sockets, and the
site already holds those keys (its own `/papi/piggy-ids`). So the verifier is
split into a fetch wrapper and a pure core:

| Function (`internal/alfa/inspect`) | I/O | Use |
|---|---|---|
| `VerifyReceipt(ctx, c, raw)` | fetches published keys, then delegates | the native `papi verify-receipt` CLI (unchanged) |
| `VerifyReceiptWithKeys(raw, []*ecdsa.PublicKey)` | none | callers holding parsed keys |
| `VerifyReceiptWithPublishedIDs(raw, []string)` | none | the WASM module; takes published slot-9A keys as `/papi/piggy-ids` markl-id strings |

Both checks are unchanged: **self_proof** (offline — the new card's slot-9A key
signs the 9D↔9A binding claim) and **attestation** (an already-published slot-9A
key signs the receipt's canonical bytes). `VerifyReceiptWithPublishedIDs` accepts
the domain's whole piggy-ids list and ignores non-slot-9A entries (the 9D
`piggy-recipient-v1` keys), so the caller passes it verbatim.

### The module — `cmd/papi-verify-wasm`

A second `main` package importing only `inspect` (+ stdlib), so it never links
the TUI subtree. It reads one JSON envelope on stdin and writes the verdict on
stdout:

```
stdin:  {"receipt": {<papi-enroll-receipt-v1>}, "published_ids": ["piggy-piv_auth-v1@…", …]}
stdout: {"ok": true, "checks": [{"name":"self_proof","ok":true,"detail":"…"}, …]}
```

Exit code: `0` verified, `1` a check failed, `2` malformed input. The same source
also builds as an ordinary host CLI, which keeps it under host `go vet` /
`go build ./...`; `just build-wasm` cross-compiles it to
`build/papi-verify.wasm` and is part of the `build` aggregate, so the merge
pre-hook fails if a future TUI/`os/user` import sneaks into the verify core.

## Examples

Cross-build the module (verifies the core stays WASM-able):

```
$ just build-wasm
-rwxr-xr-x 1 user user 6.4M build/papi-verify.wasm
```

Verify the real two-card receipt against linenisgreat's published ids under a
WASI runtime (no network):

```
$ jq -n --slurpfile r enroll-receipt-2835305c.json \
     '{receipt: $r[0], published_ids: [
        "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qft20htscs7x4z2sjwx2qd6tvdanm894thyty4ty4jy3d72hn6lh6yvfqw7",
        "piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-qfr7rwnad74gjawymf02zpaswpvcf2ewd3s87qzn7f4kpzxvwm7uw2tcjed"]}' \
  | wasmtime build/papi-verify.wasm
{"checks":[{"name":"self_proof","ok":true,"detail":"…"},{"name":"attestation","ok":true,"detail":"…"}],"ok":true}
```

## Limitations

- **Verify-only.** Enrollment/provisioning stay native (`papi enroll`): they need
  the physical card, `piggy`/`pivy-tool` (`os/exec`), and the interactive TUI
  (`huh`) — none of which a WASM sandbox provides. The module is the read side of
  FDR-0001, not the write side.
- **Network-free by construction.** The caller supplies the trusted published
  keys; the module does not fetch or discover them. A host that *wants* discovery
  (RFC §8.1) still uses the native CLI.
- **Not yet executed in CI under a runtime.** `build-wasm` proves the module
  compiles; running it end-to-end needs a WASI runtime (wasmtime or a wazero Go
  harness) added to the devShell — a follow-up.

## More Information

- FDR-0001 (`0001-papi-new-yubikey-enrollment.md`) — the enrollment receipt this
  module verifies, the slot roles, and the native `papi verify-receipt` CLI.
- `internal/alfa/inspect/receipt.go` — the fetch/verify split.
- `cmd/papi-verify-wasm/main.go` — the module entry point.
