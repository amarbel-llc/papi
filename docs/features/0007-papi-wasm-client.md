---
status: experimental
date: 2026-06-24
promotion-criteria: >
  proposed → experimental: a recipe produces the client-core js/wasm module
  exposing the decode/verify functions, and a TS test decodes a real `/papi`
  document and verifies its §10 signature through it — no network inside the wasm.
  experimental → testing: a zx/.mjs consumer (e.g. eng's bootstrap-identity) uses
  the TS client in place of re-deriving the wire format or shelling to the `papi`
  CLI, on an exploratory branch. testing → accepted: that consumer ships on the TS
  client with no parallel JS wire-format code for two weeks.
---

# papi client as a WASM core + TypeScript wrapper

## Problem Statement

JavaScript/zx consumers (eng's `bootstrap-identity.mjs`, installer-adjacent
tooling) that need a domain's PAPI must today either shell out to the `papi` Go
CLI or re-implement RFC-0001's wire format and its §5/§10 crypto in JS. Both are
bad: a subprocess needs the native binary on PATH, and a parallel JS
implementation drifts from the spec — especially the markl-id, §10 signature, and
§5 sign-challenge crypto, which must not be re-derived loosely. papi should expose
its client as a portable module JS/TS consumers link directly.

## Interface

Two layers, structured so the **network-free core (1)** is usable on its own and a
**convenience client (2)** wraps it for ergonomics:

### 1. The js/wasm client core (network-free)

A wasm module (sibling of `papi-verify-wasm`, FDR-0002 — same TUI-free import
discipline, so it never links the `huh`→`os/user` subtree) exposing **pure,
network-free** functions over the RFC-0001 wire format. It targets `js/wasm`
(`GOOS=js GOARCH=wasm`), driven via Go's `wasm_exec.js`, **not** `wasip1`: Bun (the
chosen runtime) cannot instantiate a Go `wasip1` module through its `node:wasi`
(see *Decision* below). The functions:

- **decode** — discovery (§4.1), the projected document (§1), and the
  `repos` / `profiles` / `caches` / `piggy-ids` / `ssh-authorized-keys` payloads
  (envelope unwrap included);
- **verify** — §10 document signature(s) and §9 proof signatures, via the markl
  `ecdsa_p256_sig` / `ssh_ecdsa_nistp256_pub` machinery already in
  `internal/0/markl` + `internal/alfa/inspect`;
- **§5 helpers** — construct the sign-challenge preimage
  (`papi-auth-v1\n<domain>\n<nonce>`), encode/decode the `papi-auth-sig-v1` markl,
  and verify a published-key match (§5.2).

It is network-free by construction (the core registers only a pure
`papiCall(reqJSON) -> resJSON` function via `syscall/js`; it opens no sockets):
bytes in, decoded/verified results out — the FDR-0002 pattern, broadened from
receipt-verify to the whole read/verify surface.

### 2. The TypeScript client wrapper

A small TS package that loads the wasm core and offers two modes:

- **bare core** — call the decode/verify functions directly on bytes the caller
  already holds (the network-free path; e.g. a host that already has the
  document);
- **convenience `Client`** — does the HTTP in TS (Node/zx `fetch`) and calls the
  core to decode/verify: `client.document()`, `client.profiles()`,
  `client.sshAuthorizedKeys()`, `client.verifyDocument()` — a typed, spec-faithful
  client with no subprocess and no hand-rolled parsing.

Fetch stays in TS (zx already does HTTP well); the Go-in-wasm owns the parsing and
the §5/§10 crypto (the drift-prone part).

## Examples

```js
// zx / Node — convenience client (does the fetch, calls the wasm to decode/verify)
import { Client } from "@amarbel/papi"
const c = await Client.for("linenisgreat.com")
const doc = await c.document()              // TS fetch → wasm decode
const profiles = await c.profiles()         // [{id, flakeref, home_flakeref, …}]
const authentic = await c.verifyDocument()  // wasm §10 verify against discovery

// bare core — no network, caller already holds the bytes
import { decodeDocument, verifyDocument } from "@amarbel/papi/core"
const doc = decodeDocument(rawBytesFromElsewhere)
```

## Decision: js/wasm, not wasip1

The original design (and FDR-0002) targeted `wasip1`, driven via Node-style
`node:wasi`. That does **not** work under **Bun**, the chosen runtime: Bun's
`node:wasi` cannot instantiate a Go `wasip1` module — it throws `RuntimeError: Out
of bounds memory access` inside `start()` before the module runs. Verified
empirically across every currently-shipping Bun (all the non-baseline avx2 build),
on an identical 6.7 MB module:

| Bun build | Result on the Go wasip1 module |
|---|---|
| 1.3.13 (devshell) | OOB at `node:wasi` `start()` |
| 1.3.14 (latest stable) | OOB at `node:wasi` `start()` |
| 1.4.0-canary.1 (newest JSC + all merged `node:wasi` work) | OOB at `node:wasi` `start()` |

It is **not** the baseline-build JSC-WASM bug (oven-sh/bun#22551 — our bun is the
non-baseline `Linux x64` build) and it is **not** fixed by any released or canary
version. The post-1.3.14 `node:wasi` merges (`getImportObject`/`initialize`/
`path_open`) target Rust/programmatic-WASI ergonomics, not Go startup.

The canonical Go `js/wasm` path (Go's `wasm_exec.js` + `syscall/js`) runs cleanly
under the shipped Bun 1.3.13, including `syscall/js` round-trips. So the core
targets `js/wasm`: `export_js.go` registers a synchronous `papiCall` global and
parks on `select{}`; `clients/ts/papi.ts` loads `wasm_exec.js`, instantiates once,
and calls `papiCall` per request. The same source still builds as a host CLI
(`main.go`, stdin/stdout) so `dispatch()` stays unit-testable without a wasm host.
(FDR-0002's verify core stays `wasip1` — its host is php-wasm, whose WASI runtime
runs Go `wasip1` fine; only Bun's `node:wasi` is the blocker here.)

## Limitations

- **Core is network-free; HTTP lives in TS.** The core opens no sockets; the
  convenience client does the fetch in Node/zx. A non-Node host wires its own
  fetch to the bare core.
- **Signing is not in the core.** §5 sign-challenge / cert signing needs a private
  key (the card via pivy/piggy, or a held cert key) — out of scope for a
  read/verify client. The core builds the preimage and encodes/verifies; the
  key-holder signs.
- **Implemented (experimental).** The js/wasm core (`cmd/papi-client-wasm`) and
  the TS wrapper (`clients/ts/papi.ts`) ship and are exercised by `just test-ts`:
  `decode_{document,discovery,repos,profiles,caches}` and `verify_document` (§10)
  are wired, and a committed **real signed** `/papi` fixture
  (`clients/ts/testdata/signed-papi.*`, regenerated by `just debug-signed-doc`) is
  verified through the wasm core — the promotion-to-experimental bar. Still to do:
  §9 proof verify and the §5 sign-challenge helpers.
- **Packaging: flake output.** The artifact is `papi.ts` + the `js/wasm` module +
  Go's `wasm_exec.js`, distributed as the zero-dependency Nix flake output
  `packages.papi-client-ts` (not npm) — no bun2nix, since the wrapper has no
  runtime deps beyond `node:` builtins + the wasm. `just build-ts` builds it;
  `just test-ts-bundle` smokes the store output via default sibling resolution.

## More Information

- FDR-0002 (`0002-papi-verify-wasm-module.md`) — the verify-only `wasip1` module
  and the TUI-free import discipline this broadens.
- RFC-0001 §1 / §4.1 / §5 / §9 / §10 / §11 / §13 — the wire surface the core
  decodes and verifies.
- `internal/0/papi`, `internal/0/markl`, `internal/alfa/inspect` — the Go packages
  the core wraps.
- [papi#29](https://github.com/amarbel-llc/papi/issues/29) — the request.
