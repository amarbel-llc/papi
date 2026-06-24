---
status: proposed
date: 2026-06-24
promotion-criteria: >
  proposed → experimental: a recipe produces the client-core wasip1 module
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

### 1. The wasip1 client core (network-free)

A wasm module (sibling of `papi-verify-wasm`, FDR-0002 — same `wasip1` target and
TUI-free import discipline, so it never links the `huh`→`os/user` subtree)
exposing **pure, network-free** functions over the RFC-0001 wire format:

- **decode** — discovery (§4.1), the projected document (§1), and the
  `repos` / `profiles` / `caches` / `piggy-ids` / `ssh-authorized-keys` payloads
  (envelope unwrap included);
- **verify** — §10 document signature(s) and §9 proof signatures, via the markl
  `ecdsa_p256_sig` / `ssh_ecdsa_nistp256_pub` machinery already in
  `internal/0/markl` + `internal/alfa/inspect`;
- **§5 helpers** — construct the sign-challenge preimage
  (`papi-auth-v1\n<domain>\n<nonce>`), encode/decode the `papi-auth-sig-v1` markl,
  and verify a published-key match (§5.2).

It is network-free by construction (a `wasip1` module has no sockets): bytes in,
decoded/verified results out — exactly the FDR-0002 pattern, broadened from
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

## Limitations

- **Core is network-free; HTTP lives in TS.** The wasm has no sockets (`wasip1`);
  the convenience client does the fetch in Node/zx. A non-Node host wires its own
  fetch to the bare core.
- **Signing is not in the core.** §5 sign-challenge / cert signing needs a private
  key (the card via pivy/piggy, or a held cert key) — out of scope for a
  read/verify client. The core builds the preimage and encodes/verifies; the
  key-holder signs.
- **Not yet implemented.** This FDR is the design; the wasm function surface and
  the TS package are the build-out. Reuses `build-wasm`/`wasip1` and FDR-0002's
  TUI-free import discipline.
- **Packaging TBD.** npm vs vendored vs served-via-PAPI is an open sub-question;
  the artifact is the `.wasm` plus a `wasm_exec`-free `wasip1` loader and the TS
  types.

## More Information

- FDR-0002 (`0002-papi-verify-wasm-module.md`) — the verify-only `wasip1` module
  and the TUI-free import discipline this broadens.
- RFC-0001 §1 / §4.1 / §5 / §9 / §10 / §11 / §13 — the wire surface the core
  decodes and verifies.
- `internal/0/papi`, `internal/0/markl`, `internal/alfa/inspect` — the Go packages
  the core wraps.
- [papi#29](https://github.com/amarbel-llc/papi/issues/29) — the request.
