# papi

Personal API (PAPI) — a well-known, self-describing person document: the
wire-format spec plus an introspection/validation tool that checks domains for
conformance against it.

A PAPI is one canonical JSON document a person publishes from an HTTP API
subdomain to answer four machine-readable questions about themselves: **how to
encrypt to them**, **which keys may SSH as them**, **where their code lives**,
and **what they publish**. It is discoverable from a single well-known URI and
cleanly separates freely-fetchable public information from data scoped to an
authenticated caller — where the credential is the caller's own PIV key and the
published encryption recipients are themselves the authentication identities (no
pre-shared secret).

This repository is the canonical home of:

- **the PAPI wire-format spec** — [RFC-0001](docs/rfcs/0001-personal-api-papi-wire-format.md),
  the normative interface contract (document schema, the visibility/ACL
  projection model, the HTTP endpoints, and the reflexive challenge/response
  auth handshake); and
- **`papi`** — a Go CLI that fetches a domain's PAPI, reports what it publishes,
  and validates it against that contract.

It is **not** the reference server implementation. That lives in
[friedenberg/linenisgreat](https://github.com/friedenberg/linenisgreat)
(`api/protected/lib/`), served live at
<https://api.linenisgreat.com/.well-known/papi>, and is documented there in
ADR-0004.

## The CLI

`papi` has two subcommands.

### `papi validate <domain>`

Fetch `<domain>`'s PAPI, report what it publishes, and check it against the
RFC-0001 conformance contract — discovery, the `{data, meta}` envelope and
`meta.visibility`, ACL-strip, projection, the `text/plain` endpoints, the auth
error codes, identity-ownership proofs (§9), and the detached document signature
(§10). Output is an [ndjson-crap](https://github.com/amarbel-llc/crap) stream
(pipe it to `crap-present` to render); the process exits non-zero on any MUST
violation.

```console
$ papi validate linenisgreat.com | crap-present
```

Accepts a bare domain (`https` assumed) or a full URL. By default it validates
only the public/anonymous tier. To also exercise the §5 challenge/response
handshake and the authenticated/scoped projection, supply a recipient identity
you control and a `--decrypt-cmd` that reads the challenge ebox (base64) on
stdin and writes the recovered nonce on stdout. `piggy box challenge respond`
(a [pivy-box](https://github.com/arekinath/pivy) passthrough) is exactly such a
command:

```console
$ papi validate linenisgreat.com \
    --recipient piggy-recipient-v1@... \
    --decrypt-cmd 'piggy box challenge respond' | crap-present
```

| flag            | meaning                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------- |
| `--recipient`   | piggy recipient id to authenticate as; runs the §5 handshake + scoped-tier checks             |
| `--decrypt-cmd` | shell command that reads the challenge ebox (base64) on stdin and writes the nonce on stdout  |

### `papi piggy-ids <domain>`

Fetch `<domain>`'s `GET /papi/piggy-ids` and print it verbatim — the piggy-ids
file: comment lines, slot-9D encryption recipients, and slot-9A SSH auth ids.
With `--recipients-only`, emit just the bare slot-9D encryption recipients
(RFC-0001 §5.1), ready to feed as a recipient set to an encryptor:

```console
$ papi piggy-ids --recipients-only linenisgreat.com
```

## Install

The CLI is distributed as a Nix flake package — there is no non-Nix install
path:

```console
$ nix build github:amarbel-llc/papi#papi   # ./result/bin/papi
$ nix run   github:amarbel-llc/papi -- validate linenisgreat.com
```

## Development

A `just` recipe drives every dev loop; `just` with no argument runs the local CI
lane (lint + build + test), which is also the pre-merge gate.

```console
$ just            # lint build test (the CI lane)
$ just build-go   # fast out-of-nix build to ./build/papi
$ just test-go    # hermetic Go test suite (httptest fixtures; no network)
$ nix develop     # devShell with go, just, gomod2nix, conformist
```

Run `just --list` for the full recipe set. Dependency changes go through
`just update-go` (`go mod tidy` + regenerate `gomod2nix.toml`).

## Layout

```
docs/rfcs/        the PAPI wire-format spec (RFC-0001)
internal/papi/    HTTP client + wire-format decoders
internal/inspect/ the validate command: introspection + conformance checks
main.go           cobra CLI (validate, piggy-ids)
```
