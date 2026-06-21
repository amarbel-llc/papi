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

`papi` has these subcommands: `validate` checks a domain against the spec;
`piggy-ids` / `ssh-keys` / `person` / `repos` surface a domain's published
identity material, keys, and repositories for downstream consumption;
`query` runs a jq expression over the document; `enroll` emits a signed
enrollment receipt for a new YubiKey; and `verify-receipt` checks that receipt
against a domain's published keys (FDR-0001).

### `papi validate <domain>`

Fetch `<domain>`'s PAPI, report what it publishes, and check it against the
RFC-0001 conformance contract — discovery, the `{data, meta}` envelope and
`meta.visibility`, ACL-strip, projection, the `text/plain` endpoints, the auth
error codes, identity-ownership proofs (§9), the detached document signature
(§10), and the nix binary cache entry schema (§11). Output is an
[ndjson-crap](https://github.com/amarbel-llc/crap) stream
(pipe it to `crap-present` to render); the process exits non-zero on any MUST
violation.

```console
$ papi validate linenisgreat.com | crap-present
```

Accepts a bare domain (`https` assumed) or a full URL. By default it validates
only the public/anonymous tier. To also exercise the §5 challenge/response
handshake and the authenticated/scoped projection, supply a recipient identity
you control and a `--decrypt-cmd` that reads the challenge ebox (base64) on
stdin and writes the recovered nonce on stdout. `base64 -d | pivy-box stream
decrypt` (talking to a running pivy/piggy-agent that holds the recipient's
slot-9D key) is exactly such a command — it base64-decodes the ebox and decrypts
it through the card:

```console
$ papi validate linenisgreat.com \
    --recipient piggy-recipient-v1@... \
    --decrypt-cmd 'base64 -d | pivy-box stream decrypt' | crap-present
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

### `papi ssh-keys <domain>`

Fetch `<domain>`'s `GET /papi/ssh-authorized-keys` and print it verbatim — one
OpenSSH `authorized_keys` line per visible slot-9A key, each annotated with
`guid=<HEX>` and `cn=<name>`. With `--guid <HEX>`, print only the line whose
`guid=` annotation matches (case-insensitively), erroring if none does — the
affordance a bootstrapping client uses to pin its own card's signing key:

```console
$ papi ssh-keys --guid DEADBEEF linenisgreat.com
```

### `papi person <domain>`

Fetch `<domain>`'s `GET /papi` and print its `person` block as JSON — handle,
display name, and contact email. Anonymously the ACL-gated `person.contact` is
stripped, so no email shows (RFC-0001 §2). Pass `--recipient` (and the same
`--decrypt-cmd` as `validate`) to run the §5 handshake and fetch the scoped
projection, revealing `contact.email` — the identity-bootstrap affordance a
downstream consumer sources name/email from:

```console
$ papi person linenisgreat.com           # anonymous: handle + display_name
$ papi person linenisgreat.com \
    --recipient piggy-recipient-v1@... \
    --decrypt-cmd 'base64 -d | pivy-box stream decrypt'   # + contact.email
```

### `papi repos <domain>`

Fetch `<domain>`'s `GET /papi/repos` — the flattened, provenance-annotated
repository list — and print it. By default emits the repos as JSON; `--url`
prints one repository url per line (a `curl`+`jq` replacement for consumers that
clone them); `--owner` filters to a single owner:

```console
$ papi repos linenisgreat.com                          # JSON: name/url/owner/forge/…
$ papi repos linenisgreat.com --owner amarbel-llc --url
https://github.com/amarbel-llc/papi
https://github.com/amarbel-llc/eng
…
```

### `papi query <domain> <jq-expr>`

Fetch `<domain>`'s `GET /papi` document and evaluate a jq expression against it —
an embedded [gojq](https://github.com/itchyny/gojq), so no external `jq` is
needed — printing each result as JSON, or unquoted strings under `--raw`/`-r`.
Lets consumers pluck arbitrary fields (`forges[]`, `organizations[]`, `repos[]`,
`person`, …) without bespoke `curl`+`jq`:

```console
$ papi query linenisgreat.com '.person.handle' -r
linenisgreat
$ papi query linenisgreat.com '.forges[].repos[].url' -r
```

### `papi enroll <domain>`

Provision a **new** YubiKey and emit a signed card-enrollment receipt
(`papi-enroll-receipt-v1`,
[FDR-0001](docs/features/0001-papi-new-yubikey-enrollment.md)), attested by an
**already-bootstrapped** trusted card, for `<domain>`'s deploy side to publish.
By default it shows an **interactive picker** over the attached cards — blank
cards are selectable, the provisioned trusted card is shown but not enrollable —
then runs `piggy card init` on the chosen blank card, reads it back, and enrolls
it. The new card self-signs its 9D↔9A binding and the trusted card attests
(`piggy sign-bytes --slot 9a`); the receipt is written then verified against
`<domain>`. papi drives the papi-agnostic piggy primitives (`piggy list`,
`age-plugin-piggy`, `piggy sign-bytes`); all cards must be present (PCSC) and
provisioning prompts for the PIN on your terminal.

- `--new-guid <G>` — enroll an **already-provisioned** card (skip the picker +
  provisioning).
- `--new-serial <N>` — pick the blank card to provision non-interactively.
- `--trusted-guid <G>` — the attester (default: the sole provisioned card).

Pair it with `verify-receipt` on the deploy side.

```console
$ papi enroll linenisgreat.com --new-guid A1B2C3D4 --trusted-guid E5F6A7B8 --pin ******
wrote enroll-receipt-a1b2c3d4.json
self_proof: verified — new card's slot-9A key signs the 9D↔9A binding claim
attestation: verified — an already-published slot-9A key attests the receipt
```

### `papi verify-receipt <receipt-file> --domain <domain>`

Verify a card-enrollment receipt (`papi-enroll-receipt-v1`, [FDR-0001](docs/features/0001-papi-new-yubikey-enrollment.md))
emitted when a new YubiKey is provisioned. Two checks, both required: the
`self_proof` binds the new card's slot-9D recipient to its slot-9A key (a §9.3
`papi-proof-sig-v1` over the claim, verified against the receipt's own slot-9A
key), and the `attestation` is signed by a slot-9A key **already published** on
`--domain`'s `/papi/piggy-ids` (a `papi-enroll-att-v1` over the receipt's
canonical bytes) — an already-trusted card vouching for the new one. Prints one
verdict line per check and exits non-zero if any fails; this is the verifier a
deploy gate runs before publishing a new key.

```console
$ papi verify-receipt enroll-receipt-55C3439D.json --domain linenisgreat.com
self_proof: verified — new card's slot-9A key signs the 9D↔9A binding claim
attestation: verified — an already-published slot-9A key attests the receipt
```

## Install

The CLI is distributed as a Nix flake package — there is no non-Nix install
path. Run it ad-hoc, install it onto your profile, or pin a tagged release:

```console
$ nix run   github:amarbel-llc/papi -- validate linenisgreat.com   # ad-hoc
$ nix profile install github:amarbel-llc/papi#papi                 # onto PATH
$ nix build github:amarbel-llc/papi#papi                           # ./result/bin/papi
```

For a reproducible consumer, pin a released tag rather than the floating
default branch:

```console
$ nix run github:amarbel-llc/papi/v0.2.0 -- validate linenisgreat.com
```

```nix
# flake.nix
inputs.papi.url = "github:amarbel-llc/papi/v0.2.0";
```

`papi version` reports the burned-in `papi <version>+<commit>` (the version
comes from `version.env`, injected by igloo's `buildGoApplication`).

Releases are cut with `just release <new>` from `master` (eng-versioning(7)):
it generates the changelog, bumps `version.env`, and creates a signed `v<sem>`
tag plus a GitHub release.

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
docs/rfcs/             the PAPI wire-format spec (RFC-0001)
internal/0/papi/       HTTP client + wire-format decoders
internal/0/markl/      markl-id (blech32) parser (RFC-0002)
internal/alfa/inspect/ the validate command: introspection + conformance checks
main.go                cobra CLI (validate, piggy-ids, ssh-keys, person)
```

Packages under `internal/` are tiered by dependency depth — NATO-phonetic
levels where `0` is a leaf (no internal deps), `alfa` depends only on level
`0`, and so on — repositioned with [dagnabit](https://github.com/amarbel-llc/purse-first)
(`nix run github:amarbel-llc/purse-first#dagnabit -- --initial internal`).
