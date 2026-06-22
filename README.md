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
`ssh-copy-id` installs those keys onto a host; `bootstrap` prints a domain's
cold-host self-bootstrap shim; `query` runs a jq expression
over the document; `enroll` emits a signed enrollment receipt for a new
YubiKey; `verify-receipt` checks that receipt against a domain's published
keys (FDR-0001); and `verified-recipients` distils a batch of receipts into the
verified slot-9D encryption-recipient set (FDR-0002).

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

### `papi ssh-copy-id <destination> --domain <domain>`

Fetch **all** of `<domain>`'s published slot-9A keys and install them into
`<destination>`'s `~/.ssh/authorized_keys` — like `ssh-copy-id(1)`, but sourcing
the keys from PAPI instead of a local file. `<destination>` is anything `ssh`
accepts: a hostname, an IP, a `user@host`, or — most usefully — a `Host` alias
from your `~/.ssh/config`. The install shells to `ssh <destination>`, so ssh
resolves the config (`HostName`, `User`, `Port`, `IdentityFile`, `ProxyJump`, …)
exactly as a normal `ssh <destination>` would; `--port` / `--identity` override
it. The append is idempotent (deduped by key material; `~/.ssh` and the file are
created `0700`/`0600` if missing), so re-running keeps a host in sync as cards
are enrolled or rotated. With `--guid <HEX>`, install just one card's key. Only
lines that parse as real SSH keys are installed (a hostile domain cannot inject
text into the remote step).

The command presents via the **crap-TUI** ([amarbel-llc/crap](https://github.com/amarbel-llc/crap)):
on a terminal it renders a live viewport of the operation (the fetch + install
phases and a per-key tally); piped or redirected it emits raw ndjson-crap, so
`… | crap-present` renders the same TUI and `… > run.ndjson` captures it.

```console
$ papi ssh-copy-id prod --domain linenisgreat.com   # 'prod' resolved from ~/.ssh/config
▸ ssh-copy-id prod
   ✓ fetch /papi/ssh-authorized-keys
   ✓ install via ssh
   ssh-copy-id prod — 2 done, 1 skipped, 0 failed
```

The install runs a small `sh` script remotely by default. If the destination has
no usable shell (a forced-command, `sftp`-only, or `nologin`-shell target), papi
**automatically retries over SFTP** — fetching `authorized_keys`, merging the new
keys locally, and re-uploading it, with no remote shell. The crap stream shows
this as a **skipped** `install via ssh` (orange — a shell-less host is an
expected miss, not an error) followed by a passing `install via sftp`, and the
operation as a whole succeeds. (SSH can't advertise its subsystems, so attempting
is the only way to discover SFTP works.) Pass `--sftp` to force the SFTP path
directly and skip the
shell attempt. A connection/auth failure is *not* retried over SFTP (it would
fail identically); a host offering neither a shell nor SFTP (e.g. a strict
rsync-only target that confines paths away from `~/.ssh`) can't be driven in-band
at all.

> **Note:** ssh-copy-id currently targets pre-provisioned, **non-interactive**
> hosts — the live viewport owns the terminal, so a step that prompts for an SSH
> passphrase or YubiKey touch isn't supported yet
> ([crap#31](https://github.com/amarbel-llc/crap/issues/31)).

### `papi bootstrap <domain>`

Fetch `<domain>`'s `GET /papi/bootstrap` and print the **self-bootstrap shim**
verbatim — the small POSIX-sh script a cold, YubiKey-provisioned host runs to
clone eng over HTTPS and `exec` its provisioner. It is the inspect-before-you-run
companion to the cold-host entrypoint, which needs no papi binary at all
([FDR-0003](docs/features/0003-papi-self-bootstrap-endpoint.md)):

```console
$ curl -fsSL https://linenisgreat.com/papi/bootstrap | sh   # cold host: only a card + network
$ papi bootstrap linenisgreat.com | less                    # or review it first
```

The shim's contents are owned and version-controlled in eng (`bin/provision.sh`);
PAPI only **hosts** them — public and unprojected, since gating a bootstrap shim
behind §5 would be circular.

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
- `--allow-reprovision` — also offer **provisioned** cards in the picker;
  choosing one **resets** it (destroys its keys) and re-provisions from scratch,
  behind a loud extra confirm. Off by default — re-provisioning is destructive
  and never the silent default.
- `--cn-prefix <name>` — name the new card's slot certs (`cn=…`, surfaces in
  `piggy list` and `/papi/ssh-authorized-keys`), e.g. `laptop-alice`. Default:
  piggy's `piv-auth@<guid8>`. Interactive runs prompt for it.
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
canonical bytes) — an already-trusted card vouching for the new one. The two
checks are presented via the **crap-TUI** (live viewport on a terminal,
ndjson-crap when piped to `crap-present`); the command exits non-zero if either
fails — this is the verifier a deploy gate runs before publishing a new key.

```console
$ papi verify-receipt enroll-receipt-55C3439D.json --domain linenisgreat.com
✓ self_proof — new card's slot-9A key signs the 9D↔9A binding claim
✓ attestation — an already-published slot-9A key attests the receipt
```

A host without a Go binary (e.g. a php-wasm site verifying receipts natively) can
run the same two checks from the network-free WASM module — `just build-wasm`
builds `cmd/papi-verify-wasm` to a wasip1 artifact that takes the published keys
as input instead of fetching them ([FDR-0002](docs/features/0002-papi-verify-wasm-module.md)).

### `papi verified-recipients <receipt-file>... --domain <domain>`

Verify a batch of enrollment receipts against `--domain` and print the slot-9D
recipient id (`recipient.id`) of every one that passes — the verified
encryption-recipient set, in the `piggy-ids --recipients-only` form. It is the
trust gate of the [FDR-0002](docs/features/0002-papi-verify-wasm-module.md)
composition: a card's recipient is emitted only when a trusted card has attested
its enrollment, so the set can drive a PIV-gated encrypt (linenisgreat's
`.pivy-ids`) instead of a hand-curated list. Failing receipts are reported on
stderr and excluded; `--strict` makes any failure exit non-zero with no output:

```console
$ papi verified-recipients --domain linenisgreat.com enroll-receipt-*.json
piggy-recipient-v1@pivy_ecdh_p256_pub-q0p9kkux…
piggy-recipient-v1@pivy_ecdh_p256_pub-qfjr3sgs…
# enroll-receipt-bogus.json: excluded — attestation: …not published…   (stderr)
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
internal/0/papi/       HTTP client + wire-format decoders + enrollment receipt
internal/0/markl/      markl-id (blech32) parser (RFC-0002)
internal/alfa/inspect/ the validate command + receipt verification core
internal/alfa/enroll/  the enroll command: card provisioning + receipt assembly
cmd/papi-verify-wasm/  network-free receipt verifier, built to wasip1 (FDR-0002)
main.go                cobra CLI (validate, piggy-ids, ssh-keys, ssh-copy-id, bootstrap, person, enroll, verify-receipt, verified-recipients)
```

Packages under `internal/` are tiered by dependency depth — NATO-phonetic
levels where `0` is a leaf (no internal deps), `alfa` depends only on level
`0`, and so on — repositioned with [dagnabit](https://github.com/amarbel-llc/purse-first)
(`nix run github:amarbel-llc/purse-first#dagnabit -- --initial internal`).
