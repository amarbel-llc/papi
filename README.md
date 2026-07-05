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
`piggy-ids` / `ssh-keys` / `person` / `repos` / `forges` surface a domain's
published identity material, keys, repositories, and forge identities for
downstream consumption (`person` / `repos` / `forges` / `profiles` / `piggy-ids` /
`ssh-keys` / `query` all take `--auth-key-id` — the RECOMMENDED §5.2 sign-challenge,
or the legacy `--recipient`/`--decrypt-cmd` — to run the §5 handshake and fetch the
full scoped projection instead of the anonymous one — e.g. §5-gated private forges);
`ssh-copy-id` installs those keys onto a remote host, and `ssh-sync` keeps a
local managed `authorized_keys` file in sync with a domain on a timer (via a
home-manager service); `bootstrap` prints a domain's
cold-host self-bootstrap shim; `query` runs a jq expression
over the document; `enroll` emits a signed enrollment receipt for a new
YubiKey; `verify-receipt` checks that receipt against a domain's published
keys (FDR-0001); `verified-recipients` distils a batch of receipts into the
verified slot-9D encryption-recipient set (FDR-0002); `sign-challenge` answers a
§5 auth challenge by signing the server's nonce with your slot-9A key; `gh-check`
reconciles your GitHub SSH keys against a domain's published keys; `gh-auth`
grants gh the scopes those GitHub commands need; and `identity get` / `identity
domain` read scalar fields from the local `identity.toml` (the one command family
that reads local config rather than a remote domain — FDR-0009).

### `papi validate <domain>`

Fetch `<domain>`'s PAPI, report what it publishes, and check it against the
RFC-0001 conformance contract — discovery, the `{data, meta}` envelope and
`meta.visibility`, ACL-strip, projection, the `text/plain` endpoints, the auth
error codes, identity-ownership proofs (§9), key co-location proofs (§9.6), the
detached document signature (§10), and the nix binary cache entry schema (§11).
Output is an
[ndjson-crap](https://github.com/amarbel-llc/crap) stream
(pipe it to `crap-present` to render); the process exits non-zero on any MUST
violation.

```console
$ papi validate linenisgreat.com | crap-present
```

Accepts a bare domain (`https` assumed) or a full URL. By default it validates
only the public/anonymous tier. To also exercise the §5 handshake and the
authenticated/scoped projection, authenticate with your slot-9A key via the
RECOMMENDED sign-challenge scheme (RFC-0001 §5.2): pass `--auth-key-id <slot-9A id>`
and papi signs the server's challenge nonce with that card — through a forwarded SSH
agent when `$SSH_AUTH_SOCK` is set, else `piggy sign-bytes` against a local card:

```console
$ papi validate linenisgreat.com \
    --auth-key-id piggy-auth-v1@... | crap-present
```

Servers advertising the OPTIONAL, legacy decrypt-challenge scheme instead take a
`--recipient` you control plus a `--decrypt-cmd` that reads the challenge ebox
(base64) on stdin and writes the recovered nonce on stdout — e.g. `base64 -d |
pivy-box stream decrypt`, talking to a pivy/piggy-agent that holds the recipient's
slot-9D key. papi honors the server's advertised discovery `auth.scheme`, so pass
whichever pair the target accepts.

| flag            | meaning                                                                                          |
| --------------- | ------------------------------------------------------------------------------------------------ |
| `--auth-key-id` | slot-9A id to authenticate as; runs the RECOMMENDED §5.2 sign-challenge handshake                 |
| `--signer`      | slot-9A signer for `--auth-key-id`: `auto` ($SSH_AUTH_SOCK agent, else piggy sign-bytes), `agent`, `pcsc` |
| `--sign-guid`   | GUID of the slot-9A card to sign with (default: the sole provisioned card)                        |
| `--pin`         | PIV PIN for slot-9A signing                                                                       |
| `--recipient`   | slot-9D id for the OPTIONAL, legacy decrypt-challenge scheme                                      |
| `--decrypt-cmd` | shell command that reads the challenge ebox (base64) on stdin and writes the nonce on stdout      |

### `papi piggy-ids <domain>`

Fetch `<domain>`'s `GET /papi/piggy-ids` and print it verbatim — the piggy-ids
file: comment lines, slot-9D encryption recipients, and slot-9A SSH auth ids.
With `--recipients-only`, emit just the bare slot-9D encryption recipients
(RFC-0001 §5.1), ready to feed as a recipient set to an encryptor. Pass
`--auth-key-id` (or the legacy `--recipient`/`--decrypt-cmd`) to run the §5
handshake and see the full scoped set:

```console
$ papi piggy-ids --recipients-only linenisgreat.com
```

### `papi ssh-keys <domain>`

Fetch `<domain>`'s `GET /papi/ssh-authorized-keys` and print it verbatim — one
OpenSSH `authorized_keys` line per visible slot-9A key, each annotated with
`guid=<HEX>` and `cn=<name>`. With `--guid <HEX>`, print only the line whose
`guid=` annotation matches (case-insensitively), erroring if none does — the
affordance a bootstrapping client uses to pin its own card's signing key. Pass
`--auth-key-id` (or the legacy `--recipient`/`--decrypt-cmd`) to run the §5
handshake and see the full scoped set:

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

### `papi ssh-sync <domain>`

Fetch all of `<domain>`'s published slot-9A keys and **(re)write them in full**
into a LOCAL managed file — the counterpart to `ssh-copy-id` for *this* host.
Where `ssh-copy-id` appends to a remote `authorized_keys` and never prunes,
`ssh-sync` owns its target file: it is rewritten to exactly the domain's current
key set each run, so a rotated or revoked card is removed on the next sync. The
default target is `$XDG_CONFIG_HOME/papi/ssh-sync/<domain>.keys` (the host,
lowercased, non-`[a-z0-9.-]` bytes → `_`); override with `--authorized-keys`. The
write is atomic (`0700` dir / `0600` file), and a deterministic header banner
marks the file machine-owned, so an unchanged upstream is reported `unchanged`.
`--guid <HEX>` syncs a single card's key; a domain publishing no keys prunes the
file to header-only rather than erroring.

```console
$ papi ssh-sync linenisgreat.com
synced 2 key(s) to /home/me/.config/papi/ssh-sync/linenisgreat.com.keys (updated)
```

Run it on a schedule with the **`services.papi-ssh-sync` home-manager module**
(`homeManagerModules.papi-ssh-sync`): a systemd user timer + oneshot service on
Linux, a launchd agent on Darwin. It works on NixOS, nix-darwin, and standalone
home-manager (Ubuntu).

```nix
services.papi-ssh-sync = {
  enable = true;
  domain = "linenisgreat.com";          # or `instances.<name> = { domain = …; }` for several
};
```

For incoming logins to honor the synced keys, sshd must read the managed file.
On **NixOS** the companion `nixosModules.papi-ssh-sync` wires
`services.openssh.authorizedKeysFiles` automatically. On **nix-darwin** and
**standalone home-manager** add the line once yourself:

```
AuthorizedKeysFile .ssh/authorized_keys .config/papi/ssh-sync/linenisgreat.com.keys
```

(Or point `authorizedKeysPath` at `~/.ssh/authorized_keys2`, which stock sshd
reads by default — zero config for a single domain.) See
[FDR-0005](docs/features/0005-papi-ssh-sync.md) for the full design and trust
model.

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
stripped, so no email shows (RFC-0001 §2). Pass `--auth-key-id` (the §5.2
sign-challenge, as with `validate`) to run the §5 handshake and fetch the scoped
projection, revealing `contact.email` — the identity-bootstrap affordance a
downstream consumer sources name/email from:

```console
$ papi person linenisgreat.com           # anonymous: handle + display_name
$ papi person linenisgreat.com \
    --auth-key-id piggy-auth-v1@...       # + contact.email
```

### `papi repos <domain>`

Fetch `<domain>`'s repositories and print them. By default emits the flattened,
provenance-annotated `GET /papi/repos` list as JSON; `--owner` filters to a single
owner. `--url` instead prints one **directly-clonable** git url per line: papi
joins each repo to its forge's clone channel — the forge's published `ssh_clone`
base, else an scp-style `git@<host>` derived from `base_url` — so each line is
`git clone`-able as-is, including §5-gated forges whose published `url` is only the
SSO-gated web url. The owner segment is the forge's `identity` (one identity per
forge, RFC-0001 §1.1). Anonymously only public forges project; pass `--auth-key-id`
(the §5.2 sign-challenge) to run the §5 handshake and get the full scoped set (e.g. a
private forgejo over SSH):

```console
$ papi repos linenisgreat.com                          # JSON: name/url/owner/forge/…
$ papi repos linenisgreat.com --owner friedenberg --url
git@github.com:friedenberg/papi.git
git@github.com:friedenberg/eng.git
…
$ papi repos linenisgreat.com \
    --auth-key-id piggy-auth-v1@... --url
git@github.com:friedenberg/papi.git
ssh://git@krone:2222/friedenberg/private-forgejo-repo.git   # + §5-gated forgejo, over SSH
```

So a clone loop is just `papi repos … --url | while read -r u; do git clone "$u"; done`.
(`--url` covers forge-hosted repos; organization-hosted repos, if any, appear only
in the JSON view. For the raw forge metadata behind the synthesis, see `papi forges`.)

### `papi forges <domain>`

Fetch `<domain>`'s `GET /papi/forges` — the forge identities (`kind`, `base_url`,
`repos[]`, and any server-specific fields such as `ssh_clone`) — and print the
projected array as JSON, verbatim: unrecognized members are preserved (RFC-0001
§1.1), so a clone consumer can read a forge's clone channel and join it with its
`repos[]`. Anonymously only public forges project; pass `--auth-key-id` (the §5.2
sign-challenge) for the §5 handshake and the full scoped set — e.g. a private
forgejo with its `ssh_clone` base:

```console
$ papi forges linenisgreat.com                         # JSON: public forges
$ papi forges linenisgreat.com \
    --auth-key-id piggy-auth-v1@...                    # + §5-gated forgejo (ssh_clone)
```

### `papi forge check <domain>`

Reconcile what `<domain>` **declares** about forge/repo visibility against what is
**verified** anonymously accessible (papi#48, [FDR-0010](docs/features/0010-forge-access-asserter.md)),
as an ndjson-crap stream (pipe to `crap-present`); exits non-zero on a MUST violation.
The **card-free floor** reads each forge's declared `canary` — a published
`visibility:private` repo (RFC-0001 §1.1) — and fails if it appears in the anonymous
`/papi/repos` (a private-repo leak). Pass `--auth-key-id` (or the legacy
`--recipient`/`--decrypt-cmd`) to also reconcile the full declared set: every
declared-public repo anonymously visible, every declared-private/scoped repo hidden.
`--forge <id>` scopes to one forge. Deployment/topology (DNS, firewall, nginx) is out
of scope — that is circus's plane, which delegates the visibility half here.

```console
$ papi forge check linenisgreat.com                        # card-free canary floor
$ papi forge check linenisgreat.com --forge forgejo-krone  # scope to one forge
$ papi forge check linenisgreat.com \
    --auth-key-id piggy-auth-v1@...                         # + full declared-vs-verified reconcile
```

### `papi profiles <domain>`

Fetch `<domain>`'s `GET /papi/profiles` — the host profiles (flakerefs) a staged
installer activates (RFC-0001 §13) — and print them. By default emits the
profiles as JSON; `--id` selects a single profile (erroring if none matches);
`--flakeref` prints one flakeref per line. Host profiles are commonly §5-gated, so
an unauthenticated fetch shows only the anonymous-visible set; pass `--auth-key-id`
(the §5.2 sign-challenge) to run the §5 handshake and see the full set:

```console
$ papi profiles linenisgreat.com                       # JSON: id/flakeref/home_flakeref/…
$ papi profiles linenisgreat.com --id framework-laptop --flakeref
github:amarbel-llc/eng#nixosConfigurations.framework-laptop
$ papi profiles linenisgreat.com --auth-key-id piggy-auth-v1@... --flakeref   # + §5-gated profiles
```

### `papi query <domain> <jq-expr>`

Fetch `<domain>`'s `GET /papi` document and evaluate a jq expression against it —
an embedded [gojq](https://github.com/itchyny/gojq), so no external `jq` is
needed — printing each result as JSON, or unquoted strings under `--raw`/`-r`.
Lets consumers pluck arbitrary fields (`forges[]`, `organizations[]`, `repos[]`,
`person`, …) without bespoke `curl`+`jq`. Anonymously the document is the public
projection; pass `--auth-key-id` (the §5.2 sign-challenge) to jq over the full scoped
projection — the way to reach the projected endpoints without a dedicated
subcommand (`organizations[]`, `sitemap`, `templates[]`, …):

```console
$ papi query linenisgreat.com '.person.handle' -r
linenisgreat
$ papi query linenisgreat.com '.forges[].repos[].url' -r
$ papi query linenisgreat.com '.person.contact.email' -r \
    --auth-key-id piggy-auth-v1@...                      # acl-gated, needs auth
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
provisioning prompts for the PIN on your terminal. On success papi also registers
the new card's slot-9A key on **your GitHub account** as both an authentication
and a signing key (via `gh`), so the card can immediately `git@github.com` and
sign commits — pass `--no-gh-register` to skip (e.g. enrolling for someone else).

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
- `--no-gh-register` — do NOT register the new card's slot-9A key on GitHub
  (auth + signing). Registration is on by default; skip it when enrolling a card
  for someone else's account.
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

### `papi sign-challenge --domain <domain>`

Answer a [§5.2 sign-challenge](docs/rfcs/0001-personal-api-papi-wire-format.md)
(the RECOMMENDED `papi/v0` auth scheme). It is a strict signing **primitive**: read
the **bare challenge payload** (`{challenge_id, nonce, expires_at}`) on **stdin**,
build the domain-separated preimage `papi-auth-v1\n<domain>\n<nonce>`, sign
`SHA-256(preimage)` with your PIV **slot-9A** key (ECDSA P-256, via `piggy
sign-bytes --slot 9a` — the card must be present; no agent), and print the `POST
/papi/auth/response` body `{challenge_id, signature}` on **stdout**, where
`signature` is a `papi-auth-sig-v1@ecdsa_p256_sig` markl id (raw 64-byte `r‖s`).
A live server wraps its `POST /papi/auth/challenge` response in the
[§4.2 `{data, meta}` envelope](docs/rfcs/0001-personal-api-papi-wire-format.md), so
stdin is the bare challenge, **not** the raw HTTP body — pass **`--from-response`**
to feed that whole enveloped response on stdin and read the challenge from `.data`.
`--domain` is the PAPI identity domain the signature binds to — it is **never
echoed** by the challenge (cross-site relay defense), so you supply it. With no
`--guid` the sole provisioned card is used; `--pin` passes the slot-9A PIN. The
command does no network I/O itself — the caller POSTs the body and the server
verifies it against the registered slot-9A key, minting a session.

```console
# the signing primitive: a bare challenge payload on stdin
$ echo '{"challenge_id":"a1b2…","nonce":"3f9c…","expires_at":1750000000}' \
    | papi sign-challenge --domain staging.example.com --pin ******
{"challenge_id":"a1b2…","signature":"papi-auth-sig-v1@ecdsa_p256_sig-qqqsyq…"}

# or pipe the live server's enveloped {data,meta} response straight in
$ curl -fsS https://api.example.com/papi/auth/challenge -d '{"auth_key_id":"…"}' \
    | papi sign-challenge --domain example.com --from-response --pin ******
{"challenge_id":"a1b2…","signature":"papi-auth-sig-v1@ecdsa_p256_sig-qqqsyq…"}
```

### `papi gh-check <domain>`

Cross-check `<domain>`'s published slot-9A keys — **the domain is the source of
truth** — against the SSH keys on your authenticated GitHub account (both
authentication and signing, via `gh api`), matching by key material. Every
domain-published key must be registered on GitHub; a published card **missing**
from GitHub is a failure (a **gap**). Extra keys on GitHub (not from the domain)
are fine and never fail — `--show-orphans` lists them as informational notes.
Presented via the crap-TUI; exits non-zero only on a gap.

GitHub gates the two key kinds behind separate scopes — auth keys need
`admin:public_key`, signing keys need `admin:ssh_signing_key` (or the `read:`
variants). A missing scope **skips** that kind (surfacing gh's
`gh auth refresh -s …` hint) rather than failing the whole check; grant both with
`papi gh-auth`.

```console
$ papi gh-check linenisgreat.com
✓ domain key guid=55C3439D… is registered on GitHub
✗ domain key guid=2835305C… is registered on GitHub
    reason: gap — published on the domain but NOT on GitHub
↷ GitHub signing keys listed # SKIP gh api …: needs admin:ssh_signing_key
```

### `papi gh-auth`

Launch `gh auth refresh` to add the OAuth scopes papi's GitHub integration uses —
`admin:public_key` and `admin:ssh_signing_key` — to your existing `gh` login. The
one-liner for the missing-scope case above; interactive (gh runs its
browser/device flow). `--hostname` overrides the default `github.com`.

```console
$ papi gh-auth
```

### `papi identity get <dotted.path>` / `papi identity domain`

Read a scalar field from the local `identity.toml` — the canonical reader eng
consumers use instead of hand-rolling `nix eval`/`grep` over the file
([FDR-0009](docs/features/0009-papi-identity-toml-reader.md)). This is the one
command family that reads **local config** rather than a remote domain. papi owns
only the read *mechanism* (TOML parse, dotted-path lookup, default-on-absent, XDG
resolution); it attaches no meaning to any field — the schema is the consumer's.

`papi identity get <dotted.path>` prints the scalar at the path (e.g.
`host.privilege-escalation`, `papi.domain`) with a trailing newline. The file is
`$XDG_CONFIG_HOME/identity.toml`, falling back to `~/.config/identity.toml`;
`--file` overrides it. When the file or the key is **absent**, it prints
`--default` (empty if unset) and exits 0 — mirroring a shell `… or "<default>"`
read, so it is safe under `set -e`. A present empty string is printed as-is (the
default does not fire). A path resolving to a **table or array**, or a
malformed/unreadable file, exits non-zero — a wrong path is a caller bug, not an
absence.

`papi identity domain` is sugar over `papi identity get papi.domain` — the one
papi-semantic field, the host's PAPI identity domain (`[papi] domain`). It
deliberately has **no built-in default and no `--default`**: papi stays
domain-agnostic, so the domain's single source of truth is `identity.toml`, not
papi's binary. An absent key prints empty and exits 0; for a fallback use the
generic `papi identity get papi.domain --default <d>`.

```console
$ papi identity get host.privilege-escalation --default auto
auto
$ papi identity domain
linenisgreat.com
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
internal/0/identity/   local identity.toml scalar reader (FDR-0009)
internal/alfa/inspect/ the validate command + receipt verification core
internal/alfa/enroll/  the enroll command: card provisioning + receipt assembly
internal/alfa/signchallenge/  the sign-challenge command: §5.2 preimage + slot-9A response
cmd/papi-verify-wasm/  network-free receipt verifier, built to wasip1 (FDR-0002)
cmd/papi-client-wasm/  network-free RFC-0001 decode/verify core, built to js/wasm (FDR-0007)
cmd/papi-installer/    staged host installer: RFC-0003 phase engine + crap TUI (FDR-0006)
clients/ts/            TypeScript client wrapper over the js/wasm core (FDR-0007)
internal/0/installer/  the RFC-0003 phase engine the installer drives (FDR-0006)
nix/hm, nix/nixos/     the papi-ssh-sync home-manager + NixOS modules (FDR-0005)
main.go                cobra CLI (validate, piggy-ids, ssh-keys, ssh-copy-id, ssh-sync, bootstrap, gh-check, gh-auth, person, enroll, verify-receipt, verified-recipients, sign-challenge, identity)
```

Packages under `internal/` are tiered by dependency depth — NATO-phonetic
levels where `0` is a leaf (no internal deps), `alfa` depends only on level
`0`, and so on — repositioned with [dagnabit](https://github.com/amarbel-llc/purse-first)
(`nix run github:amarbel-llc/purse-first#dagnabit -- --initial internal`).
