---
status: experimental
date: 2026-06-29
promotion-criteria: >
  exploring → proposed: this document. proposed → experimental: `papi identity
  get` and `papi identity domain` land with tests, matching the output/exit
  contract below. experimental → testing: eng's shared `eng_identity_field`
  adopts papi (prefer-papi-when-on-PATH, else the existing nix-eval read) and a
  real host reads its `host.*` fields and `papi.domain` through papi at the
  post-home-manager call sites. testing → accepted: eng's domain de-duplication
  completes — `home/papi-ssh-sync.nix` and `bin/bootstrap-sshd-papi-keys.bash`
  both source the PAPI domain through this reader (or directly from
  identity.toml), the literal living in exactly one place, running two weeks with
  no hand-synced copy.
---

# papi identity (`papi identity get` + `papi identity domain`)

## Problem Statement

eng consumers read `~/.config/identity.toml` by hand, each re-implementing TOML
access, default handling, and XDG path resolution:

- `bin/lib/privesc.bash`'s `eng_identity_field` hand-rolls
  `nix eval --impure --raw --expr '(builtins.fromTOML (builtins.readFile "<toml>")).host."<field>" or "<default>"'`.
- `bin/bootstrap-nix-daemon.bash` does the same for the
  `host.krone-cache-substituter` / `host.krone-cache-push` fields.
- `bin/bootstrap-builder-papi-keys.bash` greps identity.toml for
  `enable-linux-builder`.

Separately, the PAPI identity **domain** is duplicated across eng's
`home/papi-ssh-sync.nix` (`services.papi-ssh-sync.domain`) and
`bin/bootstrap-sshd-papi-keys.bash` (`PAPI_DOMAIN`, from which it derives the
fragment filename `~/.config/papi/ssh-sync/<domain>.keys`). The two MUST match by
hand or sshd points at the wrong fragment (`papi#38`).

papi today reads **no** local config — it is purely a remote-PAPI client and
vendors no TOML parser. But papi is the natural home for the *mechanism*: it is
the tool already present on these hosts, it already resolves XDG paths (FDR-0005),
and it is the rightful semantic owner of exactly one field in that file — its own
identity domain.

## Design principle: mechanism, not schema

This feature draws a hard line.

- **papi owns the read mechanism.** TOML parse, dotted-path traversal, scalar
  coercion, default-on-absent, XDG file resolution, and a single named accessor
  for the one papi-semantic field (`domain`).
- **papi owns no field meanings.** It does not know, validate, or enumerate the
  keys in identity.toml. `host.privilege-escalation`, `host.krone-cache-push`,
  `host.enable-linux-builder` are **eng's** schema; papi reads any path it is
  handed and returns the default when it is absent, with no notion of whether the
  path "should" exist. There is no embedded schema and nothing to keep in sync
  with eng.

This is what lets `papi identity get host.privilege-escalation` work without papi
having any stake in privilege-escalation. papi is `tomlq` with a canonical path
and a default contract — never the owner of the consumer's configuration shape.

## Interface

### `papi identity get <dotted.path> [--default V] [--file PATH]`

Read the scalar at a dotted TOML path from identity.toml and print it.

- **Source resolution:** `$XDG_CONFIG_HOME/identity.toml`, falling back to
  `~/.config/identity.toml` when `XDG_CONFIG_HOME` is unset. `--file PATH`
  overrides both (tests, non-standard hosts).
- **Output:** the resolved scalar printed verbatim to stdout followed by a single
  newline — no quoting, no decoration. A string prints as-is; a boolean prints
  `true`/`false`; an integer/float prints its canonical TOML lexical form. (Mirrors
  `nix eval --raw` on a scalar.)
- **Exit / default contract** — the load-bearing part, designed to mirror eng's
  `... or "<default>"` which never fails:

  | situation | behavior |
  |---|---|
  | file absent | exit 0, print `--default` (empty string if omitted) |
  | file present, key absent | exit 0, print `--default` (empty string if omitted) |
  | key present, scalar value | exit 0, print the value |
  | key present, value is empty string | exit 0, print empty — **`--default` does not fire** |
  | path resolves to a table or array | **exit non-zero** — caller bug; the default does NOT apply |
  | file present but unreadable / malformed TOML | **exit non-zero**, diagnostic on stderr |

  An **absent** file is not an error (it is the default case). An **unreadable or
  malformed** file is. `--default` applies only to absence (missing file or
  missing key), never to a present-but-wrong-type (a programming error, distinct
  from absence) and never to a present empty string (returned as-is).

  Exit 0 on absent-with-default makes the command safe under `set -e`.

### `papi identity domain`

The one papi-semantic accessor: sugar over `papi identity get papi.domain`.

- Reads the dotted path `papi.domain` (the canonical key, see below). Absent file
  or key → empty + exit 0.
- It has **no built-in default and no `--default` flag** (see Decision). If a
  consumer needs a fallback it calls the generic
  `papi identity get papi.domain --default <d>` instead.
- The point of the named accessor is to de-duplicate the **key path**, not the
  value: both eng's `home/papi-ssh-sync.nix` and `bin/bootstrap-sshd-papi-keys.bash`
  call `papi identity domain` and neither hardcodes the path `papi.domain` nor the
  domain value.

## Decision: papi carries no built-in domain default

The canonical PAPI-domain key is `[papi] domain` (dotted path `papi.domain`); eng
adds a `[papi]` table to its identity schema. When that key is absent,
`papi identity domain` returns **empty** — papi does **not** fall back to a
compiled-in domain literal.

Rationale:

- papi is a general-purpose, published, **domain-agnostic** tool. Every other
  subcommand takes `<domain>` as an explicit argument; papi never assumes "your"
  domain. Baking one person's domain as a functional built-in default would break
  that design and embed a specific identity into a multi-user tool's source as a
  value papi returns *by default for every user* — distinct from the illustrative
  `linenisgreat.com` the docs use as an example.
- It would also undermine the reason identity.toml has a `papi.domain` field at
  all. The analogy: `git` reads your email from `.gitconfig`; it does not compile
  your address into the binary. identity.toml is the `.gitconfig` here — the
  person's config and the rightful home of the domain value.

**Single source of truth = identity.toml `[papi] domain`**, not papi's binary. The
empty-domain footgun (an absent key → sshd points at
`~/.config/papi/ssh-sync/.keys`) is resolved **consumer-side**. Two ways exist —
pass `--default <domain>` to `papi identity get papi.domain`, or guarantee the key
is always materialized — and eng has chosen the latter: `bin/bootstrap-identity.mjs`
already holds the domain as its irreducible bootstrap **seed** (it is the script
that *writes* identity.toml and so cannot read the domain out of the file it
creates), and will write `[papi] domain` from that seed; existing hosts are
backfilled once. No `--default` literal therefore reappears at any call site, which
is why `papi identity domain` stays default-less. eng's de-duplication net: the
three duplicated literals (`bootstrap-identity.mjs`, `home/papi-ssh-sync.nix`,
`bin/bootstrap-sshd-papi-keys.bash`) collapse to that one pre-existing seed.

papi returning empty for an absent key is correct mechanism behavior, not a defect
to paper over with a baked literal.

## Consumer adoption (eng-side — informational, not papi's to implement)

eng's shared `eng_identity_field` will **prefer `papi` when it is on `PATH`, else
fall back to the existing nix-eval read.** papi installs via home-manager
(present from `provision.sh` step 6 onward); call sites that run earlier —
`bin/bootstrap-nix-daemon.bash` (step 2) and, on Darwin,
`bin/bootstrap-builder-papi-keys.bash` (step 5, before `darwin-rebuild`) — run
before papi is on `PATH` and use the nix fallback. nix is guaranteed at all those
sites; papi is not. **This CLI does not solve cold-host bootstrap — eng's fallback
shim does.**

## Examples

```console
$ papi identity get host.privilege-escalation --default auto
auto
$ papi identity get papi.domain
linenisgreat.com
$ papi identity domain
linenisgreat.com
$ papi identity get host.does-not-exist --default fallback     # absent key + default
fallback
$ papi identity get host.does-not-exist                        # absent, no default
                                                               # → empty line, exit 0
$ papi identity get papi                                       # path is a table
Error: papi: not a scalar (table)                              # → exit 1 (stderr)
```

## Implementation notes

- papi vendors no TOML decoder today; this adds one (e.g.
  `pelletier/go-toml/v2` or `BurntSushi/toml`). Decode to a generic map and walk
  the dotted path; `gojq` (already vendored) is unnecessary for flat scalar
  lookup.
- Expose the read as a small library function (an `internal/0` leaf, e.g.
  `ReadIdentityField(path string, opts …)`), so the `domain` accessor and any
  future consumer share one implementation; `main.go` gets a thin `identity`
  cobra command with `get` and `domain` subcommands.
- Dotted-path splitting is on `.`; keys containing a literal dot are out of scope
  (identity.toml's keys are plain identifiers).

## Limitations

- **Read-only.** papi reads identity.toml and never writes it. Materializing
  `papi.domain` (or any key) is eng's responsibility.
- **Scalar-only.** A path resolving to a table or array is a caller-bug exit, not
  traversable. A consumer needing a list is a future extension (e.g. a `--json`
  mode or repeated-line output), explicitly out of scope here.
- **No schema / no validation.** papi cannot catch a typo'd key — it returns the
  default. By design (mechanism, not schema).
- **TOML only**, file named `identity.toml`; no other formats or filenames beyond
  the `--file` override.

## Ownership split

| Piece | Owner |
|---|---|
| `papi identity get`, `papi identity domain`, the TOML read mechanism + XDG resolution | **papi** (this FDR) |
| identity.toml schema, field meanings, `host.*` and their defaults, writing the file | eng |
| the `papi.domain` **value** (single source of truth) | identity.toml `[papi] domain`, owned by the host owner / eng bootstrap |
| the papi-preferring fallback in `eng_identity_field` | eng |

## More Information

- `papi#38` — the filing issue.
- FDR-0005 (`0005-papi-ssh-sync.md`) — XDG path-resolution precedent and the
  `papi.domain` consumer (`papi-ssh-sync.domain`) this de-duplicates.
- eng consumers: `bin/lib/privesc.bash`, `bin/bootstrap-nix-daemon.bash`,
  `bin/bootstrap-builder-papi-keys.bash` (the hand-rolled reads); `home/papi-ssh-sync.nix`,
  `bin/bootstrap-sshd-papi-keys.bash` (the domain-duplication motivating example).
