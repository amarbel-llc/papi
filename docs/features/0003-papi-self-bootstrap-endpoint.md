---
status: experimental
date: 2026-06-22
promotion-criteria: >
  proposed → experimental: MET 2026-06-22 — linenisgreat request-time-proxies
  eng@master:bin/provision.sh at GET /papi/bootstrap and `papi bootstrap
  linenisgreat.com` prints it verbatim.
  experimental → testing: a real cold host runs `curl -fsSL
  https://linenisgreat.com/papi/bootstrap | sh` and provisions against eng end to
  end. testing → accepted: a second cold host bootstraps with no manual steps.
---

# PAPI self-bootstrap endpoint (`GET /papi/bootstrap`)

## Problem Statement

A host that has a provisioned YubiKey installed (the card FDR-0001 enrolls and
deploys) should be able to **self-bootstrap**: fetch a small script over PAPI and
run it to provision itself against eng — with no prior tooling on the box. The
chicken-and-egg is that a cold host has nothing yet (no nix, no ssh-agent, no
`jq`), only a card and a network, so the entrypoint must be a single public
`curl … | sh`.

## Interface

papi adds one endpoint and a read affordance; the script itself lives in eng.

### `GET /papi/bootstrap` (RFC-0001 §4.2)

- `text/plain`, NOT enveloped — like `/papi/piggy-ids` and
  `/papi/ssh-authorized-keys`.
- **OPTIONAL** per-domain; absent on domains that publish no shim.
- **Public and unprojected** — the same body for every requester, no auth. Gating
  it behind §5 would be circular (the shim is what bootstraps the ability to
  authenticate).
- The body is the **self-bootstrap shim**, owned and version-controlled in eng
  (`bin/provision.sh`, `#!/bin/sh`), hosted **verbatim** by the serving domain.

Cold-host entrypoint:

    curl -fsSL https://<domain>/papi/bootstrap | sh

### `papi bootstrap <domain>`

Fetches `GET /papi/bootstrap` and prints the shim verbatim — the
inspect-before-you-run affordance (review the body, then pipe it to `sh`
yourself). Mirrors `papi piggy-ids` / `papi ssh-keys`. `papi.Client.Bootstrap` is
the library method.

### The shim (eng-owned, self-contained `provision.sh`)

The served body is eng's self-contained `bin/provision.sh` (`bin/up.sh` is a thin
alias that execs it). It:

1. `git clone`s eng over **HTTPS** from a hardcoded public URL (`ENG_GIT_URL`
   override for tests). HTTPS, not SSH / `/papi/repos`+`jq`: on a cold host the
   pivy / ssh-agent-mux stack and `jq` do not exist yet (home-manager installs
   them inside `provision.sh`), and `amarbel-llc/eng` is public.
2. stages the host (nix → tools → identity bootstrap from PAPI keyed on card GUID
   → rcm → home-manager). The `/papi/repos`+`jq`+SSH sibling-repo cascade runs
   **inside** `provision.sh`, after the agent and `jq` exist.

## Examples

    # cold host, only a provisioned YubiKey + network:
    $ curl -fsSL https://linenisgreat.com/papi/bootstrap | sh

    # inspect before running, on a host that already has papi:
    $ papi bootstrap linenisgreat.com | less
    $ papi bootstrap linenisgreat.com > provision.sh   # review, then: sh provision.sh

## Trust model

- The shim is fetched **publicly, no auth**. The trust anchor is that the
  HTTPS-clone target (`amarbel-llc/eng`) is reviewed and version-controlled, and
  the served body is hosted **verbatim** from `eng/bin/provision.sh` —
  minimizing the unreviewed `curl | sh` surface and preventing drift from a
  one-off pasted script.
- Sensitive data (e.g. `person.contact.email`) stays **§5-gated downstream**,
  unchanged — the shim provisions the ability to authenticate; it does not reveal
  gated data.
- Slot roles (do not conflate): §5 = slot-9D box/ECDH decrypt; slot-9A = the
  published ssh-auth/signing key (git clone + §9/§10 signatures).

## Limitations

- **papi only hosts.** All of the shim's logic — the HTTPS clone, the staging, the
  HTTPS→SSH origin rewrite once the agent is up, and the cold-host hardening — lives
  in eng's `provision.sh`, not papi. papi serves the bytes verbatim and has no say
  in what they do.
- **No fetch-time verification.** A host runs whatever the domain serves; the
  defense is the verbatim-from-eng hosting plus a public, reviewed clone target,
  not a signature on the shim. A future signed/pinned shim is an open decision.

## Ownership split

| Piece | Owner |
|---|---|
| `GET /papi/bootstrap` endpoint + RFC-0001 §4.2 + `papi bootstrap` | **papi** (this FDR) |
| Serving the shim body at the domain | **linenisgreat** (glad-acacia) |
| The shim content + cold-host hardening (`bin/provision.sh`) | **eng** (live-acacia, eng#201) |

## More Information

- [papi#16](https://github.com/amarbel-llc/papi/issues/16) — the request and the
  HTTPS-cold-clone correction.
- FDR-0001 (`0001-papi-new-yubikey-enrollment.md`) — the enrollment receipt /
  provisioned card this consumes.
- RFC-0001 §4.2 (the endpoint), §5 (auth handshake), §12 (identity-bootstrap
  consumption).
- eng: `bin/provision.sh` (the `bin/up.sh` alias execs it), `bin/clone-papi-repos.bash`.
