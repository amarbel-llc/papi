---
status: experimental
date: 2026-06-22
promotion-criteria: >
  proposed → experimental: MET 2026-06-22 — linenisgreat request-time-proxies
  eng@master:bin/provision.sh at GET /papi/bootstrap and `papi bootstrap
  linenisgreat.com` prints it verbatim.
  experimental → accepted via cold-host E2E is RETIRED: iteration 1 (proving the
  bash path end to end on a real cold host) was dropped — the only available cold
  host, the fanless Framework board, is too slow to provision testably. The bash
  shim stays the live served `/papi/bootstrap` entrypoint in the interim and is
  superseded by the binary installer (FDR-0006) when that lands.
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
alias: `exec "$(dirname "$0")/provision.sh"`). The **same script** is both the
served shim and the in-checkout provisioner — it path-selects on `$0` (eng#201's
unified idempotent provisioner, eng `docs/features/0006-unified-idempotent-provisioner.md`):

1. **Cold bootstrap** — run via `curl … | sh`, so `$0` is not an eng checkout.
   Preflight, then `git clone`/`pull` eng over **HTTPS** from a hardcoded public
   URL (`ENG_GIT_URL` override for tests), then hand off to the on-disk copy:
   `ENG_PROVISION_REEXEC=1 exec ~/eng/bin/provision.sh`. HTTPS, not SSH /
   `/papi/repos`+`jq`: on a cold host the pivy / ssh-agent-mux stack and `jq` do
   not exist yet (home-manager installs them inside `provision.sh`), and
   `amarbel-llc/eng` is public.
2. **In-checkout run** — the re-exec'd copy (or any invocation from within the eng
   checkout) runs the provisioning Steps 0–6: nix → tools → identity bootstrap
   from PAPI keyed on card GUID → rcm → home-manager. The `/papi/repos`+`jq`+SSH
   sibling-repo cascade runs **here**, after the agent and `jq` exist.

The `$0` path-select + `ENG_PROVISION_REEXEC` re-exec means the served shim and the
committed provisioner are **one artifact**: the cold entrypoint is just the
in-checkout provisioner reached via a clone-and-re-exec preamble, so there is no
second script to drift.

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
- eng#201 / eng `docs/features/0006-unified-idempotent-provisioner.md` — the
  unified `provision.sh` (served shim == in-checkout provisioner via `$0`
  path-select + `ENG_PROVISION_REEXEC` re-exec) this section mirrors.
