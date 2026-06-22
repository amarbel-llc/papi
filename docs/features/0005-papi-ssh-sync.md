---
status: proposed
date: 2026-06-22
promotion-criteria: >
  exploring → proposed: this document. proposed → experimental: `papi ssh-sync`
  + the papi-ssh-sync home-manager/NixOS modules land, the eval-test passes, and
  a NixOS host auto-wires services.openssh.authorizedKeysFiles from a synced
  fragment. experimental → testing: a real host keeps authorized_keys in sync
  from linenisgreat.com on a timer across a card rotation — both an added key and
  a removed key are reflected on the next run. testing → accepted: running on
  NixOS, nix-darwin, and standalone home-manager (Ubuntu) for two weeks with no
  manual steps beyond the one-time sshd wiring on the non-NixOS platforms.
---

# papi ssh-sync (`papi ssh-sync` + the papi-ssh-sync home-manager/NixOS modules)

## Problem Statement

A PAPI domain publishes the slot-9A SSH keys that may authenticate as a person
(`GET /papi/ssh-authorized-keys`, RFC-0001 §4.2). Today papi can only *push*
those keys to a **remote** host via `papi ssh-copy-id`, which **appends** to the
remote `~/.ssh/authorized_keys` and never prunes — a rotated or revoked card's
key lingers until someone removes it by hand. There is no way to keep a **local**
host's `authorized_keys` in sync, and no Nix service surface to run a sync on a
schedule.

A host should be able to *declaratively* track a domain: full rewrite of a
dedicated file, prune on rotation, on a timer — so that pointing a host at a papi
domain once keeps its accepted login keys current as cards are enrolled and
retired. This mirrors how piggy and ssh-agent-mux ship a home-manager service.

## Interface

### `papi ssh-sync <domain>`

Fetch all of `<domain>`'s published slot-9A keys (the §8.1 discovery-following
client) and **(re)write them in full** into a LOCAL managed file. Unlike
`ssh-copy-id`, ssh-sync OWNS its target file: the file is rewritten to exactly
the domain's current key set every run, so an upstream-removed key is pruned on
the next sync. An unchanged upstream leaves the file byte-identical (reported
`unchanged`); a changed one is reported `updated`.

- Default target: `$XDG_CONFIG_HOME/papi/ssh-sync/<host>.keys`, where `<host>` is
  the domain's host (scheme/path stripped), lowercased, with every byte outside
  `[a-z0-9.-]` — notably the port `:` — mapped to `_`. Override with
  `--authorized-keys PATH`.
- The parent dir is created `0700` and the file `0600`, written atomically (temp
  + rename) so a concurrent sshd read never sees a half-written file.
- A managed, **timestamp-free** header banner marks the file as machine-owned
  (the timestamp-free part is what lets an unchanged upstream report `unchanged`).
- `--guid <HEX>` syncs only that one card's key.
- **One domain per invocation** — the file→domain mapping (and the service's
  one-unit-per-instance model) stays unambiguous. A domain that publishes no keys
  prunes the managed file to header-only rather than erroring.

`papi.NormalizeBaseHost` is the library helper the default-path slug is derived
from (the same host for `example.com`, `https://example.com`, and
`https://example.com/foo`).

### `services.papi-ssh-sync` (home-manager module)

`homeManagerModules.papi-ssh-sync`, curried with the papi flake's `self` so
`package` defaults to `self.packages.${system}.papi` (papi isn't in nixpkgs).
Runs `papi ssh-sync` on a schedule:

- **Linux**: a `Type=oneshot` `systemd.user.service` plus a `systemd.user.timer`
  (`OnBootSec=2min`, `OnUnitActiveSec=<intervalSeconds>s`, `Persistent=true`).
- **Darwin**: a `launchd.agents` entry with `RunAtLoad=true` and
  `StartInterval=<intervalSeconds>` (launchd's interval is seconds, 1:1).

Single-instance via top-level `domain`/`authorizedKeysPath`/`guid`/
`intervalSeconds`/`extraArgs` (unit `papi-ssh-sync`); multi-instance via an
`instances.<name>` attrset (units `papi-ssh-sync-<name>`), each writing its own
per-domain fragment so instances never collide. The two modes are mutually
exclusive (asserted). The module also puts `papi` on `home.packages`.

### `nixosModules.papi-ssh-sync`

Re-exports the home-manager module into every home-manager-managed user AND
**auto-wires** sshd: it enumerates each enabled instance's fragment path into
`services.openssh.authorizedKeysFiles`, re-adding the stock
`%h/.ssh/authorized_keys` (assigning the list replaces sshd's default).

## Cross-platform wiring

The home-manager module keeps the fragment fresh and the timer running on every
platform, but it **cannot edit system `sshd_config`**. So who points sshd's
`AuthorizedKeysFile` at the fragment differs:

| Platform | Fragment + timer | sshd wiring |
|---|---|---|
| NixOS | hm module | **automatic** via `nixosModules.papi-ssh-sync` → `services.openssh.authorizedKeysFiles` |
| nix-darwin | hm module (launchd) | **manual once** — add `AuthorizedKeysFile .ssh/authorized_keys <fragment>` to `/etc/ssh/sshd_config.d/` (or write it via nix-darwin `environment.etc`) |
| standalone home-manager (Ubuntu) | hm module (systemd user) | **manual once** — add the same `AuthorizedKeysFile` line to `/etc/ssh/sshd_config.d/` and reload sshd |

Zero-config single-instance fallback: point `authorizedKeysPath` at
`~/.ssh/authorized_keys2`, which stock sshd reads by default — no sshd config
change at all (covers one domain only; verify your platform's default
`AuthorizedKeysFile` includes `authorized_keys2`). Keep fragments under `$HOME`
with the `0700`/`0600` perms the CLI sets, or sshd `StrictModes` will refuse
them.

## Examples

```console
# one-shot, standalone:
$ papi ssh-sync linenisgreat.com
synced 2 key(s) to /home/me/.config/papi/ssh-sync/linenisgreat.com.keys (updated)
$ papi ssh-sync linenisgreat.com            # nothing changed upstream
synced 2 key(s) to /home/me/.config/papi/ssh-sync/linenisgreat.com.keys (unchanged)
```

```nix
# home-manager, single domain (NixOS auto-wires sshd):
services.papi-ssh-sync = {
  enable = true;
  domain = "linenisgreat.com";
};

# home-manager, multiple domains:
services.papi-ssh-sync.enable = true;
services.papi-ssh-sync.instances = {
  work = { domain = "example.com"; };
  home = { domain = "linenisgreat.com"; intervalSeconds = 1800; };
};
```

```
# nix-darwin / standalone-HM one-time sshd line (path from the fragment default):
AuthorizedKeysFile .ssh/authorized_keys .config/papi/ssh-sync/linenisgreat.com.keys
```

## Trust model

- The **domain is the source of truth.** A full rewrite means a rotated or
  revoked card is pruned on the very next sync — strictly stronger than
  `ssh-copy-id`'s append, which would leave a revoked key authorized.
- The managed file is `0600`; only lines that parse as real SSH keys are written
  (reusing `extractAuthorizedKeys`'s `ParseAuthorizedKey` gate), so a hostile
  domain cannot smuggle arbitrary text into `authorized_keys`.
- **No fetch-time signature.** A host honors whatever the domain serves over
  HTTPS at sync time — the same posture as `ssh-copy-id` and `bootstrap`
  (FDR-0003). A signed/pinned key set is an open decision.
- Slot roles (do not conflate): slot-9A is the published ssh-auth key this syncs;
  §5/slot-9D box decrypt is unrelated and unaffected.

## Limitations

- **Non-NixOS sshd wiring is a one-time operator step** (see the table). The
  module never overpromises: it cannot touch `/etc/ssh/sshd_config` from
  home-manager.
- **`network-online.target` under the systemd *user* manager / standalone HM is
  best-effort** — it isn't always populated the way the system manager's is. papi
  has a 15s HTTP timeout and the timer retries on cadence, so a too-early run just
  fails one cycle; the dependency is a hint, not load-bearing.
- **The service ships the wrapped papi** (piggy + gh on PATH), whose closure rides
  along though ssh-sync needs neither. Exposing an unwrapped `papi` package and
  defaulting the module to it is a clean follow-up if closure weight matters.
- **One domain per unit** — multi-domain hosts use multiple instances.

## Ownership split

| Piece | Owner |
|---|---|
| `papi ssh-sync` + `papi.NormalizeBaseHost` + the hm/NixOS modules | **papi** (this FDR) |
| Serving `GET /papi/ssh-authorized-keys` at the domain | the serving domain (e.g. linenisgreat) |
| sshd `AuthorizedKeysFile` on non-NixOS hosts | the operator / their config management |

## More Information

- RFC-0001 §4.2 (`/papi/ssh-authorized-keys`), §8.1 (discovery-following client),
  §12 (identity-bootstrap consumption).
- FDR-0003 (`0003-papi-self-bootstrap-endpoint.md`) — the sibling text-endpoint
  consumer; same "no fetch-time signature" posture.
- Reference module patterns: piggy `nix/hm/piggy-agent.nix` +
  `nix/hm/eval-test.nix` + `nix/nixos/piggy-agent.nix`; ssh-agent-mux
  `nix/home-manager.nix` (the `self`-curry).
