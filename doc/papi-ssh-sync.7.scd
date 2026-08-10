papi-ssh-sync(7) "papi"

# NAME

papi-ssh-sync - keep a local authorized_keys file in sync with a PAPI domain's slot-9A keys

# DESCRIPTION

A PAPI domain publishes the slot-9A SSH keys that may authenticate as a person (_GET /papi/ssh-authorized-keys_, RFC-0001 4.2). *papi ssh-sync* tracks that set on a *local* host: it fetches all of a domain's published slot-9A keys and rewrites a dedicated, machine-owned file to *exactly* the domain's current set on every run.

The domain is the source of truth. Because every run is a full rewrite, a rotated or revoked card is *pruned* on the next sync — strictly stronger than *papi ssh-copy-id*(1), which appends to a remote _authorized_keys_ and never removes a stale key. An unchanged upstream leaves the file byte-identical (reported _unchanged_); a changed one is reported _updated_.

This page describes the sync model and its Nix deployment surface. For the command's flags and arguments, see *papi-ssh-sync*(1).

# THE MANAGED FILE

*papi ssh-sync* owns its target file entirely:

- Default path _$XDG_CONFIG_HOME/papi/ssh-sync/<host>.keys_, where _<host>_ is the domain's host (scheme and path stripped), lowercased, every byte outside _[a-z0-9.-]_ (notably the port colon) mapped to underscore. Override with _--authorized-keys PATH_.
- The parent directory is created _0700_ and the file _0600_, written atomically (temp then rename) so a concurrent sshd read never sees a half-written file.
- A managed, timestamp-free header banner marks the file as machine-owned; the absent timestamp is what lets an unchanged upstream report _unchanged_ rather than churning the file.
- One domain per invocation. A domain that publishes no keys prunes the managed file to header-only rather than erroring.

# DEPLOYMENT

The papi flake ships two modules that run *papi ssh-sync* on a schedule, each curried with the flake's _self_ so _package_ defaults to the flake's own papi (papi is not in nixpkgs).

## services.papi-ssh-sync (home-manager)

_homeManagerModules.papi-ssh-sync_ runs the sync on a timer and puts papi on _home.packages_:

- On Linux, a _Type=oneshot_ user service plus a user timer (_OnBootSec=2min_, _OnUnitActiveSec_, _Persistent=true_).
- On Darwin, a _launchd.agents_ entry with _RunAtLoad=true_ and _StartInterval_.

Configure a single domain via the top-level _domain_, _authorizedKeysPath_, _guid_, _intervalSeconds_, and _extraArgs_ options (unit _papi-ssh-sync_), or many via an _instances.<name>_ attrset (units _papi-ssh-sync-<name>_), each writing its own per-domain fragment. The two modes are mutually exclusive and asserted.

## nixosModules.papi-ssh-sync

Re-exports the home-manager module into every home-manager-managed user and *auto-wires* sshd: it enumerates each enabled instance's fragment into _services.openssh.authorizedKeysFiles_, re-adding the stock _%h/.ssh/authorized_keys_ (assigning the list replaces sshd's default).

# SSHD WIRING

The home-manager module keeps the fragment fresh and the timer running on every platform, but it *cannot edit system sshd_config*. Who points sshd's _AuthorizedKeysFile_ at the fragment therefore differs by platform:

- *NixOS*: automatic, via _nixosModules.papi-ssh-sync_.
- *nix-darwin*: manual once — add an _AuthorizedKeysFile_ line naming the fragment to _/etc/ssh/sshd_config.d/_ (or via nix-darwin _environment.etc_).
- *standalone home-manager* (e.g. Ubuntu): manual once — add the same _AuthorizedKeysFile_ line to _/etc/ssh/sshd_config.d/_ and reload sshd.

A zero-config single-domain fallback is to point _authorizedKeysPath_ at _~/.ssh/authorized_keys2_, which stock sshd reads by default (no _sshd_config_ change at all). Keep fragments under _$HOME_ with the _0700_/_0600_ perms the CLI sets, or sshd _StrictModes_ will refuse them.

# TRUST MODEL

- The domain is the source of truth. A full rewrite prunes a rotated or revoked card on the very next sync.
- The managed file is _0600_, and only lines that parse as real SSH keys are written, so a hostile domain cannot smuggle arbitrary text into _authorized_keys_.
- No fetch-time signature. A host honors whatever the domain serves over HTTPS at sync time — the same posture as *papi ssh-copy-id*(1) and the self-bootstrap shim (see *papi-bootstrap*(7)).
- Do not conflate slot roles: slot-9A is the published ssh-auth key this syncs; the 5-handshake slot-9D decrypt is unrelated and unaffected.

# EXAMPLES

Sync once, standalone:

```
$ papi ssh-sync linenisgreat.com
synced 2 key(s) to /home/me/.config/papi/ssh-sync/linenisgreat.com.keys (updated)
$ papi ssh-sync linenisgreat.com
synced 2 key(s) to /home/me/.config/papi/ssh-sync/linenisgreat.com.keys (unchanged)
```

Home-manager, single domain (NixOS auto-wires sshd):

```
services.papi-ssh-sync = {
  enable = true;
  domain = "linenisgreat.com";
};
```

Home-manager, multiple domains:

```
services.papi-ssh-sync.enable = true;
services.papi-ssh-sync.instances = {
  work = { domain = "example.com"; };
  home = { domain = "linenisgreat.com"; intervalSeconds = 1800; };
};
```

# SEE ALSO

*papi-ssh-sync*(1), *papi-ssh-keys*(1), *papi-ssh-copy-id*(1), *papi-bootstrap*(7), *papi*(1), *sshd_config*(5)

The design record is _docs/features/0005-papi-ssh-sync.md_ (FDR-0005).
