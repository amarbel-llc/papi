papi-bootstrap(7) "papi"

# NAME

papi-bootstrap - cold-host self-bootstrap over PAPI (GET /papi/bootstrap)

# DESCRIPTION

A host with a provisioned YubiKey installed should be able to *self-bootstrap*: fetch a small script over PAPI and run it to provision itself against eng, with no prior tooling on the box. The chicken-and-egg is that a cold host has nothing yet — no nix, no ssh-agent, no _jq_ — only a card and a network, so the entrypoint must be a single public pipe into a shell.

*papi* owns one endpoint and one read affordance; the script itself lives in eng and is served verbatim. This page describes the bootstrap concept and trust model. For the command's flags, see *papi-bootstrap*(1).

# THE ENDPOINT

_GET /papi/bootstrap_ (RFC-0001 4.2):

- _text/plain_, not enveloped — like _/papi/piggy-ids_ and _/papi/ssh-authorized-keys_.
- Public and unprojected: the same body for every requester, no auth. Gating it behind the 5-handshake would be circular, since the shim is what bootstraps the ability to authenticate.
- Optional per-domain; absent on domains that publish no shim.
- The body is the self-bootstrap shim, owned and version-controlled in eng (_bin/provision.sh_) and hosted verbatim by the serving domain.

The cold-host entrypoint is:

```
curl -fsSL https://<domain>/papi/bootstrap | sh
```

# INSPECTING BEFORE RUNNING

*papi bootstrap <domain>* fetches the endpoint and prints the shim verbatim: the inspect-before-you-run affordance. Review the body, then pipe it to a shell yourself:

```
$ papi bootstrap linenisgreat.com | less
$ papi bootstrap linenisgreat.com > provision.sh   # review, then: sh provision.sh
```

# THE SHIM

The served body is eng's self-contained _provision.sh_. The same script is both the served shim and the in-checkout provisioner; it path-selects on _$0_:

- *Cold bootstrap* — run via the pipe entrypoint, so _$0_ is not an eng checkout. It preflights, clones eng over *HTTPS* from a hardcoded public URL, then hands off to the on-disk copy via a re-exec. HTTPS (not SSH or _/papi/repos_) is used because on a cold host the ssh-agent stack and _jq_ do not exist yet.
- *In-checkout run* — the re-exec'd copy runs the provisioning steps: nix, tools, identity bootstrap from PAPI keyed on card GUID, rcm, then home-manager. The SSH sibling-repo cascade runs here, after the agent and _jq_ exist.

Because the served shim and the committed provisioner are one artifact, there is no second script to drift.

# EVOLUTION: THE BINARY-FETCHING SHIM

The endpoint *contract is unchanged* — _GET /papi/bootstrap_ stays a public, unprojected _text/plain_ shim — so there is no RFC version bump. What evolves is the shim *body*: instead of cloning eng and exec'ing _provision.sh_, the next iteration fetches, *verifies*, and execs the signed staged installer binary (FDR-0006). The evolved shim verifies a detached slot-9A (P-256) signature against the domain's published slot-9A ids (_/papi/piggy-ids_) *and* a digest pin the shim itself carries, before it execs anything (FDR-0008). This closes the bash path's fetch-time-verification gap.

# TRUST MODEL

- The shim is fetched publicly, with no auth. The anchor for the bash path is that the HTTPS clone target is public and reviewed, and the served body is hosted verbatim from eng — minimizing the unreviewed pipe-to-shell surface and preventing drift from a one-off pasted script.
- No fetch-time verification on the bash path: a host runs whatever the domain serves. The binary-fetching shim above closes this with a signature and digest check before exec.
- Do not conflate slot roles: the 5-handshake uses slot-9D (decrypt); slot-9A is the published ssh-auth/signing key used for the git clone and for signatures.

# OWNERSHIP

- *papi* owns the endpoint, its RFC-0001 4.2 contract, and the *papi bootstrap* read affordance.
- The serving domain hosts the shim body verbatim.
- *eng* owns the shim content and cold-host hardening (_bin/provision.sh_).

# SEE ALSO

*papi-bootstrap*(1), *papi-enroll*(1), *papi-ssh-sync*(7), *papi*(1)

The design record is _docs/features/0003-papi-self-bootstrap-endpoint.md_ (FDR-0003); the staged installer binary is FDR-0006 and its signing strategy is FDR-0008.
