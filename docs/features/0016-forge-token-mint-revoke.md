---
status: experimental
date: 2026-09-02
promotion-criteria: >
  experimental (the CLI and the fine-grained mint path are implemented and covered by
  hermetic tests, but no token has been minted against a live forge — the credential
  papi authenticates WITH is still undecided) → testing when the mint credential is
  provisioned and a real round-trip runs end to end on forge.starbrandshoes.com: mint a
  token for one repo, push with it, confirm an unlisted repo is not writable, revoke,
  confirm the token is gone; → accepted when spinclass's `[auth]` drives a session's
  whole lifecycle through it (spinclass FDR-0028's own promotion criteria) and the
  deadline sweep has reaped a real orphan.
---

# Forge access-token mint / revoke (`papi forge token`)

## Problem Statement

Fleet automation pushes to the forge over SSH using a forwarded, card-backed
ssh-agent. That agent drops mid-run: on 2026-09-01 two multi-hour passes died at
~45m and ~1h40m with `Permission denied (publickey)` on every subsequent push. The
fix chosen by the operator (spinclass#285, ruling of 2026-09-01) is an HTTPS access
token established once at session start — but a token is only acceptable if it is
*narrow* (write to just the repository the session works on) and *ephemeral* (gone
when the session ends).

Neither property is free. Forgejo token **scopes** are category-wide, so
`write:repository` grants write to every repo the account can reach; and Forgejo
tokens have **no expiry at all**, so nothing dies on its own. Both gaps have to be
closed by whoever issues the token. Nothing did — the previous mint path was an ad-hoc
`forgejo admin user generate-access-token` over SSH on the forge host, which leaks one
non-expiring, all-repos token per run (circus#193).

## Interface

`papi forge token <mint|revoke|list|sweep>`, sharing connection and credential flags:

    --host <forge-hostname>
    --user <forge-account>
    --card-login              # sign the papi verifier's login challenge with the card (no stored secret)
    --auth-domain <host>      # host the verifier binds §5.2 signatures to (default: --host)
    --password-command <sh>   # prints the account password
    --otp-command <sh>        # prints a TOTP code (accounts with TOTP enrolled)
    --token-command <sh>      # prints an access token; drives the read-only paths only

Minting and revoking need `--card-login` or `--password-command`; `--token-command`
reaches only `list` (see Limitations). Secrets arrive as **shell commands**, never as
flag values or environment variables, so nothing lands in argv (world-readable in
`/proc`) or in a child's environment. The canonical value is a piggy read. This
follows `papi validate --decrypt-cmd`.

**`--card-login` is the presence-bound credential and stores no forge secret at
all.** papi drives the FDR-0014 forward-auth verifier's login flow headlessly:
`GET /auth/login` answers with a redirect carrying a nonce and a signed state, papi
signs the nonce with slot-9A, and `GET /auth/callback` returns the verifier's session
cookie, which the reverse proxy turns into an asserted account for the API. The flow
was built for browsers — the redirect normally aims at a workstation oracle holding
the card — but a CLI already has the card, so it reads the nonce out of the redirect
and signs directly. **This needs no change to the verifier**: the oracle is bypassed,
and `/auth/verify-signature` (FDR-0013) is deliberately not used, because it is
stateless by design and issues no cookie.

Two byte-exact details decide whether it works, both easy to get wrong and both
failing as an indistinguishable 401: the signature is bound to the verifier's own
external host rather than the host being called (hence `--auth-domain`), and papi
sends **no** Authorization header on the API request, because the forge vhost routes
header-authenticated requests away from the header-asserting location.

- **`mint --repo <owner/name|name> --session <id> [--scope ...] [--ttl 12h]`** creates
  a token whose write access is confined to `--repo`, and prints **the token and
  nothing else** on stdout; every diagnostic goes to stderr, because a caller captures
  all of stdout as the secret. `--repo` accepts a bare name and resolves the owner
  against the forge — spinclass derives it from the remote URL path, which is
  owner-less on the fleet's vanity remotes (`git@host:<name>.git`). An ambiguous name
  is an error naming the candidates, never a guess.
- **`revoke --session <id>`** deletes every token minted for that session. Revoking a
  session with no tokens **succeeds**.
- **`list [--session <id>] [--all]`** is the inventory, with the session and deadline
  decoded from each name. The one read-only path, so it works with `--token-command`.
- **`sweep`** revokes every papi-minted token whose deadline has passed.

**The mint goes through the forge API, never the admin CLI.** This is a correctness
requirement, not a preference: `forgejo admin user generate-access-token` hardcodes
`ResourceAllRepos = true` ("maintain legacy behaviour ... not fine-grained"), so it
can only ever mint user-wide tokens. Per-repo narrowing lives on v15's orthogonal
**token resources** axis — `ResourceAllRepos=false` plus an `access_token_resource`
row per repository — reachable only from the web UI and the API.

The wire trap that follows from this is worth naming, because getting it wrong fails
*silently and unsafely*: Forgejo reads the `repositories` field as **absent vs
present**, not empty vs non-empty. Omitting it yields `ResourceAllRepos=true` — a
user-wide token. `internal/0/forgetoken` therefore refuses an empty target set
outright rather than encoding one, so no input to the package can produce a
user-wide token.

**Deadlines live in the token's name.** papi keeps no state for this feature. A
token is named `papi-<escaped-session>-<deadline-unix>`, so any papi process on any
host can list the account's tokens and reconstruct which session owns what and when
it expires. That is what lets `revoke` find a token minted hours earlier by a
different process, and what lets `sweep` reap a session that died without revoking.
The session is escaped **reversibly** (bytes outside `[A-Za-z0-9.]` become `_XX`), so
two different sessions can never collide — a lossy flattening of `/` to `-` would
make repo `a-b` + branch `c` indistinguishable from repo `a` + branch `b-c`, and one
session's revoke would kill another's token. Only names in this form are ever
considered, so the operator's own tokens are structurally out of the sweeper's reach.

## Examples

Mint a token for one repository, print it, and use it:

    $ papi forge token mint --host forge.example.com --user sasha \
        --password-command 'piggy pass show forge/krone-password' \
        --repo linenisgreat/papi --session papi/mild-maple --ttl 12h
    minted "papi-papi_2Fmild-maple-1789041600" (id 41) for linenisgreat/papi, scopes write:repository, expires 2026-09-02T22:00:00Z
    <the token, on stdout>

The session manager's `[auth]` wiring (spinclass FDR-0028), where the command string
is a sweatfile value:

    [auth]
    mint-command = "papi forge token mint --host $SPINCLASS_FORGE_HOST --user sasha --password-command 'piggy pass show forge/krone-password' --repo $SPINCLASS_FORGE_REPO --session $SPINCLASS_SESSION_ID --ttl 12h"
    revoke-command = "papi forge token revoke --host $SPINCLASS_FORGE_HOST --user sasha --password-command 'piggy pass show forge/krone-password' --session $SPINCLASS_SESSION_ID"

Reap what crashed sessions left behind:

    $ papi forge token sweep --host forge.example.com --user sasha --password-command '...'
    revoked expired "papi-papi_2Fkeen-holly-1788955200" (id 38, session papi/keen-holly, deadline 2026-09-01T22:00:00Z)

## Limitations

- **Write is confined; read is not.** With `ResourceAllRepos=false`, unlisted
  *public* repositories stay **readable** through the token (unlisted private ones are
  invisible). For a public forge plane that is no exposure beyond what anonymous
  readers have, but "limited to the listed repository" is a claim about write only and
  should not be stated more broadly.
- **papi cannot mint with an access token.** Forgejo gates both token creation and
  token deletion behind `ReqBasicOrRevProxyAuth`, which accepts only real password
  basic-auth or a trusted reverse proxy; an access token is refused however broadly
  scoped — verified live, not only in source: with a disposable `write:user` token past
  the scope gate, `DELETE /api/v1/users/sasha/tokens/…` returns 401 `auth method not
  allowed` in both token-auth forms. So eng's sealed `forge/krone-api-token` can neither
  mint nor revoke, and the sweeper needs the same privileged credential as the mint.
- **`--card-login` works up to a forge-side flag that has not deployed yet.** What is
  verified live against `forge.starbrandshoes.com`: the login legs complete (redirect →
  slot-9A signature off the forwarded agent → `__papi_session`), and that cookie
  satisfies the vhost's `auth_request` — an anonymous request to the same path is
  bounced by nginx with a 302 to the login, while the cookie-bearing one reaches
  Forgejo. What is **not** verified: Forgejo honouring the asserted account. It answers
  403 `doer should be the site admin or be same as the contextUser`, consistent with
  its API auth chain not yet including the reverse-proxy method — that is
  `ENABLE_REVERSE_PROXY_AUTHENTICATION_API`, approved by the operator and landing
  through circus, not yet deployed. **That the flag closes this gap is a prediction,
  not an observation, and no token has been minted against a live forge.**
  `--password-command` works against the forge as it stands today and is the fallback.
- **Basic auth is unavailable to some accounts.** An account with WebAuthn keys
  enrolled cannot use basic auth at all; one with TOTP needs `--otp-command`, and a
  code that expires between fetch and use will fail the call.
- **The deadline is advisory until someone sweeps.** The forge does not enforce it —
  an expired token keeps working until `sweep` (or a revoke) runs. `sweep` has no
  daemon; something must call it.
- **Owner resolution sees only what the credential sees.** A bare `--repo` name is
  resolved by searching the forge, so a repository invisible to the credential looks
  absent rather than private.
- **One repository per token in practice.** The package accepts several, but `mint`
  exposes a single `--repo`, which is what the session-per-repo consumer needs.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| default `--ttl` | 12h | covers a long interactive or worker session without a mid-run 401, while bounding an orphan's life | passes routinely exceed it → raise; forge-native expiry lands → shorten toward the sweep interval |
| default `--scope` | `write:repository` | the minimum a push needs; `write:X` implies `read:X`, and public repos are anonymously readable | private repos whose fetch needs an explicit `read:repository` |
| name prefix | `papi-` | marks a token as papi-minted; `sweep` and `revoke` touch nothing else | a collision with a human-made token named `papi-…` (would need a more distinctive prefix) |
| owner resolution | forge repo search, exact-name match | spinclass cannot supply an owner from a vanity remote | ambiguity becomes common → resolve through the domain's PAPI `/papi/repos` projection instead |

## More Information

- papi#73 — the issue this record settles. spinclass#285 — the SSH-CA-vs-token
  ranking and the operator's shape-C ruling. spinclass FDR-0028 — the consuming
  lifecycle (mint at session creation → mode-600 credential file → worktree-scoped
  `credential.helper` + `insteadOf` → revoke at close → orphan sweep).
- **Forge-source facts, verified at Forgejo v15.0.7 by circus/keen-aspen** (the
  deployed version, confirmed via `GET /api/v1/version`): the admin CLI's hardcoded
  `ResourceAllRepos=true`; `ReqBasicOrRevProxyAuth` on both `POST` and `DELETE` of
  `/users/{username}/tokens`, with `GET` ungated; `repositories` as
  `[{owner, name}]` strings resolved server-side, with absent-vs-present deciding
  `ResourceAllRepos`; delete-by-name falling back from a numeric id, returning 422 on
  multiple matches — which is why `revoke` deletes by **id** after a list, never by
  name — and 404 when already gone.
- **Forward-looking: expiry-aware minting.** The sweep exists solely because Forgejo
  has no token expiry, open upstream as forgejo#8837. When a patched forge lands
  (examination tracked on GitHub amarbel-llc/circus#205), `--ttl` becomes a real
  expiry field on the create call and the sweep degrades to a belt-and-suspenders
  prune. The deadline is kept out of every interface except the token name precisely
  so that change stays a one-line addition rather than a redesign.
- **Rejected — deploy keys and machine users.** Deploy keys are per-repo but need
  per-repo registration per session and attribute pushes to the key rather than the
  user; machine users scope at account granularity and sprawl identities. Both were
  weighed and dropped on spinclass#285. **Rejected — card-CA SSH certificates**: native
  expiry and no sweeper, but Forgejo SSH auth is all-or-nothing at the user level, so it
  cannot express per-repo write. Retained there as the no-sweeper fallback if the
  per-repo-vs-sweeper trade is ever revisited.
- FDR-0010 (`papi forge check`) — the other `papi forge` subcommand; it reads the
  domain's PAPI projection, whereas this one talks to the forge's own API.
