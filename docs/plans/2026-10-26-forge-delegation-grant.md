# Bounded delegation grants for forge tokens (papi#88)

Question (papi#88): after one card unlock, can papi issue a bounded grant (repo
list, expiry, maximum credentials) that a manager process presents to mint
per-session, per-repo tokens without the card agent, with those tokens still
revocable by session id and covered by the TTL sweep? What format, what
verification? Design note; no code.

Labels: R = read in the cited file, I = inferred, V = verified by a run. Line
numbers are at papi `crisp-juniper` after a47b0ef; spinclass paths are at its
`firm-mulberry` worktree. Companion: spinclass
`docs/plans/2026-10-26-unattended-spawn-without-agent.md` section 4(b).

## Short answer

Yes, but **not as a client-side feature**. The forge accepts a mint or revoke
only with password basic-auth or a reverse-proxy-asserted account, never an
access token (`internal/0/forgetoken/forgetoken.go:17-19,42-48`, R). So a grant
verified on the coordinator's host gives it nothing to mint *with*: something
holding mint authority has to check the grant and do the mint. The only papi
component that already holds that authority without a stored secret is the
forward-auth verifier (`internal/bravo/authproxy`, FDR-0014), which turns a card
signature into an asserted account (`authproxy/verifier.go:105-122`, R).

The smallest workable design is a new verifier endpoint, `POST /auth/grant-mint`:
the verifier checks a card-signed grant offline against an allowed-signers file,
checks a grantee-signed mint request against the key the grant names, enforces
the bounds, and mints the token itself under papi's usual naming. That is a
papi code change plus a deploy of the verifier, which is configured and run from
circus (`circus/infra`, not this repo; I from the wiring grep for papi#91). It is
larger than the token pool (papi#80, shipped as `mint --batch`), so for a trip
that starts next week the pool is the realistic answer and this is the
follow-up (I).

## Why not cheaper variants

| Variant | Why not |
|---|---|
| Grant checked by the coordinator's own papi, which then mints with `--password-command` | the account password is unbounded authority sitting next to the grant; the grant bounds nothing (I) |
| Hand the coordinator a verifier session cookie | the cookie asserts the whole account for `SessionTTL`, default 12 h (`authproxy/verifier.go:57-58,74-76`, R): any repo, any token, any web action. Not bounded, and too short anyway |
| Pre-minted pool (papi#80) | shipped; bounded by count and repo at mint time, but standing bearer tokens at rest. The grant replaces standing tokens with standing *authority to mint*, which is narrower per credential and revocable as one object |

## Grant record

Canonical text, same discipline as spinclass's profile grant: fixed line order,
strict inverse parse, allowlisted value alphabet, newline-terminated, at most
4096 bytes (`spinclass internal/0/profilegrant/grant.go:69-89,96-179,186-199`, R).

```
papi forge-grant v1
grantor: operator
grantee: <principal>
grantee-key: <ssh public key, authorized_keys form, one line>
forge: forge.example.com
user: <forge account>
repos: owner/a owner/b
scopes: write:repository
max-live: 8
max-ttl: 24h
not-before: 2026-11-02T00:00:00Z
expires: 2026-11-09T00:00:00Z
nonce: <random>
```

- **Grant id** = SHA-256 of the canonical text, shown as its first 12 hex digits
  in token names (below). Content-addressed like spinclass's `Record.Digest`
  (`grant.go:414-423`, R).
- **Signature**: an sshsig over the canonical text under a papi-specific
  namespace, e.g. `papi-forge-grant-v1`, made by the operator's slot-9A key
  through the agent (`ssh-keygen -Y sign` shape). A distinct namespace keeps a
  grant signature from ever being valid as a spinclass escalation act or a git
  commit signature, and vice versa (I, the reason spinclass uses
  `KeysForStrict` with a namespace, `grantverify.go:55-57`, R).
- `repos` sorted, each `owner/name` (resolved; no bare names, so the verifier
  never searches). `scopes` sorted. `max-live` bounds tokens alive at once.
  `max-ttl` bounds each token's deadline; every token's deadline is also
  clamped to `expires`.
- `not-before` lets the operator sign consecutive grants in one sitting (see
  the cap question below).

## Mint request

The grantee proves possession of `grantee-key` per request, so a stolen grant
alone mints nothing:

```
papi forge-grant-mint v1
grant: <grant id>
repo: owner/name
session: <consumer's session id, e.g. papi/crisp-juniper>
ttl: 12h
time: 2026-11-03T10:00:00Z
```

signed with sshsig under `papi-forge-grant-mint-v1` by the grantee's key. Body:
`{grant_text, grant_sig, request_text, request_sig}` over TLS to the verifier.

## Verification (all offline: no card, no network beyond the forge itself)

1. Parse the grant strictly; recompute its id.
2. Verify `grant_sig` against an allowed-signers file on the verifier host,
   principal `operator`, namespace `papi-forge-grant-v1`, strict (no
   wildcard principal, no namespace-less entry), file owned by the verifier's
   uid and not group/other-writable: the `grantverify.LoadSigners` rules
   (`grantverify.go:36-63`, R). papi has no sshsig code today (R: no match for
   sshsig in `*.go`); spinclass's `internal/0/sshsig` is the reference, and
   papi would carry its own copy or a shared module (I).
3. `not-before <= now < expires`; grant id not in a local deny file.
4. Parse the request; verify `request_sig` against `grantee-key` under
   `papi-forge-grant-mint-v1`; `time` within ±5 min of now.
5. `repo` in `repos`; `ttl <= max-ttl`; deadline = min(now + ttl, expires).
6. List the account's papi tokens (`Client.Managed`, `session.go:28-42`, R)
   and count live ones whose session carries this grant's prefix; refuse at
   `max-live`. Refuse if the requested session already has a token (keeps
   revoke-by-session exact and makes a replayed request a no-op).
7. Mint through the existing `Client.Mint` with the verifier's own asserted
   credential and session `grant/<id12>/<session>`, return the secret in the
   response body only.

Counting by listing keeps papi's no-database rule ("the token name is the only
place papi records per-session state", `naming.go:22-26`, R). It bounds *live*
credentials, not total ever minted; a lifetime cap needs a small append-only
log on the verifier host (I). Live-only is the smallest; say so to the operator.

## Revocation

- **One token**: `papi forge token revoke --session grant/<id12>/<session>`, as
  today (`session.go:44-68`, R), card required. Add a grantee-signed
  `POST /auth/grant-revoke` for tokens under its own grant prefix: revoking
  only narrows authority, so letting the grantee do it is safe and lets a
  coordinator clean up while the operator is away (I).
- **Whole grant**: add its id to the verifier's deny file (stops new mints) and
  revoke every token with its prefix. Removing the operator line from the
  allowed-signers file kills every grant at once.
- **Sweep**: grant tokens carry deadlines in their names like any other papi
  token, so `sweep` reaps them (`session.go:70-104`, R). Sweep still needs the
  card or a password (`main.go:713-742`, R), and nothing schedules it (papi#91
  answer). A verifier-side sweep with its own asserted credential would make
  the TTL real while the operator is away; that is a natural part of the same
  build (I).

## The 168 h cap question

The 168 h cap is spinclass's, on its profile-grant transition TTL
(`spinclass internal/0/sweatfile/sweatfile.go:175-184`, R), not papi's. papi has
no cap today because it has no grants. Two options for a two-week trip:

1. **Two consecutive grants, one sitting** (recommended): sign week 1
   (`not-before` = departure) and week 2 (`not-before` = departure + 7 d) before
   leaving. Each grant stays under a 168 h cap, a leaked grant is live at most
   a week, and the second can be deny-listed without touching the first. Costs
   one more card signature at signing time, none during the trip.
2. Raise the cap for this record type to 336 h. Simpler, but doubles the
   exposure window of one leaked grant.

Recommend papi enforce `expires - not-before <= 168h` to match spinclass.

## What has to be built (I, estimates)

| Piece | Repo | Size |
|---|---|---|
| sshsig verify + allowed-signers loader (or shared module) | papi | 1 batch |
| grant/request canonical text, parse, verify, bounds; tests with a fake forge and fake keys | papi | 1-2 batches |
| `/auth/grant-mint`, `/auth/grant-revoke`, verifier config (signers path, deny file) | papi | 1 batch |
| `papi forge grant sign` (operator, card) and `papi forge grant mint` (grantee, its own key) CLI | papi | 1 batch |
| verifier deployment config, signers file on the forge host | circus | operator / circus |
| spinclass mint-command in spawn context uses `papi forge grant mint` with the coordinator's key | spinclass | spinclass#390 |

## Risks for the operator

- **The grantee key is the new secret at rest.** It sits on the coordinator's
  host as the operator uid, readable by anything running as that uid,
  including unconfined agents (spinclass FDR 0035 banner, per the spinclass
  note §4(a)). Its blast radius is the grant's bounds, not the account.
- **Repo write includes the default branch.** A `write:repository` token with
  resource rows can push any branch of its repos, default included (I from the
  scope model, `forgetoken.go:12-15`, R). Branch protection would stop it, but
  spinclass's `merge-this-session` pushes the default branch with the session
  token (spinclass note §2), so a protection that forbids push to the default
  branch also breaks merges. Protecting the default branch against
  **force-push and deletion** only keeps fast-forward merges working and
  stops history rewrites (I: confirm the exact Forgejo protection options on
  the live forge before relying on them).
- **An LLM coordinator chooses what to mint from text workers can influence.**
  Prompt injection in a worker's chat could steer which repo in the grant the
  coordinator spawns into, or burn `max-live`. Bounds that hold regardless:
  repo list, live count, TTL, expiry. Keep `repos` to what the trip needs and
  take repo choices from operator-written config, not worker messages.
- **Verifier compromise is account compromise**, as it already is: it holds
  the asserted-account power today. The grant endpoint adds code on that host,
  so it should be small and strictly parsed.
