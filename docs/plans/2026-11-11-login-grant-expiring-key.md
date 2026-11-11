# Login grant: an expiring, non-card key may log in as a restricted principal

Operator priority, 2026-11-11. Goal: sessions on a second host (nikulin) mint
their own session-scoped forge tokens (`papi forge token mint --card-login`
shape) with no card present at spawn, using a software key that is sealed at the
card once, valid until 2026-11-18T00:00:00Z, and unable to touch circus repos.

Labels: V = verified by reading code/docs at papi `lucid-hazel` (7bb175a);
T = theory, not checked. Companion: `2026-10-26-forge-delegation-grant.md`
(papi#88), `2026-10-26-papi-trip-pool-runbook.md` (the pool, dropped for this
purpose). RFC text: `2026-11-11-rfc-0001-login-grant-amendment-draft.md`.

## How long does it outlive the grant expiry? (operator question, 2026-11-11)

**Login authority ends exactly at `expires`; the tokens it minted do not.** (1)
Normal path, `--ttl 12h` default (V, `main.go:635`): a token minted one second
before expiry carries deadline = mint time + 12h, so about 2026-11-18T11:59:59Z.
But a deadline only marks the token for reaping: the forge has no token expiry
(V, `doc/papi-forge-token.7.scd:70`) and `sweep` runs only when someone runs it
with the card or a password; nothing schedules it (V, papi#88 note). So the
token stays usable past its deadline until a sweep or revoke. (2) Hostile holder:
papi caps nothing. `--ttl` is any duration; `ttl <= 0` yields deadline 0, which
the name encodes as "never swept" (V, `main.go:612,675`, `naming.go:32,100-105`).
The forge does not cap it either, so the maximum is unbounded until revoked.
(3) Without (a): a max-ttl in the grant checked by papi is client-side only, and a
hostile holder uses their own client or curl, so it is advisory. The verifier
never sees the mint (V: it serves only `/auth/*`; the mint goes nginx -> forge).
An nginx rule that rejects a token-create whose `name` deadline exceeds the grant
expiry would need body inspection (njs/lua, T) and is a verifier-in-the-mint-path
component in all but name; it also trusts the name, which the holder chooses. The
cap that does hold without (a) is the **account**: at expiry, disable the
restricted account and revoke every token it owns (`list --all`, revoke by id;
I will add a `revoke --all-for-user` to make this one card-gated command). All
tokens of that account are nikulin's by construction, so nothing legitimate is
lost. Whether Forgejo stops honoring tokens of a disabled account is T and must
be tested by circus before 11-18. (4) Time handling: the grant carries RFC 3339
UTC with a literal `Z`, whole seconds, anything else rejected; comparisons are on
Unix seconds, `expires` exclusive; the cookie already uses Unix `exp`
(V, `token.go:71-75`). No timezone or rounding exposure; the unbounded part is
token lifetime, which is a gap, not a rounding error.

## Constraint that shapes everything

V: the verifier cookie is `{principal, groups, exp}` and the reverse proxy turns
it into an asserted forge ACCOUNT (`authproxy/token.go:69-75`,
`verifier.go:108-122`); the forge accepts mint and revoke only from password
basic-auth or that asserted account (`doc/papi-forge-token.7.scd:37-48`).
So whatever logs in has the whole authority of the account the principal maps to,
and the verifier is not in the mint path. **A repo allowlist or a token-TTL cap
cannot be enforced by anything that only controls login.** Two ways out:

| | (a) grant-mint endpoint (papi#88) | (b) login grant to a restricted principal |
|---|---|---|
| Login | unchanged | new: software-key login against a card-signed grant |
| Repo allowlist | enforced by verifier (it mints) | enforced by the forge: the principal maps to a SEPARATE forge account that is a collaborator only on non-circus repos |
| Token TTL cap | enforced by verifier | NOT enforced; bounded by cookie life, grant expiry, and the account being disabled/stripped at expiry |
| New code | sshsig, grant+request parse, `/auth/grant-mint`, live-count, verifier needs a forge-asserting credential | grant parse, ed25519 verify, one extra check in callback and verify |
| Deploy surface (circus) | verifier gets a forge credential path; larger | one forge account + nginx header mapping + config of allowed grant principals |
| Size | 4-5 batches | 1-2 batches |

Recommendation: **(b)**, the narrowest mechanism that meets "expiring,
non-card, circus excluded" by 2026-11-18, and keep (a) as the follow-up if the
operator later wants verifier-enforced repo lists or TTL caps. Cost of (b): the
operator (or circus) creates one forge account and gives it collaborator rights
by hand; the repo list lives in forge permissions, not in the grant.

## Mechanism (b)

1. **Grant**: a short canonical text naming the software public key, the
   restricted principal it logs in as, the verifier's binding domain, a validity
   window and a per-login session cap. Signed once at the card (slot-9A, ECDSA
   P-256) over a domain-separated preimage. Self-contained: no file to deploy
   per grant.
2. **Login**: the existing `/auth/login` -> sign -> `/auth/callback` flow. The
   client signs a distinct preimage with the software key and sends the grant,
   its card signature and the key signature. No new endpoint.
3. **Verifier** (`handleCallback` only; NOT `/auth/verify-signature`, so the
   FDR-0013 consumers are untouched) checks, in order, and answers the same
   generic 401 for every failure:
   1. grant parses strictly (fixed field order, allowlisted alphabet, <= 2048 B);
   2. `domain` equals the verifier's binding domain;
   3. the card signature verifies under some registered slot-9A key;
   4. `not-before <= now < expires`; `expires - not-before <= 168h`;
   5. grant id is not in the deny file;
   6. `principal` is in the verifier's `AllowGrantPrincipals` AND is not the
      principal of any registered card (a grant can never log in as the operator);
   7. the key signature verifies under the grant's key over the login preimage
      bound to the grant id (below);
   8. the cookie gets `exp = min(now + SessionTTL, now + max-session, expires)`
      and carries the grant id.
4. **`/auth/verify`** additionally refuses a cookie whose grant id is on the deny
   file, so deny-listing kills live cookies, not only new logins.

### Preimages (all LF-separated, no trailing newline)

- Grant card signature: `papi-login-grant-v1\n<canonical grant text>`.
- Software login signature:
  `papi-auth-soft-v1\n<domain>\n<nonce>\n<grant id>`. Distinct prefix from
  `papi-auth-v1`, and a different key type, so a card login signature and a
  software one can never validate as each other.
- Grant id: lowercase hex of the first 16 bytes of SHA-256 of the canonical text.

### Software key

ed25519, authorized_keys form. The CLI signs through an ssh-agent (so the key
can be sealed with piggy and loaded into an agent that nikulin reaches) or from a
key file. The grant names the PUBLIC key only.

## What a stolen key can do (T unless marked)

- Log in as the restricted principal until `expires`, from anywhere, as often as
  it likes; each cookie lasts at most `max-session`. Nothing else: no card
  operation, no registry change, no other principal (step 3.6, V by design).
- Mint tokens for exactly the repos the restricted forge account can reach, and
  revoke/list tokens under that account. Circus is excluded only if the account
  is not a collaborator there; this is a forge-side fact the operator must check.
- Not bounded by the grant: the deadline a token is minted with (client-chosen,
  V: `--ttl` is recorded in the token name, `doc/papi-forge-token.7.scd:68-80`).
  A token minted on 11-17 with a long `--ttl` outlives the grant. Mitigations:
  strip or disable the account on 11-18 (kills them all at once, T on Forgejo
  behaviour), run `sweep`, or move to (a).
- Replay: the nonce/state is stateless with a 5 min TTL (V, existing); a captured
  login request replays inside that window. Unchanged by this work.

## Revocation

- Before expiry, one grant: add its id to the verifier's deny file (hot reload,
  same pattern as the registry, V `registry.go:120-146`); live cookies die at the
  next `/auth/verify`.
- Everything: remove the principal from `AllowGrantPrincipals`, or disable the
  forge account.
- Tokens already minted: `papi forge token revoke --session ...` /
  `sweep`, card or password required (V, unchanged).

## What stays card-only

Registering any card key, creating any grant, logging in as any card principal,
the operator forge account. A grant never widens `AllowGrantPrincipals`; that is
verifier config, set by circus.

## Verifier complexity

New: strict grant parser (~100 lines), one card-signature check (existing
`signchallenge`-style ECDSA verify with the new preimage), ed25519 verify,
deny-file loader (copy of the registry hot-reload), one cookie claim. No new
endpoint, no state beyond the deny file, no forge credential on the verifier.

## Test vectors and cases

Implemented as in-code golden constants, not files: `internal/alfa/logingrant/vector_test.go`
pins the canonical text, grant id and ed25519 login signature for a fixed public test
seed (ed25519 is deterministic). ECDSA card signatures are randomized, so they are
checked by verification, not pinned. The cases below are tests in
`internal/bravo/authproxy/grant_test.go` and `denylist_test.go`.

Review additions (2026-11-11, independent review): `/auth/verify` emits
`Remote-Grant: <grant id>` for grant sessions and omits it for card sessions, so the
proxy can map the two to different accounts; the card-principal collision check is
case-insensitive; a grant must be signed by a card the verifier would let log in
(`AllowPrincipals` applies to signers); bad deny-file reloads are logged and an
emptying reload is refused; input files are opened without following symlinks and
size-capped. **The verifier does not choose the forge account.** "A grant can never
act as the operator" holds only if the proxy honors `Remote-Grant`; the required
mapping is in `man 7 papi-forge-token`.

| # | Case | Expected |
|---|---|---|
| 1 | valid grant, valid key sig, inside window | 302 + cookie, `exp = min(...)`, principal = grant principal |
| 2 | `now == expires` | 401 |
| 3 | `now < not-before` | 401 |
| 4 | `expires - not-before = 168h + 1s` | 401 |
| 5 | card signature by an unregistered ECDSA key | 401 |
| 6 | grant text altered by one byte after signing | 401 |
| 7 | `domain` differs from verifier domain | 401 |
| 8 | principal not in `AllowGrantPrincipals` | 401 |
| 9 | principal equals a registered card principal | 401 |
| 10 | key signature by a different ed25519 key | 401 |
| 11 | key signature over a card-login preimage (`papi-auth-v1`) | 401 |
| 12 | key signature with a different grant id in the preimage | 401 |
| 13 | grant id on deny file | 401; and a previously issued cookie fails `/auth/verify` after the deny file changes |
| 14 | `max-session` > verifier `SessionTTL` | cookie capped at `SessionTTL` |
| 15 | non-canonical grant (reordered fields, CRLF, trailing junk, unknown field, > 2048 B) | 401 |
| 16 | grant sent to `/auth/verify-signature` | not accepted (old behaviour) |
| 17 | existing card login | byte-identical to today |

Client tests: `CardLogin` with a software signer drives both legs; a signer error
and a 401 produce distinct, actionable messages that do not say the card key is
unregistered.

## Build order (after the operator's go)

1. `internal/alfa/logingrant`: canonical text parse/format, id, preimages, with
   vector tests first.
2. `authproxy`: registry accessor for card keys, deny list, callback branch,
   verify-time deny check, cookie claim; httptest tests for cases 1-17.
3. `forgetoken`/CLI: `--login-grant FILE`, `--login-key-agent PUBKEY|--login-key-file`,
   software `NonceSigner`; `papi forge grant sign` (card; emits the grant file).
4. Man pages and the RFC amendment moved from draft to RFC-0001.
5. Hand-off to circus (not my repo): the restricted forge account, nginx
   mapping of the verifier's `Remote-User` to it, `AllowGrantPrincipals` and the
   deny-file path in the deployed verifier config, then deploy.

## Costs of (b), stated plainly

- A second forge account must exist, and someone (operator or circus) must add it
  as collaborator on each non-circus repo by hand; a new repo is invisible to
  nikulin sessions until that is done.
- Pushes and PRs from nikulin sessions are attributed to that account, not the
  operator.
- Revoking a minted token by session name still needs the card (or the account
  password); the grant does not change that. Disabling the account is the
  card-free kill switch.
- Defense in depth is the point: the repo limit lives in forge permissions, so a
  verifier bug in grant parsing cannot widen it beyond that account's reach.
- Ship order: (b) first; (a) later without redoing (b), since the grant record
  is reusable as the (a) grant by adding `repos`/`max-ttl` fields.

## Circus hand-off list (precise; the coordinator routes it)

Nothing below is built or verified by me; each item is T until circus confirms.

1. Forge account (name chosen by operator, e.g. the grant's `principal`), with
   collaborator write on the agreed non-circus repos and NO access to circus
   repos; no admin; password unset or unusable (login is by proxy assertion only).
2. Reverse-proxy mapping so the verifier's `Remote-User` equal to that principal
   is asserted to that forge account for the API vhost, the same path the
   operator's principal takes today.
3. Verifier config: `AllowGrantPrincipals = {<principal>}`; deny-file path; the
   binding domain already configured (`ExternalURL` host). I will name the exact
   config keys/flags when implemented.
4. The registry already published stays as is; grants need no registry change
   (the grant is signed by an existing slot-9A key). No PHP server change.
5. Deploy of the new papi verifier build (after my merge and lock bump, which
   are the coordinator's/operator's call).
6. At 2026-11-18T00:00Z: disable the account (or strip collaborators), then
   `sweep`.

## Division with circus/noble-mahogany (SSH half)

Grant key and SSH spawn key: bind them rather than reuse them. Proposal sent to
that session: it owns the nikulin forced-command SSH key and its `authorized_keys`
expiry; I own the login grant file. The grant's `key` line is the public half of
a keypair that session generates (or a distinct one), and the grant's
`not-before`/`expires` are set to the same window (11-18T00:00Z) so the two die
together. Which file lives where is settled in chat; nothing is merged for it
without the operator's ruling.

## Open questions for the operator

1. Is a second forge account acceptable, and who creates it and its collaborator
   rights (T: circus/operator)? Without it, (b) gives expiry but not the circus
   exclusion, and the answer must switch to (a).
2. Same ed25519 key as circus/noble-mahogany's nikulin spawn key, or a separate
   one bound to it? Prefer separate: a leaked SSH key should not also be a login.
3. Accept that token deadlines are client-chosen under (b)?
