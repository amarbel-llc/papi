# Trip token pool: operator runbook

For the operator, before the two-week trip. This page is how to pre-mint the
per-repo forge tokens that spinclass spawns will use while the card is away
(papi#80), and what not to do while you are gone. Labels: R = read in code,
V = observed by a run, I = inferred.

## 0. While away: nobody runs `papi forge token sweep`

`sweep` revokes **every** papi token whose name-encoded deadline has passed, and
it does not check whether the session is still alive
(`internal/0/forgetoken/session.go:21-23,77-94`, R). Today nothing schedules it
(papi#91), which is why sessions older than 12 h keep working. One manual
`sweep` during the trip would cut off every token past its TTL. Do not run it,
and do not add a timer for it, until you are back.

Revoke and sweep both need the card (they mint-authenticate, `main.go:580-742`,
R), so **nothing can clean up pool tokens while you are away**. They live until
their deadline passes **and** someone sweeps after you return.

## 1. Write the rows file

One `<repo> <session>` per line; `#` comments and blank lines are fine. `repo`
is `owner/name` or a bare name (papi resolves the owner); either way papi's writer
records the **resolved** `owner/name` in the manifest (`MintPool`,
`PoolEntry.Repo`, R). For a repo whose origin is on the vanity plane
(code.linenisgreat.com), both `linenisgreat/<name>` and `<name>` work. With
spinclass fae0c6d (on spinclass master; deployed with the next bump), an
owner-less session repo (the origin path, e.g. `spinclass` for
`ssh://git@code.linenisgreat.com/spinclass.git`) is matched against the
manifest's last path segment, and an owner-qualified session repo still matches
exactly. If two slots share a last segment under different owners, spinclass
refuses the match as ambiguous. `session` is a **slot
name you choose**. It must be unique in the file and must not already own a papi
token. Size the pool to the workers you expect, per repo, and list only the repos
the coordinator actually works in.

```
# trip pool 2026-11
linenisgreat/papi       pool/papi/01
linenisgreat/papi       pool/papi/02
linenisgreat/spinclass  pool/spinclass/01
linenisgreat/spinclass  pool/spinclass/02
```

The slot name is the token's session on the forge: `revoke --session
pool/papi/01` revokes exactly that one token, and `list --session pool/papi/01`
shows it. Spinclass records which slot a spawn took and revokes by that slot.

## 2. Dry run (no card, no network)

Run the real command **without any credential flag**. papi parses and checks the
rows file first, then stops at the missing credential before it opens any
connection or creates `--out`:

```
papi forge token mint --host forge.starbrandshoes.com --user sasha \
  --batch ./trip-rows --out "${XDG_STATE_HOME:-$HOME/.local/state}/spinclass/token-pool" --ttl 336h
```

- Good file → `papi: no credential: pass --card-login or --password-command
  (mint/revoke), or --token-command (read-only)` (V, 2026-10-26, with a sample
  rows file and `--host forge.example.invalid`).
- Bad file → names the line, e.g. `papi: batch line 2: session "pool/papi/01"
  already used on line 1` (V, same run).

The dry run does **not** check that the repos resolve or that the slots are
free on the forge. The real run checks both **before its first mint**: a
failure there mints nothing and leaves `--out` uncreated
(`internal/0/forgetoken/pool.go`, `MintPool`; tested with a fake forge, V).
There is no `--dry-run` flag; adding one is a possible follow-up.

## 3. Real run (one card signature)

Same command plus `--card-login`. `--ttl` must cover the trip: 336h is 14 days
from the moment of minting. Mint as close to departure as practical.

```
papi forge token mint --host forge.starbrandshoes.com --user sasha --card-login \
  --batch ./trip-rows --out "${XDG_STATE_HOME:-$HOME/.local/state}/spinclass/token-pool" --ttl 336h
```

- The card signs **once** for the whole file (tested with an injected signer,
  V; not yet run against the live forge with a real card).
- `--out` must not exist, but its **parent** must (papi uses `mkdir`, not
  `mkdir -p`; create `$XDG_STATE_HOME/spinclass` first if it is missing). papi
  creates `--out` mode 0700 itself and chmods it to 0700 regardless of umask
  (`MintPool`, R); it never accepts a pre-existing directory of any mode, so a
  wider-than-0700 pool directory cannot arise from papi. Writes one mode-0600
  `<escaped-session>.token` per token, plus `manifest.json`. stdout lists
  `id  session  repo  deadline  file` per token and **never** a secret.
- If a mint fails part-way, the tokens already minted are in `manifest.json`
  and the error names the slots that were not minted. Fix the cause, then mint
  the rest with a new rows file and a **new** `--out`.
- `--out` must be exactly the fixed path spinclass reads,
  `$XDG_STATE_HOME/spinclass/token-pool` (default `~/.local/state/spinclass/token-pool`),
  and that directory must be mode 0700 (spinclass side; confirmed by
  spinclass/light-cedar's review of `auth/pool.go`). Any other `--out` is
  invisible to spinclass.
- Each manifest row's `repo` is the resolved `owner/name` (see section 1 for how
  spinclass matches it against the session's origin).
- Sweatfile prerequisites (spinclass side; mentioned here, not changed by papi),
  in the sweatfile layer above the repos, **deployed before the mint**:
  - `[auth].forge-hosts` must contain the **git plane**,
    `code.linenisgreat.com`.
  - The pinned `[auth].revoke-command` must carry `--host <H>`, where `<H>` is
    exactly the host passed to `papi forge token mint --host` (here
    `forge.starbrandshoes.com`). The manifest's `forge` is papi's API host
    (`https://forge.starbrandshoes.com`); it is **not** in `forge-hosts`, and
    spinclass accepts it because it equals the `--host` of the pinned
    revoke-command. Do **not** add the API host to `forge-hosts`: that makes
    origins on that host mint tokens, and every https push then fails.
  - `allow-stale-base` must be set for the trip repos, or spawns will not use
    the pool.
- **Order matters:** with a pool present and the host unaccepted, every
  vanity-origin session creation errors. Deploy the sweatfile settings first,
  then mint.
- Verify after any real mint (read-only): list the manifest's repos and compare
  each with the repo's origin path.

  ```
  jq -r '.tokens[].repo' "${XDG_STATE_HOME:-$HOME/.local/state}/spinclass/token-pool/manifest.json"
  git remote get-url origin        # in each trip repo
  ```

  In the spinclass checkout, `just explore-pool-check <pooldir> '<dir1> <dir2>'`
  (read-only) prints PASS or NO MATCH per repo directory.
- Check after: `papi forge token list --host … --user sasha --token-command '…'
  | grep pool/` (read-only) should show each slot as `live` with the deadline.

## 4. Pool format (for the consumer)

`<dir>` (0700):

- `<escaped-session>.token`, 0600: the secret on one line followed by a newline,
  the same shape `mint` prints on stdout. The escape keeps `[A-Za-z0-9.]` as is
  and writes every other byte as `_XX` (uppercase hex), so `pool/spinclass/01` →
  `pool_2Fspinclass_2F01.token`.
- `manifest.json`, 0600, no secrets, rewritten atomically after each mint:

```json
{"version":1,"forge":"https://forge.starbrandshoes.com","user":"sasha",
 "tokens":[{"session":"pool/spinclass/01","repo":"linenisgreat/spinclass",
            "id":123,"deadline":"2026-11-23T10:00:00Z",
            "file":"pool_2Fspinclass_2F01.token"}]}
```

A missing `deadline` means the token has none and `sweep` never reaps it (`--ttl 0`).

Consumer contract: take a slot whose `repo` matches, record its `session`, and
pin that session in your revoke (not your own session id). An atomic rename of
the `.token` file out of the pool directory makes the claim exclusive (I,
spinclass decides).

## 5. Branch protection: decide before leaving

A `write:repository` token confined to a repo can push **any** branch of it,
default branch included (I, from Forgejo's scope model,
`internal/0/forgetoken/forgetoken.go:12-15`, R). Branch protection on the
default branch would stop that, but spinclass's `merge-this-session` pushes the
default branch with the session token. Protection that forbids pushing to
default would therefore break merges too.

The question for you: for the repos in the pool, enable a default-branch rule
that **blocks force-push and deletion** but still allows fast-forward pushes
(and the same for tags, if you care about tags)? That keeps merges working and
stops history rewrites by a leaked or misused token. Unverified (I): which exact
options the live Forgejo exposes, and whether they bind the owner account the
tokens act as. Check one repo's settings page before you rely on it.

## 6. Risks you are accepting

- The `.token` files can be read by anything running as your uid, unconfined
  agents included. Keep the pool directory where only the coordinator's
  frontend reads it.
- Revoking while away is impossible (it needs the card). A leaked token lives
  out its TTL.
- Read access is not confined: other **public** repos stay readable through any
  of these tokens (FDR 0016, R).
- The LLM coordinator picks which repo to spawn into. Worker text could steer it
  toward any repo in the pool or use the pool up. The repo list and pool size
  are the bounds, so keep both minimal.
- `--card-login`'s verifier cookie asserts your whole forge account for 12 h
  (`internal/bravo/authproxy/verifier.go:57-58`, R). papi keeps it in memory
  for the one run only.

Card-signed delegation grants (papi#88,
`docs/plans/2026-10-26-forge-delegation-grant.md`) would replace standing
tokens with bounded authority to mint. That is after the trip.
