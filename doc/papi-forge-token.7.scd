papi-forge-token(7) "papi"

# NAME

papi-forge-token - fine-grained, per-repository forge access tokens as an ephemeral push credential

# DESCRIPTION

Fleet automation needs to push to a forge without a live card-backed ssh-agent: a forwarded agent drops mid-run and kills long unattended passes. The replacement is an HTTPS access token that is minted when a session starts, confined to the one repository that session works on, and revoked when the session ends.

*papi forge token* is the issuer for that lifecycle — mint, revoke, list, and the sweep that enforces a deadline the forge itself cannot. This page describes the model and the trust boundaries. For flags, see *papi-forge-token-mint*(1), *papi-forge-token-revoke*(1), *papi-forge-token-list*(1) and *papi-forge-token-sweep*(1).

# WHY THE API, NEVER THE ADMIN CLI

Forgejo exposes two unrelated ways to narrow a token, and only one of them is reachable from a command line on the forge host.

*Scopes* (_write:repository_, _read:repository_, ...) are *category-wide*. A token with _write:repository_ can write to *every* repository its owner can touch. Scopes alone confine nothing to one repo.

*Resources* are the separate axis Forgejo v15 added: _ResourceAllRepos=false_ plus one _access\_token\_resource_ row per repository. This is the real per-repo narrowing, and it is settable only from the web UI and the API.

_forgejo admin user generate-access-token_ — the obvious mint path, and the one the fleet used before — *hardcodes* _ResourceAllRepos=true_, with the source comment "maintain legacy behaviour ... not fine-grained". It can never produce a per-repo token. So papi mints through the *API*, and this is a correctness requirement rather than a preference.

# WHAT A MINTED TOKEN CAN DO

Write is confined to the repositories named at mint time. *Read is not.* With _ResourceAllRepos=false_:

- listed repositories: full access at the token's scopes;
- unlisted *public* repositories: read-only;
- unlisted *private* repositories: no access.

So "limited to the listed repository" is a statement about *write*. A leaked token still reads everything anonymous readers can, which for a public forge plane is no additional exposure — but it is not the same as total confinement, and it should not be described as such.

Enforcement covers git-over-HTTPS, not merely API calls: the forge's basic-auth path feeds the same fine-grained authorization reducer, so a _git push_ authenticated with the token is subject to the resource rows.

# THE CREDENTIAL PAPI ITSELF NEEDS

Minting a token requires a credential that can *create* tokens, and the forge is deliberately strict about which kinds qualify. Both _POST_ and _DELETE_ on the token routes are gated behind a check that accepts only:

- *password basic-auth* — a real account password, not a token; or
- a *trusted reverse proxy* asserting the account.

An access token is refused on those two routes *however broadly it is scoped* — a deliberate anti-escalation rule, so a leaked token cannot mint itself a fresh one or delete the evidence. Listing is not gated this way and works with a token.

The practical consequence is that *a sealed forge API token cannot drive this feature*, and neither can it revoke — the sweeper needs the same privileged credential as the mint. There are two ways to satisfy the forge.

*--card-login* (the presence-bound path) authenticates with the operator's YubiKey and stores no forge secret anywhere. papi drives the forward-auth verifier's login flow headlessly: _GET /auth/login_ answers with a redirect carrying a nonce and a signed state, papi signs the nonce with slot-9A, and _GET /auth/callback_ returns the verifier's session cookie. The reverse proxy then turns that cookie into an asserted account for the API. The flow exists for browsers — the redirect normally aims at a workstation oracle that holds the card — but a CLI already has the card, so it reads the nonce out of the redirect and signs directly; the oracle is never involved and the verifier needs no change.

Two byte-exact details decide whether this works: the signature is bound to the verifier's *own* external host, not necessarily the host being called (see *--auth-domain*), and papi sends *no* Authorization header on the API request, because the forge vhost deliberately routes header-authenticated requests away from the header-asserting location.

*--password-command* (the stored-secret path) supplies an account password by running a shell command, canonically a *piggy*(1) read, so the secret never appears in argv or in any process environment. It works with no proxy configuration, but a standing account password read unattended is a larger blast radius than a scoped token, and it is not presence-bound. An account with WebAuthn keys enrolled cannot use basic auth at all; an account with TOTP needs *--otp-command*.

*--token-command* reaches only *list*.

# WHICH HOST TO POINT AT

*--host* names the host serving the forge *API* — and, under *--card-login*, the papi verifier. That is not necessarily the host in your git remote, and on a split deployment it will not be.

A forge is commonly published on more than one plane: a public vanity plane that serves *git only*, often at owner-less paths, and a separate (frequently network-restricted) vhost carrying _/api/v1_ and the verifier's _/auth/_ routes. Pointing *--host* at the vanity plane fails with a 404 on _/auth/login_ or _/api/v1_, because those routes simply are not there.

This is safe to get right once and forget: a token minted against the API host authenticates for git against the vanity host, since both planes front the same forge. So a session manager keeps writing its credential for whatever host the remote names, and only the mint and revoke calls need the API host.

# DEADLINES WITHOUT FORGE SUPPORT

Forgejo tokens have *no native expiry*. "Ephemeral" is therefore not a property the forge maintains — it is a lifecycle the issuer owns: mint, revoke, and sweep whatever was never revoked because a session crashed.

papi keeps *no state of its own* for this. A token's deadline and the session it belongs to are encoded in the token's *name*, so any papi process on any host can list the account's tokens and reconstruct the whole picture. That is what lets *revoke* find a token minted by a different process hours earlier, and what lets *sweep* reap the tokens of a session that died without ever calling revoke.

The name is _papi-forge-token-<session>-<deadline>_, with the session reversibly escaped so that two different sessions can never produce the same name, and the deadline as a Unix timestamp (_0_ meaning none). Only names in this exact form are ever considered, so a token papi did not mint is invisible to *revoke* and untouchable by *sweep*.

That scoping is enforced by the *escape alphabet*, not by the prefix alone. The escaping encodes _-_ as ___2D_, so a papi-minted session part never contains a literal hyphen; a name shaped like _<something>-<epoch>-<pid>_ — the shape a great many ad-hoc minting scripts produce — is therefore excluded structurally. This is not hypothetical: an earlier version keyed on the bare prefix _papi-_ and a single *sweep* revoked over five thousand unrelated tokens whose trailing PID happened to parse as a long-past deadline.

When upstream token expiry lands (forgejo#8837), the same _--ttl_ becomes a real expiry field the forge enforces, and the sweep degrades to a belt-and-suspenders prune rather than the mechanism.

# IDEMPOTENCE

Revoking a session that has no tokens *succeeds*. This is a requirement, not a convenience: a session manager that retries a failed revoke — as spinclass's orphan sweep does, re-running the revoke command for every credential it never saw revoked — would otherwise retry forever the moment the token actually went away.

# THE SESSION-MANAGER LIFECYCLE

The reference consumer is spinclass's _[auth]_ section (its FDR 0028). At session creation it runs the mint command in the new worktree, captures the token from stdout, and writes it mode-600 as a git-credential-store file; a worktree-scoped _credential.helper_ plus a forge-host-scoped _url.<https>.insteadOf_ then carry it into every fetch and push of that session and of the throwaway worktree its merge lands from. At close it runs the revoke command; for sessions that never closed, it re-runs revoke from the next session's orphan sweep, and papi's own *sweep* is the backstop behind that.

Because mint prints the token and nothing else on stdout, *every diagnostic from mint goes to stderr* — a caller treats all of stdout as the secret.

# SEE ALSO

*papi*(1), *papi-forge-token-mint*(1), *papi-forge-token-revoke*(1), *papi-forge-token-list*(1), *papi-forge-token-sweep*(1), *papi-forge-check*(1), *piggy*(1)
