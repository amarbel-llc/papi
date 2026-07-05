---
status: proposed
date: 2026-07-05
promotion-criteria: >
  proposed → experimental when `papi auth` is implemented (runs the §5 handshake and
  prints the minted session). experimental → testing when a reference consumer scripts
  it (a curl-with-session flow or a CI gate) instead of driving challenge/response by
  hand, and the output shape (json / --header / --raw) has held steady for two weeks.
  testing → accepted when it is the documented way to obtain a reusable PAPI session.
---

# One-shot authentication (`papi auth`)

## Problem Statement

Obtaining a §5 PAPI session today is one of two things, neither ergonomic. The
integrated `--auth-key-id` handshake baked into `papi repos` / `validate` / `query`
runs the full flow but mints and **consumes the session internally** — it is never
exposed, so a caller cannot reuse it. The low-level `papi sign-challenge` primitive
signs one challenge but leaves the caller to drive discovery, challenge, and response
by hand (curl the challenge, pipe it in, curl the response, extract the session).
There is no one-shot "authenticate to `<domain>` and hand me a session token" command
— the natural thing for scripting a `curl` against a §5-gated endpoint, a CI gate, or
debugging.

## Interface

`papi auth <domain> --auth-key-id <slot-9A id> [--signer … --guid … --pin …]` (or the
legacy `--recipient <id> --decrypt-cmd <cmd>`) runs the full §5 handshake — discovery
→ challenge → sign → response — and prints the **minted session**, then exits. It
performs one card operation and makes no further requests; the session is the caller's
to present (§5.3).

Output modes:

- **default (JSON)**: `{ "session": "<id>", "principal": "<id>", "groups": [...], "expires_at": <unix> }` — the §5.2 response payload, for a consumer that wants the metadata.
- **`--header`**: the ready-to-use `Authorization: PiggySession <id>` line, for piping into `curl -H`.
- **`--raw`**: the bare session id.

Unlike the integrated `--auth-key-id` flow, `papi auth` **exposes** the session as a
reusable capability instead of minting and discarding it inside one enumeration; and
unlike `sign-challenge`, it drives the whole handshake, not just the signature.

## Examples

    # obtain a session and reuse it against a §5-gated endpoint
    $ SESSION=$(papi auth linenisgreat.com --auth-key-id piggy-piv_auth-v1@… --raw)
    $ curl -H "Authorization: PiggySession $SESSION" https://api.linenisgreat.com/papi/repos

    # header form, straight into curl
    $ papi auth linenisgreat.com --auth-key-id … --header
    Authorization: PiggySession 1a2b3c…

    # full metadata (default)
    $ papi auth linenisgreat.com --auth-key-id …
    {"session":"1a2b3c…","principal":"amarbel-llc","groups":["authenticated"],"expires_at":1783000000}

## Limitations

- **A session is short-lived (§5.2, ~15 min default).** `papi auth` mints one and
  prints it; it does not refresh or stash it. A long-running consumer re-runs the
  command (one card op each) when the session expires.
- **One card operation per invocation.** Like every §5 handshake, obtaining a session
  signs with the slot-9A card (or decrypts with slot-9D); `papi auth` does not cache
  across invocations.
- **Not a session store.** It prints to stdout; wiring it into a keyring or agent is a
  consumer concern (a future direction, not this feature).

## More Information

- amarbel-llc/papi#51 — the tracking issue.
- RFC-0001 §5 (handshake), §5.2 (the response/session payload), §5.3 (presenting a
  session) — `papi auth` is the client driver of the full flow.
- Related surfaces: the integrated `--auth-key-id` tier on `repos`/`validate`/`query`/
  `forge check` (mints + consumes internally), `papi sign-challenge` (the signing
  primitive), and `papi sign-challenge-serve` (the browser oracle). `papi auth` is the
  CLI one-shot that exposes the session the others keep internal — sharing the same
  `inspect.Handshake` core.
