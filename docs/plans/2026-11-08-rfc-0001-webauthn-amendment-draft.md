# Draft: RFC-0001 Amendment 28, the WebAuthn assertion scheme (amarbel-llc/circus#414)

Status: a DRAFT for the operator's review. It is not edited into
`docs/rfcs/0001-personal-api-papi-wire-format.md`, and nothing implements the
server side. It turns the list in
`docs/plans/2026-11-04-papi-enroll-webauthn.md` §6 into proposed normative
text, written against RFC-0001 as it stands (§3 registry, §4.1 discovery, §5
handshake, Amendment 27 the latest). Section numbers below are the ones the
amendment would take or touch.

What exists on the papi side today: the receipt-v2 `webauthn` block that
`papi enroll --webauthn` writes, its verifier in `papi verify-receipt`, and
`internal/0/webauthn` (`VerifyAssertion`, `VerifyBrowserAssertion`,
`CheckClientDataJSON`), a stdlib verifier that tests exercise with generated
keys. What does not exist: any server, the deploy splice, and the front-end
page. Those belong to circus `sites/linenisgreat/api` (plan §7).

## Decisions this draft rests on

All already ruled by the operator (plan §8): one credential per card serves
both tiers (D1–D3); the FIDO2 PIN equals the PIV PIN (Q1); a PIV
sign-challenge session counts as the PIN tier (Q2); signCount and the
attestation chain are not enforced (Q4, Q6); origin
`https://linenisgreat.com` only (Q9); the credential arrives by deploy, not by
a registration endpoint (§12.3 unchanged).

## Proposed text

### 1. `piggy.webauthn_credentials[]` (§1, new member of `piggy`)

An OPTIONAL array. An entry is the receipt-v2 `webauthn` block's public
members:

    { "visibility": "public", "label": "yubikey-fido2-<guid8>",
      "guid": "<PIV GUID>", "rp_id": "linenisgreat.com",
      "credential_id": "<base64url>", "public_key": "<base64url COSE_Key>",
      "alg": -7, "aaguid": "<hex>", "cred_protect": 2,
      "uv_policy": { "tier1": "discouraged", "tier2": "required" } }

`public_key` is the byte-exact COSE_Key from the registration's authenticator
data. `alg` MUST be -7 (ES256). Credential ids and public keys are public. The
projected endpoint is `GET /papi/webauthn-credentials`, subject to §2 and the
§4.2 envelope like the other projected sections.

### 2. Principal registry (§3)

The registry maps each `credential_id` to the principal of the card whose
`guid` it names, exactly as it maps a slot-9A key. The trust anchor for an
assertion is the registered COSE key, never a key the caller sends.

### 3. Discovery (§4.1)

When the document publishes at least one credential, discovery MAY carry

    "auth": { "webauthn": { "rp_id": "linenisgreat.com",
                            "tiers": ["touch", "pin"] } }

and `methods` in `auth` lists `"webauthn"` (§4.1 already allows several
methods). `tiers` names the assurance levels a session can reach.

### 4. §5.5 WebAuthn assertion (new)

Challenge, `POST /papi/auth/challenge`:

    { "method": "webauthn", "tier": "touch" | "pin" }

- A missing or unknown `method` or `tier` MUST yield `400`.
- With no published credential the server MUST yield `503`.
- Otherwise it mints a random challenge of at least 32 bytes, stores a
  one-time record (`challenge_id`, the tier, the expiry), and returns `200`:

      { "challenge_id": "<hex>", "challenge": "<base64url>",
        "rp_id": "linenisgreat.com",
        "allow_credentials": ["<credential_id>", …],
        "user_verification": "discouraged" | "required",
        "expires_at": <unix-seconds> }

  `user_verification` is `discouraged` for tier `touch` and `required` for
  tier `pin`. `allow_credentials` lists every published id: the caller does not
  say who it is, and the ids are public. A client MUST pass them as
  `allowCredentials`, because the credential is non-discoverable.

Response, `POST /papi/auth/response`:

    { "challenge_id": "<hex>", "credential_id": "<base64url>",
      "authenticator_data": "<base64url>", "client_data_json": "<base64url>",
      "signature": "<base64url, ASN.1 DER>" }

- A missing or non-string member MUST yield `400`.
- The server consumes the challenge one-time: unknown, consumed or expired
  MUST yield `401`.
- It MUST then verify, in WebAuthn L3 §7.2 order, and yield `401` on any
  failure:
  1. `credential_id` is registered (§3) and appears in `allow_credentials`;
  2. `client_data_json` has `type` `webauthn.get`, the issued `challenge`, an
     `origin` that exactly equals an allowed origin (`https://linenisgreat.com`
     only), and no `crossOrigin: true`;
  3. `authenticator_data` has `rpIdHash` equal to SHA-256 of `rp_id`, user
     presence set, and backup state not set without backup eligibility;
  4. for tier `pin`, user verification is set;
  5. the signature verifies over `authenticator_data ‖ SHA-256(client_data_json)`
     with the registered ES256 key.
- signCount is not checked (ruled, Q4).
- On success it mints the §5.3 session for the credential's principal with
  groups by what the assertion proved, not by what was asked:

  | proved | groups |
  |---|---|
  | user presence only | `authenticated`, `assurance-touch` |
  | presence and user verification | `authenticated`, `assurance-touch`, `assurance-pin` |

  A tier-`pin` request that proves only presence MUST yield `401`.

A PIV sign-challenge session (§5.2) MUST carry `assurance-pin` as well (Q2).
A page is gated by §2 projection: tier 1 `acl: ["assurance-touch"]`, tier 2
`acl: ["assurance-pin"]`.

### 5. Security Considerations (additions)

- Anyone holding the key passes the touch tier. The operator accepted this for
  low-sensitivity material only (Q5).
- One PIN guards both the PIV and FIDO2 applets (Q1): a leak of one is a leak
  of both.
- A PIV sign-challenge session passes the PIN tier (Q2).
- Credential ids and public keys are public; the assertion never reveals more.
- No clone detection: the site keeps no signCount state (Q4, flagged for the
  security audit).
- The FIDO attestation certificate is not verified (Q6, flagged); it proves a
  vendor and model, not that the credential sits on a card with that PIV GUID.
  That binding rests on the new card's slot-9A signature and the trusted
  card's attestation.
- Phishing resistance comes from the browser binding the origin into
  `client_data_json`, which the server checks exactly. A credential made by a
  CLI keeps that property for browser assertions, because an assertion
  carries its own client data (plan §4).
- A key that is lost is removed by a deploy from another trusted card, and a
  spare is enrolled (operator decision, 2026-11-04).

### 6. Amendment History entry (proposed)

> **Amendment 28 — WebAuthn assertion scheme.** Added the OPTIONAL
> `piggy.webauthn_credentials[]` member and `GET /papi/webauthn-credentials`
> (§1, §4), registry mapping from credential id to principal (§3), discovery
> `auth.webauthn` (§4.1), and the §5.5 challenge and response, minting sessions
> with `assurance-touch` and `assurance-pin` groups. A PIV sign-challenge
> session now carries `assurance-pin`.

## Open points for the operator

1. **Does `allow_credentials` leak anything we mind?** Every published id goes
   to anyone who asks for a challenge. They are public in the document
   anyway; if the operator would rather not hand out the list, the challenge
   could take a `card` hint, at the price of telling an anonymous caller
   whether a card exists.
2. **Session lifetime per tier.** The text above keeps the §5.2 defaults
   (challenge two minutes, session fifteen). A touch-only session might want to
   be shorter than a PIN session.
3. **Subdomain origins.** The draft allows exactly `https://linenisgreat.com`
   (Q9). WebAuthn lets an rp id of `linenisgreat.com` serve its subdomains
   too; I know that from memory and have not checked it.
4. **Where `assurance-pin` is minted for PIV sessions.** That is a change to
   §5.2's session, not to the new scheme; it should land with it.

Nothing here has been run on a device. The assertion checks mirror what
`internal/0/webauthn` already implements and tests with generated keys.
