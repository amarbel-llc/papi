# RFC-0001 Amendment 29 (DRAFT): login grants (§5.2, §10.4)

Status: draft, not yet merged into RFC-0001. Numbering assumes Amendment 28
(WebAuthn, `2026-11-08-rfc-0001-webauthn-amendment-draft.md`) lands first.
Rationale and threat model: `2026-11-11-login-grant-expiring-key.md`.

## Text to add to §5.2 (new subsection 5.2.1, "Login grants")

A verifier MAY accept a **software-key login** under a **login grant**: a record
signed once by a registered slot-9A key that authorizes one software public key
to log in as one restricted principal for a bounded window. A verifier that does
not implement grants MUST treat a request carrying one as an ordinary failed
login.

**Grant text.** UTF-8, LF line endings, exactly these lines in this order, newline
after the last, at most 2048 bytes:

```
papi login-grant v1
principal: <token>
key: <ssh public key, authorized_keys form, type and base64 only, no comment>
domain: <host[:port] the verifier binds §5.2 signatures to>
not-before: <RFC 3339 UTC, Z suffix, whole seconds>
expires: <RFC 3339 UTC, Z suffix, whole seconds>
max-session: <integer seconds>
nonce: <base64url, no padding, 16 bytes>
```

`<token>` is `[a-z0-9][a-z0-9._-]{0,63}`. A verifier MUST reject text that is not
byte-identical to the canonical re-serialization of its parse (reordered or
missing or unknown lines, CRLF, trailing bytes, other alphabets).

**Grant id.** Lowercase hex of the first 16 bytes of SHA-256 of the grant text.

**Grant signature.** A slot-9A ECDSA P-256 signature (SHA-256) over
`"papi-login-grant-v1\n"` followed by the grant text, carried as a markl-id of
purpose `papi-login-grant-sig-v1` and format `ecdsa_p256_sig`
(registration in RFC-0002 is required before this leaves draft).

**Login signature.** The software key signs
`"papi-auth-soft-v1\n" + domain + "\n" + nonce + "\n" + grant-id`
(no trailing newline), where `domain` and `nonce` are those of §5.2. The prefix
differs from `papi-auth-v1`, so a signature valid for one preimage is never valid
for the other.

**Verification.** A verifier MUST accept a grant login only if ALL hold, and MUST
answer every failure identically to an unregistered key:

1. the grant text is canonical;
2. `domain` equals the verifier's binding domain;
3. the grant signature verifies under a registered slot-9A key;
4. `not-before <= now < expires` and `expires - not-before <= 168 h`;
5. the grant id is not deny-listed;
6. `principal` is one the verifier is configured to assume under grants, and is
   not the principal of any registered card;
7. the login signature verifies under `key`;
8. the session it issues expires no later than
   `min(now + max-session, expires)` and no later than the verifier's own limit.

A verifier SHOULD re-check deny-listing each time it honors a session issued under
a grant. A grant MUST NOT be accepted by the stateless verify-signature oracle
(FDR-0013).

**Non-goals.** A grant bounds login, not downstream authority: what the principal
may do is whatever the relying service grants that principal. A grant carries no
repository list and no token lifetime, because a login-only verifier cannot
enforce either.

## Amendment log entry (when merged)

- **DATE, Amendment 29 — Login grants (§5.2.1).** Added card-signed grants that
  let an expiring software key log in as a restricted principal (nikulin session
  forge tokens). Additive and OPTIONAL — no version bump. papi#NEW.
