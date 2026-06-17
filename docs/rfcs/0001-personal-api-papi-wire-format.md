---
status: proposed
date: 2026-06-16
---

# Personal API (PAPI) Wire Format and HTTP Interface

## Abstract

The Personal API (PAPI) is a well-known, self-describing document that a person
publishes from an HTTP API subdomain to answer four machine-readable questions
about themselves: how to encrypt to them, which keys may SSH as them, where
their code lives, and what they publish. This document specifies the PAPI wire
format — the source document schema, the per-node `visibility`/`acl` projection
model that separates public from privately-scoped data, the set of HTTP
endpoints and their response shapes, and the reflexive challenge/response
authentication handshake by which a caller proves control of a published
encryption recipient's private key to unlock private nodes. No pre-shared secret
is involved: the credential is the recipient's PIV key, and the published
recipients are themselves the authentication identities.

## Introduction

An HTTP API that serves content collections (`objects`, `code`, `yoga`, …) does
not answer "who is this person and how do I interact with them" in a form tools
can consume. PAPI fills that gap with one canonical document plus a small set of
projections, discoverable from a single well-known URI, that cleanly separate
freely-fetchable public information from information scoped to an authenticated
caller.

This RFC specifies the interface so that:

- a **server** can implement a conformant PAPI endpoint, and
- a **client** (a person's tool, another service, or `curl`) can fetch, parse,
  and — for private data — authenticate against it.

This repository (amarbel-llc/papi) is the canonical home of the PAPI wire-format
spec and of the introspection/validation tool that checks domains for
conformance against it; it is not the reference PHP implementation. The design
rationale, considered alternatives, and trade-offs are recorded in ADR-0004
(`docs/decisions/0004-personal-api-papi.md` in
[friedenberg/linenisgreat](https://github.com/friedenberg/linenisgreat)); this
RFC is the normative interface contract derived from it and from the reference
implementation in that repository's `api/protected/lib/`, served live at
<https://api.linenisgreat.com/.well-known/papi>. Scope is the `papi/v0` wire
format. The `localsend` ingestion block and a slot-9A HTTP-signature
authentication strategy are named but out of scope, deferred to `papi/v1`.

## Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in RFC 2119.

## Specification

### 1. Source Document

A PAPI server MUST be backed by a single source document, a JSON object, here
called the **document**. The reference implementation loads it from
`api/protected/data/papi.json`. If the document is absent or unparseable, the
server MUST behave as though the document were the empty object `{}` (a
fully-public, empty PAPI) rather than failing the request.

The document MAY contain these top-level members; all are OPTIONAL:

| Member            | Type   | Meaning                                                                   |
| ----------------- | ------ | ------------------------------------------------------------------------- |
| `version`         | string | Wire-format version. MUST default to `"papi/v0"` if absent or non-string. |
| `person`          | object | Subject handle, display name, domains, and `contact`.                     |
| `piggy`           | object | `encryption_recipients[]` and `ssh_authorized_keys[]`.                    |
| `forges[]`        | array  | Forge identities (see §1.1), each with `repos[]`.                         |
| `organizations[]` | array  | Organization accounts, each with `repos[]`.                               |
| `sitemap`         | object | A domain → entries map.                                                   |
| `localsend`       | object | Declared but disabled in `papi/v0`; `enabled` MUST be `false`.            |

`person.handle`, when present, MUST be a string; it is used as the subject label
in the `text/plain` projections. When absent the server MUST substitute the
literal `unknown`.

#### 1.1. Forge model

The forge model is vendor-agnostic. Each entry of `forges[]` and the `kind`
field of each `organizations[]` entry MUST use a `kind` drawn from:

    github | gitea | gitlab | codeberg | forgejo | bare

A forge entry SHOULD carry `id`, `kind`, `base_url`, `identity`,
`identity_type`, and `repos[]`. The server MAY include additional fields; clients
MUST ignore members they do not recognize.

### 2. Visibility and ACL Projection

Every node (any JSON object) in the document carries an OPTIONAL `visibility`
member and an OPTIONAL `acl` member that together gate the node. A server MUST
project the document through the requesting **principal** (§3) before serializing
any response, applying the following rules.

1. **Visibility values.** The `visibility` member, when present, MUST be the
   string `"public"` or `"private"`. A node with no `visibility` member MUST be
   treated as `"public"`.

2. **Public nodes.** A `"public"` node (or a node with no `visibility`) MUST be
   visible to every principal, including the anonymous principal.

3. **Private nodes.** A `"private"` node MUST be visible only to a principal that
   satisfies the node's ACL:
   - If the node has a non-empty `acl` (an array of strings), the principal MUST
     be granted iff at least one ACL subject matches the principal's id, one of
     the principal's groups, or the wildcard group `authenticated` (§3).
   - If the node has no `acl`, or an empty `acl`, the node MUST be visible to any
     **authenticated** principal and MUST NOT be visible to the anonymous
     principal.

4. **Gating is keyed on `visibility`.** Because privateness is determined by the
   `visibility` member, a document author who intends to gate a node MUST set
   `visibility: "private"` on it. An `acl` member alone, without
   `visibility: "private"`, does NOT gate the node and MUST NOT be relied upon to
   restrict access.

5. **Dropping.** A node not visible to the principal MUST be dropped from the
   response entirely (the key disappears for an object member; the element is
   omitted for a list element) rather than emitted as an empty husk.

6. **ACL stripping.** The `acl` member MUST NOT appear in any response. A server
   MUST strip every `acl` member from every node it serializes, on every path,
   so the gate is never leaked to the caller.

7. **Recursion.** Projection MUST be applied recursively to the entire document
   tree, so that a private subtree nested inside a visible parent is dropped, and
   an individual private element of an otherwise-visible list is dropped.

The reference implementation realizes these rules in
`PersonalApi::filterNode()`/`visibleTo()`.

### 3. Principal and Principal Registry

A **principal** is the identity a request is projected through. It is one of:

- the **anonymous** principal — id `anonymous`, no groups; or
- an **authenticated** principal — a non-empty string `id` and a list of group
  strings. Every authenticated principal MUST implicitly carry the group
  `authenticated`.

The anonymous principal MUST NOT match any ACL subject, including
`authenticated`.

A server MUST maintain a **principal registry** mapping a piggy **recipient id**
(§5) to a principal `{id, groups}`. The reference implementation loads it from
`api/protected/data/papi_principals.json` (overridable via the
`PAPI_PRINCIPALS_PATH` environment variable). Registry values are **public**
recipient ids and group names only; the registry MUST NOT contain secrets and is
safe to commit and ship with the document.

Provisioning a caller is a registry edit: add a `recipient-id → {id, groups}`
entry, then list that `id`, one of its `groups`, or `authenticated` in the `acl`
of each node the caller should see.

### 4. HTTP Endpoints

All paths are relative to the API base. A conformant server MUST register the
PAPI routes so that the literal `papi`/`papi/…`/`.well-known/papi` patterns take
precedence over any generic collection/item route that could otherwise capture
`papi/<segment>`.

| Method | Path                        | Response                                    | Auth-gated         |
| ------ | --------------------------- | ------------------------------------------- | ------------------ |
| GET    | `/.well-known/papi`         | discovery JSON (§4.1)                       | no (always public) |
| GET    | `/papi`                     | full projected document, JSON               | projected          |
| GET    | `/papi/forges`              | projected `forges[]`, JSON                  | projected          |
| GET    | `/papi/repos`               | flattened, provenance-annotated repos, JSON | projected          |
| GET    | `/papi/organizations`       | projected `organizations[]`, JSON           | projected          |
| GET    | `/papi/sitemap`             | projected `sitemap`, JSON                   | projected          |
| GET    | `/papi/piggy-ids`           | `text/plain` piggy-ids recipient template   | projected          |
| GET    | `/papi/ssh-authorized-keys` | `text/plain` authorized_keys body           | projected          |
| POST   | `/papi/auth/challenge`      | challenge JSON (§5)                         | no                 |
| POST   | `/papi/auth/response`       | session JSON (§5)                           | no                 |

"Projected" means the response MUST reflect the projection (§2) for the
principal resolved from the request (§5.3): the anonymous principal for an
unauthenticated request, the registered principal for an authenticated one.

#### 4.1. Discovery document

`GET /.well-known/papi` MUST return a JSON object with at least:

- `version` — the document version,
- `handle` — the subject handle,
- `resources` — an object whose values are **absolute** URLs to `/papi`,
  `/papi/piggy-ids`, `/papi/ssh-authorized-keys`, `/papi/forges`, `/papi/repos`,
  `/papi/organizations`, and `/papi/sitemap`, and
- `auth` — `{scheme: "piggy-challenge-response", challenge, response,
present_session_as}`, where `challenge`/`response` are absolute URLs.

The discovery document MUST always be public (it is not projected).

#### 4.2. Response envelope

JSON endpoints MUST wrap their payload in the envelope:

    { "data": <payload>, "meta": { "count": <int>, "type": "<string>", ... } }

`/papi` MUST add `meta.version` and `meta.visibility`. The four projected-list
endpoints MUST add `meta.visibility`. `meta.visibility` MUST be `"public"` for
the anonymous principal and `"scoped"` for an authenticated principal.

The two `text/plain` endpoints (`/papi/piggy-ids`, `/papi/ssh-authorized-keys`)
MUST NOT use the envelope; they return a raw body with `Content-Type:
text/plain`. Clients MUST NOT assume every PAPI response is the JSON envelope.

- `/papi/piggy-ids` MUST emit a piggy-ids recipient template: comment lines
  beginning with `#`, then one recipient `id` per line (each OPTIONALLY followed
  by `  # <label>`), for every **visible** encryption recipient.
- `/papi/ssh-authorized-keys` MUST emit one `authorized_keys` line per visible
  SSH key, suitable for appending to `~/.ssh/authorized_keys`.

Both text endpoints draw only from nodes visible to the principal under §2.

#### 4.3. CORS

A server SHOULD answer `OPTIONS` preflight with `Access-Control-Allow-Methods:
GET, POST, OPTIONS` and `Access-Control-Allow-Headers: Content-Type,
Authorization`, and pin `Access-Control-Allow-Origin` to a configured origin.

### 5. Authentication Handshake

Private nodes are unlocked by a reflexive challenge/response handshake. The
caller proves control of the PIV private key behind a **published** encryption
recipient; the server only ever **encrypts** (pure software, no card).

#### 5.1. Challenge

`POST /papi/auth/challenge` with a JSON body `{ "recipient": "<recipient-id>" }`.

- The `recipient` member MUST be a non-empty string. A missing or non-string
  `recipient` MUST yield HTTP `400`.
- If the server cannot perform encryption (no box backend available), it MUST
  yield HTTP `503`.
- If `recipient` is not present in the principal registry (§3), the server MUST
  yield HTTP `403` and MUST NOT reveal whether the recipient grammar was valid.
- Otherwise the server MUST mint a cryptographically random **nonce**, encrypt it
  **to that recipient** (producing a piggy ebox), store a one-time challenge
  record, and return HTTP `200` with:

      { "challenge_id": "<hex>", "ebox_b64": "<base64 ebox>", "expires_at": <unix-seconds> }

  The nonce MUST NOT leave the server in cleartext. `challenge_id` MUST be
  unpredictable. The recipient id MUST match the grammar
  `^piggy-recipient-v1@pivy_ecdh_p256_pub-[0-9a-z-]+$` before it is passed to the
  box backend.

#### 5.2. Response

The caller decrypts `ebox_b64` with their PIV card to recover the nonce, then
calls `POST /papi/auth/response` with
`{ "challenge_id": "<hex>", "nonce": "<recovered nonce>" }`.

- A missing or non-string `challenge_id` or `nonce` MUST yield HTTP `400`.
- The server MUST consume the challenge **one-time**: a `challenge_id` that is
  unknown, already consumed, or expired MUST yield HTTP `401`.
- The nonce comparison MUST be constant-time. A mismatch MUST yield HTTP `401`.
- On a match the server MUST mint a short-lived **session** bound to the
  challenge's principal and return HTTP `200` with:

      { "session": "<hex>", "principal": "<id>", "groups": [<string>...], "expires_at": <unix-seconds> }

- If the session cannot be persisted, the server SHOULD yield HTTP `502` rather
  than an unhandled `500`.

A server SHOULD use a challenge TTL on the order of two minutes and a session TTL
on the order of fifteen minutes (the reference defaults are 120 s and 900 s).

#### 5.3. Presenting a session

A subsequent request authenticates by presenting the session id in **either**:

- the header `Authorization: PiggySession <session-id>`, or
- the query parameter `?papi_session=<session-id>`.

The server MUST resolve a live session to its bound principal. A request with no
session, or an unknown/expired session, MUST resolve to the **anonymous**
principal (public-only projection) rather than an error. The session is an
ephemeral capability; the durable identity is the piggy recipient that was
proven to obtain it.

### 6. Examples

A private node and a public node in the document:

    {
      "person": {
        "visibility": "public",
        "handle": "linenisgreat",
        "contact": { "visibility": "private", "acl": ["authenticated"],
                     "email": "hello@example.com" }
      }
    }

`GET /papi` as the **anonymous** principal — `contact` dropped, no `acl` leaks:

    { "data": { "person": { "visibility": "public", "handle": "linenisgreat" } },
      "meta": { "count": 1, "type": "papi", "version": "papi/v0",
                "visibility": "public" } }

`GET /papi` as an **authenticated** principal — `contact` present, `acl` stripped:

    { "data": { "person": { "visibility": "public", "handle": "linenisgreat",
                            "contact": { "visibility": "private",
                                         "email": "hello@example.com" } } },
      "meta": { "count": 1, "type": "papi", "version": "papi/v0",
                "visibility": "scoped" } }

A registry entry granting a caller the `friends` group:

    { "principals": {
        "piggy-recipient-v1@pivy_ecdh_p256_pub-qqqsyqcyq5rq…": {
          "id": "friend", "groups": ["authenticated", "friends"] } } }

## Security Considerations

**Trust boundary on the document.** The document and the principal registry are
authored and committed by the subject; a caller never supplies them. The values
that gate access (`visibility`, `acl`) are therefore not attacker-controlled
input. The recipient ids and SSH keys in the document are **public** keys; the
registry holds only public recipient ids and group names. Neither file contains
secrets, and both are safe to ship alongside the rest of the served tree.

**Fail-open visibility (OPEN ISSUE).** §2 requires `visibility` to be exactly
`"public"` or `"private"`. The reference implementation treats _any_ value other
than the literal `"private"` as public (`visibility !== 'private'`), so a
malformed value (`"Private"`, an unknown string, a non-string) on a node the
author meant to gate silently exposes it. Because the document is
author-controlled this is a footgun, not a remotely exploitable hole, but a
conformant server SHOULD fail **closed**: treat any value that is not exactly
`"public"` (or absent) as gated, routing it through the ACL path. Document
authors MUST NOT rely on a non-canonical `visibility` value to gate a node.

**ACL stripping is load-bearing.** The `acl` member encodes the gate. A server
that fails to strip `acl` on any serialization path (object member, list element,
nested subtree, or the `text/plain` projections) leaks the access policy. §2(6)
makes stripping unconditional; implementations MUST test it on every path.

**Reflexive credential, no shared secret.** The credential is the PIV slot-9D
key behind a published recipient; the server never holds a card, a PIN, or an
agent, and only encrypts. A leaked **session** grants only what its principal
could see and expires quickly; it cannot be re-derived without the card.
Challenges MUST be one-time (replay-proof) and the nonce MUST never leave the
server in cleartext, so observing traffic does not yield a reusable credential.
The nonce comparison MUST be constant-time to avoid a timing oracle.

**Box availability and denial of the private tier.** When no box backend is
available (e.g. the host lacks the piggy toolchain), `/papi/auth/challenge`
returns `503` and only public data is reachable. This is a graceful degradation,
not a vulnerability, but operators MUST understand that the private tier is live
only where the box runs.

**Discovery and the `Host` header.** The discovery document's absolute URLs are
derived, in the reference implementation, from the request `Host` header. A
client that follows discovery links from a response it did not itself originate
could be steered to an attacker-chosen host (including the auth endpoints). A
server SHOULD derive the base URL from configuration or validate `Host` against
an allowlist rather than trusting it blindly.

**Authorization header transport.** The `Authorization: PiggySession` path
depends on the header reaching PHP as `HTTP_AUTHORIZATION`; some FastCGI/Apache
deployments strip it unless explicitly forwarded (e.g. `CGIPassAuth`). Operators
MUST verify forwarding, or rely on the `?papi_session=` fallback, lest every
authenticated caller silently degrade to anonymous.

**Session storage.** Sessions and one-time challenges are stored as atomic JSON
files (reference: under `api/tmp/papi-auth/`). The store MUST key lookups by the
opaque id (not a directory scan) and MUST treat an absent/expired record as no
session. A host without a reaping cron relies on lazy expiry at access time.

## Conformance Testing

Conformance tests for the reference implementation live in
[friedenberg/linenisgreat](https://github.com/friedenberg/linenisgreat) under
`api/private/` and run via `just` recipes (TAP-over-`curl`/PHP, that
repository's integration-test convention):

- `just test-papi-unit` (`api/private/test-papi.php`) — hermetic, in the `test`
  gate. Drives the projection (§2) and the full handshake (§5) through a mock box
  encryptor, against the committed data files. No network, secret, or card.
- `just test-papi` (`api/private/test-papi.sh` + `mock-piggy-ids.sh`) — the HTTP
  surface (§4–§5) end to end against a mock `piggy-ids` binary, including replay,
  `403`/`400`, and route-precedence guards.
- `just test-papi-challenge-fibby` (`api/private/test-papi-challenge-fibby.sh`) —
  the real card round-trip via a fibby virtual PIV card; SKIPs without the piggy
  toolchain (not in the gate).

### Covered Requirements

| Requirement                  | Test                            | Description                                                        |
| ---------------------------- | ------------------------------- | ------------------------------------------------------------------ |
| §2, projection + `acl` strip | `test-papi.php`                 | anonymous vs authenticated projection; `acl` never serialized      |
| §3, principal/ACL match      | `test-papi.php`                 | id match, group match, non-match denial, anonymous matches nothing |
| §5.1–5.2, handshake          | `test-papi.php`, `test-papi.sh` | challenge → decrypt → response → session; constant-time mismatch   |
| §5.2, one-time/expiry        | `test-papi.php`, `test-papi.sh` | replay rejected (`401`); expired challenge/session absent          |
| §5.1, error codes            | `test-papi.sh`                  | `503` no box, `403` unknown recipient, `400` malformed             |
| §5.3, session resolution     | `test-papi.php`                 | header and query-param presentation; unknown → anonymous           |
| §4, route precedence         | `test-papi.sh`                  | `papi/<segment>` not captured by the generic item route            |

A future re-implementation in another language SHOULD be able to satisfy the same
HTTP-level suite (`test-papi.sh`) unchanged, since it exercises only the wire
contract.

A language-agnostic introspection/validation tool — a conformance checker that
fetches a domain's PAPI endpoints and verifies them against this RFC — is the
purpose of amarbel-llc/papi and is tracked by
[friedenberg/linenisgreat#25](https://github.com/friedenberg/linenisgreat/issues/25);
this section is its normative anchor.

## Compatibility

This is the first articulation of the PAPI wire format; there are no prior
consumers to preserve. Versioning is carried by the document's `version` member
and echoed in `meta.version` on `GET /papi`.

- The current version string is `"papi/v0"`. A breaking change to the document
  schema or endpoint semantics MUST bump it to `"papi/v1"` (etc.); clients SHOULD
  branch on `version`.
- New OPTIONAL members MAY be added to any node without a version bump; clients
  MUST ignore unrecognized members (§1.1).
- The `localsend` block and a slot-9A HTTP-signature authentication strategy are
  reserved for `papi/v1`; in `papi/v0` `localsend.enabled` MUST be `false` and a
  server MUST NOT advertise a signature auth scheme in discovery.
- PAPI coexists with the host's other collections under the same `{data, meta}`
  envelope; this RFC does not alter those collections.

## References

Normative:

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC 8615] Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)",
  RFC 8615, May 2019.
- [ADR-0004] "Personal API (PAPI): a well-known person-description type on the
  API subdomain", `docs/decisions/0004-personal-api-papi.md` in
  friedenberg/linenisgreat.
  <https://github.com/friedenberg/linenisgreat/blob/master/docs/decisions/0004-personal-api-papi.md>

Informative:

- [reference-impl] PAPI reference implementation (PHP), in
  friedenberg/linenisgreat under `api/protected/lib/`; served live at
  <https://api.linenisgreat.com/.well-known/papi>.
- [papi-tool] PAPI introspection/validation tool (conformance checker), this
  repository (amarbel-llc/papi); tracked by friedenberg/linenisgreat#25.
  <https://github.com/friedenberg/linenisgreat/issues/25>
- [related] linenisgreat follow-ups: #26 (discovery `http://` self-links),
  #27 (server-side repo-list read-through).
  <https://github.com/friedenberg/linenisgreat/issues/26>,
  <https://github.com/friedenberg/linenisgreat/issues/27>
- [piggy] piggy — passwordstore.org fork with PIV smart-card encryption;
  `piggy-ids encrypt` (slot-9D ECDH recipient templates), `pivy-box stream
decrypt`, slot-9A SSH auth. <https://github.com/amarbel-llc/piggy>
- [LocalSend] LocalSend protocol. <https://github.com/localsend/protocol>
