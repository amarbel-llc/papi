---
status: proposed
date: 2026-06-16
amended: 2026-06-23
amendments: 15
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
recipients are themselves the authentication identities. Two OPTIONAL primitives
anchor the document to a key rather than to a domain: a `proofs[]` member that
carries Keyoxide-style bidirectional ownership proofs for the identities a
document asserts, and a detached document **signature** that lets a client verify
authorship of a fetched document offline, independent of the host that served it.
A further OPTIONAL `caches[]` member advertises the nix binary caches a caller may
substitute from to bootstrap, gated like every other node so a subject's private
infrastructure stays scoped to authenticated callers. An OPTIONAL `profiles[]`
member similarly advertises the host profiles (flake references) a staged
installer activates, scoped the same way.

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
format. The `localsend` ingestion block is named but out of scope, deferred to
`papi/v1` (a slot-9A signature authentication strategy, once deferred to `papi/v1`,
is now the RECOMMENDED `papi/v0` §5 sign-challenge scheme — see §5, Amendment 14).

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
| `templates[]`     | array  | Advertised nix flake templates for repo bootstrap (see §7).               |
| `proofs[]`        | array  | Bidirectional identity-ownership proofs (see §9).                          |
| `signatures[]`    | array  | Detached signatures binding the document to published keys (see §10).      |
| `caches[]`        | array  | Advertised nix binary caches for substituter bootstrap (see §11).          |
| `profiles[]`      | array  | Advertised host profiles (flakerefs) a staged installer activates (see §13). |
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

A server MUST maintain a **principal registry** mapping a published piggy key id
(§5) to a principal `{id, groups}` — a **slot-9A auth-key id**
(`piggy-piv_auth-v1@…`, for sign-challenge) and/or a **slot-9D recipient id**
(`piggy-recipient-v1@…`, for decrypt-challenge). The sign-challenge verifier takes
the public key from the registered id (the trust anchor), never from the caller.
The reference implementation loads it from
`api/protected/data/papi_principals.json` (overridable via the
`PAPI_PRINCIPALS_PATH` environment variable). Registry values are **public**
recipient ids and group names only; the registry MUST NOT contain secrets and is
safe to commit and ship with the document.

Provisioning a caller is a registry edit: add a `key-id → {id, groups}` entry
(a slot-9A auth-key or slot-9D recipient), then list that `id`, one of its `groups`, or `authenticated` in the `acl`
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
| GET    | `/papi/templates`           | projected `templates[]`, JSON               | projected          |
| GET    | `/papi/proofs`              | projected `proofs[]`, JSON                  | projected          |
| GET    | `/papi/caches`              | projected `caches[]`, JSON                  | projected          |
| GET    | `/papi/profiles`            | projected `profiles[]`, JSON                | projected          |
| GET    | `/papi/piggy-ids`           | `text/plain` piggy-ids file (recipients + auth ids) | projected          |
| GET    | `/papi/ssh-authorized-keys` | `text/plain` authorized_keys body           | projected          |
| GET    | `/papi/bootstrap`           | `text/plain` self-bootstrap shim (OPTIONAL) | no                 |
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
  `/papi/organizations`, `/papi/sitemap`, (when the document advertises
  templates, §7) `/papi/templates`, (when the document advertises proofs,
  §9) `/papi/proofs`, (when the document advertises caches, §11)
  `/papi/caches`, (when the document advertises host profiles, §13)
  `/papi/profiles`, (when the document serves a self-bootstrap shim, §4.2)
  `/papi/bootstrap`, and
- `auth` — `{scheme, challenge, response, present_session_as}`, where
`challenge`/`response` are absolute URLs and `scheme` is the §5 scheme the server
offers: `"piggy-sign-challenge"` (the RECOMMENDED slot-9A signature scheme) or
`"piggy-challenge-response"` (the OPTIONAL slot-9D decrypt scheme). A server MAY
list a `methods` array to advertise more than one (including the §5.4 cardless
`ssh-cert` variant); the same `challenge`/`response` URLs serve all of them.

When the document carries `signatures[]` (§10), the discovery document MUST
additionally expose a `signatures` member equal to the document's `signatures`
array, so a client can verify document authorship (§10.3) from the always-public
discovery response without first fetching `/papi`.

The discovery document MUST always be public (it is not projected).

#### 4.2. Response envelope

JSON endpoints MUST wrap their payload in the envelope:

    { "data": <payload>, "meta": { "count": <int>, "type": "<string>", ... } }

`/papi` MUST add `meta.version` and `meta.visibility`. The eight projected-list
endpoints (`/papi/forges`, `/papi/repos`, `/papi/organizations`, `/papi/sitemap`,
`/papi/templates`, `/papi/proofs`, `/papi/caches`, `/papi/profiles`) MUST add
`meta.visibility`.
`meta.visibility` MUST be
`"public"` for the anonymous principal and `"scoped"` for an authenticated
principal.

The `text/plain` endpoints (`/papi/piggy-ids`, `/papi/ssh-authorized-keys`, and
the OPTIONAL `/papi/bootstrap`) MUST NOT use the envelope; they return a raw body
with `Content-Type: text/plain`. Clients MUST NOT assume every PAPI response is
the JSON envelope.

- `/papi/piggy-ids` MUST emit a piggy-ids file: comment lines beginning with `#`,
  then one piggy `id` per line (each OPTIONALLY followed by `  # <label>`) — the
  **visible** encryption recipients (`piggy-recipient-v1@…`, PIV slot 9D) followed
  by the **visible** SSH auth ids (`piggy-piv_auth-v1@…`, PIV slot 9A; for any SSH
  key that records an `id`). It is a complete piggy-ids listing, not only
  encryption recipients.
- `/papi/ssh-authorized-keys` MUST emit one `authorized_keys` line per visible
  SSH key, suitable for appending to `~/.ssh/authorized_keys`.
- `/papi/bootstrap` (OPTIONAL) MAY serve a **self-bootstrap shim**: a POSIX-sh
  script a cold, YubiKey-provisioned host runs to provision itself — e.g. clone a
  provisioner repo over HTTPS, then `exec` it — for the entrypoint `curl -fsSL
  https://<domain>/papi/bootstrap | sh`. When present it is served **public and
  unprojected**: a cold host has no card-auth stack yet, and gating the shim
  behind §5 would be circular (the shim is what bootstraps the ability to
  authenticate). The shim's contents SHOULD be owned and version-controlled out
  of band (so the `curl | sh` surface stays reviewed) and hosted verbatim; any
  sensitive data the shim later needs stays §5-gated downstream (§6, §12).

The two projected text endpoints (`/papi/piggy-ids`, `/papi/ssh-authorized-keys`)
draw only from nodes visible to the principal under §2; `/papi/bootstrap` is
public and the same for every requester.

#### 4.3. CORS

A server SHOULD answer `OPTIONS` preflight with `Access-Control-Allow-Methods:
GET, POST, OPTIONS` and `Access-Control-Allow-Headers: Content-Type,
Authorization`, and pin `Access-Control-Allow-Origin` to a configured origin.

### 5. Authentication Handshake

Private nodes are unlocked by a reflexive challenge/response handshake. A server
advertises which **scheme** it offers in discovery (§4.1):

- the **sign-challenge** scheme (RECOMMENDED; `auth.scheme:
  "piggy-sign-challenge"`) — the caller signs a server-issued nonce with the
  published **slot-9A** auth key, proving control of it. The server performs **no
  cryptography of its own** (it verifies a signature) and so needs no box backend;
- the **decrypt-challenge** scheme (OPTIONAL; `auth.scheme:
  "piggy-challenge-response"`) — the server encrypts a nonce to a published
  **slot-9D** recipient (a piggy ebox) and the caller decrypts it, proving control
  of the recipient key. This requires the server to produce the ebox (a box
  backend).

A **cardless variant** of sign-challenge (§5.4) lets a host that holds no card sign
with a provisioned certificate chaining to the published slot-9A. §5.1–5.2 specify
the challenge and response for both schemes; all paths mint the same session
(§5.3). A server implements at least one scheme and advertises it.

#### 5.1. Challenge

`POST /papi/auth/challenge`. The request body selects the scheme.

**Sign-challenge** (RECOMMENDED): `{ "auth_key_id": "<slot-9A auth-key id>" }`,
where `auth_key_id` is a published slot-9A id of the form
`piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-<blech32>`.

- A missing or non-string `auth_key_id` MUST yield HTTP `400`.
- If `auth_key_id` is not in the principal registry (§3), the server MUST yield
  HTTP `403`.
- If the server cannot verify signatures (verifier unavailable), it MUST yield
  HTTP `503`.
- Otherwise the server MUST mint a cryptographically random **nonce** — a
  plaintext 64-hex string — store a one-time challenge record, and return HTTP
  `200` with `{ "challenge_id": "<hex>", "nonce": "<64-hex>", "expires_at":
  <unix-seconds> }`. `challenge_id` MUST be unpredictable. No encryption is
  performed and no box backend is required.

**Decrypt-challenge** (OPTIONAL): `{ "recipient": "<recipient-id>" }`.

- A missing or non-string `recipient` MUST yield HTTP `400`.
- If the server cannot perform encryption (no box backend), it MUST yield HTTP
  `503`.
- If `recipient` is not in the principal registry (§3), the server MUST yield HTTP
  `403` and MUST NOT reveal whether the recipient grammar was valid.
- Otherwise the server MUST mint a random nonce, encrypt it **to that recipient**
  (a piggy ebox), store a one-time challenge record, and return HTTP `200` with
  `{ "challenge_id": "<hex>", "ebox_b64": "<base64 ebox>", "expires_at":
  <unix-seconds> }`. The nonce MUST NOT leave the server in cleartext. The
  recipient id MUST match `^piggy-recipient-v1@pivy_ecdh_p256_pub-[0-9a-z-]+$`
  before it is passed to the box backend.

#### 5.2. Response

**Sign-challenge.** The caller forms the domain-separated preimage

      papi-auth-v1\n<identity-domain>\n<nonce>

— where `<identity-domain>` is the PAPI identity domain, binding the signature to
this site and defending against cross-site relay — signs `SHA-256(preimage)` with
the slot-9A key (ECDSA P-256), and encodes the signature as a markl id
`papi-auth-sig-v1@ecdsa_p256_sig-<blech32>` (raw 64-byte `r‖s`, the §9.3/§10
signature format). It then calls `POST /papi/auth/response` with
`{ "challenge_id": "<hex>", "signature": "<papi-auth-sig-v1 markl id>" }`.

- A missing or non-string `challenge_id` or `signature` MUST yield HTTP `400`.
- The server MUST verify the signature: it decodes the registered `auth_key_id`'s
  markl to a 33-byte SEC1 compressed point → P-256 public key (the trust anchor,
  taken from the **registry** (§3), never the caller's word), decodes the
  `signature` markl to the 64-byte `r‖s`, and ECDSA-verifies it over
  `SHA-256(preimage)`. A failure MUST yield HTTP `401`.

**Decrypt-challenge.** The caller decrypts `ebox_b64` with their slot-9D PIV key
to recover the nonce, then calls `POST /papi/auth/response` with
`{ "challenge_id": "<hex>", "nonce": "<recovered nonce>" }`.

- A missing or non-string `challenge_id` or `nonce` MUST yield HTTP `400`.
- The nonce comparison MUST be constant-time; a mismatch MUST yield HTTP `401`.

For either scheme the server MUST consume the challenge **one-time**: a
`challenge_id` that is unknown, already consumed, or expired MUST yield HTTP `401`.
On success the server MUST mint a short-lived **session** bound to the challenge's
principal and return HTTP `200` with:

      { "session": "<hex>", "principal": "<id>", "groups": [<string>...], "expires_at": <unix-seconds> }

If the session cannot be persisted, the server SHOULD yield HTTP `502` rather than
an unhandled `500`. A server SHOULD use a challenge TTL on the order of two minutes
and a session TTL on the order of fifteen minutes (reference defaults 120 s and
900 s).

#### 5.3. Presenting a session

A subsequent request authenticates by presenting the session id in **either**:

- the header `Authorization: PiggySession <session-id>` (RECOMMENDED), or
- the query parameter `?papi_session=<session-id>` (NOT RECOMMENDED — query
  strings leak into access logs, `Referer` headers, and proxy caches; use it only
  where the header cannot be delivered, e.g. a deployment that strips
  `Authorization`).

The server MUST resolve a live session to its bound principal. A request with no
session, or an unknown/expired session, MUST resolve to the **anonymous**
principal (public-only projection) rather than an error. The session is an
ephemeral capability; the durable identity is the published key — the slot-9A
auth key (sign-challenge) or slot-9D recipient (decrypt-challenge) — proven to
obtain it.

#### 5.4. Certificate-signature proof (cardless)

A caller that holds a **provisioned SSH certificate** instead of a live PIV card
MAY authenticate by signature — a **cardless variant of the §5.2 sign-challenge** —
serving cloud, headless, and CI hosts where no card is present (locally or
forwarded). The certificate is issued out of band on a machine with the physical
card, which signs it as an SSH **certificate authority**; the host then
authenticates cardless until the certificate expires.

**Challenge.** `POST /papi/auth/challenge` with `{ "method": "ssh-cert" }` (no
`recipient`). The server MUST mint a cryptographically random nonce and return
HTTP `200` with `{ "challenge_id": "<hex>", "nonce_b64": "<base64>",
"expires_at": <unix-seconds> }`. This path performs **no encryption** and
therefore requires **no box backend** (contrast §5.1).

**Response.** `POST /papi/auth/response` with `{ "challenge_id": "<hex>",
"certificate": "<OpenSSH certificate>", "signature_b64": "<base64>" }`, where the
signature is over `SHA-256(preimage)` (the §5.2 domain-separated preimage),
produced by the certificate's private key. The server MUST verify ALL of, else
yield HTTP `401`:

1. the signature verifies against the certificate's public key over the exact
   nonce;
2. the certificate is a well-formed OpenSSH certificate whose **signing key (CA)
   is a published slot-9A key** of the subject — matched by the §10.1 union (a
   point-match against `ssh_authorized_keys[]` or string-equality against a
   `/papi/piggy-ids` slot-9A id);
3. the certificate is currently **valid** — its validity window covers the present
   time and its certificate type (and principals, if constrained) admit this use.

On success the server MUST mint a session (§5.2) bound to the principal the
certificate authorizes.

**CA identity.** In `papi/v0` the CA is the subject's published **slot-9A** key
(the same key that signs documents, §10, and SSHes as the subject) acting as an
SSH CA — so a verifier needs no key beyond what PAPI already publishes, and there
is no standing dedicated key that can mint credentials.

**Validity and revocation.** Certificates SHOULD be **short-lived** (scoped to the
bootstrap window); expiry is the revocation bound, so `papi/v0` publishes no
revocation list. Issuance requires the physical card acting as CA; the certificate
then works cardless until it expires.

**Future (not `papi/v0`):** multiple redundant CA keys (a certificate verifies if
it chains to ANY published CA), and a published Key Revocation List (KRL) for
revoke-before-expiry of longer-lived certificates.

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

### 7. Flake Template Advertisement

A PAPI document MAY advertise one or more **nix flake templates** that bootstrap
a repository in the subject's house style. This turns "who is this person" into
"scaffold me a repo the way they scaffold theirs", served from the same
well-known document.

#### 7.1. `templates[]`

The OPTIONAL top-level `templates[]` member is an array of **template entries**.
Each entry is a JSON object with:

| Member        | Type   | Required | Meaning                                                                                                      |
| ------------- | ------ | -------- | ---------------------------------------------------------------------------------------------------------- |
| `id`          | string | MUST     | Stable identifier, unique within `templates[]`; the selector used by §8.                                    |
| `flakeref`    | string | MUST     | A nix-resolvable flake reference including the template attribute, e.g. `github:amarbel-llc/conformist#eng`. |
| `description` | string | SHOULD   | One-line human summary.                                                                                     |
| `kind`        | string | MAY      | Bootstrap mechanism; MUST default to `"flake-template"` when absent.                                        |

A server MAY include additional members; clients MUST ignore members they do not
recognize (§1.1). `id` MUST be a non-empty string and MUST be unique within the
array; a document with duplicate `id`s is malformed, and a client MUST refuse to
resolve a duplicated `id` (§8) rather than choose arbitrarily. `flakeref` MUST be
a non-empty string; this RFC does not constrain its grammar beyond "a reference
`nix flake init -t` accepts", deferring to the nix flake-reference syntax.

`kind` exists so future bootstrap mechanisms can be added without a version bump;
in `papi/v0` the only defined value is `"flake-template"`. A client MUST skip an
entry whose `kind` it does not understand rather than fail the whole list.

#### 7.2. Projection

`templates[]` is an ordinary part of the document and MUST be projected through
the requesting principal exactly as every other node (§2): a `"private"` entry is
dropped for principals its `acl` does not admit, the `acl` member MUST be stripped
from every serialized entry, and the array MUST contain only entries visible to
the principal. A domain MAY therefore publish public templates to everyone and
gate house-internal templates behind the auth handshake (§5).

#### 7.3. `GET /papi/templates`

A server that advertises templates MUST serve `GET /papi/templates`, returning
the projected `templates[]` in the JSON envelope (§4.2):

    { "data": [ <template entry>, ... ],
      "meta": { "count": <int>, "type": "templates",
                "visibility": <"public"|"scoped"> } }

`meta.count` MUST be the number of entries in `data` after projection;
`meta.visibility` follows §4.2. A server whose projected `templates[]` is empty
MUST return a `200` with an empty `data` array (`count: 0`), not a `404`. The
discovery document (§4.1) MUST list `templates` in `resources` with an absolute
URL to `/papi/templates`.

### 8. Template Resolution and Bootstrap

This section specifies how a **client** turns a bootstrap target into a concrete
flake reference and scaffolds from it. It is the contract behind a
`conform <domain>` / `bootstrap <domain>` style command; the reference consumer is
`conformist conform <domain>` (amarbel-llc/conformist).

#### 8.1. Target grammar

A bootstrap target is either:

- `<domain>` — resolve against the domain's advertised templates, or
- `<domain>#<id>` — select the template whose `id` equals `<id>`.

`<domain>` is the authority of the well-known URI (§4); the client fetches
`https://<domain>/.well-known/papi` and follows `resources.templates` (falling
back to `<base>/papi/templates` if the discovery document omits it).

#### 8.2. Selection

From the **visible** `templates[]` (§7.2), after skipping entries whose `kind` it
does not understand (§7.1), the client MUST select as follows:

1. If the target carried `#<id>`: select the entry whose `id` equals `<id>`. No
   match MUST be an error; the client MUST NOT fall back to another entry.
2. Otherwise (bare `<domain>`): if exactly one template is visible, select it. If
   more than one is visible the target is ambiguous and the client MUST
   disambiguate — it MAY prompt the operator to choose, but a client running
   non-interactively MUST fail with a diagnostic listing the available `id`s
   rather than guess. If none are visible, that MUST be an error.

#### 8.3. Bootstrap

Having selected an entry, the client bootstraps by initializing its `flakeref` as
a flake template — the reference behavior is `nix flake init -t <flakeref>` in the
target directory. A client SHOULD refuse to scaffold over a non-empty target
unless explicitly told to overwrite.

#### 8.4. Private templates

A template gated under §7.2 is invisible to the anonymous principal, so resolving
it requires presenting an authenticated session (§5.3): the client performs the
challenge/response handshake (§5) before fetching `/papi/templates`. A client MAY
support only public templates in a first cut, in which case it MUST treat a domain
that advertises only private templates as "no templates visible" (§8.2) rather
than erroring opaquely.

### 9. Identity-Ownership Proofs

A PAPI document **asserts** identities — the forge accounts of §1.1, the
`person.handle`, the contact endpoints — but §1–§8 give a caller no way to
**verify** that the subject actually controls them. Any author of a `papi.json`
can list any GitHub login or Mastodon handle. This section closes that gap with a
Keyoxide/Ariadne-style **bidirectional proof**: the document claims an external
identity, the external identity links back to the document's key, and a verifier
(§9.4) is satisfied only when **both directions** agree. Like every other member,
`proofs[]` is OPTIONAL and additive within `papi/v0`; a document without it is
unchanged and a pre-§9 client ignores it.

The proof is anchored not to the serving domain but to a **published encryption
recipient** (§5) — the same PIV-backed identity the auth handshake already trusts.
A proof therefore survives a change of host or domain: it is verifiable from the
key side as well as the document side, which is the portability property a
domain-bound assertion lacks.

#### 9.1. `proofs[]`

The OPTIONAL top-level `proofs[]` member is an array of **proof entries**. Each
entry is a JSON object with:

| Member      | Type   | Required | Meaning                                                                                          |
| ----------- | ------ | -------- | ------------------------------------------------------------------------------------------------ |
| `id`        | string | MUST     | Stable identifier, unique within `proofs[]`.                                                      |
| `recipient` | string | MUST     | The published recipient id (§5.1 grammar) this proof binds the claimed identity to.               |
| `claim`     | string | MUST     | The external identity being proven, as a URI (`https://…`, `dns:…`, `mailto:…`, or a forge `id`). |
| `proof_uri` | string | MUST     | The URL a verifier fetches to read the backlink (the gist, profile bio, repo file, DNS TXT, …).  |
| `service`   | string | SHOULD   | Service-provider matcher hint (`github`, `gitlab`, `mastodon`, `dns`, `https`, `forge`, …).       |
| `fmt`       | string | MAY      | Backlink format; MUST default to `"recipient"` when absent (see §9.3).                            |

A server MAY include additional members; clients MUST ignore members they do not
recognize (§1.1). `id` MUST be non-empty and unique within the array; a document
with duplicate `id`s is malformed and a verifier MUST refuse to evaluate a
duplicated `id` rather than choose arbitrarily. `recipient` MUST satisfy the §5.1
recipient grammar and SHOULD appear in `piggy.encryption_recipients[]`; a verifier
MUST treat a `recipient` absent from the document's published recipients as an
**unverifiable** proof (§9.4), never as verified.

#### 9.2. Projection

`proofs[]` is an ordinary part of the document and MUST be projected through the
requesting principal exactly as every other node (§2): a `"private"` entry is
dropped for principals its `acl` does not admit, the `acl` member MUST be stripped
from every serialized entry, and the array MUST contain only entries visible to
the principal. The `proof_uri`, `claim`, and `recipient` of a proof are all public
keys / public locations by construction (§ Security Considerations), so the common
case is a fully public `proofs[]`; gating exists only so a subject MAY withhold the
existence of a proof from anonymous callers.

#### 9.3. Backlink format

The **backlink** is the token a verifier expects to find at `proof_uri`. The
`fmt` member selects which token, so the proof composes with whatever the external
service lets the subject write:

- `"recipient"` (default) — the document fetched from `proof_uri` MUST contain the
  literal `recipient` id as a substring. This is the lowest-common-denominator
  proof: paste the recipient id into a GitHub profile bio, a gist, a pinned
  toot, or a DNS TXT record.
- `"signature"` — the resource at `proof_uri` MUST contain a
  `papi-proof-sig-v1@ecdsa_p256_sig-…` **markl-id** (madder [RFC-0002]): a slot-9A
  ECDSA P-256 signature (raw 64-byte `r‖s`) over the **exact `claim` string's
  bytes**, hashed SHA-256. A verifier extracts the markl-id from the `proof_uri`
  document (or TXT records, §9.4) and checks the signature against the subject's
  **published slot-9A keys** — the `ssh_authorized_keys[]` entries and the
  `piggy-piv_auth-v1@…` ids on `/papi/piggy-ids` (the same union match as §10.1).
  The signature alone proves "the holder of a published slot-9A key signed this
  `claim`"; the proof's co-published `recipient` (§9.1) binds that to the asserted
  identity. This upgrades the presence check to a cryptographic one and reuses the
  §10 markl-id machinery — the proof signature (`papi-proof-sig-v1`) signs the
  `claim` string, where the §10 document signature (`papi-doc-sig-v1`) signs the
  JCS document bytes. (The `recipient`, a slot-9D ECDH id, cannot itself verify an
  ECDSA signature, so the signing key is always a published slot-9A key.)

A verifier MUST skip a proof whose `fmt` it does not understand (treating it as
unverifiable, §9.4) rather than fail the whole list, mirroring the `kind`-skip
rule of §7.1.

#### 9.4. Verification (the validator's contract)

This section is the normative anchor for the introspection/validation tool that
is the purpose of this repository (amarbel-llc/papi). A verifier evaluates a proof
entry to exactly one of three outcomes:

1. **verified** — the entry is well-formed, its `recipient` is a published
   recipient of the document (§9.1), the resource at `proof_uri` was fetched
   successfully, and it contains the backlink the `fmt` requires (§9.3) for this
   `recipient`/`claim`. Both directions agree.
2. **unverified** — the entry is well-formed but the backlink is absent,
   malformed, served with the wrong content type, or the fetch failed. The claim
   is **not** proven; a verifier MUST NOT report it as proven.
3. **unverifiable** — the entry is malformed (missing/duplicate `id`, a
   `recipient` outside the published set, an unknown `fmt`). The verifier reports
   the defect and moves on.

A verifier MUST fetch `proof_uri` over HTTPS (or the scheme the `service` matcher
defines, e.g. DNS for `dns:`), MUST follow only same-or-explicitly-allowed-host
redirects, and SHOULD bound the response size and time. The verifier MUST NOT
treat a TLS error, a redirect to a foreign host, or a non-success status as
verified. The check is **stateless and reproducible**: it consumes only public
inputs (the document, the recipient ids, the `proof_uri` contents), so any third
party can run it and reach the same verdict without trusting the verifier — the
property §9 imports from Keyoxide.

#### 9.5. `GET /papi/proofs`

A server that advertises proofs MUST serve `GET /papi/proofs`, returning the
projected `proofs[]` in the JSON envelope (§4.2):

    { "data": [ <proof entry>, ... ],
      "meta": { "count": <int>, "type": "proofs",
                "visibility": <"public"|"scoped"> } }

`meta.count` MUST be the number of entries in `data` after projection;
`meta.visibility` follows §4.2. A server whose projected `proofs[]` is empty MUST
return a `200` with an empty `data` array (`count: 0`), not a `404`. The endpoint
serves the **claims**, not verdicts: a PAPI server MUST NOT itself fetch
`proof_uri` or annotate entries with a verification outcome, because doing so would
make the server an oracle for its own claims and defeat the third-party-verifier
property of §9.4. Verification is the client/validator's job.

### 10. Document Signature

§9 binds the document's **assertions** to a key; this section binds the
**document itself** to a key, so a client can verify authorship of a fetched
document offline. Without it, PAPI's trust root is "whoever controls the domain":
a document fetched from a cache, a mirror, or a CDN that has been compromised
carries no evidence of who authored it. The OPTIONAL `signatures[]` member makes
the document **self-certifying** — one or more detached signatures, each
verifiable against a published key rather than against the host that served it,
the second portability property §9 named.

#### 10.1. `signatures[]`

The OPTIONAL top-level `signatures[]` member is an array of **signature entries**.
Each entry is a JSON object with:

| Member    | Type   | Required | Meaning                                                                                                   |
| --------- | ------ | -------- | --------------------------------------------------------------------------------------------------------- |
| `key`     | string | MUST     | The verifying public key, as a published markl-id: a `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…` (§10.4). |
| `sig`     | string | MUST     | The detached signature, as a `papi-doc-sig-v1@ecdsa_p256_sig-…` markl-id over the §10.2 input (§10.4).      |
| `created` | int    | SHOULD   | Unix-seconds the signature was produced.                                                                  |

There is no `alg` member: the signing method is carried **natively by the
markl-ids** (the wire form madder [RFC-0002] defines). The `key`'s purpose
(`piggy-piv_auth-v1` ⇒ a PIV slot-9A authentication key) and the `sig`'s format
(`ecdsa_p256_sig` ⇒ ECDSA P-256, raw `r‖s`, verified with SHA-256) together fully
determine verification, so a separate algorithm selector would be redundant.

A verifier MUST skip an entry whose markl-id purpose or format it does not
understand (treating that entry as absent, §10.3) rather than fail. An entry's
`key` MUST be **published**: either string-equal to a slot-9A id advertised on
`/papi/piggy-ids`, or — for a document that publishes only OpenSSH keys — decoding
to the same P-256 public point as an `ssh_authorized_keys[]` entry. A `key`
matching neither is **unverifiable** and that entry MUST be treated as absent.

Multiple entries let several keys co-sign the identical §10.2 bytes — e.g. two PIV
slot-9A keys (two hardware tokens), or an outgoing and an incoming key across a
rotation. The document's verdict over the array is **conjunctive** (§10.3).

The pre-Amendment-9 singular `signature` object — `{ alg: "ssh-9a", key, sig }`
with an OpenSSH `key` line and a base64 SSH-wire `sig` — is **superseded** by
`signatures[]` and retained only for backward compatibility; a verifier MAY still
accept it when no `signatures[]` is present (§10.4, "Legacy").

#### 10.2. Signing input (canonicalization)

The signature covers the document **with the `signature` and `signatures` members
removed**: a signer MUST delete both top-level keys, serialize the remaining
document by [RFC 8785] JSON Canonicalization Scheme (JCS) — lexicographically
sorted keys, no insignificant whitespace, canonical number forms — and sign the
resulting UTF-8 bytes. A verifier reconstructs the identical bytes by removing both
`signature` and `signatures` and re-canonicalizing before checking each `sig`;
stripping both forms lets producer and verifier agree on the bytes regardless of
which form a document carries. The signed document MUST be the **anonymous
projection** — the document `GET /papi` serves to the anonymous principal (§2), the
same bytes any verifier can fetch without authenticating. A signer therefore signs
the to-be-served anonymous document, NOT the pre-projection source: private nodes
are dropped before signing, so the signature commits to no private content and is
verifiable by anyone. A verifier MUST verify against anonymous `/papi` (or the
discovery `signatures`, §4.1) and MUST NOT verify against a scoped/authenticated
response, whose additional private nodes would not match the signed bytes.

#### 10.3. Verification

A verifier that finds `signatures[]` (in the discovery document, §4.1, or on an
anonymous `GET /papi`) MUST evaluate **each** entry: confirm the `key` and `sig`
markl-id purposes/formats are understood and the `key` is published (§10.1);
reconstruct the §10.2 signing input; and verify the `sig` over those bytes with
`key`. Each entry is one of **signed-and-valid**, **signed-but-invalid** (the
markl-ids were understood but the signature does not verify), or **unverifiable**
(a markl-id purpose/format the verifier cannot use, or a `key` that is not
published).

The document's verdict is **conjunctive**: **signed-and-valid** iff at least one
entry is evaluable and every evaluable entry is valid; **signed-but-invalid** if
any evaluable entry fails (report prominently — a present-but-broken signature is a
stronger negative signal than no signature); **unsigned** if no `signatures[]`/
`signature` is present, or no entry is evaluable. A verifier MUST NOT treat an
unsigned document as invalid — signatures are OPTIONAL — but SHOULD surface the
distinction so a consumer can require signed documents in higher-trust contexts.

#### 10.4. The `papi-doc-sig-v1` signature

A `signatures[]` entry binds a PIV **slot-9A** authentication key to the §10.2
bytes, expressed entirely as markl-ids (madder [RFC-0002]):

- `key` is a `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-<blech32>` markl-id whose
  payload is the 33-byte SEC1-compressed P-256 public point. The purpose
  `piggy-piv_auth-v1` denotes the slot (9A, Authentication); the format
  `ssh_ecdsa_nistp256_pub` denotes an SSH-suitable P-256 key.
- `sig` is a `papi-doc-sig-v1@ecdsa_p256_sig-<blech32>` markl-id whose payload is
  the raw 64-byte ECDSA signature `r‖s` (two 32-byte big-endian integers, no DER,
  no SSH-wire framing).

- **Signing.** The signer passes the §10.2 JCS bytes to the slot-9A agent sign
  operation (ECDSA P-256 over **SHA-256**, the digest `ecdsa-sha2-nistp256`
  mandates), strips the SSH-wire framing to the bare 64-byte `r‖s`, and blech32-
  encodes it under the `papi-doc-sig-v1@ecdsa_p256_sig` markl-id. The published key
  is the matching `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub` markl-id.
- **Verifying.** The verifier decodes the `sig` markl-id to 64 bytes
  (`r` = bytes 0–31, `s` = bytes 32–63), decodes the `key` markl-id to the P-256
  point, and checks the ECDSA signature on curve NIST P-256 with **SHA-256** over
  the §10.2 JCS bytes. A `sig`/`key` whose markl-id parses with the expected
  purpose/format but fails to verify makes that entry **signed-but-invalid**
  (§10.3); a markl-id whose purpose/format is not understood makes the entry
  **unverifiable** (skipped, §10.1).

**Legacy (`ssh-9a`, pre-Amendment 9).** The superseded singular `signature` object
carries `alg: "ssh-9a"`, an OpenSSH `ecdsa-sha2-nistp256` `key` line, and a `sig`
that is base64 of the raw SSH-wire agent signature (`"ecdsa-sha2-nistp256"` +
`(r, s)` mpints, [RFC 5656] §3.1.2) — the same ECDSA-P256/SHA-256 verification over
the §10.2 bytes, differing only in encoding. A verifier MAY accept it when no
`signatures[]` is present.

Future formats or purposes (e.g. a software-signer or SSHSIG-framed variant) MAY be
registered in [RFC-0002] without a version bump; a verifier skips a markl-id whose
purpose/format it does not implement (§10.1).

### 11. Nix Binary Cache Advertisement

A PAPI document MAY advertise one or more **nix binary caches** (substituters)
that a caller configures to fetch the subject's pre-built closures instead of
compiling from source. This turns "who is this person" into "which caches do they
let me pull from to bootstrap", served from the same well-known document and gated
by the same projection (§2) and authentication (§5) as every other node. The
reference consumer is a host bootstrap: a freshly-provisioned machine, its caller
authenticated by a forwarded piggy agent, reads the advertised caches and writes
them into its nix `substituters`/`trusted-public-keys` so the subject's closures
substitute rather than rebuild. Like every other top-level member, `caches[]` is
OPTIONAL and additive within `papi/v0`; a document without it is unchanged and a
pre-§11 client ignores it.

#### 11.1. `caches[]`

The OPTIONAL top-level `caches[]` member is an array of **cache entries**. Each
entry is a JSON object with:

| Member                | Type            | Required | Meaning                                                                                    |
| --------------------- | --------------- | -------- | ------------------------------------------------------------------------------------------ |
| `id`                  | string          | MUST     | Stable identifier, unique within `caches[]`.                                               |
| `url`                 | string          | MUST     | The substituter base URL, a nix `substituters` entry (e.g. `http://krone:8080`).            |
| `trusted_public_keys` | array of string | MUST     | One or more nix `trusted-public-keys` lines (`<name>:<base64-ed25519-pub>`); at least one.  |
| `priority`            | int             | MAY      | The nix substituter priority (lower = preferred).                                          |
| `kind`                | string          | MAY      | Cache mechanism; MUST default to `"nix-binary-cache"` when absent.                         |

A server MAY include additional members; clients MUST ignore members they do not
recognize (§1.1). `id` MUST be a non-empty string and MUST be unique within the
array; a document with duplicate `id`s is malformed, and a client MUST refuse to
resolve a duplicated `id` rather than choose arbitrarily. `url` MUST be a non-empty
string and `trusted_public_keys` MUST contain at least one non-empty string; this
RFC does not constrain their grammar beyond "a value nix accepts as a
`substituters` / `trusted-public-keys` entry", deferring to nix's configuration
syntax. The `trusted_public_keys` member is an array — not a single key — so a
cache mid-rotation can publish both its outgoing and incoming keys.

`kind` exists so future cache mechanisms can be added without a version bump; in
`papi/v0` the only defined value is `"nix-binary-cache"`. A client MUST skip an
entry whose `kind` it does not understand rather than fail the whole list,
mirroring §7.1.

#### 11.2. Projection

`caches[]` is an ordinary part of the document and MUST be projected through the
requesting principal exactly as every other node (§2): a `"private"` entry is
dropped for principals its `acl` does not admit, the `acl` member MUST be stripped
from every serialized entry, and the array MUST contain only entries visible to the
principal. What gating a cache entry hides is not a secret — the substituter `url`
is a network locator and the `trusted_public_keys` are verification keys, both
public by construction — but the **existence and location** of the subject's
private infrastructure. A domain MAY therefore publish public caches to everyone
and gate house-internal caches (a tailnet-only substituter, a private build host)
behind the auth handshake (§5), so an anonymous caller never learns the private
cache exists.

#### 11.3. `GET /papi/caches`

A server that advertises caches MUST serve `GET /papi/caches`, returning the
projected `caches[]` in the JSON envelope (§4.2):

    { "data": [ <cache entry>, ... ],
      "meta": { "count": <int>, "type": "caches",
                "visibility": <"public"|"scoped"> } }

`meta.count` MUST be the number of entries in `data` after projection;
`meta.visibility` follows §4.2. A server whose projected `caches[]` is empty MUST
return a `200` with an empty `data` array (`count: 0`), not a `404`. The discovery
document (§4.1) MUST list `caches` in `resources` with an absolute URL to
`/papi/caches`.

#### 11.4. Client consumption and bootstrap

A client turns a visible cache entry into nix configuration by appending `url` to
its `substituters` and each `trusted_public_keys` entry to its
`trusted-public-keys`, honoring `priority` where its nix configuration supports it.
A cache gated under §11.2 is invisible to the anonymous principal, so reading it
requires presenting an authenticated session (§5.3): the bootstrapping client
performs the challenge/response handshake (§5) — proving control of a published
recipient's PIV slot-9D key, which a **forwarded piggy agent satisfies headless**
(the agent's ECDH-decrypt extension rides the forwarded socket) — before fetching
`/papi/caches`. The authenticated tier is live only where the server can encrypt a
challenge, i.e. a box backend is present (§ Security Considerations, "Box
availability"); against an anonymous-only host the private caches are simply absent
(the handshake's `/papi/auth/challenge` returns `503`), and a client MUST treat
that as "no private caches visible" rather than erroring opaquely, mirroring §8.4.

### 12. Identity-Bootstrap Consumption

A PAPI document already carries everything a tool needs to source a person's
**identity material** — the SSH/signing key behind a published slot-9A key and the
person's name and contact email — from the well-known document instead of reading a
local card or prompting an operator. This section documents that **consumption
contract**: which already-specified affordances a client reads, and through which
paths. It defines no new document member, endpoint, or projection rule; the server
behavior it consumes is §2 (projection), §4.2 (the text endpoints), and §5 (the
handshake), all unchanged. The reference consumer is an identity-bootstrap tool
that wires a freshly-provisioned machine's git/SSH identity from a domain's PAPI.

#### 12.1. Consumable affordances

A client MAY treat the following published, already-specified data as a bootstrap
source:

- **`person.contact.email`** — the email on the ACL-gated `person.contact` node
  (§1, §6). Per §2 the anonymous projection drops it; an authenticated principal
  whose projection admits the node (§5) sees it. A consumer that needs the email
  MUST authenticate (§12.2); a consumer MUST treat a missing `contact` (the node
  was gated and the caller is anonymous, or the document publishes none) as
  **absent, not an error**, and fall back to another source or proceed without it.
- **`person.display_name`** (or `person.handle` / `person.name` as fallbacks) — the
  subject's name, public by default. A consumer SHOULD prefer `display_name`, then
  `name`, then `handle`.
- **The `/papi/ssh-authorized-keys` annotations** — each line the endpoint emits
  (§4.2) is an OpenSSH `authorized_keys` line a server MAY annotate with
  `guid=<HEX>` (the slot-9A key's PIV card GUID) and `cn=<name>` (its common name)
  in the line's trailing comment field. A client that knows a card's GUID MAY
  select that card's published key by matching `guid=<HEX>` case-insensitively
  against the `guid=` annotation, isolating the one line whose key the card holds.
  These annotations are an OPTIONAL server affordance; a client MUST tolerate lines
  that carry neither (treating an un-annotated body as "no GUID-addressable key").

#### 12.2. Client paths

The reference validator/CLI (amarbel-llc/papi) exposes the consumption contract as:

- **`papi person <domain>`** — fetches `GET /papi` and prints the `person` block
  (handle, display name, contact email) as JSON. Anonymously, `contact.email` is
  absent (§2). With `--recipient <id>` (and `--decrypt-cmd <cmd>`) it runs the §5
  handshake to obtain a session, presents it on `GET /papi` (§5.3), and so reveals
  `contact.email` from the scoped projection. The same handshake core drives
  `papi validate`'s authenticated tier; a consumer SHOULD reuse a §5
  implementation rather than reimplement the challenge/response.
- **`papi ssh-keys <domain>`** — fetches `GET /papi/ssh-authorized-keys` and prints
  it verbatim; with `--guid <HEX>` it prints only the line whose `guid=<HEX>`
  annotation matches (§12.1), erroring if none matches. This is how a client pins
  the signing/SSH key for a specific local card.

#### 12.3. Future bootstrap directions (deferred to `papi/v1`)

The following extend the consumption contract from sourcing **identity material**
to bootstrapping **secrets and general authentication** against PAPI. They are
recorded here for design continuity and are **deferred to `papi/v1`**; nothing in
this subsection is implemented or REQUIRED in `papi/v0`.

- **Scoped SECRETS retrieval.** A future `papi/v1` MAY define a node class that
  projects an encrypted secret (an ebox) to an authenticated caller, so a client
  that proves control of a published slot-9D recipient via the §5 handshake unlocks
  scoped secret nodes and decrypts them locally with the same card. The secret MUST
  remain encrypted to the recipient on the wire (the server only ever encrypts,
  §5), and such a node MUST be gated `visibility: "private"` like every other
  scoped node (§2). The client SHOULD reuse the session minted for the initial
  unlock for any follow-on secret fetches rather than re-handshaking per node.
- **General AUTH against PAPI for provisioning.** A future `papi/v1` MAY let a
  client reuse a §5 session as a general authentication capability for further
  provisioning steps against the domain (beyond reading projected nodes) — proving
  control of a published recipient once, then acting as that principal for a
  bounded session. Any such use MUST honor the §5.2 session TTL and the §5.3 rule
  that an expired/unknown session degrades to anonymous, and MUST NOT treat the
  ephemeral session as a durable credential; the durable identity remains the
  slot-9D card, re-proven by a fresh handshake when the session lapses. A
  provisioning surface that mutates server state is out of scope for both `papi/v0`
  and this subsection and would require its own RFC.

### 13. Host-Profile Advertisement

A PAPI document MAY advertise one or more **host profiles** that a staged host
installer activates to bring a machine into the subject's configuration. This
turns "who is this person" into "configure this host the way they configure
theirs", served from the same well-known document and gated by the same
projection (§2) and authentication (§5) as every other node. The reference
consumer is the staged installer (a papi-built binary); the installer's phase
model and the timing of this read are specified in a separate RFC.

#### 13.1. `profiles[]`

The OPTIONAL top-level `profiles[]` member is an array of **profile entries**.
Each entry is a JSON object with:

| Member        | Type   | Required | Meaning                                                                                                                          |
| ------------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `id`          | string | MUST     | Stable identifier, unique within `profiles[]`; the selector the installer presents (TUI choice or `#id`).                       |
| `flakeref`    | string | MUST     | A nix-resolvable flake reference to the profile to activate, e.g. `github:amarbel-llc/eng#nixosConfigurations.<host>` or `…#homeConfigurations.<name>`. |
| `home_flakeref`| string | MAY     | On a `nixos-configuration` entry: the flakeref of the host's **standalone** `homeConfiguration`, applied separately via `home-manager` (not the NixOS module). Absent/ignored for `home-configuration` entries. |
| `description` | string | SHOULD   | One-line human summary, shown in the installer's selection UI.                                                                  |
| `platform`    | string | MAY      | Target-platform hint (e.g. `"nixos"`, `"linux"`, `"darwin"`); a client MAY use it to filter the offered set.                    |
| `kind`        | string | MAY      | Activation mechanism (see below).                                                                                               |

A server MAY include additional members; clients MUST ignore members they do not
recognize (§1.1). `id` MUST be a non-empty string and MUST be unique within the
array; a document with duplicate `id`s is malformed, and a client MUST refuse to
resolve a duplicated `id` rather than choose arbitrarily. `flakeref` MUST be a
non-empty string; this RFC does not constrain its grammar beyond "a reference
`nix` resolves", deferring to the nix flake-reference syntax.

`kind` selects how a client activates the entry's `flakeref`. Defined values in
`papi/v0`:

- `"nixos-configuration"` — activate via `nixos-rebuild` against the flakeref (a
  `nixosConfigurations.<host>` output);
- `"home-configuration"` — activate via `home-manager` against the flakeref (a
  `homeConfigurations.<name>` output).

`kind` exists so future activation mechanisms can be added without a version
bump. When `kind` is absent, a client SHOULD infer the mechanism from the
flakeref's output attribute (`nixosConfigurations.*` ⇒ `"nixos-configuration"`,
`homeConfigurations.*` ⇒ `"home-configuration"`). A client MUST skip an entry
whose `kind` it does not understand rather than fail the whole list.

`home_flakeref`, when present on a `nixos-configuration` entry, names the host's
**standalone** home layer. A NixOS host profile is a pair: the `nixosConfiguration`
(`flakeref`, applied as system configuration) and a standalone `homeConfiguration`
(`home_flakeref`, applied separately via `home-manager`, **not** through the NixOS
home-manager module). A `home-configuration` entry is itself the home layer and
MUST NOT carry a `home_flakeref`. This member only carries the targets; how and
when an installer applies each is specified by the installer phase-contract RFC.

#### 13.2. Projection

`profiles[]` is an ordinary part of the document and MUST be projected through
the requesting principal exactly as every other node (§2): a `"private"` entry
is dropped for principals its `acl` does not admit, the `acl` member MUST be
stripped from every serialized entry, and the array MUST contain only entries
visible to the principal. Host profiles are commonly **scoped to authenticated
callers** (a subject's host set is private infrastructure); a domain MAY publish
public profiles to everyone and gate the rest behind the §5 handshake. A consumer
that needs gated profiles MUST present an authenticated session (§5.3), which a
forwarded or local piggy agent satisfies headless — or which a consumer MAY
satisfy by **direct PIV-card access** (e.g. `pivy-box`) without a running agent,
as the staged installer does (see the installer phase-contract RFC §4).

#### 13.3. `GET /papi/profiles`

A server that advertises profiles MUST serve `GET /papi/profiles`, returning the
projected `profiles[]` in the JSON envelope (§4.2):

    { "data": [ <profile entry>, ... ],
      "meta": { "count": <int>, "type": "profiles",
                "visibility": <"public"|"scoped"> } }

`meta.count` MUST be the number of entries in `data` after projection;
`meta.visibility` follows §4.2. A server whose projected `profiles[]` is empty
MUST return a `200` with an empty `data` array (`count: 0`), not a `404`. The
discovery document (§4.1) MUST list `profiles` in `resources` with an absolute
URL to `/papi/profiles`.

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
SHOULD verify forwarding so the header works, lest every authenticated caller
silently degrade to anonymous; the `?papi_session=` query param is a last-resort
fallback only (§5.3, NOT RECOMMENDED — it leaks the session into logs/`Referer`).

**Session storage.** Sessions and one-time challenges are stored as atomic JSON
files (reference: under `api/tmp/papi-auth/`). The store MUST key lookups by the
opaque id (not a directory scan) and MUST treat an absent/expired record as no
session. A host without a reaping cron relies on lazy expiry at access time.

**Template flakerefs are executable trust (§7–§8).** A `flakeref` advertised in
`templates[]` points at code that `nix flake init -t` fetches and writes into the
operator's working tree; bootstrapping from a domain therefore extends that
domain (and whatever forge its flakeref resolves to) the trust to scaffold files
the operator will build and run. The flakeref is chosen by the document author,
not the caller, so it is not attacker-controlled in the normal case — but a client
that resolves a domain it does not trust, or that followed a discovery link from a
response it did not originate (see the `Host` header note above), could be steered
to an arbitrary flake. A bootstrapping client SHOULD surface the resolved flakeref
to the operator before initializing it, MUST honor nix's own flake-evaluation trust
prompts rather than suppressing them, and SHOULD restrict resolution to domains the
operator named explicitly.

**Advertised caches are configuration trust (§11).** A `caches[]` entry names a
substituter the consuming host will fetch closures from and a `trusted_public_keys`
it will trust those closures' signatures against — so advertising a cache extends
the consuming host the trust to run code substituted from it, exactly as a
`templates[]` flakeref (§7–§8) extends the trust to scaffold. The `url` and keys
are chosen by the document author, not the caller, so they are not
attacker-controlled in the normal case; but a client that resolves a domain it does
not trust, or that followed a discovery link from a response it did not originate
(see the `Host` header note above), could be steered to an arbitrary substituter
and trust key. Critically, a tailnet-local cache is typically served over plain
HTTP with no transport authentication, so the advertised `trusted_public_keys` IS
the integrity root for the substituted closures: a consumer that trusts a key
learned from PAPI is trusting PAPI as the key-distribution channel. A bootstrapping
client SHOULD therefore require a valid document signature (§10) before honoring an
advertised `trusted_public_keys`, so the key is verified against the subject's
published signing key rather than against whatever host served the document, and
SHOULD restrict cache resolution to domains the operator named explicitly.

**Proofs prove control, not the document (§9).** A verified proof (§9.4) attests
that the holder of `recipient` also controls the external `claim` — nothing more.
It does NOT attest that the PAPI document is authentic (that is §10's job), nor
that the external account is benign. The backlink is fetched from an
attacker-influenceable location (a third-party service), so a verifier MUST bound
the fetch (§9.4), MUST NOT follow redirects to a foreign host, and MUST treat a
failed or ambiguous fetch as **unverified**, never verified — failing closed
exactly as §2's visibility does. Because the verdict is computed only from public
inputs, a malicious verifier can lie about an outcome but cannot forge one that an
honest third party will reproduce; consumers in a trust-sensitive context SHOULD
re-verify rather than trust a reported verdict.

**The `fmt: "recipient"` backlink is a presence check, not a signature.** A bare
recipient id pasted into a profile proves the subject could write that location at
proof time; it does not cryptographically bind the content. A service that lets
attackers inject substrings into the fetched page (open redirects, reflected
parameters, user-controlled fragments at `proof_uri`) could manufacture a false
positive. Subjects SHOULD prefer `fmt: "signature"` (§9.3) where the service
allows it, and verifiers SHOULD scope the substring search to the
service-provider-defined region of the response rather than the whole body.

**A document signature binds authorship, not freshness (§10).** A valid §10
signature proves the holder of `key` authored these exact bytes; absent `created`
and a freshness policy, it does not prove the bytes are current. An attacker who
captures a signed document can replay an older signed version (e.g. one that still
lists a since-revoked SSH key). Consumers that care about revocation SHOULD honor
`created` and reject signatures older than a policy bound, and subjects SHOULD
re-sign on every material change. Canonicalization (§10.2) is load-bearing: a
verifier that checks `sig` over non-canonical bytes, or that forgets to strip the
`signature` and `signatures` members first, will reject valid documents or —
worse, if it is lenient about trailing data — accept manipulated ones. Verify only
over the JCS bytes of the signature-stripped source document.

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
| §9, `/papi/proofs` serving   | `test-papi.php`, `test-papi.sh` | projected `proofs[]`; server emits claims, never verdicts (§9.5)    |
| §10, signature serving       | `test-papi.php`                 | `signatures` echoed in discovery (§4.1); stripped from signing input |

A future re-implementation in another language SHOULD be able to satisfy the same
HTTP-level suite (`test-papi.sh`) unchanged, since it exercises only the wire
contract.

The **verification** side of §9.4 and §10.3 — fetching `proof_uri`, checking the
backlink, and verifying the `signatures` — is the introspection/validation tool's
own conformance surface (this repository, amarbel-llc/papi), not the server's. The
validator's checks against a live or fixtured domain are the executable form of
the §9.4 three-outcome verdict and the §10.3 signed/invalid/unsigned verdict.

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
- The `templates[]` member and the `/papi/templates` endpoint (§7) are an additive
  OPTIONAL extension within `papi/v0`: a document without `templates[]` is
  unchanged, and a client predating §7 ignores both the member and the endpoint.
  No version bump is required.
- The `proofs[]` member and the `/papi/proofs` endpoint (§9), and the
  `signatures[]` member (§10), are additive OPTIONAL extensions within `papi/v0`
  on the same footing: a document without them is unchanged, a client predating
  §9–§10 ignores the members and the endpoint, and the discovery
  `proofs`/`signatures` fields appear only when the document advertises them. No
  version bump is required.
- The `caches[]` member and the `/papi/caches` endpoint (§11) are an additive
  OPTIONAL extension within `papi/v0` on the same footing: a document without
  `caches[]` is unchanged, a client predating §11 ignores both, and the discovery
  `caches` resource appears only when the document advertises caches. No version
  bump is required.
- The `localsend` block is reserved for `papi/v1`; in `papi/v0`
  `localsend.enabled` MUST be `false`. (The slot-9A signature auth strategy once
  reserved here is now the RECOMMENDED `papi/v0` §5 sign-challenge scheme — §5,
  Amendment 14 — advertised as `auth.scheme: "piggy-sign-challenge"`.)
- PAPI coexists with the host's other collections under the same `{data, meta}`
  envelope; this RFC does not alter those collections.

## References

Normative:

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement
  Levels", BCP 14, RFC 2119, March 1997.
- [RFC 8615] Nottingham, M., "Well-Known Uniform Resource Identifiers (URIs)",
  RFC 8615, May 2019.
- [RFC 8785] Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme
  (JCS)", RFC 8785, June 2020. Normative for the §10.2 signing input.
- [RFC 5656] Stebila, D., Green, J., "Elliptic Curve Algorithm Integration in the
  Secure Shell Transport Layer", RFC 5656, December 2009. Normative for the
  `ecdsa-sha2-nistp256` signature encoding (§10.4, Legacy).
- [RFC-0002] "markl-id: self-describing identifier wire format", `docs/rfcs/` in
  amarbel-llc/madder. Normative for the §10 `signatures[]` markl-id encoding
  (blech32, the `papi-doc-sig-v1`/`piggy-piv_auth-v1` purposes, the
  `ecdsa_p256_sig`/`ssh_ecdsa_nistp256_pub` formats).
  <https://github.com/amarbel-llc/madder>
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
- [nix-flakes] Nix Reference Manual — flake references and `nix flake init -t
  <flakeref>`. <https://nix.dev/manual/nix/latest/>
- [Keyoxide] Keyoxide — decentralized identity verification via bidirectional
  proofs; the prior art §9 adapts (claim-in-key ↔ backlink-in-account, stateless
  reproducible verification). <https://keyoxide.org/>
- [Ariadne] Ariadne Identity / Ariadne Signature Profile — the proof-notation and
  signed-profile model behind Keyoxide. <https://ariadne.id/>

## Amendment History

- **2026-06-17, Amendment 1 — Flake Template Advertisement.** Added the OPTIONAL
  `templates[]` document member (§1, §7.1), its projection (§7.2), the
  `GET /papi/templates` endpoint (§4, §7.3), the `templates` discovery resource
  (§4.1), and the §4.2 envelope and Compatibility updates. Additive and OPTIONAL —
  no version bump.
- **2026-06-17, Amendment 2 — Template Resolution and Bootstrap.** Added §8,
  specifying client-side resolution of a `<domain>` / `<domain>#<id>` target to a
  template flakeref and bootstrap via `nix flake init -t`, including
  disambiguation and private-template behavior. Sequenced after Amendment 1; the
  reference consumer is `conformist conform <domain>`.
- **2026-06-17, Amendment 3 — Identity-Ownership Proofs and Document Signature.**
  Added §9 (the OPTIONAL `proofs[]` document member, its projection, the
  Keyoxide-style bidirectional backlink formats, the three-outcome verifier
  contract, and the `GET /papi/proofs` endpoint) and §10 (the OPTIONAL `signature`
  member, JCS signing input, and signed/invalid/unsigned verification), plus the
  §1 member table, §4 endpoint table, §4.1 discovery `proofs`/`signature` fields,
  Security Considerations, Compatibility, and References ([RFC 8785], [Keyoxide],
  [Ariadne]) updates. Adapts Keyoxide/Ariadne's key-anchored, third-party-verifiable
  identity model so PAPI **proves** the identities it asserts (§9) and a document is
  verifiable against a key rather than its host (§10). Additive and OPTIONAL — no
  version bump. The verification side is the amarbel-llc/papi validator's surface;
  the producing side is a planned `piggy papi` subcommand family (sign / prove /
  verify) over piggy's slot-9A SSH-auth and slot-9D ECDH keys.
- **2026-06-17, Amendment 4 — Piggy-ids listing parity.** Updated §4 (endpoint
  table) and §4.2 so `/papi/piggy-ids` emits a complete piggy-ids file — the
  visible slot-9D encryption recipients (`piggy-recipient-v1@…`) followed by the
  visible slot-9A SSH auth ids (`piggy-piv_auth-v1@…`) — rather than only
  encryption recipients, mirroring the reference impl. Spec-parity edit; no new
  member or endpoint, no version bump.
- **2026-06-17, Amendment 5 — `ssh-9a` signature encoding.** Pinned the §10
  signature wire encoding (new §10.4, [RFC 5656] reference, §10.1 `sig` cell):
  `alg: "ssh-9a"` `sig` is base64 of the raw ssh-agent `ecdsa-sha2-nistp256`
  signature blob (`"ecdsa-sha2-nistp256"` + `(r, s)` mpints), verified as
  ECDSA-P256 with SHA-256 over the §10.2 JCS bytes — the bare agent signature, NOT
  SSHSIG framing. Resolves a producer/verifier wire-contract ambiguity flagged by
  the piggy side (the `piggy papi` sign surface) so both agree. Clarification of an
  OPTIONAL feature; no version bump.
- **2026-06-17, Amendment 6 — signature over the anonymous document (§10.2).**
  Resolved the source-vs-anon ambiguity: the signed document MUST be the anonymous
  projection (the bytes `GET /papi` serves the anonymous principal), not the
  pre-projection source — so the signature commits to no private content and any
  verifier can check it against anonymous `/papi`. Matches the validator's verifier
  and piggy's `papi sign` (operates on the to-be-served-anon document). Surfaced
  while implementing the §10.4 verifier; agreed with the piggy side. Clarification
  of an OPTIONAL feature; no version bump.
- **2026-06-18, Amendment 7 — Nix Binary Cache Advertisement.** Added the OPTIONAL
  `caches[]` document member (§1, §11.1), its projection (§11.2), the
  `GET /papi/caches` endpoint (§4, §11.3), the client-consumption/bootstrap
  contract (§11.4), the `caches` discovery resource (§4.1), and the §4.2 envelope,
  Security Considerations, and Compatibility updates. Turns the well-known document
  into the ACL-gated discovery surface for a subject's nix substituters: a host
  whose caller is authenticated by a forwarded piggy agent (§5) reads the gated
  caches and configures nix to substitute the subject's closures instead of
  rebuilding from source. Captured from a working cross-implementation proof —
  validated against the reference implementation's live anonymous tier (the gated
  cache correctly invisible to anonymous) and its hermetic scoped tier (the
  authenticated reveal with `acl` stripped, §2.6). Additive and OPTIONAL — no
  version bump. The §10 multi-signature + markl-id re-spec is sequenced as a later
  amendment, pending the markl→piggy ownership move.
- **2026-06-19, Amendment 8 — Identity-Bootstrap Consumption.** Added §12,
  documenting the **consumption contract** by which a client sources a person's
  identity material from a domain's PAPI: the ACL-gated `person.contact.email`
  (§1, §6), `person.display_name`, and the OPTIONAL `guid=`/`cn=` annotations on
  `/papi/ssh-authorized-keys` lines (§4.2) as consumable affordances (§12.1), the
  `papi person` (anonymous + §5-authed) and `papi ssh-keys --guid` client paths
  (§12.2), and v1-deferred directions for scoped SECRETS retrieval and general AUTH
  against PAPI (§12.3). Documents consumption of already-specified server behavior
  (§2 projection, §4.2 text endpoints, §5 handshake) — it defines no new member,
  endpoint, or projection rule and changes no §2 gating. The producing side is the
  reference implementation's existing live tier; the consuming side is the
  amarbel-llc/papi CLI (`papi person`, `papi ssh-keys`) and a downstream
  identity-bootstrap tool. Additive and OPTIONAL — no version bump.
- **2026-06-20, Amendment 9 — `signatures[]` + markl-id re-spec.** Re-spec'd §10
  from the singular `signature` object to a `signatures[]` **array** of
  `{ key, sig, created? }` entries, verified with a **conjunctive** verdict
  (authentic only if every evaluable entry verifies), to support multiple
  co-signing keys (e.g. two PIV slot-9A tokens). `key` and `sig` are now
  **markl-ids** (madder [RFC-0002]): `key` =
  `piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…` (33-byte SEC1 point), `sig` =
  `papi-doc-sig-v1@ecdsa_p256_sig-…` (raw 64-byte `r‖s`). The `alg` member is
  **dropped** — the signing method is carried natively by the markl-ids (the key
  purpose ⇒ slot 9A; the sig format ⇒ ECDSA P-256/SHA-256). Updated §1, §4.1
  (discovery echoes `signatures`), §10.1–§10.4, §10.2 (the signing input strips
  **both** `signature` and `signatures`), Security Considerations, Compatibility,
  References ([RFC-0002]), and the conformance table. A `key` is published by
  string-equality against a `/papi/piggy-ids` slot-9A id **or** a P-256
  point-match against `ssh_authorized_keys[]` (so OpenSSH-only documents still
  verify). The pre-Amendment-9 singular `signature` (`ssh-9a`) is **superseded**
  but retained as a verifier fallback when no `signatures[]` is present.
  Supersedes the Amendment 5/6 single-signature form. The validator
  (amarbel-llc/papi) parses markl-ids via a minimal blech32 port validated against
  [RFC-0002]'s conformance vectors. Clarification/re-spec of an OPTIONAL feature —
  no version bump.
- **2026-06-20, Amendment 10 — `fmt="signature"` proof signatures (§9.3).** Pinned
  the §9.3 `fmt="signature"` backlink as a `papi-proof-sig-v1@ecdsa_p256_sig-…`
  markl-id (madder [RFC-0002], the proof-claim sibling of §10's `papi-doc-sig-v1`):
  a slot-9A ECDSA P-256 signature over the **exact `claim` string** (SHA-256),
  embedded at `proof_uri` (https body or dns TXT, §9.4) and verified against the
  subject's published slot-9A keys (the §10.1 union match — `ssh_authorized_keys[]`
  point-match or `/papi/piggy-ids` string-equality). Resolved the prior §9.3
  ambiguity ("verifiable against … the `recipient`"): a `recipient` is a slot-9D
  ECDH id and cannot verify an ECDSA signature, so the signing key is always a
  published slot-9A key, and the proof's co-published `recipient` provides the
  identity binding. The signing-input + key-binding were pinned jointly with the
  piggy producer side. Implemented in the validator (amarbel-llc/papi), reusing
  the §10 markl-id machinery; the `papi-proof-sig-v1` purpose is registered in
  piggy's go/markl. Additive clarification of an OPTIONAL feature — no version
  bump.
- **2026-06-23, Amendment 11 — Host-Profile Advertisement.** Added the OPTIONAL
  `profiles[]` document member (§1, §13.1), its projection (§13.2), the
  `GET /papi/profiles` endpoint (§4, §13.3), the `profiles` discovery resource
  (§4.1), and the §4.2 envelope update (projected-list count `seven`→`eight`).
  Advertises the host profiles (flakerefs to `nixosConfigurations` /
  `homeConfigurations`) a staged host installer activates, gated like every other
  node so a subject's host set stays scoped to authenticated callers. In the
  staged installer it is the PAPI **datasource** the framework reads — after the
  card-auth stack is up — to select and activate a host profile; the installer's
  phase model is specified in a separate RFC. Additive and OPTIONAL — no version
  bump. The consuming side is the amarbel-llc/papi client (a planned `papi
  profiles`) and the papi-built installer framework.
- **2026-06-23, Amendment 12 — Host-profile system+home pairing + auth cross-ref.**
  Added the OPTIONAL `home_flakeref` member to a `profiles[]` entry (§13.1): a
  NixOS host profile is a pair — the `nixosConfiguration` (`flakeref`, system) and
  a **standalone** `homeConfiguration` (`home_flakeref`, applied via `home-manager`,
  not the NixOS module) — so one entry carries both targets, while a
  `home-configuration` entry is itself the home layer and carries no
  `home_flakeref`. Also added a §13.2 cross-reference noting a §5 session MAY be
  satisfied by direct PIV-card access (`pivy-box`) without a running agent (the
  staged installer's path, RFC-0003 §4). Resolves the eng-side line-level review's
  system+home gap. Additive and OPTIONAL — no version bump.
- **2026-06-24, Amendment 13 — Certificate-signature §5 proof (cardless auth).**
  Added §5.4: a second §5 proof type alongside the slot-9D decrypt proof — a
  cardless caller signs the challenge with a provisioned OpenSSH **certificate**
  whose CA is the subject's published **slot-9A** key (verified by the §10.1 union
  match), valid and in-window. Serves cloud / headless / CI hosts with no card
  (local or forwarded). The path performs **no encryption** and so needs **no box
  backend**. Certificates SHOULD be short-lived (expiry = revocation); issuance
  requires the physical card acting as CA. Updated the §5 intro (two proof types),
  §5.1 (the challenge endpoint dispatches on `recipient` vs `method:"ssh-cert"`),
  and §4.1 (discovery MAY advertise the `ssh-cert` method). Future, not `papi/v0`:
  multiple redundant CA keys and a published KRL. Security considerations are
  inline in §5.4. Additive and OPTIONAL — no version bump. The reference consumer
  is the staged installer's `auth` stage (RFC-0003 §4).
- **2026-06-24, Amendment 14 — Sign-challenge §5 scheme (slot-9A signature).**
  Re-spec'd §5 around two discovery-advertised schemes: the new **sign-challenge**
  (slot-9A signs the domain-separated preimage `papi-auth-v1\n<identity-domain>\n
  <nonce>`, verified against the registered slot-9A auth-key markl id — no server
  crypto, no box backend) is now RECOMMENDED, and the original **decrypt-challenge**
  (slot-9D ebox) is retained as an OPTIONAL alternative. `auth.scheme` advertises
  which (`piggy-sign-challenge` | `piggy-challenge-response`). Introduced the markl
  purpose `papi-auth-sig-v1@ecdsa_p256_sig-…` (sibling of `papi-doc-sig-v1` /
  `papi-proof-sig-v1`); reframed §5.4 as the cardless variant of sign-challenge;
  updated §3 (registry keys on the slot-9A auth-key id; pubkey from the registry,
  never the caller), §4.1 (`auth.scheme`), the Introduction, and the §14 reservation
  (the slot-9A signature strategy once deferred to `papi/v1` is now the `papi/v0`
  default). Captured from a merged reference-server impl (site-linenisgreat
  sign-challenge, replacing the decrypt path the NFSN host cannot produce); mirrors
  the validator's `ecdsa_p256_sig` / `ssh_ecdsa_nistp256_pub` formats. Client signer
  tracked as papi#31. Additive (decrypt retained, discovery-negotiated) — no version
  bump.
- **2026-06-24, Amendment 15 — Session transport: header preferred.** Marked the
  §5.3 `?papi_session=` query-param session presentation **NOT RECOMMENDED** (query
  strings leak into access logs, `Referer`, and proxy caches), with the
  `Authorization: PiggySession` header RECOMMENDED; the query param stays defined
  as a last-resort fallback for deployments that strip the header. Tempered the
  Security Considerations "Authorization header transport" note accordingly. From
  the reference server defaulting to header-only sessions (site-linenisgreat).
  Clarification of an existing OPTIONAL transport — no version bump.
