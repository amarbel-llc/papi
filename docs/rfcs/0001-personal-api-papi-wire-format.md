---
status: proposed
date: 2026-06-16
amended: 2026-06-17
amendments: 3
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
| `templates[]`     | array  | Advertised nix flake templates for repo bootstrap (see §7).               |
| `proofs[]`        | array  | Bidirectional identity-ownership proofs (see §9).                          |
| `signature`       | object | Detached signature binding the document to a published key (see §10).      |
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
| GET    | `/papi/templates`           | projected `templates[]`, JSON               | projected          |
| GET    | `/papi/proofs`              | projected `proofs[]`, JSON                  | projected          |
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
  `/papi/organizations`, `/papi/sitemap`, (when the document advertises
  templates, §7) `/papi/templates`, and (when the document advertises proofs,
  §9) `/papi/proofs`, and
- `auth` — `{scheme: "piggy-challenge-response", challenge, response,
present_session_as}`, where `challenge`/`response` are absolute URLs.

When the document carries a `signature` (§10), the discovery document MUST
additionally expose a `signature` member equal to the document's `signature`
object, so a client can verify document authorship (§10.3) from the always-public
discovery response without first fetching `/papi`.

The discovery document MUST always be public (it is not projected).

#### 4.2. Response envelope

JSON endpoints MUST wrap their payload in the envelope:

    { "data": <payload>, "meta": { "count": <int>, "type": "<string>", ... } }

`/papi` MUST add `meta.version` and `meta.visibility`. The five projected-list
endpoints (`/papi/forges`, `/papi/repos`, `/papi/organizations`, `/papi/sitemap`,
`/papi/templates`) MUST add `meta.visibility`. `meta.visibility` MUST be
`"public"` for the anonymous principal and `"scoped"` for an authenticated
principal.

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
- `"signature"` — the document at `proof_uri` MUST contain a piggy slot-9A SSH
  signature (or the §10 detached signature) over the exact string `claim`,
  verifiable against an `ssh_authorized_keys[]` entry or the `recipient`. This
  upgrades a presence check to a cryptographic one for services that allow longer
  free-form content.

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
carries no evidence of who authored it. The OPTIONAL `signature` member makes the
document **self-certifying** — verifiable against a published key rather than
against the host that served it, the second portability property §9 named.

#### 10.1. `signature`

The OPTIONAL top-level `signature` member is a JSON object with:

| Member      | Type   | Required | Meaning                                                                                |
| ----------- | ------ | -------- | -------------------------------------------------------------------------------------- |
| `alg`       | string | MUST     | Signature algorithm: `"ssh-9a"` (piggy slot-9A SSH signature) in `papi/v0`.             |
| `key`       | string | MUST     | The verifying public key: an `ssh_authorized_keys[]` entry or a published `recipient`.  |
| `sig`       | string | MUST     | Base64 detached signature over the canonical signing input (§10.2).                     |
| `created`   | int    | SHOULD   | Unix-seconds the signature was produced.                                               |

A verifier MUST skip a `signature` whose `alg` it does not understand (treating
the document as unsigned, §10.3) rather than fail. `key` MUST appear in the
document's published `ssh_authorized_keys[]` or `piggy.encryption_recipients[]`; a
`key` outside both is **unverifiable** and the document MUST be treated as
unsigned.

#### 10.2. Signing input (canonicalization)

The signature covers the document **with the `signature` member removed**: a
signer MUST delete the top-level `signature` key, serialize the remaining document
by [RFC 8785] JSON Canonicalization Scheme (JCS) — lexicographically sorted keys,
no insignificant whitespace, canonical number forms — and sign the resulting UTF-8
bytes. A verifier reconstructs the identical bytes by removing `signature` and
re-canonicalizing before checking `sig`. The signature is computed over the
**source** document (pre-projection), so it is stable across principals; a verifier
MUST therefore verify the signature against `/papi` requested **anonymously** (or
against the discovery `signature`, §4.1), not against a projected response, whose
dropped private nodes would not match the signed bytes.

#### 10.3. Verification

A verifier that finds a `signature` (in the discovery document, §4.1, or on an
anonymous `GET /papi`) MUST: confirm `alg` is understood and `key` is published
(§10.1); reconstruct the §10.2 signing input; and verify `sig` over those bytes
with `key`. The outcome is one of **signed-and-valid**, **signed-but-invalid**
(report prominently; a present-but-broken signature is a stronger negative signal
than no signature), or **unsigned** (no `signature`, or an `alg`/`key` the verifier
cannot use). A verifier MUST NOT treat an unsigned document as invalid — signatures
are OPTIONAL — but SHOULD surface the distinction so a consumer can require
signed documents in higher-trust contexts.

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
`signature` member first, will reject valid documents or — worse, if it is lenient
about trailing data — accept manipulated ones. Verify only over the JCS bytes of
the signature-stripped source document.

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
| §10, signature serving       | `test-papi.php`                 | `signature` echoed in discovery (§4.1); stripped from signing input |

A future re-implementation in another language SHOULD be able to satisfy the same
HTTP-level suite (`test-papi.sh`) unchanged, since it exercises only the wire
contract.

The **verification** side of §9.4 and §10.3 — fetching `proof_uri`, checking the
backlink, and verifying the `signature` — is the introspection/validation tool's
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
- The `proofs[]` member and the `/papi/proofs` endpoint (§9), and the `signature`
  member (§10), are additive OPTIONAL extensions within `papi/v0` on the same
  footing: a document without them is unchanged, a client predating §9–§10 ignores
  the members and the endpoint, and the discovery `proofs`/`signature` fields
  appear only when the document advertises them. No version bump is required.
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
- [RFC 8785] Rundgren, A., Jordan, B., Erdtman, S., "JSON Canonicalization Scheme
  (JCS)", RFC 8785, June 2020. Normative for the §10.2 signing input.
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
