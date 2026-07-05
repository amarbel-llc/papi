---
status: experimental
date: 2026-07-05
promotion-criteria: >
  experimental (`papi validate` reconciles /papi/repos ⟷ /papi/forges as SHOULD
  verdicts — forge-provenance resolution + clone-channel reachability) → testing when
  the invariants are pinned in an RFC-0001 amendment (so the check MUST-fails on drift)
  and, replayed against the pre-fix papi#50 shape, it flags it. testing → accepted when
  it has caught or cleared a real projection change in the wild and the reconciled-
  endpoint set has held steady for two weeks.
---

# PAPI resources as consistent projections of one model

## Problem Statement

RFC-0001 defines `/papi` (the full document) and several sub-endpoints —
`/papi/repos`, `/papi/forges`, `/papi/organizations`, … — that expose overlapping
data (a domain's repositories, viewed flattened, by forge, and by organization). It
never states how these views relate: whether they must agree, which is authoritative,
or that a flattened repo's `forge` provenance must name a real forge. A server is free
to materialize each view independently, and the reference server did: `/papi/forges`
publishes forge nodes with empty `repos[]` while the same repositories appear in the
flattened `/papi/repos` — the divergence behind papi#50, where `--url` read one view
and silently missed every repo the other carried. The views are two renderings of one
dataset, but nothing makes them consistent, and nothing lets a client or validator
detect when they drift.

## Interface

**The principle.** `/papi` is the single canonical model. Every sub-endpoint is a
**pure projection** of it — a pre-materialized static view, not an independently
sourced resource. This is GraphQL's "one graph, many views" discipline applied to a
**static** document; it is deliberately **not** GraphQL (no query language, no
server-side resolver), because PAPI's whole value is a cacheable, `curl`-able,
statically-hostable document that a query engine would break. The sub-endpoints are
best understood as pre-rendered common queries over the one model, required to stay
consistent with it.

**The invariants** (to be pinned in an RFC-0001 amendment):

- `/papi/forges` ≡ the document's `forges[]`; `/papi/organizations` ≡ its
  `organizations[]` — each the §2-projected array, member-for-member.
- `/papi/repos` is the **authoritative** flattened repository set: the union of the
  repos reachable from `forges[]` and `organizations[]`, each entry
  provenance-annotated. A repository's existence is defined by its presence here.
- Every `/papi/repos` entry's `forge` **MUST** resolve to a `forges[].id`. This is
  the join key that makes clone-channel synthesis total (the papi#50 fix) and makes a
  repo's provenance verifiable.
- A `forges[]` (or `organizations[]`) entry's own `repos[]` **MAY** be empty or a
  subset: a forge/org node MAY be a platform or read-through **anchor** (identity +
  clone channel) whose repositories are enumerated only into the flattened
  `/papi/repos`. Emptiness there is legal; a dangling `forge` provenance in
  `/papi/repos` is not.

**The validator reconciliation check.** `papi validate` gains a conformance pass that
fetches `/papi` plus the projected sub-endpoints and asserts the invariants — a
MUST-fail on any drift:

- a `/papi/repos` entry whose `forge` resolves to no `forges[].id` (dangling
  provenance);
- a sub-endpoint's projection disagreeing with the corresponding `/papi` member;
- the papi#50 shape — a repo present in the flattened view but structurally
  unreachable from the join a sibling view feeds (e.g. no forge clone channel).

The check turns "these are consistent views" from a hope into an enforced,
automatically-detected property: it would have flagged the linenisgreat github-drop
the instant it deployed, instead of it silently eating ~30 repos from a downstream
cascade.

## Examples

A conformant domain — the projections reconcile:

    $ papi validate linenisgreat.com
    …
    ok    projections: /papi/forges == the document's forges[] (§4)
    ok    projections: /papi/repos flattens the document's forge + org repos (§4)
    ok    projections: every /papi/repos entry resolves its forge to a forges[].id (§1.1)

The papi#50 drift shape is caught rather than silently tolerated:

    $ papi validate linenisgreat.com
    …
    FAIL  projections: 19 /papi/repos entries name forge "github-primary" with no clone channel reachable from /papi/forges (§1.1)

## Limitations

- **Intra-document consistency only.** This reconciles a domain's own PAPI views
  against each other. It does not check them against the *live upstream forge* (a
  papi.json gone stale relative to github/forgejo); that is FDR-0010's option (b), a
  separate concern with its own reachability boundary.
- **Requires an RFC amendment to be normative.** This FDR proposes the invariants;
  they become MUST-level — and the validator's authority to fail on them — only once
  landed as an RFC-0001 amendment. Until then the check can warn (SHOULD) rather than
  fail.
- **Projection, not byte-equality.** The check asserts the *relationships*
  (membership, join-resolvability), not byte-identity of overlapping fields — a server
  MAY carry extra members on one view (RFC-0001 §1.1 forward-compat) as long as the
  projections still reconcile.

## More Information

- amarbel-llc/papi#50 — the drift this design durably prevents; its client-side
  `--url` fix (sourcing the flattened `/papi/repos` and joining clone channels by
  forge id) is the interim floor this makes unnecessary to rediscover per-consumer.
- RFC-0001 §1.1 (forge/organization model), §2 (projection), §4 (endpoints) — the
  invariants are a planned additive amendment.
- FDR-0010 (forge access asserter) — a sibling that also reconciles declared vs
  verified projection; both are "reconcile PAPI's own views" checks and SHOULD share
  the `internal/alfa/inspect` projection machinery.
