---
status: exploring
date: 2026-09-15
promotion-criteria: >
  exploring → proposed: a madder session agrees the blob-store plugin contract
  (how a plugin is named, handed a store's host, fetches a digest, and reports
  a digest mismatch) and how a PAPI document declares a store; the gated-blob
  question under Limitations is resolved; and one existing leaf (e.g.
  /papi/pigpen) is specified end to end as a blob with its papi/v0 raw-path
  alias. Until then this is a captured papi/v1 direction, not a commitment.
---

# PAPI leaf nodes as content-addressed blobs

## Problem Statement

PAPI mixes two response shapes: JSON nodes in the §4.2 `{data, meta}` envelope,
and a growing set of raw leaf documents at fixed paths (`/papi/piggy-ids`,
`/papi/ssh-authorized-keys`, `/papi/bootstrap`, `/papi/pigpen`,
`/papi/conformist-profile`). Every client and `papi validate` must know by path
which shape to expect, so each new leaf means another special case: the
pigpen/bootstrap bug fixed in cf8e0b5 was exactly a missing entry in that
per-path table. Leaves also get integrity only when they carry their own
signature (§14, §15), and nothing makes them cacheable by content.

## Interface

A `papi/v1` direction with two node kinds:

- **Parent (metadata) nodes** stay enveloped JSON, projected through §2 as today.
- **Leaf nodes** become opaque blobs. A parent node references each leaf by its
  markl-id **digest** and **media type** instead of embedding or path-addressing
  it.

The PAPI instance's own document declares where its blobs live:

- one or more **blob stores**, each naming a **blob-store plugin kind** and a
  **host** (or base) for that plugin to reach;
- no hostname is baked into papi or the plugin — the store entry supplies it,
  so any PAPI instance can point at its own blob host.

A client resolving a leaf:

1. reads the parent JSON node and takes the leaf's digest and media type;
2. selects a blob store from the instance's document and hands its host to the
   named plugin;
3. the plugin resolves the host, downloads the blob by digest, and **verifies
   the bytes hash to the digest** before returning them;
4. the client interprets the bytes by media type (e.g. a §15 signed hyphence
   document, still verified by its own signature).

`papi validate` collapses to one rule: JSON nodes must be enveloped; blobs must
hash to their digest.

The plugin and the store declaration are madder's design space (madder
blob-store(7), blob-store-multi(7)); papi states only what it needs from them.

## Examples

Illustrative only — every member name and the digest format below are
placeholders pending the madder design.

A parent node referencing a leaf:

    { "data": {
        "pigpen": { "digest": "<markl-id digest>", "media_type": "text/vnd.pigpen" }
      },
      "meta": { "type": "pigpen", "visibility": "public" } }

The instance declaring its blob store, host-agnostic:

    "blob_stores": [
      { "id": "primary", "plugin": "<madder papi plugin kind>",
        "host": "<the instance's blob host>" }
    ]

A client fetching the leaf:

    parent node → digest + media type
    blob_stores[primary] → plugin(host) → GET blob by digest → verify hash
    → bytes (text/vnd.pigpen) → §14.2 self-signature check as today

Unchanged for papi/v0 clients:

    curl -fsSL https://<domain>/papi/bootstrap | sh
    papi pigpen resolve <domain>

## Limitations

- **papi/v0 raw paths stay.** `curl | sh` bootstrap, piggy's use of
  `/papi/piggy-ids`, the pigpen resolver, and conformist's profile fetch all
  expect a raw body at a fixed path. They remain as aliases serving the same
  bytes; the blob model is additive in v1, not a replacement of v0.
- **A digest pins content.** Updating a leaf changes its digest, so the parent
  node referencing it must be rewritten and re-served (and re-signed, where the
  parent is covered by §10).
- **Integrity is not authorship.** A digest proves the bytes match what the
  parent node named, not who wrote them. §14/§15 document signatures still apply
  to signed leaves, and trust in the parent node still comes from §10 or the
  host.
- **Gated leaves — open question.** §2 projects parent nodes, so an anonymous
  caller never sees a gated leaf's digest. Either blob fetch by digest must also
  be §5-gated for gated content, or blobs are treated as public-by-digest and
  gated content must never become a blob. Unresolved.
- **Not content negotiation.** Serving several formats per endpoint via
  `Accept` was considered for v0 and deferred as OPTIONAL; this record does not
  depend on it.
- **No madder API is specified here.** Plugin naming, the fetch protocol, store
  configuration, and the digest format are to be settled with a madder session.

## More Information

- RFC-0001 §2 (projection), §4.2 (envelope and raw endpoints), §10 (document
  signature), §14 (pigpen), §15 (signed hyphence documents).
- papi cf8e0b5 — `papi validate`'s raw-endpoint table, the special-casing this
  model would retire.
- FDR-0011 (PAPI resources as consistent projections of one model) — parent
  nodes as projections, leaves as content.
- FDR-0015 (papi as a conformist-config adoption channel) — the conformist
  profile is one of the leaves this would cover.
- madder blob-store(7), blob-store-multi(7) — the owning design space for blob
  stores and plugins.
