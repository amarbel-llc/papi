---
status: exploring
date: 2026-06-22
promotion-criteria: >
  exploring → proposed: the broker interface + the scoped-secret tailnet-key node
  are specified (the state-mutating broker RFC §12.3 calls for) and the §5 box
  backend (papi#8) is live. proposed → experimental: papi mints a card-gated
  tailscale.com pre-auth key, delivers it as a scoped-secret ebox, and a host
  joins the tailnet with it. experimental → testing: an enrolled cold host joins
  automatically as a bootstrap stage, end to end. All gated on papi/v1 deps.
---

# Card-gated tailnet join during bootstrap

## Problem Statement

A host that carries an enrolled + provisioned YubiKey (FDR-0001) should
**automatically join the tailnet during bootstrap**, with the card as the only
credential — no separate tailnet login, no shared static auth key. The tailnet is
tailscale.com today and will move to **headscale run under circus**
(`amarbel-llc/circus`, the personal-cloud orchestrator); the design should make
that control-plane switch a configuration change, not a host change. This is a
`papi/v1`-class feature: it builds on surfaces RFC-0001 §12.3 reserves but defers
(the §5 box backend and scoped-secret retrieval). It is recorded here to explore
the shape, not to build now.

## Interface (explored)

Joining a tailnet unattended requires a **pre-auth key**. The design makes the
card *gate* obtaining one: **papi is a card-gated broker**.

    cold host (enrolled card)
       │  §5 box handshake (slot-9D ECDH)         ← proves card possession
       ▼
    papi ──mint/fetch pre-auth key──▶ control plane (tailscale.com API → circus/headscale)
       │  project it as a §12.3 scoped-secret ebox   ← encrypted to the card's slot-9D recipient
       ▼
    host decrypts locally with the card → `tailscale up --auth-key=<key>` → on the tailnet

### Properties

- **The card is the credential.** §5 (slot-9D box decrypt) proves card
  possession; the pre-auth key is delivered encrypted to that same slot-9D
  recipient — never plaintext on the wire (§5 / §12.3). Enroll + provision ⇒
  eligible to join, automatically. The durable identity is the card; the §5
  session is ephemeral (§5.2 TTL, §5.3 degrade-to-anonymous).
- **Control-plane-agnostic.** papi brokers a pre-auth key from a configured
  backend: the tailscale.com API (mint → `tailscale up --auth-key`) today,
  `headscale preauthkeys create` under circus later. The host-side flow is
  identical; the switch is a papi backend swap, not a host change.
- **A bootstrap stage.** This is the natural payload of the bootstrap *framework*
  (papi#23): after the host has papi + a one-off piggy agent + the tailscale
  client, the "join tailnet" stage runs §5 → ebox → `tailscale up`, then hands off
  to eng's provisioner. ACL **tags** on the key (e.g. `tag:enrolled`, derivable
  from the card CN/role — FDR-0001, papi#19) give the node its tailnet policy
  automatically.

## Dependencies

| Needs | Status |
|---|---|
| §5 box backend (the handshake/decrypt) | papi#8 — not live |
| §12.3 scoped-secret node class (ebox to an authenticated caller) | reserved, `papi/v1` |
| A broker that **mutates external state** (mints a key in tailscale/headscale) | §12.3 says this "would require its own RFC" — unwritten |
| circus / headscale control plane | future (circus) |
| Bootstrap framework + one-off agent | papi#23 |
| `tailscale up` in the provisioner | eng `bin/provision.sh` |

## Open questions

- **Broker interface** abstracted over tailscale.com vs headscale: key TTL,
  reusable vs one-time, ephemeral vs persistent nodes, tag derivation.
- **One-off agent doing the §5 decrypt on a cold host** — chicken-and-egg with
  the agent stack (cf. the HTTPS-not-SSH cold-clone constraint, FDR-0003).
- **Server-side key lifecycle** — pre-mint + rotate vs mint-per-§5-session.
- **Ordering** — the `tailscale` client must exist before the join (nix-installed,
  or a static tailscaled pulled early in the papi#23 sequence).
- **Trust scoping** — what an §5 session is allowed to broker, bounded per §12.3.

## Limitations

- **No `papi/v0` path.** Every dependency above is deferred; this FDR is design
  continuity, not a buildable plan.
- **State-mutating surface.** The broker mints credentials in an external system —
  exactly the kind of surface papi has deliberately kept out of v0. §12.3 requires
  it to have its own RFC before it can be specified, let alone built.

## More Information

- [papi#24](https://github.com/amarbel-llc/papi/issues/24) (this FDR's request),
  papi#23 (bootstrap framework), papi#22 (piggy `pass`→papi over JSON-RPC — the
  agent/interaction channel), papi#8 (box backend).
- FDR-0001 (enrollment), FDR-0003 (`/papi/bootstrap`).
- RFC-0001 §5 (auth handshake), §12.3 (scoped secrets + general AUTH-against-PAPI).
- `amarbel-llc/circus` (headscale host); tailscale.com API / headscale
  `preauthkeys`.
