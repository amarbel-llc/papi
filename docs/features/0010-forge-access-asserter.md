---
status: experimental
date: 2026-07-05
promotion-criteria: >
  experimental (option (a) implemented in papi; the `canary` forge member landed in
  RFC-0001 §1.1 as Amendment 19) → testing when a reference consumer — linenisgreat's
  canary gate — calls `papi forge check` in place of its hand-rolled assertion and the
  linenisgreat papi.json declares its `canary`; → accepted when circus's
  forge-public-plane-check also delegates its visibility assertion here and the
  "must-hide visibility set" lever has held steady for two weeks.
---

# Forge access asserter (`papi forge check`)

## Problem Statement

A forge's public read plane (circus FDR-0016: `forge.linenisgreat.com` serves an
anonymous, public-repos-only API, rendered into papi.json by the linenisgreat
read-through) makes "does a private repo leak anonymously?" a correctness property
every consumer wants to assert — and each is re-deriving it by hand. linenisgreat
hand-rolls a canary test (a `visibility:private` repo asserted absent from the
anonymous listing); a stale copy of that assertion already drifted, still asserting
the pre-public-flip invariant that anonymous *hides* the forgejo forge node, which
after the flip is legitimately visible. PAPI already models forges (RFC-0001 §1.1)
and consumes the public projection, so it should own one shared check that
reconciles what a domain **declares** about forge/repo visibility against what is
**verified** to be anonymously accessible — callable by linenisgreat's test gate, a
circus canary, and any future consumer, instead of each re-deriving "which repo is
the canary and what a leak looks like."

## Interface

`papi forge check <domain> [--forge <id>] [--auth-key-id <id> | --recipient <id> --decrypt-cmd <cmd>]`

Data-driven from the domain's PAPI document — the consumer supplies no per-forge
knowledge. Output is the `papi validate` NDJSON point stream (`ok` / `must-fail` /
`skip`); the process exits nonzero on any MUST failure.

**Verified source — option (a), papi's anonymous projection.** "Verified anonymous
access" means what the domain's own **anonymous `/papi` projection** exposes:
`GET /papi/forges` and `GET /papi/repos` with no session. This is deliberately
*not* the forge's raw upstream API (forgejo `/api/v1`, …): the projection is
identical across forge kinds, so the check is **forge-agnostic by construction** —
the property the issue asks for — and it reuses the existing client plus the
projection machinery in `internal/alfa/inspect` (`privateHuskPoint`, `scopedPoints`).
The trade-off (drift between papi.json and the *live upstream forge* is not caught)
is recorded under Limitations and is the seam for a later option (b).

**The `canary` forge member.** A forge entry MAY carry an optional public member

    "canary": "<owner>/<private-repo-name>"

naming a repo that is published `visibility:private` on that forge. The member
lives on the **public** forge entry (visible in anonymous `/papi/forges`) precisely
so a **card-free** checker can learn the canary's name and then assert that name is
absent from the anonymous `/papi/repos`. This is what makes the shared gate runnable
with no credentials. (Inferring canaries from `visibility:private` repos instead was
rejected: it requires the authenticated view to know the private set, which defeats
the anonymous-canary use case.) Standardizing the member is a one-line RFC-0001 §1.1
amendment; it is additive and OPTIONAL, so no version bump.

**Two tiers of assertion:**

- **Anonymous floor (no credentials).** For the target forge, read its declared
  `canary` from anonymous `/papi/forges`, then MUST-fail if that repo appears in
  anonymous `/papi/repos` (a private-repo leak — the shared, card-free canary gate).
- **Authenticated reconciliation (`--auth-key-id` / `--recipient`, one card op).**
  Fetch the full declared set (authed `/papi/forges` + `/papi/repos`) and the
  verified public set (anonymous), and MUST-fail if any of:
  - a repo the forge declares `visibility:public` is **absent** anonymously
    (declared-public but not verified-visible);
  - a repo the forge declares `visibility:private`/`scoped` (including the canary)
    is **present** anonymously (declared-private but leaked);
  - a forge node declared public does not surface anonymously, or a declared
    private/scoped forge node leaks into the anonymous forge list.

`--forge <id>` scopes the check to one forge entry; omitted, every forge in the
document is checked. Reachability: papi MAY resolve and reach a forge's canonical
name to confirm it answers, but MUST NOT assert any IP, port-firewall, or nginx
topology — those belong to circus (see Limitations / Layering).

## Examples

Card-free canary gate (the shared assertion linenisgreat's test calls):

    $ papi forge check linenisgreat.com --forge forgejo-krone-amarbel-llc
    ok    forge forgejo-krone-amarbel-llc: declared canary amarbel-llc/papi-private-canary absent from anonymous /papi/repos (§2.5)
    ok    forge forgejo-krone-amarbel-llc: forge node visible in anonymous /papi/forges (declared public)

A leak is a hard failure with a nonzero exit:

    $ papi forge check linenisgreat.com --forge forgejo-krone-amarbel-llc
    FAIL  forge forgejo-krone-amarbel-llc: canary amarbel-llc/papi-private-canary LEAKED into anonymous /papi/repos (§2.5)
    $ echo $?
    1

Full declared-vs-verified reconciliation with a card:

    $ papi forge check linenisgreat.com \
        --auth-key-id piggy-piv_auth-v1@ssh_ecdsa_nistp256_pub-…
    ok    forge forgejo-krone-amarbel-llc: 12 declared-public repos all anonymously visible
    ok    forge forgejo-krone-amarbel-llc: 3 declared-private repos (incl. canary) all anonymously hidden
    ok    forge github-primary: declared public, surfaces anonymously

## Limitations

- **v0 verifies papi's own projection, not upstream drift.** Option (a) checks that
  the domain's anonymous `/papi` projection is self-consistent with its declarations.
  It does **not** re-query the live upstream forge API, so a papi.json that has gone
  stale relative to the upstream forge (a repo made private upstream but still
  rendered public in papi.json) is not caught. That stronger check is option (b) —
  a forge-public-API client with per-kind adapters — deliberately deferred: it fights
  the forge-agnostic goal and pulls in a reachability boundary, so it earns its own
  phase once (a) is in use.
- **Topology and deployment are out of scope (layering).** papi owns read-through /
  visibility correctness only. Whether public DNS resolves the canonical name to the
  expected address (and not a tailnet address), whether `:2222` is firewall-dropped,
  and the nginx allowlist matrix are **circus**'s concern (a `forge-public-plane-check`
  recipe), which delegates the visibility half to this papi check. papi may reach the
  canonical name to confirm liveness but hardcodes no IP/firewall/nginx facts.
- **The canary is a single named repo per forge.** The member names one canary; a
  forge wanting several private-leak canaries lists the most representative. The
  authenticated tier already asserts the *whole* declared-private set is hidden, so
  the named canary is the card-free spot-check, not the exhaustive one.

## Tuning Levers

| Lever | Current | Rationale | Change signal |
|---|---|---|---|
| must-hide visibility set | `private`, `scoped` | anything not `public` must not appear in the anonymous projection (§2.5) | a new visibility value is added to RFC-0001 §2 that should also be anonymously hidden |
| default forge scope | all forges when `--forge` omitted | a domain-wide check is the useful default for a periodic canary | domains routinely carry forges a consumer wants to exclude |

## More Information

- amarbel-llc/papi#48 — the proposal this record settles.
- RFC-0001 §1.1 (forge model) and §2.5 (private-node projection) — the `canary`
  member is a planned additive §1.1 amendment (OPTIONAL, no version bump).
- Builds on `internal/alfa/inspect/check.go` (`privateHuskPoint`, `scopedPoints`) and
  the anonymous/authed fetch split already used by `papi validate` and `papi repos`.
- circus `docs/features/0016-forgejo-public-read-plane.md` — the public read plane
  this reconciles; its `forge-public-plane-check` recipe delegates the visibility
  half here. Reference consumers to converge: linenisgreat's canary gate and
  `test-papi-prod-live`.
- Future direction: a periodic (`--cron`) canary mode for standing drift detection,
  and option (b) — live upstream-forge reconciliation — as a later phase.
