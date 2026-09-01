---
status: exploring
date: 2026-09-01
promotion-criteria: >
  exploring → proposed: a concrete papi-sourced adoption mechanism for EXISTING
  repos is specified (which document member carries the roster/template, how a
  codemod consumes it, how it avoids the conformist↔just-us cycle) AND it is
  demonstrated to re-wire a real fleet repo's conformist setup from a single
  central change. Until then this is a captured desire with its constraints
  written down, NOT a commitment — the near-term fleet answer lives in the nix
  layer (conformist presets / templates), not papi's HTTP surface.
---

# papi as a conformist-config adoption channel

## Problem Statement

sasha wants to know whether "the conformist profile at papi.linenisgreat.com"
can be updated ONCE to push a dev-tooling convention change (concretely: the
just-us `justfile-*` linter roster) to the whole fleet, instead of hand-editing
~20 repos. That desire — papi as the central publication point for the house
dev-tooling posture (linter roster, pinned tool versions, scaffolding), which
consumers adopt from one place — is worth capturing as a tracked direction. This
record captures BOTH the vision AND a precise account of why it is not the
near-term fleet-flip path, so nobody re-derives the analysis. It is a captured
future direction with constraints to solve, not a commitment.

## Interface

### What papi already does here (real, shipped)

papi is a Personal API: a person/house publishes ONE canonical JSON document
(RFC-0001) answering machine-readable questions about themselves. It is NOT a
nix-module or config-distribution service, and it is itself a *consumer* of
conformist presets (its own `flake.nix` imports `conformist.lib.presets.eng`
via a hash-pinned `conformist` flake input, exactly like every other repo).

But papi is not disconnected from conformist distribution. RFC-0001 **§7 (Flake
Template Advertisement)** and **§8 (Template Resolution and Bootstrap)** already
define a real channel:

- a document MAY publish `templates[]`, each entry a `{ id, flakeref, … }` where
  `flakeref` is nix-resolvable, e.g. `github:amarbel-llc/conformist#eng`;
- `GET /papi/templates` serves the projected list;
- the reference consumer is **`conformist conform <domain>`**: it fetches a
  domain's PAPI, resolves a template, and `nix flake init -t <flakeref>`
  scaffolds a repo in the house style.

So papi ALREADY distributes conformist *scaffolding* to consumers — for **new**
repos. If the advertised `conformist#eng` template wires both the conformist
presets and the just-us roster (conformist's `templates/eng/` composes exactly
that today), then papi's §7/§8 channel already delivers the just-us roster to
any repo scaffolded via `conform <domain>`.

### The vision (not yet built)

Extend that scaffold-time channel into a fuller "adopt my conventions" surface:
papi publishes the canonical house dev-tooling posture as DATA — the linter
roster, the pinned tool versions (e.g. which just-us build supplies
`justfile-common.justPackage`), the template flakerefs — and fleet repos adopt
it from that one published source. This fits FDR-0011's "one model, many
projections" philosophy: the posture is data on the person-model, projected
through the auth handshake like everything else.

## Examples

Already real — scaffolding a NEW repo from the published template channel:

    $ conformist conform linenisgreat.com          # §8: resolve templates[] → nix flake init -t
    $ conformist conform linenisgreat.com#eng       # select a specific template id

The vision — a fleet repo re-adopting the current published posture centrally
(NOT built; the constraint below is why):

    $ conform --sync linenisgreat.com               # read published roster, re-wire THIS repo's flake

## Limitations

Why papi is NOT the near-term fleet-flip answer — the constraints a future
design must solve:

- **Nix category mismatch (the load-bearing one).** A repo's flake inputs and
  its `imports = [ … ]` list are hash-pinned SOURCE in that repo's
  `flake.nix`/`flake.lock`, evaluated offline and reproducibly. No runtime HTTP
  service — papi included — can inject imports or config into N repos' flake
  evaluations without editing those N repos. papi serves a runtime document; nix
  consumes build-time locked source. "Flip the fleet with one HTTP update" is
  incompatible with nix's reproducibility model, independent of papi.
- **The template channel is PULL-at-scaffold, not PUSH-into-existing.** §7/§8
  bootstrap a repo at `nix flake init` time. They cannot re-wire an
  already-initialized repo. The ~20 repos that need the just-us roster flip are
  exactly the EXISTING population papi's template channel does not reach.
- **papi-as-nix-aggregator is the wrong home.** Even if papi's flake re-exported
  a combined preset, ~no fleet repo imports papi, so adoption would STILL require
  the ~20-repo sweep (add a papi input + switch imports) and would wrongly couple
  every repo's dev-tooling to papi (a heavy, semantically unrelated input).

### Constraints to solve (the path to viability)

For papi to serve the EXISTING-repo case, the only viable shape is
**papi-as-source-of-truth DATA + a codemod as the injector**: papi publishes the
canonical roster/template/versions; a fleet tool (`conform`'s brownfield splice,
fixed to re-wire repos that ALREADY have conformist wiring — today its `eval`
let-binding is its own idempotency sentinel and it skips them) reads that data
and rewrites each repo's flake. Still per-repo edits, but centrally SOURCED —
one authoritative change, mechanically applied. Two properties any such design
must preserve:

- **Dodge the conformist↔just-us cycle by composing at the TEMPLATE, not in
  conformist's shared lib.** The template flakeref papi advertises is a normal
  flake that takes both `conformist` and `just-us` inputs and wires the roster +
  `justfile-common.justPackage` — no conformist→just-us edge, and the consumer's
  flake.lock keeps control of the just-us version (unlike an eval-time
  fixed-output fetch buried in conformist's library).
- **Supply `justPackage` per-system.** The just-us shared option is
  system-independent and cannot default to a per-system build; the composed
  template resolves it from `just-us.packages.${system}.default` at the consumer,
  which is the natural place that context exists.

## More Information

- RFC-0001 §7 (Flake Template Advertisement), §8 (Template Resolution and
  Bootstrap) — the existing papi↔conformist scaffolding channel and its
  reference consumer `conformist conform <domain>`.
- FDR-0011 (PAPI resources as consistent projections of one model) — the
  "one model, many projections" philosophy a published-posture surface would
  extend.
- just-us FDR-0003 (`--dump-format model`) — why the `justfile-*` linters moved
  into the just-us fork (they read a fork-only dump format; conformist cannot
  take a just-us input without a cycle), and the `lib.conformistPresets.justfile`
  + mandatory `linters.justfile-common.justPackage` adopter contract.
- conformist `nix/presets/eng.nix` — the current split: `presets.eng` carries
  the fork-free rules and documents the just-us pairing; the roster ships from
  just-us. conformist self-lints via a fixed-output source pin of just-us
  (`justUsSrc`/`justUsPkg` in its flake), the cycle-free pattern that inspired
  the "central injection" question this record answers.
- eng#280 — the justfile-linter rollout this adoption channel would enable.
- The near-term fleet-flip options (fold the roster into `conformist.lib.presets.eng`
  vs a separate preset vs the template-composition path) are a conformist-side
  decision, coordinated with the conformist maintainer; they are out of scope
  here and are NOT papi changes.
