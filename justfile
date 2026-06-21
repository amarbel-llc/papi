# papi justfile. Conventions: eng-design_patterns-justfile(7), eng-versioning(7),
# conformist-justfile(7). `default` is the local CI lane (also the
# merge-this-session pre-hook). Bare-verb recipes are aggregates; leaves are
# verb-noun.

default: lint build test

# --- lint ---

lint: lint-fmt

# Read-only formatting + the eng preset's file-based linters, via the sandboxed
# checks.formatting derivation.
lint-fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.formatting" --no-link --print-build-logs

lint-impure: lint-worktree

# The impure eng checks (git remotes, sweatfile, agents-md) against the working
# tree, where .git is available. Needs SSH remotes + a sweatfile; add lint-impure
# to the `lint` aggregate above once those exist.
lint-worktree:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg=$(nix build --no-link --print-out-paths '.#conformist-impure-config')
    conformist check --config-file "$cfg" --tree-root .

# --- build ---

build: build-gomod2nix build-go build-nix

# Regenerate gomod2nix.toml from go.mod/go.sum. A no-op when current; run after
# changing deps. (conformist-justfile(7): a build-* leaf lives in the build
# aggregate.)
build-gomod2nix:
    nix develop --command gomod2nix

# Out-of-nix go build for a fast inner loop. Version stays dev/unknown here; the
# nix build injects the real values (eng-versioning(7)).
build-go:
    nix develop --command go build -o build/papi .

# Full nix build of the papi CLI (injects the real version/commit).
build-nix:
    nix build --no-link --print-build-logs .#papi

# --- test ---

test: test-go

# Hermetic Go test suite (httptest fixtures; no network, no card).
test-go:
    nix develop --command go test ./...

# Regenerate the committed sample enrollment receipt fixture
# (internal/alfa/enroll/testdata/) — a hand-off artifact for the deploy-side
# verify recipe (site-linenisgreat). Normal `test-go` skips this generator.
[group("debug")]
debug-sample-receipt:
    PAPI_GEN_SAMPLE=1 nix develop --command go test ./internal/alfa/enroll/ -run TestGenerateSampleReceipt -v

# --- codemod ---

codemod-fmt: codemod-fmt-tree

# Format the tree in place (repair mode) via `nix fmt`.
codemod-fmt-tree:
    nix fmt

codemod-reposition: codemod-reposition-go

# Rebalance internal/ package tiers by dependency depth via dagnabit (from
# purse-first; on the devShell PATH). Run after adding or moving packages;
# preview with `nix develop --command dagnabit -n internal`. The one-time
# initial tiering of the flat layout used `dagnabit --initial internal`.
codemod-reposition-go:
    nix develop --command dagnabit internal

# --- maintenance ---

# `go mod tidy`, then regenerate gomod2nix.toml (the && dependency).
update-go: && build-gomod2nix
    nix develop --command go mod tidy

# Rewrite PAPI_VERSION in version.env (pure mutation; `release` stages + commits).
[group("maintenance")]
bump-version new_version:
    sed -E -i "s/^(export PAPI_VERSION)=.*/\1={{new_version}}/" version.env

# Create + push a signed annotated v<sem> tag from version.env, then verify it.
[group("maintenance")]
tag $message:
    #!/usr/bin/env bash
    set -euo pipefail
    . version.env
    tag="v${PAPI_VERSION:?missing PAPI_VERSION in version.env}"
    git tag -s -m "$message" "$tag"
    gum log --level info "Created tag: $tag"
    git push origin "$tag"
    gum log --level info "Pushed $tag"
    git tag -v "$tag"

# Full release from master (eng-versioning(7)): changelog -> idempotent
# bump+commit -> signed tag -> gh release.
[group("maintenance")]
release new_version:
    #!/usr/bin/env bash
    set -euo pipefail
    branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$branch" != "master" ]]; then
        gum log --level error "release only allowed from master (on '$branch')"
        exit 1
    fi
    prev=$(git tag --sort=-v:refname -l "v*" | head -1)
    header="release v{{new_version}}"
    if [[ -n "$prev" ]]; then
        summary=$(git log --format='- %s' "$prev"..HEAD)
        msg="$header"$'\n\n'"$summary"
    else
        msg="$header"
    fi
    . version.env
    if [[ "${PAPI_VERSION:-}" != "{{new_version}}" ]]; then
        just bump-version "{{new_version}}"
        git add version.env
        git commit -m "$header"
    else
        gum log --level info "version.env already at {{new_version}}; skipping bump/commit"
    fi
    just tag "$msg"
    gh release create "v{{new_version}}" --title "$header" --notes "$msg"
