# papi justfile. Conventions: conformist-justfile(7). `default` is the read-only
# CI lane; `just` passing means the tree is conformant. Build-*/test-* aggregates
# get added (and wired into `default`) as the validator lands.

default: lint

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
# to the `lint` aggregate above once those exist. Runs conformist from the
# devShell (direnv `use flake`).
lint-worktree:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg=$(nix build --no-link --print-out-paths '.#conformist-impure-config')
    conformist check --config-file "$cfg" --tree-root .

# --- codemod ---

codemod-fmt: codemod-fmt-tree

# Format the tree in place (repair mode) via `nix fmt`.
codemod-fmt-tree:
    nix fmt
