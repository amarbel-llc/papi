# papi justfile. Conventions: eng-design_patterns-justfile(7), eng-versioning(7),
# conformist-justfile(7). `default` is the local CI lane (also the
# merge-this-session pre-hook). Bare-verb recipes are aggregates; leaves are
# verb-noun.

default: lint build test

# --- lint ---

lint: lint-fmt

# Read-only formatting + the eng preset's file-based linters, via the sandboxed
# checks.formatting derivation.
#
# run the read-only formatting and file-based lint checks
lint-fmt:
    #!/usr/bin/env bash
    set -euo pipefail
    system=$(nix eval --raw --impure --expr 'builtins.currentSystem')
    nix build ".#checks.${system}.formatting" --no-link --print-build-logs

lint-impure: lint-worktree

# The impure eng checks (git remotes, sweatfile, agents-md) against the working
# tree, where .git is available. Needs SSH remotes + a sweatfile; add lint-impure
# to the `lint` aggregate above once those exist.
#
# run the impure conformist checks against the working tree
lint-worktree:
    #!/usr/bin/env bash
    set -euo pipefail
    cfg=$(nix build --no-link --print-out-paths '.#conformist-impure-config')
    conformist check --config-file "$cfg" --tree-root .

# --- build ---

build: build-gomod2nix build-go build-wasm build-wasm-client build-nix build-ts build-installer

# Regenerate gomod2nix.toml from go.mod/go.sum. A no-op when current; run after
# changing deps. (conformist-justfile(7): a build-* leaf lives in the build
# aggregate.)
#
# regenerate gomod2nix.toml from go.mod/go.sum
build-gomod2nix:
    nix develop --command gomod2nix

# Out-of-nix go build for a fast inner loop. Version stays dev/unknown here; the
# nix build injects the real values (eng-versioning(7)).
#
# build the papi CLI out-of-nix into build/papi
build-go:
    nix develop --command go build -o build/papi .

# Cross-build the network-free receipt-verify core to a wasip1 WASM module
# (cmd/papi-verify-wasm, FDR-0002) for php-wasm native verification. In `build` so
# the merge pre-hook enforces that the verify core stays free of the enroll TUI
# subtree (huh→termenv→terminfo→os/user) that blocks a wasip1 compile.
#
# cross-build the receipt-verify core to a wasip1 WASM module
build-wasm:
    nix develop --command env GOOS=wasip1 GOARCH=wasm go build -o build/papi-verify.wasm ./cmd/papi-verify-wasm
    @ls -lh build/papi-verify.wasm

# Cross-build the network-free client core (cmd/papi-client-wasm, FDR-0007) to a
# js/wasm module — the decode/verify surface a TS/zx wrapper drives via Go's
# wasm_exec.js (copied beside the wasm; the loader reads it as a sibling). js/wasm
# rather than wasip1 because Bun's node:wasi cannot instantiate a Go wasip1 module
# (FDR-0007). In `build` so the merge pre-hook keeps the client core wasm-able (no
# TUI/os.user import).
#
# cross-build the client core to a js/wasm module plus wasm_exec.js
build-wasm-client:
    nix develop --command env GOOS=js GOARCH=wasm go build -o build/papi-client.wasm ./cmd/papi-client-wasm
    @install -m 0644 "$(nix develop --command go env GOROOT)/lib/wasm/wasm_exec.js" build/wasm_exec.js
    @ls -lh build/papi-client.wasm build/wasm_exec.js

# full nix build of the papi CLI (injects the real version/commit)
build-nix:
    nix build --no-link --print-build-logs .#papi

# Build the zero-dep papi-client-ts flake output (FDR-0007): the js/wasm core +
# wasm_exec.js + papi.ts staged into one store path. Validates the derivation in
# the build lane; `test-ts-bundle` smokes the result.
#
# build the papi-client-ts flake bundle
build-ts:
    nix build --no-link --print-build-logs .#papi-client-ts

# Build the staged host installer binary (FDR-0006): a static, CGO-free
# papi-installer. Validates the flake package in the build lane; the engine + the
# headless run are covered by `test-go`.
#
# build the static papi-installer binary
build-installer:
    nix build --no-link --print-build-logs .#papi-installer

# --- test ---

test: test-go test-grammar test-ts test-ts-bundle test-nix-hm-module test-nix-oracle-module test-nix-verifier-module

# hermetic Go test suite (httptest fixtures; no network, no card)
test-go:
    nix develop --command go test ./...

# Enforced pigpen grammar-conformance gate (papi#54/#58/#60): feed the
# SignPigpen fixture's metadata lines through langlang's parse of hyphence's
# canonical hyphence-content.peg. Hermetic — both the langlang binary and the
# grammar come from flake inputs (.#langlang / .#hyphence-content-grammar,
# an SSH-auth git+ssh langlang fetch + the public hyphence tarball), so no
# sibling ~/eng/repos checkout is needed. The test skips gracefully in plain
# `test-go` (no env set); this recipe is what makes it fail on a real
# regression.
#
# .#hyphence-content-grammar is a STAGING DIRECTORY, not a bare .peg (papi#72):
# hyphence-content.peg `@import`s piggy's marklid.peg, which langlang resolves
# relative to the importing file, so both sit side by side in it.
#
# run the pigpen grammar-conformance gate against hyphence-content.peg
test-grammar:
    #!/usr/bin/env bash
    set -euo pipefail
    langlang_bin="$(nix build .#langlang --no-link --print-out-paths)/bin/langlang"
    grammar="$(nix build .#hyphence-content-grammar --no-link --print-out-paths)/hyphence-content.peg"
    nix develop --command env \
      LANGLANG_BIN="$langlang_bin" \
      PAPI_HYPHENCE_GRAMMAR="$grammar" \
      go test ./internal/alfa/inspect/ -run TestPigpenGrammarConformance -v

# Smoke-test the TypeScript client wrapper (clients/ts, FDR-0007): cross-build the
# js/wasm core, then run its bun tests, which drive the wasm via Go's wasm_exec.js
# (path handed in via $PAPI_CLIENT_WASM). Network-free — the fetch-based Client is
# not exercised here.
#
# run the TypeScript client wrapper's bun tests against the js/wasm core
test-ts: build-wasm-client
    nix develop --command env PAPI_CLIENT_WASM="$PWD/build/papi-client.wasm" bun test clients/ts

# Smoke the distributed flake bundle (packages.papi-client-ts, FDR-0007): build it
# and import its papi.ts straight from the nix store with NO $PAPI_CLIENT_WASM, so
# papi.ts's default sibling resolution of the wasm + wasm_exec.js is exercised —
# the real consumer path test-ts does not cover.
#
# smoke the distributed papi-client-ts bundle from the Nix store
test-ts-bundle:
    #!/usr/bin/env bash
    set -euo pipefail
    out=$(nix build --no-link --print-out-paths .#papi-client-ts)
    nix develop --command env PAPI_CLIENT_TS_DIR="$out" bun clients/ts/bundle-smoke.mjs

# Smoke-test the `services.papi-ssh-sync` home-manager module: evaluate it
# against synthetic configs (lib.evalModules, no home-manager input) and verify
# the option schema, both platform code paths, the default fragment-path slug,
# and the assertions. Mirrors piggy's test-nix-hm-module.
#
# evaluate the services.papi-ssh-sync home-manager module against synthetic configs
test-nix-hm-module:
    #!/usr/bin/env bash
    set -euo pipefail
    expr='let
      flake = builtins.getFlake (toString ./.);
      pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
      test = import ./nix/hm/eval-test.nix {
        inherit pkgs;
        module = flake.homeManagerModules.papi-ssh-sync;
      };
    in test'
    json="$(nix eval --impure --json --expr "$expr")"
    printf '%s\n' "$json" | jq -r '.summary'
    if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
        printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
        exit 1
    fi

# Smoke-test the `services.papi-oracle` home-manager module: evaluate it against
# synthetic configs (lib.evalModules, no home-manager input) and verify the option
# schema, the authorize-only ExecStart (--allow-callback but no --domain/--origin),
# the default agent socket, and the non-empty-allowCallbacks assertion.
#
# evaluate the services.papi-oracle home-manager module against synthetic configs
test-nix-oracle-module:
    #!/usr/bin/env bash
    set -euo pipefail
    expr='let
      flake = builtins.getFlake (toString ./.);
      pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
      test = import ./nix/hm/papi-oracle-eval-test.nix {
        inherit pkgs;
        module = flake.homeManagerModules.papi-oracle;
      };
    in test'
    json="$(nix eval --impure --json --expr "$expr")"
    printf '%s\n' "$json" | jq -r '.summary'
    if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
        printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
        exit 1
    fi

# Smoke-test the `services.papi-auth-verifier` NixOS module: evaluate it against
# synthetic configs (lib.evalModules, no NixOS system) and verify the option schema,
# the forward-auth / verify-signature-only / combined ExecStart, and the
# forward-auth-requires-its-flags assertion. Mirrors test-nix-oracle-module.
#
# evaluate the services.papi-auth-verifier NixOS module against synthetic configs
test-nix-verifier-module:
    #!/usr/bin/env bash
    set -euo pipefail
    expr='let
      flake = builtins.getFlake (toString ./.);
      pkgs = flake.inputs.igloo.legacyPackages.${builtins.currentSystem};
      test = import ./nix/nixos/papi-auth-verifier-eval-test.nix {
        inherit pkgs;
        module = flake.nixosModules.papi-auth-verifier;
      };
    in test'
    json="$(nix eval --impure --json --expr "$expr")"
    printf '%s\n' "$json" | jq -r '.summary'
    if [[ "$(printf '%s\n' "$json" | jq -r '.pass')" != "true" ]]; then
        printf '%s\n' "$json" | jq -r '.failures[] | "FAIL: \(.name)\n  got: \(.result.got)"'
        exit 1
    fi

# Explore: parse an arbitrary string against hyphence-content.peg with the
# flake-pinned langlang, dumping the RAW bytes (piped through `cat -v`, so ANSI
# escapes are visible) plus the exit code. This is the zero-power check for
# `test-grammar` (hyphence#9's lesson): it shows whether a FAILED parse is
# distinguishable from a successful one by the stdout prefix the test keys off.
# e.g. `just debug-grammar-parse 'not a valid @@@ markl id'`
#
# parse a string against hyphence-content.peg with the pinned langlang
[group("debug")]
debug-grammar-parse content:
    #!/usr/bin/env bash
    set -euo pipefail
    langlang_bin="$(nix build .#langlang --no-link --print-out-paths)/bin/langlang"
    grammar="$(nix build .#hyphence-content-grammar --no-link --print-out-paths)/hyphence-content.peg"
    input="$(mktemp)"
    printf '%s' '{{content}}' > "$input"
    set +e
    out="$("$langlang_bin" -grammar "$grammar" -disable-builtins -disable-spaces -input "$input" 2>&1)"
    rc=$?
    set -e
    echo "--- exit code: $rc"
    echo "--- input path: $input"
    echo "--- raw output (cat -v):"
    printf '%s' "$out" | cat -v
    echo
    echo "--- starts with '<input-path>:'? "
    case "$out" in "$input":*) echo "YES (test would FAIL on this input)";; *) echo "NO (test would PASS on this input)";; esac

# Regenerate the committed sample enrollment receipt fixture
# (internal/alfa/enroll/testdata/) — a hand-off artifact for the deploy-side
# verify recipe (site-linenisgreat). Normal `test-go` skips this generator.
#
# regenerate the committed sample enrollment receipt fixture
[group("debug")]
debug-sample-receipt:
    PAPI_GEN_SAMPLE=1 nix develop --command go test ./internal/alfa/enroll/ -run TestGenerateSampleReceipt -v

# Regenerate the committed §10-signed /papi fixture (clients/ts/testdata/
# signed-papi.json + signed-papi.pubid.txt) the bun §10-verify test consumes
# (FDR-0007). Deterministic (fixed-seed key+sig); normal `test-go` skips it.
#
# regenerate the committed §10-signed /papi fixture
[group("debug")]
debug-signed-doc:
    PAPI_GEN_SIGNED_DOC=1 nix develop --command go test ./internal/alfa/inspect/ -run TestGenerateSignedDocFixture -v

# Inspect attached PIV cards (read-only, PIN-free) to verify provisioning state
# before a live `papi enroll` run — which card is provisioned (slot 9D+9A) vs
# blank. Runs via the PINNED piggy (the flake input papi uses), so blank cards
# show up via piggy#193. Serves the papi#15 live-test prep.
#
# list attached PIV cards and their provisioning state
[group("debug")]
debug-cards:
    nix develop --command bash -c 'echo "=== piggy list --format=ndjson (all cards, incl. blank via piggy#193) ==="; piggy list --format=ndjson; echo; echo "=== piggy list --format=ssh ==="; piggy list --format=ssh'

# Run the current papi against a live domain (go run, so it picks up uncommitted
# changes). For live-test verification, e.g. `just debug-papi piggy-ids
# linenisgreat.com`. Serves the papi#15 live-test prep.
#
# run the working-tree papi with ARGS via go run
[group("debug")]
debug-papi *ARGS:
    nix develop --command go run . {{ARGS}}

# Render man pages into build/man and open one — section 1 via the CLI's hidden
# `generate-man` (Go codegen), section 7 via scdoc. Local preview of the pages
# `nix build` ships (eng-manpages(7)), no full nix build needed.
#
# render papi's man pages locally and open PAGE (default papi)
[group("debug")]
debug-man page="papi":
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf build/man && mkdir -p build/man/share/man/man7
    nix develop --command go run . generate-man build/man
    for f in doc/*.7.scd; do
      [ -e "$f" ] || continue
      nix develop --command scdoc < "$f" > "build/man/share/man/man7/$(basename "$f" .scd)"
    done
    page=build/man/share/man/man1/{{page}}.1
    [ -e "$page" ] || page=build/man/share/man/man7/{{page}}.7
    man "$page"

# Read a card's slot-9D age recipient (read-only, PIN-free) to validate the
# age-plugin-piggy readback parser. Serves the papi#15 live-test prep.
#
# print a card's slot-9D age recipient
[group("debug")]
debug-age guid:
    nix develop --command age-plugin-piggy generate --guid {{guid}}

# Run pivy-tool (via piggy's passthrough) for live-test exploration — e.g.
# `just debug-pivy list` to enumerate all PIV cards incl. blank ones that
# `piggy list` hides. Read-only ops only here. Serves the papi#15 live-test prep.
#
# run pivy-tool with ARGS via piggy's passthrough
[group("debug")]
debug-pivy *ARGS:
    piggy tool {{ARGS}}

# Confirm the PINNED piggy (the flake input papi burns in, not ambient PATH)
# exposes `sign-bytes` (piggy#190) — papi enroll's slot-9A signer. papi#15 prep.
#
# check that the pinned piggy exposes sign-bytes
[group("debug")]
debug-piggy-signcheck:
    nix develop --command piggy sign-bytes --help

# Smoke-test the §5.2 slot-9A signer with the REAL card (papi#36): pipe a dummy
# challenge to `papi sign-challenge` and confirm it emits a papi-auth-sig-v1
# signature. Proves the signer + r‖s reframe without a browser or server (the dummy
# nonce won't authenticate — this checks signing, not the round-trip). signer=agent
# uses the forwarded $SSH_AUTH_SOCK (this host); signer=auto/pcsc for a local card.
# Operator-in-the-loop: may prompt the card for PIN/touch. e.g.
#   just debug-sign-challenge-smoke api.linenisgreat.com
#
# sign a dummy challenge with the real card to smoke the slot-9A signer
[group("debug")]
debug-sign-challenge-smoke domain="api.linenisgreat.com" signer="agent":
    echo '{"challenge_id":"smoke","nonce":"deadbeefdeadbeef","expires_at":0}' | nix develop --command go run . sign-challenge --domain "{{domain}}" --signer "{{signer}}"

# Run the §5 card oracle for the browser demo (papi#36). Its /login broker runs the
# whole handshake against --target server-side (no PAPI-server CORS needed) and signs
# with the card; the browser talks only to this oracle. Set --origin to the page's
# exact origin and --addr so the browser host can reach it (0.0.0.0 for a remote /
# tailnet browser). auto signer → the forwarded agent on this host. Operator-in-the-
# loop (card PIN/touch). domain = the server's §5.2 binding domain (must match its
# PAPI_AUTH_DOMAIN). e.g.
#   just debug-sign-challenge-serve linenisgreat.com https://api.linenisgreat.com http://<your-host>.ts.net:8080
#
# serve the §5 card oracle for the browser login demo
[group("debug")]
debug-sign-challenge-serve domain target origin addr="0.0.0.0:8088":
    nix develop --command go run . sign-challenge-serve --domain "{{domain}}" --target "{{target}}" --origin "{{origin}}" --addr "{{addr}}"

# Run the standalone verify-signature verifier (FDR-0013 app-native verify oracle) for
# an interim/dev test: POST /auth/verify-signature turns a card §5.2 signature + domain
# + nonce into the verified principal (stateless JSON). Point a consumer (e.g. a Better
# Auth plugin) at it. registry = a papi-ssh-sync fragment / saved
# /papi/ssh-authorized-keys body carrying the slot-9A auth keys. addr=0.0.0.0:9099 to
# reach it from another host/tailnet (it holds no secret — registry public keys only).
# e.g.
#   just debug-auth-verify-signature-serve /var/lib/papi/registry
#
# serve the standalone verify-signature auth verifier
[group("debug")]
debug-auth-verify-signature-serve registry addr="127.0.0.1:9099":
    nix develop --command go run . auth-verifier --enable-verify-signature --authorized-keys-file "{{registry}}" --addr "{{addr}}" --log-format text

# Serve the sign-challenge demo page (clients/ts/examples/) over http://localhost so
# the browser sees a real http origin (file:// gives Origin "null"). Pulls python3
# from nixpkgs on demand — no devShell dep. Pair with debug-sign-challenge-serve. e.g.
#   just debug-sign-challenge-demo 8080
# then open http://localhost:8080/sign-challenge-demo.html
#
# serve the sign-challenge demo page over http://localhost
[group("debug")]
debug-sign-challenge-demo port="8080":
    nix run nixpkgs#python3 -- -m http.server {{port}} --directory clients/ts/examples

# Smoke-test `papi enroll` end-to-end against a real card + a live domain by
# enrolling a provisioned card INTO ITSELF (degenerate: new==trusted) — exercises
# the full chain (read-back → slot-9A signing ×2 → receipt → verify against the
# live site) with NO blank card / piggy#193/#194 needed. Run in YOUR terminal so
# the PIN prompt reaches you; pass `pin=<PIN>` if it hangs with no prompt. Needs
# the card present + `piggy sign-bytes`. papi#15 live-test prep.
#
# smoke `papi enroll` end-to-end by enrolling one card into itself
[group("debug")]
debug-enroll-smoke guid domain="linenisgreat.com" pin="":
    #!/usr/bin/env bash
    set -euo pipefail
    args=(enroll "{{domain}}" --new-guid "{{guid}}" --trusted-guid "{{guid}}")
    if [[ -n "{{pin}}" ]]; then args+=(--pin "{{pin}}"); fi
    nix develop --command go run . "${args[@]}"

# Independently verify an enrollment receipt against a domain (the deploy-gate
# check `papi enroll` also runs internally). papi#15 live-test prep.
#
# verify an enrollment receipt file against a domain
[group("debug")]
debug-verify-receipt file domain="linenisgreat.com":
    nix develop --command go run . verify-receipt "{{file}}" --domain "{{domain}}"

# Provision the SOLE attached blank card via pivy-tool (INTERIM, until piggy#194's
# native `piggy card init`): init (assign GUID + CHUID) + generate eccp256 slot 9D
# + 9A with piggy's CN convention. Run with ONLY the blank card attached —
# pivy-tool can't target a blank card by serial alongside another. Factory admin
# key is auto-tried; prints the new GUID for `just debug-enroll`. papi#15 prep.
#
# provision the sole attached blank card via pivy-tool
[group("debug")]
debug-provision-blank:
    #!/usr/bin/env bash
    set -euo pipefail
    guid=$(nix develop --command piggy tool init | tr -dc '0-9A-Fa-f')
    g8=$(printf '%s' "$guid" | cut -c1-8 | tr 'A-Z' 'a-z')
    echo "init: new GUID = $guid"
    nix develop --command piggy tool generate -a eccp256 -n "piv-key-mgmt@$g8" 9d >/dev/null
    nix develop --command piggy tool generate -a eccp256 -n "piv-auth@$g8" 9a >/dev/null
    echo "generated 9D + 9A (eccp256). Re-attach the trusted card, then run:"
    echo "  just debug-enroll $guid <trusted-guid>"

# Run `papi enroll` for a REAL two-card enrollment: the new card (--new-guid)
# attested by the trusted card (--trusted-guid). Run in YOUR terminal (PIN
# prompt); pass `pin=<PIN>` if it hangs. papi#15 live test.
#
# run a real two-card `papi enroll` (new card attested by trusted card)
[group("debug")]
debug-enroll new_guid trusted_guid domain="linenisgreat.com" pin="":
    #!/usr/bin/env bash
    set -euo pipefail
    args=(enroll "{{domain}}" --new-guid "{{new_guid}}" --trusted-guid "{{trusted_guid}}")
    if [[ -n "{{pin}}" ]]; then args+=(--pin "{{pin}}"); fi
    nix develop --command go run . "${args[@]}"

# Explore: cross-build ARBITRARY packages for both wasm targets, isolated from
# papi's own build graph — the way to ask "is this dependency wasm-clean?"
# without papi's TUI/auth stack (huh→termenv→terminfo→os/user, creack/pty,
# runtime/cgo) failing first for unrelated reasons. Building a papi package that
# carries a wasm build-tag split cannot answer it: the tag just selects whichever
# file already compiles. Defaults to the papi#62 gate — piggy's markl, unblocked
# for wasm by purse-first#172/#173 in dewey; a regression there is upstream, not
# papi's. e.g. `just debug-build-wasm-pkg code.linenisgreat.com/hyphence/go/hyphence`
#
# cross-build arbitrary packages for both wasm targets, isolated from papi
[group("debug")]
debug-build-wasm-pkg pkg="code.linenisgreat.com/piggy/go/pkgs/markl code.linenisgreat.com/piggy/go/pkgs/markl_registrations":
    nix develop --command env GOOS=js GOARCH=wasm go build {{pkg}}
    nix develop --command env GOOS=wasip1 GOARCH=wasm go build {{pkg}}
    @echo "OK: {{pkg}} builds for js/wasm and wasip1/wasm"

# Explore: which packages in a build subtree import a given (often stdlib)
# package — e.g. `just debug-imports-of os/user .` locates the transitive wasip1
# build blocker, and `... ./internal/alfa/inspect` checks if the verify core is
# clean of it. WASM-isolation exploration.
#
# list which packages in a build subtree import a given package
[group("debug")]
debug-imports-of target pkg=".":
    nix develop --command bash -c 'go list -deps -json {{pkg}} | jq -r --arg p "{{target}}" "select(.Imports != null and (.Imports | index(\$p))) | .ImportPath"'

# Explore: trace WHY a package sits in the devShell closure (eval-only, no build)
# — e.g. `just debug-why-depends ffmpeg-headless` pins what drags ffmpeg into the
# merge-gate cold build. Finds the exact instance via --requisites, then prints the
# dependency chain.
#
# trace why a package sits in the devShell closure
[group("debug")]
debug-why-depends pkg:
    #!/usr/bin/env bash
    set -euo pipefail
    sys=$(nix eval --impure --raw --expr 'builtins.currentSystem')
    shell=".#devShells.${sys}.default"
    drv=$(nix path-info --derivation "$shell")
    target=$(nix-store -q --requisites "$drv" | grep -- '{{pkg}}' | grep '\.drv$' | head -1)
    echo "devShell: $drv"
    echo "target:   ${target:-<not found in closure>}"
    [ -n "${target:-}" ] && nix why-depends --derivation "$shell" "$target"

# Show PIV PIN/PUK retry counts per attached card (read-only via ykman) — diagnose
# a blocked PIN after a live test. papi#15 live-test debug.
#
# show PIV PIN/PUK retry counts per attached card
[group("debug")]
debug-pin-status:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "=== ykman list ==="
    ykman list || true
    for s in $(ykman list --serials 2>/dev/null); do
        echo
        echo "=== serial $s ==="
        ykman --device "$s" piv info 2>&1 | grep -iE 'PIN|PUK|tries|retr|attempt|management|WARNING' || ykman --device "$s" piv info 2>&1
    done

# Explore: query the live forge's OpenAPI spec with a jq filter — the authoritative,
# credential-free description of the Forgejo build papi actually mints against (field
# spellings and per-operation security drift between versions, so reading the spec
# beats reading upstream source). Serves papi#73's mint/revoke design. e.g.
#   just debug-forge-swagger '.definitions.CreateAccessTokenOption'
#   just debug-forge-swagger '.paths."/users/{username}/tokens".post'
#
# query the live forge's OpenAPI spec with a jq filter
[group("debug")]
debug-forge-swagger filter="." host="forge.starbrandshoes.com":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p build
    spec="build/{{host}}.swagger.json"
    curl -fsSL -o "$spec" "https://{{host}}/swagger.v1.json"
    # Keep the fetched spec on disk so a jq parse failure (spec disabled, HTML error
    # page, auth redirect) is inspectable instead of vanishing down the pipe.
    jq '{{filter}}' "$spec" || { echo "--- first 400 bytes of $spec ---" >&2; head -c 400 "$spec" >&2; echo >&2; exit 1; }

# Explore: make an authed call against the live forge API with the operator token
# sealed in the eng piggy store (`forge/krone-api-token`) — the credential papi#73's
# mint uses. Needs an unlocked piggy-agent. Read-only verbs only here; a mint/revoke
# round-trip goes through `papi forge token` itself, not this. e.g.
#   just debug-forge-api GET user
#   just debug-forge-api GET 'users/sasha/tokens'
#
# call the live forge API with the piggy-sealed operator token
[group("debug")]
debug-forge-api method="GET" path="user" json="" host="forge.starbrandshoes.com":
    #!/usr/bin/env bash
    set -euo pipefail
    tok="$(piggy pass show forge/krone-api-token </dev/null | head -1)"
    [[ -n $tok ]] || { echo "empty piggy entry forge/krone-api-token" >&2; exit 1; }
    args=(-sS -o /dev/stderr -w '\nHTTP %{http_code}\n' -X "{{method}}" -H "Authorization: token $tok")
    if [[ -n "{{json}}" ]]; then args+=(-H 'Content-Type: application/json' -d '{{json}}'); fi
    # Status code is the point of this probe (401 vs 404 distinguishes "auth method
    # not allowed" from "route reached"), so don't let -f swallow error bodies.
    curl "${args[@]}" "https://{{host}}/api/v1/{{path}}" </dev/null

# --- codemod ---

codemod-fmt: codemod-fmt-tree

# format the tree in place (repair mode) via `nix fmt`
codemod-fmt-tree:
    nix fmt

codemod-reposition: codemod-reposition-go

# Rebalance internal/ package tiers by dependency depth via dagnabit (from
# purse-first; on the devShell PATH). Run after adding or moving packages;
# preview with `nix develop --command dagnabit -n internal`. The one-time
# initial tiering of the flat layout used `dagnabit --initial internal`.
#
# rebalance internal/ package tiers by dependency depth
codemod-reposition-go:
    nix develop --command dagnabit internal

# --- maintenance ---

# `go mod tidy`, then regenerate gomod2nix.toml (the && dependency)
update-go: && build-gomod2nix
    nix develop --command go mod tidy

# rewrite PAPI_VERSION in version.env (pure mutation; `release` stages + commits)
[group("maintenance")]
bump-version new_version:
    sed -E -i "s/^(export PAPI_VERSION)=.*/\1={{new_version}}/" version.env

# create + push a signed annotated v<sem> tag from version.env, then verify it
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
# bump+commit -> signed tag -> fj release.
#
# cut a full release from master at new_version
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
    fj release create "$header" --tag "v{{new_version}}" --body "$msg"
