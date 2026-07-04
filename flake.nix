{
  description = "papi: Personal API (PAPI) wire-format spec and conformance validator";

  inputs = {
    # conformist provides the linter/formatter multiplexer, its Nix module
    # library (conformist.lib), and the eng-convention presets.
    conformist.url = "github:amarbel-llc/conformist";
    # igloo's legacyPackages carries the gomod2nix overlay's buildGoApplication /
    # mkGoEnv and the shared pkgs.go; the fork's buildGoApplication auto-injects
    # `-X main.version` from version.env and `-X main.commit` from src.rev
    # (eng-versioning(7)). Follow conformist's nixpkgs-master so the closure is
    # shared rather than duplicated.
    igloo.url = "github:amarbel-llc/igloo";
    igloo.inputs.nixpkgs-master.follows = "nixpkgs";
    nixpkgs.follows = "conformist/nixpkgs-master";
    nixpkgs-master.url = "github:NixOS/nixpkgs/567a49d1913ce81ac6e9582e3553dd90a955875f";
    utils.follows = "conformist/utils";

    # purse-first provides `dagnabit`, the code-organization tool that tiers
    # internal/ packages by dependency depth (the internal/0|alfa layout) and
    # is on the devShell PATH for `just codemod-reposition`; its nix package
    # also installs dagnabit(1). Follow the shared inputs to collapse the lock.
    purse-first = {
      url = "github:amarbel-llc/purse-first";
      inputs.igloo.follows = "igloo";
      inputs.nixpkgs-master.follows = "nixpkgs";
      inputs.utils.follows = "utils";
    };

    # piggy provides the slot-9A byte-signer (`piggy sign-bytes`), the card
    # enumeration (`piggy list`), and the bundled `age-plugin-piggy` that
    # `papi enroll` shells out to. Pinning it here (instead of resolving `piggy`
    # off the operator's ambient PATH) makes enrollment reproducible and
    # independent of whatever piggy build happens to be installed.
    piggy = {
      url = "github:amarbel-llc/piggy";
      inputs.igloo.follows = "igloo";
      inputs.nixpkgs-master.follows = "nixpkgs";
      inputs.utils.follows = "utils";
    };
    piggy.inputs.bats.inputs.utils.follows = "conformist/utils";
    conformist.inputs.igloo.follows = "igloo";
    piggy.inputs.bats.inputs.treefmt-nix.follows = "igloo/treefmt-nix";
    conformist.inputs.nixpkgs-master.follows = "nixpkgs-master";
    piggy.inputs.bats.inputs.nixpkgs-master.follows = "nixpkgs-master";
    piggy.inputs.purse-first.inputs.gomod2nix.follows = "purse-first/gomod2nix";
    piggy.inputs.conformist.follows = "conformist";
    piggy.inputs.purse-first.follows = "purse-first";
  };

  outputs =
    {
      self,
      conformist,
      igloo,
      nixpkgs,
      nixpkgs-master,
      purse-first,
      piggy,
      utils,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        # igloo's flake path (not the `import igloo {}` shim): applies the fork
        # overlay (buildGoApplication, mkGoEnv, pkgs.go) over our pinned
        # nixpkgs-master.
        pkgs = igloo.legacyPackages.${system};

        # On x86_64-linux conformist's `.default` is the godyn build (needs the
        # ca-derivations feature); swap to `.conformist-bga` to avoid it.
        conformistPkg = conformist.packages.${system}.default;

        # piggy bundles `piggy` + `age-plugin-piggy` in bin/; `papi enroll` execs
        # both by name, so the pinned package is burned onto the wrapped binary's
        # PATH (below) and added to the devShell.
        piggyPkg = piggy.packages.${system}.piggy;

        # The papi CLI. version/commit are injected by the fork's
        # buildGoApplication from version.env + self.rev — no ldflags here.
        papi = pkgs.buildGoApplication {
          pname = "papi";
          src = self;
          pwd = ./.;
          modules = ./gomod2nix.toml;
          subPackages = [ "." ];
          go = pkgs.go;
          GOTOOLCHAIN = "local";
          # Unit tests run via `just test-go` (some reach the network); keep the
          # package build hermetic.
          doCheck = false;
          # `papi enroll` shells out by name to piggy/age-plugin-piggy (card I/O)
          # and to `gh` (registering the new card's slot-9A key on GitHub as an
          # auth + signing key); wrap the binary so the pinned piggy/bin and gh
          # take precedence over the ambient PATH.
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            wrapProgram $out/bin/papi \
              --prefix PATH : ${
                pkgs.lib.makeBinPath [
                  piggyPkg
                  pkgs.gh
                ]
              }
          '';
          meta.mainProgram = "papi";
        };

        # The papi TypeScript client (FDR-0007): a zero-dependency flake output —
        # the js/wasm core, Go's wasm_exec.js, and the wrapper staged side by side,
        # so a zx/Bun consumer imports `${papi-client-ts}/papi.ts` directly (papi.ts
        # resolves papi-client.wasm + wasm_exec.js as siblings). No bun2nix
        # lockfiles: the wrapper has no runtime deps beyond node: builtins + the
        # wasm. Built via buildGoApplication for the gomod2nix module cache, but
        # with a custom build/install since the artifact is a js/wasm file plus
        # static assets, not a host binary.
        papi-client-ts = pkgs.buildGoApplication {
          pname = "papi-client-ts";
          src = self;
          pwd = ./.;
          modules = ./gomod2nix.toml;
          go = pkgs.go;
          GOTOOLCHAIN = "local";
          doCheck = false;
          buildPhase = ''
            runHook preBuild
            env GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -o papi-client.wasm ./cmd/papi-client-wasm
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p $out
            cp papi-client.wasm $out/papi-client.wasm
            cp ${pkgs.go}/share/go/lib/wasm/wasm_exec.js $out/wasm_exec.js
            cp clients/ts/papi.ts $out/papi.ts
            runHook postInstall
          '';
          meta.description = "papi TypeScript client: js/wasm core + wasm_exec.js + wrapper (FDR-0007)";
        };

        # The staged host installer (FDR-0006): a static binary that drives an
        # RFC-0003 phase manifest, linking the internal/0/papi client + the crap
        # TUI. First increment — the phase engine + the runnable early phases;
        # host/hardware-gated phases are seams and slot-9A signing is out of scope
        # (FDR-0008), so this binary is built UNSIGNED. CGO-free static binary.
        papi-installer = pkgs.buildGoApplication {
          pname = "papi-installer";
          src = self;
          pwd = ./.;
          modules = ./gomod2nix.toml;
          subPackages = [ "cmd/papi-installer" ];
          go = pkgs.go;
          GOTOOLCHAIN = "local";
          CGO_ENABLED = "0";
          doCheck = false;
          meta.mainProgram = "papi-installer";
        };

        # Pure lane: eng preset + this repo's overlay -> `nix fmt` + the
        # sandboxed checks.formatting gate.
        eval = conformist.lib.evalModule pkgs {
          imports = [
            conformist.lib.presets.eng
            ./conformist.nix
          ];
          package = conformistPkg;
        };

        # Impure lane: git-state checks, run via `just lint-worktree` once the
        # repo has SSH remotes + a sweatfile.
        impureEval = conformist.lib.evalModule pkgs {
          imports = [ conformist.lib.presets.eng-impure ];
          package = conformistPkg;
          projectRootFile = "flake.nix";
        };
      in
      {
        packages = {
          default = papi;
          papi = papi;
          papi-client-ts = papi-client-ts;
          papi-installer = papi-installer;
          conformist-impure-config = impureEval.config.build.configFile;
          # The store-pinned, toolchain-hermetic spinclass hook pair from the
          # pure eval (eng tier-B convergence, proven on madder): pre-commit
          # (`--staged --exit-zero-on-fix`) formats staged content at
          # authoring time; repair (`--commit --amend --exit-zero-on-fix`) is
          # the merge-repair phase, which self-heals bump commits against the
          # rebuilt post-bump devshell. Both on the devShell PATH below —
          # papi previously exposed NEITHER, so the eng-sweatfile hooks fell
          # through to eng's (now severed) fallback wrapper.
          conformist-pre-commit = eval.config.build.preCommit;
          conformist-repair = eval.config.build.repair;
        };

        formatter = eval.config.build.wrapper;
        checks.formatting = eval.config.build.check self;

        devShells.default = pkgs.mkShell {
          packages = [
            # mkGoEnv puts the gomod2nix-regen `go` wrapper + the gomod2nix CLI
            # on PATH, so `just build-gomod2nix` / `just update-go` work.
            (pkgs.mkGoEnv { pwd = ./.; })
            pkgs.go
            pkgs.just
            conformistPkg
            # The spinclass hook pair (see packages.conformist-pre-commit /
            # .conformist-repair), resolved from the devShell PATH by the
            # sweatfile [hooks] commands.
            eval.config.build.preCommit
            eval.config.build.repair
            # dagnabit(1): tiers internal/ packages by dependency depth — see
            # `just codemod-reposition` and the README Layout section.
            purse-first.packages.${system}.dagnabit
            # gum + gh drive the eng-versioning(7) release recipes
            # (`just bump-version` / `tag` / `release`).
            pkgs.gum
            pkgs.gh
            # Pinned piggy + age-plugin-piggy, so `go run .` (the debug recipes /
            # live test) execs the same piggy the wrapped binary does — not the
            # operator's ambient PATH piggy.
            piggyPkg
            # bun: runtime + bundler for the TypeScript client wrapper
            # (clients/ts, FDR-0007). The bun2nix lockfile generation and the
            # `build-ts` recipe run under it; igloo's overlay carries the
            # buildBunBinary/buildZxScript helpers that consume the lockfiles.
            pkgs.bun
          ];
        };
      }
    ))
    // {
      # papi-ssh-sync home-manager + NixOS modules (system-independent, so they
      # live outside eachDefaultSystem). The hm module is curried with `self` so
      # its `package` option can default to self.packages.${system}.papi — papi
      # isn't in nixpkgs, so there's no pkgs.papi fallback. The NixOS module
      # re-exports the hm module into every home-manager-managed user AND
      # auto-wires each instance's fragment path into
      # services.openssh.authorizedKeysFiles. See docs/features/0005.
      homeManagerModules.papi-ssh-sync = import ./nix/hm/papi-ssh-sync.nix self;
      nixosModules.papi-ssh-sync = import ./nix/nixos/papi-ssh-sync.nix self;

      # The client-side sibling to nixosModules.papi-auth-verifier: runs the §5.2
      # card oracle (`papi sign-challenge-serve`) in authorize-only mode as a per-user
      # service, so a card login's /authorize redirect resolves on the user's own
      # machine. FDR-0014 client side; see papi#44.
      homeManagerModules.papi-oracle = import ./nix/hm/papi-oracle.nix self;

      # The FDR-0014 forward-auth verifier as a systemd service (a consumer like circus
      # imports it and fronts it with nginx auth_request). With enableVerifySignature it
      # also (or, standalone, only) serves the FDR-0013 app-native /auth/verify-signature
      # oracle. Curried with `self` so `package` defaults to self.packages.${system}.papi.
      nixosModules.papi-auth-verifier = import ./nix/nixos/papi-auth-verifier.nix self;
    };
}
