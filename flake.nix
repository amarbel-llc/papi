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
    nixpkgs-master.url = "github:NixOS/nixpkgs/d233902339c02a9c334e7e593de68855ad26c4cb";
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
          conformist-impure-config = impureEval.config.build.configFile;
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
    };
}
