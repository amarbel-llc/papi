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
  };

  outputs =
    {
      self,
      conformist,
      igloo,
      nixpkgs,
      purse-first,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        # igloo's flake path (not the `import igloo {}` shim): applies the fork
        # overlay (buildGoApplication, mkGoEnv, pkgs.go) over our pinned
        # nixpkgs-master.
        pkgs = igloo.legacyPackages.${system};

        # On x86_64-linux conformist's `.default` is the godyn build (needs the
        # ca-derivations feature); swap to `.conformist-bga` to avoid it.
        conformistPkg = conformist.packages.${system}.default;

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
          ];
        };
      }
    );
}
