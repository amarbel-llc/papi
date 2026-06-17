{
  description = "papi: Personal API (PAPI) wire-format spec and conformance validator";

  inputs = {
    # conformist provides the linter/formatter multiplexer, its Nix module
    # library (conformist.lib), and the eng-convention presets. Following its
    # nixpkgs-master/utils pins keeps this flake's closure shared with conformist's.
    conformist.url = "github:amarbel-llc/conformist";
    nixpkgs.follows = "conformist/nixpkgs-master";
    utils.follows = "conformist/utils";
  };

  outputs =
    {
      self,
      conformist,
      nixpkgs,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # On x86_64-linux `.default` is the godyn build (needs the ca-derivations
        # experimental feature); swap to `.conformist-bga` to avoid it.
        conformistPkg = conformist.packages.${system}.default;

        # Pure lane: the eng preset + this repo's own formatters/excludes
        # (./conformist.nix). Drives `nix fmt` and the sandboxed `checks.formatting`.
        eval = conformist.lib.evalModule pkgs {
          imports = [
            conformist.lib.presets.eng
            ./conformist.nix
          ];
          package = conformistPkg;
        };

        # Impure lane: the git-state checks (git-remotes, sweatfile, agents-md).
        # They need a live .git / host tools, so they run via `just lint-worktree`
        # against the working tree, not the sandboxed check. Wire this in once the
        # repo has SSH remotes + a sweatfile (see the justfile).
        impureEval = conformist.lib.evalModule pkgs {
          imports = [ conformist.lib.presets.eng-impure ];
          package = conformistPkg;
          projectRootFile = "flake.nix";
        };
      in
      {
        formatter = eval.config.build.wrapper;
        checks.formatting = eval.config.build.check self;
        packages.conformist-impure-config = impureEval.config.build.configFile;

        devShells.default = pkgs.mkShell {
          packages = [
            conformistPkg
            pkgs.just
          ];
        };
      }
    );
}
