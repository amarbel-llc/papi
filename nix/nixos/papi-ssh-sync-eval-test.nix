# Smoke-test harness for the `papi-ssh-sync` NixOS module's sshd wiring.
#
# Drives `lib.evalModules` with stub options (no NixOS system, no home-manager
# input): a home-manager user with one synced fragment, then checks that the
# fragment reaches services.openssh.authorizedKeysFiles, and that an mkForce
# override which drops it raises the module's warning (papi#70).
#
# Use via: `just test-nix-ssh-sync-module`. Mirrors papi-auth-verifier-eval-test.nix.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  fragment = "/home/alice/.local/state/papi-ssh-sync/linenisgreat.com";

  harness = {
    options = {
      home-manager.sharedModules = lib.mkOption {
        type = lib.types.listOf lib.types.raw;
        default = [ ];
      };
      home-manager.users = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      services.openssh.authorizedKeysFiles = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
      };
      warnings = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
      };
    };
    # A home-manager user who enabled the service, as the hm module exposes it.
    config.home-manager.users.alice.services.papi-ssh-sync._fragmentPaths.linenisgreat = fragment;
  };

  runEval =
    cfg:
    lib.evalModules {
      modules = [
        harness
        module
        cfg
      ];
    };

  cases = [
    {
      name = "fragment-wired";
      cfg = { };
      check =
        result:
        let
          files = result.config.services.openssh.authorizedKeysFiles;
          warns = result.config.warnings;
        in
        {
          ok = lib.elem fragment files && lib.elem "%h/.ssh/authorized_keys" files && warns == [ ];
          got = { inherit files warns; };
        };
    }
    {
      name = "mkForce-override-warns";
      cfg = {
        services.openssh.authorizedKeysFiles = lib.mkForce [ "/etc/ssh/authorized_keys.d/%u" ];
      };
      check =
        result:
        let
          warns = result.config.warnings;
        in
        {
          ok = lib.any (w: lib.hasInfix fragment w) warns;
          got = warns;
        };
    }
    {
      name = "override-that-keeps-fragment-is-quiet";
      cfg = {
        services.openssh.authorizedKeysFiles = lib.mkOverride 45 [
          "/etc/ssh/authorized_keys.d/%u"
          fragment
        ];
      };
      check =
        result:
        let
          warns = result.config.warnings;
        in
        {
          ok = warns == [ ];
          got = warns;
        };
    }
  ];

  results = map (c: {
    name = c.name;
    result = c.check (runEval c.cfg);
  }) cases;

  failures = builtins.filter (r: !r.result.ok) results;
in
{
  inherit results failures;
  pass = failures == [ ];
  summary = "${
    toString (lib.length cases - lib.length failures)
  }/${toString (lib.length cases)} cases passed";
}
