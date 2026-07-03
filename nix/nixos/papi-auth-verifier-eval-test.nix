# Smoke-test harness for the `services.papi-auth-verifier` NixOS module.
#
# Drives `lib.evalModules` against the module with synthetic configs to verify the
# option schema, the two serving modes (forward-auth vs verify-signature-only), the
# combined mode, and the forward-auth-requires-its-flags assertion — without building
# papi or a real NixOS system.
#
# Use via: `just test-nix-verifier-module`. Mirrors nix/hm/papi-oracle-eval-test.nix.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  harness = {
    options = {
      users.users = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      users.groups = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      systemd.services = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      assertions = lib.mkOption {
        type = lib.types.listOf (
          lib.types.submodule {
            options = {
              assertion = lib.mkOption { type = lib.types.bool; };
              message = lib.mkOption { type = lib.types.str; };
            };
          }
        );
        default = [ ];
      };
    };
  };

  # Pin package to pkgs.hello (mkDefault) so ExecStart resolves without building papi.
  pinPackage = {
    services.papi-auth-verifier.package = lib.mkDefault pkgs.hello;
  };

  runEval =
    cfg:
    lib.evalModules {
      modules = [
        harness
        module
        pinPackage
        cfg
      ];
      specialArgs = { inherit pkgs; };
    };

  trippedMessages =
    result: map (a: a.message) (builtins.filter (a: !a.assertion) result.config.assertions);

  unitExec = result: result.config.systemd.services.papi-auth-verifier.serviceConfig.ExecStart;

  registry = "/var/lib/papi/registry";
  cookieKey = "/run/secrets/papi-cookie-key";
  oracle = "http://localhost:9098/authorize";
  external = "https://forge.linenisgreat.com";

  cases = [
    {
      name = "forward-auth-mode";
      cfg = {
        services.papi-auth-verifier.enable = true;
        services.papi-auth-verifier.authorizedKeysFile = registry;
        services.papi-auth-verifier.cookieKeyFile = cookieKey;
        services.papi-auth-verifier.oracleLogin = oracle;
        services.papi-auth-verifier.externalUrl = external;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          exec = unitExec result;
        in
        {
          # default mode: the forward-auth flags are present, the verify-signature
          # enabler is absent.
          ok =
            tripped == [ ]
            && lib.hasInfix "auth-verifier" exec
            && lib.hasInfix "--cookie-key-file" exec
            && lib.hasInfix "--oracle-login" exec
            && lib.hasInfix "--external-url" exec
            && lib.hasInfix "--authorized-keys-file" exec
            && !(lib.hasInfix "--enable-verify-signature" exec);
          got = { inherit tripped exec; };
        };
    }
    {
      name = "verify-signature-only-mode";
      cfg = {
        services.papi-auth-verifier.enable = true;
        services.papi-auth-verifier.enableVerifySignature = true;
        services.papi-auth-verifier.authorizedKeysFile = registry;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          exec = unitExec result;
        in
        {
          # standalone: the verify-signature enabler + registry are present; NONE of the
          # forward-auth flags are.
          ok =
            tripped == [ ]
            && lib.hasInfix "--enable-verify-signature" exec
            && lib.hasInfix "--authorized-keys-file" exec
            && !(lib.hasInfix "--cookie-key-file" exec)
            && !(lib.hasInfix "--oracle-login" exec)
            && !(lib.hasInfix "--external-url" exec);
          got = { inherit tripped exec; };
        };
    }
    {
      name = "combined-mode";
      cfg = {
        services.papi-auth-verifier.enable = true;
        services.papi-auth-verifier.enableVerifySignature = true;
        services.papi-auth-verifier.authorizedKeysFile = registry;
        services.papi-auth-verifier.cookieKeyFile = cookieKey;
        services.papi-auth-verifier.oracleLogin = oracle;
        services.papi-auth-verifier.externalUrl = external;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          exec = unitExec result;
        in
        {
          # both modes on: the verify-signature enabler AND the forward-auth flags.
          ok =
            tripped == [ ]
            && lib.hasInfix "--enable-verify-signature" exec
            && lib.hasInfix "--cookie-key-file" exec;
          got = { inherit tripped exec; };
        };
    }
    {
      name = "forward-auth-missing-flags-trips-assertion";
      cfg = {
        services.papi-auth-verifier.enable = true;
        services.papi-auth-verifier.authorizedKeysFile = registry;
        services.papi-auth-verifier.cookieKeyFile = cookieKey;
        # oracleLogin + externalUrl omitted → forward-auth mode is incomplete.
      };
      check =
        result:
        let
          tripped = trippedMessages result;
        in
        {
          ok = lib.any (m: lib.hasInfix "forward-auth mode needs" m) tripped;
          got = tripped;
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
