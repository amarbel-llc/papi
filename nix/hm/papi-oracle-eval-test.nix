# Smoke-test harness for the `services.papi-oracle` home-manager module.
#
# Drives `lib.evalModules` against the module with synthetic configs to verify
# the option schema, the rendered ExecStart (authorize-only: --allow-callback but
# NO --domain/--origin), the default agent socket, and the non-empty-allowCallbacks
# assertion — without a real home-manager or building papi.
#
# Use via: `just test-nix-oracle-module`. Mirrors nix/hm/eval-test.nix.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  harness = {
    options = {
      home.packages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [ ];
      };
      home.homeDirectory = lib.mkOption {
        type = lib.types.str;
        default = "/Users/eval-test"; # absolute home for the agentSocket + Darwin log path
      };
      systemd.user.services = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      launchd.agents = lib.mkOption {
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
    services.papi-oracle.package = lib.mkDefault pkgs.hello;
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

  unitExec =
    result:
    if pkgs.stdenv.isLinux then
      result.config.systemd.user.services.papi-oracle.Service.ExecStart
    else
      lib.concatStringsSep " " result.config.launchd.agents.papi-oracle.config.ProgramArguments;

  callback = "https://forge.linenisgreat.com/auth/callback";

  cases = [
    {
      name = "authorize-only-evaluates-cleanly";
      cfg = {
        services.papi-oracle.enable = true;
        services.papi-oracle.allowCallbacks = [ callback ];
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          exec = unitExec result;
        in
        {
          # authorize-only: the /authorize enabler is present, the /sign-mode flags
          # (--domain/--origin) are ABSENT, and the default agent path is wired.
          ok =
            tripped == [ ]
            && lib.hasInfix "sign-challenge-serve" exec
            && lib.hasInfix "--allow-callback" exec
            && lib.hasInfix callback exec
            && !(lib.hasInfix "--domain" exec)
            && !(lib.hasInfix "--origin" exec)
            && lib.hasInfix "--signer agent" exec
            && lib.hasInfix "mux-agent.sock" exec;
          got = { inherit tripped exec; };
        };
    }
    {
      name = "empty-allowCallbacks-trips-assertion";
      cfg = {
        services.papi-oracle.enable = true;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
        in
        {
          ok = lib.any (m: lib.hasInfix "allowCallbacks" m) tripped;
          got = tripped;
        };
    }
    {
      name = "guid-and-custom-socket-in-exec";
      cfg = {
        services.papi-oracle.enable = true;
        services.papi-oracle.allowCallbacks = [ callback ];
        services.papi-oracle.guid = "DEADBEEF";
        services.papi-oracle.agentSocket = "/run/user/1000/custom-agent.sock";
        services.papi-oracle.signer = "pcsc";
      };
      check =
        result:
        let
          exec = unitExec result;
        in
        {
          ok =
            lib.hasInfix "--guid" exec
            && lib.hasInfix "DEADBEEF" exec
            && lib.hasInfix "/run/user/1000/custom-agent.sock" exec
            && lib.hasInfix "--signer pcsc" exec;
          got = { inherit exec; };
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
