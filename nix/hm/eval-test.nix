# Smoke-test harness for the `services.papi-ssh-sync` home-manager module.
#
# Drives `lib.evalModules` against the module with synthetic configs to verify
# the option schema, the Linux/Darwin code paths, the default fragment-path
# derivation, and every assertion — without a real home-manager.
#
# Use via: `just test-nix-hm-module`. The recipe imports this file and evaluates
# `pass`/`failures` in JSON; a non-empty `failures` causes a non-zero exit.
{
  pkgs,
  module,
}:
let
  inherit (pkgs) lib;

  # Stub the home-manager option surface the module writes to. In a real
  # home-manager invocation hm declares these.
  harness = {
    options = {
      home.packages = lib.mkOption {
        type = lib.types.listOf lib.types.package;
        default = [ ];
      };
      home.homeDirectory = lib.mkOption {
        type = lib.types.str;
        default = "/Users/eval-test"; # Darwin StandardErrorPath needs an absolute home
      };
      xdg.configHome = lib.mkOption {
        type = lib.types.str;
        default = "/home/eval-test/.config";
      };
      systemd.user.services = lib.mkOption {
        type = lib.types.attrs;
        default = { };
      };
      systemd.user.timers = lib.mkOption {
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

  # The `package` default reads self.packages.${system}.papi, which is never
  # forced once a definition is present. Pin it to pkgs.hello (mkDefault) so the
  # exec line resolves to a real store path without building papi.
  pinPackage = {
    services.papi-ssh-sync.package = lib.mkDefault pkgs.hello;
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

  # Force the per-unit exec through nix's laziness (the bug class that only
  # surfaces when home-manager realizes the unit), returning it as a string on
  # either platform.
  unitExec =
    unitName: result:
    if pkgs.stdenv.isLinux then
      result.config.systemd.user.services.${unitName}.Service.ExecStart
    else
      lib.concatStringsSep " " result.config.launchd.agents.${unitName}.config.ProgramArguments;

  unitInterval =
    unitName: result:
    if pkgs.stdenv.isLinux then
      result.config.systemd.user.timers.${unitName}.Timer.OnUnitActiveSec
    else
      toString result.config.launchd.agents.${unitName}.config.StartInterval;

  fragmentPath =
    unitName: result: result.config.services.papi-ssh-sync._fragmentPaths.${unitName} or null;

  cases = [
    {
      name = "single-instance-evaluates-cleanly";
      cfg = {
        services.papi-ssh-sync.enable = true;
        services.papi-ssh-sync.domain = "example.com";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          exec = unitExec "papi-ssh-sync" result;
          frag = fragmentPath "papi-ssh-sync" result;
        in
        {
          ok =
            tripped == [ ]
            && lib.hasInfix "ssh-sync" exec
            && lib.hasInfix "example.com" exec
            && frag != null
            && lib.hasSuffix "/papi/ssh-sync/example.com.keys" frag;
          got = { inherit tripped exec frag; };
        };
    }
    {
      # Slug parity with the Go papiHostSlug: scheme/path stripped, lowercased,
      # the port ':' mapped to '_'. https://Example.COM:8443 → example.com_8443.
      name = "default-fragment-path-uses-host-slug";
      cfg = {
        services.papi-ssh-sync.enable = true;
        services.papi-ssh-sync.domain = "https://Example.COM:8443/papi";
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          frag = fragmentPath "papi-ssh-sync" result;
        in
        {
          ok = tripped == [ ] && frag != null && lib.hasSuffix "/example.com_8443.keys" frag;
          got = { inherit tripped frag; };
        };
    }
    {
      name = "guid-appears-in-exec";
      cfg = {
        services.papi-ssh-sync.enable = true;
        services.papi-ssh-sync.domain = "example.com";
        services.papi-ssh-sync.guid = "DEADBEEF";
      };
      check =
        result:
        let
          exec = unitExec "papi-ssh-sync" result;
        in
        {
          ok = lib.hasInfix "--guid" exec && lib.hasInfix "DEADBEEF" exec;
          got = { inherit exec; };
        };
    }
    {
      name = "interval-maps-to-unit";
      cfg = {
        services.papi-ssh-sync.enable = true;
        services.papi-ssh-sync.domain = "example.com";
        services.papi-ssh-sync.intervalSeconds = 1800;
      };
      check =
        result:
        let
          interval = unitInterval "papi-ssh-sync" result;
        in
        {
          ok = lib.hasInfix "1800" interval;
          got = { inherit interval; };
        };
    }
    {
      name = "multi-instance-distinct-fragments";
      cfg = {
        services.papi-ssh-sync.enable = true;
        services.papi-ssh-sync.instances = {
          work = {
            domain = "example.com";
          };
          home = {
            domain = "linenisgreat.com";
            intervalSeconds = 1800;
          };
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          workFrag = fragmentPath "papi-ssh-sync-work" result;
          homeFrag = fragmentPath "papi-ssh-sync-home" result;
          workExec = unitExec "papi-ssh-sync-work" result;
          homeExec = unitExec "papi-ssh-sync-home" result;
        in
        {
          ok =
            tripped == [ ]
            && workFrag != null
            && homeFrag != null
            && workFrag != homeFrag
            && lib.hasSuffix "/example.com.keys" workFrag
            && lib.hasSuffix "/linenisgreat.com.keys" homeFrag
            && lib.hasInfix "example.com" workExec
            && lib.hasInfix "linenisgreat.com" homeExec;
          got = {
            inherit
              tripped
              workFrag
              homeFrag
              ;
          };
        };
    }
    {
      name = "missing-domain-trips-required-assertion";
      cfg = {
        services.papi-ssh-sync.enable = true;
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "set `domain`" m) tripped;
        in
        {
          ok = hasExpected;
          got = tripped;
        };
    }
    {
      name = "top-level-with-instances-trips-assertion";
      cfg = {
        services.papi-ssh-sync.enable = true;
        services.papi-ssh-sync.domain = "example.com";
        services.papi-ssh-sync.instances.work = {
          domain = "other.example";
        };
      };
      check =
        result:
        let
          tripped = trippedMessages result;
          hasExpected = lib.any (m: lib.hasInfix "top-level options" m) tripped;
        in
        {
          ok = hasExpected;
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
