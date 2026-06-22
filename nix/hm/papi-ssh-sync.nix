# home-manager module for `services.papi-ssh-sync`.
#
# Runs `papi ssh-sync <domain>` on a timer to keep a LOCAL managed
# authorized_keys file in sync with a PAPI domain's published slot-9A keys
# (full rewrite each run, so a rotated/revoked card is pruned). Linux uses a
# systemd user timer + oneshot service; Darwin uses a launchd agent with
# StartInterval. Both are home-manager option surfaces, so this works on NixOS,
# nix-darwin, and standalone home-manager on Ubuntu alike.
#
# Curried with `self` (the papi flake) so `package` can default to
# self.packages.${system}.papi — papi is not in nixpkgs, so there is no
# pkgs.papi to fall back to.
#
# The module writes the fragment file(s) and runs the timer; it does NOT wire
# sshd's AuthorizedKeysFile (it cannot touch system sshd_config from
# home-manager). On NixOS the companion nixosModules.papi-ssh-sync auto-wires
# services.openssh.authorizedKeysFiles; on nix-darwin / standalone home-manager
# the operator adds the AuthorizedKeysFile line once (see the FDR / README).
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkIf mkOption types;

  cfg = config.services.papi-ssh-sync;

  # hostSlug mirrors the Go papiHostSlug (main.go): the host (scheme/path
  # stripped), lowercased, with every char outside [a-z0-9.-] — notably the
  # port ':' — replaced by '_'. It MUST match the CLI, or the module's default
  # fragment path diverges from the CLI's default for the same domain.
  hostSlug =
    domain:
    let
      afterScheme = lib.last (lib.splitString "://" domain);
      host = lib.head (lib.splitString "/" afterScheme);
      safeChar = c: if builtins.match "[a-z0-9.-]" c != null then c else "_";
    in
    lib.concatStrings (map safeChar (lib.stringToCharacters (lib.toLower host)));

  # Per-instance unit definition. `unitName` is the systemd unit / launchd label;
  # the default fragment path embeds the domain slug so multiple instances never
  # collide on one file.
  mkInstance =
    unitName: ic:
    let
      fragmentPath =
        if ic.authorizedKeysPath != null then
          ic.authorizedKeysPath
        else
          "${config.xdg.configHome}/papi/ssh-sync/${hostSlug ic.domain}.keys";

      argv = [
        "ssh-sync"
        ic.domain
        "--authorized-keys"
        fragmentPath
      ]
      ++ lib.optionals (ic.guid != null) [
        "--guid"
        ic.guid
      ]
      ++ ic.extraArgs;

      # Linux ExecStart: a single command line. The fragment path resolves to a
      # concrete absolute string at eval time (config.xdg.configHome is
      # eval-known), so no runtime shell expansion is needed and escapeShellArgs
      # is safe.
      exec = "${cfg.package}/bin/papi " + lib.escapeShellArgs argv;

      # Darwin ProgramArguments: an argv list (launchd runs no shell).
      programArguments = [ "${cfg.package}/bin/papi" ] ++ argv;

      linuxService = {
        Unit = {
          Description = "papi ssh-sync — authorized_keys from ${ic.domain}";
          Documentation = "https://github.com/amarbel-llc/papi";
          After = [ "network-online.target" ];
          Wants = [ "network-online.target" ];
        };
        Service = {
          Type = "oneshot";
          ExecStart = exec;
        };
        # No Install.WantedBy: the timer below activates this service.
      };

      linuxTimer = {
        Unit.Description = "papi ssh-sync timer — ${ic.domain}";
        Timer = {
          OnBootSec = "2min"; # a first sync shortly after login
          OnUnitActiveSec = "${toString ic.intervalSeconds}s"; # then on cadence
          Persistent = true; # catch up a missed run (laptop asleep)
        };
        Install.WantedBy = [ "timers.target" ];
      };

      darwinAgent = {
        enable = true;
        config = {
          ProgramArguments = programArguments;
          RunAtLoad = true; # a first sync at login
          StartInterval = ic.intervalSeconds; # launchd interval is SECONDS — 1:1
          ProcessType = "Background";
          # launchd does not expand $HOME and home-manager type-checks this as an
          # absolute path, so resolve the home prefix at eval time.
          StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/${unitName}.log";
        };
      };
    in
    {
      inherit
        fragmentPath
        linuxService
        linuxTimer
        darwinAgent
        ;
    };

  hasInstances = cfg.instances != { };

  topLevelInstanceCfg = {
    inherit (cfg)
      domain
      authorizedKeysPath
      guid
      intervalSeconds
      extraArgs
      ;
  };

  # Whether any top-level instance option is set to a non-default value (used by
  # the top-level-vs-instances mutex assertion).
  topLevelHasInstanceConfig =
    cfg.domain != null
    || cfg.authorizedKeysPath != null
    || cfg.guid != null
    || cfg.intervalSeconds != 3600
    || cfg.extraArgs != [ ];

  # Single-instance mode synthesizes one `papi-ssh-sync` unit from the top-level
  # options; multi-instance mode namespaces each key as `papi-ssh-sync-<name>`.
  effectiveInstances =
    if hasInstances then
      lib.mapAttrs' (name: ic: lib.nameValuePair "papi-ssh-sync-${name}" ic) cfg.instances
    else
      { papi-ssh-sync = topLevelInstanceCfg; };

  builtInstances = lib.mapAttrs mkInstance effectiveInstances;

  # Per-instance required-domain assertion (multi-instance entries each need a
  # domain; the submodule has no default for it). The unit-name suffix points at
  # the offending entry.
  perInstanceAssertions = lib.mapAttrsToList (unitName: ic: {
    assertion = ic.domain != null && ic.domain != "";
    message = "services.papi-ssh-sync: `domain` is required (instance ${unitName}).";
  }) effectiveInstances;

  instanceModule = types.submodule {
    options = {
      domain = mkOption {
        type = types.str;
        example = "linenisgreat.com";
        description = "PAPI domain to sync slot-9A keys from.";
      };
      authorizedKeysPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Managed fragment file this instance rewrites in full each run. Defaults to a per-domain path under $XDG_CONFIG_HOME/papi/ssh-sync/.";
      };
      guid = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Sync only the slot-9A key whose guid= annotation matches (case-insensitive).";
      };
      intervalSeconds = mkOption {
        type = types.ints.positive;
        default = 3600;
        description = "Re-sync cadence (systemd OnUnitActiveSec / launchd StartInterval).";
      };
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Extra argv appended to `papi ssh-sync`.";
      };
    };
  };
in
{
  options.services.papi-ssh-sync = {
    enable = lib.mkEnableOption "papi ssh-sync — declarative authorized_keys sync from a PAPI domain";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.papi;
      defaultText = lib.literalExpression "papi.packages.\${system}.papi";
      description = "The papi package providing `papi ssh-sync`.";
    };

    # Top-level single-instance options. Mutually exclusive with `instances`.
    domain = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "linenisgreat.com";
      description = "PAPI domain to sync slot-9A keys from (single-instance mode). Use this OR `instances`, not both.";
    };
    authorizedKeysPath = mkOption {
      type = types.nullOr types.str;
      default = null;
      defaultText = lib.literalExpression ''"''${config.xdg.configHome}/papi/ssh-sync/<domain>.keys"'';
      description = "Managed fragment file to rewrite in full each run. Defaults to a per-domain path under $XDG_CONFIG_HOME/papi/ssh-sync/.";
    };
    guid = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Sync only the slot-9A key whose guid= annotation matches (case-insensitive).";
    };
    intervalSeconds = mkOption {
      type = types.ints.positive;
      default = 3600;
      description = "Re-sync cadence in seconds (systemd OnUnitActiveSec / launchd StartInterval).";
    };
    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra argv appended to `papi ssh-sync`.";
    };

    instances = mkOption {
      type = types.attrsOf instanceModule;
      default = { };
      example = lib.literalExpression ''
        {
          work = { domain = "example.com"; };
          home = { domain = "linenisgreat.com"; intervalSeconds = 1800; };
        }
      '';
      description = ''
        Multi-instance map. Each key becomes a `papi-ssh-sync-<name>` systemd
        user timer + service (Linux) or launchd agent (Darwin), each writing its
        own per-domain fragment file. Mutually exclusive with the top-level
        `domain`/`authorizedKeysPath`/`guid`/`intervalSeconds`/`extraArgs`
        options — use one mode or the other.
      '';
    };

    _fragmentPaths = mkOption {
      type = types.attrsOf types.str;
      internal = true;
      visible = false;
      default = { };
      description = ''
        Internal: per-instance managed fragment paths, keyed by unit name.
        Exposed for nixosModules.papi-ssh-sync to enumerate into
        services.openssh.authorizedKeysFiles, and for eval-test to assert the
        rendered paths. Not part of the user-facing surface.
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = perInstanceAssertions ++ [
      {
        assertion = !(hasInstances && topLevelHasInstanceConfig);
        message =
          "services.papi-ssh-sync: top-level options "
          + "(`domain`/`authorizedKeysPath`/`guid`/`intervalSeconds`/`extraArgs`) "
          + "are forbidden when `instances` is non-empty. Use one mode or the other.";
      }
      {
        assertion = hasInstances || cfg.domain != null;
        message = "services.papi-ssh-sync: set `domain` (single-instance) or define `instances`.";
      }
    ];

    home.packages = [ cfg.package ];

    services.papi-ssh-sync._fragmentPaths = lib.mapAttrs (_: built: built.fragmentPath) builtInstances;

    systemd.user.services = mkIf pkgs.stdenv.hostPlatform.isLinux (
      lib.mapAttrs (_: built: built.linuxService) builtInstances
    );

    systemd.user.timers = mkIf pkgs.stdenv.hostPlatform.isLinux (
      lib.mapAttrs (_: built: built.linuxTimer) builtInstances
    );

    launchd.agents = mkIf pkgs.stdenv.hostPlatform.isDarwin (
      lib.mapAttrs (_: built: built.darwinAgent) builtInstances
    );
  };
}
