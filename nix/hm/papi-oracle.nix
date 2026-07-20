# home-manager module for `services.papi-oracle`.
#
# Runs the RFC-0001 §5.2 card oracle (`papi sign-challenge-serve`) as a
# long-running per-user service in AUTHORIZE-ONLY mode: it serves just the
# FDR-0014 forward-auth `/authorize` leg a browser is redirected to during a
# card login (no `/sign` SPA endpoint, no PAPI-server broker). It is the
# client-side sibling to `nixosModules.papi-auth-verifier` (the server side): the
# verifier runs on the protected host, this oracle runs on the user's own machine
# where the card physically lives, and the browser bounces between them.
#
# Linux uses a systemd user service; Darwin uses a launchd agent. Both start at
# login and run whether or not a card is present — the oracle only touches the
# card at sign time (per /authorize request), via the SSH agent (default
# `--signer agent`, pointed at `agentSocket`). If the card is absent or the agent
# is locked, only the sign leg fails (the login just doesn't complete); the daemon
# stays up and recovers the instant the card returns. So there is deliberately no
# card-presence gate at startup and no aggressive restart loop.
#
# Curried with `self` (the papi flake) so `package` defaults to
# self.packages.${system}.papi — papi is not in nixpkgs.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkIf mkOption types;

  cfg = config.services.papi-oracle;

  argv = [
    "sign-challenge-serve"
    "--addr"
    cfg.addr
  ]
  ++ lib.concatMap (c: [
    "--allow-callback"
    c
  ]) cfg.allowCallbacks
  ++ [
    "--signer"
    cfg.signer
  ]
  ++ lib.optionals (cfg.agentSocket != "") [
    "--agent-socket"
    cfg.agentSocket
  ]
  ++ lib.optionals (cfg.guid != null) [
    "--guid"
    cfg.guid
  ]
  ++ [
    "--log-format"
    cfg.logFormat
  ]
  ++ cfg.extraArgs;

  # Linux ExecStart is a single command line; Darwin ProgramArguments is an argv
  # list (launchd runs no shell). No runtime shell expansion is needed — every arg
  # resolves to a concrete string at eval time.
  exec = "${cfg.package}/bin/papi " + lib.escapeShellArgs argv;
  programArguments = [ "${cfg.package}/bin/papi" ] ++ argv;
in
{
  options.services.papi-oracle = {
    enable = lib.mkEnableOption "papi sign-challenge oracle — the FDR-0014 forward-auth /authorize card-signer";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.papi;
      defaultText = lib.literalExpression "papi.packages.\${system}.papi";
      description = "The papi package providing `papi sign-challenge-serve`.";
    };

    addr = mkOption {
      type = types.str;
      default = "127.0.0.1:9098";
      description = ''
        Loopback address the oracle listens on. The verifier redirects the browser
        here, so it must match the verifier's `oracleLogin` host:port. Keep it on
        127.0.0.1 — the browser is on this same machine; there is no reason to expose
        the card-signer on the network.
      '';
    };

    allowCallbacks = mkOption {
      type = types.listOf types.str;
      example = [ "https://forge.linenisgreat.com/auth/callback" ];
      description = ''
        Exact verifier callback URLs the /authorize card-sign may sign for. Required
        (non-empty) — this enables /authorize, and the oracle binds each signature to
        the callback's host, so a page cannot coax a signature for another verifier.
      '';
    };

    signer = mkOption {
      type = types.enum [
        "agent"
        "auto"
        "pcsc"
      ];
      default = "agent";
      description = ''
        slot-9A signer. Default `agent` (the SSH agent at `agentSocket`) is the only
        one that starts cardless: it dials the socket lazily at sign time. `pcsc`
        (and `auto` when no agent socket is found) enumerates the card AT STARTUP and
        so fails to start without a card — avoid it for an always-on user service
        unless you also set `guid`.
      '';
    };

    agentSocket = mkOption {
      type = types.str;
      default = "${config.home.homeDirectory}/.local/state/ssh/mux-agent.sock";
      defaultText = lib.literalExpression ''"''${config.home.homeDirectory}/.local/state/ssh/mux-agent.sock"'';
      description = ''
        SSH agent socket the `agent` signer dials for slot-9A. Defaults to the
        eng ssh-agent-mux socket (which fronts piggy-agent's slot 9A). Set explicitly
        so the user service need not inherit $SSH_AUTH_SOCK. Empty string falls back
        to $SSH_AUTH_SOCK.
      '';
    };

    guid = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Sign with the slot-9A key whose guid=<HEX> matches (default: the sole card).";
    };

    logFormat = mkOption {
      type = types.enum [
        "text"
        "json"
      ];
      default = "json";
      description = "Log output format (json for the journal).";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra argv appended to `papi sign-challenge-serve`.";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.allowCallbacks != [ ];
        message = "services.papi-oracle: `allowCallbacks` must be non-empty (it enables the /authorize endpoint the oracle serves).";
      }
    ];

    home.packages = [ cfg.package ];

    systemd.user.services = mkIf pkgs.stdenv.hostPlatform.isLinux {
      papi-oracle = {
        Unit = {
          Description = "papi sign-challenge oracle (FDR-0014 forward-auth /authorize)";
          Documentation = "https://code.linenisgreat.com/papi";
        };
        Service = {
          Type = "simple";
          ExecStart = exec;
          # Runs fine cardless (only the sign leg needs the card), so on-failure only
          # catches real crashes (e.g. the port already bound). Not a restart storm.
          Restart = "on-failure";
          RestartSec = "5s";
        };
        Install.WantedBy = [ "default.target" ];
      };
    };

    launchd.agents = mkIf pkgs.stdenv.hostPlatform.isDarwin {
      papi-oracle = {
        enable = true;
        config = {
          ProgramArguments = programArguments;
          RunAtLoad = true;
          KeepAlive = true; # keep the oracle up; it's cheap and idle when unused
          ProcessType = "Background";
          StandardErrorPath = "${config.home.homeDirectory}/Library/Logs/papi-oracle.log";
        };
      };
    };
  };
}
