# NixOS module — `services.papi-auth-verifier`: the FDR-0014 PAPI-session
# forward-auth verifier as a systemd service. A consumer (circus) imports this,
# sets the options, and fronts it with nginx `auth_request`:
#
#   services.papi-auth-verifier = {
#     enable = true;
#     externalUrl = "https://forge.example.com";
#     oracleLogin = "http://localhost:9098/authorize";   # the card-machine oracle
#     cookieKeyFile = "/run/secrets/papi-cookie-key";    # decrypted 9D ebox (secret)
#     authorizedKeysFile = "/var/lib/papi/registry";     # papi-ssh-sync fragment (public)
#     allowGroups = [ "owner" ];
#   };
#
# With `enableVerifySignature = true` it ALSO serves POST /auth/verify-signature (the
# FDR-0013 app-native verify oracle). Set it with NONE of cookieKeyFile/oracleLogin/
# externalUrl for a standalone verify-signature-only verifier — the app-native shape a
# consumer that mints its own session (e.g. a Better Auth plugin) points at:
#
#   services.papi-auth-verifier = {
#     enable = true;
#     enableVerifySignature = true;
#     authorizedKeysFile = "/var/lib/papi/registry";     # papi-ssh-sync fragment (public)
#     addr = "127.0.0.1:9099";
#   };
#
# Curried with `self` so `package` defaults to self.packages.${system}.papi — papi
# isn't in nixpkgs, so there is no pkgs.papi fallback.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.papi-auth-verifier;
  # Forward-auth mode (the default) serves /auth/verify|login|callback and needs the
  # cookie/oracle/external config; verify-signature-only mode (enableVerifySignature
  # with none of them) serves just /auth/verify-signature. Mirrors the CLI's own mode
  # selection in newAuthVerifierCmd.
  forwardAuth =
    !cfg.enableVerifySignature
    || cfg.cookieKeyFile != null
    || cfg.oracleLogin != ""
    || cfg.externalUrl != "";
in
{
  options.services.papi-auth-verifier = {
    enable = lib.mkEnableOption "the PAPI-session forward-auth verifier (FDR-0014)";

    enableVerifySignature = lib.mkEnableOption ''
      the FDR-0013 app-native verify oracle (POST /auth/verify-signature): a card §5.2
      signature plus the domain and nonce it was signed over in, the verified principal
      out, as stateless JSON, for a consumer that mints its own session instead of
      taking the verifier cookie. With NONE of cookieKeyFile/oracleLogin/externalUrl set
      the verifier runs verify-signature-only (registry + addr); set alongside them it
      serves both. The endpoint holds no secret (registry public keys only).
    '';

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.papi;
      defaultText = lib.literalExpression "papi.packages.\${system}.papi";
      description = "The papi package providing `papi auth-verifier`.";
    };

    addr = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:9099";
      description = "Address the verifier listens on (nginx `auth_request` proxies to it).";
    };

    cookieKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        File with the verifier-only HMAC cookie key (>= 32 bytes) — a RUNTIME SECRET,
        e.g. a slot-9D ebox decrypted at activation into a restricted-perms file the
        service user can read. Never world-readable. Required for forward-auth mode;
        leave null (with enableVerifySignature) for a verify-signature-only verifier.
      '';
    };

    authorizedKeysFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        The registered cards, as authorized_keys lines: a papi-ssh-sync fragment, or
        a saved `/papi/ssh-authorized-keys` body (RFC-0001 §4.2). The verifier reads
        the ecdsa-sha2-nistp256 (slot-9A auth) lines and ECDSA-verifies each
        card-direct login against them (§5.2). It hot-reloads this file when its mtime
        changes, so a sync refresh (a card added or revoked) takes effect on the next
        login without restarting the service. Public — only public keys, safe to expose.
      '';
    };

    oracleLogin = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "http://localhost:9098/authorize";
      description = ''
        The card-machine oracle's /authorize URL the login flow redirects the browser
        to. With client-side signing this is a localhost URL (the browser is on the
        card machine); the verifier never connects to it, it only emits the redirect.
        Required for forward-auth mode; unused by verify-signature-only.
      '';
    };

    externalUrl = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "https://forge.example.com";
      description = ''
        The verifier's external base URL (scheme://host) — the callback base and §5.2
        signature domain. Required for forward-auth mode; unused by
        verify-signature-only (which takes the domain from each request instead).
      '';
    };

    allowPrincipals = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Allowed principals. Empty principals AND empty groups → any registered card.";
    };

    allowGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "owner" ];
      description = "Allowed groups.";
    };

    cookieSecure = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Set Secure on the session cookie (requires HTTPS; set false only for plain-HTTP over an encrypted tailnet).";
    };

    cookieDomain = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Session cookie Domain (default: host-only).";
    };

    logFormat = lib.mkOption {
      type = lib.types.enum [
        "text"
        "json"
      ];
      default = "json";
      description = "Log output format (json for the journal).";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "papi-auth-verifier";
      description = "System user the service runs as.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion =
          !forwardAuth || (cfg.cookieKeyFile != null && cfg.oracleLogin != "" && cfg.externalUrl != "");
        message = ''
          services.papi-auth-verifier: forward-auth mode needs cookieKeyFile,
          oracleLogin, and externalUrl. For a verify-signature-only verifier, set
          enableVerifySignature = true and leave all three unset.
        '';
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.user;
    };
    users.groups.${cfg.user} = { };

    systemd.services.papi-auth-verifier = {
      description = "PAPI-session forward-auth verifier (FDR-0014)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart =
          let
            args = lib.escapeShellArgs (
              [
                "auth-verifier"
                "--addr"
                cfg.addr
                "--authorized-keys-file"
                (toString cfg.authorizedKeysFile)
                "--log-format"
                cfg.logFormat
              ]
              ++ lib.optional cfg.enableVerifySignature "--enable-verify-signature"
              # Forward-auth flags (cookie/oracle/external + cookie attributes) only when
              # that mode is active; a verify-signature-only verifier omits them all.
              ++ lib.optionals forwardAuth (
                [
                  "--cookie-key-file"
                  (toString cfg.cookieKeyFile)
                  "--oracle-login"
                  cfg.oracleLogin
                  "--external-url"
                  cfg.externalUrl
                ]
                ++ lib.optionals (cfg.cookieDomain != "") [
                  "--cookie-domain"
                  cfg.cookieDomain
                ]
                ++ lib.optional (!cfg.cookieSecure) "--cookie-secure=false"
              )
              ++ lib.concatMap (p: [
                "--allow-principal"
                p
              ]) cfg.allowPrincipals
              ++ lib.concatMap (g: [
                "--allow-group"
                g
              ]) cfg.allowGroups
            );
          in
          "${cfg.package}/bin/papi ${args}";
        User = cfg.user;
        Restart = "on-failure";
        RestartSec = "2s";
        # hardening — the verifier needs only its key files + the network.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallFilter = [ "@system-service" ];
      };
    };
  };
}
