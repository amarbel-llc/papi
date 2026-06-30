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
in
{
  options.services.papi-auth-verifier = {
    enable = lib.mkEnableOption "the PAPI-session forward-auth verifier (FDR-0014)";

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
      type = lib.types.path;
      description = ''
        File with the verifier-only HMAC cookie key (>= 32 bytes) — a RUNTIME SECRET,
        e.g. a slot-9D ebox decrypted at activation into a restricted-perms file the
        service user can read. Never world-readable.
      '';
    };

    authorizedKeysFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        The registered cards, as authorized_keys lines: a papi-ssh-sync fragment, or
        a saved `/papi/ssh-authorized-keys` body (RFC-0001 §4.2). The verifier reads
        the ecdsa-sha2-nistp256 (slot-9A auth) lines and ECDSA-verifies each
        card-direct login against them (§5.2). Public — only public keys, safe to
        expose.
      '';
    };

    oracleLogin = lib.mkOption {
      type = lib.types.str;
      example = "http://localhost:9098/authorize";
      description = ''
        The card-machine oracle's /authorize URL the login flow redirects the browser
        to. With client-side signing this is a localhost URL (the browser is on the
        card machine); the verifier never connects to it, it only emits the redirect.
      '';
    };

    externalUrl = lib.mkOption {
      type = lib.types.str;
      example = "https://forge.example.com";
      description = "The verifier's external base URL (scheme://host) — the callback base and §5.2 signature domain.";
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
                "--cookie-key-file"
                (toString cfg.cookieKeyFile)
                "--authorized-keys-file"
                (toString cfg.authorizedKeysFile)
                "--oracle-login"
                cfg.oracleLogin
                "--external-url"
                cfg.externalUrl
                "--log-format"
                cfg.logFormat
              ]
              ++ lib.optionals (cfg.cookieDomain != "") [
                "--cookie-domain"
                cfg.cookieDomain
              ]
              ++ lib.optional (!cfg.cookieSecure) "--cookie-secure=false"
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
