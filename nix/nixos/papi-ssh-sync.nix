# NixOS module — `services.papi-ssh-sync` via home-manager, with sshd wiring.
#
# Two jobs:
#   1. Add the home-manager papi-ssh-sync module to every home-manager-managed
#      user, so callers can write:
#
#        home-manager.users.alice.services.papi-ssh-sync = {
#          enable = true;
#          domain = "linenisgreat.com";
#        };
#
#   2. Auto-wire sshd: enumerate every configured instance's managed fragment
#      path into services.openssh.authorizedKeysFiles, so incoming logins
#      actually honor the synced keys. The stock `%h/.ssh/authorized_keys` is
#      re-added explicitly because assigning the list replaces sshd's default.
#
# This is the one platform where the module can wire sshd itself. On nix-darwin
# and standalone home-manager the operator adds the AuthorizedKeysFile line once
# (see docs/features/0005 / README) — the home-manager module still keeps the
# fragment fresh and the timer running there.
#
# Requires the host to also import the home-manager NixOS module (e.g.
# home-manager.nixosModules.home-manager); without it, evaluation fails on the
# unknown `home-manager.sharedModules` option — a clear pointer to the missing
# import.
#
# The list is set at normal priority, so a higher-priority assignment elsewhere
# wins and drops the fragments silently. srvos's SSH hardening does exactly
# that with lib.mkForce [ "/etc/ssh/authorized_keys.d/%u" ]. The module then
# warns at eval time, naming the missing paths. To keep both, the host sets the
# list itself above mkForce, e.g.
#   lib.mkOverride 45 ([ "/etc/ssh/authorized_keys.d/%u" ] ++ <fragment paths>).
self:
{ config, lib, ... }:
let
  # Collect the managed fragment paths from every home-manager user that enabled
  # the service. Users that didn't enable it contribute nothing (_fragmentPaths
  # defaults to {}).
  users = config.home-manager.users or { };
  fragmentsOf = u: lib.attrValues (u.services.papi-ssh-sync._fragmentPaths or { });
  allFragments = lib.unique (lib.concatMap fragmentsOf (lib.attrValues users));
  droppedFragments = lib.subtractLists config.services.openssh.authorizedKeysFiles allFragments;
in
{
  home-manager.sharedModules = [ self.homeManagerModules.papi-ssh-sync ];

  # Make sshd read the fragments.
  services.openssh.authorizedKeysFiles = [ "%h/.ssh/authorized_keys" ] ++ allFragments;

  warnings = lib.optional (droppedFragments != [ ]) (
    "services.papi-ssh-sync: services.openssh.authorizedKeysFiles was overridden "
    + "at a higher priority (for example srvos's lib.mkForce), so sshd will not read "
    + "these synced fragments: ${lib.concatStringsSep ", " droppedFragments}. "
    + "Set the list yourself above that priority and include them; see "
    + "nix/nixos/papi-ssh-sync.nix."
  );
}
