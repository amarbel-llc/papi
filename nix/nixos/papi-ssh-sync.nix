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
self:
{ config, lib, ... }:
{
  home-manager.sharedModules = [ self.homeManagerModules.papi-ssh-sync ];

  # Collect the managed fragment paths from every home-manager user that enabled
  # the service, and make sshd read them. Users that didn't enable it contribute
  # nothing (_fragmentPaths defaults to {}).
  services.openssh.authorizedKeysFiles =
    let
      users = config.home-manager.users or { };
      fragmentsOf = u: lib.attrValues (u.services.papi-ssh-sync._fragmentPaths or { });
      allFragments = lib.concatMap fragmentsOf (lib.attrValues users);
    in
    [ "%h/.ssh/authorized_keys" ] ++ lib.unique allFragments;
}
