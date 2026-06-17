# This repo's conformist overlay, merged with conformist.lib.presets.eng in
# flake.nix. The preset enables the eng-convention linters; here you choose the
# formatters and any repo-specific tweaks.
{ ... }:
{
  # Formatters this repo wants. nixfmt formats the flake itself; gofmt arrives
  # with the validator's Go sources. See `man conformist.toml` and the conformist
  # programs registry.
  programs.nixfmt.enable = true;

  # eng-versioning(7) derives the version key from go.mod / Cargo.toml. There is
  # no go.mod yet (the validator lands next), so set the key explicitly to match
  # version.env. Once go.mod exists with module .../papi this derives PAPI_VERSION
  # on its own and this line can be dropped.
  linters.eng-versioning.key = "PAPI_VERSION";

  # Prose and generated files are out of scope for code formatters.
  settings.excludes = [
    "*.md"
    "flake.lock"
    "LICENSE"
  ];
}
