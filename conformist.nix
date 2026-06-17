# This repo's conformist overlay, merged with conformist.lib.presets.eng in
# flake.nix. The preset enables the eng-convention linters; here we choose the
# formatters and repo-specific tweaks.
{ ... }:
{
  # Formatters: nixfmt for the flake, gofmt for the validator's Go sources.
  programs.nixfmt.enable = true;
  programs.gofmt.enable = true;

  # eng-versioning(7) derives the key from go.mod (module .../papi -> PAPI_VERSION);
  # set it explicitly too so version.env stays the unambiguous source of truth.
  linters.eng-versioning.key = "PAPI_VERSION";

  # Generated / locked / prose files are out of scope for code formatters.
  settings.excludes = [
    "gomod2nix.toml"
    "go.sum"
    "flake.lock"
    "*.md"
    "LICENSE"
  ];
}
