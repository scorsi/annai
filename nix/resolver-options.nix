# Options shared by the NixOS and nix-darwin resolver client modules (ADR 0010).
{ lib }:
{
  enable = lib.mkEnableOption "resolving the internal zone through annai";

  address = lib.mkOption {
    type = lib.types.str;
    example = "10.100.0.2";
    description = "Address of the `uchi` annai instance (a stable overlay address once kekkai runs).";
  };

  domain = lib.mkOption {
    type = lib.types.str;
    example = "uchi.example.org";
    description = ''
      The internal zone. It and `kekkai.<domain>` are pushed as search domains (ADR 0005), so
      `<service>` and `<node>` resolve unqualified; queries under it go to {option}`address`.
    '';
  };
}
