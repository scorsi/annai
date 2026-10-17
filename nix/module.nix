# NixOS module skeleton for annai (ADR 0010): options rendered to TOML and checked at build time by
# nix/render.nix. The service unit comes with the server itself (M1).
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.services.annai;
in
{
  options.services.annai = {
    enable = lib.mkEnableOption "annai, the homelab DNS server";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "annai.packages.\${system}.default";
      description = "The annai package.";
    };

    mode = mkOption {
      type = types.enum [
        "uchi"
        "soto"
      ];
      description = ''
        `uchi`: authoritative for the zones, forwarding resolver for everything else.
        `soto`: authoritative only, accepts RFC 2136 updates (ADR 0002).
      '';
    };

    listen = mkOption {
      type = types.listOf types.str;
      default = [
        "0.0.0.0:53"
        "[::]:53"
      ];
      example = [
        "192.0.2.1:53"
        "[2001:db8::1]:53"
      ];
      description = "`address:port` listeners, UDP and TCP; IPv6 addresses in brackets.";
    };

    forwarding.upstreams = mkOption {
      type = types.listOf types.str;
      default = lib.optionals (cfg.mode == "uchi") [
        "9.9.9.9"
        "2620:fe::fe"
      ];
      defaultText = lib.literalExpression ''[ "9.9.9.9" "2620:fe::fe" ] in uchi mode, [ ] otherwise'';
      description = "Upstream resolver addresses, tried in order (ADR 0008). `uchi` mode only.";
    };

    update.keys = mkOption {
      type = types.attrsOf (
        types.submodule {
          options.secretFile = mkOption {
            type = types.str;
            example = "/run/secrets/annai-tsig-hanko";
            description = "Absolute path to the file holding the HMAC-SHA256 secret (a sops secret path, never a value).";
          };
        }
      );
      default = { };
      description = "TSIG keys allowed to send RFC 2136 updates, by key name (ADR 0006). `soto` mode only.";
    };

    zones = mkOption {
      type = types.attrsOf (pkgs.formats.toml { }).type;
      default = { };
      example = lib.literalExpression ''
        {
          "uchi.example.org." = {
            ttl = 300;
            serial = deployment.lastModified;
            soa = { mname = "annai.uchi.example.org."; rname = "hostmaster.example.org."; refresh = 3600; retry = 600; expire = 604800; minimum = 300; };
            names."@".ns = [ "annai" ];
            names."annai".a = [ "10.100.0.2" ];
          };
        }
      '';
      description = "Zones by origin, in the shape of ADR 0003 without `origin`, which is the attribute name.";
    };

    configFile = mkOption {
      type = types.package;
      readOnly = true;
      default = import ./render.nix {
        inherit pkgs cfg;
        inherit (cfg) package;
      };
      defaultText = lib.literalMD "annai.toml rendered from the options above and checked by `annai check`";
      description = "The generated annai.toml.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."annai/annai.toml".source = cfg.configFile;
  };
}
