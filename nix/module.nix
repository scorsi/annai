# NixOS module for annai (ADR 0010): options rendered to TOML and checked at build time by
# nix/render.nix, and the hardened service unit (ADR 0011).
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
      description = "Upstream resolver addresses, tried in order (ADR 0008). `uchi` mode only; empty = names outside the zones are REFUSED.";
    };

    forwarding.minTtl = mkOption {
      type = types.ints.between 0 2147483647;
      default = 0;
      description = "Lower clamp of the lifetime of a cached positive answer, in seconds (ADR 0008).";
    };

    forwarding.maxTtl = mkOption {
      type = types.ints.between 0 2147483647;
      default = 86400;
      description = "Upper clamp of the lifetime of any cached answer, negative ones included, in seconds (ADR 0008).";
    };

    forwarding.cacheBytes = mkOption {
      type = types.ints.unsigned;
      default = 16 * 1024 * 1024;
      description = "Hard cap on the cache size in bytes; least recently used answers are evicted beyond it (ADR 0008).";
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

    reverse.zone = mkOption {
      type = types.str;
      example = "uchi.example.org.";
      description = "The zone of {option}`services.annai.zones` whose `<node>.kekkai` A and AAAA records become the PTRs of the reverse zones; they reuse its SOA, NS, TTL and serial.";
    };

    reverse.prefixes = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [
        "10.100.0.0/16"
        "fd12:3456:789a::/48"
      ];
      description = ''
        kekkai's IPv4 range and IPv6 prefix (ADR 0005): one `in-addr.arpa` or `ip6.arpa` zone each,
        with `PTR <node>.kekkai.<zone>` for every A or AAAA of such a node name of
        {option}`services.annai.reverse.zone` inside it. Lengths end on an octet (IPv4) or nibble (IPv6) boundary.
      '';
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

    systemd.services.annai = {
      description = "annai DNS server (${cfg.mode} mode)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      # ADR 0011 v0: a configuration change restarts the service (reload is M5).
      restartTriggers = [ cfg.configFile ];
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} serve ${cfg.configFile}";
        Restart = "on-failure";
        RestartSec = "2s";
        # annai never writes to disk (ADR 0003) and only needs to bind port 53.
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        UMask = "0077";
      };
    };
  };
}
