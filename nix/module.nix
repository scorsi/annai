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
  imports = [
    (lib.mkRemovedOptionModule [ "services" "annai" "forwarding" "minTtl" ] ''
      Remove this option: upstream TTLs are never raised (ADR 0012: docs/adr/0012-cache-ttl-bounds.md).
    '')
  ];

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
            description = ''
              Absolute path to the file holding the HMAC-SHA256 secret (a sops secret path, never a
              value): one line, the base64 secret, optionally prefixed with `<key name>:` as in
              hanko's key files. Read by root through `LoadCredential`, so a `0400` root file works.
            '';
          };
        }
      );
      default = { };
      description = "TSIG keys allowed to send RFC 2136 updates, by key name (ADR 0006). `soto` mode only.";
    };

    update.maxTtl = mkOption {
      type = types.ints.between 0 2147483647;
      default = 120;
      description = "Cap on the TTL served for a dynamic `_acme-challenge` TXT record, in seconds, so resolvers do not cache an old challenge. The default is the value fixed by ADR 0006 and deployments keep it; the option exists so tests can use short values.";
    };

    update.lifetime = mkOption {
      type = types.ints.between 0 2147483647;
      default = 3600;
      description = "Seconds a dynamic record stays when the client never deletes it, e.g. after a crash. The default is the value fixed by ADR 0006 and deployments keep it; the option exists so tests can use short values.";
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

    metrics.listen = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9153";
      description = "`127.0.0.1:<port>` or `[::1]:<port>` of the Prometheus `GET /metrics` listener (ADR 0011); `null` = no listener. Loopback only: the local agent is the only scraper.";
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
    assertions = [
      {
        assertion =
          cfg.metrics.listen == null
          || builtins.match "(127\\.0\\.0\\.1|\\[::1])(:[0-9]+)" cfg.metrics.listen != null;
        message = "services.annai.metrics.listen must be 127.0.0.1:<port> or [::1]:<port>, got ${toString cfg.metrics.listen}";
      }
    ];

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
        # TSIG secrets stay root-owned on disk; systemd hands them to the dynamic user (ADR 0006).
        LoadCredential = lib.mapAttrsToList (name: key: "tsig-${name}:${key.secretFile}") cfg.update.keys;
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
        # One line per query (nisshi ADR 0009): 1000 lines/s sustained before journald drops.
        LogRateLimitIntervalSec = lib.mkDefault "30s";
        LogRateLimitBurst = lib.mkDefault 30000;
      };
    };
  };
}
