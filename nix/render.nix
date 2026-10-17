# Renders the options of services.annai to annai.toml plus one TOML file per zone (ADR 0003), and
# runs `annai check` on the result at build time: an invalid zone fails the build, not the server.
{
  pkgs,
  package,
  cfg,
}:
let
  inherit (pkgs) lib;
  toml = pkgs.formats.toml { };
  zoneFile = origin: zone: toml.generate "${origin}toml" (zone // { inherit origin; });
  zones =
    cfg.zones
    // lib.optionalAttrs (cfg.reverse.prefixes != [ ]) (
      import ./reverse.nix {
        inherit lib;
        inherit (cfg) zones reverse;
      }
    );
  raw = toml.generate "annai.toml" (
    {
      inherit (cfg) mode listen;
      zones = lib.mapAttrsToList (origin: zone: "${zoneFile origin zone}") zones;
    }
    // lib.optionalAttrs (cfg.forwarding.upstreams != [ ]) {
      forwarding = {
        inherit (cfg.forwarding) upstreams;
        min_ttl = cfg.forwarding.minTtl;
        max_ttl = cfg.forwarding.maxTtl;
        cache_bytes = cfg.forwarding.cacheBytes;
      };
    }
    // lib.optionalAttrs (cfg.update.keys != { }) {
      update.keys = lib.mapAttrsToList (name: key: {
        inherit name;
        secret_file = key.secretFile;
      }) cfg.update.keys;
    }
  );
in
pkgs.runCommand "annai.toml" { } ''
  ${lib.getExe package} check ${raw}
  cp ${raw} $out
''
