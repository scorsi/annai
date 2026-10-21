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
        max_ttl = cfg.forwarding.maxTtl;
        cache_bytes = cfg.forwarding.cacheBytes;
      };
    }
    // lib.optionalAttrs (cfg.metrics.listen != null) { metrics = cfg.metrics.listen; }
    // lib.optionalAttrs (cfg.update.keys != { }) {
      update = {
        # The path LoadCredential gives the unit (nix/module.nix), not the secret's own path.
        keys = lib.mapAttrsToList (name: _: {
          inherit name;
          secret_file = "/run/credentials/annai.service/tsig-${name}";
        }) cfg.update.keys;
        max_ttl = cfg.update.maxTtl;
        inherit (cfg.update) lifetime;
      };
    }
  );
in
pkgs.runCommand "annai.toml" { } ''
  ${lib.getExe package} check ${raw}
  cp ${raw} $out
''
