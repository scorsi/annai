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
  raw = toml.generate "annai.toml" (
    {
      inherit (cfg) mode listen;
      zones = lib.mapAttrsToList (origin: zone: "${zoneFile origin zone}") cfg.zones;
    }
    // lib.optionalAttrs (cfg.forwarding.upstreams != [ ]) {
      forwarding = { inherit (cfg.forwarding) upstreams; };
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
