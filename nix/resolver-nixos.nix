# NixOS resolver client (ADR 0010): annai as the per-link DNS server of the interface that reaches
# it, in systemd-resolved, with the internal zone as search and routing domains. Only names under
# the zone go to annai until M2 makes it the resolver for everything.
{
  config,
  lib,
  utils,
  ...
}:
let
  cfg = config.services.annai.resolver;
  device = "sys-subsystem-net-devices-${utils.escapeSystemdPath cfg.interface}.device";
  resolvectl = "${config.systemd.package}/bin/resolvectl";
in
{
  options.services.annai.resolver = import ./resolver-options.nix { inherit lib; } // {
    interface = lib.mkOption {
      type = lib.types.str;
      example = "kekkai0";
      description = "The link through which {option}`address` is reached; the settings are bound to it.";
    };
  };

  config = lib.mkIf cfg.enable {
    services.resolved.enable = true;

    # Applied whenever the link appears, whoever manages it; a manager that rewrites the link's
    # DNS settings afterwards (networkd, NetworkManager) wins, which is a deployment concern.
    systemd.services.annai-resolver = {
      description = "annai as the resolver of ${cfg.domain} on ${cfg.interface}";
      bindsTo = [ device ];
      after = [
        device
        "systemd-resolved.service"
      ];
      wants = [ "systemd-resolved.service" ];
      wantedBy = [ device ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        ${resolvectl} dns ${cfg.interface} ${cfg.address}
        ${resolvectl} domain ${cfg.interface} ${cfg.domain} kekkai.${cfg.domain}
        ${resolvectl} default-route ${cfg.interface} false
      '';
    };
  };
}
