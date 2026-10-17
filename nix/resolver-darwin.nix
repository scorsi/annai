# nix-darwin resolver client (ADR 0010): annai does not run on macOS, this only points the system
# resolver at it. `/etc/resolver/<domain>` (resolver(5)) sends every name under the zone to annai;
# the search domains go through `networking.search`, which nix-darwin applies to the network
# services listed in `networking.knownNetworkServices` (a deployment value).
{ config, lib, ... }:
let
  cfg = config.services.annai.resolver;
in
{
  options.services.annai.resolver = import ./resolver-options.nix { inherit lib; };

  config = lib.mkIf cfg.enable {
    environment.etc."resolver/${cfg.domain}".text = "nameserver ${cfg.address}\n";
    networking.search = [
      cfg.domain
      "kekkai.${cfg.domain}"
    ];
  };
}
