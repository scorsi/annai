# nix-darwin resolver client (ADR 0010): annai does not run on macOS, this only points the system
# resolver at it. Clients send all their queries to the uchi instance (ADR 0002): `networking.dns`
# and the search domains of `networking.search` apply to the network services listed in
# `networking.knownNetworkServices` (a deployment value); `/etc/resolver/<domain>` (resolver(5))
# keeps the zone on annai even where a network service's DNS servers are overridden.
{ config, lib, ... }:
let
  cfg = config.services.annai.resolver;
in
{
  options.services.annai.resolver = import ./resolver-options.nix { inherit lib; };

  config = lib.mkIf cfg.enable {
    environment.etc."resolver/${cfg.domain}".text = "nameserver ${cfg.address}\n";
    networking.dns = [ cfg.address ];
    networking.search = [
      cfg.domain
      "kekkai.${cfg.domain}"
    ];
  };
}
