# The configuration of a public nameserver (ADR 0004, 0009): a `soto` instance with the apex zone
# (public records only, a CAA record, no `uchi` names) and hanko's TSIG key (ADR 0006). Evaluated
# by the module check on every system and by the update nixosTest.
{
  services.annai = {
    enable = true;
    mode = "soto";
    # Root-owned sops secret in the deployment; the unit reads it through LoadCredential.
    update.keys.hanko.secretFile = "/etc/annai/hanko.key";
    zones."example.org." = {
      ttl = 300;
      serial = 1760400000;
      soa = {
        mname = "ns1.example.org.";
        rname = "hostmaster.example.org.";
        refresh = 3600;
        retry = 600;
        expire = 604800;
        minimum = 300;
      };
      names = {
        "@" = {
          ns = [
            "ns1"
            "ns2"
          ];
          a = [ "192.0.2.1" ];
          caa = [
            {
              flags = 0;
              tag = "issue";
              value = "letsencrypt.org";
            }
          ];
        };
        ns1 = {
          a = [ "192.0.2.53" ];
          aaaa = [ "2001:db8::53" ];
        };
        ns2.a = [ "192.0.2.54" ];
        "www.soto".a = [ "192.0.2.80" ];
        www.cname = "www.soto";
      };
    };
  };
}
