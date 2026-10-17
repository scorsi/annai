# The configuration the flake checks evaluate: the uchi zone of ADR 0003.
{
  services.annai = {
    enable = true;
    mode = "uchi";
    # ADR 0005: PTRs for kekkai's ranges, generated from the <node>.kekkai A/AAAA records below.
    reverse = {
      zone = "uchi.example.org.";
      prefixes = [
        "10.100.0.0/16"
        "fd12:3456:789a::/48"
      ];
    };
    zones."uchi.example.org." = {
      ttl = 300;
      serial = 1760400000;
      soa = {
        mname = "annai.uchi.example.org.";
        rname = "hostmaster.example.org.";
        refresh = 3600;
        retry = 600;
        expire = 604800;
        minimum = 300;
      };
      names = {
        "@".ns = [ "annai.uchi.example.org." ];
        "annai".a = [ "10.100.0.2" ];
        "hub.kekkai" = {
          a = [ "10.100.0.1" ];
          aaaa = [ "fd12:3456:789a::1" ];
        };
        "vm.kekkai".a = [ "10.100.0.3" ];
        "git".cname = "vm.kekkai";
        "_imaps._tcp".srv = [
          {
            priority = 10;
            weight = 0;
            port = 993;
            target = "mail.soto.example.org.";
          }
        ];
        "mail".mx = [
          {
            preference = 10;
            exchange = "mail.soto.example.org.";
          }
        ];
        "info".txt = [ "v=spf1 -all" ];
      };
    };
  };
}
