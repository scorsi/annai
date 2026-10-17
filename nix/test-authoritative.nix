# M1 nixosTest (ADR 0011): `dig` as the oracle for the authoritative semantics of ADR 0007 over
# UDP and TCP, IPv4 and IPv6, against the uchi zone of nix/example.nix, plus the NixOS resolver
# client module resolving through the server with the search domains of ADR 0005.
{ self, pkgs }:
pkgs.testers.runNixOSTest {
  name = "annai-authoritative";

  nodes = {
    server =
      { lib, ... }:
      {
        imports = [
          self.nixosModules.default
          ./example.nix
        ];
        # Eight 255-byte strings: over 1232 bytes, so UDP answers are truncated and TCP is needed.
        services.annai.zones."uchi.example.org.".names.big.txt = map (
          _: lib.concatStrings (lib.replicate 255 "x")
        ) (lib.range 1 8);
        networking.firewall.allowedUDPPorts = [ 53 ];
        networking.firewall.allowedTCPPorts = [ 53 ];
      };

    client =
      { nodes, ... }:
      {
        imports = [ self.nixosModules.resolver ];
        environment.systemPackages = [ pkgs.dig ];
        services.annai.resolver = {
          enable = true;
          address = nodes.server.networking.primaryIPAddress;
          interface = "eth1";
          domain = "uchi.example.org";
        };
      };
  };

  testScript =
    { nodes, ... }:
    ''
      import re

      v4 = "${nodes.server.networking.primaryIPAddress}"
      v6 = "${nodes.server.networking.primaryIPv6Address}"

      def q(args, server=v4):
          return client.succeed(f"dig @{server} +time=3 +tries=1 +norecurse {args}")

      def size(out):
          return int(re.search(r"MSG SIZE  rcvd: (\d+)", out).group(1))

      server.wait_for_unit("annai.service")
      server.wait_for_open_port(53)
      client.wait_for_unit("multi-user.target")

      with subtest("A over UDP: AA, the question keeps the client's case"):
          out = q("+noall +comments +question +answer HuB.Kekkai.UCHI.example.org A")
          assert "flags: qr aa;" in out and "status: NOERROR" in out, out
          assert ";HuB.Kekkai.UCHI.example.org." in out and "10.100.0.1" in out, out

      with subtest("AAAA over the IPv6 listener"):
          assert "fd12:3456:789a::1" in q("+short hub.kekkai.uchi.example.org AAAA", server=v6)

      with subtest("CNAME chased in zone, over TCP"):
          out = q("+tcp +noall +answer git.uchi.example.org A")
          assert re.search(r"CNAME\s+vm\.kekkai\.uchi\.example\.org\.", out) and "10.100.0.3" in out, out

      with subtest("apex SOA and NS in the answer section (hanko locates the zone here)"):
          assert re.search(r"IN\s+SOA\s+annai\.uchi\.example\.org\. hostmaster\.example\.org\.", q("+noall +answer uchi.example.org SOA"))
          assert re.search(r"IN\s+NS\s+annai\.uchi\.example\.org\.", q("+noall +answer uchi.example.org NS"))

      with subtest("NXDOMAIN, NODATA and empty non-terminal carry the SOA in the authority section"):
          out = q("+noall +comments +authority nope.uchi.example.org A")
          assert "status: NXDOMAIN" in out and re.search(r"uchi\.example\.org\.\s+300\s+IN\s+SOA", out), out
          for name, rtype in [("hub.kekkai.uchi.example.org", "MX"), ("kekkai.uchi.example.org", "A")]:
              out = q(f"+noall +comments +authority {name} {rtype}")
              assert "status: NOERROR" in out and "ANSWER: 0" in out and re.search(r"IN\s+SOA", out), out

      with subtest("REFUSED outside the loaded zones, NOTIMP for other opcodes"):
          assert "status: REFUSED" in q("+noall +comments example.net A")
          assert "status: REFUSED" in q("+noall +comments org A")
          assert "status: NOTIMP" in q("+noall +comments +opcode=5 hub.kekkai.uchi.example.org A")

      with subtest("SRV, MX, TXT, ANY"):
          assert "10 0 993 mail.soto.example.org." in q("+short _imaps._tcp.uchi.example.org SRV")
          assert "10 mail.soto.example.org." in q("+short mail.uchi.example.org MX")
          assert '"v=spf1 -all"' in q("+short info.uchi.example.org TXT")
          assert re.search(r'HINFO\s+"RFC8482" ""', q("+noall +answer hub.kekkai.uchi.example.org ANY"))

      with subtest("EDNS payload sizing and truncation"):
          out = q("+noedns +ignore +noall +comments +stats big.uchi.example.org TXT")
          assert "flags: qr aa tc;" in out and size(out) <= 512, out
          out = q("+bufsize=4096 +ignore +noall +comments +stats big.uchi.example.org TXT")
          assert "flags: qr aa tc;" in out and "udp: 1232" in out and 512 < size(out) <= 1232, out
          out = q("+tcp +noall +comments big.uchi.example.org TXT")
          assert "ANSWER: 8" in out and "tc;" not in out, out

      with subtest("the resolver module: per-link DNS and search domains"):
          client.wait_for_unit("annai-resolver.service")
          assert "10.100.0.1" in client.succeed("resolvectl query hub.kekkai.uchi.example.org")
          assert "10.100.0.1" in client.succeed("getent hosts hub")
          assert "10.100.0.2" in client.succeed("getent hosts annai")
    '';
}
