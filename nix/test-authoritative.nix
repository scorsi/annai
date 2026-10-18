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
        services.annai.zones."uchi.example.org.".names = {
          big.txt = map (_: lib.concatStrings (lib.replicate 255 "x")) (lib.range 1 8);
          # Wildcards (RFC 4592): a wildcard with a sibling name, an empty non-terminal below
          # it, and a wildcard CNAME.
          "*.wild".a = [ "10.100.0.9" ];
          "host.wild".a = [ "10.100.0.10" ];
          "x.ent.wild".a = [ "10.100.0.11" ];
          "*.alias".cname = "vm.kekkai";
        };
        # No forwarding (no Internet in the sandbox): names outside the zones stay REFUSED.
        services.annai.forwarding.upstreams = [ ];
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
          m = re.search(r"MSG SIZE  rcvd: (\d+)", out)
          assert m, f"no MSG SIZE line in dig output: {out}"
          return int(m.group(1))

      server.wait_for_unit("annai.service")
      server.wait_for_open_port(53)
      client.wait_for_unit("multi-user.target")

      with subtest("A over UDP: AA, the question keeps the client's case"):
          out = q("+noall +comments +question +answer HuB.Kekkai.UCHI.example.org A")
          assert "flags: qr aa;" in out and "status: NOERROR" in out, out
          assert ";HuB.Kekkai.UCHI.example.org." in out and "10.100.0.1" in out, out

      with subtest("AAAA over the IPv6 listener"):
          out = q("+short hub.kekkai.uchi.example.org AAAA", server=v6)
          assert "fd12:3456:789a::1" in out, out

      with subtest("CNAME chased in zone, over TCP"):
          out = q("+tcp +noall +answer git.uchi.example.org A")
          assert re.search(r"CNAME\s+vm\.kekkai\.uchi\.example\.org\.", out) and "10.100.0.3" in out, out

      with subtest("apex SOA and NS in the answer section (hanko locates the zone here)"):
          out = q("+noall +answer uchi.example.org SOA")
          assert re.search(r"IN\s+SOA\s+annai\.uchi\.example\.org\. hostmaster\.example\.org\.", out), out
          out = q("+noall +answer uchi.example.org NS")
          assert re.search(r"IN\s+NS\s+annai\.uchi\.example\.org\.", out), out

      with subtest("NXDOMAIN, NODATA and empty non-terminal carry the SOA in the authority section"):
          out = q("+noall +comments +authority nope.uchi.example.org A")
          assert "status: NXDOMAIN" in out and re.search(r"uchi\.example\.org\.\s+300\s+IN\s+SOA", out), out
          for name, rtype in [("hub.kekkai.uchi.example.org", "MX"), ("kekkai.uchi.example.org", "A")]:
              out = q(f"+noall +comments +authority {name} {rtype}")
              assert "status: NOERROR" in out and "ANSWER: 0" in out and re.search(r"IN\s+SOA", out), out

      with subtest("REFUSED outside the loaded zones and for UPDATE in uchi mode, NOTIMP for other opcodes"):
          # Opcode 5 (UPDATE) is REFUSED on a uchi (ADR 0006); opcode 2 (STATUS) is not implemented.
          for args, status in [("example.net A", "REFUSED"), ("org A", "REFUSED"), ("+opcode=5 hub.kekkai.uchi.example.org A", "REFUSED"), ("+opcode=2 hub.kekkai.uchi.example.org A", "NOTIMP")]:
              out = q(f"+noall +comments {args}")
              assert f"status: {status}" in out, out
          out = server.succeed("journalctl -u annai.service --no-pager")
          assert "event=update-refused" in out and "reason=uchi-mode" in out, out

      with subtest("SRV, MX, TXT, ANY"):
          for args, expected in [("_imaps._tcp.uchi.example.org SRV", "10 0 993 mail.soto.example.org."), ("mail.uchi.example.org MX", "10 mail.soto.example.org."), ("info.uchi.example.org TXT", '"v=spf1 -all"')]:
              out = q(f"+short {args}")
              assert expected in out, out
          out = q("+noall +answer hub.kekkai.uchi.example.org ANY")
          assert re.search(r'HINFO\s+"RFC8482" ""', out), out

      with subtest("wildcards (RFC 4592)"):
          for name, addr in [("anything.wild.uchi.example.org", "10.100.0.9"), ("a.b.wild.uchi.example.org", "10.100.0.9"), ("*.wild.uchi.example.org", "10.100.0.9"), ("host.wild.uchi.example.org", "10.100.0.10")]:
              out = q(f"+noall +comments +answer {name} A")
              assert "flags: qr aa;" in out and re.search(rf"^{re.escape(name)}\.\s+300\s+IN\s+A\s+{re.escape(addr)}$", out, re.M), out
          out = q("+noall +answer foo.alias.uchi.example.org A")
          assert re.search(r"^foo\.alias\.uchi\.example\.org\.\s+300\s+IN\s+CNAME\s+vm\.kekkai\.uchi\.example\.org\.$", out, re.M) and "10.100.0.3" in out, out
          # No synthesis below an existing name, for an empty non-terminal, below the wildcard
          # itself, or for a type the wildcard lacks (NODATA).
          for name, rtype, status in [("sub.host.wild.uchi.example.org", "A", "NXDOMAIN"), ("ent.wild.uchi.example.org", "A", "NOERROR"), ("ghost.*.wild.uchi.example.org", "A", "NXDOMAIN"), ("anything.wild.uchi.example.org", "MX", "NOERROR")]:
              out = q(f"+noall +comments +authority {name} {rtype}")
              assert f"status: {status}" in out and "ANSWER: 0" in out and re.search(r"IN\s+SOA", out), out

      with subtest("EDNS payload sizing and truncation"):
          out = q("+noedns +ignore +noall +comments +stats big.uchi.example.org TXT")
          assert "flags: qr aa tc;" in out and size(out) <= 512, out
          out = q("+bufsize=4096 +ignore +noall +comments +stats big.uchi.example.org TXT")
          assert "flags: qr aa tc;" in out and "udp: 1232" in out and 512 < size(out) <= 1232, out
          out = q("+tcp +noall +comments big.uchi.example.org TXT")
          assert "ANSWER: 8" in out and "tc;" not in out, out

      with subtest("the resolver module: per-link DNS and search domains"):
          client.wait_for_unit("annai-resolver.service")
          out = client.succeed("resolvectl query hub.kekkai.uchi.example.org")
          assert "10.100.0.1" in out, out
          # `getent hosts` is gethostbyname2(AF_INET6) first and prints only that family when an
          # AAAA exists (glibc nss/getent.c), so ask for the A records explicitly. `hub` exists
          # only under kekkai.<domain>: resolving it at all proves the second search domain.
          for name, addr in [("hub", "10.100.0.1"), ("annai", "10.100.0.2")]:
              out = client.succeed(f"getent ahostsv4 {name}")
              assert addr in out, out
    '';
}
