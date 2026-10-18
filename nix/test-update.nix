# M3 nixosTest (ADR 0011): a `soto` VM with the apex zone of nix/example-soto.nix and hanko's
# TSIG key, a client VM with BIND's `nsupdate` and `dig` as the oracle. Covers the soto mode of
# ADR 0002 (RD ignored, RA=0, REFUSED outside the zones), CAA, RFC 2136 UPDATE under the ADR 0006
# policy (add RR, delete RR, delete RRset, TTL cap, empty non-terminals of ADR 0004, expiry), TSIG
# (signed answers, BADSIG, BADKEY, BADTIME), and the secret file handed over by LoadCredential.
{ self, pkgs }:
let
  secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldC0xMjM0";
in
pkgs.testers.runNixOSTest {
  name = "annai-update";

  nodes = {
    soto = {
      imports = [
        self.nixosModules.default
        ./example-soto.nix
      ];
      # Short enough to watch a record expire; the deployment keeps the default hour.
      services.annai.update.lifetime = 15;
      # Root-only, as a sops secret is: only LoadCredential can get it to the dynamic user.
      environment.etc."annai/hanko.key" = {
        text = "hanko:${secret}\n";
        mode = "0400";
      };
      networking.firewall.allowedUDPPorts = [ 53 ];
      networking.firewall.allowedTCPPorts = [ 53 ];
    };

    client = {
      environment.systemPackages = [ pkgs.dnsutils ];
    };
  };

  testScript =
    { nodes, ... }:
    ''
      import re

      v4 = "${nodes.soto.networking.primaryIPAddress}"
      key = "hmac-sha256:hanko:${secret}"
      challenge = "_acme-challenge.git.uchi.example.org"

      def q(args):
          return client.succeed(f"dig @{v4} +time=3 +tries=1 {args}")

      def nsupdate(script, key=key, opts=""):
          """nsupdate's own output; the exit status is not the oracle, the printed rcode is."""
          lines = f"server {v4}\nzone example.org\n{script}\nsend\n"
          key_opt = f"-y {key}" if key else ""
          _, out = client.execute(f"printf '{lines}' | nsupdate {key_opt} {opts} 2>&1")
          return out

      soto.wait_for_unit("annai.service")
      soto.wait_for_open_port(53)
      client.wait_for_unit("multi-user.target")

      with subtest("soto: RD echoed but ignored, RA never set, REFUSED outside the zones"):
          out = q("+noall +comments +answer www.example.org A")
          assert "flags: qr aa rd;" in out and "status: NOERROR" in out and "192.0.2.80" in out, out
          out = q("+noall +comments www.example.net A")
          assert "status: REFUSED" in out, out

      with subtest("CAA"):
          out = q("+short example.org CAA")
          assert '0 issue "letsencrypt.org"' in out, out

      with subtest("add over UDP: TTL capped at 120, the names above the challenge exist (NODATA)"):
          out = nsupdate(f"update add {challenge} 3600 TXT tok1")
          assert "failed" not in out, out
          out = q(f"+noall +answer {challenge} TXT")
          assert re.search(rf"{challenge}\.\s+120\s+IN\s+TXT\s+\"tok1\"", out), out
          for name in ["git.uchi.example.org", "uchi.example.org"]:
              out = q(f"+noall +comments {name} A")
              assert "status: NOERROR" in out and "ANSWER: 0" in out, out

      with subtest("a second value over TCP coexists; one RR is deleted alone; the RRset delete empties the name"):
          out = nsupdate(f"update add {challenge} 60 TXT tok2", opts="-v")
          assert "failed" not in out, out
          out = q(f"+short {challenge} TXT")
          assert '"tok1"' in out and '"tok2"' in out, out
          out = nsupdate(f"update delete {challenge} TXT tok1")
          assert "failed" not in out, out
          out = q(f"+short {challenge} TXT")
          assert '"tok1"' not in out and '"tok2"' in out, out
          out = nsupdate(f"update delete {challenge} TXT")
          assert "failed" not in out, out
          for name, rtype in [(challenge, "TXT"), ("git.uchi.example.org", "A")]:
              out = q(f"+noall +comments {name} {rtype}")
              assert "status: NXDOMAIN" in out, out

      with subtest("a signed query gets a signed answer that dig validates"):
          out = client.succeed(f"dig @{v4} +time=3 +tries=1 -y {key} www.example.org A")
          assert "TSIG PSEUDOSECTION" in out and "could not be validated" not in out, out

      with subtest("REFUSED: another owner, another type, no key; NOTAUTH: wrong secret, unknown key, clock skew"):
          for script in [
              "update add foo.example.org 60 TXT x",
              f"update add {challenge} 60 A 192.0.2.1",
              "update delete git.uchi.example.org TXT",
          ]:
              out = nsupdate(script)
              assert "REFUSED" in out, out
          out = nsupdate(f"update add {challenge} 60 TXT x", key="")
          assert "REFUSED" in out, out
          out = nsupdate(f"update add {challenge} 60 TXT x", key="hmac-sha256:hanko:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
          assert "NOTAUTH" in out, out
          out = nsupdate(f"update add {challenge} 60 TXT x", key="hmac-sha256:other:${secret}")
          assert "NOTAUTH" in out, out
          client.succeed("date -s @$(( $(date +%s) + 3600 ))")
          out = nsupdate(f"update add {challenge} 60 TXT x")
          client.succeed("date -s @$(( $(date +%s) - 3600 ))")
          assert "NOTAUTH" in out, out
          out = q(f"+noall +comments {challenge} TXT")
          assert "status: NXDOMAIN" in out, out
          journal = soto.succeed("journalctl -u annai.service --no-pager")
          for needle in ["reason=policy", "reason=unsigned", "code=badsig", "code=badkey", "code=badtime"]:
              assert needle in journal, journal

      with subtest("a dynamic record expires after the configured lifetime"):
          out = nsupdate(f"update add {challenge} 60 TXT gone")
          assert "failed" not in out, out
          out = q(f"+short {challenge} TXT")
          assert '"gone"' in out, out
          client.sleep(20)
          out = q(f"+noall +comments {challenge} TXT")
          assert "status: NXDOMAIN" in out, out
    '';
}
