# M5 nixosTest (ADR 0011): readiness and reload of the systemd unit. A `soto` VM with the apex
# zone of nix/example-soto.nix and hanko's key: the unit is `Type=notify-reload` and answers as
# soon as it is active; a deploy that changes a zone (switch-to-configuration to a specialisation)
# reloads it in the same process; a rotated key file is picked up by `systemctl reload`; a broken
# zone file is refused and the previous answers stay. dig and nsupdate are the oracles.
{
  self,
  pkgs,
  validate,
}:
let
  secret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldC0xMjM0";
  # A rotated secret, written by the test script over the root-only key file.
  rotated = "cm90YXRlZC1yb3RhdGVkLXJvdGF0ZWQtcm90YXRlZC0xMjM0NTY3";
in
pkgs.testers.runNixOSTest {
  name = "annai-reload";

  nodes.soto = {
    imports = [
      self.nixosModules.default
      ./example-soto.nix
    ];
    # A copied root-only file (mode set), as a sops secret is: the script can overwrite it.
    environment.etc."annai/hanko.key" = {
      text = "hanko:${secret}\n";
      mode = "0400";
    };
    services.annai.metrics.listen = "127.0.0.1:9153";
    environment.systemPackages = [
      pkgs.curl
      pkgs.dnsutils
    ];
    # The same system plus one name: only the zone changes, so only X-Reload-Triggers does.
    specialisation.zone-changed.configuration = {
      services.annai.zones."example.org.".names.reloaded.a = [ "192.0.2.99" ];
    };
  };

  testScript =
    { nodes, ... }:
    ''
      def q(args):
          return soto.succeed(f"dig @127.0.0.1 +time=3 +tries=1 +short {args}").strip()

      def main_pid():
          return soto.succeed("systemctl show -p MainPID --value annai.service").strip()

      def journal():
          return soto.succeed("journalctl -u annai.service -o cat")

      def nsupdate(secret):
          script = "server 127.0.0.1\\nzone example.org\\ncheck-names off\\nupdate add _acme-challenge.www.example.org 60 TXT ok\\nsend\\n"
          _, out = soto.execute(f"printf '{script}' | nsupdate -y hmac-sha256:hanko:{secret} 2>&1")
          return out

      soto.wait_for_unit("annai.service")

      with subtest("Type=notify-reload: active only once the listeners are bound and the zones loaded"):
          t = soto.succeed("systemctl show -p Type --value annai.service").strip()
          assert t == "notify-reload", t
          # `systemctl restart` returns when the unit is active, i.e. after READY=1: the very next
          # query is answered, with no wait for the port.
          soto.succeed("systemctl restart annai.service")
          out = q("www.example.org A")
          assert "192.0.2.80" in out, out
          pid = main_pid()
          out = q("reloaded.example.org A")
          assert out == "", out

      with subtest("a deploy that changes a zone reloads it in the same process"):
          soto.succeed("${nodes.soto.system.build.toplevel}/specialisation/zone-changed/bin/switch-to-configuration test")
          out = q("reloaded.example.org A")
          assert "192.0.2.99" in out, out
          assert main_pid() == pid, "the switch restarted annai"
          assert '"event":"reload"' in journal(), journal()

      with subtest("systemctl reload picks up a rotated key file"):
          out = nsupdate("${secret}")
          assert "update failed" not in out, out
          soto.succeed("printf 'hanko:${rotated}\\n' > /etc/annai/hanko.key")
          soto.succeed("systemctl reload annai.service")
          out = nsupdate("${rotated}")
          assert "update failed" not in out, out
          out = nsupdate("${secret}")
          assert "BADSIG" in out, out
          assert main_pid() == pid, "the reload restarted annai"

      with subtest("a broken zone file is refused: the previous answers stay"):
          # annai.toml pointing at a copy of the zone with a TOML error; `annai check` would never
          # let a deploy build this, so it is written by hand.
          soto.succeed(
              "z=$(grep -o '/nix/store/[^\"]*example.org.toml' /etc/annai/annai.toml)"
              " && { cat $z; echo 'broken = ['; } > /etc/annai/broken.toml"
              " && sed \"s|$z|/etc/annai/broken.toml|\" $(readlink -f /etc/annai/annai.toml) > /etc/annai/annai.toml.new"
              " && mv /etc/annai/annai.toml.new /etc/annai/annai.toml"
          )
          soto.succeed("systemctl reload annai.service")
          out = journal()
          assert '"event":"reload-failed"' in out and "/etc/annai/broken.toml" in out, out
          out = q("reloaded.example.org A")
          assert "192.0.2.99" in out, out
          assert soto.succeed("systemctl is-active annai.service").strip() == "active"
          assert main_pid() == pid, "the failed reload restarted annai"

      with subtest("logs (nisshi's schema) and metrics (masu's convention) of ADR 0011"):
          soto.succeed("journalctl _SYSTEMD_UNIT=annai.service -o cat | ${validate.logs} validate --logs")
          soto.succeed("${validate.metrics} validate --metrics http://127.0.0.1:9153/metrics")
          out = soto.succeed("curl -s http://127.0.0.1:9153/metrics")
          assert 'annai_reloads_total{result="ok"} 2' in out, out
          assert 'annai_reloads_total{result="failed"} 1' in out, out
    '';
}
