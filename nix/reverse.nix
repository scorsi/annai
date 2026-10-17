# Reverse zones of ADR 0005, generated from the forward zone's node data: one zone per prefix of
# `reverse.prefixes`, holding `PTR <node>.kekkai.<zone>` for every A or AAAA of such a node name
# inside that prefix. SOA, NS, TTL and serial are the forward zone's. Prefixes end on an octet
# (IPv4) or nibble (IPv6) boundary.
{
  lib,
  zones,
  reverse,
}:
let
  forward = zones.${reverse.zone};
  abs =
    name:
    if name == "@" then
      reverse.zone
    else if lib.hasSuffix "." name then
      name
    else
      "${name}.${reverse.zone}";

  isNode =
    owner:
    builtins.match "[^.]+\\.kekkai\\..*" owner != null && lib.hasSuffix ".kekkai.${reverse.zone}" owner;
  nodes = lib.filterAttrs (owner: _: isNode (abs owner)) forward.names;
  isV6 = lib.hasInfix ":";
  # Most significant label first: four decimal octets, or 32 hex nibbles.
  labels =
    addr:
    if isV6 addr then
      lib.stringToCharacters (
        lib.concatMapStrings (lib.fixedWidthString 4 "0") (
          lib.splitString ":" (lib.network.ipv6.fromString addr).address
        )
      )
    else
      lib.splitString "." addr;
  arpa = parts: suffix: lib.concatStringsSep "." (lib.reverseList parts) + suffix;

  zoneFor =
    prefix:
    let
      split = lib.splitString "/" prefix;
      addr = lib.head split;
      v6 = isV6 addr;
      bits = if v6 then 4 else 8;
      length = lib.toInt (lib.elemAt split 1);
      n = length / bits;
      head = lib.take n (labels addr);
      suffix = if v6 then ".ip6.arpa." else ".in-addr.arpa.";
      ptrs = lib.concatLists (
        lib.mapAttrsToList (
          owner: rrsets:
          lib.concatMap (
            a:
            let
              parts = labels a;
            in
            lib.optional (lib.take n parts == head) {
              ${arpa (lib.drop n parts) ""}.ptr = [ (abs owner) ];
            }
          ) (rrsets.${if v6 then "aaaa" else "a"} or [ ])
        ) nodes
      );
    in
    assert lib.assertMsg
      (
        lib.length split == 2
        && length > 0
        && lib.mod length bits == 0
        && length < bits * lib.length (labels addr)
      )
      "services.annai.reverse.prefixes: \"${prefix}\" must be a prefix ending on an ${
        if v6 then "nibble" else "octet"
      } boundary";
    {
      name = arpa head suffix;
      value = {
        inherit (forward) ttl serial;
        soa = forward.soa // {
          mname = abs forward.soa.mname;
          rname = abs forward.soa.rname;
        };
        names = lib.zipAttrsWith (_: values: { ptr = lib.concatMap (v: v.ptr) values; }) ptrs // {
          "@".ns = map abs forward.names."@".ns;
        };
      };
    };
in
lib.listToAttrs (map zoneFor reverse.prefixes)
