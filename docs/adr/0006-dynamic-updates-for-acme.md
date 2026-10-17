# ADR-0006: Dynamic updates for ACME DNS-01

- Status: accepted
- Date: 2026-10-14

## Context

Internal services (`*.uchi.example.org`) are unreachable from the Internet, and the primary domain's TLD forces HTTPS (ADR-0005), so their certificates can only be obtained through **DNS-01**. Let's Encrypt queries the *public* nameservers of `example.org` for `_acme-challenge.<name>` TXT records, picking any NS. This is the single exception to "fully declarative" (ADR-0003), and it must stay narrow.

## Decision

- **Protocol: RFC 2136 DNS UPDATE, authenticated with TSIG (HMAC-SHA256, RFC 8945).** Keys are distributed through sops; one key per client. The only client is **hanko**, the certificate service; genkan never sends an UPDATE. Accepted over TCP and UDP, on every listener including the public addresses: hanko's host has no overlay address before kekkai exists. Restricting UPDATE to an overlay-facing listener is a later hardening, once every hanko host is a kekkai node.
- **Only in `soto` mode.** `uchi` instances answer `REFUSED` to any UPDATE.
- **Authorisation policy**, enforced before any change:
  - owner name must start with the `_acme-challenge.` label and lie within a loaded zone;
  - RR type must be `TXT`;
  - operations allowed: add RR, delete RRset/RR. Prerequisites are evaluated per RFC 2136 but cannot touch anything outside the policy.
  Anything else → `REFUSED`, logged with the key name.
- **In-memory only**, bounded: TTL capped (default 120 s on the record, lifetime capped at 1 h regardless of client TTL), hard cap on the number of dynamic records, gone on restart. ACME flows take seconds and hanko retries; persistence buys nothing.
- **No replication between nameservers.** Let's Encrypt may ask ns1 or ns2: the client (hanko) sends the UPDATE to **every** soto instance. annai does not implement NOTIFY, IXFR, or any primary/secondary logic.
- Dynamic records are a separate overlay consulted after the static zone; they never modify the static RRsets and do not bump the SOA serial.

## Alternatives considered

- **Custom HTTP API**: would require inventing a protocol and a client in hanko. RFC 2136 is standard; how hanko implements it is hanko's decision.
- **The registrar's API** for DNS-01 as an interim before M4: rejected, throwaway code. No certificate exists before annai is the public NS, and the NS switch is reversible at the registrar (ADR-0009).
- **ACME inside genkan** (TLS-ALPN-01 or DNS-01) or NixOS `security.acme`: rejected, issuance is a product of its own (hanko) so that the proxy only reads files and the DNS-01 client can fan out to every NS and check each one directly.
- **Replication inside annai** (NOTIFY + IXFR or a custom gossip): more protocol surface for a problem the client solves with a loop.
- **A private CA** instead of ACME, trusted on all devices: avoids DNS-01 entirely. Rejected: iOS profile management and no public trust for `soto` names; Let's Encrypt is the simpler operational path. A private CA for service-to-service mTLS is a possible later issuer inside hanko and does not concern annai.

## Consequences

- TSIG requires HMAC-SHA256 and careful request/response MAC handling — a well-specified, test-friendly piece of Zig.
- hanko's DNS-01 contract (ADR-0010): list of nameservers, key name + secret, fan-out, wait for propagation by querying each NS directly before asking the CA.
- If a nameserver is down during issuance, the CA may hit it: hanko should treat a failed UPDATE on any NS as a retry condition, not ignore it.
