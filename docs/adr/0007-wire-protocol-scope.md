# ADR-0007: Wire protocol scope

- Status: accepted
- Date: 2026-10-14

## Context

"Only what is necessary first, then add." A DNS server that modern resolvers can talk to has an incompressible minimum; this ADR fixes it and names what is deliberately out.

## Decision

### v0 (incompressible)

- RFC 1035 message codec: header, question, RRs, **name compression** on both parse and emit (pointers, loop/bounds checks).
- **UDP/53 and TCP/53** (RFC 7766): TCP is mandatory for truncated answers and for UPDATE; connection timeouts and a per-connection message cap.
- **EDNS0** (RFC 6891): parse OPT, echo an OPT, honour the advertised UDP payload size (cap at 1232 per DNS Flag Day 2020), set `TC` and truncate at 512 bytes when the client sent no OPT. Unknown EDNS options are ignored.
- Case-insensitive name matching; the question section is echoed with the client's case (0x20 compatibility).
- Record types: `A`, `AAAA`, `CNAME`, `TXT`, `SOA`, `NS`, `PTR`, `SRV`, `MX`, `OPT`. Unknown types stored opaquely (RFC 3597) so a zone can carry anything.
- Authoritative semantics: `AA` bit, `NXDOMAIN` with SOA in the authority section (RFC 2308), `NODATA`, **empty non-terminals** (ADR-0004), in-zone CNAME chasing (add target RRs to the answer), `REFUSED` for names outside loaded zones (soto) or forwarding (uchi).
- `ANY` answered with a synthetic `HINFO` (RFC 8482). Unknown opcodes → `NOTIMP`.
- IPv4 and IPv6 listeners from day one.

### v1

- `CAA` records (pairs well with ACME), `TSIG` (ADR-0006), **wildcards** (RFC 4592), `DS`-less `NS` glue handling for `ns1`/`ns2`.

### v2 / later

- Upstream **DoT** (ADR-0008); response rate limiting (ADR-0011).
- **DNSSEC** signing: not planned before v2, possibly never. The RRset abstraction must not preclude it (RRsets as the unit, not individual RRs).

### Not planned

- AXFR/IXFR/NOTIFY (`REFUSED`, see ADR-0009), DoT/DoH as a *server*, DNS cookies, EDNS client subnet, recursion from the roots.

## Alternatives considered

- Skipping TCP or EDNS0 in v0: tempting, but every modern resolver sends OPT and large TXT answers (ACME, SPF) need TCP fallback. Both would be rewritten within weeks.

## Consequences

- The codec is the most-tested module: round-trip unit tests, a malformed-packet corpus, fuzzing before soto exposure (ADR-0011).
- Responses larger than the UDP limit are a real path (TXT, many AAAA), so TCP must be tested in the nixosTest, not assumed.
