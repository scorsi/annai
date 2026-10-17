# ADR-0004: Split horizon by zone loading, no internal delegation

- Status: accepted
- Date: 2026-10-14

## Context

Internal names (`*.uchi.example.org`, including kekkai nodes) must resolve only inside the mesh, yet Let's Encrypt must be able to validate `_acme-challenge.<name>.uchi.example.org` from the public Internet (DNS-01, ADR-0006). The naive design, delegating `uchi.example.org` with NS records to the internal annai, breaks DNS-01: Let's Encrypt follows the delegation to nameservers it cannot reach.

## Decision

The horizon is defined by **which zones an instance loads**, not by delegation.

- **`uchi` instances** load `uchi.example.org` (and the reverse zones for kekkai's address ranges) as local authoritative zones and forward everything else upstream. Public names therefore resolve normally through forwarding.
- **`soto` instances** load the apex zones `example.org` and `example.net`, containing public records only (`soto.*`, product CNAMEs, MX, CAA, NS, glue). They hold **no A/AAAA for `uchi` names**. They accept dynamic `_acme-challenge.*` TXT records for any name under the apex, including names under `uchi`, which are otherwise absent from the public view.
- **No NS records for `uchi` or `soto` inside the apex zones.** They are plain labels. The only delegation that exists is at the registrar: `example.org` / `example.net` → `ns1`/`ns2.example.org` (ADR-0009).

Resulting behaviour:

| Query | From inside the mesh (uchi) | From the Internet (soto) |
|---|---|---|
| `git.uchi.example.org A` | local zone answer | `NOERROR` / no data if an ACME TXT exists below it, else `NXDOMAIN` |
| `_acme-challenge.git.uchi.example.org TXT` | `NXDOMAIN`: the name is inside the local zone, nothing is forwarded. hanko therefore checks propagation against each public NS by address, never through a resolver (ADR-0010) | dynamic TXT |
| `cv.example.org A` | forwarded → soto answer | CNAME → `cv.soto.example.org` → A/AAAA |

## Alternatives considered

- **Delegate `uchi` to internal NS**: breaks DNS-01, see above.
- **Delegate `uchi` to the soto instances as well, serving internal A/AAAA publicly**: leaks the mesh addressing. Rejected on privacy grounds, even though overlay addresses are not directly routable.
- **acme-dns pattern** (`_acme-challenge.x` CNAME → `x.acme.example.org`, a separate zone on one NS): confines dynamics to one zone but adds a second zone, a CNAME per service, and still needs the CNAMEs in the public apex. Unnecessary once the apex itself accepts scoped updates.

## Consequences

- The public zone reveals that `git.uchi.example.org` *exists* (via the ACME TXT and the empty non-terminal). Certificate Transparency logs reveal the same name anyway. Accepted.
- Empty non-terminals must be handled correctly by the authoritative engine (ADR-0007): `git.uchi.example.org` exists if any name below it exists.
- The same Nix data produces both views; the NixOS module decides per record whether it belongs to the internal zone, the public apex, or both.
