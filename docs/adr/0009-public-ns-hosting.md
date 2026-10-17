# ADR-0009: Public nameserver hosting

- Status: accepted
- Date: 2026-10-14

## Context

v1 makes annai the authoritative NS for `example.org` and `example.net` on the Internet, replacing the registrar's DNS. Registrars require at least two NS entries.

## Decision

- **`ns1.example.org` and `ns2.example.org`** on two public hosts named by the deployment, with **glue records** (A + AAAA) registered at the registrar. `example.net` uses the same two nameservers (out-of-bailiwick NS, no glue needed).
- **Both instances load identical generated zone files** deployed by the deployment repository. There is no primary/secondary, no AXFR/IXFR/NOTIFY: a Nix deploy *is* the zone transfer. Consistency between NS is a deployment property (deploy both in the same `nixos-rebuild` run).
- `soto` instances listen on the public IPv4 and IPv6 addresses, authoritative only (ADR-0002), rate limiting in v2 (ADR-0011), UPDATE restricted by TSIG (ADR-0006).
- **Constraint on the deployment**: never publish a DS record at the registry, annai does not sign (ADR-0007). The registrar-side migration (TTLs, NS and glue switch, observation, rollback to the previous DNS host) is a deployment checklist, not an annai decision.

## Alternatives considered

- **Primary/secondary with AXFR**: standard, but adds protocol surface to replicate what Nix already does.
- **Keeping the registrar as NS** and only running internal DNS: works, but then DNS-01 must go through the registrar's API and the sovereignty goal is not met.
- **A third NS elsewhere** (secondary DNS provider): more resilience, but a third party again. Possible later as a *declaratively fed* secondary if an outage ever hurts.

## Consequences

- Public exposure raises the bar on robustness: fuzzing of the codec and a malformed-packet corpus are prerequisites to M4, not nice-to-haves.
- Every zone change is a commit + deploy; there is no hot path for editing records, by design.
