# ADR-0002: Roles and modes

- Status: accepted
- Date: 2026-10-14

## Context

Two independent DNS roles exist: *authoritative* (answers for zones it owns) and *resolver* (answers anything for its clients). annai serves both the public NS for example.org / example.net (ADR-0009) and the resolver for every kekkai node. A public instance must never be an open resolver (amplification/reflection abuse).

## Decision

One binary, two **modes**, selected by `mode` in the config:

- **`uchi`** (内, inside): authoritative for the loaded zones, **forwarding resolver with cache** for everything else (ADR-0008). Runs inside the mesh; how many instances and where is a deployment choice. Clients point *all* their queries at it.
- **`soto`** (外, outside): **authoritative only**. Queries outside the loaded zones get `REFUSED`, the `RD` bit is ignored, `RA` is always 0. Accepts RFC 2136 updates (ADR-0006). Runs on the public entry points.

Configuration that does not match the mode is a startup error (`[forwarding]` in `soto` mode, `[update]` in `uchi` mode).

Full recursion from the root servers is **not planned**. If it is ever built, it is a third mode (`saki`, 先?), v3 at the earliest, as a learning project.

## Alternatives considered

- **Authoritative only everywhere**, with kekkai-node doing split-DNS on each OS (the MagicDNS approach). Rejected: more client-side OS plumbing (macOS resolver files, iOS tunnel DNS settings, systemd-resolved), and no central point for caching or later blocklists.
- **Full recursive resolver** (Unbound-like). Rejected for now: iteration, QNAME minimisation, DNSSEC validation, and years of edge cases — a project in itself.
- **Two binaries**. Rejected: 90% shared code, and one NixOS module is simpler.

## Consequences

- The security posture is per instance and decided by one config field: a `soto` instance cannot be misconfigured into a recursor.
- Forwarding exists only inside the mesh, where kekkai already encrypts transport; upstream DoT is a later privacy improvement (ADR-0008), not a correctness need.
