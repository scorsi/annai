# ADR-0008: Upstream forwarding and cache (uchi mode)

- Status: accepted; amended by [ADR-0012](0012-cache-ttl-bounds.md)
- Date: 2026-10-14
- Amendment — 2026-10-21: [ADR-0012](0012-cache-ttl-bounds.md) removes the minimum-TTL clamp
  and its configuration option. Cache lifetime cannot exceed any retained record's TTL.

## Context

In `uchi` mode (ADR-0002) annai answers every query from mesh clients. Names outside the local zones must be forwarded to a public resolver.

## Decision

- **Upstreams** are a configured list (`[forwarding] upstreams = ["9.9.9.9", "2620:fe::fe"]`), tried in order with failover on timeout, round-robin optional. v0 transport: plain UDP with TCP fallback on `TC`.
- **Anti-spoofing** (RFC 5452) is mandatory in v0: random query IDs, random source ports, strict matching of ID + question + upstream address on responses.
- **Cache**: positive entries keyed by (name, type, class), expiry = min(TTL, max-ttl); the original configurable minimum-TTL clamp was removed by [ADR-0012](0012-cache-ttl-bounds.md). **Negative caching** per RFC 2308 (NXDOMAIN and NODATA, bounded by the SOA TTL and MINIMUM); bounded size with LRU eviction; no prefetch, no serve-stale in v0. Cache is consulted only for non-local names: local zones always answer from the loaded data.
- **In-flight coalescing**: identical concurrent questions share one upstream query.
- Forwarded answers are returned with `RA=1`, `AA=0`, TTLs decremented.
- **v2**: upstream DoT (TLS 1.3 client, `std.crypto.tls` or a dependency), which is the actual privacy gain versus the ISP; optional local blocklist zones (served as NXDOMAIN) as a cheap ad-blocking feature.

## Alternatives considered

- **No cache, pure forwarder**: simplest, but every client query becomes an upstream round-trip and the mesh resolver would be slower than the OS cache it replaces.
- **Forwarding to the ISP resolver** by default: declined; the default is a validating public resolver (Quad9), overridable in Nix.

## Consequences

- The cache is the only unbounded-growth risk in the process; its cap is a hard config value and a metric (ADR-0011).
- DNSSEC validation is not done by annai; relying on a validating upstream over plain UDP is a known weakness until DoT (v2).
