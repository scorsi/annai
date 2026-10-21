# ADR-0012: Cache TTL bounds

- Status: Accepted — 2026-10-21
- Date: 2026-10-21
- Amends: [ADR-0008](0008-upstream-forwarding-and-cache.md)'s minimum-TTL clamp

## Context

Review A5 and the batch 3 brief require that caching never extend any upstream record's TTL.
ADR-0008 permitted a configurable minimum-TTL clamp, which conflicts with that requirement.

## Decision

- Keep whole-packet cache entries, age each ordinary RR's own TTL from insertion, and expire
  the entry before any retained RR expires, including authority and additional records.
- Bound NXDOMAIN and NODATA after CNAMEs by the authority SOA's TTL and MINIMUM (RFC 2308).
  Serve the authority SOA with that bound. Without an SOA, do not cache a negative answer.
- `max_ttl` still caps entry lifetime. Remove `min_ttl` and the NixOS option
  `services.annai.forwarding.minTtl` entirely: no upstream TTL is raised. Config loading and
  `annai check` reject `min_ttl` with a diagnostic pointing here; the NixOS module reports
  `forwarding.minTtl` as a removed option.

## Alternatives considered

- Retain the positive minimum clamp: violates the explicit batch 3 invariant.
- Retain the minimum-TTL option as a no-op: rejected by the owner; obsolete settings must fail clearly.
- Cache RRsets separately or discard expired sections: more state and reconstruction logic.

## Consequences

Short-lived additional records may cause earlier cache misses. Existing configurations must
remove `min_ttl` / `services.annai.forwarding.minTtl`, including explicit zero values, before
they can load or evaluate successfully. No prefetch or serve-stale is introduced.
