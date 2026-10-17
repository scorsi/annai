# ADR-0001: Language and runtime model

- Status: accepted
- Date: 2026-10-14

## Context

annai (案内) is a from-scratch DNS server for the author's homelab. It owns everything DNS in the homelab: zones, resolution, and the resolver configuration of the hosts. It must integrate with kekkai (Rust/Go), genkan (Go) and hanko (Go). The author wants to write it in Zig. Performance is not a driver: the homelab produces a handful of queries per second; any language would do.

## Decision

- **Zig**, pinned to a tagged release in the flake (track the release branch of every dependency, never Zig master).
- **No shared code** with kekkai, genkan or hanko. All integration goes through wire protocols (DNS, RFC 2136). See ADR-0010.
- **Single-threaded event loop** over non-blocking sockets: kqueue on macOS, epoll on Linux, behind a small internal poller abstraction. No dependency on Zig async / `std.Io` until it is stable.
- **Memory**: one arena per request; long-lived data (zones, cache) in dedicated allocators. `std.heap.GeneralPurposeAllocator` in debug builds to catch leaks.
- **Build & packaging**: `zig build`; Nix packaging through zig2nix with dependency hashes fixed in the flake. The binary is static on Linux (musl target) so the public entry points carry no runtime dependencies.

## Alternatives considered

- **Rust**: would share crypto with kekkai if DNSSEC/DoT ever land, mature DNS crates (hickory). Rejected: the point is to learn Zig.
- **Go**: would share the HTTP/TLS stack with genkan and miekg/dns. Rejected for the same reason.

## Consequences

- The DNS wire codec, TOML loading, and later TSIG/TLS are written against Zig's std only, plus a TOML dependency (ADR-0003).
- Zig has no 1.0; each Zig upgrade is a planned task, not an accident. Dependencies are kept to a minimum.
- A single-threaded loop is a conscious cap: tens of thousands of QPS are out of scope. Multi-threading (SO_REUSEPORT per core) is a possible later refactor, not a v0 concern.
