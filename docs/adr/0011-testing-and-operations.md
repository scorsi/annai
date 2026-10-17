# ADR-0011: Testing and operations

- Status: accepted
- Date: 2026-10-14

## Context

annai will face the Internet in `soto` mode. Nothing important runs on the homelab during v0, so operational comfort (hot reload, metrics) can wait; correctness and safety cannot.

## Decision

### Testing (from v0)

- **Unit tests** (`zig build test`): codec round-trips, name compression edge cases (pointer loops, out-of-bounds, 255-byte names), TOML schema validation, cache TTL arithmetic, TSIG MAC vectors (v1).
- **Malformed-packet corpus** replayed in unit tests; **fuzzing** of the parser (zig's fuzzer or a minimal harness) is a hard prerequisite to public exposure (M4).
- **nixosTest** as the integration harness, using standard tools as the oracle, never annai testing itself: `dig` (A/AAAA/CNAME/TXT/SRV, `+tcp`, `+norecurse`, EDNS payload sizes, NXDOMAIN/NODATA/empty non-terminal), `nsupdate` with TSIG for UPDATE (v1). Topology: one `soto` VM, one `uchi` VM forwarding to the `soto` VM as its "upstream", one client VM.
- **A breakage seen on the real hosts becomes a nixosTest case before it is fixed.** That is how real-network incidents pay for themselves.
- CI on the Forgejo runner: `nix flake check` runs unit tests, `annai check` on the example configs, and the nixosTest.

### Operations

- **v0**: configuration changes restart the service (`systemd.services.annai.restartTriggers`); structured key=value logs to stderr → journald; `annai check` at build time; `annai` refuses to start on an invalid config.
- **v1**: `SIGHUP` reloads zones and keys atomically (parse new set, swap pointer, free old); metrics (queries by type/rcode, cache size/hit ratio, upstream latency, dynamic record count, UPDATE refusals) exposed as a Prometheus text endpoint on a loopback/mesh listener; `systemd` `Type=notify` readiness.
- **v2**: response rate limiting on `soto` (per-source token bucket, slip ratio), query logging sampling, upstream DoT health.

## Alternatives considered

- Testing against a real resolver only (manual `dig` from a laptop): kept as a sanity step, not as the test suite.

## Consequences

- The nixosTest is the definition of done for every milestone.
- `annai check` doubles as the schema documentation: whatever it accepts is the format.
