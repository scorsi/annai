# ADR-0011: Testing and operations

- Status: accepted, amended 2026-10-20 (logs and metrics, below), amended 2026-10-22 (CI builds each check separately, below)
- Date: 2026-10-14

## Context

annai will face the Internet in `soto` mode. Nothing important runs on the homelab during v0, so operational comfort (hot reload, metrics) can wait; correctness and safety cannot.

## Decision

### Testing (from v0)

- **Unit tests** (`zig build test`): codec round-trips, name compression edge cases (pointer loops, out-of-bounds, 255-byte names), TOML schema validation, cache TTL arithmetic, TSIG MAC vectors (v1).
- **Malformed-packet corpus** replayed in unit tests; **fuzzing** of the parser (zig's fuzzer or a minimal harness) is a hard prerequisite to public exposure (M4).
- **nixosTest** as the integration harness, using standard tools as the oracle, never annai testing itself: `dig` (A/AAAA/CNAME/TXT/SRV, `+tcp`, `+norecurse`, EDNS payload sizes, NXDOMAIN/NODATA/empty non-terminal), `nsupdate` with TSIG for UPDATE (v1). Topology: one `soto` VM, one `uchi` VM forwarding to the `soto` VM as its "upstream", one client VM.
- **A breakage seen on the real hosts becomes a nixosTest case before it is fixed.** That is how real-network incidents pay for themselves.
- CI on the Forgejo runner: one `nix build -L` per check (amended 2026-10-22) runs unit tests, `annai check` on the example configs, and the nixosTest, because `nix flake check` evaluates every nixosTest in one process (6-9 GB) and is OOM-killed at the runner's cap. `nix flake check` stays the dev command.

### Operations

- **v0**: configuration changes restart the service (`systemd.services.annai.restartTriggers`); structured key=value logs to stderr → journald; `annai check` at build time; `annai` refuses to start on an invalid config.
- **v1**: `SIGHUP` reloads zones and keys atomically (parse new set, swap pointer, free old); metrics (queries by type/rcode, cache size/hit ratio, upstream latency, dynamic record count, UPDATE refusals) exposed as a Prometheus text endpoint on a loopback/mesh listener; `systemd` `Type=notify` readiness.
- **v2**: response rate limiting on `soto` (per-source token bucket, slip ratio), query logging sampling, upstream DoT health.

## Alternatives considered

- Testing against a real resolver only (manual `dig` from a laptop): kept as a sanity step, not as the test suite.

## Consequences

- The nixosTest is the definition of done for every milestone.
- `annai check` doubles as the schema documentation: whatever it accepts is the format.

## Amendment (2026-10-20): log and metric outputs

The stack's observability products fix the formats annai writes: nisshi's log schema v1 (nisshi
ADR 0004, `docs/log-schema.md`; how services write it: nisshi ADR 0009) and masu's metric
convention (masu ADR 0005, `docs/metric-convention.md`). This amendment replaces the "structured
key=value logs" of v0 and the metrics bullet of v1; the rest of the decision stands.

### Logs

- One JSON object per line on stderr (journald keeps it), schema v1: `v` = 1, `ts` = UTC wall
  clock with exactly nine fractional digits, `level`, `event`, then the event's own fields; `err`
  only on `warn` and `error` lines. annai never writes a field the agent or the store reserves
  (`node`, `service`, `stream`, `seq`, `source`, `recv_ts`, `_*`).
- One `query` line per answered query, REFUSED and FORMERR included: `proto` (`udp`/`tcp`),
  `client` (source address, no port), `qname` (lowercase, trailing dot; absent when the question
  cannot be read), `qtype` (mnemonic, else `TYPE<n>`), `rcode` (`BADVERS` included), `aa`,
  `cache` (`hit`, `miss`, `none` when no forwarding was involved), `size` (response bytes),
  `dur_us` (from reading the query to its answer, upstream wait included). A forwarded query is
  logged when its answer is sent. A packet that gets no answer (shorter than a header, a
  response, a waiter over the coalescing cap) gets no line.
- The other events keep their names (`listen`, `upstream-timeout`, `upstream-error`,
  `forward-refused`, `forward-failed`, `tcp-refused`, `accept`, `tsig`, `update`,
  `update-refused`, `update-failed`, `poller`, and the socket call names `socket`, `bind`,
  `listen`, `connect`, `send` at `error`); `errno=` becomes `err`. New: `metrics-listen`.
- Every string that can come from a client is written with `std.json.Stringify`; names off the
  wire are printed as `zone.fmt` does (non-printable bytes as `?`) then escaped. A line over
  2 KiB is dropped (names are at most 255 bytes, so only a bug can reach it).
- `annai check` and a refused start write schema v1 `error` lines too (owner decision
  2026-10-20: a refused start reaches the journal): `config-invalid`, `read-failed`,
  `key-invalid` or `start-failed`, with `err` = `<path>: <message>` (the error name for
  `start-failed`); only the usage line for a wrong command line, which the unit's fixed
  `annai serve <path>` never prints, stays plain text.
- The NixOS module sets `LogRateLimitIntervalSec=30s` and `LogRateLimitBurst=30000` as
  `mkDefault` (nisshi ADR 0009): 1000 lines/s sustained; hikyaku counts what journald drops.
  Sampling above that stays v2.

### Metrics

- `services.annai.metrics.listen` (`127.0.0.1:<port>` or `[::1]:<port>`, default `null` = no
  listener), rendered as `metrics` in annai.toml. Loopback only, refused by both the module's
  assertion and `annai check`: the local agent is the only scraper. This replaces the
  "loopback/mesh listener" above and M5's "mesh listener".
- `GET /metrics` returns Prometheus text format 0.0.4, written by hand (no dependency, ADR 0001);
  any other request gets 404. The listener is one more descriptor on the single poller of
  ADR 0001: a scrape is accepted, read and answered inline, then closed, so a scraper that
  stalls blocks the loop for at most one second (the same bound as `sendAll`); acceptable for a
  loopback-only client, revisited if scrapes ever show in `annai_query_duration_seconds`.
- Families: `annai_build_info{version,mode}`, `annai_queries_total{proto,qtype,rcode}`
  (`qtype` = the types annai knows, else `other`; `rcode` = the named rcodes, `BADVERS`, else
  `other`), `annai_query_duration_seconds{proto}` (buckets fixed in the code, 0.1 ms to 10 s),
  `annai_cache_entries`, `annai_cache_lookups_total{result=hit|miss}`,
  `annai_upstream_queries_total{upstream,result=ok|timeout|error|rcode}` (`upstream` = the
  configured address; `rcode` = it answered SERVFAIL, REFUSED, NOTIMP or FORMERR),
  `annai_updates_total{key,result=ok|refused|notauth|error}` (`key` = a configured key name, or
  `none` when unsigned or when TSIG verification failed, since the key name is then not
  trusted), `annai_dynamic_records`. No client, name or error text in any label; at most
  2 × 15 × 13 query series, 30 histogram series and 4 per upstream and per key, under masu's
  500-series budget for any realistic configuration.
- Counters live in the `Server` and only go up from process start (SIGHUP reload, M5, must
  keep them).

### Tests

- Unit tests: the `ts` format (padding, leap day), the JSON line (field order, escaping of a
  hostile qname, optional fields left out), the question reader, the exposition (closed label
  sets, cumulative buckets, escaped label values, one HELP/TYPE per family), the `metrics`
  key of annai.toml.
- Every nixosTest (`authoritative`, `forwarding`, `update`) enables `metrics.listen`, asserts
  the `query` lines (and update events) its queries produced, pipes
  `journalctl _SYSTEMD_UNIT=annai.service -o cat` into `nisshi validate --logs`, runs
  `masu validate --metrics` on the endpoint, and checks that a counter moved. nisshi and masu
  are test-only flake inputs: the package and the module never depend on them.
- Flake checks: `module-metrics` renders a listener, `module-metrics-public` must fail
  `annai check`, `module-metrics-assertion` evaluates the module's assertion.

