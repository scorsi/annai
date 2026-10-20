//! The counters of ADR 0011 and their Prometheus text exposition (format 0.0.4, masu's metric
//! convention), written by hand. Every label value comes from a closed set: the types and
//! rcodes annai knows (else `other`), the configured upstreams and TSIG keys.

const std = @import("std");
const wire = @import("wire.zig");
const zone = @import("zone.zig");
const tsig = @import("tsig.zig");
const log = @import("log.zig");
const Writer = std.Io.Writer;

pub const Proto = @import("engine.zig").Transport;

const qtypes = std.enums.values(wire.Type);
const rcodes = std.enums.values(wire.Rcode);
/// Seconds; forwarded misses wait 2 s per silent upstream (ADR 0008).
const bounds = [_][]const u8{ "0.0001", "0.0005", "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "2.5", "5", "10" };
const bounds_ns = [_]u64{ 100_000, 500_000, 1_000_000, 5_000_000, 10_000_000, 50_000_000, 100_000_000, 500_000_000, 1_000_000_000, 2_500_000_000, 5_000_000_000, 10_000_000_000 };

pub const Upstream = enum { ok, timeout, @"error", rcode };
pub const Update = enum { ok, refused, notauth, @"error" };

pub const Metrics = struct {
    /// [proto][qtype, `other` last][rcode, BADVERS then `other` last]
    queries: [2][qtypes.len + 1][rcodes.len + 2]u64 = @splat(@splat(@splat(0))),
    /// Per bucket, not cumulative; the last one is above every bound.
    buckets: [2][bounds.len + 1]u64 = @splat(@splat(0)),
    sum_ns: [2]u64 = @splat(0),
    cache: [2]u64 = @splat(0), // hit, miss
    /// One row per configured upstream.
    upstreams: [][4]u64 = &.{},
    /// One row per configured key, then `none`: unsigned, or a TSIG failure.
    updates: [][4]u64 = &.{},

    pub fn init(gpa: std.mem.Allocator, n_upstreams: usize, n_keys: usize) !Metrics {
        const m: Metrics = .{ .upstreams = try gpa.alloc([4]u64, n_upstreams), .updates = try gpa.alloc([4]u64, n_keys + 1) };
        @memset(m.upstreams, @splat(0));
        @memset(m.updates, @splat(0));
        return m;
    }

    pub fn deinit(m: *Metrics, gpa: std.mem.Allocator) void {
        gpa.free(m.upstreams);
        gpa.free(m.updates);
    }

    /// `rcode` is the full 12-bit value (BADVERS = 16).
    pub fn query(m: *Metrics, proto: Proto, qtype: ?wire.Type, rcode: u12, dur_ns: u64) void {
        const p = @intFromEnum(proto);
        const t = if (qtype) |q| std.mem.indexOfScalar(wire.Type, qtypes, q) orelse qtypes.len else qtypes.len;
        const r: usize = if (rcode == 16) rcodes.len else if (rcode < 16) std.mem.indexOfScalar(wire.Rcode, rcodes, @enumFromInt(@as(u4, @intCast(rcode)))) orelse rcodes.len + 1 else rcodes.len + 1;
        m.queries[p][t][r] += 1;
        const b = for (bounds_ns, 0..) |ns, i| {
            if (dur_ns <= ns) break i;
        } else bounds.len;
        m.buckets[p][b] += 1;
        m.sum_ns[p] += dur_ns;
    }

    pub fn cacheLookup(m: *Metrics, hit: bool) void {
        m.cache[if (hit) 0 else 1] += 1;
    }

    pub fn upstream(m: *Metrics, i: usize, result: Upstream) void {
        m.upstreams[i][@intFromEnum(result)] += 1;
    }

    /// `key`: the wire name of the key that signed the UPDATE, null when unsigned or not authenticated.
    pub fn update(m: *Metrics, keys: []const tsig.Key, key: ?[]const u8, rc: wire.Rcode) void {
        const i = for (keys, 0..) |k, i| {
            if (key != null and std.mem.eql(u8, k.name, key.?)) break i;
        } else keys.len;
        m.updates[i][@intFromEnum(@as(Update, switch (rc) {
            .noerror => .ok,
            .refused => .refused,
            .notauth => .notauth,
            else => .@"error",
        }))] += 1;
    }
};

/// What the exposition reads besides the counters.
pub const Info = struct {
    version: []const u8,
    mode: []const u8,
    upstreams: []const std.Io.net.IpAddress,
    keys: []const tsig.Key,
    cache_entries: usize,
    dynamic_records: usize,
};

pub const content_type = "text/plain; version=0.0.4; charset=utf-8";

pub fn write(m: *const Metrics, info: Info, w: *Writer) Writer.Error!void {
    try head(w, "annai_build_info", "gauge", "Build version and mode; always 1.");
    try w.writeAll("annai_build_info{version=");
    try label(w, info.version);
    try w.writeAll(",mode=");
    try label(w, info.mode);
    try w.writeAll("} 1\n");

    try head(w, "annai_queries_total", "counter", "Queries answered, by transport, query type and response code.");
    var any = false;
    for (m.queries, 0..) |by_type, p| for (by_type, 0..) |by_rcode, t| for (by_rcode, 0..) |n, r| if (n > 0) {
        any = true;
        try w.print("annai_queries_total{{proto=\"{s}\",qtype=\"", .{@tagName(@as(Proto, @enumFromInt(p)))});
        if (t < qtypes.len) try w.print("{f}", .{log.typeName(qtypes[t])}) else try w.writeAll("other");
        try w.writeAll("\",rcode=\"");
        if (r < rcodes.len) {
            for (@tagName(rcodes[r])) |c| try w.writeByte(std.ascii.toUpper(c));
        } else try w.writeAll(if (r == rcodes.len) "BADVERS" else "other");
        try w.print("\"}} {d}\n", .{n});
    };
    // A family without samples is legal, but one zero series keeps it visible from the start.
    if (!any) try w.writeAll("annai_queries_total{proto=\"udp\",qtype=\"other\",rcode=\"other\"} 0\n");

    try head(w, "annai_query_duration_seconds", "histogram", "Time from reading a query to sending its answer.");
    for (m.buckets, 0..) |counts, p| {
        const proto = @tagName(@as(Proto, @enumFromInt(p)));
        var total: u64 = 0;
        for (counts, 0..) |n, i| {
            total += n;
            try w.print("annai_query_duration_seconds_bucket{{proto=\"{s}\",le=\"{s}\"}} {d}\n", .{ proto, if (i < bounds.len) bounds[i] else "+Inf", total });
        }
        try w.print("annai_query_duration_seconds_sum{{proto=\"{s}\"}} {d}\n", .{ proto, @as(f64, @floatFromInt(m.sum_ns[p])) / 1e9 });
        try w.print("annai_query_duration_seconds_count{{proto=\"{s}\"}} {d}\n", .{ proto, total });
    }

    try head(w, "annai_cache_entries", "gauge", "Answers in the forwarding cache.");
    try w.print("annai_cache_entries {d}\n", .{info.cache_entries});
    try head(w, "annai_cache_lookups_total", "counter", "Forwarded queries looked up in the cache, by result.");
    try w.print("annai_cache_lookups_total{{result=\"hit\"}} {d}\nannai_cache_lookups_total{{result=\"miss\"}} {d}\n", .{ m.cache[0], m.cache[1] });

    if (info.upstreams.len > 0) {
        try head(w, "annai_upstream_queries_total", "counter", "Queries sent to each configured upstream, by result.");
        for (m.upstreams, info.upstreams) |counts, addr| for (counts, 0..) |n, r| {
            var b: [64]u8 = undefined;
            try w.writeAll("annai_upstream_queries_total{upstream=");
            try label(w, std.fmt.bufPrint(&b, "{f}", .{addr}) catch unreachable); // `[v6]:port` fits
            try w.print(",result=\"{s}\"}} {d}\n", .{ @tagName(@as(Upstream, @enumFromInt(r))), n });
        };
    }

    try head(w, "annai_updates_total", "counter", "RFC 2136 updates by configured TSIG key (`none` when unsigned or not authenticated) and result.");
    for (m.updates, 0..) |counts, k| for (counts, 0..) |n, r| {
        var b: [256]u8 = undefined;
        const name = if (k < info.keys.len) std.fmt.bufPrint(&b, "{f}", .{zone.fmt(info.keys[k].name)}) catch unreachable else "none";
        try w.writeAll("annai_updates_total{key=");
        try label(w, std.mem.trimEnd(u8, name, ".")); // the configured spelling: `hanko`, not `hanko.`
        try w.print(",result=\"{s}\"}} {d}\n", .{ @tagName(@as(Update, @enumFromInt(r))), n });
    };

    try head(w, "annai_dynamic_records", "gauge", "Records added by RFC 2136 updates and not yet expired.");
    try w.print("annai_dynamic_records {d}\n", .{info.dynamic_records});
}

fn head(w: *Writer, comptime name: []const u8, comptime kind: []const u8, comptime help: []const u8) !void {
    try w.writeAll("# HELP " ++ name ++ " " ++ help ++ "\n# TYPE " ++ name ++ " " ++ kind ++ "\n");
}

/// A quoted label value, `\`, `"` and newline escaped.
fn label(w: *Writer, v: []const u8) !void {
    try w.writeByte('"');
    for (v) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        '\n' => try w.writeAll("\\n"),
        else => try w.writeByte(c),
    };
    try w.writeByte('"');
}

const testing = std.testing;

test "exposition: closed label sets, cumulative buckets, escaped values" {
    var m = try Metrics.init(testing.allocator, 1, 1);
    defer m.deinit(testing.allocator);
    m.query(.udp, .a, 0, 50_000); // 50 µs
    m.query(.udp, .a, 0, 3_000_000_000); // 3 s
    m.query(.tcp, @enumFromInt(65), 16, 1);
    m.query(.udp, null, 1, 1);
    m.cacheLookup(true);
    m.upstream(0, .timeout);
    const keys = [_]tsig.Key{.{ .name = "\x05hanko\x00", .secret = "x" }};
    m.update(&keys, "\x05hanko\x00", .refused);
    m.update(&keys, "\x05other\x00", .notauth);
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try write(&m, .{ .version = "0.0.0", .mode = "uc\"hi", .upstreams = &.{try std.Io.net.IpAddress.parse("9.9.9.9", 53)}, .keys = &keys, .cache_entries = 3, .dynamic_records = 1 }, &out.writer);
    const text = out.written();
    for ([_][]const u8{
        "annai_build_info{version=\"0.0.0\",mode=\"uc\\\"hi\"} 1\n",
        "annai_queries_total{proto=\"udp\",qtype=\"A\",rcode=\"NOERROR\"} 2\n",
        "annai_queries_total{proto=\"udp\",qtype=\"other\",rcode=\"FORMERR\"} 1\n",
        "annai_queries_total{proto=\"tcp\",qtype=\"other\",rcode=\"BADVERS\"} 1\n",
        "annai_query_duration_seconds_bucket{proto=\"udp\",le=\"0.0001\"} 2\n",
        "annai_query_duration_seconds_bucket{proto=\"udp\",le=\"2.5\"} 2\n",
        "annai_query_duration_seconds_bucket{proto=\"udp\",le=\"5\"} 3\n",
        "annai_query_duration_seconds_bucket{proto=\"udp\",le=\"+Inf\"} 3\n",
        "annai_query_duration_seconds_sum{proto=\"udp\"} 3.000050001\n",
        "annai_query_duration_seconds_count{proto=\"udp\"} 3\n",
        "annai_cache_entries 3\n",
        "annai_cache_lookups_total{result=\"hit\"} 1\n",
        "annai_upstream_queries_total{upstream=\"9.9.9.9:53\",result=\"timeout\"} 1\n",
        "annai_updates_total{key=\"hanko\",result=\"refused\"} 1\n",
        "annai_updates_total{key=\"none\",result=\"notauth\"} 1\n",
        "annai_dynamic_records 1\n",
    }) |want| if (std.mem.indexOf(u8, text, want) == null) {
        std.debug.print("missing {s} in:\n{s}", .{ want, text });
        return error.TestExpectedEqual;
    };
    try testing.expect(std.mem.endsWith(u8, text, "\n"));
    // One HELP and one TYPE per family.
    try testing.expectEqual(@as(usize, 8), std.mem.count(u8, text, "# TYPE "));
}
