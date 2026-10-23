//! Validation of annai.toml and of the zone files it references (ADR 0003). Whatever `check`
//! accepts is the format (ADR 0011).

const std = @import("std");
const mw = @import("microwave");
const wire = @import("wire.zig");
const zone = @import("zone.zig");

const Value = mw.Parser.Value;
const Table = Value.Table;
const Allocator = std.mem.Allocator;

pub const Error = error{Invalid} || Allocator.Error;

/// Holds the message of the first validation error.
pub const Diag = struct {
    buf: [1024]u8 = undefined,
    msg: []const u8 = "",

    fn fail(d: *Diag, comptime fmt: []const u8, args: anytype) error{Invalid} {
        d.msg = std.fmt.bufPrint(&d.buf, fmt, args) catch d.buf[0..];
        return error.Invalid;
    }
};

pub const Mode = enum { uchi, soto };

pub const Config = struct {
    mode: Mode,
    listen: []const std.Io.net.IpAddress,
    /// Zone file paths as written; relative ones are relative to annai.toml.
    zones: []const []const u8,
    /// uchi only; absent means names outside the zones are REFUSED.
    forwarding: ?Forwarding = null,
    /// soto only (ADR 0006).
    update: ?Update = null,
    /// The loopback `GET /metrics` listener (ADR 0011); null = none.
    metrics: ?std.Io.net.IpAddress = null,
};

/// `[update]` (ADR 0006).
pub const Update = struct {
    keys: []const KeyRef,
    /// Cap on the TTL of a dynamic record, and the seconds it stays whatever its TTL.
    max_ttl: u32 = 120,
    lifetime: u32 = 3600,
};

pub const KeyRef = struct {
    /// Lowercase wire name.
    name: []const u8,
    secret_file: []const u8,
};

/// `[forwarding]` (ADR 0008).
pub const Forwarding = struct {
    /// Port 53, tried in order.
    upstreams: []const std.Io.net.IpAddress,
    /// Upper bound on whole-packet cache lifetime, positive and negative.
    max_ttl: u32 = 86400,
    /// Hard cap on the cache: packet bytes plus per-entry overhead, LRU eviction beyond it.
    cache_bytes: usize = 16 << 20,
};

fn parse(a: Allocator, text: []const u8, d: *Diag) Error!Table {
    // shortcut: microwave fails on a value at end of input without a newline; drop once fixed upstream.
    const padded = try std.mem.concat(a, u8, &.{ text, "\n" });
    const doc = mw.parseFromSliceLeaky(a, padded) catch |e| return d.fail("invalid TOML: {s}", .{@errorName(e)});
    return doc.table;
}

fn checkKeys(t: Table, comptime allowed: []const []const u8, ctx: []const u8, d: *Diag) Error!void {
    outer: for (t.keys()) |k| {
        inline for (allowed) |name| if (std.mem.eql(u8, k, name)) continue :outer;
        return d.fail("{s}: unknown key \"{s}\"", .{ ctx, k });
    }
}

fn need(t: Table, key: []const u8, ctx: []const u8, d: *Diag) Error!Value {
    return t.get(key) orelse d.fail("{s}: missing \"{s}\"", .{ ctx, key });
}

fn table(v: Value, ctx: []const u8, d: *Diag) Error!Table {
    return v.anyTableOrNull() orelse d.fail("{s}: expected a table", .{ctx});
}

fn string(v: Value, ctx: []const u8, d: *Diag) Error![]const u8 {
    return if (v == .string) v.string else d.fail("{s}: expected a string", .{ctx});
}

fn int(comptime T: type, v: Value, ctx: []const u8, d: *Diag) Error!T {
    if (v != .integer) return d.fail("{s}: expected an integer", .{ctx});
    return std.math.cast(T, v.integer) orelse d.fail("{s}: {d} out of range", .{ ctx, v.integer });
}

/// A non-empty array: an RRset or a list that must say something.
fn array(v: Value, ctx: []const u8, d: *Diag) Error![]const Value {
    const arr = v.anyArrayOrNull() orelse return d.fail("{s}: expected an array", .{ctx});
    if (arr.items.len == 0) return d.fail("{s}: empty array", .{ctx});
    return arr.items;
}

/// An absolute name in presentation form: lowercase labels of `[a-z0-9_-]` (ADR 0005, `_` for
/// service and ACME labels), 1 to 63 bytes each, at most 255 bytes on the wire.
fn checkName(name: []const u8, ctx: []const u8, d: *Diag) Error!void {
    if (name.len < 2 or name[name.len - 1] != '.') return d.fail("{s}: \"{s}\" is not an absolute name", .{ ctx, name });
    if (name.len + 1 > 255) return d.fail("{s}: \"{s}\" is longer than 255 bytes", .{ ctx, name });
    var labels = std.mem.splitScalar(u8, name[0 .. name.len - 1], '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return d.fail("{s}: \"{s}\" has a label of {d} bytes", .{ ctx, name, label.len });
        for (label) |c| switch (c) {
            'a'...'z', '0'...'9', '-', '_' => {},
            else => return d.fail("{s}: \"{s}\" has character '{c}' (labels are [a-z0-9_-])", .{ ctx, name, c }),
        };
    }
}

/// `name` made absolute: `@` is the origin, names without a final dot are relative to it.
fn absName(a: Allocator, name: []const u8, origin: []const u8, ctx: []const u8, d: *Diag) Error![]const u8 {
    if (std.mem.eql(u8, name, "@")) return origin;
    const abs = if (std.mem.endsWith(u8, name, ".")) name else try std.fmt.allocPrint(a, "{s}.{s}", .{ name, origin });
    try checkName(abs, ctx, d);
    return abs;
}

fn inZone(name: []const u8, origin: []const u8) bool {
    if (!std.mem.endsWith(u8, name, origin)) return false;
    return name.len == origin.len or name[name.len - origin.len - 1] == '.';
}

pub fn checkConfig(a: Allocator, text: []const u8, d: *Diag) Error!Config {
    const root = try parse(a, text, d);
    try checkKeys(root, &.{ "mode", "listen", "zones", "forwarding", "update", "metrics" }, "annai.toml", d);

    const mode_name = try string(try need(root, "mode", "annai.toml", d), "mode", d);
    const mode = std.meta.stringToEnum(Mode, mode_name) orelse return d.fail("mode: \"{s}\" is not uchi or soto", .{mode_name});

    var listen: std.ArrayList(std.Io.net.IpAddress) = .empty;
    for (try array(try need(root, "listen", "annai.toml", d), "listen", d)) |v| {
        const s = try string(v, "listen", d);
        const addr = std.Io.net.IpAddress.parseLiteral(s) catch return d.fail("listen: \"{s}\" is not address:port", .{s});
        if (addr.getPort() == 0) return d.fail("listen: \"{s}\" needs a port", .{s});
        try listen.append(a, addr);
    }

    var zones: std.ArrayList([]const u8) = .empty;
    if (root.get("zones")) |v| {
        const arr = v.anyArrayOrNull() orelse return d.fail("zones: expected an array", .{});
        for (arr.items) |z| try zones.append(a, try string(z, "zones", d));
    }

    // ADR 0002: configuration that does not match the mode is an error.
    var forwarding: ?Forwarding = null;
    if (root.get("forwarding")) |v| {
        const t = try table(v, "forwarding", d);
        if (t.contains("min_ttl")) return d.fail("forwarding: removed key \"min_ttl\"; remove this option (ADR 0012: docs/adr/0012-cache-ttl-bounds.md)", .{});
        if (mode != .uchi) return d.fail("forwarding: only allowed in uchi mode", .{});
        try checkKeys(t, &.{ "upstreams", "max_ttl", "cache_bytes" }, "forwarding", d);
        var upstreams: std.ArrayList(std.Io.net.IpAddress) = .empty;
        for (try array(try need(t, "upstreams", "forwarding", d), "forwarding.upstreams", d)) |u| {
            const s = try string(u, "forwarding.upstreams", d);
            try upstreams.append(a, std.Io.net.IpAddress.parse(s, 53) catch return d.fail("forwarding.upstreams: \"{s}\" is not an IP address", .{s}));
        }
        var f: Forwarding = .{ .upstreams = upstreams.items };
        // RFC 2181: TTLs are 31 bits.
        if (t.get("max_ttl")) |x| f.max_ttl = try int(u31, x, "forwarding.max_ttl", d);
        if (t.get("cache_bytes")) |x| f.cache_bytes = try int(usize, x, "forwarding.cache_bytes", d);
        forwarding = f;
    }
    var update: ?Update = null;
    if (root.get("update")) |v| {
        if (mode != .soto) return d.fail("update: only allowed in soto mode", .{});
        const t = try table(v, "update", d);
        try checkKeys(t, &.{ "keys", "max_ttl", "lifetime" }, "update", d);
        const keys = try array(try need(t, "keys", "update", d), "update.keys", d);
        const refs = try a.alloc(KeyRef, keys.len);
        for (keys, refs, 0..) |k, *ref, i| {
            const kt = try table(k, "update.keys", d);
            try checkKeys(kt, &.{ "name", "secret_file" }, "update.keys", d);
            const name = try string(try need(kt, "name", "update.keys", d), "update.keys.name", d);
            const abs = if (std.mem.endsWith(u8, name, ".")) name else try std.fmt.allocPrint(a, "{s}.", .{name});
            try checkName(abs, "update.keys.name", d);
            const path = try string(try need(kt, "secret_file", "update.keys", d), "update.keys.secret_file", d);
            if (!std.fs.path.isAbsolute(path)) return d.fail("update.keys: secret_file \"{s}\" is not absolute", .{path});
            ref.* = .{ .name = try wireName(a, abs), .secret_file = path };
            for (refs[0..i]) |prev| if (std.mem.eql(u8, prev.name, ref.name)) return d.fail("update.keys: duplicate key \"{s}\"", .{name});
        }
        var u: Update = .{ .keys = refs };
        if (t.get("max_ttl")) |x| u.max_ttl = try int(u31, x, "update.max_ttl", d);
        if (t.get("lifetime")) |x| u.lifetime = try int(u31, x, "update.lifetime", d);
        update = u;
    }
    var metrics: ?std.Io.net.IpAddress = null;
    if (root.get("metrics")) |v| {
        const s = try string(v, "metrics", d);
        const addr = std.Io.net.IpAddress.parseLiteral(s) catch return d.fail("metrics: \"{s}\" is not address:port", .{s});
        // The local agent is the only scraper (masu's metric convention).
        const loopback = switch (addr) {
            .ip4 => |ip| std.mem.eql(u8, &ip.bytes, &.{ 127, 0, 0, 1 }),
            .ip6 => |ip| std.mem.eql(u8, &ip.bytes, &(.{0} ** 15 ++ .{1})),
        };
        if (!loopback or addr.getPort() == 0) return d.fail("metrics: \"{s}\" is not 127.0.0.1:<port> or [::1]:<port>", .{s});
        metrics = addr;
    }
    return .{ .mode = mode, .listen = listen.items, .zones = zones.items, .forwarding = forwarding, .update = update, .metrics = metrics };
}

const record_types = .{ "a", "aaaa", "cname", "ns", "ptr", "mx", "srv", "txt", "caa" };

/// Type codes and the wire RDATA of one record value, built while validating it.
const Record = struct { type: wire.Type, rdata: []const u8 };

/// Validates one zone file and loads it: RRsets in wire form with the zone's default TTL, the
/// SOA both as `soa` and as an RRset of the apex, and every empty non-terminal (ADR 0004).
pub fn loadZone(a: Allocator, text: []const u8, d: *Diag) Error!zone.Zone {
    const root = try parse(a, text, d);
    try checkKeys(root, &.{ "origin", "ttl", "serial", "soa", "names" }, "zone", d);

    const origin = try string(try need(root, "origin", "zone", d), "origin", d);
    try checkName(origin, "origin", d);
    const ttl = try int(u31, try need(root, "ttl", origin, d), "ttl", d); // RFC 2181: TTLs are 31 bits
    const serial = try int(u32, try need(root, "serial", origin, d), "serial", d);

    const soa = try table(try need(root, "soa", origin, d), "soa", d);
    try checkKeys(soa, &.{ "mname", "rname", "refresh", "retry", "expire", "minimum" }, "soa", d);
    var soa_rdata: std.ArrayList(u8) = .empty;
    inline for (.{ "mname", "rname" }) |k| try soa_rdata.appendSlice(a, try wireName(a, try absName(a, try string(try need(soa, k, "soa", d), "soa." ++ k, d), origin, "soa." ++ k, d)));
    try appendInt(a, &soa_rdata, u32, serial);
    inline for (.{ "refresh", "retry", "expire", "minimum" }) |k| try appendInt(a, &soa_rdata, u32, try int(u32, try need(soa, k, "soa", d), "soa." ++ k, d));
    const soa_set: zone.RRset = .{ .type = .soa, .ttl = ttl, .rdatas = try a.dupe([]const u8, &.{soa_rdata.items}) };

    // Owners by absolute name, for CNAME exclusivity, the apex NS and glue.
    var owners: std.StringArrayHashMapUnmanaged(Table) = .empty;
    var names: std.StringHashMapUnmanaged(zone.Name) = .empty;
    var ns_targets: std.ArrayList([]const u8) = .empty;
    const names_t = try table(try need(root, "names", origin, d), "names", d);
    for (names_t.keys(), names_t.values()) |key, v| {
        const ctx = try std.fmt.allocPrint(a, "names.\"{s}\"", .{key});
        // RFC 4592 wildcards (ADR 0007 v1): `*` only as the whole leftmost label of an owner.
        const wild = std.mem.eql(u8, key, "*") or std.mem.startsWith(u8, key, "*.");
        const owner = if (wild) try std.mem.concat(a, u8, &.{ "*.", if (key.len == 1) origin else try absName(a, key[2..], origin, ctx, d) }) else try absName(a, key, origin, ctx, d);
        if (owner.len + 1 > 255) return d.fail("{s}: \"{s}\" is longer than 255 bytes", .{ ctx, owner });
        if (!inZone(owner, origin)) return d.fail("{s}: \"{s}\" is outside {s}", .{ ctx, owner, origin });
        const rrsets = try table(v, ctx, d);
        try checkKeys(rrsets, &record_types, ctx, d);
        const seen = try owners.getOrPut(a, owner);
        if (seen.found_existing) return d.fail("{s}: same name as another key ({s})", .{ ctx, owner });
        seen.value_ptr.* = rrsets;

        var sets: std.ArrayList(zone.RRset) = .empty;
        if (std.mem.eql(u8, owner, origin)) try sets.append(a, soa_set);
        for (rrsets.keys(), rrsets.values()) |rtype, rv| {
            const rctx = try std.fmt.allocPrint(a, "{s}.{s}", .{ ctx, rtype });
            if (std.mem.eql(u8, rtype, "cname")) {
                const target = try absName(a, try string(rv, rctx, d), origin, rctx, d);
                if (std.mem.eql(u8, owner, origin)) return d.fail("{s}: no CNAME at the zone apex", .{rctx});
                if (rrsets.count() > 1) return d.fail("{s}: cname excludes every other type on the name", .{rctx});
                try sets.append(a, .{ .type = .cname, .ttl = ttl, .rdatas = try a.dupe([]const u8, &.{try wireName(a, target)}) });
                continue;
            }
            const values = try array(rv, rctx, d);
            const rdatas = try a.alloc([]const u8, values.len);
            var rtype_code: wire.Type = undefined;
            for (values, rdatas) |r, *rd| {
                const rec = try checkRecord(a, rtype, r, origin, rctx, d);
                rtype_code = rec.type;
                rd.* = rec.rdata;
            }
            if (rtype_code == .mx and rdatas.len > 1) for (rdatas) |rd| if (rd.len == 3)
                return d.fail("{s}: a null MX (exchange \".\") must be the only MX of its name (RFC 7505)", .{rctx});
            try sets.append(a, .{ .type = rtype_code, .ttl = ttl, .rdatas = rdatas });
            if (std.mem.eql(u8, rtype, "ns")) {
                if (!std.mem.eql(u8, owner, origin)) return d.fail("{s}: NS only at the zone apex, no delegation (ADR 0004)", .{rctx});
                for (values) |r| try ns_targets.append(a, try absName(a, r.string, origin, rctx, d));
            }
        }
        try names.put(a, try wireName(a, owner), .{ .rrsets = sets.items });
    }

    if (ns_targets.items.len == 0) return d.fail("names.\"@\": the zone apex needs an ns RRset", .{});
    // Glue sanity: a nameserver inside the zone must have an address in it.
    for (ns_targets.items) |t| if (inZone(t, origin)) {
        const rrsets = owners.get(t) orelse return d.fail("ns: \"{s}\" is in the zone but has no A or AAAA", .{t});
        if (rrsets.get("a") == null and rrsets.get("aaaa") == null) return d.fail("ns: \"{s}\" is in the zone but has no A or AAAA", .{t});
    };

    // Empty non-terminals: every ancestor of an owner, down to the origin, exists.
    const origin_wire = try wireName(a, origin);
    for (owners.keys()) |owner| {
        var n = try wireName(a, owner);
        while (n.len > origin_wire.len) {
            n = n[1 + n[0] ..];
            const ent = try names.getOrPut(a, n);
            if (ent.found_existing) break;
            ent.value_ptr.* = .{};
        }
    }
    return .{ .origin = origin_wire, .soa = soa_set, .names = names };
}

fn appendInt(a: Allocator, out: *std.ArrayList(u8), comptime T: type, v: T) Allocator.Error!void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .big);
    try out.appendSlice(a, &b);
}

fn wireName(a: Allocator, text: []const u8) Error![]const u8 {
    var buf: [255]u8 = undefined;
    return a.dupe(u8, wire.nameFromText(&buf, text) catch unreachable); // checkName ran first
}

/// An MX exchange or SRV target in wire form: a name as `absName` takes it, or the root "." (null
/// MX, RFC 7505; service decidedly not available, RFC 2782), allowed nowhere else.
fn targetName(a: Allocator, v: Value, origin: []const u8, ctx: []const u8, d: *Diag) Error![]const u8 {
    const s = try string(v, ctx, d);
    return wireName(a, if (std.mem.eql(u8, s, ".")) s else try absName(a, s, origin, ctx, d));
}

fn checkRecord(a: Allocator, rtype: []const u8, r: Value, origin: []const u8, ctx: []const u8, d: *Diag) Error!Record {
    const eql = std.mem.eql;
    if (eql(u8, rtype, "a")) {
        const s = try string(r, ctx, d);
        const ip = std.Io.net.Ip4Address.parse(s, 0) catch return d.fail("{s}: \"{s}\" is not an IPv4 address", .{ ctx, s });
        return .{ .type = .a, .rdata = try a.dupe(u8, &ip.bytes) };
    } else if (eql(u8, rtype, "aaaa")) {
        const s = try string(r, ctx, d);
        const ip = std.Io.net.Ip6Address.parse(s, 0) catch return d.fail("{s}: \"{s}\" is not an IPv6 address", .{ ctx, s });
        return .{ .type = .aaaa, .rdata = try a.dupe(u8, &ip.bytes) };
    } else if (eql(u8, rtype, "ns") or eql(u8, rtype, "ptr")) {
        const name = try wireName(a, try absName(a, try string(r, ctx, d), origin, ctx, d));
        return .{ .type = if (eql(u8, rtype, "ns")) .ns else .ptr, .rdata = name };
    } else if (eql(u8, rtype, "txt")) {
        // One <character-string> per 255 bytes, as every zone tool splits long TXT values.
        const s = try string(r, ctx, d);
        if (s.len == 0) return d.fail("{s}: empty string", .{ctx});
        var out: std.ArrayList(u8) = .empty;
        var rest = s;
        while (rest.len > 0) {
            const n = @min(rest.len, 255);
            try out.append(a, @intCast(n));
            try out.appendSlice(a, rest[0..n]);
            rest = rest[n..];
        }
        return .{ .type = .txt, .rdata = out.items };
    } else if (eql(u8, rtype, "mx")) {
        const t = try table(r, ctx, d);
        try checkKeys(t, &.{ "preference", "exchange" }, ctx, d);
        var out: std.ArrayList(u8) = .empty;
        const pref = try int(u16, try need(t, "preference", ctx, d), ctx, d);
        const exchange = try targetName(a, try need(t, "exchange", ctx, d), origin, ctx, d);
        if (exchange.len == 1 and pref != 0) return d.fail("{s}: a null MX (exchange \".\") has preference 0, not {d} (RFC 7505)", .{ ctx, pref });
        try appendInt(a, &out, u16, pref);
        try out.appendSlice(a, exchange);
        return .{ .type = .mx, .rdata = out.items };
    } else if (eql(u8, rtype, "srv")) {
        const t = try table(r, ctx, d);
        try checkKeys(t, &.{ "priority", "weight", "port", "target" }, ctx, d);
        var out: std.ArrayList(u8) = .empty;
        inline for (.{ "priority", "weight", "port" }) |k| try appendInt(a, &out, u16, try int(u16, try need(t, k, ctx, d), ctx, d));
        try out.appendSlice(a, try targetName(a, try need(t, "target", ctx, d), origin, ctx, d));
        return .{ .type = .srv, .rdata = out.items };
    } else if (eql(u8, rtype, "caa")) {
        // RFC 8659: flags, a tag of 1-15 letters or digits, a value of any length.
        const t = try table(r, ctx, d);
        try checkKeys(t, &.{ "flags", "tag", "value" }, ctx, d);
        const tag = try string(try need(t, "tag", ctx, d), ctx, d);
        if (tag.len == 0 or tag.len > 15) return d.fail("{s}: tag \"{s}\" is not 1 to 15 characters", .{ ctx, tag });
        for (tag) |c| if (!std.ascii.isAlphanumeric(c)) return d.fail("{s}: tag \"{s}\" is not alphanumeric", .{ ctx, tag });
        const value = try string(try need(t, "value", ctx, d), ctx, d);
        var out: std.ArrayList(u8) = .empty;
        try out.append(a, try int(u8, try need(t, "flags", ctx, d), ctx, d));
        try out.append(a, @intCast(tag.len));
        try out.appendSlice(a, tag);
        try out.appendSlice(a, value);
        return .{ .type = .caa, .rdata = out.items };
    } else unreachable; // checkKeys allowed only record_types
}

const testing = std.testing;

const good_zone =
    \\origin = "uchi.example.org."
    \\ttl = 300
    \\serial = 1760400000
    \\
    \\[soa]
    \\mname = "annai.uchi.example.org."
    \\rname = "hostmaster.example.org."
    \\refresh = 3600
    \\retry = 600
    \\expire = 604800
    \\minimum = 300
    \\
    \\[names."@"]
    \\ns = ["annai.uchi.example.org."]
    \\
    \\[names."annai"]
    \\a = ["10.100.0.2"]
    \\
    \\[names."hub.kekkai"]
    \\a = ["10.100.0.1"]
    \\aaaa = ["fd12:3456:789a::1"]
    \\
    \\[names."git"]
    \\cname = "vm.kekkai"
    \\
    \\[names."mail"]
    \\mx = [{ preference = 10, exchange = "mail.soto.example.org." }]
    \\txt = ["v=spf1 -all"]
    \\
    \\[names."_imaps._tcp"]
    \\srv = [{ priority = 10, weight = 0, port = 993, target = "mail.soto.example.org." }]
    \\
    \\[names."nomail"]
    \\mx = [{ preference = 0, exchange = "." }]
    \\
    \\[names."_off._tcp"]
    \\srv = [{ priority = 0, weight = 0, port = 0, target = "." }]
    \\
    \\[names."web"]
    \\caa = [{ flags = 0, tag = "issue", value = "letsencrypt.org" }]
    \\
    \\[names."*.wild"]
    \\a = ["10.100.0.9"]
    \\
    \\[names."*"]
    \\cname = "web"
;

fn expectZone(text: []const u8, want: ?[]const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var d: Diag = .{};
    const got = loadZone(arena.allocator(), text, &d);
    if (want) |msg| {
        try testing.expectError(error.Invalid, got);
        if (std.mem.indexOf(u8, d.msg, msg) == null) {
            std.debug.print("want \"{s}\" in \"{s}\"\n", .{ msg, d.msg });
            return error.TestUnexpectedResult;
        }
    } else {
        try testing.expectEqualStrings("\x04uchi\x07example\x03org\x00", (try got).origin);
    }
}

/// `good_zone` with `old` replaced by `new`.
fn mutate(old: []const u8, new: []const u8) ![]u8 {
    const out = try std.mem.replaceOwned(u8, testing.allocator, good_zone, old, new);
    try testing.expect(!std.mem.eql(u8, out, good_zone));
    return out;
}

test "the ADR 0003 zone is valid" {
    try expectZone(good_zone, null);
}

test "the root is one zero byte as a null MX exchange and an SRV target" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var d: Diag = .{};
    const z = try loadZone(arena.allocator(), good_zone, &d);
    const nomail = z.names.get("\x06nomail\x04uchi\x07example\x03org\x00").?;
    try testing.expectEqualSlices(u8, "\x00\x00\x00", nomail.rrsets[0].rdatas[0]);
    const off = z.names.get("\x04_off\x04_tcp\x04uchi\x07example\x03org\x00").?;
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x00\x00\x00", off.rrsets[0].rdatas[0]);
}

test "every invalid zone is rejected" {
    const cases = [_]struct { []const u8, []const u8, []const u8 }{
        .{ "ttl = 300", "ttl = -1", "ttl: -1 out of range" },
        .{ "ttl = 300", "ttl = 2147483648", "out of range" },
        .{ "serial = 1760400000", "serial = 4294967296", "out of range" },
        .{ "serial = 1760400000", "", "missing \"serial\"" },
        .{ "origin = \"uchi.example.org.\"", "origin = \"uchi.example.org\"", "not an absolute name" },
        .{ "minimum = 300", "minimum = \"300\"", "expected an integer" },
        .{ "minimum = 300", "", "missing \"minimum\"" },
        .{ "expire = 604800", "expire = 604800\nserial = 1", "unknown key \"serial\"" },
        .{ "cname = \"vm.kekkai\"", "cname = \"vm.kekkai\"\na = [\"10.0.0.1\"]", "cname excludes" },
        .{ "[names.\"@\"]", "[names.\"@\"]\ncname = \"x\"", "no CNAME at the zone apex" },
        .{ "ns = [\"annai.uchi.example.org.\"]", "ns = []", "empty array" },
        .{ "[names.\"@\"]\nns = [\"annai.uchi.example.org.\"]", "", "apex needs an ns" },
        .{ "ns = [\"annai.uchi.example.org.\"]", "ns = [\"ns1.uchi.example.org.\"]", "has no A or AAAA" },
        .{ "[names.\"annai\"]\na = [\"10.100.0.2\"]", "[names.\"annai\"]\ntxt = [\"x\"]", "has no A or AAAA" },
        .{ "cname = \"vm.kekkai\"", "ns = [\"a.example.net.\"]", "NS only at the zone apex" },
        .{ "a = [\"10.100.0.2\"]", "a = [\"10.100.0.256\"]", "not an IPv4 address" },
        .{ "a = [\"10.100.0.2\"]", "a = [\"fd12::1\"]", "not an IPv4 address" },
        .{ "aaaa = [\"fd12:3456:789a::1\"]", "aaaa = [\"10.0.0.1\"]", "not an IPv6 address" },
        .{ "aaaa = [\"fd12:3456:789a::1\"]", "aaaa = \"fd12::1\"", "expected an array" },
        .{ "txt = [\"v=spf1 -all\"]", "caa = [\"x\"]", "expected a table" },
        .{ "tag = \"issue\"", "tag = \"issue wild\"", "not alphanumeric" },
        .{ "tag = \"issue\"", "tag = \"\"", "not 1 to 15" },
        .{ "flags = 0", "flags = 256", "out of range" },
        .{ "flags = 0, ", "", "missing \"flags\"" },
        .{ "[names.\"git\"]", "[names.\"Git\"]", "character 'G'" },
        .{ "[names.\"git\"]", "[names.\"git.example.net.\"]", "outside uchi.example.org." },
        .{ "[names.\"git\"]", "[names.\"a..b\"]", "label of 0 bytes" },
        .{ "[names.\"git\"]", "[names.\"" ++ "x" ** 64 ++ "\"]", "label of 64 bytes" },
        .{ "[names.\"git\"]", "[names.\"" ++ ("x" ** 60 ++ ".") ** 5 ++ "\"]", "longer than 255 bytes" },
        .{ "[names.\"git\"]", "[names.\"annai.uchi.example.org.\"]", "same name as another key" },
        .{ "port = 993", "port = 65536", "out of range" },
        .{ "port = 993, ", "", "missing \"port\"" },
        .{ "preference = 10", "preference = 10, weight = 1", "unknown key \"weight\"" },
        .{ "exchange = \"mail.soto.example.org.\"", "exchange = \"mail soto\"", "character ' '" },
        .{ "origin = \"uchi.example.org.\"", "origin = = 1", "invalid TOML" },
        // The root "." only as an MX exchange (null MX, RFC 7505: preference 0, alone) or SRV target.
        .{ "preference = 0, exchange = \".\"", "preference = 10, exchange = \".\"", "has preference 0, not 10" },
        .{ "preference = 0, exchange = \".\" }", "preference = 0, exchange = \".\" }, { preference = 10, exchange = \"mail\" }", "must be the only MX" },
        .{ "cname = \"web\"", "cname = \".\"", "\".\" is not an absolute name" },
        .{ "ns = [\"annai.uchi.example.org.\"]", "ns = [\".\"]", "\".\" is not an absolute name" },
        .{ "mname = \"annai.uchi.example.org.\"", "mname = \".\"", "\".\" is not an absolute name" },
        .{ "[names.\"git\"]", "[names.\".\"]", "\".\" is not an absolute name" },
        .{ "origin = \"uchi.example.org.\"", "origin = \".\"", "\".\" is not an absolute name" },
        // Wildcards: `*` is a whole leftmost owner label, nothing else (RFC 4592, ADR 0007).
        .{ "[names.\"*.wild\"]", "[names.\"a.*.wild\"]", "character '*'" },
        .{ "[names.\"*.wild\"]", "[names.\"*.*.wild\"]", "character '*'" },
        .{ "[names.\"*.wild\"]", "[names.\"*wild\"]", "character '*'" },
        .{ "cname = \"web\"", "cname = \"*.wild\"", "character '*'" },
        // 253 bytes of relative name pass checkName on their own; the `*.` label pushes the owner over.
        .{ "[names.\"*.wild\"]", "[names.\"*." ++ ("x" ** 60 ++ ".") ** 3 ++ "x" ** 52 ++ "\"]", "longer than 255 bytes" },
        .{ "[names.\"*.wild\"]\na = [\"10.100.0.9\"]", "[names.\"*.wild\"]\nns = [\"annai.uchi.example.org.\"]", "NS only at the zone apex" },
    };
    for (cases) |c| {
        const text = try mutate(c[0], c[1]);
        defer testing.allocator.free(text);
        expectZone(text, c[2]) catch |e| {
            std.debug.print("case {s} -> {s}\n", .{ c[0], c[1] });
            return e;
        };
    }
}

test "a type named in wire.Type is not a zone record type unless the parser lists it (ADR 0003)" {
    inline for (@typeInfo(wire.Type).@"enum".fields) |f| {
        const listed = comptime for (record_types) |t| {
            if (std.mem.eql(u8, t, f.name)) break true;
        } else false;
        if (!listed) {
            const text = try mutate("txt = [\"v=spf1 -all\"]", f.name ++ " = [\"x\"]");
            defer testing.allocator.free(text);
            try expectZone(text, "unknown key \"" ++ f.name ++ "\"");
        }
    }
}

fn expectConfig(text: []const u8, want: ?[]const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var d: Diag = .{};
    const got = checkConfig(arena.allocator(), text, &d);
    if (want) |msg| {
        try testing.expectError(error.Invalid, got);
        if (std.mem.indexOf(u8, d.msg, msg) == null) {
            std.debug.print("want \"{s}\" in \"{s}\"\n", .{ msg, d.msg });
            return error.TestUnexpectedResult;
        }
    } else _ = try got;
}

test "annai.toml" {
    const uchi = "mode = \"uchi\"\nlisten = [\"0.0.0.0:53\", \"[::]:53\"]\nzones = [\"uchi.toml\"]\n";
    const soto = "mode = \"soto\"\nlisten = [\"192.0.2.1:53\"]\n";
    try expectConfig(uchi ++ "[forwarding]\nupstreams = [\"9.9.9.9\", \"2620:fe::fe\"]", null);
    try expectConfig(uchi ++ "[forwarding]\nupstreams = [\"9.9.9.9\"]\nmax_ttl = 3600\ncache_bytes = 1048576", null);
    try expectConfig(uchi ++ "[forwarding]\nupstreams = [\"9.9.9.9\"]\nmax_ttl = 2147483648", "out of range");
    try expectConfig(uchi ++ "[forwarding]\nupstreams = [\"9.9.9.9\"]\ncache_bytes = -1", "out of range");
    try expectConfig(soto ++ "[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/run/secrets/k\"", null);
    try expectConfig(soto ++ "[update]\nmax_ttl = 60\nlifetime = 600\n[[update.keys]]\nname = \"hanko.example.org.\"\nsecret_file = \"/run/secrets/k\"", null);
    try expectConfig(soto ++ "[update]\nmax_tll = 60\n[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/k\"", "unknown key \"max_tll\"");
    try expectConfig(soto ++ "[update]\nlifetime = -1\n[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/k\"", "out of range");
    try expectConfig(soto ++ "[[update.keys]]\nname = \"Hanko\"\nsecret_file = \"/k\"", "character 'H'");

    try expectConfig("listen = [\"0.0.0.0:53\"]", "missing \"mode\"");
    try expectConfig("mode = \"saki\"\nlisten = [\"0.0.0.0:53\"]", "not uchi or soto");
    try expectConfig("mode = \"uchi\"", "missing \"listen\"");
    try expectConfig("mode = \"uchi\"\nlisten = []", "empty array");
    try expectConfig("mode = \"uchi\"\nlisten = [\"0.0.0.0\"]", "needs a port");
    try expectConfig("mode = \"uchi\"\nlisten = [\"::\"]", "not address:port");
    try expectConfig(uchi ++ "zone = []", "unknown key \"zone\"");
    try expectConfig(uchi ++ "[forwarding]\nupstreams = [\"quad9\"]", "not an IP address");
    try expectConfig(uchi ++ "[forwarding]\nupstream = [\"9.9.9.9\"]", "unknown key \"upstream\"");
    try expectConfig(soto ++ "[forwarding]\nupstreams = [\"9.9.9.9\"]", "only allowed in uchi mode");
    try expectConfig(uchi ++ "[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/k\"", "only allowed in soto mode");
    try expectConfig(soto ++ "[[update.keys]]\nname = \"hanko\"\nsecret_file = \"k\"", "is not absolute");
    try expectConfig(soto ++ "[[update.keys]]\nname = \"hanko\"\nsecret = \"c2VjcmV0\"", "unknown key \"secret\"");
    try expectConfig(soto ++ "[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/a\"\n[[update.keys]]\nname = \"hanko.\"\nsecret_file = \"/b\"", "duplicate key");
    try expectConfig(uchi ++ "metrics = \"127.0.0.1:9153\"", null);
    try expectConfig(soto ++ "metrics = \"[::1]:9153\"", null);
    try expectConfig(uchi ++ "metrics = \"0.0.0.0:9153\"", "is not 127.0.0.1:<port>");
    try expectConfig(uchi ++ "metrics = \"[::]:9153\"", "is not 127.0.0.1:<port>");
    try expectConfig(uchi ++ "metrics = \"127.0.0.1:0\"", "is not 127.0.0.1:<port>");
    try expectConfig(uchi ++ "metrics = \"localhost:9153\"", "not address:port");
}

test "annai.toml: min_ttl was removed by ADR 0012" {
    inline for (.{ "uchi", "soto" }) |mode| {
        inline for (.{ "0", "30", "\"unused\"" }) |value| {
            try expectConfig("mode = \"" ++ mode ++ "\"\nlisten = [\"127.0.0.1:53\"]\n[forwarding]\nupstreams = [\"9.9.9.9\"]\nmin_ttl = " ++ value, "forwarding: removed key \"min_ttl\"; remove this option (ADR 0012: docs/adr/0012-cache-ttl-bounds.md)");
        }
    }
}
