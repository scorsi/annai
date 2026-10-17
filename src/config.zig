//! Validation of annai.toml and of the zone files it references (ADR 0003). Whatever `check`
//! accepts is the format (ADR 0011).

const std = @import("std");
const mw = @import("microwave");

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
    /// Zone file paths as written; relative ones are relative to annai.toml.
    zones: []const []const u8,
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
    try checkKeys(root, &.{ "mode", "listen", "zones", "forwarding", "update" }, "annai.toml", d);

    const mode_name = try string(try need(root, "mode", "annai.toml", d), "mode", d);
    const mode = std.meta.stringToEnum(Mode, mode_name) orelse return d.fail("mode: \"{s}\" is not uchi or soto", .{mode_name});

    for (try array(try need(root, "listen", "annai.toml", d), "listen", d)) |v| {
        const s = try string(v, "listen", d);
        const addr = std.Io.net.IpAddress.parseLiteral(s) catch return d.fail("listen: \"{s}\" is not address:port", .{s});
        if (addr.getPort() == 0) return d.fail("listen: \"{s}\" needs a port", .{s});
    }

    var zones: std.ArrayList([]const u8) = .empty;
    if (root.get("zones")) |v| {
        const arr = v.anyArrayOrNull() orelse return d.fail("zones: expected an array", .{});
        for (arr.items) |z| try zones.append(a, try string(z, "zones", d));
    }

    // ADR 0002: configuration that does not match the mode is an error.
    if (root.get("forwarding")) |v| {
        if (mode != .uchi) return d.fail("forwarding: only allowed in uchi mode", .{});
        const t = try table(v, "forwarding", d);
        try checkKeys(t, &.{"upstreams"}, "forwarding", d);
        for (try array(try need(t, "upstreams", "forwarding", d), "forwarding.upstreams", d)) |u| {
            const s = try string(u, "forwarding.upstreams", d);
            _ = std.Io.net.IpAddress.parse(s, 53) catch return d.fail("forwarding.upstreams: \"{s}\" is not an IP address", .{s});
        }
    }
    if (root.get("update")) |v| {
        if (mode != .soto) return d.fail("update: only allowed in soto mode", .{});
        const t = try table(v, "update", d);
        try checkKeys(t, &.{"keys"}, "update", d);
        const keys = try array(try need(t, "keys", "update", d), "update.keys", d);
        for (keys, 0..) |k, i| {
            const kt = try table(k, "update.keys", d);
            try checkKeys(kt, &.{ "name", "secret_file" }, "update.keys", d);
            const name = try string(try need(kt, "name", "update.keys", d), "update.keys.name", d);
            try checkName(if (std.mem.endsWith(u8, name, ".")) name else try std.fmt.allocPrint(a, "{s}.", .{name}), "update.keys.name", d);
            for (keys[0..i]) |prev| if (std.mem.eql(u8, prev.anyTableOrNull().?.get("name").?.string, name))
                return d.fail("update.keys: duplicate key \"{s}\"", .{name});
            const path = try string(try need(kt, "secret_file", "update.keys", d), "update.keys.secret_file", d);
            if (!std.fs.path.isAbsolute(path)) return d.fail("update.keys: secret_file \"{s}\" is not absolute", .{path});
        }
    }
    return .{ .mode = mode, .zones = zones.items };
}

const record_types = .{ "a", "aaaa", "cname", "ns", "ptr", "mx", "srv", "txt" };

/// Validates one zone file and returns its origin.
pub fn checkZone(a: Allocator, text: []const u8, d: *Diag) Error![]const u8 {
    const root = try parse(a, text, d);
    try checkKeys(root, &.{ "origin", "ttl", "serial", "soa", "names" }, "zone", d);

    const origin = try string(try need(root, "origin", "zone", d), "origin", d);
    try checkName(origin, "origin", d);
    _ = try int(u31, try need(root, "ttl", origin, d), "ttl", d); // RFC 2181: TTLs are 31 bits
    _ = try int(u32, try need(root, "serial", origin, d), "serial", d);

    const soa = try table(try need(root, "soa", origin, d), "soa", d);
    try checkKeys(soa, &.{ "mname", "rname", "refresh", "retry", "expire", "minimum" }, "soa", d);
    inline for (.{ "mname", "rname" }) |k| _ = try absName(a, try string(try need(soa, k, "soa", d), "soa." ++ k, d), origin, "soa." ++ k, d);
    inline for (.{ "refresh", "retry", "expire", "minimum" }) |k| _ = try int(u32, try need(soa, k, "soa", d), "soa." ++ k, d);

    // Owners by absolute name, for CNAME exclusivity, the apex NS and glue.
    var owners: std.StringArrayHashMapUnmanaged(Table) = .empty;
    var ns_targets: std.ArrayList([]const u8) = .empty;
    const names = try table(try need(root, "names", origin, d), "names", d);
    for (names.keys(), names.values()) |key, v| {
        const ctx = try std.fmt.allocPrint(a, "names.\"{s}\"", .{key});
        const owner = try absName(a, key, origin, ctx, d);
        if (!inZone(owner, origin)) return d.fail("{s}: \"{s}\" is outside {s}", .{ ctx, owner, origin });
        const rrsets = try table(v, ctx, d);
        try checkKeys(rrsets, &record_types, ctx, d);
        const seen = try owners.getOrPut(a, owner);
        if (seen.found_existing) return d.fail("{s}: same name as another key ({s})", .{ ctx, owner });
        seen.value_ptr.* = rrsets;

        for (rrsets.keys(), rrsets.values()) |rtype, rv| {
            const rctx = try std.fmt.allocPrint(a, "{s}.{s}", .{ ctx, rtype });
            if (std.mem.eql(u8, rtype, "cname")) {
                _ = try absName(a, try string(rv, rctx, d), origin, rctx, d);
                if (std.mem.eql(u8, owner, origin)) return d.fail("{s}: no CNAME at the zone apex", .{rctx});
                if (rrsets.count() > 1) return d.fail("{s}: cname excludes every other type on the name", .{rctx});
                continue;
            }
            for (try array(rv, rctx, d)) |r| try checkRecord(a, rtype, r, origin, rctx, d);
            if (std.mem.eql(u8, rtype, "ns")) {
                if (!std.mem.eql(u8, owner, origin)) return d.fail("{s}: NS only at the zone apex, no delegation (ADR 0004)", .{rctx});
                for (rv.anyArrayOrNull().?.items) |r| try ns_targets.append(a, try absName(a, r.string, origin, rctx, d));
            }
        }
    }

    if (ns_targets.items.len == 0) return d.fail("names.\"@\": the zone apex needs an ns RRset", .{});
    // Glue sanity: a nameserver inside the zone must have an address in it.
    for (ns_targets.items) |t| if (inZone(t, origin)) {
        const rrsets = owners.get(t) orelse return d.fail("ns: \"{s}\" is in the zone but has no A or AAAA", .{t});
        if (rrsets.get("a") == null and rrsets.get("aaaa") == null) return d.fail("ns: \"{s}\" is in the zone but has no A or AAAA", .{t});
    };
    return origin;
}

fn checkRecord(a: Allocator, rtype: []const u8, r: Value, origin: []const u8, ctx: []const u8, d: *Diag) Error!void {
    const eql = std.mem.eql;
    if (eql(u8, rtype, "a")) {
        const s = try string(r, ctx, d);
        _ = std.Io.net.Ip4Address.parse(s, 0) catch return d.fail("{s}: \"{s}\" is not an IPv4 address", .{ ctx, s });
    } else if (eql(u8, rtype, "aaaa")) {
        const s = try string(r, ctx, d);
        _ = std.Io.net.Ip6Address.parse(s, 0) catch return d.fail("{s}: \"{s}\" is not an IPv6 address", .{ ctx, s });
    } else if (eql(u8, rtype, "ns") or eql(u8, rtype, "ptr")) {
        _ = try absName(a, try string(r, ctx, d), origin, ctx, d);
    } else if (eql(u8, rtype, "txt")) {
        _ = try string(r, ctx, d);
    } else if (eql(u8, rtype, "mx")) {
        const t = try table(r, ctx, d);
        try checkKeys(t, &.{ "preference", "exchange" }, ctx, d);
        _ = try int(u16, try need(t, "preference", ctx, d), ctx, d);
        _ = try absName(a, try string(try need(t, "exchange", ctx, d), ctx, d), origin, ctx, d);
    } else if (eql(u8, rtype, "srv")) {
        const t = try table(r, ctx, d);
        try checkKeys(t, &.{ "priority", "weight", "port", "target" }, ctx, d);
        inline for (.{ "priority", "weight", "port" }) |k| _ = try int(u16, try need(t, k, ctx, d), ctx, d);
        _ = try absName(a, try string(try need(t, "target", ctx, d), ctx, d), origin, ctx, d);
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
;

fn expectZone(text: []const u8, want: ?[]const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var d: Diag = .{};
    const got = checkZone(arena.allocator(), text, &d);
    if (want) |msg| {
        try testing.expectError(error.Invalid, got);
        if (std.mem.indexOf(u8, d.msg, msg) == null) {
            std.debug.print("want \"{s}\" in \"{s}\"\n", .{ msg, d.msg });
            return error.TestUnexpectedResult;
        }
    } else {
        try testing.expectEqualStrings("uchi.example.org.", try got);
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
        .{ "txt = [\"v=spf1 -all\"]", "caa = [\"x\"]", "unknown key \"caa\"" },
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
    try expectConfig(soto ++ "[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/run/secrets/k\"", null);

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
    try expectConfig(soto ++ "[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/a\"\n[[update.keys]]\nname = \"hanko\"\nsecret_file = \"/b\"", "duplicate key");
}
