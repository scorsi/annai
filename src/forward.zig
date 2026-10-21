//! The cache of forwarded answers (ADR 0008): upstream response packets keyed by (name, type),
//! class IN only, with an expiry in monotonic seconds, a hard byte cap and LRU eviction. No
//! prefetch, no serve-stale. Local zones never reach it: the engine answers them first.

const std = @import("std");
const wire = @import("wire.zig");
const Allocator = std.mem.Allocator;
const List = std.DoublyLinkedList;

/// Bytes counted per entry on top of its key and packet (entry, map slot, allocator headers).
const entry_overhead = 128;

/// The cache key: the lowercase wire name followed by the type.
pub fn key(buf: *[257]u8, lower_name: []const u8, t: wire.Type) []const u8 {
    @memcpy(buf[0..lower_name.len], lower_name);
    std.mem.writeInt(u16, buf[lower_name.len..][0..2], @intFromEnum(t), .big);
    return buf[0 .. lower_name.len + 2];
}

/// Whole-packet caching expires before any retained RR does (ADR 0012).
pub fn lifetime(m: wire.Message, max_ttl: u32) ?u32 {
    if (m.flags.tc) return null;
    const opt = m.edns() catch return null;
    if (opt) |o| if (o.ext_rcode != 0) return null;
    if (m.flags.rcode != 0 and m.flags.rcode != 3) return null;
    var ttl = max_ttl;
    var positive = false;
    for (m.answer) |rr| {
        if (m.question.len == 1) {
            if (rr.type == m.question[0].type or m.question[0].type == .any) positive = true;
        } else if (rr.type != .cname) positive = true;
    }
    if (m.flags.rcode == 3 or !positive) {
        const neg = negativeTtl(m) orelse return null;
        ttl = @min(ttl, neg);
    }
    for ([_][]const wire.RR{ m.answer, m.authority, m.additional }) |section| {
        for (section) |rr| if (rr.type != .opt) {
            ttl = @min(ttl, rr.ttl);
        };
    }
    return ttl;
}

pub fn negativeTtl(m: wire.Message) ?u32 {
    for (m.authority) |rr| if (rr.type == .soa and rr.rdata.len >= 20) {
        const minimum = std.mem.readInt(u32, rr.rdata[rr.rdata.len - 4 ..][0..4], .big);
        return @min(rr.ttl, minimum);
    };
    return null;
}

pub const Cache = struct {
    gpa: Allocator,
    cap: usize,
    used: usize = 0,
    map: std.StringHashMapUnmanaged(*Entry) = .empty,
    /// Most recently used first.
    lru: List = .{},

    pub const Entry = struct {
        node: List.Node = .{},
        key: []u8,
        packet: []u8,
        /// Monotonic seconds.
        expires: i64,
        inserted: i64,

        fn size(e: *const Entry) usize {
            return e.key.len + e.packet.len + entry_overhead;
        }
    };

    pub fn init(gpa: Allocator, cap: usize) Cache {
        return .{ .gpa = gpa, .cap = cap };
    }

    pub fn deinit(c: *Cache) void {
        while (c.lru.first) |n| c.drop(@fieldParentPtr("node", n));
        c.map.deinit(c.gpa);
    }

    /// A live entry, now the most recently used; an expired one is dropped.
    pub fn get(c: *Cache, k: []const u8, now: i64) ?*const Entry {
        const e = c.map.get(k) orelse return null;
        if (e.expires <= now) {
            c.drop(e);
            return null;
        }
        c.lru.remove(&e.node);
        c.lru.prepend(&e.node);
        return e;
    }

    /// Stores a copy of `packet` for `ttl` seconds, replacing any entry under `k` and evicting
    /// the least recently used ones beyond the cap. A zero TTL or an entry above the cap is not stored.
    pub fn put(c: *Cache, k: []const u8, packet: []const u8, ttl: u32, now: i64) Allocator.Error!void {
        if (c.map.get(k)) |old| c.drop(old);
        if (ttl == 0 or k.len + packet.len + entry_overhead > c.cap) return;
        const e = try c.gpa.create(Entry);
        errdefer c.gpa.destroy(e);
        e.* = .{ .key = try c.gpa.dupe(u8, k), .packet = undefined, .expires = now + ttl, .inserted = now };
        errdefer c.gpa.free(e.key);
        e.packet = try c.gpa.dupe(u8, packet);
        errdefer c.gpa.free(e.packet);
        try c.map.put(c.gpa, e.key, e);
        c.lru.prepend(&e.node);
        c.used += e.size();
        while (c.used > c.cap) c.drop(@fieldParentPtr("node", c.lru.last.?));
    }

    fn drop(c: *Cache, e: *Entry) void {
        _ = c.map.remove(e.key);
        c.lru.remove(&e.node);
        c.used -= e.size();
        c.gpa.free(e.key);
        c.gpa.free(e.packet);
        c.gpa.destroy(e);
    }
};

const testing = std.testing;

fn testRR(t: wire.Type, ttl: u32) wire.RR {
    return .{ .name = "\x00", .type = t, .ttl = ttl, .rdata = "\x00\x00\x00\x00" };
}

/// SOA RDATA with MINIMUM = `minimum` (two root names, then five u32).
fn soa(ttl: u32, comptime minimum: u32) wire.RR {
    var r = testRR(.soa, ttl);
    r.rdata = comptime "\x00\x00" ++ "\x00" ** 16 ++ std.mem.toBytes(std.mem.nativeToBig(u32, minimum));
    return r;
}

test "lifetime: positive capped, negative from the SOA, never without one" {
    const pos: wire.Message = .{ .answer = &.{ testRR(.cname, 600), testRR(.a, 300) } };
    try testing.expectEqual(@as(?u32, 300), lifetime(pos, 86400));
    try testing.expectEqual(@as(?u32, 60), lifetime(pos, 60));
    try testing.expectEqual(@as(?u32, 0), lifetime(.{ .answer = &.{testRR(.a, 0)} }, 86400));

    const nx: wire.Message = .{ .flags = .{ .rcode = 3 }, .authority = &.{soa(3600, 300)} };
    try testing.expectEqual(@as(?u32, 300), lifetime(nx, 86400));
    try testing.expectEqual(@as(?u32, 100), lifetime(nx, 100));
    const nodata: wire.Message = .{ .authority = &.{soa(30, 300)} };
    try testing.expectEqual(@as(?u32, 30), lifetime(nodata, 86400));
    try testing.expectEqual(@as(?u32, null), lifetime(.{ .flags = .{ .rcode = 3 } }, 86400));
    try testing.expectEqual(@as(?u32, null), lifetime(.{ .flags = .{ .rcode = 2 }, .authority = &.{soa(30, 300)} }, 86400));
}

test "cache: expiry, replacement, LRU eviction under the byte cap" {
    const one = 10 + 2 + entry_overhead; // a 2-byte key and a 10-byte packet
    var c = Cache.init(testing.allocator, 3 * one);
    defer c.deinit();
    const p = "0123456789";
    try c.put("aa", p, 10, 100);
    try testing.expect(c.get("aa", 109) != null);
    try testing.expect(c.get("aa", 110) == null); // expired and dropped
    try testing.expectEqual(@as(usize, 0), c.used);

    try c.put("aa", p, 10, 0);
    try c.put("bb", p, 10, 0);
    try c.put("cc", p, 10, 0);
    try c.put("cc", p, 20, 0); // replaced, not duplicated
    try testing.expectEqual(3 * one, c.used);
    _ = c.get("aa", 1); // aa is now the most recent: bb is the eviction victim
    try c.put("dd", p, 10, 0);
    try testing.expectEqual(3 * one, c.used);
    try testing.expect(c.get("bb", 1) == null);
    for ([_][]const u8{ "aa", "cc", "dd" }) |k| try testing.expect(c.get(k, 1) != null);
    try testing.expectEqual(@as(i64, 20), c.get("cc", 1).?.expires);

    try c.put("ee", p, 0, 0); // zero TTL: not stored
    try c.put("ff", "x" ** (3 * one), 10, 0); // above the cap: not stored, nothing evicted
    try testing.expect(c.get("ee", 1) == null and c.get("ff", 1) == null);
    try testing.expectEqual(3 * one, c.used);
}

test "review A5: mixed sections and CNAME negatives expire before every retained RR" {
    const q: wire.Question = .{ .name = "\x00", .type = .a };
    const cname: wire.RR = .{ .name = "\x00", .type = .cname, .ttl = 300, .rdata = "\x01x\x00" };
    const address: wire.RR = .{ .name = "\x01x\x00", .type = .a, .ttl = 200, .rdata = "1234" };
    const pos: wire.Message = .{ .question = &.{q}, .answer = &.{ cname, address }, .additional = &.{testRR(.a, 10)} };
    try testing.expectEqual(@as(?u32, 10), lifetime(pos, 86400));
    for ([_]u4{ 0, 3 }) |rcode| {
        var neg: wire.Message = .{ .question = &.{q}, .flags = .{ .rcode = rcode }, .answer = &.{cname}, .authority = &.{soa(3600, 30)} };
        try testing.expectEqual(@as(?u32, 30), lifetime(neg, 86400));
        neg.answer = &.{.{ .name = cname.name, .type = .cname, .ttl = 5, .rdata = cname.rdata }};
        try testing.expectEqual(@as(?u32, 5), lifetime(neg, 86400));
        neg.authority = &.{};
        try testing.expectEqual(@as(?u32, null), lifetime(neg, 86400));
    }
    var truncated = pos;
    truncated.flags.tc = true;
    try testing.expectEqual(@as(?u32, null), lifetime(truncated, 86400));
}
