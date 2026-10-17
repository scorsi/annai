//! In-memory zones (M1): RRsets by owner name, with the empty non-terminals of ADR 0004 and the
//! lookups the authoritative engine needs. Names are lowercase wire names (`wire.zig`); the
//! loader (`config.zig`) builds zones, nothing here mutates them afterwards (ADR 0003).

const std = @import("std");
const wire = @import("wire.zig");

pub const RRset = struct { type: wire.Type, ttl: u32, rdatas: []const []const u8 };

/// A name that exists in the zone; no RRset means an empty non-terminal.
pub const Name = struct {
    rrsets: []const RRset = &.{},

    pub fn get(n: Name, t: wire.Type) ?RRset {
        for (n.rrsets) |s| if (s.type == t) return s;
        return null;
    }
};

pub const Zone = struct {
    origin: []const u8,
    soa: RRset,
    names: std.StringHashMapUnmanaged(Name),

    pub fn lookup(z: *const Zone, name: []const u8) ?Name {
        return z.names.get(name);
    }

    /// SOA TTL for negative answers: min(SOA TTL, SOA MINIMUM) (RFC 2308 §3).
    pub fn negativeTtl(z: *const Zone) u32 {
        const rdata = z.soa.rdatas[0];
        return @min(z.soa.ttl, std.mem.readInt(u32, rdata[rdata.len - 4 ..][0..4], .big));
    }
};

/// The zone whose origin is the longest suffix of `name` (lowercase wire form).
pub fn find(zones: []const Zone, name: []const u8) ?*const Zone {
    var best: ?*const Zone = null;
    for (zones) |*z| {
        if (best != null and z.origin.len <= best.?.origin.len) continue;
        if (isUnder(name, z.origin)) best = z;
    }
    return best;
}

/// Whether `name` is `origin` or below it, both in wire form with the same case.
pub fn isUnder(name: []const u8, origin: []const u8) bool {
    if (name.len < origin.len) return false;
    const at = name.len - origin.len;
    var i: usize = 0;
    while (i < at) i += 1 + name[i]; // label starts are the only valid suffix offsets
    return i == at and std.mem.eql(u8, name[at..], origin);
}

/// Lowercases a wire name in place; length bytes are below 64 so only letters change.
pub fn lower(name: []u8) []u8 {
    return std.ascii.lowerString(name, name);
}

const testing = std.testing;

test "isUnder respects label boundaries" {
    var buf: [255]u8 = undefined;
    const origin = try testing.allocator.dupe(u8, try wire.nameFromText(&buf, "example.org."));
    defer testing.allocator.free(origin);
    try testing.expect(isUnder(try wire.nameFromText(&buf, "example.org."), origin));
    try testing.expect(isUnder(try wire.nameFromText(&buf, "a.b.example.org."), origin));
    try testing.expect(!isUnder(try wire.nameFromText(&buf, "notexample.org."), origin));
    try testing.expect(!isUnder(try wire.nameFromText(&buf, "org."), origin));
    try testing.expect(!isUnder(try wire.nameFromText(&buf, "example.net."), origin));
}

test "lower keeps the label lengths" {
    var buf: [255]u8 = undefined;
    const n = try wire.nameFromText(&buf, "HuB.Kekkai.UCHI.example.org.");
    try testing.expectEqualSlices(u8, "\x03hub\x06kekkai\x04uchi\x07example\x03org\x00", lower(buf[0..n.len]));
}
