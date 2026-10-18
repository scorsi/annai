//! RFC 2136 UPDATE under the policy of ADR 0006, and the in-memory overlay it feeds: TXT records
//! at `_acme-challenge.` owners inside a loaded zone, added and deleted by a TSIG-authenticated
//! client (hanko), served after the static data and never written to disk. Bounded: the TTL is
//! capped, the lifetime is capped whatever the TTL, and the count has a hard cap.

const std = @import("std");
const builtin = @import("builtin");
const wire = @import("wire.zig");
const zone = @import("zone.zig");
const Allocator = std.mem.Allocator;
const Rcode = wire.Rcode;

pub const max_records = 1024;
const challenge_label = "\x0f_acme-challenge";

pub const Overlay = struct {
    gpa: Allocator,
    /// Cap on the TTL served; seconds a record stays, whatever its TTL.
    max_ttl: u32,
    lifetime: u32,
    records: std.ArrayList(Record) = .empty,

    /// A dynamic TXT record; `name` is a lowercase wire name, `expires` monotonic seconds.
    pub const Record = struct { name: []u8, rdata: []u8, ttl: u32, expires: i64 };

    pub fn init(gpa: Allocator, max_ttl: u32, lifetime: u32) Overlay {
        return .{ .gpa = gpa, .max_ttl = max_ttl, .lifetime = lifetime };
    }

    pub fn deinit(o: *Overlay) void {
        for (o.records.items) |r| o.free(r);
        o.records.deinit(o.gpa);
    }

    /// Whether `name` or any name below it has a dynamic record: the name exists (ADR 0004).
    pub fn exists(o: *const Overlay, name: []const u8) bool {
        for (o.records.items) |r| if (zone.isUnder(r.name, name)) return true;
        return false;
    }

    /// Adds a TXT record or refreshes the identical one; the TTL and lifetime caps apply.
    fn add(o: *Overlay, name: []const u8, rdata: []const u8, ttl: u32, now: i64) error{ Full, OutOfMemory }!void {
        const capped = @min(ttl, o.max_ttl);
        const expires = now + o.lifetime;
        for (o.records.items) |*r| if (std.mem.eql(u8, r.name, name) and std.mem.eql(u8, r.rdata, rdata)) {
            r.ttl = capped;
            r.expires = expires;
            return;
        };
        if (o.records.items.len >= max_records) return error.Full;
        const n = try o.gpa.dupe(u8, name);
        errdefer o.gpa.free(n);
        const d = try o.gpa.dupe(u8, rdata);
        errdefer o.gpa.free(d);
        try o.records.append(o.gpa, .{ .name = n, .rdata = d, .ttl = capped, .expires = expires });
    }

    /// Deletes the record with this RDATA, or every record of the name when `rdata` is null.
    fn remove(o: *Overlay, name: []const u8, rdata: ?[]const u8) void {
        var i: usize = 0;
        while (i < o.records.items.len) {
            const r = o.records.items[i];
            if (std.mem.eql(u8, r.name, name) and (rdata == null or std.mem.eql(u8, r.rdata, rdata.?))) o.free(o.records.swapRemove(i)) else i += 1;
        }
    }

    /// Drops the records whose lifetime is over.
    pub fn expire(o: *Overlay, now: i64) void {
        var i: usize = 0;
        while (i < o.records.items.len) {
            if (o.records.items[i].expires <= now) o.free(o.records.swapRemove(i)) else i += 1;
        }
    }

    fn free(o: *Overlay, r: Record) void {
        o.gpa.free(r.name);
        o.gpa.free(r.rdata);
    }
};

/// Applies the UPDATE `m` (RFC 2136 §3) sent under `key` (null = unsigned) to `overlay` (null =
/// uchi mode): zone section, prerequisites, the ADR 0006 policy, prescan, then the changes.
pub fn apply(overlay: ?*Overlay, zones: []const zone.Zone, m: wire.Message, key: ?[]const u8, now: i64) Rcode {
    const o = overlay orelse return refused(key, "uchi-mode", null);
    const k = key orelse return refused(null, "unsigned", null);
    const zq = m.question[0];
    if (zq.type != .soa or zq.class != .in) return .formerr;
    var zbuf: [255]u8 = undefined;
    const zname = lowerInto(&zbuf, zq.name);
    const z = for (zones) |*z| {
        if (std.mem.eql(u8, z.origin, zname)) break z;
    } else return .notauth;

    // §3.2 prerequisites, evaluated against the static data plus the overlay.
    for (m.answer) |p| {
        if (p.ttl != 0) return .formerr;
        var nbuf: [255]u8 = undefined;
        const owner = lowerInto(&nbuf, p.name);
        if (!zone.isUnder(owner, z.origin)) return .notzone;
        const whole_name = p.type == .any;
        switch (p.class) {
            .any, .none => {
                if (p.rdata.len != 0) return .formerr;
                if (!isChallenge(owner) or !(whole_name or p.type == .txt)) return refused(k, "prerequisite", owner);
                const present = if (whole_name) z.lookup(owner) != null or o.exists(owner) else count(z, o, owner) > 0;
                if (p.class == .any and !present) return if (whole_name) .nxdomain else .nxrrset;
                if (p.class == .none and present) return if (whole_name) .yxdomain else .yxrrset;
            },
            .in => {
                if (!allowed(owner, p.type)) return refused(k, "prerequisite", owner);
                if (!has(z, o, owner, p.rdata)) return .nxrrset;
                // Value dependent (§3.2.3): the live RRset holds nothing beyond the prerequisite RRs.
                var distinct: usize = 0;
                for (m.answer, 0..) |q, j| if (q.class == .in and std.ascii.eqlIgnoreCase(q.name, p.name)) {
                    const seen = for (m.answer[0..j]) |e| {
                        if (e.class == .in and std.ascii.eqlIgnoreCase(e.name, q.name) and std.mem.eql(u8, e.rdata, q.rdata)) break true;
                    } else false;
                    if (!seen) distinct += 1;
                };
                if (distinct != count(z, o, owner)) return .nxrrset;
            },
            else => return .formerr,
        }
    }

    // §3.3 permissions (the policy) and §3.4.1 prescan.
    for (m.authority) |u| {
        var nbuf: [255]u8 = undefined;
        const owner = lowerInto(&nbuf, u.name);
        if (!zone.isUnder(owner, z.origin)) return .notzone;
        if (!allowed(owner, u.type)) return refused(k, "policy", owner);
        switch (u.class) {
            .in => if (!validTxt(u.rdata)) return .formerr,
            .any => if (u.ttl != 0 or u.rdata.len != 0) return .formerr,
            .none => if (u.ttl != 0 or !validTxt(u.rdata)) return .formerr,
            else => return .formerr,
        }
    }

    // §3.4.2: the changes, on the overlay only; static RRsets and the SOA serial never move.
    for (m.authority) |u| {
        var nbuf: [255]u8 = undefined;
        const owner = lowerInto(&nbuf, u.name);
        switch (u.class) {
            .in => o.add(owner, u.rdata, u.ttl, now) catch |e| {
                std.debug.print("level=warn event=update-failed key={f} owner={f} reason={s}\n", .{ zone.fmt(k), zone.fmt(owner), @errorName(e) });
                return .servfail;
            },
            .any => o.remove(owner, null),
            .none => o.remove(owner, u.rdata),
            else => unreachable, // prescan
        }
        // The count-cap test would otherwise flood the build runner's stderr.
        if (!builtin.is_test) std.debug.print("level=info event=update key={f} owner={f} op={s} records={d}\n", .{ zone.fmt(k), zone.fmt(owner), @tagName(u.class), o.records.items.len });
    }
    return .noerror;
}

fn refused(key: ?[]const u8, reason: []const u8, owner: ?[]const u8) Rcode {
    std.debug.print("level=warn event=update-refused key={f} owner={f} reason={s}\n", .{ zone.fmt(key orelse "\x04none\x00"), zone.fmt(owner orelse "\x00"), reason });
    return .refused;
}

fn lowerInto(buf: *[255]u8, name: []const u8) []const u8 {
    @memcpy(buf[0..name.len], name);
    return zone.lower(buf[0..name.len]);
}

/// ADR 0006: only TXT records at `_acme-challenge.<something>`.
fn allowed(owner: []const u8, t: wire.Type) bool {
    return t == .txt and isChallenge(owner);
}

fn isChallenge(owner: []const u8) bool {
    return std.mem.startsWith(u8, owner, challenge_label) and owner.len > challenge_label.len + 1;
}

/// TXT RDATA is one or more <character-string>s and nothing else.
fn validTxt(rdata: []const u8) bool {
    if (rdata.len == 0) return false;
    var i: usize = 0;
    while (i < rdata.len) i += 1 + rdata[i];
    return i == rdata.len;
}

/// The live TXT RRset of `owner`: static values followed by dynamic ones.
fn count(z: *const zone.Zone, o: *const Overlay, owner: []const u8) usize {
    var n: usize = if (z.lookup(owner)) |name| (if (name.get(.txt)) |set| set.rdatas.len else 0) else 0;
    for (o.records.items) |r| if (std.mem.eql(u8, r.name, owner)) {
        n += 1;
    };
    return n;
}

fn has(z: *const zone.Zone, o: *const Overlay, owner: []const u8, rdata: []const u8) bool {
    if (z.lookup(owner)) |name| if (name.get(.txt)) |set| for (set.rdatas) |rd| if (std.mem.eql(u8, rd, rdata)) return true;
    for (o.records.items) |r| if (std.mem.eql(u8, r.name, owner) and std.mem.eql(u8, r.rdata, rdata)) return true;
    return false;
}

// ---- tests -------------------------------------------------------------------------------------

const testing = std.testing;
const config = @import("config.zig");

const apex =
    \\origin = "example.org."
    \\ttl = 300
    \\serial = 1
    \\[soa]
    \\mname = "ns1"
    \\rname = "hostmaster"
    \\refresh = 3600
    \\retry = 600
    \\expire = 604800
    \\minimum = 60
    \\[names."@"]
    \\ns = ["ns1"]
    \\[names."ns1"]
    \\a = ["192.0.2.53"]
    \\[names."_acme-challenge.static"]
    \\txt = ["fixed"]
;

/// One prerequisite or update RR; `txt` is the single <character-string> of its RDATA.
const Op = struct { name: []const u8, class: wire.Class = .in, type: wire.Type = .txt, ttl: u32 = 60, txt: []const u8 = "" };

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    zones: [1]zone.Zone,
    overlay: Overlay,

    fn init() !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.arena = std.heap.ArenaAllocator.init(testing.allocator);
        f.overlay = Overlay.init(testing.allocator, 120, 3600);
        var d: config.Diag = .{};
        f.zones[0] = config.loadZone(f.arena.allocator(), apex, &d) catch |e| {
            std.debug.print("{s}\n", .{d.msg});
            return e;
        };
        return f;
    }

    fn deinit(f: *Fixture) void {
        f.overlay.deinit();
        f.arena.deinit();
        testing.allocator.destroy(f);
    }

    /// Applies an UPDATE on `zone` with the given prerequisites and updates, as key "hanko".
    fn send(f: *Fixture, zname: []const u8, prereqs: []const Op, updates: []const Op, now: i64) !Rcode {
        const a = f.arena.allocator();
        var nbuf: [255]u8 = undefined;
        const m: wire.Message = .{
            .flags = .{ .opcode = 5 },
            .question = &.{.{ .name = try a.dupe(u8, try wire.nameFromText(&nbuf, zname)), .type = .soa }},
            .answer = try f.rrs(prereqs),
            .authority = try f.rrs(updates),
        };
        return apply(&f.overlay, &f.zones, m, "\x05hanko\x00", now);
    }

    fn rrs(f: *Fixture, ops: []const Op) ![]wire.RR {
        const a = f.arena.allocator();
        const out = try a.alloc(wire.RR, ops.len);
        for (ops, out) |op, *rr| {
            var nbuf: [255]u8 = undefined;
            const rdata = if (op.txt.len == 0) "" else try std.mem.concat(a, u8, &.{ &.{@as(u8, @intCast(op.txt.len))}, op.txt });
            rr.* = .{ .name = try a.dupe(u8, try wire.nameFromText(&nbuf, op.name)), .type = op.type, .class = op.class, .ttl = op.ttl, .rdata = rdata };
        }
        return out;
    }

    fn values(f: *Fixture, name: []const u8) usize {
        var nbuf: [255]u8 = undefined;
        return count(&f.zones[0], &f.overlay, wire.nameFromText(&nbuf, name) catch unreachable);
    }

    fn hasTxt(f: *Fixture, name: []const u8, rdata: []const u8) bool {
        var nbuf: [255]u8 = undefined;
        return has(&f.zones[0], &f.overlay, wire.nameFromText(&nbuf, name) catch unreachable, rdata);
    }
};

const ch = "_acme-challenge.git.uchi.example.org.";

test "add, refresh, delete one RR, delete the RRset; TTL and lifetime caps; expiry" {
    const f = try Fixture.init();
    defer f.deinit();
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = ch, .ttl = 3600, .txt = "tok1" }}, 1000));
    try testing.expectEqual(Rcode.noerror, try f.send("EXAMPLE.org.", &.{}, &.{.{ .name = "_ACME-challenge.git.uchi.example.org.", .txt = "tok2" }}, 1001));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = ch, .ttl = 30, .txt = "tok1" }}, 1002)); // refreshed, not duplicated
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = "_acme-challenge.example.org.", .txt = "apex" }}, 1002)); // a certificate for the apex
    try testing.expectEqual(@as(usize, 1), f.values("_acme-challenge.example.org."));
    try testing.expectEqual(@as(usize, 2), f.values(ch));
    try testing.expectEqual(@as(u32, 30), f.overlay.records.items[0].ttl);
    try testing.expectEqual(@as(i64, 1002 + 3600), f.overlay.records.items[0].expires);
    try testing.expectEqual(@as(u32, 60), f.overlay.records.items[1].ttl);
    try testing.expect(f.overlay.exists("\x03git\x04uchi\x07example\x03org\x00") and !f.overlay.exists("\x03vm\x04uchi\x07example\x03org\x00"));

    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = ch, .class = .none, .ttl = 0, .txt = "tok1" }}, 1003));
    try testing.expectEqual(@as(usize, 1), f.values(ch));
    try testing.expect(f.hasTxt(ch, "\x04tok2") and !f.hasTxt(ch, "\x04tok1"));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = ch, .class = .any, .ttl = 0 }}, 1004));
    try testing.expectEqual(@as(usize, 0), f.values(ch));
    // The static TXT is never touched.
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = "_acme-challenge.static.example.org.", .class = .any, .ttl = 0 }}, 1005));
    try testing.expectEqual(@as(usize, 1), f.values("_acme-challenge.static.example.org."));

    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = ch, .txt = "gone" }}, 2000));
    f.overlay.expire(2000 + 3599);
    try testing.expectEqual(@as(usize, 1), f.values(ch));
    f.overlay.expire(2000 + 3600);
    try testing.expectEqual(@as(usize, 0), f.values(ch));
}

test "policy: REFUSED for other owners, types and operations; FORMERR, NOTAUTH, NOTZONE; the count cap" {
    const f = try Fixture.init();
    defer f.deinit();
    const cases = [_]struct { Op, Rcode }{
        .{ .{ .name = "git.uchi.example.org.", .txt = "x" }, .refused },
        .{ .{ .name = ch, .type = .a, .txt = "x" }, .refused },
        .{ .{ .name = ch, .type = .any, .class = .any, .ttl = 0 }, .refused }, // delete every RRset of the name
        .{ .{ .name = ch, .class = .any, .ttl = 0, .txt = "x" }, .formerr },
        .{ .{ .name = ch, .class = .none, .ttl = 1, .txt = "x" }, .formerr },
        .{ .{ .name = ch, .class = @enumFromInt(3), .txt = "x" }, .formerr },
        .{ .{ .name = "_acme-challenge.git.uchi.example.net.", .txt = "x" }, .notzone },
    };
    for (cases) |c| try testing.expectEqual(c[1], try f.send("example.org.", &.{}, &.{c[0]}, 0));
    try testing.expectEqual(Rcode.notauth, try f.send("uchi.example.org.", &.{}, &.{.{ .name = ch, .txt = "x" }}, 0));
    try testing.expectEqual(Rcode.notauth, try f.send("example.net.", &.{}, &.{.{ .name = ch, .txt = "x" }}, 0));
    // Malformed TXT RDATA.
    var nbuf: [255]u8 = undefined;
    const bad: wire.Message = .{ .question = &.{.{ .name = try wire.nameFromText(&nbuf, "example.org."), .type = .soa }}, .authority = &.{.{ .name = "\x0f_acme-challenge\x01a\x07example\x03org\x00", .type = .txt, .rdata = "\x05ab" }} };
    try testing.expectEqual(Rcode.formerr, apply(&f.overlay, &f.zones, bad, "\x05hanko\x00", 0));
    // Unsigned, and uchi mode.
    try testing.expectEqual(Rcode.refused, apply(&f.overlay, &f.zones, bad, null, 0));
    try testing.expectEqual(Rcode.refused, apply(null, &f.zones, bad, "\x05hanko\x00", 0));
    try testing.expectEqual(@as(usize, 0), f.overlay.records.items.len);

    var name_buf: [64]u8 = undefined;
    for (0..max_records) |i| {
        const name = try std.fmt.bufPrint(&name_buf, "_acme-challenge.n{d}.example.org.", .{i});
        try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = name, .txt = "x" }}, 0));
    }
    try testing.expectEqual(Rcode.servfail, try f.send("example.org.", &.{}, &.{.{ .name = ch, .txt = "x" }}, 0));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = "_acme-challenge.n7.example.org.", .txt = "x" }}, 0)); // a refresh needs no room
}

test "prerequisites per RFC 2136 §3.2, within the policy" {
    const f = try Fixture.init();
    defer f.deinit();
    const static = "_acme-challenge.static.example.org.";
    const in_use: Op = .{ .name = ch, .class = .any, .type = .any, .ttl = 0 };
    const not_in_use: Op = .{ .name = ch, .class = .none, .type = .any, .ttl = 0 };
    const set_exists: Op = .{ .name = ch, .class = .any, .ttl = 0 };
    const set_absent: Op = .{ .name = ch, .class = .none, .ttl = 0 };
    const add: Op = .{ .name = ch, .txt = "tok1" };

    try testing.expectEqual(Rcode.nxdomain, try f.send("example.org.", &.{in_use}, &.{add}, 0));
    try testing.expectEqual(Rcode.nxrrset, try f.send("example.org.", &.{set_exists}, &.{add}, 0));
    try testing.expectEqual(Rcode.nxrrset, try f.send("example.org.", &.{.{ .name = ch, .ttl = 0, .txt = "tok1" }}, &.{add}, 0));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{ not_in_use, set_absent }, &.{add}, 0));
    try testing.expectEqual(Rcode.yxdomain, try f.send("example.org.", &.{not_in_use}, &.{}, 0));
    try testing.expectEqual(Rcode.yxrrset, try f.send("example.org.", &.{set_absent}, &.{}, 0));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{ in_use, set_exists, .{ .name = ch, .ttl = 0, .txt = "tok1" } }, &.{}, 0));
    // Value dependent: the whole RRset must be listed, duplicates count once, static values count.
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{}, &.{.{ .name = ch, .txt = "tok2" }}, 0));
    try testing.expectEqual(Rcode.nxrrset, try f.send("example.org.", &.{.{ .name = ch, .ttl = 0, .txt = "tok1" }}, &.{}, 0));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{ .{ .name = ch, .ttl = 0, .txt = "tok1" }, .{ .name = ch, .ttl = 0, .txt = "tok2" }, .{ .name = ch, .ttl = 0, .txt = "tok2" } }, &.{}, 0));
    try testing.expectEqual(Rcode.noerror, try f.send("example.org.", &.{.{ .name = static, .ttl = 0, .txt = "fixed" }}, &.{}, 0));
    // Errors and the policy.
    try testing.expectEqual(Rcode.formerr, try f.send("example.org.", &.{.{ .name = ch, .class = .any, .ttl = 1 }}, &.{}, 0));
    try testing.expectEqual(Rcode.formerr, try f.send("example.org.", &.{.{ .name = ch, .class = .any, .ttl = 0, .txt = "x" }}, &.{}, 0));
    try testing.expectEqual(Rcode.notzone, try f.send("example.org.", &.{.{ .name = "_acme-challenge.example.net.", .class = .any, .ttl = 0 }}, &.{}, 0));
    try testing.expectEqual(Rcode.refused, try f.send("example.org.", &.{.{ .name = "example.org.", .class = .any, .type = .any, .ttl = 0 }}, &.{}, 0));
    try testing.expectEqual(Rcode.refused, try f.send("example.org.", &.{.{ .name = ch, .class = .any, .type = .a, .ttl = 0 }}, &.{}, 0));
    try testing.expectEqual(Rcode.refused, try f.send("example.org.", &.{.{ .name = "ns1.example.org.", .ttl = 0, .txt = "x" }}, &.{}, 0));
}
