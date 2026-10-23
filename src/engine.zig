//! Authoritative responder (ADR 0007 v0): one query packet in, one response packet out. Transport
//! independent: the caller says how many bytes the transport allows (`udp` caps at the EDNS
//! payload, 512 without OPT) and the engine sets TC when the answer does not fit. A TSIG-signed
//! message is verified before anything else and its response signed (ADR 0006); UPDATEs go to
//! `update.zig`, whose overlay is consulted after the static data.

const std = @import("std");
const wire = @import("wire.zig");
const zone = @import("zone.zig");
const tsig = @import("tsig.zig");
const update = @import("update.zig");
const log = @import("log.zig");
const forwarding = @import("forward.zig");
const metrics = @import("metrics.zig");

pub const Rcode = wire.Rcode;

/// RFC 6891 §6.2.3 and DNS Flag Day 2020: never trust a payload above 1232 or below 512.
pub const max_udp_payload = 1232;
pub const min_udp_payload = 512;
const badvers = 1; // extended RCODE 16 = ext_rcode 1, rcode 0
const hinfo_rfc8482 = "\x07RFC8482\x00";
const max_cname_hops = 8;

pub const Transport = enum { udp, tcp };

/// What the engine answers from: the zones and, in soto mode, the TSIG keys and the overlay.
pub const Context = struct {
    zones: []const zone.Zone,
    keys: []const tsig.Key = &.{},
    /// Null in uchi mode: every UPDATE is REFUSED (ADR 0006).
    overlay: ?*update.Overlay = null,
    /// Wall-clock seconds (TSIG) and monotonic seconds (overlay lifetimes).
    now: i64 = 0,
    mono: i64 = 0,
    /// Where UPDATE results are counted (ADR 0011); null in unit tests.
    metrics: ?*metrics.Metrics = null,
};

/// A query for a name outside the local zones, for the caller to forward (uchi mode, ADR 0008).
pub const Forward = struct {
    id: u16,
    rd: bool,
    /// The client's question, case kept; borrows the query packet and the arena.
    question: wire.Question,
    /// The OPT to echo, if the client sent one.
    opt: ?wire.Opt,
    /// Bytes the transport allows for the answer.
    limit: usize,
    /// `forwarding.max_ttl`: no served TTL exceeds it (ADR 0008, 0012).
    max_ttl: u32 = std.math.maxInt(u32),
};

/// Writes the response to `query` into `out` and returns its length, or null when the packet
/// deserves no answer (shorter than a header, or itself a response). With `forward`, a valid
/// query outside the zones is not REFUSED: it is stored there and null is returned.
pub fn respond(arena: std.mem.Allocator, ctx: Context, query: []const u8, out: []u8, transport: Transport, forward: ?*?Forward) ?usize {
    if (query.len < 12) return null;
    const id = std.mem.readInt(u16, query[0..2], .big);
    const qflags: wire.Flags = @bitCast(std.mem.readInt(u16, query[2..4], .big));
    if (qflags.qr) return null;

    var r: Response = .{
        // A forwarding server offers recursion on every answer, local ones included (RFC 1035 §4.1.1).
        .flags = .{ .qr = true, .opcode = qflags.opcode, .rd = qflags.rd, .ra = forward != null },
        .limit = if (transport == .tcp) out.len else min_udp_payload,
        .now = ctx.now,
        .arena = arena,
    };
    // Reject before expanding questions (A1), but echo a structurally valid OPT (B2).
    if (std.mem.readInt(u16, query[4..6], .big) != 1) {
        if (wire.findOpt(query) catch null) |_| r.opt = .{ .payload = @min(out.len, max_udp_payload) };
        return r.finish(id, out, .formerr);
    }
    const msg = wire.Message.parse(arena, query) catch |e| switch (e) {
        error.Malformed => return r.finish(id, out, .formerr),
        error.OutOfMemory => return r.finish(id, out, .servfail),
    };
    const q = msg.question[0];
    r.question = q;
    const opt = msg.edns() catch {
        // A malformed option still requires a minimal response OPT (RFC 6891 §7).
        if (msg.optRecord() catch null) |_| r.opt = .{ .payload = @min(out.len, max_udp_payload) };
        return r.finish(id, out, .formerr);
    };
    if (opt) |o| {
        r.opt = .{ .payload = @min(out.len, max_udp_payload) };
        if (transport == .udp) r.limit = std.math.clamp(o.payload, min_udp_payload, max_udp_payload);
        if (o.version != 0) {
            r.opt.?.ext_rcode = badvers;
            return r.finish(id, out, .noerror);
        }
    }
    // A signed message is verified before it is acted upon; a failure is NOTAUTH with the TSIG
    // error in the response (unsigned for BADKEY and BADSIG, signed for BADTIME, RFC 8945 §5.2).
    r.tsig = tsig.verify(ctx.keys, query, msg, ctx.now) catch return r.finish(id, out, .formerr);
    if (r.tsig) |t| if (t.err != .none) {
        log.event(.warn, "tsig", .{ .code = @tagName(t.err), .key = zone.fmt(t.name) });
        if (qflags.opcode == 5) if (ctx.metrics) |m| m.update(ctx.keys, null, .notauth);
        return r.finish(id, out, .notauth);
    };
    // An expired record is gone before anything reads the overlay, not at the next sweep (review A12).
    if (ctx.overlay) |o| o.expire(ctx.mono);
    if (qflags.opcode == 5) {
        const key = if (r.tsig) |t| t.key.?.name else null;
        const rc = update.apply(ctx.overlay, ctx.zones, msg, key, ctx.mono);
        if (ctx.metrics) |m| m.update(ctx.keys, key, rc);
        return r.finish(id, out, rc);
    }
    // ADR 0007/0009: no zone transfers, in any mode and for any name, so before the zone lookup and forwarding.
    if (qflags.opcode == 4) return r.finish(id, out, .refused); // NOTIFY
    if (qflags.opcode != 0) return r.finish(id, out, .notimp);
    if (q.class != .in) return r.finish(id, out, .refused);
    if (q.type == .ixfr or q.type == .axfr) return r.finish(id, out, .refused);

    var lowered: [255]u8 = undefined;
    @memcpy(lowered[0..q.name.len], q.name);
    const qname = zone.lower(lowered[0..q.name.len]);
    const z = zone.find(ctx.zones, qname) orelse {
        const f = forward orelse return r.finish(id, out, .refused);
        f.* = .{ .id = id, .rd = qflags.rd, .question = q, .opt = r.opt, .limit = r.limit };
        return null;
    };
    r.flags.aa = true;
    const overlay = ctx.overlay;

    if (q.type == .any) {
        // RFC 8482: a synthetic HINFO when the name exists, whatever it holds.
        if (lookup(z, overlay, qname) == null and !dynamic(overlay, qname)) return r.negative(id, out, z, .nxdomain);
        r.answer(.{ .name = q.name, .type = .hinfo, .ttl = z.soa.ttl, .rdata = hinfo_rfc8482 });
        return r.finish(id, out, .noerror);
    }

    var owner: []const u8 = qname;
    var hops: usize = 0;
    while (true) : (hops += 1) {
        const before = r.answers.items.len;
        const static = lookup(z, overlay, owner);
        if (static) |name| if (name.get(q.type)) |set| for (set.rdatas) |rd| r.answer(.{ .name = owner, .type = set.type, .ttl = set.ttl, .rdata = rd });
        // ADR 0006: dynamic records come after the static ones, never instead of them.
        if (overlay != null and q.type == .txt) {
            for (overlay.?.records.items) |rec| if (std.mem.eql(u8, rec.name, owner)) {
                // Never cached past the local lifetime (review A12); `expire` left at least one second.
                const ttl: u32 = @intCast(@min(rec.ttl, rec.expires - ctx.mono));
                r.answer(.{ .name = owner, .type = .txt, .ttl = ttl, .rdata = rec.rdata });
            };
            // RFC 2181 §5.2: one TTL for the whole RRset, static members included (review A8).
            var ttl: u32 = std.math.maxInt(u32);
            for (r.answers.items[before..]) |rr| ttl = @min(ttl, rr.ttl);
            for (r.answers.items[before..]) |*rr| {
                rr.ttl = ttl;
            }
        }
        if (r.answers.items.len > before) return r.finish(id, out, .noerror);
        // A name with dynamic records below it exists (ADR 0004): NODATA, not NXDOMAIN.
        const name = static orelse return r.negative(id, out, z, if (dynamic(overlay, owner)) .noerror else .nxdomain);
        const cname = name.get(.cname) orelse return r.negative(id, out, z, .noerror);
        r.answer(.{ .name = owner, .type = .cname, .ttl = cname.ttl, .rdata = cname.rdatas[0] });
        owner = cname.rdatas[0];
        // The chase ends where the zone ends or where a loop could begin; the client continues.
        if (!zone.isUnder(owner, z.origin) or hops == max_cname_hops) return r.finish(id, out, .noerror);
    }
}

/// Whether the overlay makes `name` exist: a dynamic record at or below it (ADR 0004).
fn dynamic(overlay: ?*const update.Overlay, name: []const u8) bool {
    return overlay != null and overlay.?.exists(name);
}

/// `name` itself when it exists, else the RRsets of `*.<closest encloser>` when that wildcard
/// exists (RFC 4592 §3.3.1). Names the overlay makes exist are never synthesized and count as
/// enclosers, so dynamic records get no wildcard treatment either way (ADR 0006). `name` is in `z`.
fn lookup(z: *const zone.Zone, overlay: ?*const update.Overlay, name: []const u8) ?zone.Name {
    if (z.lookup(name)) |n| return n;
    if (dynamic(overlay, name)) return null;
    // The closest encloser is the first existing ancestor; the origin always exists.
    var ce = name;
    while (true) {
        ce = ce[1 + ce[0] ..];
        if (z.lookup(ce) != null or dynamic(overlay, ce)) break;
    }
    var source: [255]u8 = undefined; // `ce` lost at least a 2-byte label: `*.ce` fits
    source[0] = 1;
    source[1] = '*';
    @memcpy(source[2..][0..ce.len], ce);
    return z.lookup(source[0 .. 2 + ce.len]);
}

/// The answer to a validated upstream response, each TTL aged by `age` seconds; a null or
/// unparsable `upstream` is SERVFAIL. RA=1, AA=0 (ADR 0008).
pub fn forwarded(arena: std.mem.Allocator, f: Forward, upstream: ?[]const u8, age: u32, out: []u8) usize {
    var r: Response = .{ .flags = .{ .qr = true, .rd = f.rd, .ra = true }, .limit = f.limit, .question = f.question, .opt = f.opt, .arena = arena };
    const m = wire.Message.parse(arena, upstream orelse return r.finish(f.id, out, .servfail).?) catch return r.finish(f.id, out, .servfail).?;
    const opt = m.edns() catch return r.finish(f.id, out, .servfail).?;
    if (opt) |o| if (o.ext_rcode != 0) {
        if (r.opt) |*client| client.ext_rcode = o.ext_rcode else return r.finish(f.id, out, .servfail).?;
    };
    r.flags.tc = m.flags.tc;
    var sections: [3][]wire.RR = undefined;
    for (&sections, [_][]const wire.RR{ m.answer, m.authority, m.additional }) |*dst, src| {
        var n: usize = 0;
        dst.* = arena.alloc(wire.RR, src.len) catch return r.finish(f.id, out, .servfail).?;
        for (src) |rr| if (rr.type != .opt) { // the upstream's OPT is not the client's
            dst.*[n] = rr;
            const bound = @min(f.max_ttl, if (rr.type == .soa) @min(rr.ttl, forwarding.negativeTtl(m) orelse rr.ttl) else rr.ttl);
            dst.*[n].ttl = bound -| age;
            n += 1;
        };
        dst.* = dst.*[0..n];
    }
    r.upstream = .{ .answer = sections[0], .authority = sections[1], .additional = sections[2] };
    return r.finish(f.id, out, @enumFromInt(m.flags.rcode)).?;
}

const Response = struct {
    flags: wire.Flags,
    limit: usize,
    now: i64 = 0,
    question: ?wire.Question = null,
    opt: ?wire.Opt = null,
    tsig: ?tsig.Status = null,
    /// Every selected record, in the request arena: the writer, not the collector, decides what
    /// fits and sets TC (review A4: a fixed 64 dropped records silently, over TCP too).
    arena: std.mem.Allocator,
    answers: std.ArrayList(wire.RR) = .empty,
    oom: bool = false,
    authority: ?wire.RR = null,
    /// The sections of a forwarded answer; additional records are dropped when they do not fit.
    upstream: ?wire.Message = null,

    fn answer(r: *Response, rr: wire.RR) void {
        r.answers.append(r.arena, rr) catch {
            r.oom = true;
        };
    }

    /// NXDOMAIN or NODATA: the SOA in the authority section (RFC 2308 §2) with the negative TTL.
    fn negative(r: *Response, id: u16, out: []u8, z: *const zone.Zone, rcode: Rcode) ?usize {
        r.authority = .{ .name = z.origin, .type = .soa, .ttl = z.negativeTtl(), .rdata = z.soa.rdatas[0] };
        return r.finish(id, out, rcode);
    }

    fn finish(r: *Response, id: u16, out: []u8, rcode: Rcode) ?usize {
        if (r.oom) { // never a silently incomplete RRset
            r.answers.clearRetainingCapacity();
            r.authority = null;
        }
        r.flags.rcode = @intFromEnum(if (r.oom) .servfail else rcode);
        // The OPT and the TSIG are written last but must always fit: their bytes are reserved up front.
        const opt_len: usize = if (r.opt != null) 11 else 0;
        const tsig_len: usize = if (r.tsig) |t| t.size() else 0;
        const body = out[0 .. @min(r.limit, out.len) - opt_len - tsig_len];
        var w = wire.Writer.init(body, id, r.flags) catch unreachable; // out is a response buffer
        if (r.question) |q| w.question(q) catch {
            r.flags.tc = true;
        };
        if (!r.flags.tc) for (r.answers.items) |rr| w.rr(.answer, rr) catch {
            r.flags.tc = true;
            break;
        };
        if (!r.flags.tc) if (r.authority) |rr| w.rr(.authority, rr) catch {
            r.flags.tc = true;
        };
        if (r.upstream) |m| {
            for (m.answer) |rr| if (!r.flags.tc) w.rr(.answer, rr) catch {
                r.flags.tc = true;
            };
            for (m.authority) |rr| if (!r.flags.tc) w.rr(.authority, rr) catch {
                r.flags.tc = true;
            };
            if (!r.flags.tc) for (m.additional) |rr| w.rr(.additional, rr) catch break;
        }
        std.mem.writeInt(u16, out[2..4], @bitCast(r.flags), .big);
        if (r.opt) |o| {
            w.buf = out[0 .. body.len + opt_len];
            w.rr(.additional, o.toRR()) catch unreachable; // 11 bytes were reserved
        }
        return if (r.tsig) |t| tsig.sign(t, out, w.len, r.now) else w.len;
    }
};

// ---- tests -------------------------------------------------------------------------------------

const testing = std.testing;
const config = @import("config.zig");

pub const test_zone_head =
    \\origin = "uchi.example.org."
    \\ttl = 300
    \\serial = 1
    \\[soa]
    \\mname = "annai.uchi.example.org."
    \\rname = "hostmaster.example.org."
    \\refresh = 3600
    \\retry = 600
    \\expire = 604800
    \\minimum = 60
    \\[names."@"]
    \\ns = ["annai"]
    \\[names."annai"]
    \\a = ["10.100.0.2"]
    \\[names."hub.kekkai"]
    \\a = ["10.100.0.1"]
    \\aaaa = ["fd12:3456:789a::1"]
    \\[names."git"]
    \\cname = "vm.kekkai"
    \\[names."vm.kekkai"]
    \\a = ["10.100.0.3"]
    \\[names."out"]
    \\cname = "cv.example.org."
    \\[names."dangling"]
    \\cname = "nowhere"
    \\[names."loop"]
    \\cname = "loop"
    \\[names."*.wild"]
    \\a = ["10.100.0.9"]
    \\txt = ["wild"]
    \\[names."host.wild"]
    \\a = ["10.100.0.10"]
    \\[names."x.ent.wild"]
    \\a = ["10.100.0.11"]
    \\[names."*.alias"]
    \\cname = "vm.kekkai"
    \\[names."big"]
    \\txt = [
    \\
;
/// Eight TXT strings of 255 bytes (the first one 256, so it is split): over 2 KiB of RDATA.
pub const test_zone = test_zone_head ++ "\"" ++ "y" ** 256 ++ "\",\n" ++ ("\"" ++ "x" ** 255 ++ "\",\n") ** 7 ++ "]\n";

/// The public apex of ADR 0004: no `uchi` names, a CAA record.
pub const apex_zone =
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
    \\caa = [{ flags = 0, tag = "issue", value = "letsencrypt.org" }]
    \\mx = [{ preference = 0, exchange = "." }]
    \\[names."_imaps._tcp"]
    \\srv = [{ priority = 0, weight = 0, port = 0, target = "." }]
    \\[names."ns1"]
    \\a = ["192.0.2.53"]
    \\[names."*"]
    \\txt = ["wild"]
    \\[names."_acme-challenge.static"]
    \\txt = ["fixed"]
    \\[names."_acme-challenge.alias"]
    \\cname = "ns1"
;

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    zones: [2]zone.Zone,
    overlay: update.Overlay,
    keys: [1]tsig.Key = .{tsig.vector.key},
    /// uchi by default; `soto()` turns the keys and the overlay on.
    ctx: Context = undefined,
    out: [65535]u8 = undefined,
    buf: [65535]u8 = undefined,
    last_len: usize = 0,

    fn init() !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.arena = std.heap.ArenaAllocator.init(testing.allocator);
        f.overlay = update.Overlay.init(testing.allocator, 120, 3600);
        f.keys = .{tsig.vector.key};
        var d: config.Diag = .{};
        for (&f.zones, [_][]const u8{ test_zone, apex_zone }) |*z, text| z.* = config.loadZone(f.arena.allocator(), text, &d) catch |e| {
            std.debug.print("{s}\n", .{d.msg});
            return e;
        };
        f.ctx = .{ .zones = &f.zones };
        return f;
    }

    /// The public view (ADR 0004): the apex zone only, with the keys and the overlay.
    fn soto(f: *Fixture, now: i64) void {
        f.ctx = .{ .zones = f.zones[1..2], .keys = &f.keys, .overlay = &f.overlay, .now = now, .mono = 1000 };
    }

    fn deinit(f: *Fixture) void {
        f.overlay.deinit();
        f.arena.deinit();
        testing.allocator.destroy(f);
    }

    const Query = struct { name: []const u8, type: wire.Type = .a, class: wire.Class = .in, opt: ?wire.Opt = null, opcode: u4 = 0, transport: Transport = .udp };

    fn ask(f: *Fixture, q: Query) !wire.Message {
        var nbuf: [255]u8 = undefined;
        const m: wire.Message = .{
            .id = 0x1234,
            .flags = .{ .rd = true, .opcode = q.opcode },
            .question = &.{.{ .name = try wire.nameFromText(&nbuf, q.name), .type = q.type, .class = q.class }},
            .additional = if (q.opt) |o| &.{o.toRR()} else &.{},
        };
        const len = try m.encode(&f.buf);
        return f.reply(f.buf[0..len], q.transport);
    }

    fn reply(f: *Fixture, packet: []const u8, transport: Transport) !wire.Message {
        const n = respond(f.arena.allocator(), f.ctx, packet, &f.out, transport, null) orelse return error.NoResponse;
        f.last_len = n;
        return wire.Message.parse(f.arena.allocator(), f.out[0..n]);
    }
};

fn expectRcode(m: wire.Message, rcode: Rcode) !void {
    try testing.expectEqual(rcode, @as(Rcode, @enumFromInt(m.flags.rcode)));
    try testing.expectEqual(@as(u16, 0x1234), m.id);
    try testing.expect(m.flags.qr and m.flags.rd and !m.flags.ra);
}

test "positive answers: AA, case echoed in the question, every record of the RRset" {
    const f = try Fixture.init();
    defer f.deinit();
    const m = try f.ask(.{ .name = "HuB.Kekkai.UCHI.example.org." });
    try expectRcode(m, .noerror);
    try testing.expect(m.flags.aa and !m.flags.tc);
    try testing.expectEqualSlices(u8, "\x03HuB\x06Kekkai\x04UCHI\x07example\x03org\x00", m.question[0].name);
    try testing.expectEqual(@as(usize, 1), m.answer.len);
    try testing.expectEqualSlices(u8, "\x0a\x64\x00\x01", m.answer[0].rdata);
    try testing.expectEqual(@as(u32, 300), m.answer[0].ttl);
    try testing.expectEqual(@as(usize, 0), m.authority.len);

    const aaaa = try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .type = .aaaa });
    try testing.expectEqual(@as(usize, 16), aaaa.answer[0].rdata.len);
    const soa = try f.ask(.{ .name = "uchi.example.org.", .type = .soa });
    try testing.expectEqual(wire.Type.soa, soa.answer[0].type); // hanko finds the zone apex here
    const ns = try f.ask(.{ .name = "uchi.example.org.", .type = .ns });
    try testing.expectEqualSlices(u8, "\x05annai\x04uchi\x07example\x03org\x00", ns.answer[0].rdata);
}

test "NXDOMAIN and NODATA carry the SOA with the negative TTL; ENTs are NODATA" {
    const f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { []const u8, wire.Type, Rcode }{
        .{ "nope.uchi.example.org.", .a, .nxdomain },
        .{ "deep.nope.uchi.example.org.", .a, .nxdomain },
        .{ "hub.kekkai.uchi.example.org.", .mx, .noerror },
        .{ "kekkai.uchi.example.org.", .a, .noerror },
        .{ "git.uchi.example.org.", .cname, .noerror }, // not negative, but checks the type match
    }) |c| {
        const m = try f.ask(.{ .name = c[0], .type = c[1] });
        try expectRcode(m, c[2]);
        try testing.expect(m.flags.aa);
        if (c[1] == .cname) continue;
        try testing.expectEqual(@as(usize, 0), m.answer.len);
        try testing.expectEqual(@as(usize, 1), m.authority.len);
        try testing.expectEqual(wire.Type.soa, m.authority[0].type);
        try testing.expectEqualSlices(u8, "\x04uchi\x07example\x03org\x00", m.authority[0].name);
        try testing.expectEqual(@as(u32, 60), m.authority[0].ttl);
    }
}

test "CNAME: in-zone targets are chased, out-of-zone and dangling ones are not" {
    const f = try Fixture.init();
    defer f.deinit();
    const git = try f.ask(.{ .name = "git.uchi.example.org." });
    try expectRcode(git, .noerror);
    try testing.expectEqual(@as(usize, 2), git.answer.len);
    try testing.expectEqual(wire.Type.cname, git.answer[0].type);
    try testing.expectEqual(wire.Type.a, git.answer[1].type);
    try testing.expectEqualSlices(u8, "\x02vm\x06kekkai\x04uchi\x07example\x03org\x00", git.answer[1].name);

    const out = try f.ask(.{ .name = "out.uchi.example.org." });
    try expectRcode(out, .noerror);
    try testing.expectEqual(@as(usize, 1), out.answer.len);

    const dangling = try f.ask(.{ .name = "dangling.uchi.example.org." });
    try expectRcode(dangling, .nxdomain);
    try testing.expectEqual(@as(usize, 1), dangling.answer.len);
    try testing.expectEqual(@as(usize, 1), dangling.authority.len);

    const loop = try f.ask(.{ .name = "loop.uchi.example.org." });
    try expectRcode(loop, .noerror);
    try testing.expectEqual(@as(usize, max_cname_hops + 1), loop.answer.len);
}

test "wildcards (RFC 4592): synthesis, closest encloser, no match for existing names or ENTs, CNAME, NODATA" {
    const f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { []const u8, []const u8 }{
        .{ "anything.wild.uchi.example.org.", "\x0a\x64\x00\x09" },
        .{ "a.b.wild.uchi.example.org.", "\x0a\x64\x00\x09" }, // several labels
        .{ "*.wild.uchi.example.org.", "\x0a\x64\x00\x09" }, // the wildcard owner itself
        .{ "host.wild.uchi.example.org.", "\x0a\x64\x00\x0a" }, // an existing name is never synthesized
    }) |c| {
        const m = try f.ask(.{ .name = c[0] });
        try expectRcode(m, .noerror);
        try testing.expect(m.flags.aa and m.answer.len == 1 and m.authority.len == 0);
        try testing.expectEqualSlices(u8, c[1], m.answer[0].rdata);
        var nbuf: [255]u8 = undefined;
        try testing.expectEqualSlices(u8, try wire.nameFromText(&nbuf, c[0]), m.answer[0].name); // the owner is the query name
    }
    for ([_]struct { []const u8, wire.Type, Rcode }{
        .{ "sub.host.wild.uchi.example.org.", .a, .nxdomain }, // closest encloser host.wild has no wildcard
        .{ "ent.wild.uchi.example.org.", .a, .noerror }, // empty non-terminal: NODATA, no synthesis
        .{ "ghost.*.wild.uchi.example.org.", .a, .nxdomain }, // RFC 4592 §2.2.1
        .{ "anything.wild.uchi.example.org.", .mx, .noerror }, // NODATA for a type the wildcard lacks
        .{ "nope.uchi.example.org.", .a, .nxdomain }, // no wildcard at the apex
    }) |c| {
        const m = try f.ask(.{ .name = c[0], .type = c[1] });
        try expectRcode(m, c[2]);
        try testing.expect(m.answer.len == 0 and m.authority.len == 1 and m.authority[0].type == .soa);
    }
    const cname = try f.ask(.{ .name = "foo.alias.uchi.example.org." });
    try expectRcode(cname, .noerror);
    try testing.expectEqual(@as(usize, 2), cname.answer.len);
    try testing.expectEqual(wire.Type.cname, cname.answer[0].type);
    try testing.expectEqualSlices(u8, "\x03foo\x05alias\x04uchi\x07example\x03org\x00", cname.answer[0].name);
    try testing.expectEqualSlices(u8, "\x0a\x64\x00\x03", cname.answer[1].rdata);
    try testing.expectEqual(wire.Type.hinfo, (try f.ask(.{ .name = "anything.wild.uchi.example.org.", .type = .any })).answer[0].type);
    try expectRcode(try f.ask(.{ .name = "sub.host.wild.uchi.example.org.", .type = .any }), .nxdomain);
}

test "REFUSED outside the zones, NOTIMP for other opcodes, ANY is HINFO" {
    const f = try Fixture.init();
    defer f.deinit();
    const refused = try f.ask(.{ .name = "example.net." });
    try expectRcode(refused, .refused);
    try testing.expect(!refused.flags.aa);
    try expectRcode(try f.ask(.{ .name = "notuchi.example.net." }), .refused);
    try expectRcode(try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .class = .any }), .refused);
    const notimp = try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .opcode = 6 });
    try expectRcode(notimp, .notimp);
    try testing.expectEqual(@as(u4, 6), notimp.flags.opcode);
    // ADR 0006: uchi answers REFUSED to any UPDATE.
    const upd = try f.ask(.{ .name = "uchi.example.org.", .type = .soa, .opcode = 5 });
    try expectRcode(upd, .refused);
    try testing.expectEqual(@as(u4, 5), upd.flags.opcode);
    const caa = try f.ask(.{ .name = "example.org.", .type = .caa });
    try testing.expectEqualSlices(u8, "\x00\x05issueletsencrypt.org", caa.answer[0].rdata);
    const any = try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .type = .any });
    try expectRcode(any, .noerror);
    try testing.expectEqual(wire.Type.hinfo, any.answer[0].type);
    try testing.expectEqualSlices(u8, hinfo_rfc8482, any.answer[0].rdata);
    try expectRcode(try f.ask(.{ .name = "nope.uchi.example.org.", .type = .any }), .nxdomain);
}

test "null MX (RFC 7505) and SRV target \".\" (RFC 2782): the root is served as one zero byte" {
    const f = try Fixture.init();
    defer f.deinit();
    const mx = try f.ask(.{ .name = "example.org.", .type = .mx });
    try expectRcode(mx, .noerror);
    try testing.expectEqual(@as(usize, 1), mx.answer.len);
    try testing.expectEqualSlices(u8, "\x00\x00\x00", mx.answer[0].rdata);
    try testing.expectEqual(@as(usize, 0), mx.additional.len); // nothing chased for "."
    try testing.expectEqualSlices(u8, "\x00\x0f\x00\x01\x00\x00\x01\x2c\x00\x03\x00\x00\x00", f.out[f.last_len - 13 .. f.last_len]);
    const srv = try f.ask(.{ .name = "_imaps._tcp.example.org.", .type = .srv });
    try expectRcode(srv, .noerror);
    try testing.expectEqualSlices(u8, "\x00" ** 7, srv.answer[0].rdata);
}

test "EDNS: payload clamped to [512, 1232] over UDP, OPT echoed, BADVERS, TC when too big" {
    const f = try Fixture.init();
    defer f.deinit();
    const big = "big.uchi.example.org.";
    const plain = try f.ask(.{ .name = big, .type = .txt });
    try testing.expect(plain.flags.tc);
    try testing.expect(f.last_len <= 512);
    try testing.expectEqual(@as(usize, 0), plain.additional.len);

    const small = try f.ask(.{ .name = big, .type = .txt, .opt = .{ .payload = 400 } });
    try testing.expect(small.flags.tc and f.last_len <= 512);
    try testing.expectEqual(@as(u16, 1232), (try small.edns()).?.payload);

    const large = try f.ask(.{ .name = big, .type = .txt, .opt = .{ .payload = 65535 } });
    try testing.expect(large.flags.tc and f.last_len <= 1232 and f.last_len > 512);
    try testing.expectEqual(@as(usize, 1), large.additional.len); // the OPT survives truncation

    const tcp = try f.ask(.{ .name = big, .type = .txt, .opt = .{ .payload = 65535 }, .transport = .tcp });
    try testing.expect(!tcp.flags.tc and f.last_len > 1232);
    try testing.expectEqual(@as(usize, 8), tcp.answer.len);

    const bad = try f.ask(.{ .name = big, .type = .txt, .opt = .{ .payload = 1232, .version = 1 } });
    try testing.expectEqual(@as(u8, badvers), (try bad.edns()).?.ext_rcode);
    try testing.expectEqual(@as(usize, 0), bad.answer.len);
}

test "FORMERR for malformed packets and wrong question counts; no reply to replies or runts" {
    const f = try Fixture.init();
    defer f.deinit();
    const formerr = try f.reply("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03bad", .udp);
    try expectRcode(formerr, .formerr);
    try testing.expectEqual(@as(usize, 0), formerr.question.len);
    try expectRcode(try f.reply("\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", .udp), .formerr);
    var opt = (wire.Opt{ .payload = 1232 }).toRR();
    const two: wire.Message = .{ .id = 0x1234, .flags = .{ .rd = true }, .question = &.{.{ .name = "\x00", .type = .a }}, .additional = &.{ opt, opt } };
    try expectRcode(try f.reply(f.buf[0..try two.encode(&f.buf)], .udp), .formerr);
    opt.name = "\x01a\x00";
    const owned: wire.Message = .{ .id = 0x1234, .flags = .{ .rd = true }, .question = &.{.{ .name = "\x00", .type = .a }}, .additional = &.{opt} };
    try expectRcode(try f.reply(f.buf[0..try owned.encode(&f.buf)], .udp), .formerr);
    try testing.expectError(error.NoResponse, f.reply("\x12\x34\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00", .udp));
    try testing.expectError(error.NoResponse, f.reply("\x12\x34\x01", .udp));
}

test "zone transfers are REFUSED (ADR 0007): AXFR and IXFR over UDP and TCP, NOTIFY, every mode and name" {
    const f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{ "uchi.example.org.", "hub.kekkai.uchi.example.org.", "nope.uchi.example.org.", "example.net." }) |name| {
        for ([_]u16{ 251, 252 }) |t| for ([_]Transport{ .udp, .tcp }) |transport| {
            for ([_]bool{ false, true }) |soto| {
                if (soto) f.soto(0) else f.ctx = .{ .zones = &f.zones };
                const m = try f.ask(.{ .name = name, .type = @enumFromInt(t), .transport = transport });
                try expectRcode(m, .refused);
                try testing.expect(!m.flags.aa and m.question.len == 1 and m.answer.len == 0 and m.authority.len == 0);
                try testing.expectEqual(@as(u16, t), @intFromEnum(m.question[0].type));
            }
            // uchi with forwarding on: refused, never handed to the upstream.
            f.ctx = .{ .zones = &f.zones };
            var nbuf: [255]u8 = undefined;
            const q: wire.Message = .{ .id = 0x1234, .flags = .{ .rd = true }, .question = &.{.{ .name = try wire.nameFromText(&nbuf, name), .type = @enumFromInt(t) }} };
            var fwd: ?Forward = null;
            const n = respond(f.arena.allocator(), f.ctx, f.buf[0..try q.encode(&f.buf)], &f.out, transport, &fwd).?;
            try testing.expect(fwd == null);
            try testing.expectEqual(Rcode.refused, @as(Rcode, @enumFromInt((try wire.Message.parse(f.arena.allocator(), f.out[0..n])).flags.rcode)));
        };
        const notify = try f.ask(.{ .name = name, .type = .soa, .opcode = 4 });
        try expectRcode(notify, .refused);
        try testing.expect(notify.flags.opcode == 4 and notify.answer.len == 0 and notify.authority.len == 0);
    }
}

test "forwarding: names outside the zones are handed over, answers get RA, the TTL and TC" {
    const f = try Fixture.init();
    defer f.deinit();
    const a = f.arena.allocator();
    var nbuf: [255]u8 = undefined;
    const query: wire.Message = .{ .id = 0x1234, .flags = .{ .rd = true }, .question = &.{.{ .name = try wire.nameFromText(&nbuf, "WwW.example.NET."), .type = .txt }}, .additional = &.{(wire.Opt{ .payload = 4096 }).toRR()} };
    var fwd: ?Forward = null;
    try testing.expectEqual(@as(?usize, null), respond(a, f.ctx, f.buf[0..try query.encode(&f.buf)], &f.out, .udp, &fwd));
    const q = fwd.?;
    try testing.expect(q.rd and q.limit == max_udp_payload and q.opt != null);
    // A local name is still answered, with forwarding enabled.
    fwd = null;
    const local: wire.Message = .{ .id = 1, .question = &.{.{ .name = "\x03hub\x06kekkai\x04uchi\x07example\x03org\x00", .type = .a }} };
    const n = respond(a, f.ctx, f.buf[0..try local.encode(&f.buf)], &f.out, .udp, &fwd).?;
    const answered = try wire.Message.parse(a, f.out[0..n]);
    try testing.expect(fwd == null and answered.flags.aa and answered.flags.ra and answered.answer.len == 1);

    // The upstream answer, lowercase, with its own OPT and a long TXT RRset.
    var up: [65535]u8 = undefined;
    const name = "\x03www\x07example\x03net\x00";
    const txt = "\xff" ++ "x" ** 255;
    const upstream: wire.Message = .{
        .id = 0x9999,
        .flags = .{ .qr = true, .rd = true, .ra = true, .aa = true },
        .question = &.{.{ .name = name, .type = .txt }},
        .answer = &(.{wire.RR{ .name = name, .type = .txt, .ttl = 300, .rdata = txt }} ** 8),
        .additional = &.{(wire.Opt{ .payload = 512 }).toRR()},
    };
    const packet = up[0..try upstream.encode(&up)];

    var tcp = q;
    tcp.limit = f.out.len;
    const full = try wire.Message.parse(a, f.out[0..forwarded(a, tcp, packet, 42, &f.out)]);
    try expectForwarded(full, .noerror);
    try testing.expect(!full.flags.aa and !full.flags.tc);
    try testing.expectEqualSlices(u8, "\x03WwW\x07example\x03NET\x00", full.question[0].name);
    try testing.expectEqual(@as(usize, 8), full.answer.len);
    for (full.answer) |rr| try testing.expectEqual(@as(u32, 258), rr.ttl);
    try testing.expectEqual(@as(u16, max_udp_payload), (try full.edns()).?.payload);

    const udp = try wire.Message.parse(a, f.out[0..forwarded(a, q, packet, 42, &f.out)]);
    try testing.expect(udp.flags.tc and udp.answer.len < 8);
    try expectForwarded(try wire.Message.parse(a, f.out[0..forwarded(a, q, null, 0, &f.out)]), .servfail);
    try expectForwarded(try wire.Message.parse(a, f.out[0..forwarded(a, q, "junk", 0, &f.out)]), .servfail);
}

fn expectForwarded(m: wire.Message, rcode: Rcode) !void {
    try testing.expectEqual(rcode, @as(Rcode, @enumFromInt(m.flags.rcode)));
    try testing.expectEqual(@as(u16, 0x1234), m.id);
    try testing.expect(m.flags.qr and m.flags.rd and m.flags.ra and !m.flags.aa);
}

test "soto: BIND's signed UPDATE is applied and answered signed; the overlay is served after the static data" {
    const f = try Fixture.init();
    defer f.deinit();
    f.soto(tsig.vector.time);
    var pbuf: [256]u8 = undefined;
    const pkt = tsig.vector.packet(&pbuf);
    const ack = try f.reply(pkt, .udp);
    try testing.expectEqual(Rcode.noerror, @as(Rcode, @enumFromInt(ack.flags.rcode)));
    try testing.expect(ack.flags.qr and ack.flags.opcode == 5 and !ack.flags.ra and ack.id == 0x6cb3);
    try testing.expectEqual(wire.Type.soa, ack.question[0].type);
    try testing.expectEqual(wire.Type.tsig, ack.additional[0].type);
    try testing.expect(ack.tsig_at != null);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, tsig.vector.response_mac);
    try testing.expectEqualSlices(u8, &want, f.out[f.last_len - 38 .. f.last_len - 6]);
    try testing.expectEqual(@as(usize, 1), f.overlay.records.items.len);

    const challenge = "_ACME-challenge.git.uchi.example.org.";
    const txt = try f.ask(.{ .name = challenge, .type = .txt });
    try expectRcode(txt, .noerror);
    try testing.expect(txt.flags.aa and txt.additional.len == 0); // an unsigned query gets an unsigned answer
    try testing.expectEqual(@as(usize, 1), txt.answer.len);
    try testing.expectEqualSlices(u8, "\x04tok1", txt.answer[0].rdata);
    try testing.expectEqual(@as(u32, 60), txt.answer[0].ttl);
    // The names above the challenge exist in the public view (ADR 0004): NODATA, not NXDOMAIN.
    for ([_][]const u8{ "git.uchi.example.org.", "uchi.example.org." }) |name| {
        const m = try f.ask(.{ .name = name });
        try expectRcode(m, .noerror);
        try testing.expect(m.answer.len == 0 and m.authority.len == 1 and m.authority[0].type == .soa);
    }
    // The overlay's names count as enclosers: `uchi.example.org` has no wildcard, so no synthesis from `*.example.org`.
    try expectRcode(try f.ask(.{ .name = "vm.uchi.example.org." }), .nxdomain);
    try expectRcode(try f.ask(.{ .name = challenge, .type = .a }), .noerror);
    // A challenge name without dynamic records is an ordinary name: the static wildcard applies;
    // one with dynamic records exists, so only those are served (no wildcard, no mixing).
    const other = try f.ask(.{ .name = "_acme-challenge.other.example.org.", .type = .txt });
    try testing.expect(other.answer.len == 1 and std.mem.eql(u8, other.answer[0].rdata, "\x04wild"));
    try testing.expectEqualSlices(u8, "\x04tok1", (try f.ask(.{ .name = challenge, .type = .txt })).answer[0].rdata);
    try testing.expectEqual(wire.Type.hinfo, (try f.ask(.{ .name = challenge, .type = .any })).answer[0].type);
    // Replayed outside the fudge: BADTIME, signed, nothing applied; a bad key: unsigned NOTAUTH.
    f.soto(tsig.vector.time + 301);
    const late = try f.reply(pkt, .udp);
    try testing.expectEqual(Rcode.notauth, @as(Rcode, @enumFromInt(late.flags.rcode)));
    try testing.expectEqual(@as(usize, 1), late.additional.len);
    try testing.expectEqual(@as(u16, 18), std.mem.readInt(u16, f.out[f.last_len - 10 ..][0..2], .big));
    f.keys[0].secret = "wrong";
    f.soto(tsig.vector.time);
    const badsig = try f.reply(pkt, .udp);
    try testing.expectEqual(Rcode.notauth, @as(Rcode, @enumFromInt(badsig.flags.rcode)));
    try testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, f.out[f.last_len - 4 ..][0..2], .big));
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, f.out[f.last_len - 8 ..][0..2], .big)); // MAC size: unsigned
    f.keys[0].secret = tsig.vector.secret;
    // Unsigned UPDATE: REFUSED without touching the overlay; the signed request's zone is echoed either way.
    var unsigned: [256]u8 = undefined;
    @memcpy(unsigned[0 .. pkt.len - 78], pkt[0 .. pkt.len - 78]);
    unsigned[11] = 0; // ARCOUNT
    const bare = try f.reply(unsigned[0 .. pkt.len - 78], .udp);
    try testing.expectEqual(Rcode.refused, @as(Rcode, @enumFromInt(bare.flags.rcode)));
    try testing.expectEqual(@as(usize, 1), f.overlay.records.items.len);
    try testing.expectEqual(@as(usize, 0), bare.additional.len);
}

test "a question count other than one is FORMERR before anything is decoded (review A1)" {
    const f = try Fixture.init();
    defer f.deinit();
    const chain = wire.pointerChain(&f.buf, 10914, 4); // the review's 65,501-byte packet
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const n = respond(failing.allocator(), f.ctx, chain, &f.out, .tcp, null).?;
    const m = try wire.Message.parse(f.arena.allocator(), f.out[0..n]);
    try testing.expectEqual(Rcode.formerr, @as(Rcode, @enumFromInt(m.flags.rcode)));
    try testing.expectEqual(@as(usize, 0), failing.allocations);
}

test "malformed EDNS options return FORMERR with the question and a minimal OPT (review R3)" {
    const f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{ "\x00\x01\x00", "\x00\x01\x00\x02x" }) |options| {
        for ([_]Transport{ .udp, .tcp }) |transport| {
            const m = try f.ask(.{ .name = "HuB.Kekkai.UCHI.example.org.", .opt = .{ .payload = 4096, .options = options }, .transport = transport });
            try expectRcode(m, .formerr);
            try testing.expectEqual(@as(usize, 1), m.question.len);
            try testing.expectEqualSlices(u8, "\x03HuB\x06Kekkai\x04UCHI\x07example\x03org\x00", m.question[0].name);
            try testing.expectEqual(wire.Type.a, m.question[0].type);
            try testing.expectEqual(@as(usize, 1), m.additional.len);
            const opt = (try m.edns()).?;
            try testing.expectEqual(@as(u16, max_udp_payload), opt.payload);
            try testing.expectEqual(@as(usize, 0), opt.options.len);
            try testing.expect(opt.version == 0 and opt.ext_rcode == 0 and !opt.do);
        }
    }
}

test "early question-count FORMERR echoes a valid OPT without allocation (review B2)" {
    const f = try Fixture.init();
    defer f.deinit();
    const q: wire.Question = .{ .name = "\x00", .type = .a };
    for ([_][]const wire.Question{ &.{}, &.{ q, q } }) |questions| {
        const request: wire.Message = .{ .id = 0x1234, .question = questions, .additional = &.{(wire.Opt{ .payload = 4096 }).toRR()} };
        const len = try request.encode(&f.buf);
        if (questions.len == 0) try testing.expectEqual(@as(usize, 23), len);
        var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
        const n = respond(failing.allocator(), f.ctx, f.buf[0..len], &f.out, .udp, null).?;
        const m = try wire.Message.parse(f.arena.allocator(), f.out[0..n]);
        try testing.expectEqual(Rcode.formerr, @as(Rcode, @enumFromInt(m.flags.rcode)));
        try testing.expectEqual(@as(u16, 0x1234), m.id);
        try testing.expectEqual(@as(usize, 0), m.question.len);
        try testing.expectEqual(@as(u16, max_udp_payload), (try m.edns()).?.payload);
        try testing.expectEqual(@as(usize, 0), failing.allocations);
    }
}

test "every record of a 65-value RRset is served over TCP and EDNS, or TC is set (review A4)" {
    const f = try Fixture.init();
    defer f.deinit();
    f.soto(0);
    const owner = "\x0f_acme-challenge\x07example\x03org\x00";
    for (0..65) |i| {
        var v: [3]u8 = .{ 2, 'a' + @as(u8, @intCast(i / 26)), 'a' + @as(u8, @intCast(i % 26)) };
        try f.overlay.records.append(f.overlay.gpa, .{ .name = try f.overlay.gpa.dupe(u8, owner), .rdata = try f.overlay.gpa.dupe(u8, &v), .ttl = 60, .expires = 1 << 40 });
    }
    const name = "_acme-challenge.example.org.";
    const tcp = try f.ask(.{ .name = name, .type = .txt, .transport = .tcp });
    try testing.expect(!tcp.flags.tc);
    try testing.expectEqual(@as(usize, 65), tcp.answer.len);
    const edns = try f.ask(.{ .name = name, .type = .txt, .opt = .{ .payload = 1232 } });
    try testing.expect(edns.answer.len == 65 or edns.flags.tc);
    try testing.expectEqual(@as(usize, 65), edns.answer.len); // 65 short values fit in 1232 bytes
    const plain = try f.ask(.{ .name = name, .type = .txt });
    try testing.expect(plain.flags.tc and plain.answer.len < 65);
}

test "one TTL per TXT RRset, never beyond the overlay lifetime (review A8, A12)" {
    const f = try Fixture.init();
    defer f.deinit();
    f.soto(0); // monotonic 1000
    const gpa = f.overlay.gpa;
    for ([_]struct { []const u8, []const u8, u32, i64 }{
        .{ "\x0f_acme-challenge\x03git\x07example\x03org\x00", "\x011", 30, 5000 },
        .{ "\x0f_acme-challenge\x03git\x07example\x03org\x00", "\x012", 60, 5000 },
        .{ "\x0f_acme-challenge\x06static\x07example\x03org\x00", "\x013", 120, 1000 + 90 },
        .{ "\x0f_acme-challenge\x04gone\x07example\x03org\x00", "\x014", 120, 1000 },
    }) |e| try f.overlay.records.append(gpa, .{ .name = try gpa.dupe(u8, e[0]), .rdata = try gpa.dupe(u8, e[1]), .ttl = e[2], .expires = e[3] });
    const git = try f.ask(.{ .name = "_acme-challenge.git.example.org.", .type = .txt });
    try testing.expectEqual(@as(usize, 2), git.answer.len);
    for (git.answer) |rr| try testing.expectEqual(@as(u32, 30), rr.ttl);
    // The static value (zone TTL 300) and the dynamic one (TTL 120, 90 s left) share 90.
    const static = try f.ask(.{ .name = "_acme-challenge.static.example.org.", .type = .txt });
    try testing.expectEqual(@as(usize, 2), static.answer.len);
    for (static.answer) |rr| try testing.expectEqual(@as(u32, 90), rr.ttl);
    // Expired at this very second: not served even though the sweep has not run.
    const gone = try f.ask(.{ .name = "_acme-challenge.gone.example.org.", .type = .txt });
    try testing.expect(gone.answer.len == 1 and std.mem.eql(u8, gone.answer[0].rdata, "\x04wild"));
    try testing.expectEqual(@as(usize, 3), f.overlay.records.items.len);
}

test "static TXT TTL 30 caps a dynamic member with TTL 120 (review A8)" {
    const f = try Fixture.init();
    defer f.deinit();
    var d: config.Diag = .{};
    const text = try std.mem.replaceOwned(u8, f.arena.allocator(), apex_zone, "ttl = 300", "ttl = 30");
    f.zones[1] = try config.loadZone(f.arena.allocator(), text, &d);
    f.soto(0);
    const gpa = f.overlay.gpa;
    try f.overlay.records.append(gpa, .{
        .name = try gpa.dupe(u8, "\x0f_acme-challenge\x06static\x07example\x03org\x00"),
        .rdata = try gpa.dupe(u8, "\x07dynamic"),
        .ttl = 120,
        .expires = 5000,
    });
    const m = try f.ask(.{ .name = "_acme-challenge.static.example.org.", .type = .txt });
    try expectRcode(m, .noerror);
    try testing.expectEqual(@as(usize, 2), m.answer.len);
    for (m.answer) |rr| try testing.expectEqual(@as(u32, 30), rr.ttl);
}

test "an UPDATE signed with a truncated MAC is applied and answered signed (review A7)" {
    const f = try Fixture.init();
    defer f.deinit();
    f.soto(tsig.vector.time);
    var vbuf: [256]u8 = undefined;
    const pkt = tsig.vector.packet(&vbuf);
    for ([_]usize{ 15, 16 }) |size| {
        @memcpy(f.buf[0 .. pkt.len - 78], pkt[0 .. pkt.len - 78]);
        f.buf[11] = 0;
        const len = tsig.signRequest(tsig.vector.key, &f.buf, pkt.len - 78, tsig.vector.time, size);
        const ack = try f.reply(f.buf[0..len], .udp);
        if (size == 15) {
            try testing.expectEqual(Rcode.formerr, @as(Rcode, @enumFromInt(ack.flags.rcode)));
            try testing.expectEqual(@as(usize, 0), f.overlay.records.items.len);
            continue;
        }
        try testing.expectEqual(Rcode.noerror, @as(Rcode, @enumFromInt(ack.flags.rcode)));
        try testing.expect(ack.tsig_at != null and f.overlay.records.items.len == 1);
        var want: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, tsig.vector.truncated_response_mac);
        try testing.expectEqualSlices(u8, &want, f.out[f.last_len - 38 .. f.last_len - 6]);
    }
}

test "review A5: forwarding ages each record without extending its TTL" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const name = "\x03www\x07example\x03net\x00";
    const q: wire.Question = .{ .name = name, .type = .a };
    const f: Forward = .{ .id = 7, .rd = true, .question = q, .opt = .{ .payload = 1232 }, .limit = 1232 };
    var up: [1232]u8 = undefined;
    var out: [1232]u8 = undefined;
    const m: wire.Message = .{ .flags = .{ .qr = true }, .question = &.{q}, .answer = &.{
        .{ .name = name, .type = .a, .ttl = 300, .rdata = "1234" },
        .{ .name = name, .type = .a, .ttl = 10, .rdata = "5678" },
    }, .additional = &.{.{ .name = name, .type = .a, .ttl = 5, .rdata = "abcd" }} };
    const n = try m.encode(&up);
    for ([_]u32{ 0, 3 }) |age| {
        const aged = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..n], age, &out)]);
        try testing.expectEqual(300 - age, aged.answer[0].ttl);
        try testing.expectEqual(10 - age, aged.answer[1].ttl);
        try testing.expectEqual(5 - age, aged.additional[0].ttl);
    }
    for ([_]u4{ 0, 3 }) |rcode| {
        const negative: wire.Message = .{ .flags = .{ .qr = true, .rcode = rcode }, .question = &.{q}, .answer = &.{.{ .name = name, .type = .cname, .ttl = 300, .rdata = "\x01x\x00" }}, .authority = &.{.{ .name = "\x00", .type = .soa, .ttl = 3600, .rdata = "\x00\x00" ++ "\x00" ** 19 ++ "\x1e" }} };
        const len = try negative.encode(&up);
        const aged = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..len], 3, &out)]);
        try testing.expectEqual(@as(u32, 297), aged.answer[0].ttl);
        try testing.expectEqual(@as(u32, 27), aged.authority[0].ttl);
    }
}

test "forwarded TTLs are capped by max_ttl, then aged" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const name = "\x03www\x07example\x03net\x00";
    const q: wire.Question = .{ .name = name, .type = .a };
    const f: Forward = .{ .id = 7, .rd = true, .question = q, .opt = null, .limit = 512, .max_ttl = 120 };
    var up: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const m: wire.Message = .{ .flags = .{ .qr = true, .rcode = 3 }, .question = &.{q}, .answer = &.{
        .{ .name = name, .type = .a, .ttl = 300, .rdata = "1234" },
        .{ .name = name, .type = .a, .ttl = 10, .rdata = "5678" },
    }, .authority = &.{.{ .name = "\x00", .type = .soa, .ttl = 3600, .rdata = "\x00\x00" ++ "\x00" ** 18 ++ "\x0e\x10" }} };
    const n = try m.encode(&up);
    const reply = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..n], 3, &out)]);
    try testing.expectEqual(@as(u32, 117), reply.answer[0].ttl);
    try testing.expectEqual(@as(u32, 7), reply.answer[1].ttl);
    try testing.expectEqual(@as(u32, 117), reply.authority[0].ttl);
}

test "review A6: a forwarded truncated answer retains TC and cannot be cached" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const f: Forward = .{ .id = 7, .rd = true, .question = .{ .name = "\x00", .type = .a }, .opt = null, .limit = 512 };
    const m: wire.Message = .{ .flags = .{ .qr = true, .tc = true }, .answer = &.{.{ .name = "\x00", .type = .a, .ttl = 60, .rdata = "1234" }} };
    var up: [512]u8 = undefined;
    var out: [512]u8 = undefined;
    const n = try m.encode(&up);
    const reply = try wire.Message.parse(arena.allocator(), out[0..forwarded(arena.allocator(), f, up[0..n], 0, &out)]);
    try testing.expect(reply.flags.tc);
    try testing.expectEqual(@as(?u32, null), forwarding.lifetime(m, 86400));
}

test "review A18: upstream BADVERS remains an extended error or explicit failure" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f: Forward = .{ .id = 7, .rd = true, .question = .{ .name = "\x00", .type = .a }, .opt = .{ .payload = 1232 }, .limit = 1232 };
    var up: [1232]u8 = undefined;
    var out: [1232]u8 = undefined;
    for ([_]struct { ext: u8, low: u4 }{ .{ .ext = 1, .low = 0 }, .{ .ext = 15, .low = 7 }, .{ .ext = 255, .low = 15 } }) |code| {
        const m: wire.Message = .{ .flags = .{ .qr = true, .rcode = code.low }, .additional = &.{(wire.Opt{ .payload = 1232, .ext_rcode = code.ext }).toRR()} };
        const n = try m.encode(&up);
        const bad = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..n], 0, &out)]);
        try testing.expectEqual(code.ext, (try bad.edns()).?.ext_rcode);
        try testing.expectEqual(code.low, bad.flags.rcode);
        try testing.expectEqual(@as(?u32, null), forwarding.lifetime(m, 86400));
    }
    const m: wire.Message = .{ .flags = .{ .qr = true }, .additional = &.{(wire.Opt{ .payload = 1232, .ext_rcode = 1 }).toRR()} };
    const n = try m.encode(&up);
    f.opt = null;
    const failed = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..n], 0, &out)]);
    try testing.expectEqual(@as(u4, 2), failed.flags.rcode);
}

test "review A10: malformed EDNS placement and option framing get FORMERR" {
    const f = try Fixture.init();
    defer f.deinit();
    const opt = (wire.Opt{ .payload = 1232 }).toRR();
    const q: wire.Question = .{ .name = "\x04uchi\x07example\x03org\x00", .type = .a };
    for ([_]wire.Message{
        .{ .question = &.{q}, .answer = &.{opt} },
        .{ .question = &.{q}, .authority = &.{opt}, .additional = &.{opt} },
        .{ .question = &.{q}, .additional = &.{ opt, opt } },
        .{ .question = &.{q}, .additional = &.{(wire.Opt{ .payload = 1232, .options = "\x00\x01\x00" }).toRR()} },
        .{ .question = &.{q}, .additional = &.{(wire.Opt{ .payload = 1232, .options = "\x00\x01\x00\x02\xff" }).toRR()} },
    }) |m| {
        var buf: [512]u8 = undefined;
        var query = m;
        query.id = 0x1234;
        query.flags.rd = true;
        const n = try query.encode(&buf);
        try expectRcode(try f.reply(buf[0..n], .udp), .formerr);
    }
    const valid: wire.Message = .{ .id = 0x1234, .flags = .{ .rd = true }, .question = &.{q}, .additional = &.{(wire.Opt{ .payload = 1232, .options = "\xff\xff\x00\x01x\x00\x01\x00\x00" }).toRR()} };
    var buf: [512]u8 = undefined;
    const n = try valid.encode(&buf);
    try expectRcode(try f.reply(buf[0..n], .udp), .noerror);
}

test "review A11: legacy compressed RDATA survives a changed question dictionary" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const name = "\x03www\x07example\x03net\x00";
    const target = "\x02ns\x07example\x03net\x00";
    const f: Forward = .{ .id = 7, .rd = true, .question = .{ .name = "\x03WWW\x07EXAMPLE\x03NET\x00", .type = .ns }, .opt = null, .limit = 65535 };
    var up: [65535]u8 = undefined;
    var out: [65535]u8 = undefined;
    for ([_]struct { t: u16, prefix: []const u8 = "", names: usize = 1, tail: []const u8 = "" }{
        .{ .t = 3 }, // MD
        .{ .t = 4 }, // MF
        .{ .t = 7 }, // MB
        .{ .t = 8 }, // MG
        .{ .t = 9 }, // MR
        .{ .t = 14, .names = 2 }, // MINFO
        .{ .t = 17, .names = 2 }, // RP
        .{ .t = 18, .prefix = "\x00\x01" }, // AFSDB
        .{ .t = 21, .prefix = "\x00\x01" }, // RT
        .{ .t = 24, .prefix = "\x00" ** 18, .tail = "signature" }, // SIG
        .{ .t = 26, .prefix = "\x00\x01", .names = 2 }, // PX
        .{ .t = 30, .tail = "bitmap" }, // NXT
        .{ .t = 35, .prefix = "\x00\x01\x00\x02\x01s\x00\x03abc" }, // NAPTR
    }) |case| {
        var w = try wire.Writer.init(&up, 99, .{ .qr = true });
        try w.question(.{ .name = name, .type = .ns });
        const ns_at = w.len;
        try w.rr(.answer, .{ .name = name, .type = .ns, .ttl = 300, .rdata = target });
        // The NS RDATA begins after the two-byte owner and ten-byte fixed RR header.
        const pointer: u16 = 0xc000 | @as(u16, @intCast(ns_at + 12));
        var raw: [256]u8 = undefined;
        var expected: [600]u8 = undefined;
        @memcpy(raw[0..case.prefix.len], case.prefix);
        @memcpy(expected[0..case.prefix.len], case.prefix);
        var len = case.prefix.len;
        var expanded = case.prefix.len;
        for (0..case.names) |_| {
            std.mem.writeInt(u16, raw[len..][0..2], pointer, .big);
            len += 2;
            @memcpy(expected[expanded..][0..target.len], target);
            expanded += target.len;
        }
        @memcpy(raw[len..][0..case.tail.len], case.tail);
        @memcpy(expected[expanded..][0..case.tail.len], case.tail);
        const at = w.len;
        try w.rr(.answer, .{ .name = "\x00", .type = @enumFromInt(65000), .ttl = 60, .rdata = raw[0 .. len + case.tail.len] });
        std.mem.writeInt(u16, up[at + 1 ..][0..2], case.t, .big);
        const reply = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..w.len], 0, &out)]);
        try testing.expectEqual(@as(usize, 2), reply.answer.len);
        try testing.expectEqualSlices(u8, expected[0 .. expanded + case.tail.len], reply.answer[1].rdata);
    }
    const unknown: wire.Message = .{ .flags = .{ .qr = true }, .answer = &.{.{ .name = name, .type = @enumFromInt(65000), .ttl = 60, .rdata = "\xc0\x29" }} };
    const n = try unknown.encode(&up);
    const reply = try wire.Message.parse(a, out[0..forwarded(a, f, up[0..n], 0, &out)]);
    try testing.expectEqualSlices(u8, "\xc0\x29", reply.answer[0].rdata);
}
