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
    };
    const msg = wire.Message.parse(arena, query) catch |e| switch (e) {
        error.Malformed => return r.finish(id, out, .formerr),
        error.OutOfMemory => return r.finish(id, out, .servfail),
    };
    const opt = msg.edns() catch return r.finish(id, out, .formerr);
    if (opt) |o| {
        r.opt = .{ .payload = @min(out.len, max_udp_payload) };
        if (transport == .udp) r.limit = std.math.clamp(o.payload, min_udp_payload, max_udp_payload);
        if (o.version != 0) {
            r.opt.?.ext_rcode = badvers;
            return r.finish(id, out, .noerror);
        }
    }
    if (msg.question.len != 1) return r.finish(id, out, .formerr);
    const q = msg.question[0];
    r.question = q;
    // A signed message is verified before it is acted upon; a failure is NOTAUTH with the TSIG
    // error in the response (unsigned for BADKEY and BADSIG, signed for BADTIME, RFC 8945 §5.2).
    r.tsig = tsig.verify(ctx.keys, query, msg, ctx.now) catch return r.finish(id, out, .formerr);
    if (r.tsig) |t| if (t.err != .none) {
        log.event(.warn, "tsig", .{ .code = @tagName(t.err), .key = zone.fmt(t.name) });
        if (qflags.opcode == 5) if (ctx.metrics) |m| m.update(ctx.keys, null, .notauth);
        return r.finish(id, out, .notauth);
    };
    if (qflags.opcode == 5) {
        const key = if (r.tsig) |t| t.key.?.name else null;
        const rc = update.apply(ctx.overlay, ctx.zones, msg, key, ctx.mono);
        if (ctx.metrics) |m| m.update(ctx.keys, key, rc);
        return r.finish(id, out, rc);
    }
    if (qflags.opcode != 0) return r.finish(id, out, .notimp);
    if (q.class != .in) return r.finish(id, out, .refused);

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
        const before = r.n_answers;
        const static = lookup(z, overlay, owner);
        if (static) |name| if (name.get(q.type)) |set| for (set.rdatas) |rd| r.answer(.{ .name = owner, .type = set.type, .ttl = set.ttl, .rdata = rd });
        // ADR 0006: dynamic records come after the static ones, never instead of them.
        if (overlay) |o| if (q.type == .txt) for (o.records.items) |rec| if (std.mem.eql(u8, rec.name, owner)) r.answer(.{ .name = owner, .type = .txt, .ttl = rec.ttl, .rdata = rec.rdata });
        if (r.n_answers > before) return r.finish(id, out, .noerror);
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

/// The answer to a forwarded query from a validated upstream response, every TTL set to `ttl`
/// (the remaining cache lifetime); a null or unparsable `upstream` is SERVFAIL. RA=1, AA=0 (ADR 0008).
pub fn forwarded(arena: std.mem.Allocator, f: Forward, upstream: ?[]const u8, ttl: u32, out: []u8) usize {
    var r: Response = .{ .flags = .{ .qr = true, .rd = f.rd, .ra = true }, .limit = f.limit, .question = f.question, .opt = f.opt };
    const m = wire.Message.parse(arena, upstream orelse return r.finish(f.id, out, .servfail).?) catch return r.finish(f.id, out, .servfail).?;
    var sections: [3][]wire.RR = undefined;
    for (&sections, [_][]const wire.RR{ m.answer, m.authority, m.additional }) |*dst, src| {
        var n: usize = 0;
        dst.* = arena.alloc(wire.RR, src.len) catch return r.finish(f.id, out, .servfail).?;
        for (src) |rr| if (rr.type != .opt) { // the upstream's OPT is not the client's
            dst.*[n] = rr;
            dst.*[n].ttl = ttl;
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
    answers: [64]wire.RR = undefined,
    n_answers: usize = 0,
    authority: ?wire.RR = null,
    /// The sections of a forwarded answer; additional records are dropped when they do not fit.
    upstream: ?wire.Message = null,

    fn answer(r: *Response, rr: wire.RR) void {
        if (r.n_answers == r.answers.len) return; // a 65th record would not fit a UDP answer anyway; TCP gets 64
        r.answers[r.n_answers] = rr;
        r.n_answers += 1;
    }

    /// NXDOMAIN or NODATA: the SOA in the authority section (RFC 2308 §2) with the negative TTL.
    fn negative(r: *Response, id: u16, out: []u8, z: *const zone.Zone, rcode: Rcode) ?usize {
        r.authority = .{ .name = z.origin, .type = .soa, .ttl = z.negativeTtl(), .rdata = z.soa.rdatas[0] };
        return r.finish(id, out, rcode);
    }

    fn finish(r: *Response, id: u16, out: []u8, rcode: Rcode) ?usize {
        r.flags.rcode = @intFromEnum(rcode);
        // The OPT and the TSIG are written last but must always fit: their bytes are reserved up front.
        const opt_len: usize = if (r.opt != null) 11 else 0;
        const tsig_len: usize = if (r.tsig) |t| t.size() else 0;
        const body = out[0 .. @min(r.limit, out.len) - opt_len - tsig_len];
        var w = wire.Writer.init(body, id, r.flags) catch unreachable; // out is a response buffer
        if (r.question) |q| w.question(q) catch {
            r.flags.tc = true;
        };
        if (!r.flags.tc) for (r.answers[0..r.n_answers]) |rr| w.rr(.answer, rr) catch {
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
    for (full.answer) |rr| try testing.expectEqual(@as(u32, 42), rr.ttl);
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
