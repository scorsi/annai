//! Authoritative responder (ADR 0007 v0): one query packet in, one response packet out. Transport
//! independent: the caller says how many bytes the transport allows (`udp` caps at the EDNS
//! payload, 512 without OPT) and the engine sets TC when the answer does not fit.

const std = @import("std");
const wire = @import("wire.zig");
const zone = @import("zone.zig");

pub const Rcode = enum(u4) { noerror = 0, formerr = 1, servfail = 2, nxdomain = 3, notimp = 4, refused = 5 };

/// RFC 6891 §6.2.3 and DNS Flag Day 2020: never trust a payload above 1232 or below 512.
pub const max_udp_payload = 1232;
pub const min_udp_payload = 512;
const badvers = 1; // extended RCODE 16 = ext_rcode 1, rcode 0
const hinfo_rfc8482 = "\x07RFC8482\x00";
const max_cname_hops = 8;

pub const Transport = enum { udp, tcp };

/// Writes the response to `query` into `out` and returns its length, or null when the packet
/// deserves no answer (shorter than a header, or itself a response).
pub fn respond(arena: std.mem.Allocator, zones: []const zone.Zone, query: []const u8, out: []u8, transport: Transport) ?usize {
    if (query.len < 12) return null;
    const id = std.mem.readInt(u16, query[0..2], .big);
    const qflags: wire.Flags = @bitCast(std.mem.readInt(u16, query[2..4], .big));
    if (qflags.qr) return null;

    var r: Response = .{
        .flags = .{ .qr = true, .opcode = qflags.opcode, .rd = qflags.rd },
        .limit = if (transport == .tcp) out.len else min_udp_payload,
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
    if (qflags.opcode != 0) return r.finish(id, out, .notimp);
    if (q.class != .in) return r.finish(id, out, .refused);

    var lowered: [255]u8 = undefined;
    @memcpy(lowered[0..q.name.len], q.name);
    const qname = zone.lower(lowered[0..q.name.len]);
    const z = zone.find(zones, qname) orelse return r.finish(id, out, .refused);
    r.flags.aa = true;

    if (q.type == .any) {
        // RFC 8482: a synthetic HINFO when the name exists, whatever it holds.
        if (z.lookup(qname) == null) return r.negative(id, out, z, .nxdomain);
        r.answer(.{ .name = q.name, .type = .hinfo, .ttl = z.soa.ttl, .rdata = hinfo_rfc8482 });
        return r.finish(id, out, .noerror);
    }

    var owner: []const u8 = qname;
    var hops: usize = 0;
    while (true) : (hops += 1) {
        const name = z.lookup(owner) orelse return r.negative(id, out, z, .nxdomain);
        if (name.get(q.type)) |set| {
            for (set.rdatas) |rd| r.answer(.{ .name = owner, .type = set.type, .ttl = set.ttl, .rdata = rd });
            return r.finish(id, out, .noerror);
        }
        const cname = name.get(.cname) orelse return r.negative(id, out, z, .noerror);
        r.answer(.{ .name = owner, .type = .cname, .ttl = cname.ttl, .rdata = cname.rdatas[0] });
        owner = cname.rdatas[0];
        // The chase ends where the zone ends or where a loop could begin; the client continues.
        if (!zone.isUnder(owner, z.origin) or hops == max_cname_hops) return r.finish(id, out, .noerror);
    }
}

const Response = struct {
    flags: wire.Flags,
    limit: usize,
    question: ?wire.Question = null,
    opt: ?wire.Opt = null,
    answers: [64]wire.RR = undefined,
    n_answers: usize = 0,
    authority: ?wire.RR = null,

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
        // The OPT is written last but must always fit: its 11 bytes are reserved up front.
        const reserved: usize = if (r.opt != null) 11 else 0;
        const body = out[0..@min(r.limit, out.len) - reserved];
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
        std.mem.writeInt(u16, out[2..4], @bitCast(r.flags), .big);
        if (r.opt) |o| {
            w.buf = out[0 .. body.len + reserved];
            w.rr(.additional, o.toRR()) catch unreachable; // 11 bytes were reserved
        }
        return w.len;
    }
};

// ---- tests -------------------------------------------------------------------------------------

const testing = std.testing;
const config = @import("config.zig");

const test_zone_head =
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
    \\[names."big"]
    \\txt = [
    \\
;
/// Eight TXT strings of 255 bytes (the first one 256, so it is split): over 2 KiB of RDATA.
const test_zone = test_zone_head ++ "\"" ++ "y" ** 256 ++ "\",\n" ++ ("\"" ++ "x" ** 255 ++ "\",\n") ** 7 ++ "]\n";

const Fixture = struct {
    arena: std.heap.ArenaAllocator,
    zones: [1]zone.Zone,
    out: [65535]u8 = undefined,
    buf: [65535]u8 = undefined,
    last_len: usize = 0,

    fn init() !*Fixture {
        const f = try testing.allocator.create(Fixture);
        f.arena = std.heap.ArenaAllocator.init(testing.allocator);
        var d: config.Diag = .{};
        f.zones[0] = config.loadZone(f.arena.allocator(), test_zone, &d) catch |e| {
            std.debug.print("{s}\n", .{d.msg});
            return e;
        };
        return f;
    }

    fn deinit(f: *Fixture) void {
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
        const n = respond(f.arena.allocator(), &f.zones, packet, &f.out, transport) orelse return error.NoResponse;
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

test "REFUSED outside the zones, NOTIMP for other opcodes, ANY is HINFO" {
    const f = try Fixture.init();
    defer f.deinit();
    const refused = try f.ask(.{ .name = "example.org." });
    try expectRcode(refused, .refused);
    try testing.expect(!refused.flags.aa);
    try expectRcode(try f.ask(.{ .name = "notuchi.example.org." }), .refused);
    try expectRcode(try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .class = .any }), .refused);
    const notimp = try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .opcode = 5 });
    try expectRcode(notimp, .notimp);
    try testing.expectEqual(@as(u4, 5), notimp.flags.opcode);
    const any = try f.ask(.{ .name = "hub.kekkai.uchi.example.org.", .type = .any });
    try expectRcode(any, .noerror);
    try testing.expectEqual(wire.Type.hinfo, any.answer[0].type);
    try testing.expectEqualSlices(u8, hinfo_rfc8482, any.answer[0].rdata);
    try expectRcode(try f.ask(.{ .name = "nope.uchi.example.org.", .type = .any }), .nxdomain);
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
