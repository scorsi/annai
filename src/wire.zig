//! RFC 1035 message codec (ADR 0007): header, questions, RRs with opaque RDATA, OPT, and name
//! compression on both parse and emit. An UPDATE (RFC 2136) has the same four sections on the
//! wire (zone = question, prerequisite = answer, update = authority), so nothing here looks at
//! the opcode; an empty RDATA is accepted only in class ANY (its "delete RRset" form).
//!
//! Names are kept in uncompressed wire form (length-prefixed labels, root byte last), case kept.
//! Parsing borrows the packet: a `Message` is valid as long as the packet is. Names and the
//! RDATA of the types that may carry compression pointers (NS, CNAME, SOA, PTR, MX, SRV) are
//! copied, decompressed, into the caller's allocator, an arena per request (ADR 0001); the total
//! allocated is bounded by the packet length, whatever the header counts claim.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const ParseError = error{Malformed} || Allocator.Error;
pub const WriteError = error{ NoSpace, Malformed };

pub const Type = enum(u16) { a = 1, ns = 2, cname = 5, soa = 6, ptr = 12, hinfo = 13, mx = 15, txt = 16, aaaa = 28, srv = 33, opt = 41, tsig = 250, any = 255, caa = 257, _ };
pub const Class = enum(u16) { in = 1, none = 254, any = 255, _ };
/// Header RCODEs (RFC 1035, 2136, 8945); upstreams may send any value.
pub const Rcode = enum(u4) { noerror = 0, formerr = 1, servfail = 2, nxdomain = 3, notimp = 4, refused = 5, yxdomain = 6, yxrrset = 7, nxrrset = 8, notauth = 9, notzone = 10, _ };

/// The second header word; the first field is the least significant bit.
pub const Flags = packed struct(u16) {
    rcode: u4 = 0,
    cd: bool = false,
    ad: bool = false,
    z: bool = false,
    ra: bool = false,
    rd: bool = false,
    tc: bool = false,
    aa: bool = false,
    opcode: u4 = 0,
    qr: bool = false,
};

pub const Question = struct { name: []const u8, type: Type, class: Class = .in };

pub const RR = struct {
    name: []const u8,
    type: Type,
    class: Class = .in,
    ttl: u32 = 0,
    /// Uncompressed RDATA; opaque bytes except for the names `layout` knows about.
    rdata: []const u8 = "",
};

/// EDNS(0) OPT pseudo-RR (RFC 6891). Options are kept opaque: unknown ones are ignored (ADR 0007).
pub const Opt = struct {
    payload: u16,
    ext_rcode: u8 = 0,
    version: u8 = 0,
    do: bool = false,
    options: []const u8 = "",

    pub fn fromRR(r: RR) Opt {
        return .{ .payload = @intFromEnum(r.class), .ext_rcode = @truncate(r.ttl >> 24), .version = @truncate(r.ttl >> 16), .do = r.ttl & 0x8000 != 0, .options = r.rdata };
    }

    pub fn toRR(o: Opt) RR {
        const ttl = @as(u32, o.ext_rcode) << 24 | @as(u32, o.version) << 16 | @as(u32, @intFromBool(o.do)) << 15;
        return .{ .name = "\x00", .type = .opt, .class = @enumFromInt(o.payload), .ttl = ttl, .rdata = o.options };
    }
};

pub const Section = enum { answer, authority, additional };

pub const Message = struct {
    id: u16 = 0,
    flags: Flags = .{},
    question: []const Question = &.{},
    answer: []const RR = &.{},
    authority: []const RR = &.{},
    additional: []const RR = &.{},
    /// Offset of the last additional RR when it is a TSIG (RFC 8945): the signed bytes end there.
    tsig_at: ?usize = null,

    pub fn parse(a: Allocator, packet: []const u8) ParseError!Message {
        var r: Reader = .{ .buf = packet };
        var m: Message = .{};
        m.id = try r.int(u16);
        m.flags = @bitCast(try r.int(u16));
        const qd = try r.int(u16);
        const an = try r.int(u16);
        const ns = try r.int(u16);
        const ar = try r.int(u16);
        // A question is at least 5 bytes and an RR 11: refuse a lying header before allocating.
        if (@as(usize, qd) * 5 + (@as(usize, an) + ns + ar) * 11 > packet.len - r.pos) return error.Malformed;
        const qs = try a.alloc(Question, qd);
        for (qs) |*q| q.* = .{ .name = try parseName(a, &r), .type = @enumFromInt(try r.int(u16)), .class = @enumFromInt(try r.int(u16)) };
        m.question = qs;
        var last: usize = 0;
        m.answer = try parseRRs(a, &r, an, &last);
        m.authority = try parseRRs(a, &r, ns, &last);
        m.additional = try parseRRs(a, &r, ar, &last);
        if (r.pos != packet.len) return error.Malformed;
        if (ar > 0 and m.additional[ar - 1].type == .tsig) m.tsig_at = last;
        return m;
    }

    /// Writes the whole message, compressing names; `buf` caps the size (512, 1232 or 65535).
    pub fn encode(m: Message, buf: []u8) WriteError!usize {
        var w = try Writer.init(buf, m.id, m.flags);
        for (m.question) |q| try w.question(q);
        for (m.answer) |r| try w.rr(.answer, r);
        for (m.authority) |r| try w.rr(.authority, r);
        for (m.additional) |r| try w.rr(.additional, r);
        return w.len;
    }

    /// The OPT RR, if any. Two of them, or one not owned by the root, is a FORMERR (RFC 6891 §6.1.1).
    pub fn edns(m: Message) error{Malformed}!?Opt {
        var found: ?Opt = null;
        for (m.additional) |r| if (r.type == .opt) {
            if (found != null or r.name.len != 1) return error.Malformed;
            found = Opt.fromRR(r);
        };
        return found;
    }
};

/// Presentation form to wire form, case kept; "." is the root.
pub fn nameFromText(out: *[255]u8, text: []const u8) error{Malformed}![]const u8 {
    if (std.mem.eql(u8, text, ".")) {
        out[0] = 0;
        return out[0..1];
    }
    const body = if (text.len > 0 and text[text.len - 1] == '.') text[0 .. text.len - 1] else text;
    var len: usize = 0;
    var labels = std.mem.splitScalar(u8, body, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or len + 1 + label.len > 254) return error.Malformed;
        out[len] = @intCast(label.len);
        @memcpy(out[len + 1 ..][0..label.len], label);
        len += 1 + label.len;
    }
    out[len] = 0;
    return out[0 .. len + 1];
}

/// Shape of the RDATA whose names may be compressed on the wire (RFC 1035 §3.3, RFC 3597 §4; SRV
/// is decompressed on parse but never compressed on emit).
const Field = union(enum) { name, bytes: u16 };
fn layout(t: Type) ?[]const Field {
    return switch (t) {
        .ns, .cname, .ptr => &[_]Field{.name},
        .mx => &[_]Field{ .{ .bytes = 2 }, .name },
        .soa => &[_]Field{ .name, .name, .{ .bytes = 20 } },
        .srv => &[_]Field{ .{ .bytes = 6 }, .name },
        else => null,
    };
}

pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn take(r: *Reader, n: usize) error{Malformed}![]const u8 {
        if (r.buf.len - r.pos < n) return error.Malformed;
        defer r.pos += n;
        return r.buf[r.pos..][0..n];
    }

    pub fn int(r: *Reader, comptime T: type) error{Malformed}!T {
        const n = @divExact(@bitSizeOf(T), 8);
        return std.mem.readInt(T, (try r.take(n))[0..n], .big);
    }

    /// Reads a possibly compressed name into `out`. Every pointer must point strictly before
    /// itself, which rules out loops and forward references; the result stays within 255 bytes.
    fn name(r: *Reader, out: *[255]u8) error{Malformed}![]const u8 {
        var len: usize = 0;
        var pos = r.pos;
        var jumped = false;
        while (true) {
            if (pos >= r.buf.len) return error.Malformed;
            const c = r.buf[pos];
            switch (c & 0xC0) {
                0x00 => {
                    const end = pos + 1 + c;
                    if (end > r.buf.len or len + 1 + c > 255) return error.Malformed;
                    @memcpy(out[len..][0 .. 1 + c], r.buf[pos..end]);
                    len += 1 + c;
                    pos = end;
                    if (!jumped) r.pos = pos;
                    if (c == 0) return out[0..len];
                },
                0xC0 => {
                    if (pos + 2 > r.buf.len) return error.Malformed;
                    const target = @as(usize, c & 0x3F) << 8 | r.buf[pos + 1];
                    if (target >= pos) return error.Malformed;
                    if (!jumped) r.pos = pos + 2;
                    jumped = true;
                    pos = target;
                },
                else => return error.Malformed, // 0x40 and 0x80 label types are deprecated or unassigned
            }
        }
    }
};

fn parseName(a: Allocator, r: *Reader) ParseError![]const u8 {
    var tmp: [255]u8 = undefined;
    return a.dupe(u8, try r.name(&tmp));
}

/// `last` receives the offset of the last RR read, when there is one.
fn parseRRs(a: Allocator, r: *Reader, count: u16, last: *usize) ParseError![]const RR {
    const rrs = try a.alloc(RR, count);
    for (rrs) |*rr| {
        last.* = r.pos;
        rr.name = try parseName(a, r);
        rr.type = @enumFromInt(try r.int(u16));
        rr.class = @enumFromInt(try r.int(u16));
        rr.ttl = try r.int(u32);
        const raw = try r.take(try r.int(u16));
        rr.rdata = raw;
        if (layout(rr.type)) |fields| if (raw.len != 0 or rr.class != .any) {
            rr.rdata = try decompress(a, r.buf[0..r.pos], r.pos - raw.len, fields);
        };
    }
    return rrs;
}

/// Rewrites the RDATA at `start..packet.len` with its names expanded; pointers may reach any
/// earlier byte of the packet. The RDATA must be consumed exactly.
fn decompress(a: Allocator, packet: []const u8, start: usize, fields: []const Field) ParseError![]const u8 {
    var out: [2 * 255 + 20]u8 = undefined;
    var len: usize = 0;
    var r: Reader = .{ .buf = packet, .pos = start };
    for (fields) |f| switch (f) {
        .name => {
            var tmp: [255]u8 = undefined;
            const n = try r.name(&tmp);
            @memcpy(out[len..][0..n.len], n);
            len += n.len;
        },
        .bytes => |n| {
            @memcpy(out[len..][0..n], try r.take(n));
            len += n;
        },
    };
    if (r.pos != packet.len) return error.Malformed;
    return a.dupe(u8, out[0..len]);
}

/// Incremental encoder: the header counts are kept up to date in `buf`, and a question or RR that
/// does not fit leaves the output as it was, so a caller can stop, set TC and send what fits.
pub const Writer = struct {
    buf: []u8,
    len: usize = 12,
    /// Offsets of labels written in full, below 0x4000: the targets a later name may point to.
    labels: [64]u16 = undefined,
    n_labels: usize = 0,

    pub fn init(buf: []u8, id: u16, flags: Flags) WriteError!Writer {
        if (buf.len < 12) return error.NoSpace;
        @memset(buf[0..12], 0);
        std.mem.writeInt(u16, buf[0..2], id, .big);
        std.mem.writeInt(u16, buf[2..4], @bitCast(flags), .big);
        return .{ .buf = buf };
    }

    pub fn question(w: *Writer, q: Question) WriteError!void {
        const mark = w.*;
        errdefer w.* = mark;
        try w.name(q.name, true);
        try w.int(u16, @intFromEnum(q.type));
        try w.int(u16, @intFromEnum(q.class));
        try w.bump(4);
    }

    pub fn rr(w: *Writer, section: Section, r: RR) WriteError!void {
        const mark = w.*;
        errdefer w.* = mark;
        try w.name(r.name, true);
        try w.int(u16, @intFromEnum(r.type));
        try w.int(u16, @intFromEnum(r.class));
        try w.int(u32, r.ttl);
        const rdlength_at = w.len;
        try w.int(u16, 0);
        const fields = layout(r.type);
        if (fields == null or (r.rdata.len == 0 and r.class == .any)) try w.bytes(r.rdata) else {
            var rd: Reader = .{ .buf = r.rdata };
            for (fields.?) |f| switch (f) {
                .name => {
                    var tmp: [255]u8 = undefined;
                    try w.name(try rd.name(&tmp), r.type != .srv);
                },
                .bytes => |n| try w.bytes(try rd.take(n)),
            };
            if (rd.pos != r.rdata.len) return error.Malformed;
        }
        const rdlength = std.math.cast(u16, w.len - rdlength_at - 2) orelse return error.NoSpace;
        std.mem.writeInt(u16, w.buf[rdlength_at..][0..2], rdlength, .big);
        try w.bump(6 + 2 * @as(usize, @intFromEnum(section)));
    }

    fn bump(w: *Writer, count_at: usize) WriteError!void {
        const at = w.buf[count_at..][0..2];
        const n = std.math.add(u16, std.mem.readInt(u16, at, .big), 1) catch return error.NoSpace;
        std.mem.writeInt(u16, at, n, .big);
    }

    fn bytes(w: *Writer, b: []const u8) WriteError!void {
        if (w.buf.len - w.len < b.len) return error.NoSpace;
        @memcpy(w.buf[w.len..][0..b.len], b);
        w.len += b.len;
    }

    fn int(w: *Writer, comptime T: type, v: T) WriteError!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .big);
        try w.bytes(&b);
    }

    /// Writes an uncompressed-form name, replacing the longest suffix already in the output by a
    /// pointer when `compress` is set. Labels written in full become pointer targets either way.
    fn name(w: *Writer, n: []const u8, compress: bool) WriteError!void {
        var i: usize = 0;
        while (true) {
            if (i >= n.len or n[i] > 63 or i + 1 + n[i] > n.len) return error.Malformed;
            if (n[i] == 0) return w.bytes(n[i .. i + 1]);
            if (compress) if (w.find(n[i..])) |off| return w.int(u16, 0xC000 | off);
            if (w.len < 0x4000 and w.n_labels < w.labels.len) {
                w.labels[w.n_labels] = @intCast(w.len);
                w.n_labels += 1;
            }
            try w.bytes(n[i .. i + 1 + n[i]]);
            i += 1 + n[i];
        }
    }

    fn find(w: *const Writer, suffix: []const u8) ?u16 {
        for (w.labels[0..w.n_labels]) |off| if (w.sameName(off, suffix)) return off;
        return null;
    }

    /// Compares the (possibly compressed) name at `off` in the output with an uncompressed one.
    /// The output is ours, so its pointers are trusted to go backwards.
    fn sameName(w: *const Writer, off: u16, n: []const u8) bool {
        var o: usize = off;
        var i: usize = 0;
        while (true) {
            while (w.buf[o] & 0xC0 == 0xC0) o = @as(usize, w.buf[o] & 0x3F) << 8 | w.buf[o + 1];
            const c = w.buf[o];
            if (c != n[i]) return false;
            if (c == 0) return true;
            if (!std.mem.eql(u8, w.buf[o + 1 ..][0..c], n[i + 1 ..][0..c])) return false;
            o += 1 + c;
            i += 1 + c;
        }
    }
};

// ---- tests -------------------------------------------------------------------------------------

const testing = std.testing;

fn wn(comptime text: []const u8) []const u8 {
    const wire = comptime blk: {
        var buf: [255]u8 = undefined;
        const s = nameFromText(&buf, text) catch unreachable;
        break :blk s[0..s.len].*;
    };
    return &wire;
}

fn expectEqualMessages(want: Message, got: Message) !void {
    try testing.expectEqual(want.id, got.id);
    try testing.expectEqual(want.flags, got.flags);
    try testing.expectEqual(want.question.len, got.question.len);
    for (want.question, got.question) |a, b| {
        try testing.expectEqualSlices(u8, a.name, b.name);
        try testing.expectEqual(a.type, b.type);
        try testing.expectEqual(a.class, b.class);
    }
    inline for (.{ "answer", "authority", "additional" }) |s| {
        const wa = @field(want, s);
        const ga = @field(got, s);
        try testing.expectEqual(wa.len, ga.len);
        for (wa, ga) |a, b| {
            try testing.expectEqualSlices(u8, a.name, b.name);
            try testing.expectEqual(a.type, b.type);
            try testing.expectEqual(a.class, b.class);
            try testing.expectEqual(a.ttl, b.ttl);
            try testing.expectEqualSlices(u8, a.rdata, b.rdata);
        }
    }
}

/// Iterates a corpus file: `name = hex` lines, `#` comments.
const Corpus = struct {
    lines: std.mem.SplitIterator(u8, .scalar),
    buf: [4096]u8 = undefined,

    fn init(text: []const u8) Corpus {
        return .{ .lines = std.mem.splitScalar(u8, text, '\n') };
    }

    fn next(c: *Corpus) ?struct { name: []const u8, packet: []const u8 } {
        while (c.lines.next()) |line| {
            if (line.len == 0 or line[0] == '#') continue;
            const eq = std.mem.indexOf(u8, line, " = ") orelse @panic("corpus line without ' = '");
            const hex = std.mem.trim(u8, line[eq + 3 ..], " \r");
            return .{ .name = line[0..eq], .packet = std.fmt.hexToBytes(&c.buf, hex) catch @panic("bad hex in corpus") };
        }
        return null;
    }
};

test "flags match the RFC 1035 bit layout" {
    const f: Flags = @bitCast(@as(u16, 0x8183));
    try testing.expect(f.qr and f.rd and f.ra and !f.aa and !f.tc);
    try testing.expectEqual(@as(u4, 3), f.rcode);
    try testing.expectEqual(@as(u16, 0x2C04), @as(u16, @bitCast(Flags{ .opcode = 5, .aa = true, .rcode = 4 })));
}

test "nameFromText" {
    var buf: [255]u8 = undefined;
    try testing.expectEqualSlices(u8, "\x00", try nameFromText(&buf, "."));
    try testing.expectEqualSlices(u8, "\x03WwW\x07example\x03org\x00", try nameFromText(&buf, "WwW.example.org."));
    try testing.expectEqualSlices(u8, "\x01a\x00", try nameFromText(&buf, "a"));
    for ([_][]const u8{ "", "a..b", ".a", "a" ** 64 }) |bad| try testing.expectError(error.Malformed, nameFromText(&buf, bad));
    const long = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61;
    try testing.expectEqual(@as(usize, 255), (try nameFromText(&buf, long)).len);
    try testing.expectError(error.Malformed, nameFromText(&buf, long ++ "e"));
}

test "round trip of every type with compression in owners and RDATA" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const soa = comptime wn("ns1.example.org.") ++ wn("hostmaster.example.org.") ++ "\x00\x00\x00\x01" ++ "\x00\x00\x0e\x10" ++ "\x00\x00\x03\x84" ++ "\x00\x09\x3a\x80" ++ "\x00\x00\x01\x2c";
    const want: Message = .{
        .id = 0xbeef,
        .flags = .{ .qr = true, .aa = true, .rd = true },
        .question = &.{.{ .name = wn("WWW.example.org."), .type = .a }},
        .answer = &.{
            .{ .name = wn("www.example.org."), .type = .cname, .ttl = 300, .rdata = wn("host.example.org.") },
            .{ .name = wn("host.example.org."), .type = .a, .ttl = 300, .rdata = "\xc0\x00\x02\x01" },
            .{ .name = wn("host.example.org."), .type = .aaaa, .ttl = 300, .rdata = "\x20\x01\x0d\xb8" ++ "\x00" ** 11 ++ "\x01" },
            .{ .name = wn("example.org."), .type = .mx, .ttl = 300, .rdata = comptime "\x00\x0a" ++ wn("mail.example.org.") },
            .{ .name = wn("example.org."), .type = .txt, .ttl = 300, .rdata = "\x0bv=spf1 -all" },
            .{ .name = wn("1.2.0.192.in-addr.arpa."), .type = .ptr, .ttl = 300, .rdata = wn("host.example.org.") },
            .{ .name = wn("example.org."), .type = @enumFromInt(65280), .ttl = 300, .rdata = "\xc0\x0c opaque, not a pointer" },
        },
        .authority = &.{
            .{ .name = wn("example.org."), .type = .ns, .ttl = 3600, .rdata = wn("ns1.example.org.") },
            .{ .name = wn("example.org."), .type = .soa, .ttl = 3600, .rdata = soa },
        },
        .additional = &.{ .{ .name = wn("ns1.example.org."), .type = .a, .ttl = 3600, .rdata = "\xc0\x00\x02\x02" }, (Opt{ .payload = 1232, .do = true }).toRR() },
    };
    var buf: [512]u8 = undefined;
    const len = try want.encode(&buf);
    const got = try Message.parse(arena.allocator(), buf[0..len]);
    try expectEqualMessages(want, got);
    const edns = (try got.edns()).?;
    try testing.expectEqual(@as(u16, 1232), edns.payload);
    try testing.expect(edns.do and edns.version == 0 and edns.ext_rcode == 0);
    // Owners, CNAME/MX/PTR/NS/SOA names compress; the first owner is only written once.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, buf[0..len], "\x07example\x03org"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, buf[0..len], "\x04host"));
}

test "SRV targets are never compressed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const target = wn("host.example.org.");
    const m: Message = .{
        .question = &.{.{ .name = wn("host.example.org."), .type = .srv }},
        .answer = &.{.{ .name = wn("host.example.org."), .type = .srv, .rdata = comptime "\x00\x00\x00\x00\x00\x35" ++ wn("host.example.org.") }},
    };
    var buf: [512]u8 = undefined;
    const len = try m.encode(&buf);
    // header + question (name + 4) + RR (2-byte pointer + 10 + rdata with the full target).
    try testing.expectEqual(12 + target.len + 4 + 2 + 10 + 6 + target.len, len);
    try expectEqualMessages(m, try Message.parse(arena.allocator(), buf[0..len]));
}

test "a chain of backward pointers and a pointer into RDATA are valid" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // question "example.org", then a CNAME whose owner is a 3-hop pointer chain and whose rdata
    // points at the owner's pointer, and an NS whose rdata points into the CNAME rdata.
    const pkt = "\x00\x00\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00" ++ "\x07example\x03org\x00\x00\x01\x00\x01" ++
        "\x03www\xc0\x0c" ++ "\x00\x05\x00\x01\x00\x00\x00\x00\x00\x02" ++ "\xc0\x1d" ++
        "\xc0\x2d" ++ "\x00\x02\x00\x01\x00\x00\x00\x00\x00\x05" ++ "\x02ns\xc0\x2f";
    const got = try Message.parse(arena.allocator(), pkt);
    try testing.expectEqualSlices(u8, wn("www.example.org."), got.answer[0].name);
    try testing.expectEqualSlices(u8, wn("www.example.org."), got.answer[0].rdata);
    try testing.expectEqualSlices(u8, wn("www.example.org."), got.answer[1].name);
    try testing.expectEqualSlices(u8, wn("ns.www.example.org."), got.answer[1].rdata);
}

test "UPDATE delete forms: empty RDATA only in class ANY" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m: Message = .{
        .flags = .{ .opcode = 5 },
        .question = &.{.{ .name = wn("example.org."), .type = .soa }},
        .authority = &.{
            .{ .name = wn("_acme-challenge.example.org."), .type = .txt, .class = .any },
            .{ .name = wn("_acme-challenge.example.org."), .type = .cname, .class = .any },
            .{ .name = wn("_acme-challenge.example.org."), .type = .txt, .class = .none, .rdata = "\x03abc" },
        },
    };
    var buf: [512]u8 = undefined;
    const len = try m.encode(&buf);
    try expectEqualMessages(m, try Message.parse(arena.allocator(), buf[0..len]));
    const bad: Message = .{ .authority = &.{.{ .name = wn("example.org."), .type = .cname, .class = .in }} };
    try testing.expectError(error.Malformed, bad.encode(&buf));
}

test "two OPT RRs or an OPT with an owner are FORMERR" {
    var opt = (Opt{ .payload = 512 }).toRR();
    const two: Message = .{ .additional = &.{ opt, opt } };
    try testing.expectError(error.Malformed, two.edns());
    opt.name = wn("example.org.");
    const owned: Message = .{ .additional = &.{opt} };
    try testing.expectError(error.Malformed, owned.edns());
    try testing.expectEqual(@as(?Opt, null), try (Message{}).edns());
}

test "a lying header is refused before any allocation" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.Malformed, Message.parse(failing.allocator(), "\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x00"));
}

test "no space leaves the counts untouched" {
    var buf: [40]u8 = undefined;
    var w = try Writer.init(&buf, 1, .{});
    try w.question(.{ .name = wn("example.org."), .type = .a });
    try testing.expectError(error.NoSpace, w.rr(.answer, .{ .name = wn("example.org."), .type = .a, .rdata = "\x7f\x00\x00\x01" }));
    try testing.expectEqualSlices(u8, "\x00\x01\x00\x00\x00\x00\x00\x00", buf[4..12]);
    try testing.expectEqual(@as(usize, 29), w.len);
    try testing.expectError(error.NoSpace, Writer.init(buf[0..11], 1, .{}));
}

test "captured corpus round-trips, and no prefix or extension of it parses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var corpus = Corpus.init(@embedFile("corpus/captured.txt"));
    var count: usize = 0;
    while (corpus.next()) |entry| : (count += 1) {
        const a = arena.allocator();
        const first = Message.parse(a, entry.packet) catch |e| {
            std.debug.print("captured {s}: {s}\n", .{ entry.name, @errorName(e) });
            return e;
        };
        var buf: [512]u8 = undefined;
        const len = try first.encode(&buf);
        try expectEqualMessages(first, try Message.parse(a, buf[0..len]));
        // Our compression is at least as good as the resolver's.
        try testing.expect(len <= entry.packet.len);
        var extended: [4097]u8 = undefined;
        @memcpy(extended[0..entry.packet.len], entry.packet);
        extended[entry.packet.len] = 0;
        try testing.expectError(error.Malformed, Message.parse(a, extended[0 .. entry.packet.len + 1]));
        for (0..entry.packet.len) |cut| try testing.expectError(error.Malformed, Message.parse(a, entry.packet[0..cut]));
    }
    try testing.expectEqual(@as(usize, 24), count);
}

test "malformed corpus is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var corpus = Corpus.init(@embedFile("corpus/malformed.txt"));
    var count: usize = 0;
    while (corpus.next()) |entry| : (count += 1) {
        if (Message.parse(arena.allocator(), entry.packet)) |_| {
            std.debug.print("malformed {s}: accepted\n", .{entry.name});
            return error.TestUnexpectedResult;
        } else |e| try testing.expectEqual(error.Malformed, e);
    }
    try testing.expectEqual(@as(usize, 24), count);
}
