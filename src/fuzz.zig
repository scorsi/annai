//! Fuzzing harness for the codec and the UPDATE/TSIG paths (ADR 0009, 0011; M4). The pinned Zig
//! 0.16.0 cannot build its own fuzzer (`zig build test --fuzz` fails to compile test_runner.zig),
//! so this is a seeded mutator over the corpora with oracles stronger than "no crash": whatever
//! parses must encode and parse back identical, whatever the engine emits must parse, stay within
//! the transport limit and keep the query ID, and a request must never take more than
//! `max_request_bytes`. Crashes, safety traps and hangs print the input in hex as well.
//!
//! The `tcp` target drives a real server on a loopback port (src/server.zig `Loopback`): the
//! input, framed and then raw, goes over one connection in chunks the input's hash picks, and
//! the stream invariants of `Loopback.checkStream` must hold (review A17, B4). TCP uses a
//! separate counting allocator because the server survives runs: its memory bound includes
//! live bytes at entry plus all allocations during the stream, including the oracle itself.
//!
//! The `forward` target drives a fake UDP/TCP upstream through the real server, mutating raw
//! responses and matching messages: ID/question/source checks, TC twice, short TCP frames,
//! mixed TTLs, CNAME negatives, legacy compression, extended rcodes and 64 coalesced waiters.
//! Its oracles check response questions, rcodes, cache expiry and per-record TTL ageing.
//!
//! The `update-state` target builds a signed UPDATE from the input's hash (so mutations never
//! break the MAC) and sends it through `engine.respond`, sometimes over a nearly full overlay or
//! with a failing allocation: a non-NOERROR answer must leave the overlay exactly as it was, and
//! the overlay must keep the ADR 0006 policy and valid RRsets (review A3, A8, A17).
//!
//! By hand: `zig build fuzz -- <codec|respond|update|update-state|tcp|forward> <seconds> [seed]` (or `nix run .#fuzz`, in
//! ReleaseSafe); findings are `fuzz: ...` lines on stderr. Every finding becomes a line of
//! src/corpus/fuzz.txt, which `zig build test` replays through every target.

const std = @import("std");
const wire = @import("wire.zig");
const zone = @import("zone.zig");
const engine = @import("engine.zig");
const update = @import("update.zig");
const tsig = @import("tsig.zig");
const config = @import("config.zig");
const server = @import("server.zig");
const Allocator = std.mem.Allocator;

pub const Target = enum { codec, respond, update, @"update-state", tcp, forward };

/// Per-request memory a message of at most 64 KiB may take; more is a finding.
pub const max_request_bytes = 8 << 20;
const max_packet = 65535;

pub const Finding = error{ Encode, Reparse, RoundTrip, Oversize, IdLost, NotResponse, Memory, Overflow, Stream, Atomicity, Unsigned, Invariant };

pub const Fixture = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    zones: [2]zone.Zone,
    overlay: update.Overlay,
    keys: [1]tsig.Key = .{tsig.vector.key},
    /// Per-request allocator: bump allocation, so `end_index` after a run is its peak.
    fba: std.heap.FixedBufferAllocator,
    /// The corpora, the TSIG vector and a few synthesized messages: what the mutator starts from.
    seeds: std.ArrayList([]const u8) = .empty,
    out: [max_packet]u8 = undefined,
    peak: usize = 0,
    /// The `tcp` target's server, started on first use.
    loopback: ?*server.Loopback = null,
    tcp_memory: std.testing.FailingAllocator,
    peak_tcp_bytes: usize = 0,
    stream: [2 * max_packet + 2]u8 = undefined,
    forward_probe: ?server.ForwardProbe = null,

    pub fn init(gpa: Allocator) !*Fixture {
        const f = try gpa.create(Fixture);
        errdefer gpa.destroy(f);
        f.* = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa), .zones = undefined, .overlay = update.Overlay.init(gpa, 120, 3600), .fba = undefined, .tcp_memory = .init(gpa, .{}) };
        errdefer f.arena.deinit();
        const a = f.arena.allocator();
        f.fba = std.heap.FixedBufferAllocator.init(try a.alloc(u8, 2 * max_request_bytes));
        var d: config.Diag = .{};
        for (&f.zones, [_][]const u8{ engine.test_zone, engine.apex_zone }) |*z, text| z.* = config.loadZone(a, text, &d) catch |e| {
            std.debug.print("fuzz: fixture zone: {s}\n", .{d.msg});
            return e;
        };
        inline for (.{ "corpus/captured.txt", "corpus/malformed.txt", "corpus/fuzz.txt" }) |file| {
            var corpus = wire.Corpus.init(@embedFile(file));
            while (corpus.next()) |e| try f.seeds.append(a, try a.dupe(u8, e.packet));
        }
        var vbuf: [256]u8 = undefined;
        try f.seeds.append(a, try a.dupe(u8, tsig.vector.packet(&vbuf)));
        try f.synthesize();
        return f;
    }

    pub fn deinit(f: *Fixture) void {
        if (f.loopback) |l| l.deinit();
        if (f.forward_probe) |*p| p.deinit();
        f.overlay.deinit();
        f.arena.deinit();
        f.gpa.destroy(f);
    }

    /// Queries and an UPDATE the zones answer substantively, so mutations start near the deep paths.
    fn synthesize(f: *Fixture) !void {
        const opt = (wire.Opt{ .payload = 1232 }).toRR();
        for ([_]struct { []const u8, wire.Type }{
            .{ "\x03hub\x06kekkai\x04uchi\x07example\x03org\x00", .a },
            .{ "\x08anything\x04wild\x04uchi\x07example\x03org\x00", .a },
            .{ "\x03foo\x05alias\x04uchi\x07example\x03org\x00", .a },
            .{ "\x03big\x04uchi\x07example\x03org\x00", .txt },
            .{ "\x0f_acme-challenge\x03git\x04uchi\x07example\x03org\x00", .txt },
            .{ "\x07example\x03org\x00", .caa },
            .{ "\x07example\x03org\x00", .mx },
            .{ "\x06_imaps\x04_tcp\x07example\x03org\x00", .srv },
            .{ "\x03hub\x06kekkai\x04uchi\x07example\x03org\x00", .any },
            .{ "\x03www\x07example\x03net\x00", .aaaa },
        }) |q| try f.seed(.{ .id = 0x1234, .flags = .{ .rd = true }, .question = &.{.{ .name = q[0], .type = q[1] }}, .additional = &.{opt} });
        const ch = "\x0f_acme-challenge\x03git\x04uchi\x07example\x03org\x00";
        try f.seed(.{
            .id = 0x4242,
            .flags = .{ .opcode = 5 },
            .question = &.{.{ .name = "\x07example\x03org\x00", .type = .soa }},
            .answer = &.{
                .{ .name = ch, .type = .any, .class = .any },
                .{ .name = ch, .type = .txt, .class = .none },
                .{ .name = ch, .type = .txt, .rdata = "\x04tok1" },
            },
            .authority = &.{
                .{ .name = ch, .type = .txt, .ttl = 60, .rdata = "\x04tok2" },
                .{ .name = ch, .type = .txt, .class = .none, .rdata = "\x04tok1" },
                .{ .name = ch, .type = .txt, .class = .any },
            },
        });
        // IDs make the outer framed copy a response (ignored), leaving 101 raw queries.
        var stream: [101 * 19]u8 = undefined;
        for (0..101) |id| {
            const frame = stream[id * 19 ..][0..19];
            std.mem.writeInt(u16, frame[0..2], 17, .big);
            _ = try (wire.Message{ .id = @intCast(0x8000 + id), .question = &.{.{ .name = "\x00", .type = .a }} }).encode(frame[2..]);
        }
        try f.seeds.append(f.arena.allocator(), try f.arena.allocator().dupe(u8, &stream));
    }

    fn seed(f: *Fixture, m: wire.Message) !void {
        const n = try m.encode(&f.out);
        try f.seeds.append(f.arena.allocator(), try f.arena.allocator().dupe(u8, f.out[0..n]));
    }

    /// Runs `packet` through `target`; a finding is an error, a crash is a crash.
    pub fn run(f: *Fixture, target: Target, packet: []const u8) Finding!void {
        f.fba.reset();
        defer f.peak = @max(f.peak, f.fba.end_index);
        const a = f.fba.allocator();
        switch (target) {
            .codec => try f.codec(a, packet),
            .respond => try f.respond(a, packet),
            .update => try f.applyUpdate(a, packet),
            .@"update-state" => try f.updateState(a, packet),
            .tcp => {
                const freed = f.tcp_memory.freed_bytes;
                const result = f.tcp(packet);
                const bytes = f.tcp_memory.allocated_bytes - freed;
                f.peak_tcp_bytes = @max(f.peak_tcp_bytes, bytes);
                if (bytes > max_request_bytes) return error.Memory;
                try result;
            },
            .forward => {
                if (f.forward_probe == null) f.forward_probe = server.ForwardProbe.init(f.gpa) catch return error.Stream;
                var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(17, packet));
                const rand = prng.random();
                const cases = std.enums.values(server.ForwardProbe.Case);
                f.forward_probe.?.run(a, packet, cases[rand.uintLessThan(usize, cases.len)], if (rand.uintLessThan(u8, 8) == 0) 64 else 1) catch |e| {
                    std.debug.print("fuzz: forward case failed: {s}\n", .{@errorName(e)});
                    return error.Invariant;
                };
            },
        }
        if (f.fba.end_index > max_request_bytes) return error.Memory;
    }

    fn codec(f: *Fixture, a: Allocator, packet: []const u8) Finding!void {
        const m = wire.Message.parse(a, packet) catch |e| switch (e) {
            error.Malformed => return,
            error.OutOfMemory => return error.Memory,
        };
        _ = m.edns() catch {};
        const n = m.encode(&f.out) catch |e| switch (e) {
            // SRV targets are never compressed and the writer remembers 64 labels: a re-encoding
            // may outgrow the original. Anything parsed must still be encodable.
            error.NoSpace => return,
            error.Malformed => return error.Encode,
        };
        const again = wire.Message.parse(a, f.out[0..n]) catch return error.Reparse;
        if (!same(m, again)) return error.RoundTrip;
        var small: [512]u8 = undefined;
        _ = m.encode(&small) catch {}; // must only refuse, never crash
    }

    fn respond(f: *Fixture, a: Allocator, packet: []const u8) Finding!void {
        const uchi: engine.Context = .{ .zones = &f.zones };
        const soto: engine.Context = .{ .zones = f.zones[1..2], .keys = &f.keys, .overlay = &f.overlay, .now = tsig.vector.time, .mono = 1000 };
        for ([_]engine.Context{ uchi, soto }) |ctx| for ([_]engine.Transport{ .udp, .tcp }) |t| {
            var fwd: ?engine.Forward = null;
            const n = engine.respond(a, ctx, packet, &f.out, t, if (ctx.overlay == null) &fwd else null) orelse continue;
            try f.check(a, n, t, packet[0..2]);
        };
        // The uchi side also parses whatever an upstream sends back (ADR 0008).
        const forward: engine.Forward = .{ .id = 0x1234, .rd = true, .question = .{ .name = "\x03www\x07example\x03net\x00", .type = .txt }, .opt = .{ .payload = 1232 }, .limit = engine.max_udp_payload };
        try f.check(a, engine.forwarded(a, forward, packet, 42, &f.out), .udp, "\x12\x34");
    }

    /// What the engine emits is a well-formed response within the limit, with the query ID.
    fn check(f: *Fixture, a: Allocator, n: usize, t: engine.Transport, id: []const u8) Finding!void {
        if (n > (if (t == .udp) engine.max_udp_payload else f.out.len)) return error.Oversize;
        if (!std.mem.eql(u8, f.out[0..2], id)) return error.IdLost;
        const m = wire.Message.parse(a, f.out[0..n]) catch return error.Reparse;
        if (!m.flags.qr) return error.NotResponse;
    }

    fn tcp(f: *Fixture, packet: []const u8) Finding!void {
        const l = f.loopback orelse (server.Loopback.init(f.tcp_memory.allocator(), .{}) catch return error.Stream);
        f.loopback = l;
        // shortcut: one connection per 3 ms stays under the ephemeral ports that TIME_WAIT holds
        // (about 16k for 30 s on macOS, 28k for 60 s on Linux); a faster loop runs out and fails to connect.
        _ = std.posix.system.nanosleep(&.{ .sec = 0, .nsec = 3 * std.time.ns_per_ms }, null);
        const n = @min(packet.len, max_packet);
        std.mem.writeInt(u16, f.stream[0..2], @intCast(n), .big);
        @memcpy(f.stream[2..][0..n], packet[0..n]);
        @memcpy(f.stream[2 + n ..][0..n], packet[0..n]); // as framing bytes: its ID is a length prefix
        var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0, packet));
        try l.checkStream(f.stream[0 .. 2 + 2 * n], prng.random());
    }

    fn updateState(f: *Fixture, a: Allocator, input: []const u8) Finding!void {
        var prng = std.Random.DefaultPrng.init(std.hash.Wyhash.hash(1, input));
        const rand = prng.random();
        const o = &f.overlay;
        if (o.records.items.len > 900 and rand.boolean()) o.expire(std.math.maxInt(i64));
        if (rand.uintLessThan(u8, 8) == 0) fill(o, f.gpa, update.max_records - rand.uintAtMost(usize, 3));
        const m: wire.Message = .{
            .id = rand.int(u16),
            .flags = .{ .opcode = 5 },
            .question = &.{.{ .name = pick(rand, []const u8, &.{ "\x07example\x03org\x00", "\x07example\x03org\x00", "\x07example\x03net\x00" }), .type = .soa }},
            .answer = try randomRRs(a, rand, 3, true),
            .authority = try randomRRs(a, rand, 5, false),
        };
        const n = m.encode(&f.stream) catch return;
        const len = tsig.signRequest(tsig.vector.key, &f.stream, n, tsig.vector.time, rand.intRangeAtMost(usize, tsig.min_mac_len, tsig.mac_len));
        const before = try snapshot(a, o);
        // Now and then an allocation of the overlay fails, at any point of the transaction.
        var failing = std.testing.FailingAllocator.init(f.gpa, .{ .fail_index = if (rand.uintLessThan(u8, 4) == 0) rand.uintLessThan(usize, 8) else std.math.maxInt(usize) });
        o.gpa = failing.allocator();
        defer o.gpa = f.gpa;
        const ctx: engine.Context = .{ .zones = f.zones[1..2], .keys = &f.keys, .overlay = o, .now = tsig.vector.time, .mono = 1000 };
        const out = engine.respond(a, ctx, f.stream[0..len], &f.out, .tcp, null) orelse return error.NotResponse;
        try f.check(a, out, .tcp, f.stream[0..2]);
        const reply = wire.Message.parse(a, f.out[0..out]) catch return error.Reparse;
        const rcode: wire.Rcode = @enumFromInt(reply.flags.rcode);
        if (rcode != .formerr and reply.tsig_at == null) return error.Unsigned;
        if (rcode != .noerror and !unchanged(before, o)) return error.Atomicity;
        if (!invariants(&f.zones[1], o)) return error.Invariant;
    }

    fn applyUpdate(f: *Fixture, a: Allocator, packet: []const u8) Finding!void {
        const m = wire.Message.parse(a, packet) catch return;
        if (m.question.len != 1) return;
        _ = update.apply(&f.overlay, f.zones[1..2], m, "\x05hanko\x00", 1000);
        if (f.overlay.records.items.len > update.max_records) return error.Overflow;
        // A full overlay only answers SERVFAIL: start over before it fills up.
        if (f.overlay.records.items.len > 900) f.overlay.expire(std.math.maxInt(i64));
    }
};

// ---- update-state ------------------------------------------------------------------------------

const ch_label = "\x0f_acme-challenge";
/// UPDATE owners: plain, nested (its parent becomes an empty non-terminal), the apex, beside a
/// static TXT, at a static CNAME, outside the policy, mixed case, outside the zone.
const owners = [_][]const u8{
    ch_label ++ "\x03git\x07example\x03org\x00",
    ch_label ++ ch_label ++ "\x03git\x07example\x03org\x00",
    ch_label ++ "\x07example\x03org\x00",
    ch_label ++ "\x06static\x07example\x03org\x00",
    ch_label ++ "\x05alias\x07example\x03org\x00",
    "\x03www\x07example\x03org\x00",
    "\x0f_ACME-Challenge\x03GIT\x07example\x03org\x00",
    ch_label ++ "\x03git\x07example\x03net\x00",
};
const values = [_][]const u8{ "\x04tok1", "\x04tok2", "\x05fixed", "\x01x\x01y", "", "\x05ab" };
const fill_rdata = "\x04fill";

fn pick(rand: std.Random, comptime T: type, items: []const T) T {
    return items[rand.uintLessThan(usize, items.len)];
}

fn randomRRs(a: Allocator, rand: std.Random, max: usize, prereq: bool) Finding![]wire.RR {
    const rrs = a.alloc(wire.RR, rand.uintAtMost(usize, max)) catch return error.Memory;
    for (rrs) |*rr| rr.* = .{
        .name = pick(rand, []const u8, &owners),
        .type = pick(rand, wire.Type, &.{ .txt, .txt, .txt, .any, .a }),
        .class = pick(rand, wire.Class, &.{ .in, .in, .any, .none, @enumFromInt(3) }),
        .ttl = if (prereq and rand.uintLessThan(u8, 8) != 0) 0 else pick(rand, u32, &.{ 0, 30, 60, 3600 }),
        .rdata = pick(rand, []const u8, &values),
    };
    return rrs;
}

/// Fills the overlay with distinct records up to `n`.
fn fill(o: *update.Overlay, gpa: Allocator, n: usize) void {
    var i: usize = o.records.items.len;
    while (o.records.items.len < n) : (i += 1) {
        var buf: [64]u8 = undefined;
        const name = std.fmt.bufPrint(&buf, ch_label ++ "\x05f{d:0>4}\x07example\x03org\x00", .{i % 10000}) catch unreachable;
        o.records.append(gpa, .{ .name = gpa.dupe(u8, name) catch return, .rdata = gpa.dupe(u8, fill_rdata) catch return, .ttl = 60, .expires = std.math.maxInt(i64) }) catch return;
    }
}

fn snapshot(a: Allocator, o: *const update.Overlay) Finding![]update.Overlay.Record {
    const copy = a.alloc(update.Overlay.Record, o.records.items.len) catch return error.Memory;
    for (copy, o.records.items) |*c, r| c.* = .{ .name = a.dupe(u8, r.name) catch return error.Memory, .rdata = a.dupe(u8, r.rdata) catch return error.Memory, .ttl = r.ttl, .expires = r.expires };
    return copy;
}

fn unchanged(before: []const update.Overlay.Record, o: *const update.Overlay) bool {
    if (before.len != o.records.items.len) return false;
    for (before, o.records.items) |p, q| if (!std.mem.eql(u8, p.name, q.name) or !std.mem.eql(u8, p.rdata, q.rdata) or p.ttl != q.ttl or p.expires != q.expires) return false;
    return true;
}

/// ADR 0006 and valid RRsets: challenge TXT owners in the zone, capped TTLs, no duplicate, no
/// copy of a static value, nothing at a static CNAME.
fn invariants(z: *const zone.Zone, o: *const update.Overlay) bool {
    if (o.records.items.len > update.max_records) return false;
    for (o.records.items, 0..) |r, i| {
        if (!std.mem.startsWith(u8, r.name, ch_label) or !zone.isUnder(r.name, z.origin) or r.ttl > o.max_ttl) return false;
        if (z.lookup(r.name)) |name| {
            if (name.get(.cname) != null) return false;
            if (name.get(.txt)) |set| for (set.rdatas) |rd| if (std.mem.eql(u8, rd, r.rdata)) return false;
        }
        if (std.mem.eql(u8, r.rdata, fill_rdata)) continue; // fillers are distinct by construction
        for (o.records.items[i + 1 ..]) |q| if (std.mem.eql(u8, q.name, r.name) and std.mem.eql(u8, q.rdata, r.rdata)) return false;
    }
    return true;
}

fn same(x: wire.Message, y: wire.Message) bool {
    if (x.id != y.id or @as(u16, @bitCast(x.flags)) != @as(u16, @bitCast(y.flags)) or x.question.len != y.question.len) return false;
    for (x.question, y.question) |p, q| if (!std.mem.eql(u8, p.name, q.name) or p.type != q.type or p.class != q.class) return false;
    inline for (.{ "answer", "authority", "additional" }) |s| {
        const xs = @field(x, s);
        const ys = @field(y, s);
        if (xs.len != ys.len) return false;
        for (xs, ys) |p, q| if (!std.mem.eql(u8, p.name, q.name) or p.type != q.type or p.class != q.class or p.ttl != q.ttl or !std.mem.eql(u8, p.rdata, q.rdata)) return false;
    }
    return true;
}

// ---- mutator -----------------------------------------------------------------------------------

const interesting_bytes = [_]u8{ 0, 1, 2, 5, 12, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xc1, 0xfe, 0xff };
const interesting_words = [_]u16{ 0, 1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 250, 254, 255, 257, 0x0100, 0x00ff, 0x3fff, 0x4000, 0x8000, 0xc000, 0xc00c, 0xffff };

/// A copy of one seed with one to eight mutations; `buf` holds the result.
pub fn mutate(rand: std.Random, seeds: []const []const u8, buf: []u8) []u8 {
    const base = seeds[rand.uintLessThan(usize, seeds.len)];
    var len = base.len;
    @memcpy(buf[0..len], base);
    for (0..1 + rand.uintLessThan(usize, 8)) |_| {
        if (len == 0) {
            len = 1 + rand.uintLessThan(usize, 16);
            rand.bytes(buf[0..len]);
            continue;
        }
        const at = rand.uintLessThan(usize, len);
        switch (rand.uintLessThan(u8, 10)) {
            0 => buf[at] ^= @as(u8, 1) << rand.int(u3),
            1 => buf[at] = rand.int(u8),
            2 => buf[at] = interesting_bytes[rand.uintLessThan(usize, interesting_bytes.len)],
            3 => if (at + 2 <= len) std.mem.writeInt(u16, buf[at..][0..2], interesting_words[rand.uintLessThan(usize, interesting_words.len)], .big),
            4 => buf[at] +%= if (rand.boolean()) 1 else @as(u8, 0) -% 1,
            5 => { // delete a range
                const n = 1 + rand.uintLessThan(usize, @min(len - at, 32));
                std.mem.copyForwards(u8, buf[at .. len - n], buf[at + n .. len]);
                len -= n;
            },
            6 => { // insert random or repeated bytes
                if (len == buf.len) continue;
                const n = 1 + rand.uintLessThan(usize, @min(buf.len - len, 64));
                std.mem.copyBackwards(u8, buf[at + n .. len + n], buf[at..len]);
                if (rand.boolean()) rand.bytes(buf[at..][0..n]) else @memset(buf[at..][0..n], interesting_bytes[rand.uintLessThan(usize, interesting_bytes.len)]);
                len += n;
            },
            7 => { // copy a chunk from elsewhere in the input
                const from = rand.uintLessThan(usize, len);
                const n = rand.uintLessThan(usize, @min(len - from, len - at) + 1);
                std.mem.copyForwards(u8, buf[at..][0..n], buf[from..][0..n]);
            },
            8 => { // splice: the tail of another seed
                const other = seeds[rand.uintLessThan(usize, seeds.len)];
                if (other.len == 0) continue;
                const from = rand.uintLessThan(usize, other.len);
                const n = @min(other.len - from, buf.len - at);
                @memcpy(buf[at..][0..n], other[from..][0..n]);
                len = @max(len, at + n);
            },
            9 => len = at + 1, // truncate
            else => unreachable,
        }
    }
    return buf[0..len];
}

// ---- driver ------------------------------------------------------------------------------------

/// The input under test, for the panic handler and the watchdog.
var current: []const u8 = "";
var iterations = std.atomic.Value(u64).init(0);

pub const panic = std.debug.FullPanic(onPanic);

fn onPanic(msg: []const u8, first_trace_addr: ?usize) noreturn {
    report("panic", msg);
    std.debug.defaultPanic(msg, first_trace_addr);
}

fn report(kind: []const u8, detail: []const u8) void {
    std.debug.print("fuzz: {s} {s} input={x}\n", .{ kind, detail, current });
}

/// Aborts, printing the input, when no iteration completes for several seconds: a hang.
fn watchdog(io: std.Io) void {
    var last: u64 = 0;
    while (true) {
        io.sleep(.fromMilliseconds(3000), .awake) catch return;
        const n = iterations.load(.monotonic);
        if (n == last and n != 0) {
            report("hang", "no iteration finished in 3 s");
            std.process.abort();
        }
        last = n;
    }
}

const usage = "usage: annai-fuzz <codec|respond|update|update-state|tcp|forward> <seconds> [seed]\n";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 4) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    const target = std.meta.stringToEnum(Target, args[1]) orelse {
        std.debug.print(usage, .{});
        std.process.exit(2);
    };
    const seconds = std.fmt.parseInt(u64, args[2], 10) catch {
        std.debug.print(usage, .{});
        std.process.exit(2);
    };
    const io = init.io;
    const seed = if (args.len == 4) try std.fmt.parseInt(u64, args[3], 0) else @as(u64, @truncate(@as(u96, @bitCast(std.Io.Timestamp.now(io, .real).toNanoseconds()))));
    const gpa = std.heap.smp_allocator;
    const f = try Fixture.init(gpa);
    defer f.deinit();
    const buf = try gpa.alloc(u8, max_packet);
    defer gpa.free(buf);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();
    const dog = try std.Thread.spawn(.{}, watchdog, .{io});
    dog.detach();

    const start = std.Io.Timestamp.now(io, .awake);
    std.debug.print("fuzz: start target={s} seed={d} seeds={d} seconds={d}\n", .{ @tagName(target), seed, f.seeds.items.len, seconds });
    while (true) {
        const n = iterations.load(.monotonic);
        if (n % 256 == 0 and @divTrunc(start.durationTo(std.Io.Timestamp.now(io, .awake)).toMilliseconds(), 1000) >= seconds) break;
        const input = mutate(rand, f.seeds.items, buf);
        current = input;
        f.run(target, input) catch |e| {
            report("finding", @errorName(e));
            std.process.exit(1);
        };
        iterations.store(n + 1, .monotonic);
    }
    std.debug.print("fuzz: done target={s} seed={d} iterations={d} peak_request_bytes={d} peak_tcp_bytes={d}\n", .{ @tagName(target), seed, iterations.load(.monotonic), f.peak, f.peak_tcp_bytes });
}

// ---- corpus replay -----------------------------------------------------------------------------

test "TCP fuzzing charges server allocations to its memory oracle (review B4)" {
    const f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    // Fail before opening sockets: initialization must use this allocator, not the GPA.
    f.tcp_memory.fail_index = 0;
    try std.testing.expectError(error.Stream, f.run(.tcp, ""));
    try std.testing.expect(f.tcp_memory.has_induced_failure);
    f.tcp_memory.fail_index = std.math.maxInt(usize);
    const excess = try f.tcp_memory.allocator().alloc(u8, max_request_bytes + 1);
    defer f.tcp_memory.allocator().free(excess);
    f.tcp_memory.fail_index = f.tcp_memory.alloc_index;
    try std.testing.expectError(error.Memory, f.run(.tcp, ""));
    try std.testing.expect(f.peak_tcp_bytes > max_request_bytes);
}

test "the fuzz corpus and every seed replay through every target" {
    const f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    for (f.seeds.items) |packet| for (std.enums.values(Target)) |t| f.run(t, packet) catch |e| {
        std.debug.print("fuzz replay on {s}: {s} input={x}\n", .{ @tagName(t), @errorName(e), packet });
        return e;
    };
    var corpus = wire.Corpus.init(@embedFile("corpus/fuzz.txt"));
    var count: usize = 0;
    while (corpus.next()) |_| count += 1;
    try std.testing.expect(f.seeds.items.len > 48 + count);
}

test "the mutator stays within the buffer and is deterministic" {
    var prng = std.Random.DefaultPrng.init(7);
    var a: [300]u8 = undefined;
    var b: [300]u8 = undefined;
    const seeds = [_][]const u8{ "", "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01" };
    for (0..2000) |_| _ = mutate(prng.random(), &seeds, &a);
    var p1 = std.Random.DefaultPrng.init(9);
    var p2 = std.Random.DefaultPrng.init(9);
    for (0..100) |_| try std.testing.expectEqualSlices(u8, mutate(p1.random(), &seeds, &a), mutate(p2.random(), &seeds, &b));
}
