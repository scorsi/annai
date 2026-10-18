//! Fuzzing harness for the codec and the UPDATE/TSIG paths (ADR 0009, 0011; M4). The pinned Zig
//! 0.16.0 cannot build its own fuzzer (`zig build test --fuzz` fails to compile test_runner.zig),
//! so this is a seeded mutator over the corpora with oracles stronger than "no crash": whatever
//! parses must encode and parse back identical, whatever the engine emits must parse, stay within
//! the transport limit and keep the query ID, and a request must never take more than
//! `max_request_bytes`. Crashes, safety traps and hangs print the input in hex as well.
//!
//! By hand: `zig build fuzz -- <codec|respond|update> <seconds> [seed]` (or `nix run .#fuzz`, in
//! ReleaseSafe); findings are `fuzz: ...` lines on stderr. Every finding becomes a line of
//! src/corpus/fuzz.txt, which `zig build test` replays through every target.

const std = @import("std");
const wire = @import("wire.zig");
const zone = @import("zone.zig");
const engine = @import("engine.zig");
const update = @import("update.zig");
const tsig = @import("tsig.zig");
const config = @import("config.zig");
const Allocator = std.mem.Allocator;

pub const Target = enum { codec, respond, update };

/// Per-request memory a message of at most 64 KiB may take; more is a finding.
pub const max_request_bytes = 8 << 20;
const max_packet = 65535;

pub const Finding = error{ Encode, Reparse, RoundTrip, Oversize, IdLost, NotResponse, Memory, Overflow };

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

    pub fn init(gpa: Allocator) !*Fixture {
        const f = try gpa.create(Fixture);
        errdefer gpa.destroy(f);
        f.* = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa), .zones = undefined, .overlay = update.Overlay.init(gpa, 120, 3600), .fba = undefined };
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

    fn applyUpdate(f: *Fixture, a: Allocator, packet: []const u8) Finding!void {
        const m = wire.Message.parse(a, packet) catch return;
        if (m.question.len != 1) return;
        _ = update.apply(&f.overlay, f.zones[1..2], m, "\x05hanko\x00", 1000);
        if (f.overlay.records.items.len > update.max_records) return error.Overflow;
        // A full overlay only answers SERVFAIL: start over before it fills up.
        if (f.overlay.records.items.len > 900) f.overlay.expire(std.math.maxInt(i64));
    }
};

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

const usage = "usage: annai-fuzz <codec|respond|update> <seconds> [seed]\n";

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
    std.debug.print("fuzz: done target={s} seed={d} iterations={d} peak_request_bytes={d}\n", .{ @tagName(target), seed, iterations.load(.monotonic), f.peak });
}

// ---- corpus replay -----------------------------------------------------------------------------

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
