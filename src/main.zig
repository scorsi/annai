const std = @import("std");
const config = @import("config.zig");
const zone = @import("zone.zig");
const server = @import("server.zig");
const tsig = @import("tsig.zig");
const wire = @import("wire.zig");
const log = @import("log.zig");
const notify = @import("notify.zig");

// Printed only for a wrong command line, which the unit's fixed `annai serve <path>` never is.
const usage = "usage: annai check <annai.toml> | annai serve <annai.toml>\n";

/// Every error leaves one schema v1 line (ADR 0011): a refused start reaches the journal.
pub fn main(init: std.process.Init) void {
    run(init) catch |e| {
        if (e != error.Reported) log.event(.@"error", "start-failed", .{ .err = @errorName(e) });
        std.process.exit(1);
    };
}

fn run(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    // Long-lived data (config, zones) stays in this arena for the life of the process (ADR 0001).
    const loaded = try load(init.io, init.arena.allocator(), args[2]);
    if (std.mem.eql(u8, args[1], "check")) return;
    if (!std.mem.eql(u8, args[1], "serve")) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    // Before anything can make systemd send it: SIGHUP's default action ends the process.
    const on_hup: std.posix.Sigaction = .{ .handler = .{ .handler = onHup }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
    std.posix.sigaction(.HUP, &on_hup, null);
    // Secrets are read only to serve: at build time `annai check` sees the paths, not the files.
    const keys = if (loaded.config.update) |u| try loadKeys(init.io, init.arena.allocator(), u.keys) else &.{};
    // shortcut: a GeneralPurposeAllocator in debug builds (ADR 0001) waits for a reason to look for leaks.
    const gpa = std.heap.smp_allocator;
    const s = try server.Server.init(gpa, loaded.zones, loaded.config, keys);
    defer s.deinit();
    // Type=notify-reload (ADR 0011): active once every listener is bound and every zone loaded.
    const notify_socket = init.environ_map.get("NOTIFY_SOCKET");
    notify.send(notify_socket, "READY=1");
    // The first generation lives in the process arena; each reload gets its own, freed by the next.
    var current: ?State = null;
    defer if (current) |*c| c.arena.deinit();
    while (true) {
        // shortcut: the poller retries on EINTR, so a SIGHUP waits for the next wake (at most
        // ~1 s); systemd waits for READY=1 anyway.
        try s.step(1000);
        if (!hup.swap(false, .acq_rel)) continue;
        var b: [64]u8 = undefined;
        notify.send(notify_socket, notify.reloading(&b));
        // One query is answered entirely on one state: the loop is single-threaded (ADR 0001).
        if (reread(init.io, gpa, args[2], loaded.config, s)) |next| {
            if (current) |*c| c.arena.deinit();
            current = next;
            s.metrics.reload(.ok);
            log.event(.info, "reload", .{ .zones = next.zones.len, .keys = next.keys.len });
        } else |e| {
            s.metrics.reload(.failed);
            log.event(.@"error", "reload-failed", .{ .err = if (e == error.Reported) "invalid configuration, previous zones and keys kept" else @errorName(e) });
        }
        notify.send(notify_socket, "READY=1");
    }
}

var hup = std.atomic.Value(bool).init(false);

fn onHup(_: std.posix.SIG) callconv(.c) void {
    hup.store(true, .release);
}

/// One reloaded generation of zones and keys, in its own arena.
const State = struct { arena: std.heap.ArenaAllocator, zones: []const zone.Zone, keys: []const tsig.Key };

/// Re-reads `path` and its zones and key files, and hands them to `s` (ADR 0003, ADR 0011). Only
/// zones and update keys reload: any other difference from `running` needs a restart. On error
/// nothing changed and the reason is already logged when it is `error.Reported`.
fn reread(io: std.Io, gpa: std.mem.Allocator, path: []const u8, running: config.Config, s: *server.Server) !State {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const loaded = try load(io, a, path);
    if (!eql(restartOnly(loaded.config), restartOnly(running)))
        return fail("config-invalid", "{s}: only zones and update keys reload; restart annai to apply other changes", .{path});
    const keys = if (loaded.config.update) |u| try loadKeys(io, a, u.keys) else &.{};
    try s.reload(loaded.zones, keys);
    return .{ .arena = arena, .zones = loaded.zones, .keys = keys };
}

/// `c` without what a reload may change.
fn restartOnly(c: config.Config) config.Config {
    var r = c;
    r.zones = &.{};
    if (r.update) |*u| u.keys = &.{};
    return r;
}

/// Deep equality of configuration values: slices by content.
fn eql(a: anytype, b: @TypeOf(a)) bool {
    switch (@typeInfo(@TypeOf(a))) {
        .pointer => {
            if (a.len != b.len) return false;
            for (a, b) |x, y| if (!eql(x, y)) return false;
            return true;
        },
        .optional => return if (a) |x| (if (b) |y| eql(x, y) else false) else b == null,
        .@"struct" => |s| {
            inline for (s.fields) |f| if (!eql(@field(a, f.name), @field(b, f.name))) return false;
            return true;
        },
        else => return std.meta.eql(a, b),
    }
}

/// Reads the TSIG secrets (ADR 0006). A key file holds one line: the base64 secret, optionally
/// prefixed with `<name>:` as in hanko's key files, so one sops secret can feed both products.
fn loadKeys(io: std.Io, a: std.mem.Allocator, refs: []const config.KeyRef) ![]tsig.Key {
    const keys = try a.alloc(tsig.Key, refs.len);
    for (refs, keys) |ref, *k| {
        k.* = .{ .name = ref.name, .secret = parseKey(a, ref.name, try read(io, a, ref.secret_file)) catch
            return fail("key-invalid", "{s}: expected one line, `<base64 secret>` or `{f}:<base64 secret>`", .{ ref.secret_file, zone.fmt(ref.name) }) };
    }
    return keys;
}

fn parseKey(a: std.mem.Allocator, name: []const u8, text: []const u8) ![]const u8 {
    const line = std.mem.trim(u8, text, " \t\r\n");
    const b64 = if (std.mem.lastIndexOfScalar(u8, line, ':')) |i| blk: {
        var buf: [255]u8 = undefined;
        const n = try wire.nameFromText(&buf, line[0..i]);
        if (!std.mem.eql(u8, zone.lower(buf[0..n.len]), name)) return error.OtherKey;
        break :blk line[i + 1 ..];
    } else line;
    const decoder = std.base64.standard.Decoder;
    const secret = try a.alloc(u8, try decoder.calcSizeForSlice(b64));
    try decoder.decode(secret, b64);
    if (secret.len == 0) return error.Empty;
    return secret;
}

const Loaded = struct { config: config.Config, zones: []const zone.Zone };

/// Reads annai.toml and loads every zone it references (ADR 0003): `annai check` stops here.
fn load(io: std.Io, a: std.mem.Allocator, path: []const u8) !Loaded {
    var d: config.Diag = .{};
    const cfg = config.checkConfig(a, try read(io, a, path), &d) catch |e| return report(e, path, &d);
    const zones = try a.alloc(zone.Zone, cfg.zones.len);
    for (cfg.zones, zones, 0..) |rel, *z, i| {
        const zone_path = if (std.fs.path.isAbsolute(rel)) rel else try std.fs.path.join(a, &.{ std.fs.path.dirname(path) orelse ".", rel });
        z.* = config.loadZone(a, try read(io, a, zone_path), &d) catch |e| return report(e, zone_path, &d);
        for (zones[0..i]) |prev| if (std.mem.eql(u8, prev.origin, z.origin))
            return fail("config-invalid", "{s}: origin is already loaded from another zone file", .{zone_path});
    }
    return .{ .config = cfg, .zones = zones };
}

fn read(io: std.Io, a: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(16 << 20)) catch |e|
        fail("read-failed", "{s}: {s}", .{ path, @errorName(e) });
}

fn report(e: config.Error, path: []const u8, d: *const config.Diag) error{ Reported, OutOfMemory } {
    if (e == error.OutOfMemory) return error.OutOfMemory;
    return fail("config-invalid", "{s}: {s}", .{ path, d.msg });
}

/// Writes the `error` line of a refused `check` or start, `err` = `<path>: <message>`.
fn fail(comptime name: []const u8, comptime fmt: []const u8, args: anytype) error{Reported} {
    var buf: [1536]u8 = undefined;
    log.event(.@"error", name, .{ .err = errText(&buf, fmt, args) });
    return error.Reported;
}

fn errText(buf: []u8, comptime fmt: []const u8, args: anytype) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.print(fmt, args) catch {}; // shortcut: truncated past 1.5 KiB; Diag messages stop at 1 KiB
    return w.buffered();
}

test {
    _ = config;
    _ = wire;
    _ = zone;
    _ = @import("engine.zig");
    _ = server;
    _ = @import("forward.zig");
    _ = tsig;
    _ = @import("update.zig");
    _ = @import("fuzz.zig");
    _ = @import("log.zig");
    _ = @import("metrics.zig");
    _ = notify;
}

test "key files: bare base64 or hanko's name:base64, same key only" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectEqualStrings("secret", try parseKey(a, "\x05hanko\x00", "c2VjcmV0\n"));
    try std.testing.expectEqualStrings("secret", try parseKey(a, "\x05hanko\x00", "Hanko.:c2VjcmV0"));
    try std.testing.expectEqualStrings("secret", try parseKey(a, "\x05hanko\x07example\x03org\x00", "hanko.example.org:c2VjcmV0"));
    try std.testing.expectError(error.OtherKey, parseKey(a, "\x05hanko\x00", "other:c2VjcmV0"));
    try std.testing.expectError(error.Empty, parseKey(a, "\x05hanko\x00", ""));
    try std.testing.expectError(error.InvalidCharacter, parseKey(a, "\x05hanko\x00", "!!!!"));
}

test "a refused check is one schema v1 error line" {
    var b: [256]u8 = undefined;
    var line: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line);
    try log.writeLine(&w, 0, .@"error", "config-invalid", .{ .err = errText(&b, "{s}: {s}", .{ "/nix/store/x-annai.toml", "metrics: \"0.0.0.0:9153\" is not loopback" }) });
    try std.testing.expectEqualStrings(
        \\{"v":1,"ts":"1970-01-01T00:00:00.000000000Z","level":"error","event":"config-invalid","err":"/nix/store/x-annai.toml: metrics: \"0.0.0.0:9153\" is not loopback"}
    ++ "\n", w.buffered());
}

test "reread: zones and keys are swapped in; an invalid file or a restart-only change keeps the old ones (ADR 0011)" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const engine = @import("engine.zig");
    const path = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/annai.toml", .{tmp.sub_path});
    try tmp.dir.writeFile(io, .{ .sub_path = "hanko.key", .data = "hanko:c2VjcmV0\n" });
    const key_path = try tmp.dir.realPathFileAlloc(io, "hanko.key", a);
    const toml = "mode = \"soto\"\nlisten = [\"192.0.2.1:53\"]\nzones = [\"zone.toml\"]\n[[update.keys]]\nname = \"hanko\"\nsecret_file = \"{s}\"\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "annai.toml", .data = try std.fmt.allocPrint(a, toml, .{key_path}) });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.toml", .data = engine.test_zone });
    const running = (try load(io, a, path)).config;

    const l = try server.Loopback.init(std.testing.allocator, .{});
    defer l.deinit();
    var first = try reread(io, std.testing.allocator, path, running, l.server);
    defer first.arena.deinit();
    try std.testing.expectEqual(first.zones.ptr, l.server.zones.ptr);
    try std.testing.expectEqualStrings("secret", l.server.keys[0].secret);

    // A rotated secret and a new name.
    const zone2 = engine.test_zone ++ "[names.\"new\"]\na = [\"192.0.2.9\"]\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "hanko.key", .data = "b3RoZXI=" });
    try tmp.dir.writeFile(io, .{ .sub_path = "zone.toml", .data = zone2 });
    var second = try reread(io, std.testing.allocator, path, running, l.server);
    defer second.arena.deinit();
    try std.testing.expectEqualStrings("other", l.server.keys[0].secret);
    try std.testing.expect(l.server.zones[0].names.contains("\x03new\x04uchi\x07example\x03org\x00"));

    // Each of these leaves the second generation in place.
    const broken = [_]struct { []const u8, []const u8, []const u8 }{
        .{ "zone.toml", engine.test_zone ++ "[names.\"bad\"]\ncname = \"a\"\na = [\"192.0.2.1\"]\n", zone2 },
        .{ "hanko.key", "!!!!", "b3RoZXI=" },
        .{ "annai.toml", try std.fmt.allocPrint(a, "mode = \"soto\"\nlisten = [\"192.0.2.2:53\"]\nzones = [\"zone.toml\"]\n[[update.keys]]\nname = \"hanko\"\nsecret_file = \"{s}\"\n", .{key_path}), "" },
    };
    for (broken) |b| {
        try tmp.dir.writeFile(io, .{ .sub_path = b[0], .data = b[1] });
        defer if (b[2].len > 0) tmp.dir.writeFile(io, .{ .sub_path = b[0], .data = b[2] }) catch {};
        try std.testing.expectError(error.Reported, reread(io, std.testing.allocator, path, running, l.server));
        try std.testing.expectEqual(second.zones.ptr, l.server.zones.ptr);
        try std.testing.expectEqualStrings("other", l.server.keys[0].secret);
    }
}
