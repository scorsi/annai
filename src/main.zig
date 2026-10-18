const std = @import("std");
const config = @import("config.zig");
const zone = @import("zone.zig");
const server = @import("server.zig");
const tsig = @import("tsig.zig");
const wire = @import("wire.zig");

const usage = "usage: annai check <annai.toml> | annai serve <annai.toml>\n";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    // Long-lived data (config, zones) stays in this arena for the life of the process (ADR 0001).
    const loaded = load(init.io, init.arena.allocator(), args[2]) catch |e| switch (e) {
        error.Reported => std.process.exit(1),
        else => return e,
    };
    if (std.mem.eql(u8, args[1], "check")) return;
    if (!std.mem.eql(u8, args[1], "serve")) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    // Secrets are read only to serve: at build time `annai check` sees the paths, not the files.
    const keys = if (loaded.config.update) |u| loadKeys(init.io, init.arena.allocator(), u.keys) catch |e| switch (e) {
        error.Reported => std.process.exit(1),
        else => return e,
    } else &.{};
    // shortcut: a GeneralPurposeAllocator in debug builds (ADR 0001) waits for a reason to look for leaks.
    try server.Server.run(std.heap.smp_allocator, loaded.zones, loaded.config, keys);
}

/// Reads the TSIG secrets (ADR 0006). A key file holds one line: the base64 secret, optionally
/// prefixed with `<name>:` as in hanko's key files, so one sops secret can feed both products.
fn loadKeys(io: std.Io, a: std.mem.Allocator, refs: []const config.KeyRef) ![]tsig.Key {
    const keys = try a.alloc(tsig.Key, refs.len);
    for (refs, keys) |ref, *k| {
        k.* = .{ .name = ref.name, .secret = parseKey(a, ref.name, try read(io, a, ref.secret_file)) catch {
            std.debug.print("annai: {s}: expected one line, `<base64 secret>` or `{f}:<base64 secret>`\n", .{ ref.secret_file, zone.fmt(ref.name) });
            return error.Reported;
        } };
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
        for (zones[0..i]) |prev| if (std.mem.eql(u8, prev.origin, z.origin)) {
            std.debug.print("annai: {s}: origin is already loaded from another zone file\n", .{zone_path});
            return error.Reported;
        };
    }
    return .{ .config = cfg, .zones = zones };
}

fn read(io: std.Io, a: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(16 << 20)) catch |e| {
        std.debug.print("annai: {s}: {s}\n", .{ path, @errorName(e) });
        return error.Reported;
    };
}

fn report(e: config.Error, path: []const u8, d: *const config.Diag) error{ Reported, OutOfMemory } {
    if (e == error.OutOfMemory) return error.OutOfMemory;
    std.debug.print("annai: {s}: {s}\n", .{ path, d.msg });
    return error.Reported;
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
