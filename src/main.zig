const std = @import("std");
const config = @import("config.zig");
const zone = @import("zone.zig");
const server = @import("server.zig");

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
    if (loaded.config.mode == .uchi) std.debug.print("level=warn event=no-forwarder detail=\"queries outside the zones are REFUSED until M2\"\n", .{});
    // shortcut: a GeneralPurposeAllocator in debug builds (ADR 0001) waits for a reason to look for leaks.
    try server.Server.run(std.heap.page_allocator, loaded.zones, loaded.config.listen);
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
    _ = @import("wire.zig");
    _ = zone;
    _ = @import("engine.zig");
    _ = server;
}
