const std = @import("std");
const config = @import("config.zig");

const usage = "usage: annai check <annai.toml>\n";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 or !std.mem.eql(u8, args[1], "check")) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    check(init.io, init.arena.allocator(), args[2]) catch |e| switch (e) {
        error.Reported => std.process.exit(1),
        else => return e,
    };
}

/// `annai check`: validates annai.toml and every zone it references (ADR 0003).
fn check(io: std.Io, a: std.mem.Allocator, path: []const u8) !void {
    var d: config.Diag = .{};
    const cfg = config.checkConfig(a, try read(io, a, path), &d) catch |e| return report(e, path, &d);
    var origins: std.StringHashMapUnmanaged([]const u8) = .empty;
    for (cfg.zones) |zone| {
        const zone_path = if (std.fs.path.isAbsolute(zone)) zone else try std.fs.path.join(a, &.{ std.fs.path.dirname(path) orelse ".", zone });
        const origin = config.checkZone(a, try read(io, a, zone_path), &d) catch |e| return report(e, zone_path, &d);
        const seen = try origins.getOrPut(a, origin);
        if (seen.found_existing) {
            std.debug.print("annai check: {s}: origin {s} is already loaded from {s}\n", .{ zone_path, origin, seen.value_ptr.* });
            return error.Reported;
        }
        seen.value_ptr.* = zone_path;
    }
}

fn read(io: std.Io, a: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, a, .limited(16 << 20)) catch |e| {
        std.debug.print("annai check: {s}: {s}\n", .{ path, @errorName(e) });
        return error.Reported;
    };
}

fn report(e: config.Error, path: []const u8, d: *const config.Diag) error{ Reported, OutOfMemory } {
    if (e == error.OutOfMemory) return error.OutOfMemory;
    std.debug.print("annai check: {s}: {s}\n", .{ path, d.msg });
    return error.Reported;
}

test {
    _ = config;
}
