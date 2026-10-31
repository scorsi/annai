//! systemd's readiness protocol (sd_notify(3), ADR 0011) without libsystemd: one datagram per
//! message on the AF_UNIX socket named by `NOTIFY_SOCKET`. Without that variable (macOS, a manual
//! run) every call is a no-op.

const std = @import("std");
const posix = std.posix;
const sys = posix.system;

/// Sends `msg` to `socket_path` (`NOTIFY_SOCKET`; a leading `@` names a Linux abstract socket).
/// Best effort: systemd notices a missing READY=1 by its start or reload timeout.
pub fn send(socket_path: ?[]const u8, msg: []const u8) void {
    const path = socket_path orelse return;
    var addr: posix.sockaddr.un = .{ .path = @splat(0) };
    if (path.len == 0 or path.len >= addr.path.len) return;
    @memcpy(addr.path[0..path.len], path);
    if (path[0] == '@') addr.path[0] = 0;
    // An abstract name is exactly its bytes; a file path keeps its terminating zero.
    const len: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + @intFromBool(path[0] != '@'));
    const rc = sys.socket(posix.AF.UNIX, posix.SOCK.DGRAM, 0);
    if (posix.errno(rc) != .SUCCESS) return;
    const fd: posix.fd_t = @intCast(rc);
    defer _ = sys.close(fd);
    _ = sys.sendto(fd, msg.ptr, msg.len, 0, @ptrCast(&addr), len);
}

/// The message that starts a reload of a `Type=notify-reload` unit: READY=1 must follow.
pub fn reloading(buf: *[64]u8) []const u8 {
    var ts: posix.timespec = undefined;
    _ = sys.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    const usec = @as(u64, @intCast(ts.sec)) * std.time.us_per_s + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_us;
    return std.fmt.bufPrint(buf, "RELOADING=1\nMONOTONIC_USEC={d}", .{usec}) catch unreachable;
}

test "a datagram reaches the NOTIFY_SOCKET path; no variable, no message" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/n", .{tmp.sub_path});
    var addr: posix.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    const fd: posix.fd_t = @intCast(sys.socket(posix.AF.UNIX, posix.SOCK.DGRAM, 0));
    defer _ = sys.close(fd);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(sys.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.un))));

    send(null, "READY=1");
    var b: [64]u8 = undefined;
    send(path, reloading(&b));
    send(path, "READY=1");
    var got: [128]u8 = undefined;
    const n: usize = @intCast(sys.recvfrom(fd, &got, got.len, 0, null, null));
    try std.testing.expect(std.mem.startsWith(u8, got[0..n], "RELOADING=1\nMONOTONIC_USEC="));
    _ = try std.fmt.parseInt(u64, got["RELOADING=1\nMONOTONIC_USEC=".len..n], 10);
    try std.testing.expectEqualStrings("READY=1", got[0..@intCast(sys.recvfrom(fd, &got, got.len, 0, null, null))]);
}
