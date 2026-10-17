//! The poller of ADR 0001: readiness-to-read events from kqueue (macOS) or epoll (Linux), behind
//! one small interface. Each registered descriptor carries a caller token.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const Event = struct { token: usize };

pub const Poller = switch (builtin.os.tag) {
    .linux => Epoll,
    .macos => Kqueue,
    else => @compileError("annai runs on Linux and macOS only (ADR 0001)"),
};

pub const Error = error{Unexpected};

fn check(rc: anytype) Error!void {
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            std.debug.print("level=error event=poller errno={s}\n", .{@tagName(e)});
            return error.Unexpected;
        },
    }
}

const Epoll = struct {
    const linux = std.os.linux;
    fd: i32,

    pub fn init() Error!Epoll {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        try check(rc);
        return .{ .fd = @intCast(rc) };
    }

    pub fn add(p: *Epoll, fd: posix.fd_t, token: usize) Error!void {
        var ev: linux.epoll_event = .{ .events = linux.EPOLL.IN, .data = .{ .ptr = token } };
        try check(linux.epoll_ctl(p.fd, linux.EPOLL.CTL_ADD, fd, &ev));
    }

    pub fn remove(p: *Epoll, fd: posix.fd_t) void {
        _ = linux.epoll_ctl(p.fd, linux.EPOLL.CTL_DEL, fd, null);
    }

    /// Blocks up to `timeout_ms` (-1 forever); returns the ready events.
    pub fn wait(p: *Epoll, events: []Event, timeout_ms: i32) Error![]Event {
        var raw: [64]linux.epoll_event = undefined;
        const max: u32 = @intCast(@min(raw.len, events.len));
        while (true) {
            const rc = linux.epoll_wait(p.fd, &raw, max, timeout_ms);
            if (posix.errno(rc) == .INTR) continue;
            try check(rc);
            for (raw[0..rc], events[0..rc]) |r, *e| e.* = .{ .token = r.data.ptr };
            return events[0..rc];
        }
    }
};

const Kqueue = struct {
    const c = std.c;
    fd: i32,

    pub fn init() Error!Kqueue {
        const rc = c.kqueue();
        try check(rc);
        return .{ .fd = rc };
    }

    pub fn add(p: *Kqueue, fd: posix.fd_t, token: usize) Error!void {
        var change = [_]c.Kevent{.{ .ident = @intCast(fd), .filter = c.EVFILT.READ, .flags = c.EV.ADD, .fflags = 0, .data = 0, .udata = token }};
        try check(c.kevent(p.fd, &change, 1, &change, 0, null));
    }

    pub fn remove(p: *Kqueue, fd: posix.fd_t) void {
        var change = [_]c.Kevent{.{ .ident = @intCast(fd), .filter = c.EVFILT.READ, .flags = c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 }};
        _ = c.kevent(p.fd, &change, 1, &change, 0, null);
    }

    pub fn wait(p: *Kqueue, events: []Event, timeout_ms: i32) Error![]Event {
        var raw: [64]c.Kevent = undefined;
        const max: c_int = @intCast(@min(raw.len, events.len));
        const ts: c.timespec = .{ .sec = @divTrunc(timeout_ms, 1000), .nsec = @rem(timeout_ms, 1000) * 1_000_000 };
        while (true) {
            const rc = c.kevent(p.fd, &raw, 0, &raw, max, if (timeout_ms < 0) null else &ts);
            if (posix.errno(rc) == .INTR) continue;
            try check(rc);
            const n: usize = @intCast(rc);
            for (raw[0..n], events[0..n]) |r, *e| e.* = .{ .token = r.udata };
            return events[0..n];
        }
    }
};
