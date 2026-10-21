//! The poller of ADR 0001: readiness events from kqueue (macOS) or epoll (Linux), behind one small
//! interface. Each registered descriptor carries a caller token and waits for one thing at a
//! time: input (the default), room to write (a TCP answer the socket did not take), or nothing.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub const Event = struct { token: usize, fatal: bool };
pub const Interest = enum { read, write, none };

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
            @import("log.zig").event(.@"error", "poller", .{ .err = @tagName(e) });
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

    /// What a registered descriptor waits for from now on.
    pub fn set(p: *Epoll, fd: posix.fd_t, token: usize, interest: Interest) Error!void {
        const events: u32 = switch (interest) {
            .read => linux.EPOLL.IN,
            .write => linux.EPOLL.OUT,
            .none => 0, // hangups and errors are still reported
        };
        var ev: linux.epoll_event = .{ .events = events, .data = .{ .ptr = token } };
        try check(linux.epoll_ctl(p.fd, linux.EPOLL.CTL_MOD, fd, &ev));
    }

    /// Blocks up to `timeout_ms` (-1 forever); returns the ready events.
    pub fn wait(p: *Epoll, events: []Event, timeout_ms: i32) Error![]Event {
        var raw: [64]linux.epoll_event = undefined;
        const max: u32 = @intCast(@min(raw.len, events.len));
        while (true) {
            const rc = linux.epoll_wait(p.fd, &raw, max, timeout_ms);
            if (posix.errno(rc) == .INTR) continue;
            try check(rc);
            for (raw[0..rc], events[0..rc]) |r, *e| e.* = .{ .token = r.data.ptr, .fatal = r.events & (linux.EPOLL.ERR | linux.EPOLL.HUP) != 0 };
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
        // One call per filter: the write filter may never have been added.
        for ([_]i16{ c.EVFILT.READ, c.EVFILT.WRITE }) |filter| {
            var change = [_]c.Kevent{.{ .ident = @intCast(fd), .filter = filter, .flags = c.EV.DELETE, .fflags = 0, .data = 0, .udata = 0 }};
            _ = c.kevent(p.fd, &change, 1, &change, 0, null);
        }
    }

    /// What a registered descriptor waits for from now on.
    pub fn set(p: *Kqueue, fd: posix.fd_t, token: usize, interest: Interest) Error!void {
        const on = c.EV.ADD | c.EV.ENABLE;
        const off = c.EV.ADD | c.EV.DISABLE;
        // Keep reset notifications while reads pause; EV_CLEAR avoids spinning on buffered data or a half-close.
        var changes = [_]c.Kevent{
            // EV_ADD alone does not replace EV_CLEAR on an existing macOS filter.
            .{ .ident = @intCast(fd), .filter = c.EVFILT.READ, .flags = c.EV.DELETE, .fflags = 0, .data = 0, .udata = token },
            .{ .ident = @intCast(fd), .filter = c.EVFILT.READ, .flags = switch (interest) {
                .read => on,
                .write => off,
                .none => on | c.EV.CLEAR,
            }, .fflags = 0, .data = 0, .udata = token },
            .{ .ident = @intCast(fd), .filter = c.EVFILT.WRITE, .flags = if (interest == .write) on else off, .fflags = 0, .data = 0, .udata = token },
        };
        try check(c.kevent(p.fd, &changes, changes.len, &changes, 0, null));
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
            for (raw[0..n], events[0..n]) |r, *e| e.* = .{
                .token = r.udata,
                // Read EOF without an error is a half-close: the client can still receive replies.
                .fatal = r.flags & c.EV.ERROR != 0 or (r.flags & c.EV.EOF != 0 and (r.fflags != 0 or r.filter == c.EVFILT.WRITE)),
            };
            return events[0..n];
        }
    }
};
