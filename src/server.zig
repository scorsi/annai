//! UDP and TCP listeners on the single-threaded poller of ADR 0001. Each query is answered by
//! `engine.respond` from a per-request arena; TCP connections (RFC 7766) get an idle timeout and
//! a message cap (ADR 0007). Sockets go through `std.posix.system` directly: libc on macOS, raw
//! syscalls in the static musl binary on Linux.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const net = std.Io.net;
const engine = @import("engine.zig");
const zone = @import("zone.zig");
const poll = @import("poll.zig");

const max_message = 65535;
const idle_timeout_ms = 10_000; // RFC 7766 §6.2.3: a few seconds of idle time
const max_messages_per_conn = 100;
const max_conns = 64;
const backlog = 128;
const is_linux = builtin.os.tag == .linux;
/// std.c has no IPV6 options for darwin; 27 is IPV6_V6ONLY from <netinet6/in6.h>.
const ipv6_v6only: u32 = if (is_linux) posix.IPV6.V6ONLY else 27;

const PosixAddress = extern union { any: posix.sockaddr, in: posix.sockaddr.in, in6: posix.sockaddr.in6, storage: posix.sockaddr.storage };

const Conn = struct {
    fd: posix.fd_t,
    deadline: i64,
    len: usize = 0,
    messages: u32 = 0,
    buf: [2 + max_message]u8 = undefined,
};

const Slot = union(enum) { free, udp: posix.fd_t, listener: posix.fd_t, conn: Conn };

pub const Server = struct {
    zones: []const zone.Zone,
    poller: poll.Poller,
    slots: []Slot,
    arena: std.heap.ArenaAllocator,
    in: [max_message]u8 = undefined,
    /// Two leading bytes for the TCP length prefix; UDP answers start at 2.
    out: [2 + max_message]u8 = undefined,

    /// Binds every address (UDP and TCP) and serves forever.
    pub fn run(gpa: std.mem.Allocator, zones: []const zone.Zone, listen: []const net.IpAddress) !void {
        const s = try gpa.create(Server);
        defer gpa.destroy(s);
        s.* = .{ .zones = zones, .poller = try poll.Poller.init(), .slots = try gpa.alloc(Slot, 2 * listen.len + max_conns), .arena = std.heap.ArenaAllocator.init(gpa) };
        defer gpa.free(s.slots);
        defer s.arena.deinit();
        @memset(s.slots, .free);
        for (listen, 0..) |addr, i| {
            const udp = try open(addr, posix.SOCK.DGRAM);
            s.slots[2 * i] = .{ .udp = udp };
            try s.poller.add(udp, 2 * i);
            const tcp = try open(addr, posix.SOCK.STREAM);
            s.slots[2 * i + 1] = .{ .listener = tcp };
            try s.poller.add(tcp, 2 * i + 1);
            std.debug.print("level=info event=listen addr={f}\n", .{addr});
        }
        var events: [64]poll.Event = undefined;
        while (true) {
            for (try s.poller.wait(&events, 1000)) |ev| switch (s.slots[ev.token]) {
                .udp => |fd| s.serveUdp(fd),
                .listener => |fd| s.accept(fd),
                .conn => |*c| s.serveTcp(ev.token, c),
                .free => {},
            };
            const now = nowMs();
            for (s.slots, 0..) |slot, i| if (slot == .conn and slot.conn.deadline <= now) s.close(i);
        }
    }

    fn respond(s: *Server, packet: []const u8, transport: engine.Transport) ?[]const u8 {
        defer _ = s.arena.reset(.retain_capacity);
        const n = engine.respond(s.arena.allocator(), s.zones, packet, s.out[2..], transport) orelse return null;
        return s.out[2 .. 2 + n];
    }

    fn serveUdp(s: *Server, fd: posix.fd_t) void {
        var peer: PosixAddress = undefined;
        var peer_len: posix.socklen_t = @sizeOf(PosixAddress);
        const rc = sys.recvfrom(fd, &s.in, s.in.len, 0, &peer.any, &peer_len);
        if (posix.errno(rc) != .SUCCESS) return; // EAGAIN or a transient ICMP error: nothing to answer
        const reply = s.respond(s.in[0..@intCast(rc)], .udp) orelse return;
        _ = sys.sendto(fd, reply.ptr, reply.len, 0, &peer.any, peer_len);
    }

    fn accept(s: *Server, fd: posix.fd_t) void {
        const rc = if (is_linux) sys.accept4(fd, null, null, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK) else sys.accept(fd, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR, .CONNABORTED => return,
            else => |e| return std.debug.print("level=warn event=accept errno={s}\n", .{@tagName(e)}),
        }
        const cfd: posix.fd_t = @intCast(rc);
        const slot = for (s.slots, 0..) |slot, i| {
            if (slot == .free) break i;
        } else {
            std.debug.print("level=warn event=tcp-refused reason=connection-cap\n", .{});
            _ = sys.close(cfd);
            return;
        };
        if (!is_linux) nonblocking(cfd) catch {
            _ = sys.close(cfd);
            return;
        };
        s.slots[slot] = .{ .conn = .{ .fd = cfd, .deadline = nowMs() + idle_timeout_ms } };
        s.poller.add(cfd, slot) catch s.close(slot);
    }

    fn serveTcp(s: *Server, token: usize, c: *Conn) void {
        const rc = sys.recvfrom(c.fd, c.buf[c.len..].ptr, c.buf.len - c.len, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR => return,
            else => return s.close(token),
        }
        const n: usize = @intCast(rc);
        if (n == 0) return s.close(token); // peer closed
        c.len += n;
        c.deadline = nowMs() + idle_timeout_ms;
        while (c.len >= 2) {
            const mlen = std.mem.readInt(u16, c.buf[0..2], .big);
            if (c.len < 2 + mlen) return;
            c.messages += 1;
            if (c.messages > max_messages_per_conn) return s.close(token);
            if (s.respond(c.buf[2 .. 2 + mlen], .tcp)) |reply| {
                std.mem.writeInt(u16, s.out[0..2], @intCast(reply.len), .big);
                sendAll(c.fd, s.out[0 .. 2 + reply.len]) catch return s.close(token);
            }
            std.mem.copyForwards(u8, &c.buf, c.buf[2 + mlen .. c.len]);
            c.len -= 2 + mlen;
        }
    }

    fn close(s: *Server, token: usize) void {
        const fd = s.slots[token].conn.fd;
        s.poller.remove(fd);
        _ = sys.close(fd);
        s.slots[token] = .free;
    }
};

/// Writes the whole buffer; when the socket buffer is full, waits for it up to one second.
fn sendAll(fd: posix.fd_t, data: []const u8) error{Closed}!void {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = sys.sendto(fd, data[sent..].ptr, data.len - sent, 0, null, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => sent += @intCast(rc),
            .INTR => {},
            // shortcut: this blocks the loop for a slow client; upgrade to write-readiness events if TCP ever carries volume.
            .AGAIN => {
                var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                const ready = posix.poll(&fds, 1000) catch return error.Closed;
                if (ready == 0) return error.Closed;
            },
            else => return error.Closed,
        }
    }
}

fn open(addr: net.IpAddress, kind: u32) !posix.fd_t {
    const family: u32 = switch (addr) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const flags: u32 = if (is_linux) posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK else 0;
    const rc = sys.socket(family, kind | flags, 0);
    try check(rc, "socket", addr);
    const fd: posix.fd_t = @intCast(rc);
    errdefer _ = sys.close(fd);
    if (!is_linux) try nonblocking(fd);
    const one = std.mem.toBytes(@as(c_int, 1));
    if (kind == posix.SOCK.STREAM) try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one);
    // The deployment listens on overlay addresses that may appear after the unit starts.
    if (is_linux) try posix.setsockopt(fd, posix.IPPROTO.IP, posix.IP.FREEBIND, &one);
    // A `[::]` listener must not swallow `0.0.0.0`: both are bound explicitly (ADR 0007).
    if (addr == .ip6) try posix.setsockopt(fd, posix.IPPROTO.IPV6, ipv6_v6only, &one);
    var storage: PosixAddress = undefined;
    const len: posix.socklen_t = switch (addr) {
        .ip4 => |ip4| blk: {
            storage.in = .{ .family = posix.AF.INET, .port = std.mem.nativeToBig(u16, ip4.port), .addr = @bitCast(ip4.bytes) };
            break :blk @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| blk: {
            storage.in6 = .{ .family = posix.AF.INET6, .port = std.mem.nativeToBig(u16, ip6.port), .flowinfo = 0, .addr = ip6.bytes, .scope_id = ip6.interface.index };
            break :blk @sizeOf(posix.sockaddr.in6);
        },
    };
    try check(sys.bind(fd, &storage.any, len), "bind", addr);
    if (kind == posix.SOCK.STREAM) try check(sys.listen(fd, backlog), "listen", addr);
    return fd;
}

fn check(rc: anytype, what: []const u8, addr: net.IpAddress) error{Listen}!void {
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            std.debug.print("level=error event={s} addr={f} errno={s}\n", .{ what, addr, @tagName(e) });
            return error.Listen;
        },
    }
}

/// O_NONBLOCK and FD_CLOEXEC where socket(2)/accept(2) cannot set them (macOS).
fn nonblocking(fd: posix.fd_t) error{Fcntl}!void {
    const Arg = if (is_linux) usize else c_int;
    const got = sys.fcntl(fd, posix.F.GETFL, @as(Arg, 0));
    if (posix.errno(got) != .SUCCESS) return error.Fcntl;
    const nonblock: Arg = 1 << @bitOffsetOf(posix.O, "NONBLOCK");
    if (posix.errno(sys.fcntl(fd, posix.F.SETFL, @as(Arg, @intCast(got)) | nonblock)) != .SUCCESS) return error.Fcntl;
    if (posix.errno(sys.fcntl(fd, posix.F.SETFD, @as(Arg, posix.FD_CLOEXEC))) != .SUCCESS) return error.Fcntl;
}

fn nowMs() i64 {
    var ts: posix.timespec = undefined;
    _ = sys.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000_000);
}
