//! UDP and TCP listeners on the single-threaded poller of ADR 0001. Each query is answered by
//! `engine.respond` from a per-request arena; TCP connections (RFC 7766) get an idle timeout and
//! a message cap (ADR 0007). Sockets go through `std.posix.system` directly: libc on macOS, raw
//! syscalls in the static musl binary on Linux.
//!
//! In uchi mode with `[forwarding]` (ADR 0008), names outside the zones are answered from the
//! cache or forwarded: one pending upstream query per (name, type) gathers every client asking
//! it (in-flight coalescing), on its own connected UDP socket (kernel-random source port, so the
//! kernel drops datagrams from any other address) with a random ID; the answer must match ID and
//! question (RFC 5452). Timeout, error, SERVFAIL or REFUSED moves on to the next upstream; TC
//! retries the same upstream over TCP; when every upstream failed the clients get SERVFAIL.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const sys = posix.system;
const net = std.Io.net;
const engine = @import("engine.zig");
const zone = @import("zone.zig");
const poll = @import("poll.zig");
const wire = @import("wire.zig");
const config = @import("config.zig");
const forward = @import("forward.zig");
const tsig = @import("tsig.zig");
const update = @import("update.zig");

const max_message = 65535;
const idle_timeout_ms = 10_000; // RFC 7766 §6.2.3: a few seconds of idle time
const max_messages_per_conn = 100;
const max_conns = 64;
const backlog = 128;
const max_pending = 256;
const max_waiters = 64;
const upstream_timeout_ms = 2000;
const is_linux = builtin.os.tag == .linux;
/// std.c has no IPV6 options for darwin; 27 is IPV6_V6ONLY from <netinet6/in6.h>.
const ipv6_v6only: u32 = if (is_linux) posix.IPV6.V6ONLY else 27;

const PosixAddress = extern union { any: posix.sockaddr, in: posix.sockaddr.in, in6: posix.sockaddr.in6, storage: posix.sockaddr.storage };

const Conn = struct {
    fd: posix.fd_t,
    /// Tells a later connection on the same slot from this one when a forwarded answer arrives.
    gen: u64,
    deadline: i64,
    len: usize = 0,
    messages: u32 = 0,
    buf: [2 + max_message]u8 = undefined,
};

const Slot = union(enum) { free, udp: posix.fd_t, listener: posix.fd_t, conn: Conn };

/// Where the answer to a query goes.
const ReplyTo = union(enum) {
    udp: struct { fd: posix.fd_t, peer: PosixAddress, len: posix.socklen_t },
    tcp: struct { token: usize, gen: u64 },
};

const Waiter = struct {
    /// `question.name` is rebuilt from `name` on use: waiters move when the list grows.
    query: engine.Forward,
    name: [255]u8,
    to: ReplyTo,

    fn forward(w: *const Waiter) engine.Forward {
        var f = w.query;
        f.question.name = w.name[0..f.question.name.len];
        return f;
    }
};

/// One upstream query and the clients waiting for its answer.
const Pending = struct {
    /// Lowercase wire name.
    name: [255]u8,
    name_len: usize,
    type: wire.Type,
    id: u16 = 0,
    fd: posix.fd_t = -1,
    upstream: usize = 0,
    deadline: i64 = 0,
    waiters: std.ArrayList(Waiter) = .empty,

    fn qname(p: *const Pending) []const u8 {
        return p.name[0..p.name_len];
    }
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    zones: []const zone.Zone,
    poller: poll.Poller,
    slots: []Slot,
    arena: std.heap.ArenaAllocator,
    forwarding: ?config.Forwarding,
    cache: forward.Cache,
    /// soto only (ADR 0006): the TSIG keys and the dynamic records.
    keys: []const tsig.Key,
    overlay: update.Overlay,
    soto: bool,
    /// Poller tokens `slots.len + i`.
    pending: [max_pending]?Pending = @splat(null),
    next_gen: u64 = 0,
    in: [max_message]u8 = undefined,
    /// Two leading bytes for the TCP length prefix; UDP answers start at 2.
    out: [2 + max_message]u8 = undefined,
    /// Upstream answers received over TCP.
    up: [2 + max_message]u8 = undefined,

    /// Binds every address (UDP and TCP) and serves forever.
    pub fn run(gpa: std.mem.Allocator, zones: []const zone.Zone, cfg: config.Config, keys: []const tsig.Key) !void {
        const listen = cfg.listen;
        const caps: config.Update = cfg.update orelse .{ .keys = &.{} };
        const s = try gpa.create(Server);
        defer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .zones = zones,
            .poller = try poll.Poller.init(),
            .slots = try gpa.alloc(Slot, 2 * listen.len + max_conns),
            .arena = std.heap.ArenaAllocator.init(gpa),
            .forwarding = cfg.forwarding,
            .cache = .init(gpa, if (cfg.forwarding) |f| f.cache_bytes else 0),
            .keys = keys,
            .overlay = .init(gpa, caps.max_ttl, caps.lifetime),
            .soto = cfg.mode == .soto,
        };
        defer gpa.free(s.slots);
        defer s.arena.deinit();
        defer s.cache.deinit();
        defer s.overlay.deinit();
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
            // Upstream timeouts need a finer sweep than TCP idle ones.
            const busy = for (s.pending) |p| {
                if (p != null) break true;
            } else false;
            for (try s.poller.wait(&events, if (busy) 100 else 1000)) |ev| {
                if (ev.token >= s.slots.len) {
                    s.onUpstream(ev.token - s.slots.len);
                    continue;
                }
                switch (s.slots[ev.token]) {
                    .udp => |fd| s.serveUdp(fd),
                    .listener => |fd| s.accept(fd),
                    .conn => |*c| s.serveTcp(ev.token, c),
                    .free => {},
                }
            }
            const now = nowMs();
            s.overlay.expire(@divTrunc(now, 1000));
            for (s.slots, 0..) |slot, i| if (slot == .conn and slot.conn.deadline <= now) s.close(i);
            for (&s.pending, 0..) |*p, i| if (p.* != null and p.*.?.deadline <= now) {
                std.debug.print("level=warn event=upstream-timeout upstream={f}\n", .{s.forwarding.?.upstreams[p.*.?.upstream]});
                s.attempt(i, p.*.?.upstream + 1);
            };
        }
    }

    fn respond(s: *Server, packet: []const u8, transport: engine.Transport, to: ReplyTo) ?[]const u8 {
        defer _ = s.arena.reset(.retain_capacity);
        var fwd: ?engine.Forward = null;
        const ctx: engine.Context = .{ .zones = s.zones, .keys = s.keys, .overlay = if (s.soto) &s.overlay else null, .now = nowUnix(), .mono = @divTrunc(nowMs(), 1000) };
        const n = engine.respond(s.arena.allocator(), ctx, packet, s.out[2..], transport, if (s.forwarding != null) &fwd else null) orelse
            return if (fwd) |f| s.forwardQuery(f, to) else null;
        return s.out[2 .. 2 + n];
    }

    /// Answers from the cache, or joins or starts the upstream query; null when the answer comes later.
    fn forwardQuery(s: *Server, f: engine.Forward, to: ReplyTo) ?[]const u8 {
        var lowered: [255]u8 = undefined;
        @memcpy(lowered[0..f.question.name.len], f.question.name);
        const qname = zone.lower(lowered[0..f.question.name.len]);
        var kbuf: [257]u8 = undefined;
        const now_s = @divTrunc(nowMs(), 1000);
        if (s.cache.get(forward.key(&kbuf, qname, f.question.type), now_s)) |e| {
            const n = engine.forwarded(s.arena.allocator(), f, e.packet, @intCast(e.expires - now_s), s.out[2..]);
            return s.out[2 .. 2 + n];
        }
        var waiter: Waiter = .{ .query = f, .name = undefined, .to = to };
        @memcpy(waiter.name[0..f.question.name.len], f.question.name);
        for (&s.pending) |*slot| if (slot.*) |*p| if (p.type == f.question.type and std.mem.eql(u8, p.qname(), qname)) {
            if (p.waiters.items.len == max_waiters) return null; // the client retries
            p.waiters.append(s.gpa, waiter) catch return null;
            return null;
        };
        const i = for (s.pending, 0..) |p, i| {
            if (p == null) break i;
        } else {
            std.debug.print("level=warn event=forward-refused reason=pending-cap\n", .{});
            const n = engine.forwarded(s.arena.allocator(), f, null, 0, s.out[2..]);
            return s.out[2 .. 2 + n];
        };
        s.pending[i] = .{ .name = undefined, .name_len = qname.len, .type = f.question.type };
        const p = &s.pending[i].?;
        @memcpy(p.name[0..qname.len], qname);
        p.waiters.append(s.gpa, waiter) catch {
            s.pending[i] = null;
            return null;
        };
        s.attempt(i, 0);
        return null;
    }

    /// Sends pending query `i` to the first upstream from `from` that takes it; SERVFAIL when none is left.
    fn attempt(s: *Server, i: usize, from: usize) void {
        const p = &s.pending[i].?;
        s.closeUpstream(p);
        const ups = s.forwarding.?.upstreams;
        for (from..ups.len) |u| {
            p.upstream = u;
            p.id = randomId();
            var qbuf: [512]u8 = undefined;
            const query = upstreamQuery(p, &qbuf);
            p.fd = connectUdp(ups[u], query) catch continue;
            p.deadline = nowMs() + upstream_timeout_ms;
            s.poller.add(p.fd, s.slots.len + i) catch {
                s.closeUpstream(p);
                continue;
            };
            return;
        }
        std.debug.print("level=warn event=forward-failed reason=no-upstream-left\n", .{});
        s.complete(i, null, 0);
    }

    /// An upstream answer (or error) for pending query `i`.
    fn onUpstream(s: *Server, i: usize) void {
        const p = &(s.pending[i] orelse return);
        const rc = sys.recvfrom(p.fd, &s.in, s.in.len, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR => return,
            else => |e| { // e.g. ECONNREFUSED from an ICMP port unreachable
                std.debug.print("level=warn event=upstream-error upstream={f} errno={s}\n", .{ s.forwarding.?.upstreams[p.upstream], @tagName(e) });
                return s.attempt(i, p.upstream + 1);
            },
        }
        defer _ = s.arena.reset(.retain_capacity);
        var packet: []const u8 = s.in[0..@intCast(rc)];
        var m = s.validate(p, packet) orelse return; // a spoofing attempt or a stale answer: keep waiting
        if (m.flags.tc) {
            var qbuf: [2 + 512]u8 = undefined;
            const query = upstreamQuery(p, qbuf[2..]);
            std.mem.writeInt(u16, qbuf[0..2], @intCast(query.len), .big);
            packet = tcpExchange(s.forwarding.?.upstreams[p.upstream], qbuf[0 .. 2 + query.len], &s.up) orelse return s.attempt(i, p.upstream + 1);
            m = s.validate(p, packet) orelse return s.attempt(i, p.upstream + 1);
        }
        if (m.flags.rcode != 0 and m.flags.rcode != 3) return s.attempt(i, p.upstream + 1);
        const f = s.forwarding.?;
        const ttl = forward.lifetime(m, f.min_ttl, f.max_ttl) orelse 0;
        var kbuf: [257]u8 = undefined;
        s.cache.put(forward.key(&kbuf, p.qname(), p.type), packet, ttl, @divTrunc(nowMs(), 1000)) catch {};
        s.complete(i, packet, ttl);
    }

    /// The parsed answer if it is a response to exactly this query (RFC 5452: ID and question).
    fn validate(s: *Server, p: *const Pending, packet: []const u8) ?wire.Message {
        const m = wire.Message.parse(s.arena.allocator(), packet) catch return null;
        if (!m.flags.qr or m.id != p.id or m.flags.opcode != 0 or m.question.len != 1) return null;
        const q = m.question[0];
        if (q.type != p.type or q.class != .in or !std.ascii.eqlIgnoreCase(q.name, p.qname())) return null;
        return m;
    }

    /// Answers every waiter of pending query `i` (`packet` null = SERVFAIL) and frees it.
    fn complete(s: *Server, i: usize, packet: ?[]const u8, ttl: u32) void {
        const p = &s.pending[i].?;
        s.closeUpstream(p);
        for (p.waiters.items) |*w| {
            const n = engine.forwarded(s.arena.allocator(), w.forward(), packet, ttl, s.out[2..]);
            s.deliver(w.to, s.out[2 .. 2 + n]);
        }
        p.waiters.deinit(s.gpa);
        s.pending[i] = null;
    }

    /// Sends an answer that was not written in reply to the packet being read.
    fn deliver(s: *Server, to: ReplyTo, reply: []const u8) void {
        switch (to) {
            .udp => |u| _ = sys.sendto(u.fd, reply.ptr, reply.len, 0, &u.peer.any, u.len),
            .tcp => |t| {
                const slot = s.slots[t.token];
                if (slot != .conn or slot.conn.gen != t.gen) return; // the client left
                std.mem.writeInt(u16, s.out[0..2], @intCast(reply.len), .big);
                sendAll(slot.conn.fd, s.out[0 .. 2 + reply.len]) catch s.close(t.token);
            },
        }
    }

    fn closeUpstream(s: *Server, p: *Pending) void {
        if (p.fd < 0) return;
        s.poller.remove(p.fd);
        _ = sys.close(p.fd);
        p.fd = -1;
    }

    fn serveUdp(s: *Server, fd: posix.fd_t) void {
        var to: ReplyTo = .{ .udp = .{ .fd = fd, .peer = undefined, .len = @sizeOf(PosixAddress) } };
        const rc = sys.recvfrom(fd, &s.in, s.in.len, 0, &to.udp.peer.any, &to.udp.len);
        if (posix.errno(rc) != .SUCCESS) return; // EAGAIN or a transient ICMP error: nothing to answer
        const reply = s.respond(s.in[0..@intCast(rc)], .udp, to) orelse return;
        _ = sys.sendto(fd, reply.ptr, reply.len, 0, &to.udp.peer.any, to.udp.len);
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
        s.next_gen += 1;
        s.slots[slot] = .{ .conn = .{ .fd = cfd, .gen = s.next_gen, .deadline = nowMs() + idle_timeout_ms } };
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
            if (s.respond(c.buf[2 .. 2 + mlen], .tcp, .{ .tcp = .{ .token = token, .gen = c.gen } })) |reply| {
                std.mem.writeInt(u16, s.out[0..2], @intCast(reply.len), .big);
                sendAll(c.fd, s.out[0 .. 2 + reply.len]) catch return s.close(token);
            }
            // A SERVFAIL delivered while forwarding may have closed this connection.
            if (s.slots[token] != .conn) return;
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

/// A non-blocking, close-on-exec socket of the address's family.
fn socket(addr: net.IpAddress, kind: u32) !posix.fd_t {
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
    return fd;
}

fn sockaddr(addr: net.IpAddress, storage: *PosixAddress) posix.socklen_t {
    switch (addr) {
        .ip4 => |ip4| {
            storage.in = .{ .family = posix.AF.INET, .port = std.mem.nativeToBig(u16, ip4.port), .addr = @bitCast(ip4.bytes) };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |ip6| {
            storage.in6 = .{ .family = posix.AF.INET6, .port = std.mem.nativeToBig(u16, ip6.port), .flowinfo = 0, .addr = ip6.bytes, .scope_id = ip6.interface.index };
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

fn open(addr: net.IpAddress, kind: u32) !posix.fd_t {
    const fd = try socket(addr, kind);
    errdefer _ = sys.close(fd);
    const one = std.mem.toBytes(@as(c_int, 1));
    if (kind == posix.SOCK.STREAM) try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one);
    // The deployment listens on overlay addresses that may appear after the unit starts.
    if (is_linux) try posix.setsockopt(fd, posix.IPPROTO.IP, posix.IP.FREEBIND, &one);
    // A `[::]` listener must not swallow `0.0.0.0`: both are bound explicitly (ADR 0007).
    if (addr == .ip6) try posix.setsockopt(fd, posix.IPPROTO.IPV6, ipv6_v6only, &one);
    var storage: PosixAddress = undefined;
    try check(sys.bind(fd, &storage.any, sockaddr(addr, &storage)), "bind", addr);
    if (kind == posix.SOCK.STREAM) try check(sys.listen(fd, backlog), "listen", addr);
    return fd;
}

/// The query sent upstream for `p`: its lowercase name, RD, EDNS with the payload we accept.
fn upstreamQuery(p: *const Pending, buf: []u8) []const u8 {
    const m: wire.Message = .{
        .id = p.id,
        .flags = .{ .rd = true },
        .question = &.{.{ .name = p.qname(), .type = p.type }},
        .additional = &.{(wire.Opt{ .payload = engine.max_udp_payload }).toRR()},
    };
    return buf[0 .. m.encode(buf) catch unreachable]; // a 255-byte name and an OPT fit in 512
}

/// A UDP socket connected to the upstream, the query sent. Port 0: the kernel picks a random
/// source port (RFC 5452 §9.2) and, once connected, drops datagrams from any other address.
fn connectUdp(addr: net.IpAddress, query: []const u8) !posix.fd_t {
    const fd = try socket(addr, posix.SOCK.DGRAM);
    errdefer _ = sys.close(fd);
    var storage: PosixAddress = undefined;
    try check(sys.connect(fd, &storage.any, sockaddr(addr, &storage)), "connect", addr);
    try check(sys.sendto(fd, query.ptr, query.len, 0, null, 0), "send", addr);
    return fd;
}

/// One length-prefixed query over TCP to `addr`, the answer read into `buf` (RFC 7766).
/// shortcut: blocks the loop up to the upstream timeout; upgrade to poller write-readiness if TC answers become frequent.
fn tcpExchange(addr: net.IpAddress, query: []const u8, buf: []u8) ?[]const u8 {
    const deadline = nowMs() + upstream_timeout_ms;
    const fd = socket(addr, posix.SOCK.STREAM) catch return null;
    defer _ = sys.close(fd);
    var storage: PosixAddress = undefined;
    switch (posix.errno(sys.connect(fd, &storage.any, sockaddr(addr, &storage)))) {
        .SUCCESS => {},
        .INPROGRESS => {
            if (!waitFd(fd, posix.POLL.OUT, deadline)) return null;
            var err: c_int = 0;
            var len: posix.socklen_t = @sizeOf(c_int);
            if (posix.errno(sys.getsockopt(fd, posix.SOL.SOCKET, posix.SO.ERROR, @ptrCast(&err), &len)) != .SUCCESS or err != 0) return null;
        },
        else => return null,
    }
    sendAll(fd, query) catch return null;
    var got: usize = 0;
    while (got < 2 or got < 2 + @as(usize, std.mem.readInt(u16, buf[0..2], .big))) {
        const rc = sys.recvfrom(fd, buf[got..].ptr, buf.len - got, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => if (rc == 0) return null else {
                got += @intCast(rc);
            },
            .AGAIN, .INTR => if (!waitFd(fd, posix.POLL.IN, deadline)) return null,
            else => return null,
        }
    }
    return buf[2 .. 2 + std.mem.readInt(u16, buf[0..2], .big)];
}

fn waitFd(fd: posix.fd_t, events: i16, deadline: i64) bool {
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    const left = deadline - nowMs();
    if (left <= 0) return false;
    return (posix.poll(&fds, @intCast(left)) catch 0) > 0;
}

/// RFC 5452 §4: unpredictable query IDs.
fn randomId() u16 {
    var b: [2]u8 = undefined;
    if (is_linux) _ = std.os.linux.getrandom(&b, b.len, 0) else std.c.arc4random_buf(&b, b.len);
    return std.mem.readInt(u16, &b, .little);
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

/// Wall-clock seconds, the only thing TSIG's time check can compare with the client's.
fn nowUnix() i64 {
    var ts: posix.timespec = undefined;
    _ = sys.clock_gettime(posix.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}
