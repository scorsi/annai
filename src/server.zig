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
const log = @import("log.zig");
const metrics = @import("metrics.zig");
const build_options = @import("build_options");

const max_message = 65535;
const idle_timeout_ms = 10_000; // RFC 7766 §6.2.3: a few seconds of idle time
const max_messages_per_conn = 100;
const max_conns = 64;
/// Total time an answer may wait for a slow reader before the connection is closed (review A2).
const write_timeout_ms = 5_000;
/// Answer bytes kept for one connection; forwarding admission reserves a whole response.
const max_pending_output = 2 * (2 + max_message);
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
    peer: PosixAddress,
    /// Tells a later connection on the same slot from this one when a forwarded answer arrives.
    gen: u64,
    deadline: i64,
    len: usize = 0,
    messages: u32 = 0,
    /// Answer bytes the socket has not taken yet, sent on write readiness; no new frame is
    /// read meanwhile, so a slow reader stalls its own connection only (review A2).
    pending: std.ArrayList(u8) = .empty,
    /// Reads pause while one forwarded response is outstanding (review B3).
    waiting: bool = false,
    /// The client shut its write half: what it asked is still answered, then the connection
    /// closes (review A16).
    eof: bool = false,
    buf: [2 + max_message]u8 = undefined,
};

const Slot = union(enum) { free, udp: posix.fd_t, listener: posix.fd_t, conn: Conn, scrape: posix.fd_t };

/// Who asked and when, for the `query` log line and the metrics (ADR 0011).
const Asker = struct {
    proto: engine.Transport,
    client: PosixAddress,
    /// Monotonic nanoseconds when the query was read.
    start: i64,
};

/// Whether the answer came from the forwarding cache (`none`: local zones or nothing to forward).
const CacheUse = enum { none, hit, miss };

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
    asker: Asker,

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
    mode: config.Mode,
    metrics: metrics.Metrics,
    /// Index of the first TCP connection slot: listeners and the metrics slot come first (review A13).
    first_conn: usize,
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
        const s = try init(gpa, zones, cfg, keys);
        defer s.deinit();
        while (true) try s.step(1000);
    }

    /// Binds every address of `cfg`; `deinit` closes them.
    pub fn init(gpa: std.mem.Allocator, zones: []const zone.Zone, cfg: config.Config, keys: []const tsig.Key) !*Server {
        const listen = cfg.listen;
        const caps: config.Update = cfg.update orelse .{ .keys = &.{} };
        const s = try gpa.create(Server);
        s.* = .{
            .gpa = gpa,
            .zones = zones,
            .poller = poll.Poller.init() catch |e| {
                gpa.destroy(s);
                return e;
            },
            .slots = &.{},
            .arena = std.heap.ArenaAllocator.init(gpa),
            .forwarding = cfg.forwarding,
            .cache = .init(gpa, if (cfg.forwarding) |f| f.cache_bytes else 0),
            .keys = keys,
            .overlay = .init(gpa, caps.max_ttl, caps.lifetime),
            .soto = cfg.mode == .soto,
            .mode = cfg.mode,
            .metrics = .{},
            .first_conn = 2 * listen.len + 1,
        };
        errdefer s.deinit();
        s.slots = try gpa.alloc(Slot, s.first_conn + max_conns);
        @memset(s.slots, .free);
        s.metrics = try .init(gpa, if (cfg.forwarding) |f| f.upstreams.len else 0, keys.len);
        for (listen, 0..) |addr, i| {
            const udp = try open(addr, posix.SOCK.DGRAM);
            s.slots[2 * i] = .{ .udp = udp };
            try s.poller.add(udp, 2 * i);
            const tcp = try open(addr, posix.SOCK.STREAM);
            s.slots[2 * i + 1] = .{ .listener = tcp };
            try s.poller.add(tcp, 2 * i + 1);
            log.event(.info, "listen", .{ .addr = addr });
        }
        if (cfg.metrics) |addr| {
            const fd = try open(addr, posix.SOCK.STREAM);
            s.slots[2 * listen.len] = .{ .scrape = fd };
            try s.poller.add(fd, 2 * listen.len);
            log.event(.info, "metrics-listen", .{ .addr = addr });
        }
        return s;
    }

    pub fn deinit(s: *Server) void {
        for (s.slots, 0..) |slot, i| switch (slot) {
            .free => {},
            .conn => s.close(i),
            inline .udp, .listener, .scrape => |fd| _ = sys.close(fd),
        };
        for (&s.pending) |*p| if (p.*) |*q| {
            s.closeUpstream(q);
            q.waiters.deinit(s.gpa);
        };
        _ = sys.close(s.poller.fd);
        s.metrics.deinit(s.gpa);
        s.gpa.free(s.slots);
        s.arena.deinit();
        s.cache.deinit();
        s.overlay.deinit();
        s.gpa.destroy(s);
    }

    /// One turn of the event loop: waits up to `idle_ms` for events, handles them, then expires
    /// dynamic records, connections past their deadline and upstream queries past theirs.
    pub fn step(s: *Server, idle_ms: i32) !void {
        var events: [64]poll.Event = undefined;
        // Upstream timeouts need a finer sweep than TCP idle ones.
        const busy = for (s.pending) |p| {
            if (p != null) break true;
        } else false;
        for (try s.poller.wait(&events, if (busy) @min(idle_ms, 100) else idle_ms)) |ev| {
            if (ev.token >= s.slots.len) {
                s.onUpstream(ev.token - s.slots.len);
                continue;
            }
            switch (s.slots[ev.token]) {
                .udp => |fd| s.serveUdp(fd),
                .listener => |fd| s.accept(fd),
                .conn => |*c| if (ev.fatal) s.close(ev.token) else s.serveTcp(ev.token, c),
                .scrape => |fd| s.scrape(fd),
                .free => {},
            }
        }
        const now = nowMs();
        s.overlay.expire(@divTrunc(now, 1000));
        for (s.slots, 0..) |slot, i| if (slot == .conn and slot.conn.deadline <= now) s.close(i);
        for (&s.pending, 0..) |*p, i| if (p.* != null and p.*.?.deadline <= now) {
            const u = p.*.?.upstream;
            log.event(.warn, "upstream-timeout", .{ .upstream = s.forwarding.?.upstreams[u], .qname = zone.fmt(p.*.?.qname()), .qtype = log.typeName(p.*.?.type) });
            s.metrics.upstream(u, .timeout);
            s.attempt(i, p.*.?.upstream + 1);
        };
    }

    fn respond(s: *Server, packet: []const u8, to: ReplyTo, a: Asker) ?[]const u8 {
        defer _ = s.arena.reset(.retain_capacity);
        var fwd: ?engine.Forward = null;
        const ctx: engine.Context = .{ .zones = s.zones, .keys = s.keys, .overlay = if (s.soto) &s.overlay else null, .now = nowUnix(), .mono = @divTrunc(nowMs(), 1000), .metrics = &s.metrics };
        var cache: CacheUse = .none;
        const reply = if (engine.respond(s.arena.allocator(), ctx, packet, s.out[2..], a.proto, if (s.forwarding != null) &fwd else null)) |n|
            s.out[2 .. 2 + n]
        else
            (s.forwardQuery((fwd orelse return null), to, a, &cache) orelse return null);
        s.answered(a, packet, reply, cache);
        return reply;
    }

    /// Logs and counts one answered query; `asked` holds the question (the query, or the reply).
    fn answered(s: *Server, a: Asker, asked: []const u8, reply: []const u8, cache: CacheUse) void {
        var qbuf: [255]u8 = undefined;
        const q = log.question(asked, &qbuf);
        const flags: wire.Flags = @bitCast(std.mem.readInt(u16, reply[2..4], .big));
        var rcode: u12 = flags.rcode;
        // Extended rcodes live in the OPT, including errors preserved from upstreams.
        if (wire.Message.parse(s.arena.allocator(), reply)) |m| {
            if (m.edns() catch null) |o| rcode |= @as(u12, o.ext_rcode) << 4;
        } else |_| {}
        const dur: u64 = @intCast(@max(0, nowNs() - a.start));
        s.metrics.query(a.proto, if (q) |x| x.type else null, rcode, dur);
        log.event(.info, "query", .{
            .proto = @tagName(a.proto),
            .client = Host{ .addr = a.client },
            .qname = if (q) |x| zone.fmt(x.name) else null,
            .qtype = if (q) |x| log.typeName(x.type) else null,
            .rcode = log.rcodeName(rcode),
            .aa = flags.aa,
            .cache = @tagName(cache),
            .size = reply.len,
            .dur_us = dur / 1000,
        });
    }

    /// Answers from the cache, or joins or starts the upstream query; null when the answer comes later.
    fn forwardQuery(s: *Server, query: engine.Forward, to: ReplyTo, a: Asker, cache: *CacheUse) ?[]const u8 {
        var f = query; // the waiters keep the cap for answers that come later
        f.max_ttl = s.forwarding.?.max_ttl;
        var lowered: [255]u8 = undefined;
        @memcpy(lowered[0..f.question.name.len], f.question.name);
        const qname = zone.lower(lowered[0..f.question.name.len]);
        var kbuf: [257]u8 = undefined;
        const now_s = @divTrunc(nowMs(), 1000);
        const hit = s.cache.get(forward.key(&kbuf, qname, f.question.type), now_s);
        s.metrics.cacheLookup(hit != null);
        cache.* = if (hit != null) .hit else .miss;
        if (hit) |e| {
            const n = engine.forwarded(s.arena.allocator(), f, e.packet, @intCast(now_s - e.inserted), s.out[2..]);
            return s.out[2 .. 2 + n];
        }
        var waiter: Waiter = .{ .query = f, .name = undefined, .to = to, .asker = a };
        @memcpy(waiter.name[0..f.question.name.len], f.question.name);
        for (&s.pending) |*slot| if (slot.*) |*p| if (p.type == f.question.type and std.mem.eql(u8, p.qname(), qname)) {
            if (p.waiters.items.len == max_waiters) return null; // the client retries
            p.waiters.append(s.gpa, waiter) catch return null;
            return null;
        };
        const i = for (s.pending, 0..) |p, i| {
            if (p == null) break i;
        } else {
            log.event(.warn, "forward-refused", .{ .reason = "pending-cap" });
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
            p.id = randomId(if (is_linux) linuxRandom else null) catch {
                s.metrics.upstream(u, .@"error");
                continue;
            };
            var qbuf: [512]u8 = undefined;
            const query = upstreamQuery(p, &qbuf);
            p.fd = connectUdp(ups[u], query) catch {
                s.metrics.upstream(u, .@"error");
                continue;
            };
            p.deadline = nowMs() + upstream_timeout_ms;
            s.poller.add(p.fd, s.slots.len + i) catch {
                s.closeUpstream(p);
                s.metrics.upstream(u, .@"error");
                continue;
            };
            return;
        }
        log.event(.warn, "forward-failed", .{ .reason = "no-upstream-left", .qname = zone.fmt(p.qname()), .qtype = log.typeName(p.type) });
        s.complete(i, null);
    }

    /// An upstream answer (or error) for pending query `i`.
    fn onUpstream(s: *Server, i: usize) void {
        const p = &(s.pending[i] orelse return);
        const rc = sys.recvfrom(p.fd, &s.in, s.in.len, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR => return,
            else => |e| { // e.g. ECONNREFUSED from an ICMP port unreachable
                log.event(.warn, "upstream-error", .{ .upstream = s.forwarding.?.upstreams[p.upstream], .qname = zone.fmt(p.qname()), .qtype = log.typeName(p.type), .err = @tagName(e) });
                s.metrics.upstream(p.upstream, .@"error");
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
            packet = tcpExchange(s.forwarding.?.upstreams[p.upstream], qbuf[0 .. 2 + query.len], &s.up) orelse return s.failed(i, .@"error");
            m = s.validate(p, packet) orelse return s.failed(i, .@"error");
            if (m.flags.tc) return s.failed(i, .@"error");
        }
        const opt = m.edns() catch return s.failed(i, .@"error");
        const extended = if (opt) |o| o.ext_rcode != 0 else false;
        if (!extended and m.flags.rcode != 0 and m.flags.rcode != 3) return s.failed(i, .rcode);
        s.metrics.upstream(p.upstream, .ok);
        const f = s.forwarding.?;
        const ttl = forward.lifetime(m, f.max_ttl) orelse 0;
        var kbuf: [257]u8 = undefined;
        s.cache.put(forward.key(&kbuf, p.qname(), p.type), packet, ttl, @divTrunc(nowMs(), 1000)) catch {};
        s.complete(i, packet);
    }

    /// Counts the failure of the current upstream of pending query `i` and tries the next one.
    fn failed(s: *Server, i: usize, result: metrics.Upstream) void {
        const u = s.pending[i].?.upstream;
        s.metrics.upstream(u, result);
        s.attempt(i, u + 1);
    }

    /// The parsed answer if it is a response to exactly this query (RFC 5452: ID and question).
    fn validate(s: *Server, p: *const Pending, packet: []const u8) ?wire.Message {
        const m = wire.Message.parse(s.arena.allocator(), packet) catch return null;
        if (!m.flags.qr or m.id != p.id or m.flags.opcode != 0 or m.question.len != 1) return null;
        const q = m.question[0];
        if (q.type != p.type or q.class != .in or !std.ascii.eqlIgnoreCase(q.name, p.qname())) return null;
        _ = m.edns() catch return null;
        return m;
    }

    /// Answers every waiter of pending query `i` (`packet` null = SERVFAIL) and frees it.
    fn complete(s: *Server, i: usize, packet: ?[]const u8) void {
        const p = &s.pending[i].?;
        s.closeUpstream(p);
        var waiters = p.waiters;
        defer waiters.deinit(s.gpa);
        s.pending[i] = null;
        for (waiters.items) |*w| {
            const n = engine.forwarded(s.arena.allocator(), w.forward(), packet, 0, s.out[2..]);
            s.answered(w.asker, s.out[2 .. 2 + n], s.out[2 .. 2 + n], .miss);
            s.deliver(w.to, s.out[2 .. 2 + n]);
            _ = s.arena.reset(.retain_capacity);
        }
        for (waiters.items) |w| if (w.to == .tcp) if (s.conn(w.to.tcp.token, w.to.tcp.gen)) |c| {
            if (c.eof) {
                s.settle(w.to.tcp.token);
            } else if (c.waiting) {
                c.waiting = false;
                if (c.pending.items.len == 0) {
                    s.poller.set(c.fd, w.to.tcp.token, .read) catch {
                        s.close(w.to.tcp.token);
                        continue;
                    };
                    s.frames(w.to.tcp.token, c);
                }
            }
        };
    }

    /// The connection in slot `token` if it is still generation `gen`.
    fn conn(s: *Server, token: usize, gen: u64) ?*Conn {
        const slot = &s.slots[token];
        return if (slot.* == .conn and slot.conn.gen == gen) &slot.conn else null;
    }

    /// Whether a forwarded answer is still due to connection `token`/`gen`.
    fn awaited(s: *const Server, token: usize, gen: u64) bool {
        for (s.pending) |p| if (p) |q| for (q.waiters.items) |w| if (w.to == .tcp and w.to.tcp.token == token and w.to.tcp.gen == gen) return true;
        return false;
    }

    /// Sends an answer that was not written in reply to the packet being read.
    fn deliver(s: *Server, to: ReplyTo, reply: []const u8) void {
        switch (to) {
            .udp => |u| _ = sys.sendto(u.fd, reply.ptr, reply.len, 0, &u.peer.any, u.len),
            .tcp => |t| if (s.conn(t.token, t.gen) != null) s.send(t.token, reply), // else the client left
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
        const reply = s.respond(s.in[0..@intCast(rc)], to, .{ .proto = .udp, .client = to.udp.peer, .start = nowNs() }) orelse return;
        _ = sys.sendto(fd, reply.ptr, reply.len, 0, &to.udp.peer.any, to.udp.len);
    }

    fn accept(s: *Server, fd: posix.fd_t) void {
        var peer: PosixAddress = undefined;
        const cfd = acceptConn(fd, &peer) orelse return;
        // Only the connection range: the metrics slot stays free when metrics are off (review A13).
        const slot = for (s.slots[s.first_conn..], s.first_conn..) |slot, i| {
            if (slot == .free) break i;
        } else {
            log.event(.warn, "tcp-refused", .{ .reason = "connection-cap" });
            _ = sys.close(cfd);
            return;
        };
        s.next_gen += 1;
        s.slots[slot] = .{ .conn = .{ .fd = cfd, .peer = peer, .gen = s.next_gen, .deadline = nowMs() + idle_timeout_ms } };
        s.poller.add(cfd, slot) catch s.close(slot);
    }

    fn serveTcp(s: *Server, token: usize, c: *Conn) void {
        if (c.pending.items.len > 0) return s.flush(token, c);
        if (c.waiting) return;
        if (c.eof) return s.close(token); // a hangup or an error: nothing more can be sent
        const rc = sys.recvfrom(c.fd, c.buf[c.len..].ptr, c.buf.len - c.len, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN, .INTR => return,
            else => return s.close(token),
        }
        const n: usize = @intCast(rc);
        if (n == 0) { // the client is done asking; an incomplete last frame is dropped
            c.eof = true;
            return s.settle(token);
        }
        c.len += n;
        c.deadline = nowMs() + idle_timeout_ms;
        s.frames(token, c);
    }

    /// Answers the complete frames read so far, while the socket takes the answers.
    fn frames(s: *Server, token: usize, c: *Conn) void {
        while (c.pending.items.len == 0) {
            // A forwarded reply can fill the output queue even after read readiness is paused.
            if (s.awaited(token, c.gen)) {
                c.waiting = true;
                s.poller.set(c.fd, token, .none) catch s.close(token);
                return;
            }
            const end = frameEnd(c.buf[0..c.len]) orelse return;
            c.messages += 1;
            if (c.messages > max_messages_per_conn) return s.close(token);
            c.deadline = nowMs() + idle_timeout_ms;
            if (s.respond(c.buf[2..end], .{ .tcp = .{ .token = token, .gen = c.gen } }, .{ .proto = .tcp, .client = c.peer, .start = nowNs() })) |reply| s.send(token, reply);
            // The answer, or a SERVFAIL delivered while forwarding, may have closed this connection.
            if (s.slots[token] != .conn) return;
            std.mem.copyForwards(u8, &c.buf, c.buf[end..c.len]);
            c.len -= end;
        }
    }

    /// Sends `reply` (in `s.out` after two free bytes) length-prefixed on connection `token`;
    /// what the socket does not take now waits in `pending` under a total deadline (review A2).
    fn send(s: *Server, token: usize, reply: []const u8) void {
        std.debug.assert(reply.ptr == s.out[2..].ptr);
        const c = &s.slots[token].conn;
        std.mem.writeInt(u16, s.out[0..2], @intCast(reply.len), .big);
        var data: []const u8 = s.out[0 .. 2 + reply.len];
        if (c.pending.items.len == 0) {
            data = data[sendSome(c.fd, data) orelse return s.close(token) ..];
            if (data.len == 0) {
                c.deadline = nowMs() + idle_timeout_ms;
                return;
            }
            c.deadline = nowMs() + write_timeout_ms;
            s.poller.set(c.fd, token, .write) catch return s.close(token);
        }
        if (c.pending.items.len + data.len > max_pending_output) return s.close(token);
        c.pending.appendSlice(s.gpa, data) catch return s.close(token);
    }

    /// Write readiness: sends what is pending, then reads again (or settles after an EOF).
    fn flush(s: *Server, token: usize, c: *Conn) void {
        const sent = sendSome(c.fd, c.pending.items) orelse return s.close(token);
        c.pending.replaceRangeAssumeCapacity(0, sent, &.{});
        if (c.pending.items.len > 0) return;
        c.deadline = nowMs() + idle_timeout_ms;
        if (c.eof) return s.settle(token);
        s.poller.set(c.fd, token, .read) catch return s.close(token);
        s.frames(token, c);
    }

    /// After the client's EOF: closes once every answer it is owed is written (review A16).
    fn settle(s: *Server, token: usize) void {
        const c = &s.slots[token].conn;
        if (c.pending.items.len > 0) return; // `flush` settles again
        if (!s.awaited(token, c.gen)) return s.close(token);
        s.poller.set(c.fd, token, .none) catch s.close(token);
    }

    /// One `GET /metrics` (ADR 0011), answered on the spot and closed.
    /// shortcut: served inline, a slow scraper blocks the loop up to 1 s; the only client is the local agent on loopback.
    fn scrape(s: *Server, lfd: posix.fd_t) void {
        var peer: PosixAddress = undefined;
        const fd = acceptConn(lfd, &peer) orelse return;
        defer _ = sys.close(fd);
        var req: [1024]u8 = undefined;
        var got: usize = 0;
        const deadline = nowMs() + 1000;
        while (std.mem.indexOf(u8, req[0..got], "\r\n\r\n") == null and got < req.len) {
            const rc = sys.recvfrom(fd, req[got..].ptr, req.len - got, 0, null, null);
            switch (posix.errno(rc)) {
                .SUCCESS => if (rc == 0) break else {
                    got += @intCast(rc);
                },
                .AGAIN, .INTR => if (!waitFd(fd, posix.POLL.IN, deadline)) return,
                else => return,
            }
        }
        const line = req[0 .. std.mem.indexOf(u8, req[0..got], "\r\n") orelse got];
        const ok = std.mem.startsWith(u8, line, "GET /metrics ") or std.mem.startsWith(u8, line, "GET /metrics?");
        var body: std.Io.Writer.Allocating = .init(s.gpa);
        defer body.deinit();
        if (ok) metrics.write(&s.metrics, .{
            .version = build_options.version,
            .mode = @tagName(s.mode),
            .upstreams = if (s.forwarding) |f| f.upstreams else &.{},
            .keys = s.keys,
            .cache_entries = s.cache.map.count(),
            .dynamic_records = s.overlay.records.items.len,
        }, &body.writer) catch return else body.writer.writeAll("not found\n") catch return;
        var head: [256]u8 = undefined;
        const h = std.fmt.bufPrint(&head, "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
            if (ok) "200 OK" else "404 Not Found",
            if (ok) metrics.content_type else "text/plain; charset=utf-8",
            body.written().len,
        }) catch unreachable;
        sendAll(fd, h, deadline) catch return;
        sendAll(fd, body.written(), deadline) catch return;
    }

    fn close(s: *Server, token: usize) void {
        const c = &s.slots[token].conn;
        // Drop only this generation's waiters; coalesced queries still belong to their other clients.
        for (&s.pending) |*slot| if (slot.*) |*p| {
            var i: usize = 0;
            while (i < p.waiters.items.len) {
                const to = p.waiters.items[i].to;
                if (to == .tcp and to.tcp.token == token and to.tcp.gen == c.gen) {
                    _ = p.waiters.swapRemove(i);
                } else i += 1;
            }
            if (p.waiters.items.len == 0) {
                s.closeUpstream(p);
                p.waiters.deinit(s.gpa);
                slot.* = null;
            }
        };
        s.poller.remove(c.fd);
        _ = sys.close(c.fd);
        c.pending.deinit(s.gpa);
        s.slots[token] = .free;
    }
};

/// An accepted connection, non-blocking and close-on-exec, its peer in `peer`; null on error.
fn acceptConn(fd: posix.fd_t, peer: *PosixAddress) ?posix.fd_t {
    var len: posix.socklen_t = @sizeOf(PosixAddress);
    const rc = if (is_linux) sys.accept4(fd, &peer.any, &len, posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK) else sys.accept(fd, &peer.any, &len);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .AGAIN, .INTR, .CONNABORTED => return null,
        else => |e| {
            log.event(.warn, "accept", .{ .err = @tagName(e) });
            return null;
        },
    }
    const cfd: posix.fd_t = @intCast(rc);
    if (!is_linux) nonblocking(cfd) catch {
        _ = sys.close(cfd);
        return null;
    };
    return cfd;
}

/// `{f}` prints the address of a peer without its port (the `client` of the query log).
const Host = struct {
    addr: PosixAddress,

    pub fn format(h: Host, w: *std.Io.Writer) std.Io.Writer.Error!void {
        switch (h.addr.any.family) {
            posix.AF.INET => {
                const b: [4]u8 = @bitCast(h.addr.in.addr);
                try w.print("{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
            },
            posix.AF.INET6 => try w.print("{f}", .{net.Ip6Address.Unresolved{ .bytes = h.addr.in6.addr, .interface_name = null }}),
            else => try w.writeAll("unknown"),
        }
    }
};

/// Writes what a non-blocking socket takes now; null when the connection is gone.
fn sendSome(fd: posix.fd_t, data: []const u8) ?usize {
    var sent: usize = 0;
    while (sent < data.len) {
        const rc = sys.sendto(fd, data[sent..].ptr, data.len - sent, 0, null, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => sent += @intCast(rc),
            .INTR => {},
            .AGAIN => break,
            else => return null,
        }
    }
    return sent;
}

/// Writes the whole buffer, waiting for the socket until `deadline` at most (a total bound,
/// review A2). Blocks the loop: only for the loopback scraper and the TCP upstream exchange.
fn sendAll(fd: posix.fd_t, data: []const u8, deadline: i64) error{Closed}!void {
    var sent: usize = 0;
    while (true) {
        sent += sendSome(fd, data[sent..]) orelse return error.Closed;
        if (sent == data.len) return;
        if (!waitFd(fd, posix.POLL.OUT, deadline)) return error.Closed;
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
/// shortcut: blocks the loop up to the upstream timeout in total (connect, send and receive); upgrade to poller readiness if TC answers become frequent.
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
    sendAll(fd, query, deadline) catch return null;
    var got: usize = 0;
    while (frameEnd(buf[0..got]) == null) {
        const rc = sys.recvfrom(fd, buf[got..].ptr, buf.len - got, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => if (rc == 0) return null else {
                got += @intCast(rc);
            },
            .AGAIN, .INTR => if (!waitFd(fd, posix.POLL.IN, deadline)) return null,
            else => return null,
        }
    }
    return buf[2..frameEnd(buf[0..got]).?];
}

/// End of the first length-prefixed message in `buf` (RFC 7766), null while it is incomplete.
fn frameEnd(buf: []const u8) ?usize {
    if (buf.len < 2) return null;
    // usize: `2 + u16` traps on a 0xfffe/0xffff prefix, which crashed a public soto (2026-10-20).
    const end = 2 + @as(usize, std.mem.readInt(u16, buf[0..2], .big));
    return if (buf.len < end) null else end;
}

fn waitFd(fd: posix.fd_t, events: i16, deadline: i64) bool {
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    const left = deadline - nowMs();
    if (left <= 0) return false;
    return (posix.poll(&fds, @intCast(left)) catch 0) > 0;
}

/// RFC 5452 §4: unpredictable query IDs.
fn randomId(comptime read: ?*const fn ([]u8) error{ Interrupted, Entropy }!usize) error{Entropy}!u16 {
    var b: [2]u8 = undefined;
    if (read) |get| try fillRandom(&b, get) else std.c.arc4random_buf(&b, b.len);
    return std.mem.readInt(u16, &b, .little);
}

fn linuxRandom(buf: []u8) error{ Interrupted, Entropy }!usize {
    const rc = std.os.linux.getrandom(buf.ptr, buf.len, 0);
    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => rc,
        .INTR => error.Interrupted,
        else => error.Entropy,
    };
}

fn fillRandom(buf: []u8, read: *const fn ([]u8) error{ Interrupted, Entropy }!usize) error{Entropy}!void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = read(buf[filled..]) catch |e| switch (e) {
            error.Interrupted => continue,
            error.Entropy => return error.Entropy,
        };
        if (n == 0 or n > buf.len - filled) return error.Entropy;
        filled += n;
    }
}

fn check(rc: anytype, what: []const u8, addr: net.IpAddress) error{Listen}!void {
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            log.event(.@"error", what, .{ .addr = addr, .err = @tagName(e) });
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

fn nowNs() i64 {
    var ts: posix.timespec = undefined;
    _ = sys.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
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

test "TCP framing: a 0xffff length prefix waits for more bytes instead of overflowing" {
    // The connection buffer found in the core of the 2026-10-20 crash (29 bytes, prefix 0xffff).
    var crash: [29]u8 = undefined;
    _ = try std.fmt.hexToBytes(&crash, "ffffffffffffffffffffffffffffffff001d0104fde8005ac000020100");
    try std.testing.expectEqual(@as(?usize, null), frameEnd(&crash));
    try std.testing.expectEqual(@as(?usize, null), frameEnd(&.{ 0xff, 0xfe }));
    var full: [2 + max_message]u8 = @splat(0);
    full[0] = 0xff;
    full[1] = 0xff;
    try std.testing.expectEqual(@as(?usize, full.len), frameEnd(&full));
    try std.testing.expectEqual(@as(?usize, null), frameEnd(&.{0}));
    try std.testing.expectEqual(@as(?usize, 3), frameEnd(&.{ 0, 1, 9, 0, 0 }));
}

// ---- loopback harness and stateful tests (review A2, A13, A16, A17) ----------------------------

const testing = std.testing;

/// A server on an ephemeral 127.0.0.1 port, driven one `step` at a time by the caller, with
/// non-blocking clients: the stateful tests below and the `tcp` target of src/fuzz.zig.
pub const Loopback = struct {
    gpa: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    zones: [1]zone.Zone,
    server: *Server,
    /// The TCP listener's address; port 0 gave the UDP socket another port.
    addr: net.IpAddress,
    udp_addr: net.IpAddress,

    /// engine.test_zone plus `huge`: a TXT RRset of about 64 KiB, many times a socket buffer.
    const huge_zone = engine.test_zone ++ "[names.\"huge\"]\ntxt = [\n" ++ ("\"" ++ "h" ** 255 ++ "\",\n") ** 240 ++ "]\n";

    pub const Options = struct { forwarding: ?config.Forwarding = null, metrics: bool = false };

    pub fn init(gpa: std.mem.Allocator, opts: Options) !*Loopback {
        // A client that hangs up must not kill the process that runs the server (the binary
        // gets the same from Zig's start code).
        var ignore: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = posix.sigemptyset(), .flags = 0 };
        posix.sigaction(posix.SIG.PIPE, &ignore, null);
        const l = try gpa.create(Loopback);
        errdefer gpa.destroy(l);
        l.* = .{ .gpa = gpa, .arena = .init(gpa), .zones = undefined, .server = undefined, .addr = undefined, .udp_addr = undefined };
        errdefer l.arena.deinit();
        const a = l.arena.allocator();
        var d: config.Diag = .{};
        l.zones[0] = try config.loadZone(a, huge_zone, &d);
        const any = try net.IpAddress.parse("127.0.0.1", 0);
        const fwd: ?config.Forwarding = if (opts.forwarding) |f| .{ .upstreams = try a.dupe(net.IpAddress, f.upstreams), .max_ttl = f.max_ttl, .cache_bytes = f.cache_bytes } else null;
        l.server = try Server.init(gpa, &l.zones, .{ .mode = .uchi, .listen = &.{any}, .zones = &.{}, .forwarding = fwd, .metrics = if (opts.metrics) any else null }, &.{});
        l.addr = try net.IpAddress.parse("127.0.0.1", localPort(l.server.slots[1].listener));
        l.udp_addr = try net.IpAddress.parse("127.0.0.1", localPort(l.server.slots[0].udp));
        return l;
    }

    pub fn deinit(l: *Loopback) void {
        l.server.deinit();
        l.arena.deinit();
        l.gpa.destroy(l);
    }

    /// A connected, non-blocking TCP client.
    pub fn connect(l: *Loopback) !posix.fd_t {
        const fd = try clientSocket(l.addr, posix.SOCK.STREAM);
        errdefer _ = sys.close(fd);
        var storage: PosixAddress = undefined;
        switch (posix.errno(sys.connect(fd, &storage.any, sockaddr(l.addr, &storage)))) {
            .SUCCESS => {},
            // The kernel completes the handshake without the server's accept.
            .INPROGRESS => if (!waitFd(fd, posix.POLL.OUT, nowMs() + 1000)) return error.Connect,
            else => return error.Connect,
        }
        return fd;
    }

    /// Open TCP connections on the server.
    pub fn conns(l: *const Loopback) usize {
        var n: usize = 0;
        for (l.server.slots) |slot| n += @intFromBool(slot == .conn);
        return n;
    }

    /// Sends `stream` over one connection in chunks `rand` picks, then shuts the write half and
    /// reads until the server closes. Invariants (review A17): no trap; only complete frames are
    /// answered, each once, in order, with a well-formed response; the 101st message closes the
    /// connection; the slot is released.
    pub fn checkStream(l: *Loopback, stream: []const u8, rand: std.Random) error{Stream}!void {
        var want: [max_messages_per_conn]u16 = undefined;
        var n_want: usize = 0;
        var cap_at = stream.len;
        var rest = stream;
        var frames_seen: usize = 0;
        while (frameEnd(rest)) |end| : (rest = rest[end..]) {
            frames_seen += 1;
            if (frames_seen > max_messages_per_conn) {
                cap_at = stream.len - rest.len;
                break;
            }
            const msg = rest[2..end];
            if (msg.len >= 12 and msg[2] & 0x80 == 0) { // engine.respond answers every non-response of a header or more
                want[n_want] = std.mem.readInt(u16, msg[0..2], .big);
                n_want += 1;
            }
        }
        const fd = l.connect() catch return error.Stream;
        defer _ = sys.close(fd);
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(l.gpa);
        var arena = std.heap.ArenaAllocator.init(l.gpa);
        defer arena.deinit();
        var received: usize = 0;
        var sent: usize = 0;
        var shut = false;
        var turns: usize = 0;
        var buf: [16384]u8 = undefined;
        while (true) : (turns += 1) {
            if (turns > 100_000) return error.Stream; // the server never closed the connection
            // Drain and validate the first 100 answers before frame 101 can cause a reset.
            const send_end = if (received < n_want) cap_at else stream.len;
            if (sent < send_end) {
                const chunk = 1 + rand.uintLessThan(usize, @min(send_end - sent, 4096));
                const rc = sys.sendto(fd, stream[sent..].ptr, chunk, 0, null, 0);
                switch (posix.errno(rc)) {
                    .SUCCESS => sent += @intCast(rc),
                    .AGAIN, .INTR, .NOTCONN => {},
                    else => sent = stream.len, // the server closed it (message cap)
                }
            } else if (sent == stream.len and !shut) {
                _ = sys.shutdown(fd, posix.SHUT.WR);
                shut = true;
            }
            l.server.step(0) catch return error.Stream;
            const rc = sys.recvfrom(fd, &buf, buf.len, 0, null, null);
            switch (posix.errno(rc)) {
                .SUCCESS => if (rc == 0) break else got.appendSlice(l.gpa, buf[0..@intCast(rc)]) catch return error.Stream,
                .AGAIN, .INTR => {},
                else => if (cap_at < stream.len) break else return error.Stream, // unread input at the cap
            }
            const consumed = try checkAnswers(&arena, got.items, want[0..n_want], &received, false);
            got.replaceRangeAssumeCapacity(0, consumed, &.{});
        }
        _ = try checkAnswers(&arena, got.items, want[0..n_want], &received, true);
        if (l.conns() != 0) return error.Stream;
    }
};

/// Consumes complete replies incrementally; EOF must leave every expected ID and no trailing bytes.
fn checkAnswers(arena: *std.heap.ArenaAllocator, bytes: []const u8, want: []const u16, received: *usize, eof: bool) error{Stream}!usize {
    var rest = bytes;
    while (frameEnd(rest)) |end| : (rest = rest[end..]) {
        defer _ = arena.reset(.retain_capacity);
        const m = wire.Message.parse(arena.allocator(), rest[2..end]) catch return error.Stream;
        if (received.* == want.len or !m.flags.qr or m.id != want[received.*]) return error.Stream;
        received.* += 1;
    }
    if (eof and (received.* != want.len or rest.len != 0)) return error.Stream;
    return bytes.len - rest.len;
}

test "TCP reply oracle requires all 100 ordered answers and no trailing bytes (review B4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var want: [100]u16 = undefined;
    var replies: [100 * 14]u8 = undefined;
    for (&want, 0..) |*id, i| {
        id.* = @intCast(i);
        const frame = replies[i * 14 ..][0..14];
        std.mem.writeInt(u16, frame[0..2], 12, .big);
        _ = try (wire.Message{ .id = id.*, .flags = .{ .qr = true } }).encode(frame[2..]);
    }
    for ([_]usize{ 0, 14, replies.len - 1 }) |len| {
        var received: usize = 0;
        try testing.expectError(error.Stream, checkAnswers(&arena, replies[0..len], &want, &received, true));
    }
    var received: usize = 0;
    _ = try checkAnswers(&arena, &replies, &want, &received, true);
    try testing.expectEqual(@as(usize, 100), received);
    try testing.expectError(error.Stream, checkAnswers(&arena, "\x00", &want, &received, true));
    try testing.expectError(error.Stream, checkAnswers(&arena, replies[0..14], &want, &received, true));
    received = 0;
    std.mem.writeInt(u16, replies[2..4], 1, .big);
    try testing.expectError(error.Stream, checkAnswers(&arena, &replies, &want, &received, true));
}

fn clientSocket(addr: net.IpAddress, kind: u32) !posix.fd_t {
    return socket(addr, kind);
}

fn localPort(fd: posix.fd_t) u16 {
    var storage: PosixAddress = undefined;
    var len: posix.socklen_t = @sizeOf(PosixAddress);
    _ = sys.getsockname(fd, &storage.any, &len);
    return std.mem.bigToNative(u16, storage.in.port);
}

/// A query frame (length prefix included) for `name`/`type` with `id`.
fn queryFrame(buf: []u8, id: u16, name: []const u8, t: wire.Type) []const u8 {
    var nbuf: [255]u8 = undefined;
    const m: wire.Message = .{ .id = id, .flags = .{ .rd = true }, .question = &.{.{ .name = wire.nameFromText(&nbuf, name) catch unreachable, .type = t }} };
    const n = m.encode(buf[2..]) catch unreachable;
    std.mem.writeInt(u16, buf[0..2], @intCast(n), .big);
    return buf[0 .. 2 + n];
}

/// Reads into `got` until `want` bytes arrived, stepping the server; false on EOF or no progress.
fn readSome(l: *Loopback, fd: posix.fd_t, got: *std.ArrayList(u8), want: usize) !bool {
    var buf: [4096]u8 = undefined;
    for (0..10_000) |_| {
        if (got.items.len >= want) return true;
        try l.server.step(0);
        const rc = sys.recvfrom(fd, &buf, buf.len, 0, null, null);
        switch (posix.errno(rc)) {
            .SUCCESS => if (rc == 0) return false else try got.appendSlice(testing.allocator, buf[0..@intCast(rc)]),
            .AGAIN, .INTR => {},
            else => return false,
        }
    }
    return false;
}

test "a client that does not read stalls only its own connection, within a total deadline (review A2)" {
    const l = try Loopback.init(testing.allocator, .{});
    defer l.deinit();
    const slow = try l.connect();
    defer _ = sys.close(slow);
    const small = std.mem.toBytes(@as(c_int, 4096));
    try posix.setsockopt(slow, posix.SOL.SOCKET, posix.SO.RCVBUF, &small);
    // 100 pipelined queries for a 64 KiB RRset, never read: megabytes of answers.
    var qbuf: [512]u8 = undefined;
    for (0..100) |i| {
        const q = queryFrame(&qbuf, @intCast(i), "huge.uchi.example.org.", .txt);
        try testing.expectEqual(@as(isize, @intCast(q.len)), @as(isize, @bitCast(sys.sendto(slow, q.ptr, q.len, 0, null, 0))));
    }
    // No turn of the loop waits on the slow reader (sendAll waited up to 1 s per full buffer).
    var token: ?usize = null;
    for (0..1000) |_| {
        const t0 = nowMs();
        try l.server.step(0);
        try testing.expect(nowMs() - t0 < 200);
        for (l.server.slots, 0..) |slot, i| if (slot == .conn and slot.conn.pending.items.len > 0) {
            token = i;
        };
        if (token != null) break;
    }
    const c = &l.server.slots[token.?].conn;
    try testing.expect(c.messages < 100); // reading paused behind the pending answer
    try testing.expect(c.deadline <= nowMs() + write_timeout_ms);
    // A UDP client is answered meanwhile.
    const udp = try clientSocket(l.addr, posix.SOCK.DGRAM);
    defer _ = sys.close(udp);
    var storage: PosixAddress = undefined;
    const q = queryFrame(&qbuf, 7, "hub.kekkai.uchi.example.org.", .a)[2..];
    _ = sys.sendto(udp, q.ptr, q.len, 0, &storage.any, sockaddr(l.udp_addr, &storage));
    var answer: [512]u8 = undefined;
    const n = for (0..1000) |_| {
        try l.server.step(0);
        const rc = sys.recvfrom(udp, &answer, answer.len, 0, null, null);
        if (posix.errno(rc) == .SUCCESS) break @as(usize, @intCast(rc));
    } else return error.NoAnswer;
    try testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, answer[0..2], .big));
    try testing.expect(n > 12);
    // Past its deadline the connection is closed and its slot released.
    c.deadline = 0;
    try l.server.step(0);
    try testing.expectEqual(@as(usize, 0), l.conns());
}

test "the TCP connection cap is 64 with and without the metrics listener (review A13)" {
    for ([_]bool{ false, true }) |with_metrics| {
        const l = try Loopback.init(testing.allocator, .{ .metrics = with_metrics });
        defer l.deinit();
        var clients: [max_conns + 1]posix.fd_t = undefined;
        for (&clients) |*fd| fd.* = try l.connect();
        defer for (clients) |fd| {
            _ = sys.close(fd);
        };
        for (0..4 * clients.len) |_| try l.server.step(0);
        try testing.expectEqual(@as(usize, max_conns), l.conns());
    }
}

test "three maximum forwarded replies drain an unwritable TCP connection without overflow (review B3)" {
    const any = try net.IpAddress.parse("127.0.0.1", 0);
    const up = try open(any, posix.SOCK.DGRAM);
    defer _ = sys.close(up);
    const upstream = try net.IpAddress.parse("127.0.0.1", localPort(up));
    const l = try Loopback.init(testing.allocator, .{ .forwarding = .{ .upstreams = &.{upstream} } });
    defer l.deinit();
    const fd = try l.connect();
    defer _ = sys.close(fd);
    for (0..1000) |_| {
        try l.server.step(0);
        if (l.conns() == 1) break;
    }
    try testing.expectEqual(@as(usize, 1), l.conns());
    const s = l.server;
    const token = s.first_conn;
    const c = &s.slots[token].conn;
    const small = std.mem.toBytes(@as(c_int, 4096));
    try posix.setsockopt(c.fd, posix.SOL.SOCKET, posix.SO.SNDBUF, &small);
    try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &small);
    // Fill the kernel buffer first; the client deliberately reads nothing until completion.
    const padding: [16384]u8 = @splat(0);
    var padded: usize = 0;
    for (0..1024) |_| {
        const n = sendSome(c.fd, &padding) orelse return error.Closed;
        padded += n;
        if (n == 0) break;
    } else return error.StillWritable;
    for (0..3) |id| c.len += queryFrame(c.buf[c.len..], @intCast(id), ".", .a).len;
    s.frames(token, c);
    // Before B3 all three waiters joined one completion batch, which could overflow pending.
    try testing.expectEqual(@as(u32, 1), c.messages);
    try testing.expect(c.waiting);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var packet: [max_message]u8 = undefined;
    const rdata: [max_message - 28]u8 = @splat(0); // root question (17) + root RR header (11)
    const response: wire.Message = .{
        .flags = .{ .qr = true },
        .question = &.{.{ .name = "\x00", .type = .a }},
        .answer = &.{.{ .name = "\x00", .type = @enumFromInt(65280), .rdata = &rdata }},
    };
    const len = try response.encode(&packet);
    try testing.expectEqual(@as(usize, max_message), len);
    for (0..3) |id| {
        const pending = for (s.pending, 0..) |p, i| {
            if (p != null) break i;
        } else return error.NoPendingQuery;
        try testing.expectEqual(@as(usize, 1), s.pending[pending].?.waiters.items.len);
        s.complete(pending, &packet);
        try testing.expectEqual(@as(usize, 1), l.conns());
        try testing.expect(c.pending.items.len <= max_pending_output);
        if (id == 0) try testing.expect(c.pending.items.len > 0);
        try testing.expect(try readSome(l, fd, &got, padded + (id + 1) * (2 + max_message)));
        const start = padded + id * (2 + max_message);
        try testing.expectEqual(@as(u16, max_message), std.mem.readInt(u16, got.items[start..][0..2], .big));
        try testing.expectEqual(@as(u16, @intCast(id)), std.mem.readInt(u16, got.items[start + 2 ..][0..2], .big));
    }
    try testing.expectEqual(padded + 3 * (2 + max_message), got.items.len);
    try testing.expectEqual(@as(u32, 3), c.messages);
    _ = sys.shutdown(fd, posix.SHUT.WR);
    try testing.expect(!try readSome(l, fd, &got, got.items.len + 1));
    try testing.expectEqual(@as(usize, 0), l.conns());
}

test "a TCP client's EOF does not drop the forwarded answer it is owed (review A16)" {
    // A fake upstream that answers only when the test says so.
    const any = try net.IpAddress.parse("127.0.0.1", 0);
    const up = try open(any, posix.SOCK.DGRAM);
    defer _ = sys.close(up);
    const up_addr = try net.IpAddress.parse("127.0.0.1", localPort(up));
    const l = try Loopback.init(testing.allocator, .{ .forwarding = .{ .upstreams = &.{up_addr} } });
    defer l.deinit();
    const fd = try l.connect();
    defer _ = sys.close(fd);
    var qbuf: [512]u8 = undefined;
    const q = queryFrame(&qbuf, 0x4242, "www.example.net.", .a);
    _ = sys.sendto(fd, q.ptr, q.len, 0, null, 0);
    _ = sys.shutdown(fd, posix.SHUT.WR);
    var ubuf: [512]u8 = undefined;
    var peer: PosixAddress = undefined;
    var peer_len: posix.socklen_t = @sizeOf(PosixAddress);
    const n = for (0..1000) |_| {
        try l.server.step(0);
        const rc = sys.recvfrom(up, &ubuf, ubuf.len, 0, &peer.any, &peer_len);
        if (posix.errno(rc) == .SUCCESS) break @as(usize, @intCast(rc));
    } else return error.NoUpstreamQuery;
    for (0..50) |_| try l.server.step(0); // the EOF is read while the upstream is silent
    try testing.expectEqual(@as(usize, 1), l.conns());
    var events: [64]poll.Event = undefined;
    try testing.expectEqual(@as(usize, 0), (try l.server.poller.wait(&events, 0)).len);
    // The upstream answers: the client still gets it, then the connection closes.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const asked = try wire.Message.parse(arena.allocator(), ubuf[0..n]);
    const reply: wire.Message = .{ .id = asked.id, .flags = .{ .qr = true, .rd = true, .ra = true }, .question = asked.question, .answer = &.{.{ .name = asked.question[0].name, .type = .a, .ttl = 60, .rdata = "\xc0\x00\x02\x01" }} };
    var rbuf: [512]u8 = undefined;
    const rlen = try reply.encode(&rbuf);
    _ = sys.sendto(up, &rbuf, rlen, 0, &peer.any, peer_len);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    try testing.expect(try readSome(l, fd, &got, 2));
    const end = frameEnd(got.items) orelse blk: {
        try testing.expect(try readSome(l, fd, &got, 2 + @as(usize, std.mem.readInt(u16, got.items[0..2], .big))));
        break :blk frameEnd(got.items).?;
    };
    const m = try wire.Message.parse(arena.allocator(), got.items[2..end]);
    try testing.expect(m.id == 0x4242 and m.flags.qr and m.answer.len == 1);
    try testing.expect(!try readSome(l, fd, &got, end + 1)); // then EOF
    try testing.expectEqual(@as(usize, 0), l.conns());
}

test "a reset while waiting releases the TCP slot within eight steps (review R1)" {
    for ([_]bool{ false, true }) |coalesced| {
        var probe = try ForwardProbe.init(testing.allocator);
        defer probe.deinit();
        const l = probe.l;
        const s = l.server;
        var fd = try l.connect();
        defer if (fd >= 0) {
            _ = sys.close(fd);
        };
        var qbuf: [512]u8 = undefined;
        try probeSend(fd, queryFrame(&qbuf, 1, "www.example.net.", .a), null, 0);
        var packet: [512]u8 = undefined;
        var peer: PosixAddress = undefined;
        var peer_len: posix.socklen_t = @sizeOf(PosixAddress);
        const len = try probe.receive(probe.udp, &packet, &peer, &peer_len);
        const token = s.first_conn;
        try testing.expect(s.slots[token].conn.waiting);
        const gen = s.slots[token].conn.gen;
        const survivor = if (coalesced) try l.connect() else -1;
        defer if (survivor >= 0) {
            _ = sys.close(survivor);
        };
        if (coalesced) {
            try probeSend(survivor, queryFrame(&qbuf, 2, "www.example.net.", .a), null, 0);
            for (0..8) |_| {
                try s.step(10);
                if (s.pending[0].?.waiters.items.len == 2) break;
            }
            try testing.expectEqual(@as(usize, 2), s.pending[0].?.waiters.items.len);
        }
        const reset = std.mem.toBytes(posix.linger{ .onoff = 1, .linger = 0 });
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.LINGER, &reset);
        _ = sys.close(fd);
        fd = -1;
        for (0..8) |_| {
            try s.step(10);
            if (s.slots[token] == .free) break;
        }
        try testing.expect(s.slots[token] == .free);
        try testing.expect(!s.awaited(token, gen));
        try testing.expectEqual(@as(usize, @intFromBool(coalesced)), l.conns());
        if (coalesced) {
            try testing.expectEqual(@as(usize, 1), s.pending[0].?.waiters.items.len);
        } else {
            for (s.pending) |pending| try testing.expect(pending == null);
        }
        var events: [64]poll.Event = undefined;
        try testing.expectEqual(@as(usize, 0), (try s.poller.wait(&events, 0)).len);

        // Reuse the connection slot before a late answer: it must not reach the new generation.
        const replacement = try l.connect();
        defer _ = sys.close(replacement);
        for (0..8) |_| {
            try s.step(10);
            if (s.slots[token] == .conn) break;
        }
        try testing.expect(s.slots[token] == .conn and s.slots[token].conn.gen != gen);
        packet[2] |= 0x80;
        try probeSend(probe.udp, packet[0..len], &peer, peer_len);
        if (coalesced) {
            var got: std.ArrayList(u8) = .empty;
            defer got.deinit(testing.allocator);
            try testing.expect(try readSome(l, survivor, &got, 4));
            try testing.expectEqual(@as(u16, 2), std.mem.readInt(u16, got.items[2..4], .big));
        }
        for (0..8) |_| try s.step(0);
        try testing.expect(!try probeAvailable(replacement, &qbuf));
    }
}

test "six pipelined queries with 1.8 second upstream replies all complete (review R2)" {
    var probe = try ForwardProbe.init(testing.allocator);
    defer probe.deinit();
    const l = probe.l;
    const fd = try l.connect();
    defer _ = sys.close(fd);
    var stream: [1024]u8 = undefined;
    var size: usize = 0;
    for (0..6) |id| {
        var name: [32]u8 = undefined;
        size += queryFrame(stream[size..], @intCast(id), try std.fmt.bufPrint(&name, "q{d}.example.net.", .{id}), .a).len;
    }
    try probeSend(fd, stream[0..size], null, 0);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var total: usize = 0;
    for (0..6) |id| {
        var packet: [512]u8 = undefined;
        var peer: PosixAddress = undefined;
        var peer_len: posix.socklen_t = @sizeOf(PosixAddress);
        const len = try probe.receive(probe.udp, &packet, &peer, &peer_len);
        const asked = try wire.Message.parse(arena.allocator(), packet[0..len]);
        const until = nowMs() + 1800;
        while (nowMs() < until) try l.server.step(10);
        try testing.expectEqual(@as(usize, 1), l.conns());
        const response: wire.Message = .{
            .id = asked.id,
            .flags = .{ .qr = true },
            .question = asked.question,
            .answer = &.{.{ .name = asked.question[0].name, .type = .a, .ttl = 60, .rdata = "\xc0\x00\x02\x01" }},
        };
        var reply: [512]u8 = undefined;
        const n = try response.encode(&reply);
        try probeSend(probe.udp, reply[0..n], &peer, peer_len);
        try testing.expect(try readSome(l, fd, &got, total + 2));
        const end = total + 2 + @as(usize, std.mem.readInt(u16, got.items[total..][0..2], .big));
        try testing.expect(try readSome(l, fd, &got, end));
        const answer = try wire.Message.parse(arena.allocator(), got.items[total + 2 .. end]);
        try testing.expectEqual(@as(u16, @intCast(id)), answer.id);
        try testing.expect(answer.flags.rcode == 0 and answer.answer.len == 1);
        try testing.expectEqualSlices(u8, asked.question[0].name, answer.question[0].name);
        total = end;
    }
    _ = sys.shutdown(fd, posix.SHUT.WR);
    try testing.expect(!try readSome(l, fd, &got, total + 1));
    try testing.expectEqual(@as(usize, 0), l.conns());
}

/// Frames and garbage as a client could send them: valid queries, short and empty messages,
/// responses, junk that shifts the framing, and incomplete 0xfffe/0xffff prefixes.
fn randomStream(r: std.Random, buf: []u8) []const u8 {
    var len: usize = 0;
    const pieces = r.uintLessThan(usize, 120);
    for (0..pieces) |_| {
        if (buf.len - len < 70000 - 65537) break;
        switch (r.uintLessThan(u8, 8)) {
            0, 1, 2 => len += queryFrame(buf[len..], r.int(u16), if (r.boolean()) "hub.kekkai.uchi.example.org." else "big.uchi.example.org.", if (r.boolean()) .a else .txt).len,
            3 => { // a frame of 0, 1, 11 or 12 to 40 random bytes, possibly a response
                const n: usize = switch (r.uintLessThan(u8, 4)) {
                    0 => 0,
                    1 => 1,
                    2 => 11,
                    else => 12 + r.uintLessThan(usize, 29),
                };
                std.mem.writeInt(u16, buf[len..][0..2], @intCast(n), .big);
                r.bytes(buf[len + 2 ..][0..n]);
                len += 2 + n;
            },
            4 => { // junk that shifts the framing
                const n = 1 + r.uintLessThan(usize, 32);
                r.bytes(buf[len..][0..n]);
                len += n;
            },
            5 => { // a prefix announcing a frame that never completes
                std.mem.writeInt(u16, buf[len..][0..2], if (r.boolean()) 0xfffe else 0xffff, .big);
                len += 2 + r.uintLessThan(usize, 64);
                return buf[0..len];
            },
            else => len += queryFrame(buf[len..], r.int(u16), "nope.uchi.example.org.", .aaaa).len,
        }
    }
    return buf[0..len];
}

test "TCP framing and connection state under random streams split at random points (review A17)" {
    const l = try Loopback.init(testing.allocator, .{});
    defer l.deinit();
    var prng = std.Random.DefaultPrng.init(0xa17);
    const r = prng.random();
    const buf = try testing.allocator.alloc(u8, 70000);
    defer testing.allocator.free(buf);
    @memset(buf, 0);
    for (0..100) |_| try l.checkStream(randomStream(r, buf), r);
    // Boundaries: empty and 1-byte streams, 0/1/11-byte messages, 0xfffe/0xffff prefixes, a whole 65535-byte frame.
    for ([_][]const u8{ "", "\x00", "\x00\x00", "\x00\x01\x00", "\x00\x0b" ++ "\x00" ** 11, "\xff\xfe", "\xff\xff" ++ "\x00" ** 100 }) |s| try l.checkStream(s, r);
    var full: [2 + max_message]u8 = @splat(0);
    std.mem.writeInt(u16, full[0..2], max_message, .big);
    try l.checkStream(&full, r);
    // The message cap: 100 answered, the 101st closes the connection.
    for ([_]usize{ 100, 101 }) |count| {
        var len: usize = 0;
        for (0..count) |i| len += queryFrame(buf[len..], @intCast(i), "hub.kekkai.uchi.example.org.", .a).len;
        try l.checkStream(buf[0..len], r);
    }
}

test "review A14: entropy retries interruptions and short reads, fails closed" {
    const Reader = struct {
        var calls: usize = 0;
        fn short(buf: []u8) error{ Interrupted, Entropy }!usize {
            calls += 1;
            if (calls == 1) return error.Interrupted;
            buf[0] = @intCast(calls);
            return 1;
        }
        fn failed(_: []u8) error{ Interrupted, Entropy }!usize {
            return error.Entropy;
        }
        fn partial(buf: []u8) error{ Interrupted, Entropy }!usize {
            calls += 1;
            if (calls != 1) return error.Entropy;
            buf[0] = 42;
            return 1;
        }
        fn empty(_: []u8) error{ Interrupted, Entropy }!usize {
            return 0;
        }
    };
    Reader.calls = 0;
    try testing.expectEqual(@as(u16, 0x0302), try randomId(Reader.short));
    try testing.expectError(error.Entropy, randomId(Reader.failed));
    try testing.expectError(error.Entropy, randomId(Reader.empty));
    Reader.calls = 0;
    try testing.expectError(error.Entropy, randomId(Reader.partial));
}

/// Fake upstream used by the forward fuzzer and its deterministic regressions. Both UDP and
/// TCP responses go through Server's sockets, validation, completion and cache-hit path.
pub const ForwardProbe = struct {
    l: *Loopback,
    udp: posix.fd_t,
    tcp: posix.fd_t,
    client: posix.fd_t,
    rogue: posix.fd_t,

    pub const Case = enum { arbitrary, matching, wrong_id, wrong_question, tc_twice, tcp_answer, mixed_ttls, cname_nodata, badvers, short_tcp, legacy, wrong_source };

    pub fn init(gpa: std.mem.Allocator) !ForwardProbe {
        const any = try net.IpAddress.parse("127.0.0.1", 0);
        const udp = try open(any, posix.SOCK.DGRAM);
        errdefer _ = sys.close(udp);
        const addr = try net.IpAddress.parse("127.0.0.1", localPort(udp));
        const tcp = try open(addr, posix.SOCK.STREAM);
        errdefer _ = sys.close(tcp);
        const l = try Loopback.init(gpa, .{ .forwarding = .{ .upstreams = &.{addr} } });
        errdefer l.deinit();
        const client = try connectUdp(l.udp_addr, "");
        errdefer _ = sys.close(client);
        const receive_bytes = std.mem.toBytes(@as(c_int, 256 * 1024));
        try posix.setsockopt(client, posix.SOL.SOCKET, posix.SO.RCVBUF, &receive_bytes);
        const rogue = try open(any, posix.SOCK.DGRAM);
        return .{ .l = l, .udp = udp, .tcp = tcp, .client = client, .rogue = rogue };
    }

    pub fn deinit(p: *ForwardProbe) void {
        for ([_]posix.fd_t{ p.udp, p.tcp, p.client, p.rogue }) |fd| _ = sys.close(fd);
        p.l.deinit();
    }

    /// Bounded memory includes the server's per-request arena, including all coalesced waiters.
    pub fn run(p: *ForwardProbe, a: std.mem.Allocator, input: []const u8, case: Case, count: usize) !void {
        const s = p.l.server;
        s.cache.deinit();
        s.cache = .init(s.gpa, 1 << 20);
        s.arena.deinit();
        s.arena = .init(a);
        defer {
            s.arena.deinit();
            s.arena = .init(s.gpa);
        }
        const name = "\x03www\x07example\x03net\x00";
        const alias = "\x02ns\x07example\x03net\x00";
        const question: wire.Question = .{ .name = "\x03WWW\x07EXAMPLE\x03NET\x00", .type = .a };
        var buf: [65535]u8 = undefined;
        for (0..count) |id| {
            const query: wire.Message = .{ .id = @intCast(id), .flags = .{ .rd = true }, .question = &.{question}, .additional = &.{(wire.Opt{ .payload = 1232 }).toRR()} };
            const n = try query.encode(&buf);
            try probeSend(p.client, buf[0..n], null, 0);
            try s.step(0);
        }
        var peer: PosixAddress = undefined;
        var peer_len: posix.socklen_t = @sizeOf(PosixAddress);
        const n = try p.receive(p.udp, &buf, &peer, &peer_len);
        const asked = try wire.Message.parse(a, buf[0..n]);
        const good: wire.Message = .{ .id = asked.id, .flags = .{ .qr = true }, .question = asked.question, .answer = &.{.{ .name = name, .type = .a, .ttl = 300, .rdata = "1234" }} };
        var response = good;
        switch (case) {
            .arbitrary => {},
            .matching => {
                response = wire.Message.parse(a, input) catch good;
                response.id = asked.id;
                response.flags.qr = true;
                response.flags.opcode = 0;
                response.question = asked.question;
            },
            .wrong_id => response.id +%= 1,
            .wrong_question => response.question = &.{.{ .name = alias, .type = .a }},
            .tc_twice, .tcp_answer, .short_tcp => response.flags.tc = true,
            .mixed_ttls => {
                response.answer = &.{ .{ .name = name, .type = .cname, .ttl = 300, .rdata = alias }, .{ .name = alias, .type = .a, .ttl = 30, .rdata = "1234" } };
                response.additional = &.{.{ .name = alias, .type = .a, .ttl = 5, .rdata = "5678" }};
            },
            .cname_nodata => {
                response.answer = &.{.{ .name = name, .type = .cname, .ttl = 300, .rdata = alias }};
                response.authority = &.{.{ .name = "\x00", .type = .soa, .ttl = 3600, .rdata = "\x00\x00" ++ "\x00" ** 19 ++ "\x1e" }};
            },
            .badvers => {
                response.answer = &.{};
                response.additional = &.{(wire.Opt{ .payload = 1232, .ext_rcode = 1 }).toRR()};
            },
            .legacy => response.answer = &.{ .{ .name = name, .type = .ns, .ttl = 300, .rdata = alias }, .{ .name = name, .type = @enumFromInt(17), .ttl = 30, .rdata = alias ++ alias } },
            .wrong_source => {},
        }
        var packet: []const u8 = try a.dupe(u8, if (case == .arbitrary) input[0..@min(input.len, 65507)] else buf[0 .. response.encode(&buf) catch try good.encode(&buf)]);
        if (case == .legacy) {
            var w = try wire.Writer.init(&buf, asked.id, .{ .qr = true });
            try w.question(asked.question[0]);
            const ns_at = w.len;
            try w.rr(.answer, .{ .name = name, .type = .ns, .ttl = 300, .rdata = alias });
            var raw: [4]u8 = undefined;
            const pointer = 0xc000 | @as(u16, @intCast(ns_at + 12));
            std.mem.writeInt(u16, raw[0..2], pointer, .big);
            std.mem.writeInt(u16, raw[2..4], pointer, .big);
            const at = w.len;
            try w.rr(.answer, .{ .name = name, .type = @enumFromInt(65000), .ttl = 30, .rdata = &raw });
            std.mem.writeInt(u16, buf[at + 2 ..][0..2], 17, .big);
            packet = try a.dupe(u8, buf[0..w.len]);
        }
        packet = packet[0..@min(packet.len, 65507)];
        // The oracle evaluates the actual bytes, including malformed EDNS and unmatched questions.
        var upstream = wire.Message.parse(a, packet) catch null;
        const valid = if (upstream) |m| blk: {
            _ = m.edns() catch break :blk false;
            break :blk m.id == asked.id and m.flags.qr and m.flags.opcode == 0 and m.question.len == 1 and
                m.question[0].class == .in and m.question[0].type == .a and std.ascii.eqlIgnoreCase(m.question[0].name, name);
        } else false;
        const retry = valid and upstream.?.flags.tc;
        var tcp_reply: [65537]u8 = undefined;
        var worker: ?std.Thread = null;
        if (retry) {
            // shortcut: pace TCP retries below TIME_WAIT port exhaustion, like the tcp target.
            _ = posix.poll(&.{}, 3) catch {};
            // Short TCP frames must fail rather than accepting the parseable UDP packet.
            std.mem.writeInt(u16, tcp_reply[0..2], @intCast(packet.len), .big);
            @memcpy(tcp_reply[2..][0..packet.len], packet);
            var len = packet.len + 2;
            if (case == .tcp_answer) {
                var full = upstream.?;
                full.flags.tc = false;
                const size = try full.encode(tcp_reply[2..]);
                std.mem.writeInt(u16, tcp_reply[0..2], @intCast(size), .big);
                len = size + 2;
                upstream = try wire.Message.parse(a, try a.dupe(u8, tcp_reply[2..len]));
            }
            if (case == .short_tcp) len = 3;
            worker = try std.Thread.spawn(.{}, probeTcp, .{ p.tcp, tcp_reply[0..len] });
        }
        defer if (worker) |thread| thread.join();
        if (case == .wrong_source) {
            try probeSend(p.rogue, packet, &peer, peer_len);
            for (0..8) |_| try s.step(0);
            if (try probeAvailable(p.client, &buf)) return error.UnmatchedResponse;
        }
        try probeSend(p.udp, packet, &peer, peer_len);
        if (!valid) {
            for (0..8) |_| try s.step(0);
            if (try probeAvailable(p.client, &buf)) return error.UnmatchedResponse;
            packet = try a.dupe(u8, buf[0..try good.encode(&buf)]);
            upstream = good;
            try probeSend(p.udp, packet, &peer, peer_len);
        }
        for (0..count) |id| {
            const len = try p.receive(p.client, &buf, null, null);
            const reply = try wire.Message.parse(a, buf[0..len]);
            if (!reply.flags.qr or reply.id != id or reply.question.len != 1 or !std.mem.eql(u8, reply.question[0].name, question.name)) return error.UnmatchedResponse;
            if (retry and case != .tcp_answer) {
                if (reply.flags.rcode != 2 or s.cache.map.count() != 0) return error.TruncatedCached;
                continue;
            }
            const m = upstream.?;
            const opt = try m.edns();
            const ext = if (opt) |o| o.ext_rcode else 0;
            const expected = if (ext == 0 and m.flags.rcode != 0 and m.flags.rcode != 3) 2 else m.flags.rcode;
            if (reply.flags.rcode != expected) return error.RcodeLost;
            if (ext != 0 and (try reply.edns()).?.ext_rcode != ext) return error.RcodeLost;
            if (ext != 0 and s.cache.map.count() != 0) return error.ErrorCached;
            if (expected != 2) try probeTtls(m, reply, 0);
        }
        // Exercise a real cache hit after advancing the entry's age by two seconds.
        var keys: [257]u8 = undefined;
        if (s.cache.get(forward.key(&keys, name, .a), @divTrunc(nowMs(), 1000))) |entry| {
            const lifetime = entry.expires - entry.inserted;
            for ([_][]const wire.RR{ upstream.?.answer, upstream.?.authority, upstream.?.additional }) |section| {
                for (section) |rr| if (rr.type != .opt and lifetime > rr.ttl) return error.TtlExtended;
            }
            if (case == .cname_nodata and lifetime > 30) return error.TtlExtended;
            if (lifetime <= 3) return;
            const e = @constCast(entry);
            e.inserted -= 2;
            e.expires -= 2;
            const query: wire.Message = .{ .id = 100, .question = &.{question}, .additional = &.{(wire.Opt{ .payload = 1232 }).toRR()} };
            const len = try query.encode(&buf);
            try probeSend(p.client, buf[0..len], null, 0);
            const got = try p.receive(p.client, &buf, null, null);
            const reply = try wire.Message.parse(a, buf[0..got]);
            if (reply.id != 100) return error.UnmatchedResponse;
            try probeTtls(upstream.?, reply, 2);
        }
    }

    fn receive(p: *ForwardProbe, fd: posix.fd_t, buf: []u8, peer: ?*PosixAddress, peer_len: ?*posix.socklen_t) !usize {
        for (0..1000) |_| {
            try p.l.server.step(0);
            const rc = sys.recvfrom(fd, buf.ptr, buf.len, 0, if (peer) |addr| &addr.any else null, peer_len);
            switch (posix.errno(rc)) {
                .SUCCESS => return @intCast(rc),
                .AGAIN, .INTR => {},
                else => return error.Receive,
            }
        }
        return error.NoResponse;
    }
};

fn probeSend(fd: posix.fd_t, bytes: []const u8, peer: ?*PosixAddress, len: posix.socklen_t) !void {
    const rc = sys.sendto(fd, bytes.ptr, bytes.len, 0, if (peer) |addr| &addr.any else null, len);
    if (posix.errno(rc) != .SUCCESS or rc != bytes.len) return error.Send;
}

fn probeAvailable(fd: posix.fd_t, buf: []u8) !bool {
    const rc = sys.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
    return switch (posix.errno(rc)) {
        .SUCCESS => true,
        .AGAIN, .INTR => false,
        else => error.Receive,
    };
}

fn probeTcp(listener: posix.fd_t, reply: []const u8) void {
    if (!waitFd(listener, posix.POLL.IN, nowMs() + 1000)) return;
    var peer: PosixAddress = undefined;
    const fd = acceptConn(listener, &peer) orelse return;
    defer _ = sys.close(fd);
    var buf: [1024]u8 = undefined;
    var got: usize = 0;
    while (frameEnd(buf[0..got]) == null) {
        if (!waitFd(fd, posix.POLL.IN, nowMs() + 1000)) return;
        const rc = sys.recvfrom(fd, buf[got..].ptr, buf.len - got, 0, null, null);
        if (posix.errno(rc) != .SUCCESS or rc == 0) return;
        got += @intCast(rc);
    }
    sendAll(fd, reply, nowMs() + 1000) catch {};
}

fn probeTtls(upstream: wire.Message, reply: wire.Message, age: u32) !void {
    inline for (.{ "answer", "authority", "additional" }) |section| {
        for (@field(reply, section)) |rr| {
            if (rr.type == .opt) continue;
            const original = for (@field(upstream, section)) |src| {
                if (src.type == rr.type and std.mem.eql(u8, src.rdata, rr.rdata) and std.mem.eql(u8, src.name, rr.name)) break src;
            } else return error.UnmatchedRecord;
            if (rr.ttl > original.ttl -| age) return error.TtlExtended;
        }
    }
}

test "review A6 A17 A18: fake upstream validates questions, TCP truncation, rcodes and cache TTLs" {
    var probe = try ForwardProbe.init(testing.allocator);
    defer probe.deinit();
    for (std.enums.values(ForwardProbe.Case)) |case| {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        try probe.run(arena.allocator(), "arbitrary upstream bytes", case, 64);
    }
}
