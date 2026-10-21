//! TSIG (RFC 8945) with HMAC-SHA256 only (ADR 0006): verifies the signature of a request and
//! signs the response, including the unsigned BADKEY/BADSIG and the signed BADTIME error forms.
//! The request digest covers the message without its TSIG RR (ARCOUNT decremented, ID set back
//! to the original ID) followed by the TSIG variables; the response digest starts with the
//! length-prefixed request MAC.

const std = @import("std");
const wire = @import("wire.zig");
const zone = @import("zone.zig");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const algorithm = "\x0bhmac-sha256\x00";
pub const mac_len = Hmac.mac_length;
/// The shortest truncated MAC RFC 8945 §5.2.2.1 allows for HMAC-SHA256: max(10, 32 / 2).
pub const min_mac_len = mac_len / 2;

pub const Error = enum(u16) { none = 0, badsig = 16, badkey = 17, badtime = 18 };

pub const Key = struct {
    /// Lowercase wire name.
    name: []const u8,
    secret: []const u8,
};

/// The request's TSIG RR as checked, and what the response TSIG RR must carry.
pub const Status = struct {
    /// The key the request verified against (set for BADTIME too); null = unsigned error response.
    key: ?*const Key,
    /// Key and algorithm names as sent, echoed in the response.
    name: []const u8,
    alg: []const u8,
    time: u48,
    fudge: u16,
    original_id: u16,
    /// The request MAC, first component of the response digest.
    mac: []const u8,
    err: Error,

    /// Bytes the response TSIG RR takes: owner, fixed fields, algorithm, MAC, other data.
    pub fn size(s: Status) usize {
        return s.name.len + 10 + s.alg.len + 16 + @as(usize, if (s.key != null) mac_len else 0) + @as(usize, if (s.err == .badtime) 6 else 0);
    }
};

/// Checks the TSIG RR of `packet`, already parsed as `m`, against `keys` at wall-clock `now`
/// (seconds). Null when the message carries no TSIG; `error.Malformed` is a FORMERR.
pub fn verify(keys: []const Key, packet: []const u8, m: wire.Message, now: i64) error{Malformed}!?Status {
    const at = m.tsig_at orelse {
        for (m.additional) |rr| if (rr.type == .tsig) return error.Malformed; // not the last RR
        return null;
    };
    const rr = m.additional[m.additional.len - 1];
    for (m.additional[0 .. m.additional.len - 1]) |o| if (o.type == .tsig) return error.Malformed;
    if (rr.class != .any or rr.ttl != 0) return error.Malformed;
    var r: wire.Reader = .{ .buf = rr.rdata };
    const alg = try plainName(rr.rdata);
    r.pos = alg.len;
    var s: Status = .{ .key = null, .name = rr.name, .alg = alg, .time = try r.int(u48), .fudge = try r.int(u16), .original_id = 0, .mac = "", .err = .badkey };
    // RFC 8945 §5.2.2.1: longer than the hash or shorter than max(10, half the hash) is FORMERR.
    // Local policy (§5.2.4) accepts every legal length, so BADTRUNC is never sent (review A7).
    const size = try r.int(u16);
    if (size > mac_len or size < min_mac_len) return error.Malformed;
    s.mac = try r.take(size);
    s.original_id = try r.int(u16);
    const request_err = try r.int(u16);
    const other = try r.take(try r.int(u16));
    if (r.pos != rr.rdata.len or s.size() > 400) return error.Malformed; // the response RR must fit a 512-byte answer

    var lowered: [255]u8 = undefined;
    @memcpy(lowered[0..rr.name.len], rr.name);
    const name = zone.lower(lowered[0..rr.name.len]);
    const key = for (keys) |*k| {
        if (std.mem.eql(u8, k.name, name)) break k;
    } else return s;
    if (!std.ascii.eqlIgnoreCase(alg, algorithm)) return s;

    var h = Hmac.init(key.secret);
    var header: [12]u8 = packet[0..12].*;
    std.mem.writeInt(u16, header[0..2], s.original_id, .big);
    std.mem.writeInt(u16, header[10..12], std.mem.readInt(u16, header[10..12], .big) - 1, .big);
    h.update(&header);
    h.update(packet[12..at]);
    variables(&h, key.name, s.time, s.fudge, request_err, other);
    var mac: [mac_len]u8 = undefined;
    h.final(&mac);
    // Only the sent prefix is compared, in constant time (the zeroed tails are equal).
    var sent = [_]u8{0} ** mac_len;
    @memcpy(sent[0..s.mac.len], s.mac);
    @memset(mac[s.mac.len..], 0);
    if (!std.crypto.timing_safe.eql([mac_len]u8, mac, sent)) {
        s.err = .badsig;
        return s;
    }
    s.key = key;
    s.err = if (@abs(now - @as(i64, s.time)) > s.fudge) .badtime else .none;
    return s;
}

/// Appends the response TSIG RR to the message `out[0..len]`, which must have `s.size()` bytes
/// to spare, and returns the new length. Signed when `s.key` is set.
pub fn sign(s: Status, out: []u8, len: usize, now: i64) usize {
    // RFC 8945 §5.2.3: a BADTIME response keeps the request's time and reports ours in Other Data.
    const now48: u48 = @intCast(@max(now, 0));
    const time: u48 = if (s.err == .badtime) s.time else now48;
    var other: [6]u8 = undefined;
    std.mem.writeInt(u48, &other, now48, .big);
    const other_len: usize = if (s.err == .badtime) 6 else 0;
    var mac: [mac_len]u8 = undefined;
    var mac_size: usize = 0;
    if (s.key) |k| {
        var h = Hmac.init(k.secret);
        var prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &prefix, @intCast(s.mac.len), .big);
        h.update(&prefix);
        h.update(s.mac);
        h.update(out[0..len]);
        variables(&h, k.name, time, s.fudge, @intFromEnum(s.err), other[0..other_len]);
        h.final(&mac);
        mac_size = mac_len;
    }
    return append(out, len, s.name, s.alg, time, s.fudge, mac[0..mac_size], s.original_id, @intFromEnum(s.err), other[0..other_len]);
}

/// Signs the request `out[0..len]` with `key` at `time`, keeping the first `mac_size` bytes of the
/// MAC, and returns the new length: what a client such as hanko sends (tests and the fuzzer).
pub fn signRequest(key: Key, out: []u8, len: usize, time: u48, mac_size: usize) usize {
    var h = Hmac.init(key.secret);
    h.update(out[0..len]);
    variables(&h, key.name, time, 300, 0, "");
    var mac: [mac_len]u8 = undefined;
    h.final(&mac);
    return append(out, len, key.name, algorithm, time, 300, mac[0..mac_size], std.mem.readInt(u16, out[0..2], .big), 0, "");
}

/// Appends a TSIG RR (owner uncompressed) to `out[0..len]` and bumps ARCOUNT.
fn append(out: []u8, len: usize, name: []const u8, alg: []const u8, time: u48, fudge: u16, mac: []const u8, original_id: u16, err: u16, other: []const u8) usize {
    var w: Appender = .{ .buf = out, .len = len };
    w.bytes(name);
    w.int(u16, @intFromEnum(wire.Type.tsig));
    w.int(u16, @intFromEnum(wire.Class.any));
    w.int(u32, 0);
    w.int(u16, @intCast(alg.len + 16 + mac.len + other.len));
    w.bytes(alg);
    w.int(u48, time);
    w.int(u16, fudge);
    w.int(u16, @intCast(mac.len));
    w.bytes(mac);
    w.int(u16, original_id);
    w.int(u16, err);
    w.int(u16, @intCast(other.len));
    w.bytes(other);
    std.mem.writeInt(u16, out[10..12], std.mem.readInt(u16, out[10..12], .big) + 1, .big);
    return w.len;
}

/// The TSIG variables of RFC 8945 §4.3.3, in canonical form: lowercase names, class ANY, TTL 0.
fn variables(h: *Hmac, name: []const u8, time: u48, fudge: u16, err: u16, other: []const u8) void {
    h.update(name);
    h.update(&.{ 0x00, 0xff, 0, 0, 0, 0 });
    h.update(algorithm);
    var fixed: [12]u8 = undefined;
    std.mem.writeInt(u48, fixed[0..6], time, .big);
    std.mem.writeInt(u16, fixed[6..8], fudge, .big);
    std.mem.writeInt(u16, fixed[8..10], err, .big);
    std.mem.writeInt(u16, fixed[10..12], @intCast(other.len), .big);
    h.update(&fixed);
    h.update(other);
}

/// The uncompressed name at the start of `buf` (RFC 8945 §4.2: the algorithm name is never compressed).
fn plainName(buf: []const u8) error{Malformed}![]const u8 {
    var i: usize = 0;
    while (i < buf.len and buf[i] <= 63 and i + 1 + buf[i] <= buf.len and i < 255) : (i += 1 + buf[i]) {
        if (buf[i] == 0) return buf[0 .. i + 1];
    }
    return error.Malformed;
}

const Appender = struct {
    buf: []u8,
    len: usize,

    fn bytes(w: *Appender, b: []const u8) void {
        @memcpy(w.buf[w.len..][0..b.len], b);
        w.len += b.len;
    }

    fn int(w: *Appender, comptime T: type, v: T) void {
        const n = @divExact(@bitSizeOf(T), 8);
        std.mem.writeInt(T, w.buf[w.len..][0..n], v, .big);
        w.len += n;
    }
};

// ---- tests -------------------------------------------------------------------------------------

const testing = std.testing;

/// Captured from BIND's `nsupdate -y hmac-sha256:hanko:<secret>`: zone example.org, one
/// `update add _acme-challenge.git.uchi.example.org 60 TXT "tok1"`, fudge 300. The expected
/// response MACs were computed independently with Python's hmac over the same components.
pub const vector = struct {
    pub const secret = "secret-secret-secret-secret-secret-1234";
    pub const key: Key = .{ .name = "\x05hanko\x00", .secret = secret };
    pub const time: u48 = 1792308221;
    pub const update = "6cb328000001000000010001076578616d706c65036f726700000600010f5f61636d652d6368616c6c656e6765036769740475636869c00c001000010000003c000504746f6b310568616e6b6f0000fa00ff00000000003d0b686d61632d7368613235360000006ad473fd012c0020dcebc399984f10a0666800f4a943f883faa152c3d028321381c7349dba7576046cb300000000";
    /// A NOERROR response (QR, opcode 5, the zone echoed) signed at `time`.
    pub const response_mac = "da8dcb317617b507f56dea13bacc8e99cc25f6be6f1cdd7b8bfec675c00ccb66";
    /// The NOERROR response to the same request signed with its MAC truncated to 16 bytes.
    pub const truncated_response_mac = "ee87d98f5db16dd2c17ebcf8597512407d777b7575e35b497766ed4aae62619e";
    /// The same with rcode NOTAUTH, error BADTIME and our time (`time` + 1000) in Other Data.
    pub const badtime_mac = "b11acc97eca352aa9d768c7e47c2b03020186342ce143dfb902d3a60edd01d9d";

    pub fn packet(buf: *[256]u8) []const u8 {
        return std.fmt.hexToBytes(buf, update) catch unreachable;
    }
};

test "verify BIND's request: ok, BADTIME outside the fudge, BADSIG, BADKEY, FORMERR" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [256]u8 = undefined;
    const pkt = vector.packet(&buf);
    const m = try wire.Message.parse(arena.allocator(), pkt);
    try testing.expectEqual(@as(?usize, pkt.len - 78), m.tsig_at);
    const keys = [_]Key{vector.key};

    const ok = (try verify(&keys, pkt, m, vector.time + 300)).?;
    try testing.expectEqual(Error.none, ok.err);
    try testing.expect(ok.key == &keys[0] and ok.fudge == 300 and ok.original_id == 0x6cb3 and ok.time == vector.time);
    try testing.expectEqual(Error.none, (try verify(&keys, pkt, m, vector.time - 300)).?.err);
    const late = (try verify(&keys, pkt, m, vector.time + 301)).?;
    try testing.expect(late.err == .badtime and late.key != null);

    const wrong = [_]Key{.{ .name = "\x05hanko\x00", .secret = "other" }};
    const badsig = (try verify(&wrong, pkt, m, vector.time)).?;
    try testing.expect(badsig.err == .badsig and badsig.key == null);
    const other = [_]Key{.{ .name = "\x05other\x00", .secret = vector.secret }};
    const badkey = (try verify(&other, pkt, m, vector.time)).?;
    try testing.expect(badkey.err == .badkey and badkey.key == null);
    try testing.expectEqualSlices(u8, "\x05hanko\x00", badkey.name);

    // No TSIG at all; a TSIG that is not the last RR.
    try testing.expectEqual(@as(?Status, null), try verify(&keys, pkt[0..12], .{}, vector.time));
    const rr = m.additional[0];
    const moved: wire.Message = .{ .additional = &.{ rr, (wire.Opt{ .payload = 512 }).toRR() } };
    try testing.expectError(error.Malformed, verify(&keys, pkt, moved, vector.time));
}

test "truncated MACs (RFC 8945 §5.2.2.1): 16 to 32 bytes verify, shorter or longer is FORMERR (review A7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var vbuf: [256]u8 = undefined;
    const pkt = vector.packet(&vbuf);
    const keys = [_]Key{vector.key};
    const bare = pkt.len - 78;
    var buf: [256]u8 = undefined;
    for ([_]usize{ 0, 1, 10, 15, 16, 17, 31, 32, 33 }) |size| {
        @memcpy(buf[0..bare], pkt[0..bare]);
        buf[11] = 0;
        var len = signRequest(vector.key, &buf, bare, vector.time, @min(size, mac_len));
        if (size == mac_len) try testing.expectEqualSlices(u8, pkt, buf[0..len]); // BIND's own request
        if (size > mac_len) { // one byte more than the hash: MAC Size and RDLENGTH grow, a byte is inserted
            const at = len - 6;
            std.mem.copyBackwards(u8, buf[at + 1 .. len + 1], buf[at..len]);
            buf[at] = 0;
            len += 1;
            buf[bare + 16] += 1; // RDLENGTH (low byte): after the owner (7 bytes), type, class and TTL
            buf[bare + 17 + 21] += 1; // MAC Size (low byte): after the algorithm (13), time and fudge
        }
        const m = try wire.Message.parse(arena.allocator(), buf[0..len]);
        if (size < min_mac_len or size > mac_len) {
            try testing.expectError(error.Malformed, verify(&keys, buf[0..len], m, vector.time));
            continue;
        }
        const s = (try verify(&keys, buf[0..len], m, vector.time)).?;
        try testing.expect(s.err == .none and s.mac.len == size);
        buf[len - 7] ^= 1; // the last MAC byte sent
        try testing.expectEqual(Error.badsig, (try verify(&keys, buf[0..len], m, vector.time)).?.err);
    }
    // The response digest starts with the truncated request MAC (Python oracle); ours is full length.
    @memcpy(buf[0..bare], pkt[0..bare]);
    buf[11] = 0;
    const len = signRequest(vector.key, &buf, bare, vector.time, 16);
    const s = (try verify(&keys, buf[0..len], try wire.Message.parse(arena.allocator(), buf[0..len]), vector.time)).?;
    var out: [512]u8 = undefined;
    const response = "\x6c\xb3\xa8\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x06\x00\x01";
    @memcpy(out[0..response.len], response);
    const n = sign(s, &out, response.len, vector.time);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, vector.truncated_response_mac);
    try testing.expectEqualSlices(u8, &want, out[n - 38 .. n - 6]);
}

test "sign: the NOERROR response and the signed BADTIME response match the Python oracle" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [256]u8 = undefined;
    const pkt = vector.packet(&buf);
    const m = try wire.Message.parse(arena.allocator(), pkt);
    const keys = [_]Key{vector.key};
    var out: [512]u8 = undefined;
    const response = "\x6c\xb3\xa8\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x06\x00\x01";
    @memcpy(out[0..response.len], response);

    const ok = (try verify(&keys, pkt, m, vector.time)).?;
    const len = sign(ok, &out, response.len, vector.time);
    try testing.expectEqual(response.len + ok.size(), len);
    try testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, out[10..12], .big));
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, vector.response_mac);
    try testing.expectEqualSlices(u8, &want, out[len - 38 .. len - 6]);
    // The signed response parses and verifies as a response would at the client: original ID last.
    const signed = try wire.Message.parse(arena.allocator(), out[0..len]);
    try testing.expectEqual(@as(?usize, response.len), signed.tsig_at);
    try testing.expectEqual(@as(u16, 0x6cb3), std.mem.readInt(u16, out[len - 6 ..][0..2], .big));

    var late = (try verify(&keys, pkt, m, vector.time + 1000)).?;
    try testing.expectEqual(Error.badtime, late.err);
    out[3] = 0x09; // NOTAUTH
    out[11] = 0; // ARCOUNT, bumped by the signature above
    const blen = sign(late, &out, response.len, vector.time + 1000);
    _ = try std.fmt.hexToBytes(&want, vector.badtime_mac);
    try testing.expectEqualSlices(u8, &want, out[blen - 44 .. blen - 12]);
    try testing.expectEqual(@as(u16, 18), std.mem.readInt(u16, out[blen - 10 ..][0..2], .big));
    try testing.expectEqual(@as(u48, vector.time + 1000), std.mem.readInt(u48, out[blen - 6 ..][0..6], .big));

    late.key = null;
    late.err = .badkey;
    out[11] = 0;
    const ulen = sign(late, &out, response.len, vector.time);
    try testing.expectEqual(response.len + late.size(), ulen);
    try testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[ulen - 8 ..][0..2], .big)); // MAC size
}
