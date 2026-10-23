//! The log lines of ADR 0011: one JSON object per line on stderr in nisshi's log schema v1
//! (`v`, `ts`, `level`, `event`, then the event's fields). Every string goes through
//! `std.json.Stringify`, so a name off the wire cannot break the line.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const wire = @import("wire.zig");
const zone = @import("zone.zig");

pub const Level = enum { debug, info, warn, @"error" };

/// Writes one line. `fields` is a struct literal: optional fields are left out when null,
/// values with a `format` method (`zone.fmt`, addresses) are printed with `{f}` then escaped.
pub fn event(level: Level, name: []const u8, fields: anytype) void {
    if (builtin.is_test) return; // tests trigger thousands of events (the 1024-record cap)
    var ts: posix.timespec = undefined;
    _ = posix.system.clock_gettime(posix.CLOCK.REALTIME, &ts);
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    writeLine(&w, @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec, level, name, fields) catch return; // shortcut: a line over 2 KiB is dropped; names are at most 255 bytes
    std.debug.print("{s}", .{w.buffered()});
}

/// `name` is annai's own kebab-case event name, never client data.
pub fn writeLine(w: *std.Io.Writer, now_ns: i128, level: Level, name: []const u8, fields: anytype) !void {
    try w.writeAll("{\"v\":1,\"ts\":\"");
    try writeTs(w, now_ns);
    try w.print("\",\"level\":\"{s}\",\"event\":\"{s}\"", .{ @tagName(level), name });
    inline for (std.meta.fields(@TypeOf(fields))) |f| try field(w, f.name, @field(fields, f.name));
    try w.writeAll("}\n");
}

fn field(w: *std.Io.Writer, comptime name: []const u8, v: anytype) !void {
    const T = @TypeOf(v);
    if (@typeInfo(T) == .optional) return if (v) |x| field(w, name, x);
    try w.writeAll(",\"" ++ name ++ "\":");
    if (comptime std.meta.hasMethod(T, "format")) {
        var b: [1024]u8 = undefined;
        var fw: std.Io.Writer = .fixed(&b);
        try fw.print("{f}", .{v});
        return std.json.Stringify.value(fw.buffered(), .{}, w);
    }
    if (comptime isString(T)) return std.json.Stringify.value(@as([]const u8, v), .{}, w);
    try std.json.Stringify.value(v, .{}, w);
}

fn isString(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .pointer => |p| p.child == u8 or (@typeInfo(p.child) == .array and @typeInfo(p.child).array.child == u8),
        else => false,
    };
}

/// UTC, RFC 3339, exactly nine fractional digits (nisshi's `ts`).
pub fn writeTs(w: *std.Io.Writer, ns: i128) !void {
    const secs: u64 = @intCast(@divFloor(ns, std.time.ns_per_s));
    const frac: u64 = @intCast(@mod(ns, std.time.ns_per_s));
    const es = std.time.epoch.EpochSeconds{ .secs = secs };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    try w.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>9}Z", .{
        yd.year,               md.month.numeric(),       md.day_index + 1,
        ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        frac,
    });
}

/// The first question of a packet, read without decompression (nothing precedes it to point
/// to); null when it is not there or not well formed. `name` is lowercased into `buf`.
pub fn question(packet: []const u8, buf: *[255]u8) ?struct { name: []const u8, type: wire.Type } {
    if (packet.len < 12 or std.mem.readInt(u16, packet[4..6], .big) == 0) return null;
    var i: usize = 12;
    while (true) {
        if (i >= packet.len or packet[i] > 63 or i - 12 + 1 + packet[i] > 255) return null;
        if (packet[i] == 0) break;
        i += 1 + @as(usize, packet[i]);
    }
    if (i + 3 > packet.len) return null;
    const name = buf[0 .. i + 1 - 12];
    @memcpy(name, packet[12 .. i + 1]);
    return .{ .name = zone.lower(name), .type = @enumFromInt(std.mem.readInt(u16, packet[i + 1 ..][0..2], .big)) };
}

/// `A`, `AAAA`… for the types annai knows, else `TYPE<n>` (RFC 3597).
pub fn typeName(t: wire.Type) TypeName {
    return .{ .t = t };
}

pub const TypeName = struct {
    t: wire.Type,
    pub fn format(n: TypeName, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (std.enums.tagName(wire.Type, n.t)) |s| {
            for (s) |c| try w.writeByte(std.ascii.toUpper(c));
        } else try w.print("TYPE{d}", .{@intFromEnum(n.t)});
    }
};

/// `NOERROR`, `NXDOMAIN`…, `BADVERS` for the extended 16, else `RCODE<n>`.
pub fn rcodeName(rc: u12) RcodeName {
    return .{ .rc = rc };
}

pub const RcodeName = struct {
    rc: u12,
    pub fn format(n: RcodeName, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (n.rc == 16) return w.writeAll("BADVERS");
        if (n.rc < 16) if (std.enums.tagName(wire.Rcode, @enumFromInt(@as(u4, @intCast(n.rc))))) |s| {
            for (s) |c| try w.writeByte(std.ascii.toUpper(c));
            return;
        };
        try w.print("RCODE{d}", .{n.rc});
    }
};

const testing = std.testing;

test "ts: UTC, nine fractional digits, zero padded" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeTs(&w, 1792398843 * std.time.ns_per_s + 512004117);
    try testing.expectEqualStrings("2026-10-19T08:34:03.512004117Z", w.buffered());
    w = .fixed(&buf);
    try writeTs(&w, 0);
    try testing.expectEqualStrings("1970-01-01T00:00:00.000000000Z", w.buffered());
    w = .fixed(&buf);
    try writeTs(&w, 951782400 * std.time.ns_per_s + 7); // 2000-02-29, a leap day
    try testing.expectEqualStrings("2000-02-29T00:00:00.000000007Z", w.buffered());
}

test "a query line: schema order, escaped client strings, optional fields left out" {
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const qname: ?[]const u8 = "a\"b\\c\n.example.org.";
    try writeLine(&w, 1792398843 * std.time.ns_per_s + 512004117, .info, "query", .{
        .proto = "udp",
        .client = "203.0.113.9",
        .qname = qname,
        .qtype = typeName(.soa),
        .rcode = rcodeName(0),
        .aa = true,
        .cache = "none",
        .size = @as(usize, 112),
        .dur_us = @as(u64, 38),
    });
    try testing.expectEqualStrings(
        \\{"v":1,"ts":"2026-10-19T08:34:03.512004117Z","level":"info","event":"query","proto":"udp","client":"203.0.113.9","qname":"a\"b\\c\n.example.org.","qtype":"SOA","rcode":"NOERROR","aa":true,"cache":"none","size":112,"dur_us":38}
        ++ "\n", w.buffered());
    w = .fixed(&buf);
    try writeLine(&w, 0, .warn, "upstream-error", .{ .upstream = "192.0.2.1:53", .qname = @as(?[]const u8, null), .qtype = typeName(@enumFromInt(65280)), .rcode = rcodeName(16), .other = rcodeName(12), .err = "CONNREFUSED" });
    try testing.expectEqualStrings(
        \\{"v":1,"ts":"1970-01-01T00:00:00.000000000Z","level":"warn","event":"upstream-error","upstream":"192.0.2.1:53","qtype":"TYPE65280","rcode":"BADVERS","other":"RCODE12","err":"CONNREFUSED"}
        ++ "\n", w.buffered());
}

test "type names: registered mnemonics, else TYPE<n> (RFC 3597)" {
    var buf: [32]u8 = undefined;
    for ([_]struct { u16, []const u8 }{
        .{ 1, "A" },             .{ 64, "SVCB" },  .{ 65, "HTTPS" },  .{ 43, "DS" },   .{ 51, "NSEC3PARAM" },
        .{ 252, "AXFR" },        .{ 251, "IXFR" }, .{ 255, "ANY" },   .{ 256, "URI" }, .{ 257, "CAA" },
        .{ 65280, "TYPE65280" }, .{ 0, "TYPE0" },  .{ 99, "TYPE99" },
    }) |c| try testing.expectEqualStrings(c[1], try std.fmt.bufPrint(&buf, "{f}", .{typeName(@enumFromInt(c[0]))}));
}

test "question: lowercase, bounded, null when malformed" {
    var buf: [255]u8 = undefined;
    const q = question("\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03WwW\x07example\x00\x00\x1c\x00\x01", &buf).?;
    try testing.expectEqualSlices(u8, "\x03www\x07example\x00", q.name);
    try testing.expectEqual(wire.Type.aaaa, q.type);
    try testing.expect(question("\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01", &buf) == null); // pointer
    try testing.expect(question("\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www", &buf) == null); // cut
    try testing.expect(question("\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", &buf) == null); // no question
}
