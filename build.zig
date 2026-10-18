const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const imports: []const std.Build.Module.Import = &.{.{ .name = "microwave", .module = b.dependency("microwave", .{}).module("microwave") }};
    const root = b.createModule(.{ .root_source_file = b.path("src/main.zig"), .target = target, .optimize = optimize, .imports = imports });

    b.installArtifact(b.addExecutable(.{ .name = "annai", .root_module = root }));

    const tests = b.addTest(.{ .root_module = root });
    b.step("test", "Run the unit tests").dependOn(&b.addRunArtifact(tests).step);

    // Not installed: the fuzzer is a developer tool (ADR 0011), run with `zig build fuzz -- <target> <seconds> [seed]`.
    const fuzz = b.createModule(.{ .root_source_file = b.path("src/fuzz.zig"), .target = target, .optimize = optimize, .imports = imports });
    const run_fuzz = b.addRunArtifact(b.addExecutable(.{ .name = "annai-fuzz", .root_module = fuzz }));
    if (b.args) |args| run_fuzz.addArgs(args);
    b.step("fuzz", "Fuzz a target: zig build fuzz -- <codec|respond|update> <seconds> [seed]").dependOn(&run_fuzz.step);
}
