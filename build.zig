const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const des = b.addModule("des", .{
        .root_source_file = b.path("src/des.zig"),
    });

    const zig_args_pkg = b.dependency("zig-args", .{
        .target = target,
        .optimize = optimize,
    });

    const zig_args = zig_args_pkg.module("args");

    const exe = b.addExecutable(.{
        .name = "des",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe.root_module.addImport("des", des);
    exe.root_module.addImport("args", zig_args);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/des.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests_run = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&tests_run.step);
}
