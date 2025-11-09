const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const des = b.addModule("des", .{
        .root_source_file = b.path("src/des.zig"),
        .target = target,
    });

    const args_pkg = b.dependency("args", .{
        .target = target,
        .optimize = optimize,
    });

    const args = args_pkg.module("args");

    const exe = b.addExecutable(.{
        .name = "des",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
	        .{ .name = "des", .module = des},
            },
        }),
    });

    exe.root_module.addImport("des", des);
    exe.root_module.addImport("args", args);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |build_args| {
        run_cmd.addArgs(build_args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{
        .root_module = des,
    });

    const tests_run = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&tests_run.step);
}
