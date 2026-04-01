const std = @import("std");
const fuse_support = @import("build/fuse_support.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const executable_module = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    configureFuseInterop(b, executable_module, target.result.os.tag);

    const exe = b.addExecutable(.{
        .name = "file-snitch",
        .root_module = executable_module,
    });
    fuse_support.addCompileCommandsStep(b, target.result.os.tag);
    b.installArtifact(exe);

    const test_module = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_module.addImport("app_src", b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    }));
    configureFuseInterop(b, test_module, target.result.os.tag);

    const tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_integration_tests = b.addRunArtifact(tests);

    const prompt_test_module = b.createModule(.{
        .root_source_file = b.path("src/prompt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const prompt_tests = b.addTest(.{
        .root_module = prompt_test_module,
    });
    const run_prompt_tests = b.addRunArtifact(prompt_tests);

    const test_step = b.step("test", "Run integration tests");
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_prompt_tests.step);
}

fn configureFuseInterop(
    b: *std.Build,
    module: *std.Build.Module,
    os_tag: std.Target.Os.Tag,
) void {
    module.addIncludePath(b.path("c"));
    module.addCSourceFile(.{
        .file = b.path("c/libfuse_shim.c"),
        .flags = &.{ "-std=c11", "-D_FILE_OFFSET_BITS=64" },
    });
    fuse_support.configureModule(b, module, os_tag);
}
