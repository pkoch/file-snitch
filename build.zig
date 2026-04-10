const std = @import("std");
const fuse_support = @import("build/fuse_support.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const app_version = readAppVersion(b);
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "app_version", app_version);
    const yaml_module = b.createModule(.{
        .root_source_file = b.path("vendor/zig-yaml/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const executable_module = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    executable_module.addImport("yaml", yaml_module);
    executable_module.addOptions("build_options", build_options);
    configureFuseInterop(b, executable_module, target.result.os.tag);

    const exe = b.addExecutable(.{
        .name = "file-snitch",
        .root_module = executable_module,
    });
    fuse_support.addCompileCommandsStep(b, target.result.os.tag);
    b.installArtifact(exe);

    const test_module = b.createModule(.{
        .root_source_file = b.path("tests/core_integration.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const app_src_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    app_src_module.addImport("yaml", yaml_module);
    app_src_module.addOptions("build_options", build_options);
    test_module.addImport("app_src", app_src_module);
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
    prompt_test_module.addOptions("build_options", build_options);
    const prompt_tests = b.addTest(.{
        .root_module = prompt_test_module,
    });
    const run_prompt_tests = b.addRunArtifact(prompt_tests);

    const store_test_module = b.createModule(.{
        .root_source_file = b.path("src/store.zig"),
        .target = target,
        .optimize = optimize,
    });
    store_test_module.addOptions("build_options", build_options);
    const store_tests = b.addTest(.{
        .root_module = store_test_module,
    });
    const run_store_tests = b.addRunArtifact(store_tests);

    const config_test_module = b.createModule(.{
        .root_source_file = b.path("src/config.zig"),
        .target = target,
        .optimize = optimize,
    });
    config_test_module.addImport("yaml", yaml_module);
    config_test_module.addOptions("build_options", build_options);
    const config_tests = b.addTest(.{
        .root_module = config_test_module,
    });
    const run_config_tests = b.addRunArtifact(config_tests);

    const enrollment_test_module = b.createModule(.{
        .root_source_file = b.path("src/enrollment.zig"),
        .target = target,
        .optimize = optimize,
    });
    enrollment_test_module.addOptions("build_options", build_options);
    const enrollment_tests = b.addTest(.{
        .root_module = enrollment_test_module,
    });
    const run_enrollment_tests = b.addRunArtifact(enrollment_tests);

    const agent_test_module = b.createModule(.{
        .root_source_file = b.path("src/agent.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    agent_test_module.addImport("yaml", yaml_module);
    agent_test_module.addOptions("build_options", build_options);
    const agent_tests = b.addTest(.{
        .root_module = agent_test_module,
    });
    const run_agent_tests = b.addRunArtifact(agent_tests);

    const test_step = b.step("test", "Run core integration and unit tests");
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_prompt_tests.step);
    test_step.dependOn(&run_store_tests.step);
    test_step.dependOn(&run_config_tests.step);
    test_step.dependOn(&run_enrollment_tests.step);
    test_step.dependOn(&run_agent_tests.step);
}

fn readAppVersion(b: *std.Build) []const u8 {
    const raw = std.fs.cwd().readFileAlloc(b.allocator, "VERSION", 64) catch |err| {
        std.debug.panic("failed to read VERSION: {}", .{err});
    };
    return std.mem.trim(u8, raw, " \t\r\n");
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
