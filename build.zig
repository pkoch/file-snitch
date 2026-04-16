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
    configureLinkerPolicy(exe, target.result.os.tag);
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
    app_src_module.addIncludePath(b.path("c"));
    test_module.addImport("app_src", app_src_module);
    configureFuseInterop(b, test_module, target.result.os.tag);

    const tests = b.addTest(.{
        .root_module = test_module,
    });
    configureLinkerPolicy(tests, target.result.os.tag);
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
    configureLinkerPolicy(prompt_tests, target.result.os.tag);
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
    configureLinkerPolicy(store_tests, target.result.os.tag);
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
    configureLinkerPolicy(config_tests, target.result.os.tag);
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
    configureLinkerPolicy(enrollment_tests, target.result.os.tag);
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
    configureLinkerPolicy(agent_tests, target.result.os.tag);
    const run_agent_tests = b.addRunArtifact(agent_tests);

    const completion_test_module = b.createModule(.{
        .root_source_file = b.path("src/cli_completion.zig"),
        .target = target,
        .optimize = optimize,
    });
    const completion_tests = b.addTest(.{
        .root_module = completion_test_module,
    });
    configureLinkerPolicy(completion_tests, target.result.os.tag);
    const run_completion_tests = b.addRunArtifact(completion_tests);

    const policy_watch_test_module = b.createModule(.{
        .root_source_file = b.path("src/cli_policy_watch.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const policy_watch_tests = b.addTest(.{
        .root_module = policy_watch_test_module,
    });
    configureLinkerPolicy(policy_watch_tests, target.result.os.tag);
    const run_policy_watch_tests = b.addRunArtifact(policy_watch_tests);

    const supervisor_test_module = b.createModule(.{
        .root_source_file = b.path("src/cli_supervisor.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    supervisor_test_module.addImport("yaml", yaml_module);
    supervisor_test_module.addOptions("build_options", build_options);
    const supervisor_tests = b.addTest(.{
        .root_module = supervisor_test_module,
    });
    configureLinkerPolicy(supervisor_tests, target.result.os.tag);
    const run_supervisor_tests = b.addRunArtifact(supervisor_tests);

    const filesystem_util_test_module = b.createModule(.{
        .root_source_file = b.path("src/filesystem_util.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const filesystem_util_tests = b.addTest(.{
        .root_module = filesystem_util_test_module,
    });
    configureLinkerPolicy(filesystem_util_tests, target.result.os.tag);
    const run_filesystem_util_tests = b.addRunArtifact(filesystem_util_tests);

    const test_step = b.step("test", "Run core integration and unit tests");
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_prompt_tests.step);
    test_step.dependOn(&run_store_tests.step);
    test_step.dependOn(&run_config_tests.step);
    test_step.dependOn(&run_enrollment_tests.step);
    test_step.dependOn(&run_agent_tests.step);
    test_step.dependOn(&run_completion_tests.step);
    test_step.dependOn(&run_policy_watch_tests.step);
    test_step.dependOn(&run_supervisor_tests.step);
    test_step.dependOn(&run_filesystem_util_tests.step);
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

fn configureLinkerPolicy(compile: *std.Build.Step.Compile, os_tag: std.Target.Os.Tag) void {
    if (os_tag == .linux) {
        compile.linker_allow_shlib_undefined = true;
    } else if (os_tag == .macos) {
        compile.headerpad_max_install_names = true;
    }
}
