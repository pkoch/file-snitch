const std = @import("std");
const fuse_support = @import("build/fuse_support.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const os_tag = target.result.os.tag;
    const app_version = readAppVersion(b);
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "app_version", app_version);
    build_options.addOption([]const u8, "launchd_agent_template", readSmallFile(b, "packaging/launchd/dev.file-snitch.agent.plist.in"));
    build_options.addOption([]const u8, "launchd_run_template", readSmallFile(b, "packaging/launchd/dev.file-snitch.run.plist.in"));
    build_options.addOption([]const u8, "systemd_agent_template", readSmallFile(b, "packaging/systemd/file-snitch-agent.service.in"));
    build_options.addOption([]const u8, "systemd_run_template", readSmallFile(b, "packaging/systemd/file-snitch-run.service.in"));
    const yaml_dependency = b.dependency("yaml", .{
        .target = target,
        .optimize = optimize,
    });
    const yaml_module = yaml_dependency.module("yaml");

    // Build executable
    const executable_module = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    executable_module.addImport("yaml", yaml_module);
    executable_module.addOptions("build_options", build_options);
    configureFuseInterop(b, executable_module, os_tag);

    const exe = b.addExecutable(.{
        .name = "file-snitch",
        .root_module = executable_module,
    });
    configureLinkerPolicy(exe, os_tag);
    fuse_support.addCompileCommandsStep(b, os_tag);
    b.installArtifact(exe);

    // Test step
    const test_step = b.step("test", "Run core integration and unit tests");

    // Integration test (special: needs app_src module with fuse support)
    {
        const app_src_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        app_src_module.addImport("yaml", yaml_module);
        app_src_module.addOptions("build_options", build_options);
        app_src_module.addIncludePath(b.path("c"));
        fuse_support.configureModule(b, app_src_module, os_tag);

        const test_module = b.createModule(.{
            .root_source_file = b.path("tests/core_integration.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        test_module.addImport("app_src", app_src_module);
        configureFuseInterop(b, test_module, os_tag);

        const tests = b.addTest(.{ .root_module = test_module });
        configureLinkerPolicy(tests, os_tag);
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    // Unit tests
    const unit_tests = [_]struct {
        source: []const u8,
        needs_yaml: bool,
        link_libc: bool,
    }{
        .{ .source = "src/prompt.zig", .needs_yaml = false, .link_libc = true },
        .{ .source = "src/store.zig", .needs_yaml = false, .link_libc = true },
        .{ .source = "src/config.zig", .needs_yaml = true, .link_libc = true },
        .{ .source = "src/enrollment.zig", .needs_yaml = false, .link_libc = true },
        .{ .source = "src/agent.zig", .needs_yaml = true, .link_libc = true },
        .{ .source = "src/cli_completion.zig", .needs_yaml = false, .link_libc = false },
        .{ .source = "src/cli_policy_watch.zig", .needs_yaml = false, .link_libc = true },
        .{ .source = "src/cli_supervisor.zig", .needs_yaml = true, .link_libc = true },
        .{ .source = "src/filesystem.zig", .needs_yaml = true, .link_libc = true },
        .{ .source = "src/user_services.zig", .needs_yaml = false, .link_libc = true },
        .{ .source = "src/rfc3339.zig", .needs_yaml = false, .link_libc = false },
    };

    for (unit_tests) |test_info| {
        const test_module = b.createModule(.{
            .root_source_file = b.path(test_info.source),
            .target = target,
            .optimize = optimize,
            .link_libc = test_info.link_libc,
        });
        if (test_info.needs_yaml) {
            test_module.addImport("yaml", yaml_module);
        }
        test_module.addOptions("build_options", build_options);

        const tests = b.addTest(.{ .root_module = test_module });
        configureLinkerPolicy(tests, os_tag);
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }
}

fn readAppVersion(b: *std.Build) []const u8 {
    const raw = readSmallFile(b, "VERSION");
    return std.mem.trim(u8, raw, " \t\r\n");
}

fn readSmallFile(b: *std.Build, path: []const u8) []const u8 {
    return std.Io.Dir.cwd().readFileAlloc(b.graph.io, path, b.allocator, .limited(64 * 1024)) catch |err| {
        std.debug.panic("failed to read {s}: {}", .{ path, err });
    };
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
