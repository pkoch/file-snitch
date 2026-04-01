const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const root_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "file-snitch",
        .root_module = root_module,
    });

    exe.root_module.addIncludePath(b.path("c"));
    exe.root_module.addCSourceFile(.{
        .file = b.path("c/libfuse_shim.c"),
        .flags = &.{ "-std=c11", "-D_FILE_OFFSET_BITS=64" },
    });

    switch (target.result.os.tag) {
        .linux => configureLinuxFuse(b, exe.root_module),
        .macos => configureMacFuse(b, exe.root_module),
        else => {},
    }

    b.installArtifact(exe);
}

fn configureLinuxFuse(b: *std.Build, module: *std.Build.Module) void {
    if (hasPkgConfig(b)) {
        module.linkSystemLibrary("fuse3", .{ .use_pkg_config = .force });
        return;
    }

    addSystemIncludeIfPresent(module, "/usr/include/fuse3");
    module.linkSystemLibrary("fuse3", .{ .use_pkg_config = .no });
}

fn configureMacFuse(b: *std.Build, module: *std.Build.Module) void {
    if (hasPkgConfig(b)) {
        module.linkSystemLibrary("fuse", .{ .use_pkg_config = .force });
        return;
    }

    for ([_][]const u8{ "/usr/local/include", "/opt/homebrew/include" }) |include_dir| {
        addSystemIncludeIfPresent(module, include_dir);
    }

    for ([_][]const u8{ "/usr/local/lib", "/opt/homebrew/lib" }) |library_dir| {
        addLibraryPathIfPresent(module, library_dir);
    }

    module.linkSystemLibrary("fuse", .{ .use_pkg_config = .no });
}

fn hasPkgConfig(b: *std.Build) bool {
    _ = b.findProgram(&.{"pkg-config"}, &.{ "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin" }) catch {
        return false;
    };
    return true;
}

fn addSystemIncludeIfPresent(module: *std.Build.Module, path: []const u8) void {
    if (!directoryExists(path)) {
        return;
    }

    module.addSystemIncludePath(.{ .cwd_relative = path });
}

fn addLibraryPathIfPresent(module: *std.Build.Module, path: []const u8) void {
    if (!directoryExists(path)) {
        return;
    }

    module.addLibraryPath(.{ .cwd_relative = path });
    module.addRPath(.{ .cwd_relative = path });
}

fn directoryExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}
