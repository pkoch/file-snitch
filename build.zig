const std = @import("std");
const fuse_support = @import("build/fuse_support.zig");

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

    fuse_support.configureModule(b, exe.root_module, target.result.os.tag);
    fuse_support.addCompileCommandsStep(b, target.result.os.tag);

    b.installArtifact(exe);
}
