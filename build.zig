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
        .linux => exe.root_module.linkSystemLibrary("fuse3", .{}),
        .macos => {
            exe.root_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/include" });
            exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
            exe.root_module.addRPath(.{ .cwd_relative = "/usr/local/lib" });
            exe.root_module.linkSystemLibrary("fuse", .{});
        },
        else => {},
    }

    b.installArtifact(exe);
}
