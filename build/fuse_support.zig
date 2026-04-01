const std = @import("std");

pub fn configureModule(
    b: *std.Build,
    module: *std.Build.Module,
    os_tag: std.Target.Os.Tag,
) void {
    switch (os_tag) {
        .linux => configureLinuxFuse(b, module),
        .macos => configureMacFuse(b, module),
        else => {},
    }
}

pub fn addCompileCommandsStep(b: *std.Build, os_tag: std.Target.Os.Tag) void {
    const compile_commands = b.step("compile-commands", "Write compile_commands.json for clangd");
    const update_compile_commands = b.addUpdateSourceFiles();
    update_compile_commands.addBytesToSource(
        renderCompileCommands(b, os_tag),
        "compile_commands.json",
    );
    compile_commands.dependOn(&update_compile_commands.step);
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

fn findPkgConfig(b: *std.Build) ?[]const u8 {
    return b.findProgram(&.{"pkg-config"}, &.{ "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin" }) catch null;
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

fn renderCompileCommands(b: *std.Build, os_tag: std.Target.Os.Tag) []const u8 {
    const root_path = b.build_root.path orelse ".";
    const file_path = b.pathJoin(&.{ root_path, "c", "libfuse_shim.c" });

    var arguments: std.ArrayList([]const u8) = .empty;
    arguments.append(b.allocator, "clang") catch @panic("OOM");
    arguments.append(b.allocator, "-std=c11") catch @panic("OOM");
    arguments.append(b.allocator, "-D_FILE_OFFSET_BITS=64") catch @panic("OOM");
    arguments.append(b.allocator, "-I") catch @panic("OOM");
    arguments.append(b.allocator, "c") catch @panic("OOM");
    appendFuseCompileArgs(b, &arguments, os_tag);
    arguments.append(b.allocator, file_path) catch @panic("OOM");

    const Entry = struct {
        directory: []const u8,
        file: []const u8,
        arguments: []const []const u8,
    };

    var out: std.io.Writer.Allocating = .init(b.allocator);
    var write_stream: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .indent_2 },
    };
    write_stream.write([_]Entry{.{
        .directory = root_path,
        .file = file_path,
        .arguments = arguments.items,
    }}) catch @panic("OOM");
    out.writer.writeByte('\n') catch @panic("OOM");
    return out.written();
}

fn appendFuseCompileArgs(
    b: *std.Build,
    arguments: *std.ArrayList([]const u8),
    os_tag: std.Target.Os.Tag,
) void {
    switch (os_tag) {
        .linux => {
            if (appendPkgConfigCflags(b, arguments, "fuse3")) {
                return;
            }

            appendIncludeDirIfPresent(b, arguments, "/usr/include/fuse3");
        },
        .macos => {
            if (appendPkgConfigCflags(b, arguments, "fuse")) {
                return;
            }

            for ([_][]const u8{ "/usr/local/include", "/opt/homebrew/include" }) |include_dir| {
                appendIncludeDirIfPresent(b, arguments, include_dir);
            }
        },
        else => {},
    }
}

fn appendPkgConfigCflags(
    b: *std.Build,
    arguments: *std.ArrayList([]const u8),
    package_name: []const u8,
) bool {
    const pkg_config = findPkgConfig(b) orelse return false;
    var code: u8 = 0;
    const stdout = b.runAllowFail(
        &.{ pkg_config, "--cflags", package_name },
        &code,
        .Ignore,
    ) catch return false;
    if (code != 0) {
        return false;
    }

    var parts = std.mem.tokenizeAny(u8, stdout, " \n\r\t");
    while (parts.next()) |part| {
        arguments.append(b.allocator, part) catch @panic("OOM");
    }

    return true;
}

fn appendIncludeDirIfPresent(
    b: *std.Build,
    arguments: *std.ArrayList([]const u8),
    path: []const u8,
) void {
    if (!directoryExists(path)) {
        return;
    }

    arguments.append(b.allocator, "-isystem") catch @panic("OOM");
    arguments.append(b.allocator, path) catch @panic("OOM");
}
