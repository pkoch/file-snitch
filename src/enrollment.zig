const std = @import("std");
const defaults = @import("defaults.zig");
const runtime = @import("runtime.zig");
const store = @import("store.zig");
const c = @cImport({
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
});

const guarded_source_file_read_limit_bytes = store.pass_payload_limit_bytes;

pub const PathKind = enum {
    missing,
    file,
    directory,
    other,
};

pub fn allocateObjectId(allocator: std.mem.Allocator, guarded_store: *store.Backend) ![]u8 {
    var bytes: [16]u8 = undefined;
    var object_id_buffer: [32]u8 = undefined;

    while (true) {
        runtime.io().random(&bytes);
        object_id_buffer = std.fmt.bytesToHex(bytes, .lower);
        const object_id = try allocator.dupe(u8, &object_id_buffer);
        errdefer allocator.free(object_id);

        if (!try guarded_store.exists(allocator, object_id)) {
            return object_id;
        }
    }
}

pub fn moveFileIntoGuardedStore(
    allocator: std.mem.Allocator,
    guarded_store: *store.Backend,
    source_path: []const u8,
    object_id: []const u8,
) !void {
    var object = try readStoredObjectFromFile(allocator, source_path);
    defer object.deinit(allocator);

    try guarded_store.putObject(allocator, object_id, .{
        .metadata = object.metadata,
        .content = object.content,
    });
    errdefer guarded_store.removeObject(allocator, object_id) catch |err| {
        std.debug.panic("failed to roll back guarded object {s} after failed enrollment move: {}", .{ object_id, err });
    };
    try std.Io.Dir.deleteFileAbsolute(runtime.io(), source_path);
}

pub fn moveGuardedFileBack(
    allocator: std.mem.Allocator,
    guarded_store: *store.Backend,
    object_id: []const u8,
    target_path: []const u8,
) !void {
    try removeSymlinkIfPresent(allocator, target_path, null);
    try guarded_store.restoreObjectToFile(allocator, object_id, target_path);
    errdefer std.Io.Dir.deleteFileAbsolute(runtime.io(), target_path) catch |err| {
        std.debug.panic("failed to roll back restored target file {s}: {}", .{ target_path, err });
    };
    try guarded_store.removeObject(allocator, object_id);
}

pub fn ensureProjectionSymlink(
    allocator: std.mem.Allocator,
    target_path: []const u8,
    projection_path: []const u8,
) !void {
    switch (try symlinkState(allocator, target_path)) {
        .missing => try createSymlink(allocator, projection_path, target_path),
        .symlink => {
            const current_target = try readSymlinkAlloc(allocator, target_path);
            defer allocator.free(current_target);
            if (std.mem.eql(u8, current_target, projection_path)) {
                return;
            }
            return error.PathAlreadyExists;
        },
        .other => return error.PathAlreadyExists,
    }
}

pub fn defaultLockAnchorPathAlloc(alloc: std.mem.Allocator, object_id: []const u8) ![]u8 {
    const base = try defaults.xdgBasePathAlloc(alloc, "XDG_RUNTIME_DIR", ".local/state");
    defer alloc.free(base);
    const filename = try std.fmt.allocPrint(alloc, "{s}.lock", .{object_id});
    defer alloc.free(filename);
    return std.fs.path.join(alloc, &.{ base, "file-snitch", "lock-anchors", filename });
}

pub fn pathKind(path: []const u8) !PathKind {
    const path_z = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_z);

    var stat: c.struct_stat = undefined;
    if (c.stat(path_z.ptr, &stat) != 0) return pathKindError(std.posix.errno(-1));

    const mode: u32 = @intCast(stat.st_mode);
    if (std.c.S.ISREG(mode)) return .file;
    if (std.c.S.ISDIR(mode)) return .directory;
    return .other;
}

pub fn pathExists(path: []const u8) !bool {
    return try pathKind(path) != .missing;
}

pub fn directoryExists(path: []const u8) !bool {
    return try pathKind(path) == .directory;
}

fn pathKindError(err: std.posix.E) !PathKind {
    return switch (err) {
        .NOENT => .missing,
        .ACCES, .PERM => return error.AccessDenied,
        .NAMETOOLONG => return error.NameTooLong,
        .NOTDIR => return error.NotDir,
        .INTR => return error.Interrupted,
        .IO => return error.InputOutput,
        .NXIO => return error.NoDevice,
        .NOMEM => return error.OutOfMemory,
        else => return error.Unexpected,
    };
}

const SymlinkState = enum {
    missing,
    symlink,
    other,
};

fn symlinkState(allocator: std.mem.Allocator, path: []const u8) !SymlinkState {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    var stat: c.struct_stat = undefined;
    if (c.lstat(path_z.ptr, &stat) != 0) {
        return switch (std.posix.errno(-1)) {
            .NOENT => .missing,
            .ACCES, .PERM => error.AccessDenied,
            .NAMETOOLONG => error.NameTooLong,
            .NOTDIR => error.NotDir,
            .INTR => error.Interrupted,
            .IO => error.InputOutput,
            .NXIO => error.NoDevice,
            .NOMEM => error.OutOfMemory,
            else => error.Unexpected,
        };
    }

    const mode: u32 = @intCast(stat.st_mode);
    return if ((mode & c.S_IFMT) == c.S_IFLNK) .symlink else .other;
}

fn createSymlink(
    allocator: std.mem.Allocator,
    target_path: []const u8,
    link_path: []const u8,
) !void {
    const target_z = try allocator.dupeZ(u8, target_path);
    defer allocator.free(target_z);
    const link_z = try allocator.dupeZ(u8, link_path);
    defer allocator.free(link_z);

    if (c.symlink(target_z.ptr, link_z.ptr) != 0) {
        return switch (std.posix.errno(-1)) {
            .EXIST => error.PathAlreadyExists,
            .ACCES, .PERM => error.AccessDenied,
            .NAMETOOLONG => error.NameTooLong,
            .NOTDIR => error.NotDir,
            .INTR => error.Interrupted,
            .IO => error.InputOutput,
            .NOMEM => error.OutOfMemory,
            else => error.Unexpected,
        };
    }
}

fn readSymlinkAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);

    var buffer: [std.posix.PATH_MAX]u8 = undefined;
    const target_len = c.readlink(path_z.ptr, &buffer, buffer.len);
    if (target_len < 0) {
        return switch (std.posix.errno(-1)) {
            .NOENT => error.FileNotFound,
            .INVAL => error.NotLink,
            .ACCES, .PERM => error.AccessDenied,
            .NAMETOOLONG => error.NameTooLong,
            .NOTDIR => error.NotDir,
            .INTR => error.Interrupted,
            .IO => error.InputOutput,
            .NOMEM => error.OutOfMemory,
            else => error.Unexpected,
        };
    }
    return allocator.dupe(u8, buffer[0..@intCast(target_len)]);
}

fn removeSymlinkIfPresent(
    allocator: std.mem.Allocator,
    target_path: []const u8,
    expected_target: ?[]const u8,
) !void {
    switch (try symlinkState(allocator, target_path)) {
        .missing, .other => return,
        .symlink => {},
    }

    if (expected_target) |expected| {
        const current_target = try readSymlinkAlloc(allocator, target_path);
        defer allocator.free(current_target);
        if (!std.mem.eql(u8, current_target, expected)) {
            return;
        }
    }

    const target_z = try allocator.dupeZ(u8, target_path);
    defer allocator.free(target_z);
    if (c.unlink(target_z.ptr) != 0) {
        return switch (std.posix.errno(-1)) {
            .NOENT => {},
            .ACCES, .PERM => error.AccessDenied,
            .NAMETOOLONG => error.NameTooLong,
            .NOTDIR => error.NotDir,
            .INTR => error.Interrupted,
            .IO => error.InputOutput,
            .NOMEM => error.OutOfMemory,
            else => error.Unexpected,
        };
    }
}

pub fn currentUserHomeAlloc(alloc: std.mem.Allocator) ![]u8 {
    const home = try runtime.getEnvVarOwned(alloc, "HOME");
    errdefer alloc.free(home);
    var canonical_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const canonical_len = try std.Io.Dir.realPathFileAbsolute(runtime.io(), home, &canonical_buffer);
    const canonical = try alloc.dupe(u8, canonical_buffer[0..canonical_len]);
    alloc.free(home);
    return canonical;
}

pub fn pathIsWithinDirectory(path: []const u8, directory: []const u8) bool {
    if (!std.mem.startsWith(u8, path, directory)) return false;
    if (path.len == directory.len) return true;
    if (directory.len == 1 and directory[0] == std.fs.path.sep) return true;
    return path[directory.len] == std.fs.path.sep;
}

pub fn pathOwnedByCurrentUser(path: []const u8) !bool {
    var file = try std.Io.Dir.openFileAbsolute(runtime.io(), path, .{ .mode = .read_only });
    defer file.close(runtime.io());
    const stat = try fstatFile(file);
    return stat.st_uid == c.getuid();
}

fn fstatFile(file: std.Io.File) !c.struct_stat {
    var stat: c.struct_stat = undefined;
    if (c.fstat(file.handle, &stat) != 0) return error.InputOutput;
    return stat;
}

fn readStoredObjectFromFile(allocator: std.mem.Allocator, path: []const u8) !store.Object {
    var file = try std.Io.Dir.openFileAbsolute(runtime.io(), path, .{ .mode = .read_only });
    defer file.close(runtime.io());

    const stat = try file.stat(runtime.io());
    const posix_stat = try fstatFile(file);
    var reader_buffer: [4096]u8 = undefined;
    var file_reader = file.reader(runtime.io(), &reader_buffer);
    const content = file_reader.interface.allocRemaining(allocator, .limited(guarded_source_file_read_limit_bytes)) catch |err| switch (err) {
        error.StreamTooLong => return error.GuardedSourceFileTooLarge,
        else => return err,
    };

    return .{
        .metadata = .{
            .mode = @intCast(stat.permissions.toMode() & 0o777),
            .uid = @intCast(posix_stat.st_uid),
            .gid = @intCast(posix_stat.st_gid),
            .atime_nsec = if (stat.atime) |atime| atime.toNanoseconds() else 0,
            .mtime_nsec = stat.mtime.toNanoseconds(),
        },
        .content = content,
    };
}

test "path is within directory respects segment boundaries" {
    try std.testing.expect(pathIsWithinDirectory("/Users/pkoch/.kube/config", "/Users/pkoch"));
    try std.testing.expect(pathIsWithinDirectory("/Users/pkoch", "/Users/pkoch"));
    try std.testing.expect(!pathIsWithinDirectory("/Users/pkoch2/.kube/config", "/Users/pkoch"));
    try std.testing.expect(!pathIsWithinDirectory("/Users/pkochish", "/Users/pkoch"));
}
