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
    try guarded_store.restoreObjectToFile(allocator, object_id, target_path);
    errdefer std.Io.Dir.deleteFileAbsolute(runtime.io(), target_path) catch |err| {
        std.debug.panic("failed to roll back restored target file {s}: {}", .{ target_path, err });
    };
    try guarded_store.removeObject(allocator, object_id);
}

pub fn defaultLockAnchorPathAlloc(alloc: std.mem.Allocator, object_id: []const u8) ![]u8 {
    const base = try defaults.xdgBasePathAlloc(alloc, "XDG_RUNTIME_DIR", ".local/state");
    defer alloc.free(base);
    const filename = try std.fmt.allocPrint(alloc, "{s}.lock", .{object_id});
    defer alloc.free(filename);
    return std.fs.path.join(alloc, &.{ base, "file-snitch", "lock-anchors", filename });
}

pub fn pathKind(path: []const u8) !PathKind {
    const stat = std.Io.Dir.cwd().statFile(runtime.io(), path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return err,
    };

    return switch (stat.kind) {
        .file => .file,
        .directory => .directory,
        else => .other,
    };
}

pub fn pathExists(path: []const u8) !bool {
    return try pathKind(path) != .missing;
}

pub fn directoryExists(path: []const u8) !bool {
    return try pathKind(path) == .directory;
}

pub fn currentUserHomeAlloc(alloc: std.mem.Allocator) ![]u8 {
    const home = try runtime.getEnvVarOwned(alloc, "HOME");
    errdefer alloc.free(home);
    const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(runtime.io(), home, alloc);
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
