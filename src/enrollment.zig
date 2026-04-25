const std = @import("std");
const defaults = @import("defaults.zig");
const store = @import("store.zig");

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
        std.crypto.random.bytes(&bytes);
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
    errdefer guarded_store.removeObject(allocator, object_id) catch {};
    try std.fs.deleteFileAbsolute(source_path);
}

pub fn moveGuardedFileBack(
    allocator: std.mem.Allocator,
    guarded_store: *store.Backend,
    object_id: []const u8,
    target_path: []const u8,
) !void {
    try guarded_store.restoreObjectToFile(allocator, object_id, target_path);
    errdefer std.fs.deleteFileAbsolute(target_path) catch {};
    try guarded_store.removeObject(allocator, object_id);
}

pub fn defaultLockAnchorPathAlloc(alloc: std.mem.Allocator, object_id: []const u8) ![]u8 {
    const base = try defaults.xdgBasePathAlloc(alloc, "XDG_RUNTIME_DIR", ".local/state");
    defer alloc.free(base);
    const filename = try std.fmt.allocPrint(alloc, "{s}.lock", .{object_id});
    defer alloc.free(filename);
    return std.fs.path.join(alloc, &.{ base, "file-snitch", "lock-anchors", filename });
}

pub fn pathKind(path: []const u8) PathKind {
    const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .other,
    };

    return switch (stat.kind) {
        .file => .file,
        .directory => .directory,
        else => .other,
    };
}

pub fn pathExists(path: []const u8) bool {
    return pathKind(path) != .missing;
}

pub fn directoryExists(path: []const u8) bool {
    return pathKind(path) == .directory;
}

pub fn currentUserHomeAlloc(alloc: std.mem.Allocator) ![]u8 {
    const home = try std.process.getEnvVarOwned(alloc, "HOME");
    errdefer alloc.free(home);
    const canonical = try std.fs.realpathAlloc(alloc, home);
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
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    const stat = try std.posix.fstat(file.handle);
    return stat.uid == std.posix.getuid();
}

fn readStoredObjectFromFile(allocator: std.mem.Allocator, path: []const u8) !store.Object {
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();

    const stat = try file.stat();
    const posix_stat = try std.posix.fstat(file.handle);
    const content = file.readToEndAlloc(allocator, guarded_source_file_read_limit_bytes) catch |err| switch (err) {
        error.FileTooBig => return error.GuardedSourceFileTooLarge,
        else => return err,
    };

    return .{
        .metadata = .{
            .mode = @intCast(stat.mode & 0o777),
            .uid = @intCast(posix_stat.uid),
            .gid = @intCast(posix_stat.gid),
            .atime_nsec = stat.atime,
            .mtime_nsec = stat.mtime,
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
