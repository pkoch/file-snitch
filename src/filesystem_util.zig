//! Free helpers extracted from `src/filesystem.zig`. None of them touch
//! Model/StoredFile state, so they can be unit-tested in isolation. A few
//! (currentTimestamp, currentUid, currentGid, ensureParentDirectoryAbsolute)
//! still read process/clock state — keep that in mind when adding tests.

const std = @import("std");
const policy = @import("policy.zig");
const types = @import("filesystem_types.zig");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
});

const Timestamp = types.Timestamp;
const Lookup = types.Lookup;

pub const first_dynamic_inode: u64 = 4;

pub fn writeIntoArrayList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(u8),
    offset: usize,
    bytes: []const u8,
) !void {
    const end = offset + bytes.len;
    try list.ensureTotalCapacityPrecise(allocator, end);
    if (list.items.len < end) {
        const old_len = list.items.len;
        list.items.len = end;
        @memset(list.items[old_len..end], 0);
    }
    @memcpy(list.items[offset..end], bytes);
}

pub fn resizeArrayList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(u8),
    size: usize,
) !void {
    try list.ensureTotalCapacityPrecise(allocator, size);
    if (list.items.len < size) {
        const old_len = list.items.len;
        list.items.len = size;
        @memset(list.items[old_len..size], 0);
        return;
    }

    list.items.len = size;
}

pub fn copySlice(source: []const u8, buffer: []u8, offset: usize) i32 {
    if (offset >= source.len) {
        return 0;
    }

    const length = @min(source.len - offset, buffer.len);
    @memcpy(buffer[0..length], source[offset .. offset + length]);
    return @intCast(length);
}

pub fn currentTimestamp() Timestamp {
    const now = std.time.nanoTimestamp();
    return .{
        .sec = @intCast(@divTrunc(now, std.time.ns_per_s)),
        .nsec = @intCast(@mod(now, std.time.ns_per_s)),
    };
}

pub fn ensureParentDirectoryAbsolute(path: []const u8) !void {
    const parent_dir = std.fs.path.dirname(path) orelse return error.InvalidPath;
    try std.fs.cwd().makePath(parent_dir);
}

pub fn nanosFromTimestamp(timestamp: Timestamp) i128 {
    return @as(i128, timestamp.sec) * std.time.ns_per_s + timestamp.nsec;
}

pub fn timestampFromNanos(nanos: i128) Timestamp {
    return .{
        .sec = @intCast(@divTrunc(nanos, std.time.ns_per_s)),
        .nsec = @intCast(@mod(nanos, std.time.ns_per_s)),
    };
}

pub fn timestampFromStatNanos(nanos: i128) Timestamp {
    return timestampFromNanos(nanos);
}

pub fn timestampFromPosixStat(sec: i64, nsec: u64) Timestamp {
    return .{
        .sec = sec,
        .nsec = @intCast(nsec),
    };
}

pub fn missingLookup() Lookup {
    return .{
        .node = .{
            .kind = .missing,
            .mode = 0,
            .nlink = 0,
            .size = 0,
            .block_size = 0,
            .block_count = 0,
            .inode = 0,
            .uid = 0,
            .gid = 0,
            .atime = .{ .sec = 0, .nsec = 0 },
            .mtime = .{ .sec = 0, .nsec = 0 },
            .ctime = .{ .sec = 0, .nsec = 0 },
        },
        .open_kind = .missing,
        .guarded = false,
    };
}

pub fn relativeMountedPath(path: []const u8) ?[]const u8 {
    if (path.len < 2 or path[0] != '/') {
        return null;
    }
    return path[1..];
}

pub fn joinVirtualPath(allocator: std.mem.Allocator, directory_path: []const u8, child_name: []const u8) ![]u8 {
    if (isRootPath(directory_path)) {
        return std.fmt.allocPrint(allocator, "/{s}", .{child_name});
    }
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ directory_path, child_name });
}

pub fn directChildName(directory_path: []const u8, descendant_path: []const u8) ?[]const u8 {
    const relative = if (isRootPath(directory_path)) blk: {
        if (descendant_path.len < 2 or descendant_path[0] != '/') return null;
        break :blk descendant_path[1..];
    } else blk: {
        if (!std.mem.startsWith(u8, descendant_path, directory_path)) return null;
        if (descendant_path.len <= directory_path.len or descendant_path[directory_path.len] != '/') return null;
        break :blk descendant_path[directory_path.len + 1 ..];
    };

    if (relative.len == 0) return null;
    const separator = std.mem.indexOfScalar(u8, relative, '/') orelse relative.len;
    return relative[0..separator];
}

pub fn isDescendantPath(parent_path: []const u8, candidate_path: []const u8) bool {
    if (isRootPath(parent_path)) {
        return candidate_path.len > 1 and candidate_path[0] == '/';
    }
    return std.mem.startsWith(u8, candidate_path, parent_path) and
        candidate_path.len > parent_path.len and
        candidate_path[parent_path.len] == '/';
}

pub fn syntheticDirectoryInode(path: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(path);
    return first_dynamic_inode +% hasher.final();
}

pub fn blockCountForSize(size: u64) u64 {
    if (size == 0) {
        return 0;
    }
    return (size + 511) / 512;
}

pub fn currentUid() u32 {
    return @intCast(std.posix.getuid());
}

pub fn currentGid() u32 {
    return @intCast(c.getgid());
}

pub fn accessClassForOpenFlags(flags: i32) policy.AccessClass {
    return switch (flags & c.O_ACCMODE) {
        c.O_WRONLY, c.O_RDWR => .write,
        else => .read,
    };
}

pub fn authorizeReadFromOpenFlags(flags: i32) i32 {
    return switch (flags & c.O_ACCMODE) {
        c.O_WRONLY => errnoCode(.BADF),
        else => 0,
    };
}

pub fn authorizeWriteFromOpenFlags(flags: i32) i32 {
    return switch (flags & c.O_ACCMODE) {
        c.O_RDONLY => errnoCode(.BADF),
        else => 0,
    };
}

pub fn formatOpenPromptLabel(
    allocator: std.mem.Allocator,
    operation: []const u8,
    path: []const u8,
    flags: i32,
) ![]u8 {
    var mode: std.ArrayList(u8) = .{};
    defer mode.deinit(allocator);

    switch (flags & c.O_ACCMODE) {
        c.O_WRONLY => try mode.appendSlice(allocator, "O_WRONLY"),
        c.O_RDWR => try mode.appendSlice(allocator, "O_RDWR"),
        else => try mode.appendSlice(allocator, "O_RDONLY"),
    }

    const flag_bits = [_]struct {
        mask: i32,
        name: []const u8,
    }{
        .{ .mask = c.O_APPEND, .name = "O_APPEND" },
        .{ .mask = c.O_CREAT, .name = "O_CREAT" },
        .{ .mask = c.O_EXCL, .name = "O_EXCL" },
        .{ .mask = c.O_TRUNC, .name = "O_TRUNC" },
    };

    for (flag_bits) |flag_bit| {
        if ((flags & flag_bit.mask) != 0) {
            try mode.appendSlice(allocator, "|");
            try mode.appendSlice(allocator, flag_bit.name);
        }
    }

    return std.fmt.allocPrint(allocator, "{s} {s} {s}", .{ operation, mode.items, path });
}

pub fn accessClassLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read",
        .create => "create",
        .write => "write",
        .rename => "rename",
        .delete => "delete",
        .metadata => "metadata",
        .xattr => "xattr",
    };
}

pub fn isRootPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/");
}

pub fn isTransientSidecarName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "._");
}

pub fn isTransientVirtualPath(path: []const u8) bool {
    return path.len > 3 and path[0] == '/' and isTransientSidecarName(path[1..]);
}

pub fn shouldPersistPath(path: []const u8) bool {
    return !(path.len >= 3 and path[0] == '/' and path[1] == '.' and path[2] == '_');
}

pub fn errnoCode(err: std.posix.E) i32 {
    return -@as(i32, @intFromEnum(err));
}

pub fn mapFsError(err: anyerror) i32 {
    return switch (err) {
        error.AccessDenied => errnoCode(.ACCES),
        error.FileNotFound => errnoCode(.NOENT),
        error.ObjectNotFound => errnoCode(.NOENT),
        error.PathAlreadyExists => errnoCode(.EXIST),
        error.NameTooLong => errnoCode(.NAMETOOLONG),
        error.NotDir => errnoCode(.NOTDIR),
        error.IsDir => errnoCode(.ISDIR),
        error.InvalidPath => errnoCode(.OPNOTSUPP),
        error.InvalidStoredObject, error.StoreCommandFailed, error.StoreUnavailable => errnoCode(.IO),
        error.FileBusy, error.Locked => errnoCode(.BUSY),
        error.ReadOnlyFileSystem => errnoCode(.ROFS),
        error.NoSpaceLeft => errnoCode(.NOSPC),
        error.DiskQuota => errnoCode(.DQUOT),
        error.OutOfMemory, error.SystemResources => errnoCode(.NOMEM),
        else => errnoCode(.IO),
    };
}
