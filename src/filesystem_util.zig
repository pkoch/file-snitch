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
    const full_blocks = size / 512;
    const has_remainder: u64 = if (size % 512 != 0) 1 else 0;
    return full_blocks + has_remainder;
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
        error.InvalidStoredObject,
        error.StoreCommandFailed,
        error.StoreUnavailable,
        error.StorePayloadTooLarge,
        error.StoreCommandOutputTooLarge,
        error.GuardedSourceFileTooLarge,
        => errnoCode(.IO),
        error.FileBusy, error.Locked => errnoCode(.BUSY),
        error.ReadOnlyFileSystem => errnoCode(.ROFS),
        error.NoSpaceLeft => errnoCode(.NOSPC),
        error.DiskQuota => errnoCode(.DQUOT),
        error.OutOfMemory, error.SystemResources => errnoCode(.NOMEM),
        else => errnoCode(.IO),
    };
}

const testing = std.testing;

test "relativeMountedPath strips the leading slash and rejects root or bare names" {
    try testing.expectEqualStrings("foo", relativeMountedPath("/foo").?);
    try testing.expectEqualStrings("foo/bar", relativeMountedPath("/foo/bar").?);
    try testing.expect(relativeMountedPath("/") == null);
    try testing.expect(relativeMountedPath("") == null);
    try testing.expect(relativeMountedPath("foo") == null);
}

test "joinVirtualPath handles root prefix and nested directories" {
    const a = try joinVirtualPath(testing.allocator, "/", "foo");
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("/foo", a);

    const b = try joinVirtualPath(testing.allocator, "/foo", "bar");
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("/foo/bar", b);
}

test "directChildName returns only the immediate child, even past deep descendants" {
    try testing.expectEqualStrings("foo", directChildName("/", "/foo").?);
    try testing.expectEqualStrings("foo", directChildName("/", "/foo/bar").?);
    try testing.expectEqualStrings("bar", directChildName("/foo", "/foo/bar").?);
    try testing.expectEqualStrings("bar", directChildName("/foo", "/foo/bar/baz").?);
    try testing.expect(directChildName("/foo", "/foo") == null);
    try testing.expect(directChildName("/foo", "/foobar/baz") == null);
    try testing.expect(directChildName("/foo", "/bar") == null);

    // Prefix-trap guard: /a must not see /ab as a child.
    try testing.expect(directChildName("/a", "/ab") == null);
}

test "directChildName pins current behavior for malformed paths" {
    // Trailing slash in descendant: current impl returns the empty pre-slash
    // segment as a bare name. Lock it down so accidental changes surface.
    try testing.expect(directChildName("/", "/") == null);
    try testing.expect(directChildName("/foo", "/foo/") == null);

    // Double slashes: the helper returns "" for the first empty segment.
    const double = directChildName("/", "//") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("", double);
}

test "isDescendantPath rejects prefix-match traps like /a vs /ab" {
    try testing.expect(isDescendantPath("/", "/foo"));
    try testing.expect(isDescendantPath("/foo", "/foo/bar"));
    try testing.expect(!isDescendantPath("/foo", "/foobar"));
    try testing.expect(!isDescendantPath("/foo", "/foo"));
    try testing.expect(!isDescendantPath("/foo", "/bar"));
    try testing.expect(!isDescendantPath("/", "/"));
}

test "accessClassForOpenFlags and authorizeRead/Write agree on mode gating" {
    try testing.expectEqual(policy.AccessClass.read, accessClassForOpenFlags(c.O_RDONLY));
    try testing.expectEqual(policy.AccessClass.write, accessClassForOpenFlags(c.O_WRONLY));
    try testing.expectEqual(policy.AccessClass.write, accessClassForOpenFlags(c.O_RDWR));

    try testing.expectEqual(@as(i32, 0), authorizeReadFromOpenFlags(c.O_RDONLY));
    try testing.expectEqual(errnoCode(.BADF), authorizeReadFromOpenFlags(c.O_WRONLY));
    try testing.expectEqual(@as(i32, 0), authorizeReadFromOpenFlags(c.O_RDWR));

    try testing.expectEqual(errnoCode(.BADF), authorizeWriteFromOpenFlags(c.O_RDONLY));
    try testing.expectEqual(@as(i32, 0), authorizeWriteFromOpenFlags(c.O_WRONLY));
    try testing.expectEqual(@as(i32, 0), authorizeWriteFromOpenFlags(c.O_RDWR));
}

test "formatOpenPromptLabel emits mode token then flags in declaration order" {
    const label = try formatOpenPromptLabel(testing.allocator, "open", "/foo", c.O_RDWR | c.O_CREAT | c.O_TRUNC);
    defer testing.allocator.free(label);
    try testing.expectEqualStrings("open O_RDWR|O_CREAT|O_TRUNC /foo", label);

    const bare = try formatOpenPromptLabel(testing.allocator, "create", "/bar", c.O_RDONLY);
    defer testing.allocator.free(bare);
    try testing.expectEqualStrings("create O_RDONLY /bar", bare);
}

test "mapFsError routes every enumerated branch and falls back to EIO" {
    try testing.expectEqual(errnoCode(.ACCES), mapFsError(error.AccessDenied));
    try testing.expectEqual(errnoCode(.NOENT), mapFsError(error.FileNotFound));
    try testing.expectEqual(errnoCode(.NOENT), mapFsError(error.ObjectNotFound));
    try testing.expectEqual(errnoCode(.EXIST), mapFsError(error.PathAlreadyExists));
    try testing.expectEqual(errnoCode(.NAMETOOLONG), mapFsError(error.NameTooLong));
    try testing.expectEqual(errnoCode(.NOTDIR), mapFsError(error.NotDir));
    try testing.expectEqual(errnoCode(.ISDIR), mapFsError(error.IsDir));
    try testing.expectEqual(errnoCode(.OPNOTSUPP), mapFsError(error.InvalidPath));
    try testing.expectEqual(errnoCode(.IO), mapFsError(error.InvalidStoredObject));
    try testing.expectEqual(errnoCode(.IO), mapFsError(error.StoreCommandFailed));
    try testing.expectEqual(errnoCode(.IO), mapFsError(error.StoreUnavailable));
    try testing.expectEqual(errnoCode(.BUSY), mapFsError(error.FileBusy));
    try testing.expectEqual(errnoCode(.BUSY), mapFsError(error.Locked));
    try testing.expectEqual(errnoCode(.ROFS), mapFsError(error.ReadOnlyFileSystem));
    try testing.expectEqual(errnoCode(.NOSPC), mapFsError(error.NoSpaceLeft));
    try testing.expectEqual(errnoCode(.DQUOT), mapFsError(error.DiskQuota));
    try testing.expectEqual(errnoCode(.NOMEM), mapFsError(error.OutOfMemory));
    try testing.expectEqual(errnoCode(.NOMEM), mapFsError(error.SystemResources));
    try testing.expectEqual(errnoCode(.IO), mapFsError(error.Unexpected));
}

test "writeIntoArrayList zero-fills the gap and overwrites at offset" {
    var list: std.ArrayListUnmanaged(u8) = .{};
    defer list.deinit(testing.allocator);

    try writeIntoArrayList(testing.allocator, &list, 0, "abc");
    try testing.expectEqualStrings("abc", list.items);

    try writeIntoArrayList(testing.allocator, &list, 6, "xy");
    try testing.expectEqual(@as(usize, 8), list.items.len);
    try testing.expectEqualStrings("abc", list.items[0..3]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, list.items[3..6]);
    try testing.expectEqualStrings("xy", list.items[6..8]);

    try writeIntoArrayList(testing.allocator, &list, 1, "BC");
    try testing.expectEqualStrings("aBC", list.items[0..3]);
}

test "writeIntoArrayList with zero-length bytes past end zero-fills up to offset" {
    // A zero-length write at an offset beyond the current length currently
    // grows the buffer to `offset` and zero-fills the new bytes. Lock this
    // in so callers can reason about write(fd, buf, 0) behavior.
    var list: std.ArrayListUnmanaged(u8) = .{};
    defer list.deinit(testing.allocator);

    try writeIntoArrayList(testing.allocator, &list, 0, "abc");
    try writeIntoArrayList(testing.allocator, &list, 5, "");
    try testing.expectEqual(@as(usize, 5), list.items.len);
    try testing.expectEqualStrings("abc", list.items[0..3]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, list.items[3..5]);

    // Zero-length write inside existing content must not change it.
    try writeIntoArrayList(testing.allocator, &list, 1, "");
    try testing.expectEqual(@as(usize, 5), list.items.len);
    try testing.expectEqualStrings("abc", list.items[0..3]);
}

test "resizeArrayList grows with zero fill and shrinks in place" {
    var list: std.ArrayListUnmanaged(u8) = .{};
    defer list.deinit(testing.allocator);

    try list.appendSlice(testing.allocator, "hello");
    try resizeArrayList(testing.allocator, &list, 8);
    try testing.expectEqual(@as(usize, 8), list.items.len);
    try testing.expectEqualStrings("hello", list.items[0..5]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0 }, list.items[5..8]);

    try resizeArrayList(testing.allocator, &list, 2);
    try testing.expectEqualStrings("he", list.items);
}

test "copySlice clamps to buffer length and honors offset bounds" {
    var buffer: [4]u8 = undefined;

    try testing.expectEqual(@as(i32, 4), copySlice("abcdef", &buffer, 0));
    try testing.expectEqualStrings("abcd", &buffer);

    try testing.expectEqual(@as(i32, 2), copySlice("abcdef", &buffer, 4));
    try testing.expectEqualStrings("ef", buffer[0..2]);

    try testing.expectEqual(@as(i32, 0), copySlice("abcdef", &buffer, 6));
    try testing.expectEqual(@as(i32, 0), copySlice("abcdef", &buffer, 99));
}

test "timestampFromNanos and nanosFromTimestamp round-trip non-negative ns" {
    const samples = [_]i128{ 0, 1, 999_999_999, 1_000_000_000, 12_345_678_901, 9_876_543_210_123 };
    for (samples) |ns| {
        const ts = timestampFromNanos(ns);
        try testing.expectEqual(ns, nanosFromTimestamp(ts));
    }

    const stat_sample = timestampFromStatNanos(1_750_000_000_123_456_789);
    try testing.expectEqual(@as(i64, 1_750_000_000), stat_sample.sec);
    try testing.expectEqual(@as(u32, 123_456_789), stat_sample.nsec);
}

test "timestampFromPosixStat copies fields as-is" {
    const ts = timestampFromPosixStat(42, 17);
    try testing.expectEqual(@as(i64, 42), ts.sec);
    try testing.expectEqual(@as(u32, 17), ts.nsec);
}

test "transient- and persistence-path predicates agree on AppleDouble sidecars" {
    try testing.expect(isTransientSidecarName("._something"));
    try testing.expect(!isTransientSidecarName(".hidden"));

    try testing.expect(isTransientVirtualPath("/._foo"));
    try testing.expect(!isTransientVirtualPath("/foo"));
    try testing.expect(!isTransientVirtualPath("/.foo"));

    try testing.expect(shouldPersistPath("/foo"));
    try testing.expect(shouldPersistPath("/foo/._bar"));
    try testing.expect(!shouldPersistPath("/._bar"));
}

test "missingLookup returns a zero-valued Lookup marked missing" {
    const lookup = missingLookup();
    try testing.expectEqual(types.NodeKind.missing, lookup.node.kind);
    try testing.expectEqual(types.OpenKind.missing, lookup.open_kind);
    try testing.expect(!lookup.guarded);
    try testing.expectEqual(@as(u64, 0), lookup.node.size);
    try testing.expectEqual(@as(u64, 0), lookup.node.inode);
}

test "blockCountForSize rounds up to 512-byte blocks without overflowing" {
    try testing.expectEqual(@as(u64, 0), blockCountForSize(0));
    try testing.expectEqual(@as(u64, 1), blockCountForSize(1));
    try testing.expectEqual(@as(u64, 1), blockCountForSize(512));
    try testing.expectEqual(@as(u64, 2), blockCountForSize(513));
    try testing.expectEqual(@as(u64, 2), blockCountForSize(1024));
    try testing.expectEqual(@as(u64, 3), blockCountForSize(1025));

    // maxInt(u64) is not a multiple of 512, so we expect one trailing block.
    const max_size = std.math.maxInt(u64);
    try testing.expectEqual(max_size / 512 + 1, blockCountForSize(max_size));
}

test "syntheticDirectoryInode stays stable per path and differs across paths" {
    // The inode is a wrapping sum so we can't assert an ordering against
    // first_dynamic_inode; only the stability and collision-free-ness
    // contract matters here.
    const a1 = syntheticDirectoryInode("/foo");
    const a2 = syntheticDirectoryInode("/foo");
    const b = syntheticDirectoryInode("/bar");
    try testing.expectEqual(a1, a2);
    try testing.expect(a1 != b);
}

test "accessClassLabel covers every AccessClass" {
    try testing.expectEqualStrings("read", accessClassLabel(.read));
    try testing.expectEqualStrings("create", accessClassLabel(.create));
    try testing.expectEqualStrings("write", accessClassLabel(.write));
    try testing.expectEqualStrings("rename", accessClassLabel(.rename));
    try testing.expectEqualStrings("delete", accessClassLabel(.delete));
    try testing.expectEqualStrings("metadata", accessClassLabel(.metadata));
    try testing.expectEqualStrings("xattr", accessClassLabel(.xattr));
}
