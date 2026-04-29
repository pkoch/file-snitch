const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../runtime.zig");
const rfc3339 = @import("../rfc3339.zig");
const prompt = @import("../prompt.zig");
const policy = @import("../policy.zig");
const c = @cImport({
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("stdlib.h");
    @cInclude("sys/stat.h");
    @cInclude("sys/socket.h");
    @cInclude("sys/types.h");
    @cInclude("sys/un.h");
    if (builtin.os.tag == .macos) {
        @cInclude("sys/ucred.h");
    }
    @cInclude("unistd.h");
});

pub fn ensureParentDirectory(path: []const u8) !void {
    const parent_dir = std.fs.path.dirname(path) orelse return error.InvalidPath;
    if (std.Io.Dir.cwd().statFile(runtime.io(), parent_dir, .{})) |_| {
        if (std.mem.eql(u8, std.fs.path.basename(parent_dir), "file-snitch")) {
            try chmodPath(parent_dir, 0o700);
        }
        try validatePrivateDirectory(parent_dir);
        return;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    const grandparent_dir = std.fs.path.dirname(parent_dir) orelse return error.InvalidPath;
    std.Io.Dir.cwd().createDirPath(runtime.io(), grandparent_dir) catch |err| switch (err) {
        error.PathAlreadyExists, error.NotDir => {},
        else => return err,
    };
    mkdirPath(parent_dir, 0o700) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    try chmodPath(parent_dir, 0o700);
    try validatePrivateDirectory(parent_dir);
}

pub fn validatePrivateDirectory(path: []const u8) !void {
    const file_stat = try std.Io.Dir.cwd().statFile(runtime.io(), path, .{});
    if (file_stat.kind != .directory) return error.InvalidSocketPath;

    const posix_stat = try statPath(path);
    if (posix_stat.st_uid != c.getuid()) return error.InvalidSocketPath;
    if ((posix_stat.st_mode & 0o777) != 0o700) return error.InvalidSocketPath;
}

pub fn assertSameUidPeer(stream: anytype) !void {
    const peer_uid = try peerUid(stream.socket.handle);
    if (peer_uid != c.getuid()) return error.UnauthorizedPeer;
}

pub fn chmodPath(path: []const u8, mode: c.mode_t) !void {
    const path_z = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_z);
    if (c.chmod(path_z.ptr, mode) != 0) return error.AccessDenied;
}

pub fn mkdirPath(path: []const u8, mode: c.mode_t) !void {
    const path_z = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_z);
    if (c.mkdir(path_z.ptr, mode) != 0) {
        return switch (std.posix.errno(-1)) {
            .EXIST => error.PathAlreadyExists,
            .NOENT => error.FileNotFound,
            .NOTDIR => error.NotDir,
            .ACCES, .PERM => error.AccessDenied,
            .NAMETOOLONG => error.NameTooLong,
            .INTR => error.Interrupted,
            .IO => error.InputOutput,
            .NOMEM => error.OutOfMemory,
            else => error.Unexpected,
        };
    }
}

pub fn statPath(path: []const u8) !c.struct_stat {
    const path_z = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_z);
    var stat: c.struct_stat = undefined;
    if (c.stat(path_z.ptr, &stat) != 0) return error.InvalidSocketPath;
    return stat;
}

pub fn peerUid(fd: std.posix.fd_t) !std.posix.uid_t {
    return switch (builtin.os.tag) {
        .linux => peerUidLinux(fd),
        .macos => peerUidMacos(fd),
        else => error.InvalidSocketPath,
    };
}

fn peerUidLinux(fd: std.posix.fd_t) !std.posix.uid_t {
    var credential: c.struct_ucred = undefined;
    var credential_len: c.socklen_t = @sizeOf(c.struct_ucred);
    if (c.getsockopt(
        fd,
        c.SOL_SOCKET,
        c.SO_PEERCRED,
        &credential,
        &credential_len,
    ) != 0) return error.InvalidSocketPath;
    if (credential_len < @sizeOf(c.struct_ucred)) return error.InvalidSocketPath;
    return @intCast(credential.uid);
}

fn peerUidMacos(fd: std.posix.fd_t) !std.posix.uid_t {
    var credential: c.struct_xucred = undefined;
    var credential_len: c.socklen_t = @sizeOf(c.struct_xucred);
    if (c.getsockopt(
        fd,
        c.SOL_LOCAL,
        c.LOCAL_PEERCRED,
        &credential,
        &credential_len,
    ) != 0) return error.InvalidSocketPath;
    if (credential_len < @sizeOf(c.struct_xucred)) return error.InvalidSocketPath;
    return @intCast(credential.cr_uid);
}

pub fn removeSocketFileIfStale(path: []const u8) !void {
    const stat = std.Io.Dir.cwd().statFile(runtime.io(), path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .unix_domain_socket) return error.InvalidSocketPath;

    const has_live_listener = socketPathHasLiveListener(path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (has_live_listener) return error.SocketPathInUse;

    removeStaleSocketFile(path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
}

pub fn removeStaleSocketFile(path: []const u8) !void {
    try std.Io.Dir.cwd().deleteFile(runtime.io(), path);
}

pub fn removeStaleSocketFileForCleanup(path: []const u8) void {
    removeStaleSocketFile(path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.log.warn("failed to remove stale agent socket {s}: {}", .{ path, err }),
    };
}

pub fn socketPathHasLiveListener(path: []const u8) !bool {
    var addr: c.struct_sockaddr_un = std.mem.zeroes(c.struct_sockaddr_un);
    if (path.len >= addr.sun_path.len) return error.InvalidSocketPath;

    addr.sun_family = c.AF_UNIX;
    if (@hasField(c.struct_sockaddr_un, "sun_len")) {
        addr.sun_len = @intCast(@offsetOf(c.struct_sockaddr_un, "sun_path") + path.len + 1);
    }
    @memcpy(addr.sun_path[0..path.len], path);

    const fd = c.socket(c.AF_UNIX, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketPathInUse;
    defer _ = c.close(fd);

    const addr_len: c.socklen_t = @intCast(@offsetOf(c.struct_sockaddr_un, "sun_path") + path.len + 1);
    const connect_result = if (builtin.os.tag == .linux)
        c.connect(fd, .{ .__sockaddr_un__ = &addr }, addr_len)
    else
        c.connect(fd, @ptrCast(&addr), addr_len);
    if (connect_result == 0) {
        return true;
    }

    return switch (std.posix.errno(-1)) {
        .NOENT => error.FileNotFound,
        .CONNREFUSED, .CONNRESET => false,
        else => error.SocketPathInUse,
    };
}

pub fn operationLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read, .write => "open",
        .create => "create",
        .rename => "rename",
        .delete => "unlink",
        .metadata => "metadata",
        .xattr => "metadata",
    };
}

pub fn modeLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read",
        .write, .create, .rename, .delete => "write",
        .metadata, .xattr => "metadata",
    };
}

pub fn accessClassLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read_like",
        .create, .write, .rename, .delete, .metadata, .xattr => "write_capable",
    };
}

pub fn accessClassFromLabel(label: []const u8) !policy.AccessClass {
    if (std.mem.eql(u8, label, "read_like")) return .read;
    if (std.mem.eql(u8, label, "write_capable")) return .write;
    return error.InvalidProtocolMessage;
}

pub fn outcomeLabel(decision: anytype) []const u8 {
    return switch (decision) {
        .allow => "allow",
        .deny => "deny",
        .timeout => "timeout",
        .unavailable => "unavailable",
    };
}

pub fn outcomeFromLabel(label: []const u8) !prompt.Decision {
    if (std.mem.eql(u8, label, "allow")) return .allow;
    if (std.mem.eql(u8, label, "deny")) return .deny;
    if (std.mem.eql(u8, label, "timeout")) return .timeout;
    if (std.mem.eql(u8, label, "unavailable")) return .unavailable;
    return error.InvalidProtocolMessage;
}

pub fn rememberKindLabel(kind: anytype) []const u8 {
    return switch (kind) {
        .none => "none",
        .once => "once",
        .temporary => "temporary",
        .durable => "durable",
    };
}

pub fn rememberKindFromLabel(label: []const u8) !prompt.RememberKind {
    if (std.mem.eql(u8, label, "none")) return .none;
    if (std.mem.eql(u8, label, "once")) return .once;
    if (std.mem.eql(u8, label, "temporary")) return .temporary;
    if (std.mem.eql(u8, label, "durable")) return .durable;
    return error.InvalidProtocolMessage;
}

pub fn decisionReason(decision: anytype) []const u8 {
    return switch (decision) {
        .allow => "user-approved",
        .deny => "user-denied",
        .timeout => "agent-timeout",
        .unavailable => "agent-unavailable",
    };
}

pub fn parseRememberExpiration(value: ?[]const u8) !?i64 {
    const raw = value orelse return null;
    return rfc3339.parseUtcSeconds(raw) catch |err| switch (err) {
        error.InvalidRfc3339Utc => return error.InvalidProtocolMessage,
    };
}

pub fn generateUlidAlloc(allocator: std.mem.Allocator) ![]u8 {
    var bytes: [16]u8 = undefined;
    const timestamp_ms: u64 = @intCast(runtime.milliTimestamp());
    bytes[0] = @truncate(timestamp_ms >> 40);
    bytes[1] = @truncate(timestamp_ms >> 32);
    bytes[2] = @truncate(timestamp_ms >> 24);
    bytes[3] = @truncate(timestamp_ms >> 16);
    bytes[4] = @truncate(timestamp_ms >> 8);
    bytes[5] = @truncate(timestamp_ms);
    runtime.io().random(bytes[6..]);

    var encoded: [26]u8 = undefined;
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    encoded[0] = alphabet[@intCast((bytes[0] & 0xE0) >> 5)];
    encoded[1] = alphabet[@intCast(bytes[0] & 0x1F)];
    encoded[2] = alphabet[@intCast((bytes[1] & 0xF8) >> 3)];
    encoded[3] = alphabet[@intCast(((bytes[1] & 0x07) << 2) | ((bytes[2] & 0xC0) >> 6))];
    encoded[4] = alphabet[@intCast((bytes[2] & 0x3E) >> 1)];
    encoded[5] = alphabet[@intCast(((bytes[2] & 0x01) << 4) | ((bytes[3] & 0xF0) >> 4))];
    encoded[6] = alphabet[@intCast(((bytes[3] & 0x0F) << 1) | ((bytes[4] & 0x80) >> 7))];
    encoded[7] = alphabet[@intCast((bytes[4] & 0x7C) >> 2)];
    encoded[8] = alphabet[@intCast(((bytes[4] & 0x03) << 3) | ((bytes[5] & 0xE0) >> 5))];
    encoded[9] = alphabet[@intCast(bytes[5] & 0x1F)];
    encoded[10] = alphabet[@intCast((bytes[6] & 0xF8) >> 3)];
    encoded[11] = alphabet[@intCast(((bytes[6] & 0x07) << 2) | ((bytes[7] & 0xC0) >> 6))];
    encoded[12] = alphabet[@intCast((bytes[7] & 0x3E) >> 1)];
    encoded[13] = alphabet[@intCast(((bytes[7] & 0x01) << 4) | ((bytes[8] & 0xF0) >> 4))];
    encoded[14] = alphabet[@intCast(((bytes[8] & 0x0F) << 1) | ((bytes[9] & 0x80) >> 7))];
    encoded[15] = alphabet[@intCast((bytes[9] & 0x7C) >> 2)];
    encoded[16] = alphabet[@intCast(((bytes[9] & 0x03) << 3) | ((bytes[10] & 0xE0) >> 5))];
    encoded[17] = alphabet[@intCast(bytes[10] & 0x1F)];
    encoded[18] = alphabet[@intCast((bytes[11] & 0xF8) >> 3)];
    encoded[19] = alphabet[@intCast(((bytes[11] & 0x07) << 2) | ((bytes[12] & 0xC0) >> 6))];
    encoded[20] = alphabet[@intCast((bytes[12] & 0x3E) >> 1)];
    encoded[21] = alphabet[@intCast(((bytes[12] & 0x01) << 4) | ((bytes[13] & 0xF0) >> 4))];
    encoded[22] = alphabet[@intCast(((bytes[13] & 0x0F) << 1) | ((bytes[14] & 0x80) >> 7))];
    encoded[23] = alphabet[@intCast((bytes[14] & 0x7C) >> 2)];
    encoded[24] = alphabet[@intCast(((bytes[14] & 0x03) << 3) | ((bytes[15] & 0xE0) >> 5))];
    encoded[25] = alphabet[@intCast(bytes[15] & 0x1F)];
    return allocator.dupe(u8, &encoded);
}

pub fn terminalPathForFileAlloc(allocator: std.mem.Allocator, file: std.Io.File) ![]u8 {
    if (!try file.isTty(runtime.io())) return error.NotATerminal;

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const result = c.ttyname_r(file.handle, &buffer, buffer.len);
    if (result != 0) return error.NotATerminal;

    return allocator.dupe(u8, std.mem.sliceTo(&buffer, 0));
}
