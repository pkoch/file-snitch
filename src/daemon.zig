const std = @import("std");
const filesystem = @import("filesystem.zig");
const fuse = @import("fuse/shim.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");
const runtime = @import("runtime.zig");
const store = @import("store.zig");
const builtin = @import("builtin");

extern "c" fn proc_pidpath(pid: c_int, buffer: *anyopaque, buffersize: u32) c_int;

pub const ProjectionConfig = struct {
    mount_path: []const u8,
    guarded_entries: []const filesystem.GuardedEntryConfig,
    /// Borrowed; the caller retains ownership and is the sole `deinit` site.
    guarded_store: *store.Backend,
    run_in_foreground: bool = true,
    default_mutation_outcome: policy.Outcome = .deny,
    policy_path: ?[]const u8 = null,
    // Borrowed views that must stay valid until Session.init deep-copies them
    // into the policy engine.
    policy_rule_views: []const policy.RuleView = &.{},
    prompt_broker: ?prompt.Broker = null,
    status_output_file: ?std.Io.File = null,
    audit_output_file: ?std.Io.File = null,
};

pub const Description = struct {
    backend_name: []const u8,
    mount_path: []const u8,
    high_level_ops_size: usize,
    configured_operation_count: u32,
    planned_argument_count: u32,
    mount_implemented: bool,
    has_session_state: bool,
    has_daemon_state: bool,
    has_init_callback: bool,
    run_in_foreground: bool,
    default_mutation_outcome: policy.Outcome,
};

pub const ExecutionPlan = struct {
    allocator: std.mem.Allocator,
    args: []const []const u8,

    pub fn deinit(self: *ExecutionPlan) void {
        for (self.args) |arg| {
            self.allocator.free(arg);
        }
        self.allocator.free(self.args);
        self.* = undefined;
    }
};

pub const NodeInfo = filesystem.NodeInfo;
pub const AuditEvent = filesystem.AuditEvent;

pub const RawLookup = extern struct {
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    block_size: u32,
    size: u64,
    block_count: u64,
    inode: u64,
    atime_sec: i64,
    atime_nsec: u32,
    mtime_sec: i64,
    mtime_nsec: u32,
    ctime_sec: i64,
    ctime_nsec: u32,
    open_kind: u8,
    guarded: u8,
    reserved: [2]u8,
};

pub const RawRequest = extern struct {
    path: ?[*:0]const u8,
    pid: u32,
    uid: u32,
    gid: u32,
    umask: u32,
    reserved: [4]u8,
};

pub const RawFileInfo = extern struct {
    flags: i32,
    fh_old: u64,
    writepage: i32,
    direct_io: u8,
    keep_cache: u8,
    flush: u8,
    nonseekable: u8,
    flock_release: u8,
    padding_bits: u32,
    purge_attr: u8,
    purge_ubc: u8,
    reserved: [2]u8,
    fh: u64,
    lock_owner: u64,
};

pub const RawLock = extern struct {
    cmd: i32,
    lock_type: i16,
    whence: i16,
    pid: i32,
    start: i64,
    len: i64,
};

const RawDirectoryEntryEmitFn = *const fn (?*anyopaque, [*:0]const u8) callconv(.c) c_int;

const DirectoryEntryEmitContext = struct {
    raw_context: ?*anyopaque,
    emit_fn: RawDirectoryEntryEmitFn,
    result: c_int = 0,
};

const DecodedContext = struct {
    state: *State,
    path: []const u8,
    context: filesystem.AccessContext,

    fn deinit(self: *DecodedContext) void {
        if (self.context.executable_path) |value| {
            self.state.filesystem.allocator.free(value);
            self.context.executable_path = null;
        }
    }
};

pub const State = struct {
    run_attempts: usize = 0,
    filesystem: filesystem.Model,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    state: *State,
    handle: *fuse.RawSession,

    pub fn initProjection(allocator: std.mem.Allocator, config: ProjectionConfig) !Session {
        const mount_path_z = try allocator.dupeZ(u8, config.mount_path);
        defer allocator.free(mount_path_z);

        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.* = .{
            .filesystem = try filesystem.Model.initProjection(allocator, .{
                .mount_path = config.mount_path,
                .guarded_entries = config.guarded_entries,
                .guarded_store = config.guarded_store,
                .default_mutation_outcome = config.default_mutation_outcome,
                .policy_path = config.policy_path,
                .policy_rule_views = config.policy_rule_views,
                .prompt_broker = config.prompt_broker,
                .status_output_file = config.status_output_file,
                .audit_output_file = config.audit_output_file,
            }),
        };
        errdefer state.filesystem.deinit();

        const handle = try fuse.createSession(.{
            .mount_path = mount_path_z,
            .daemon_state = state,
            .run_in_foreground = config.run_in_foreground,
        });
        errdefer fuse.destroySession(handle);

        const fuse_runtime = try fuse.describeSession(handle);
        state.filesystem.setRuntimeStats(.{
            .configured_operation_count = fuse_runtime.configured_operation_count,
            .planned_argument_count = fuse_runtime.planned_argument_count,
        });

        return .{
            .allocator = allocator,
            .state = state,
            .handle = handle,
        };
    }

    pub fn deinit(self: Session) void {
        fuse.destroySession(self.handle);
        self.state.filesystem.deinit();
        self.allocator.destroy(self.state);
    }

    pub fn describe(self: Session) !Description {
        const fuse_runtime = try fuse.describeSession(self.handle);
        return .{
            .backend_name = fuse_runtime.backend_name,
            .mount_path = self.state.filesystem.mount_path,
            .high_level_ops_size = fuse_runtime.high_level_ops_size,
            .configured_operation_count = fuse_runtime.configured_operation_count,
            .planned_argument_count = fuse_runtime.planned_argument_count,
            .mount_implemented = fuse_runtime.mount_implemented,
            .has_session_state = fuse_runtime.has_session_state,
            .has_daemon_state = fuse_runtime.has_daemon_state,
            .has_init_callback = fuse_runtime.has_init_callback,
            .run_in_foreground = fuse_runtime.run_in_foreground,
            .default_mutation_outcome = self.state.filesystem.defaultMutationOutcome(),
        };
    }

    pub fn executionPlan(self: Session, allocator: std.mem.Allocator) !ExecutionPlan {
        const count = fuse.sessionArgumentCount(self.handle);
        var args = try allocator.alloc([]const u8, count);
        var initialized: usize = 0;
        errdefer {
            for (args[0..initialized]) |arg| {
                allocator.free(arg);
            }
            allocator.free(args);
        }

        for (0..count) |index| {
            args[index] = try allocator.dupe(u8, try fuse.sessionArgument(self.handle, @intCast(index)));
            initialized += 1;
        }

        return .{
            .allocator = allocator,
            .args = args,
        };
    }

    pub fn run(self: *Session) !void {
        self.state.run_attempts += 1;
        try fuse.runSession(self.handle);
    }

    pub fn publishStatus(self: *Session) void {
        self.state.filesystem.publishStatus();
    }
};

pub fn mountProjection(allocator: std.mem.Allocator, config: ProjectionConfig) !void {
    try ensureDirectory(config.mount_path);

    var session = try Session.initProjection(allocator, config);
    defer session.deinit();

    const description = try session.describe();
    std.debug.print(
        "mounting file-snitch: mount={s} configured_ops={d} default_mutation={s}\n",
        .{
            description.mount_path,
            description.configured_operation_count,
            @tagName(description.default_mutation_outcome),
        },
    );
    session.publishStatus();

    try session.run();
}

fn ensureDirectory(path: []const u8) !void {
    var dir = try std.Io.Dir.openDirAbsolute(runtime.io(), path, .{});
    dir.close(runtime.io());
}

fn requireState(opaque_state: ?*anyopaque) ?*State {
    const ptr = opaque_state orelse return null;
    return @ptrCast(@alignCast(ptr));
}

fn requirePath(raw_path: ?[*:0]const u8) ?[]const u8 {
    const path = raw_path orelse return null;
    return std.mem.span(path);
}

fn contextFromRaw(raw_request: *const RawRequest) ?struct {
    path: []const u8,
    context: filesystem.AccessContext,
} {
    const path = raw_request.path orelse return null;
    return .{
        .path = std.mem.span(path),
        .context = .{
            .pid = raw_request.pid,
            .uid = raw_request.uid,
            .gid = raw_request.gid,
            .umask = raw_request.umask,
        },
    };
}

fn requireDecodedContext(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
) ?DecodedContext {
    const state = requireState(daemon_state) orelse return null;
    const request = contextFromRaw(raw_request) orelse return null;
    const executable_path = resolveExecutablePath(state.filesystem.allocator, request.context.pid) catch null;
    return .{
        .state = state,
        .path = request.path,
        .context = blk: {
            var context = request.context;
            context.executable_path = executable_path;
            break :blk context;
        },
    };
}

fn resolveExecutablePath(allocator: std.mem.Allocator, pid: u32) !?[]u8 {
    if (pid == 0) return null;

    return switch (builtin.os.tag) {
        .macos => resolveExecutablePathMacos(allocator, pid),
        .linux => resolveExecutablePathLinux(allocator, pid),
        else => null,
    };
}

fn resolveExecutablePathMacos(allocator: std.mem.Allocator, pid: u32) !?[]u8 {
    var buffer: [std.posix.PATH_MAX]u8 = undefined;
    const result = proc_pidpath(@intCast(pid), &buffer, buffer.len);
    if (result <= 0) {
        return null;
    }
    return try allocator.dupe(u8, buffer[0..@intCast(result)]);
}

fn resolveExecutablePathLinux(allocator: std.mem.Allocator, pid: u32) !?[]u8 {
    const link_path = try std.fmt.allocPrint(allocator, "/proc/{d}/exe", .{pid});
    defer allocator.free(link_path);

    var buffer: [std.posix.PATH_MAX]u8 = undefined;
    const target_len = std.Io.Dir.readLinkAbsolute(runtime.io(), link_path, &buffer) catch return null;
    return try allocator.dupe(u8, buffer[0..target_len]);
}

fn fileRequestFromRaw(raw_file_info: ?*const RawFileInfo) ?filesystem.FileRequestInfo {
    const file_info = raw_file_info orelse return null;
    return .{
        .flags = file_info.flags,
        .handle_id = handleIdFromRaw(file_info),
    };
}

fn handleIdFromRaw(file_info: *const RawFileInfo) ?u64 {
    if (file_info.fh != 0) {
        return file_info.fh;
    }
    if (file_info.fh_old != 0) {
        return file_info.fh_old;
    }
    return null;
}

fn modeForNode(node: NodeInfo) u32 {
    return switch (node.kind) {
        .missing => 0,
        .directory => std.posix.S.IFDIR | node.mode,
        .regular_file => std.posix.S.IFREG | node.mode,
    };
}

fn auditFileInfoFromRaw(file_info: ?*const RawFileInfo) ?filesystem.AuditFileInfo {
    const info = file_info orelse return null;
    return .{
        .flags = info.flags,
        .fh_old = info.fh_old,
        .writepage = info.writepage,
        .direct_io = info.direct_io,
        .keep_cache = info.keep_cache,
        .flush = info.flush,
        .nonseekable = info.nonseekable,
        .flock_release = info.flock_release,
        .padding_bits = info.padding_bits,
        .purge_attr = info.purge_attr,
        .purge_ubc = info.purge_ubc,
        .fh = info.fh,
        .lock_owner = info.lock_owner,
    };
}

fn auditLockInfoFromRaw(lock: *const RawLock) filesystem.AuditLockInfo {
    return .{
        .cmd = lock.cmd,
        .lock_type = lock.lock_type,
        .whence = lock.whence,
        .pid = lock.pid,
        .start = lock.start,
        .len = lock.len,
    };
}

fn auditFlockInfo(operation: i32) filesystem.AuditFlockInfo {
    return .{ .operation = operation };
}

fn errnoCode(err: std.posix.E) c_int {
    return -@as(c_int, @intFromEnum(err));
}

fn errnoCodeFromDirectoryError(err: anyerror) c_int {
    return switch (err) {
        error.FileNotFound => errnoCode(.NOENT),
        error.NotDir => errnoCode(.NOTDIR),
        error.AccessDenied => errnoCode(.ACCES),
        error.NameTooLong => errnoCode(.NAMETOOLONG),
        error.InvalidPath => errnoCode(.INVAL),
        error.BufferTooSmall => errnoCode(.NAMETOOLONG),
        error.EntryNotFound => errnoCode(.NOENT),
        error.InputOutput => errnoCode(.IO),
        error.Interrupted => errnoCode(.INTR),
        error.OutOfMemory, error.SystemResources => errnoCode(.NOMEM),
        else => errnoCode(.IO),
    };
}

fn emitDirectoryEntryToRaw(context: *DirectoryEntryEmitContext, name: []const u8) !bool {
    if (name.len + 1 > std.fs.max_path_bytes) return error.BufferTooSmall;

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buffer[0..name.len], name);
    buffer[name.len] = 0;

    const name_z = buffer[0..name.len :0];
    const result = context.emit_fn(context.raw_context, name_z.ptr);
    if (result < 0) {
        context.result = result;
        return error.EmitFailed;
    }
    return result == 0;
}

pub export fn fsn_daemon_lookup_path(
    daemon_state: ?*anyopaque,
    raw_path: ?[*:0]const u8,
    out: *RawLookup,
) c_int {
    const state = requireState(daemon_state) orelse return errnoCode(.INVAL);
    const path = requirePath(raw_path) orelse return errnoCode(.INVAL);
    const lookup = state.filesystem.lookupPath(path) catch |err| return errnoCodeFromDirectoryError(err);

    out.* = .{
        .mode = modeForNode(lookup.node),
        .nlink = lookup.node.nlink,
        .uid = lookup.node.uid,
        .gid = lookup.node.gid,
        .block_size = lookup.node.block_size,
        .size = lookup.node.size,
        .block_count = lookup.node.block_count,
        .inode = lookup.node.inode,
        .atime_sec = lookup.node.atime.sec,
        .atime_nsec = lookup.node.atime.nsec,
        .mtime_sec = lookup.node.mtime.sec,
        .mtime_nsec = lookup.node.mtime.nsec,
        .ctime_sec = lookup.node.ctime.sec,
        .ctime_nsec = lookup.node.ctime.nsec,
        .open_kind = @intFromEnum(lookup.open_kind),
        .guarded = @intFromBool(lookup.guarded),
        .reserved = std.mem.zeroes([2]u8),
    };
    return 0;
}

pub export fn fsn_daemon_open_guarded_lock_fd(
    daemon_state: ?*anyopaque,
    raw_path: ?[*:0]const u8,
    requested_flags: c_int,
) c_int {
    const state = requireState(daemon_state) orelse return errnoCode(.INVAL);
    const path = requirePath(raw_path) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.openGuardedLockFd(path, requested_flags));
}

pub export fn fsn_daemon_for_each_directory_entry(
    daemon_state: ?*anyopaque,
    raw_path: ?[*:0]const u8,
    raw_context: ?*anyopaque,
    emit_fn: RawDirectoryEntryEmitFn,
) c_int {
    const state = requireState(daemon_state) orelse return errnoCode(.INVAL);
    const path = requirePath(raw_path) orelse return errnoCode(.INVAL);
    var context = DirectoryEntryEmitContext{
        .raw_context = raw_context,
        .emit_fn = emit_fn,
    };
    state.filesystem.forEachDirectoryEntry(path, &context, emitDirectoryEntryToRaw) catch |err| {
        if (err == error.EmitFailed) return context.result;
        return errnoCodeFromDirectoryError(err);
    };
    return 0;
}

pub export fn fsn_daemon_read(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
    offset: u64,
    size: usize,
    buf: [*]u8,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.readInto(
        request.path,
        offset,
        buf[0..size],
        request.context,
        fileRequestFromRaw(raw_file_info),
    ));
}

pub export fn fsn_daemon_authorize_open(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: *const RawFileInfo,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.openFile(
        request.path,
        .{
            .flags = raw_file_info.flags,
            .handle_id = handleIdFromRaw(raw_file_info),
        },
        request.context,
    ));
}

pub export fn fsn_daemon_create(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    mode: u32,
    raw_file_info: ?*const RawFileInfo,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    if (fileRequestFromRaw(raw_file_info)) |file_request| {
        return @intCast(request.state.filesystem.createFileWithRequest(request.path, mode, request.context, file_request));
    }
    return @intCast(request.state.filesystem.createFile(request.path, mode, request.context));
}

pub export fn fsn_daemon_mkdir(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    mode: u32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.createDirectory(request.path, mode, request.context));
}

pub export fn fsn_daemon_write(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
    offset: u64,
    size: usize,
    buf: [*]const u8,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    if (fileRequestFromRaw(raw_file_info)) |file_request| {
        return @intCast(request.state.filesystem.writeFileWithRequest(
            request.path,
            offset,
            buf[0..size],
            request.context,
            file_request,
        ));
    }
    return @intCast(request.state.filesystem.writeFile(request.path, offset, buf[0..size], request.context));
}

pub export fn fsn_daemon_truncate(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
    size: u64,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    if (fileRequestFromRaw(raw_file_info)) |file_request| {
        return @intCast(request.state.filesystem.truncateFileWithRequest(request.path, size, request.context, file_request));
    }
    return @intCast(request.state.filesystem.truncateFile(request.path, size, request.context));
}

pub export fn fsn_daemon_chmod(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    mode: u32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.chmodFile(request.path, mode, request.context));
}

pub export fn fsn_daemon_chown(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    uid: u32,
    gid: u32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.chownFile(request.path, uid, gid, request.context));
}

pub export fn fsn_daemon_flush(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.flushPath(
        request.path,
        request.context,
        auditFileInfoFromRaw(raw_file_info),
    ));
}

pub export fn fsn_daemon_fsync(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
    datasync: u8,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.fsyncPath(
        request.path,
        datasync != 0,
        request.context,
        auditFileInfoFromRaw(raw_file_info),
    ));
}

pub export fn fsn_daemon_unlink(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.removeFile(request.path, request.context));
}

pub export fn fsn_daemon_rmdir(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    return @intCast(request.state.filesystem.removeDirectory(request.path, request.context));
}

pub export fn fsn_daemon_setxattr(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_name: ?[*:0]const u8,
    raw_value: ?[*]const u8,
    size: usize,
    flags: c_int,
    position: u32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    const name = requirePath(raw_name) orelse return errnoCode(.INVAL);
    var empty_value_storage: [1]u8 = undefined;
    const value: []const u8 = if (size == 0)
        empty_value_storage[0..0]
    else blk: {
        const ptr = raw_value orelse return errnoCode(.INVAL);
        break :blk ptr[0..size];
    };
    return @intCast(request.state.filesystem.setXattr(
        request.path,
        name,
        value,
        flags,
        position,
        request.context,
    ));
}

pub export fn fsn_daemon_getxattr(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_name: ?[*:0]const u8,
    raw_value: ?[*]u8,
    size: usize,
    position: u32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    const name = requirePath(raw_name) orelse return errnoCode(.INVAL);
    var empty_value_storage: [1]u8 = undefined;
    const value: []u8 = if (size == 0)
        empty_value_storage[0..0]
    else blk: {
        const ptr = raw_value orelse return errnoCode(.INVAL);
        break :blk ptr[0..size];
    };
    return @intCast(request.state.filesystem.getXattr(request.path, name, value, position, request.context));
}

pub export fn fsn_daemon_listxattr(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_list: ?[*]u8,
    size: usize,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    var empty_list_storage: [1]u8 = undefined;
    const list: []u8 = if (size == 0)
        empty_list_storage[0..0]
    else blk: {
        const ptr = raw_list orelse return errnoCode(.INVAL);
        break :blk ptr[0..size];
    };
    return @intCast(request.state.filesystem.listXattr(request.path, list, request.context));
}

pub export fn fsn_daemon_removexattr(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_name: ?[*:0]const u8,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    const name = requirePath(raw_name) orelse return errnoCode(.INVAL);
    return @intCast(request.state.filesystem.removeXattr(request.path, name, request.context));
}

pub export fn fsn_daemon_rename(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_to_path: ?[*:0]const u8,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    const to_path = requirePath(raw_to_path) orelse return errnoCode(.INVAL);
    return @intCast(request.state.filesystem.renameFile(request.path, to_path, request.context));
}

pub export fn fsn_daemon_record_open(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
    result: i32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    if (fileRequestFromRaw(raw_file_info)) |file_request| {
        request.state.filesystem.recordOpen(
            request.path,
            request.context,
            file_request,
            result,
            auditFileInfoFromRaw(raw_file_info),
        );
    } else {
        request.state.filesystem.recordPlatformAudit("open", request.path, result, .{
            .context = request.context,
            .file_info = auditFileInfoFromRaw(raw_file_info),
        });
    }
    return 0;
}

pub export fn fsn_daemon_record_release(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_file_info: ?*const RawFileInfo,
    result: i32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    if (fileRequestFromRaw(raw_file_info)) |file_request| {
        request.state.filesystem.recordRelease(
            request.path,
            request.context,
            file_request,
            result,
            auditFileInfoFromRaw(raw_file_info),
        );
    } else {
        request.state.filesystem.recordPlatformAudit("release", request.path, result, .{
            .context = request.context,
            .file_info = auditFileInfoFromRaw(raw_file_info),
        });
    }
    return 0;
}

pub export fn fsn_daemon_record_lock(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    raw_lock: *const RawLock,
    result: i32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    request.state.filesystem.recordPlatformAudit("lock", request.path, result, .{
        .context = request.context,
        .lock = auditLockInfoFromRaw(raw_lock),
    });
    return 0;
}

pub export fn fsn_daemon_record_flock(
    daemon_state: ?*anyopaque,
    raw_request: *const RawRequest,
    operation: i32,
    result: i32,
) c_int {
    var request = requireDecodedContext(daemon_state, raw_request) orelse return errnoCode(.INVAL);
    defer request.deinit();
    request.state.filesystem.recordPlatformAudit("flock", request.path, result, .{
        .context = request.context,
        .flock = auditFlockInfo(operation),
    });
    return 0;
}
