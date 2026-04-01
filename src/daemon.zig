const std = @import("std");
const filesystem = @import("filesystem.zig");
const fuse = @import("fuse/shim.zig");
const policy = @import("policy.zig");

pub const Config = struct {
    mount_path: []const u8,
    backing_store_path: []const u8,
    run_in_foreground: bool = true,
    default_mutation_outcome: policy.Outcome = .deny,
    policy_rules: []const policy.Rule = &.{},
};

pub const Description = struct {
    backend_name: []const u8,
    mount_path: []const u8,
    backing_store_path: []const u8,
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
    args: []const []const u8,
};

pub const NodeInfo = filesystem.NodeInfo;
pub const AuditEvent = filesystem.AuditEvent;

pub const RawLookup = extern struct {
    kind: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    inode: u64,
    open_kind: u8,
    persistent: u8,
    reserved: [6]u8,
};

pub const State = struct {
    run_attempts: usize = 0,
    filesystem: filesystem.Model,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    state: *State,
    handle: *fuse.RawSession,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Session {
        const mount_path_z = try allocator.dupeZ(u8, config.mount_path);
        defer allocator.free(mount_path_z);

        const backing_store_path_z = try allocator.dupeZ(u8, config.backing_store_path);
        defer allocator.free(backing_store_path_z);

        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.* = .{
            .filesystem = try filesystem.Model.init(allocator, .{
                .mount_path = config.mount_path,
                .backing_store_path = config.backing_store_path,
                .default_mutation_outcome = config.default_mutation_outcome,
                .policy_rules = config.policy_rules,
            }),
        };
        errdefer state.filesystem.deinit();

        const handle = try fuse.createSession(.{
            .mount_path = mount_path_z,
            .backing_store_path = backing_store_path_z,
            .daemon_state = state,
            .run_in_foreground = config.run_in_foreground,
        });
        errdefer fuse.destroySession(handle);

        const runtime = try fuse.describeSession(handle);
        state.filesystem.setRuntimeStats(.{
            .configured_operation_count = runtime.configured_operation_count,
            .planned_argument_count = runtime.planned_argument_count,
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
        const runtime = try fuse.describeSession(self.handle);
        return .{
            .backend_name = runtime.backend_name,
            .mount_path = self.state.filesystem.mount_path,
            .backing_store_path = self.state.filesystem.backing_store_path,
            .high_level_ops_size = runtime.high_level_ops_size,
            .configured_operation_count = runtime.configured_operation_count,
            .planned_argument_count = runtime.planned_argument_count,
            .mount_implemented = runtime.mount_implemented,
            .has_session_state = runtime.has_session_state,
            .has_daemon_state = runtime.has_daemon_state,
            .has_init_callback = runtime.has_init_callback,
            .run_in_foreground = runtime.run_in_foreground,
            .default_mutation_outcome = self.state.filesystem.defaultMutationOutcome(),
        };
    }

    pub fn executionPlan(self: Session, allocator: std.mem.Allocator) !ExecutionPlan {
        const count = fuse.sessionArgumentCount(self.handle);
        var args = try allocator.alloc([]const u8, count);
        errdefer allocator.free(args);

        for (0..count) |index| {
            args[index] = try fuse.sessionArgument(self.handle, @intCast(index));
        }

        return .{ .args = args };
    }

    pub fn freeExecutionPlan(self: Session, allocator: std.mem.Allocator, plan: ExecutionPlan) void {
        _ = self;
        allocator.free(plan.args);
    }

    pub fn inspectPath(self: Session, path: [:0]const u8) !NodeInfo {
        return self.state.filesystem.lookupPath(path).node;
    }

    pub fn rootEntries(self: Session, allocator: std.mem.Allocator) ![]const []const u8 {
        const count = self.state.filesystem.rootEntryCount();
        var entries = try allocator.alloc([]const u8, count);
        errdefer allocator.free(entries);

        for (0..count) |index| {
            const raw = self.state.filesystem.rootEntryNameAt(@intCast(index)) orelse {
                return error.Unexpected;
            };
            entries[index] = std.mem.span(raw);
        }

        return entries;
    }

    pub fn readPath(self: Session, allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
        const node = self.state.filesystem.lookupPath(path).node;
        const buffer = try allocator.alloc(u8, @intCast(node.size));
        errdefer allocator.free(buffer);

        const result = self.state.filesystem.readInto(path, 0, buffer, .{});
        if (result < 0) {
            return error.DebugReadFailed;
        }

        return buffer[0..@intCast(result)];
    }

    pub fn debugCreateFile(self: *Session, path: [:0]const u8, mode: u32) !void {
        if (self.state.filesystem.createFile(path, mode, .{}) != 0) {
            return error.DebugCreateFailed;
        }
    }

    pub fn debugWriteFile(self: *Session, path: [:0]const u8, contents: [:0]const u8) !void {
        if (self.state.filesystem.writeFile(path, 0, contents[0..contents.len], .{}) < 0) {
            return error.DebugWriteFailed;
        }
    }

    pub fn debugTruncateFile(self: *Session, path: [:0]const u8, size: u64) !void {
        if (self.state.filesystem.truncateFile(path, size, .{}) != 0) {
            return error.DebugTruncateFailed;
        }
    }

    pub fn debugRenameFile(self: *Session, from: [:0]const u8, to: [:0]const u8) !void {
        if (self.state.filesystem.renameFile(from, to, .{}) != 0) {
            return error.DebugRenameFailed;
        }
    }

    pub fn debugSyncFile(self: *Session, path: [:0]const u8, datasync: bool) !void {
        if (self.state.filesystem.syncPath(path, datasync) != 0) {
            return error.DebugSyncFailed;
        }
    }

    pub fn debugRemoveFile(self: *Session, path: [:0]const u8) !void {
        if (self.state.filesystem.removeFile(path, .{}) != 0) {
            return error.DebugRemoveFailed;
        }
    }

    pub fn auditEvents(self: Session, allocator: std.mem.Allocator) ![]AuditEvent {
        const count = self.state.filesystem.auditCount();
        var events = try allocator.alloc(AuditEvent, count);
        errdefer allocator.free(events);

        for (0..count) |index| {
            events[index] = self.state.filesystem.auditEvent(@intCast(index)) orelse {
                return error.Unexpected;
            };
        }

        return events;
    }

    pub fn run(self: *Session) !void {
        self.state.run_attempts += 1;
        try fuse.runSession(self.handle);
    }
};

fn stateFromOpaque(opaque_state: ?*anyopaque) ?*State {
    const ptr = opaque_state orelse return null;
    return @ptrCast(@alignCast(ptr));
}

fn pathFromRaw(raw_path: ?[*:0]const u8) ?[]const u8 {
    const path = raw_path orelse return null;
    return std.mem.span(path);
}

fn requestFromRaw(raw_request: *const policy.RawRequest) ?struct {
    path: []const u8,
    access_class: policy.AccessClass,
    context: filesystem.AccessContext,
} {
    const request = policy.requestFromRaw(raw_request) catch return null;
    return .{
        .path = request.path,
        .access_class = request.access_class,
        .context = .{
            .pid = request.pid,
            .uid = request.uid,
            .gid = request.gid,
        },
    };
}

fn errnoCode(err: std.posix.E) c_int {
    return -@as(c_int, @intFromEnum(err));
}

pub export fn fsn_daemon_lookup_path(
    daemon_state: ?*anyopaque,
    raw_path: ?[*:0]const u8,
    out: *RawLookup,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const path = pathFromRaw(raw_path) orelse return errnoCode(.INVAL);
    const lookup = state.filesystem.lookupPath(path);

    out.* = .{
        .kind = @intFromEnum(lookup.node.kind),
        .mode = lookup.node.mode,
        .uid = lookup.node.uid,
        .gid = lookup.node.gid,
        .size = lookup.node.size,
        .inode = lookup.node.inode,
        .open_kind = @intFromEnum(lookup.open_kind),
        .persistent = @intFromBool(lookup.persistent),
        .reserved = std.mem.zeroes([6]u8),
    };
    return 0;
}

pub export fn fsn_daemon_root_entry_count(daemon_state: ?*anyopaque) u32 {
    const state = stateFromOpaque(daemon_state) orelse return 0;
    return state.filesystem.rootEntryCount();
}

pub export fn fsn_daemon_root_entry_name_at(daemon_state: ?*anyopaque, index: u32) ?[*:0]const u8 {
    const state = stateFromOpaque(daemon_state) orelse return null;
    return state.filesystem.rootEntryNameAt(index);
}

pub export fn fsn_daemon_authorize_access(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.authorizeAccess(request.path, request.access_class, request.context));
}

pub export fn fsn_daemon_read(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    offset: u64,
    size: usize,
    buf: [*]u8,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.readInto(request.path, offset, buf[0..size], request.context));
}

pub export fn fsn_daemon_create(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    mode: u32,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.createFile(request.path, mode, request.context));
}

pub export fn fsn_daemon_write(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    offset: u64,
    size: usize,
    buf: [*]const u8,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.writeFile(request.path, offset, buf[0..size], request.context));
}

pub export fn fsn_daemon_truncate(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    size: u64,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.truncateFile(request.path, size, request.context));
}

pub export fn fsn_daemon_chmod(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    mode: u32,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.chmodFile(request.path, mode, request.context));
}

pub export fn fsn_daemon_chown(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    uid: u32,
    gid: u32,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.chownFile(request.path, uid, gid, request.context));
}

pub export fn fsn_daemon_sync(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    datasync: u8,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.syncPath(request.path, datasync != 0));
}

pub export fn fsn_daemon_unlink(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.removeFile(request.path, request.context));
}

pub export fn fsn_daemon_rename(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    raw_to_path: ?[*:0]const u8,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const request = requestFromRaw(raw_request) orelse return errnoCode(.INVAL);
    const to_path = pathFromRaw(raw_to_path) orelse return errnoCode(.INVAL);
    return @intCast(state.filesystem.renameFile(request.path, to_path, request.context));
}

pub export fn fsn_daemon_record_audit(
    daemon_state: ?*anyopaque,
    raw_action: ?[*:0]const u8,
    raw_path: ?[*:0]const u8,
    result: i32,
) c_int {
    const state = stateFromOpaque(daemon_state) orelse return errnoCode(.INVAL);
    const action = pathFromRaw(raw_action) orelse return errnoCode(.INVAL);
    const path = pathFromRaw(raw_path) orelse return errnoCode(.INVAL);
    state.filesystem.recordPlatformAudit(action, path, result);
    return 0;
}
