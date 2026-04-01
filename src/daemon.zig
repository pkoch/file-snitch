const std = @import("std");
const fuse = @import("fuse/shim.zig");
const policy = @import("policy.zig");

pub const Config = struct {
    mount_path: []const u8,
    backing_store_path: []const u8,
    run_in_foreground: bool = true,
    allow_mutations: bool = false,
    policy_rules: []const policy.Rule = &.{},
};

pub const State = struct {
    run_attempts: usize = 0,
    run_in_foreground: bool,
    allow_mutations: bool,
    policy_engine: policy.Engine,
};

pub const Description = fuse.SessionDescription;

pub const ExecutionPlan = struct {
    args: []const []const u8,
};

pub const NodeInfo = fuse.NodeInfo;
pub const AuditEvent = fuse.AuditEvent;

pub const Session = struct {
    allocator: std.mem.Allocator,
    state: *State,
    handle: *fuse.RawSession,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Session {
        const mount_path = try allocator.dupeZ(u8, config.mount_path);
        defer allocator.free(mount_path);

        const backing_store_path = try allocator.dupeZ(u8, config.backing_store_path);
        defer allocator.free(backing_store_path);

        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        var policy_engine = try policy.Engine.init(
            allocator,
            if (config.allow_mutations) .allow else .deny,
            config.policy_rules,
        );
        errdefer policy_engine.deinit();
        state.* = .{
            .run_in_foreground = config.run_in_foreground,
            .allow_mutations = config.allow_mutations,
            .policy_engine = policy_engine,
        };

        const handle = try fuse.createSession(.{
            .mount_path = mount_path,
            .backing_store_path = backing_store_path,
            .daemon_state = state,
            .run_in_foreground = config.run_in_foreground,
            .allow_mutations = config.allow_mutations,
        });

        return .{
            .allocator = allocator,
            .state = state,
            .handle = handle,
        };
    }

    pub fn deinit(self: Session) void {
        fuse.destroySession(self.handle);
        self.state.policy_engine.deinit();
        self.allocator.destroy(self.state);
    }

    pub fn describe(self: Session) !Description {
        return try fuse.describeSession(self.handle);
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
        return try fuse.debugGetattr(self.handle, path.ptr);
    }

    pub fn rootEntries(self: Session, allocator: std.mem.Allocator) ![]const []const u8 {
        const count = fuse.debugRootEntryCount(self.handle);
        var entries = try allocator.alloc([]const u8, count);
        errdefer allocator.free(entries);

        for (0..count) |index| {
            entries[index] = try fuse.debugRootEntry(self.handle, @intCast(index));
        }

        return entries;
    }

    pub fn readPath(self: Session, allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
        return try fuse.debugRead(self.handle, path.ptr, allocator);
    }

    pub fn debugCreateFile(self: *Session, path: [:0]const u8, mode: u32) !void {
        try fuse.debugCreateFile(self.handle, path.ptr, mode);
    }

    pub fn debugWriteFile(self: *Session, path: [:0]const u8, contents: [:0]const u8) !void {
        try fuse.debugWriteFile(self.handle, path.ptr, contents.ptr);
    }

    pub fn debugTruncateFile(self: *Session, path: [:0]const u8, size: u64) !void {
        try fuse.debugTruncateFile(self.handle, path.ptr, size);
    }

    pub fn debugRenameFile(self: *Session, from: [:0]const u8, to: [:0]const u8) !void {
        try fuse.debugRenameFile(self.handle, from.ptr, to.ptr);
    }

    pub fn debugSyncFile(self: *Session, path: [:0]const u8, datasync: bool) !void {
        try fuse.debugSyncFile(self.handle, path.ptr, datasync);
    }

    pub fn debugRemoveFile(self: *Session, path: [:0]const u8) !void {
        try fuse.debugRemoveFile(self.handle, path.ptr);
    }

    pub fn auditEvents(self: Session, allocator: std.mem.Allocator) ![]AuditEvent {
        const count = fuse.debugAuditCount(self.handle);
        var events = try allocator.alloc(AuditEvent, count);
        errdefer allocator.free(events);

        for (0..count) |index| {
            events[index] = try fuse.debugAuditEvent(self.handle, @intCast(index));
        }

        return events;
    }

    pub fn run(self: *Session) !void {
        self.state.run_attempts += 1;
        try fuse.runSession(self.handle);
    }
};

pub export fn fsn_policy_evaluate(
    daemon_state: ?*anyopaque,
    raw_request: *const policy.RawRequest,
    outcome_out: *u32,
) c_int {
    const state_ptr = daemon_state orelse return -1;
    const state: *State = @ptrCast(@alignCast(state_ptr));
    const request = policy.requestFromRaw(raw_request) catch return -1;
    outcome_out.* = @intFromEnum(state.policy_engine.evaluate(request));
    return 0;
}
