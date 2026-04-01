const std = @import("std");
const fuse = @import("fuse/shim.zig");

pub const Config = struct {
    mount_path: []const u8,
    backing_store_path: []const u8,
    run_in_foreground: bool = true,
};

pub const State = struct {
    run_attempts: usize = 0,
    run_in_foreground: bool,
};

pub const Description = fuse.SessionDescription;

pub const ExecutionPlan = struct {
    args: []const []const u8,
};

pub const NodeInfo = fuse.NodeInfo;

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
        state.* = .{
            .run_in_foreground = config.run_in_foreground,
        };

        const handle = try fuse.createSession(.{
            .mount_path = mount_path,
            .backing_store_path = backing_store_path,
            .daemon_state = state,
            .run_in_foreground = config.run_in_foreground,
        });

        return .{
            .allocator = allocator,
            .state = state,
            .handle = handle,
        };
    }

    pub fn deinit(self: Session) void {
        fuse.destroySession(self.handle);
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

    pub fn debugRemoveFile(self: *Session, path: [:0]const u8) !void {
        try fuse.debugRemoveFile(self.handle, path.ptr);
    }

    pub fn run(self: *Session) !void {
        self.state.run_attempts += 1;
        try fuse.runSession(self.handle);
    }
};
