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

    pub fn run(self: *Session) !void {
        self.state.run_attempts += 1;
        try fuse.runSession(self.handle);
    }
};
