const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime.zig");

pub const Outcome = enum {
    timeout,
    changed,
};

pub const LinuxWatcher = if (builtin.os.tag == .linux) struct {
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    watch_descriptor: i32,
    filename: []u8,

    pub fn deinit(self: *LinuxWatcher) void {
        if (builtin.os.tag == .linux) {
            _ = std.c.inotify_rm_watch(self.fd, self.watch_descriptor);
            (std.Io.File{ .handle = self.fd, .flags = .{ .nonblocking = false } }).close(runtime.io());
        }
        self.allocator.free(self.filename);
        self.* = undefined;
    }

    pub fn wait(self: *LinuxWatcher, timeout_ns: u64) !Outcome {
        if (builtin.os.tag != .linux) unreachable;

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = self.fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&poll_fds, nanosToPollTimeoutMs(timeout_ns));
        if (ready == 0) return .timeout;

        var buffer: [4096]u8 align(@alignOf(std.os.linux.inotify_event)) = undefined;
        const bytes_read = try std.posix.read(self.fd, &buffer);
        if (bytes_read == 0) return .timeout;

        var offset: usize = 0;
        while (offset + @sizeOf(std.os.linux.inotify_event) <= bytes_read) {
            const event: *const std.os.linux.inotify_event = @ptrCast(@alignCast(buffer[offset .. offset + @sizeOf(std.os.linux.inotify_event)]));
            const event_size = @sizeOf(std.os.linux.inotify_event) + event.len;
            if (offset + event_size > bytes_read) break;
            offset += event_size;

            const event_name = event.getName() orelse continue;
            if (!std.mem.eql(u8, std.mem.sliceTo(event_name, 0), self.filename)) continue;
            return .changed;
        }

        return .timeout;
    }
} else struct {
    pub fn deinit(self: *LinuxWatcher) void {
        _ = self;
        unreachable;
    }

    pub fn wait(self: *LinuxWatcher, timeout_ns: u64) !Outcome {
        _ = self;
        _ = timeout_ns;
        unreachable;
    }
};

pub const DarwinWatcher = if (builtin.os.tag == .macos) struct {
    kqueue_fd: std.posix.fd_t,
    directory_fd: std.posix.fd_t,

    pub fn deinit(self: *DarwinWatcher) void {
        (std.Io.File{ .handle = self.directory_fd, .flags = .{ .nonblocking = false } }).close(runtime.io());
        (std.Io.File{ .handle = self.kqueue_fd, .flags = .{ .nonblocking = false } }).close(runtime.io());
        self.* = undefined;
    }

    pub fn wait(self: *DarwinWatcher, timeout_ns: u64) !Outcome {
        var timespec = nanosToTimespec(timeout_ns);
        var event_buffer: [1]std.c.Kevent = undefined;
        const count = std.c.kevent(self.kqueue_fd, &.{}, 0, &event_buffer, event_buffer.len, &timespec);
        if (count < 0) return error.InputOutput;
        if (count == 0) return .timeout;
        return .changed;
    }
} else struct {
    pub fn deinit(self: *DarwinWatcher) void {
        _ = self;
        unreachable;
    }

    pub fn wait(self: *DarwinWatcher, timeout_ns: u64) !Outcome {
        _ = self;
        _ = timeout_ns;
        unreachable;
    }
};

pub const ChangeSource = union(enum) {
    polling,
    linux_inotify: LinuxWatcher,
    darwin_kqueue: DarwinWatcher,

    pub fn init(allocator: std.mem.Allocator, policy_path: []const u8) ChangeSource {
        return switch (builtin.os.tag) {
            .linux => initLinuxWatcher(allocator, policy_path) catch |err| {
                std.log.warn("falling back to polling for policy changes at {s}: {}", .{ policy_path, err });
                return .polling;
            },
            .macos => initDarwinWatcher(allocator, policy_path) catch |err| {
                std.log.warn("falling back to polling for policy changes at {s}: {}", .{ policy_path, err });
                return .polling;
            },
            else => .polling,
        };
    }

    pub fn deinit(self: *ChangeSource) void {
        switch (self.*) {
            .polling => {},
            .linux_inotify => |*watcher| watcher.deinit(),
            .darwin_kqueue => |*watcher| watcher.deinit(),
        }
    }

    pub fn wait(self: *ChangeSource, timeout_ns: u64) Outcome {
        return switch (self.*) {
            .polling => {
                sleepForPolling(timeout_ns);
                return .timeout;
            },
            .linux_inotify => |*watcher| watcher.wait(timeout_ns) catch |err| {
                std.log.warn("policy watcher failed; falling back to polling: {}", .{err});
                watcher.deinit();
                self.* = .polling;
                sleepForPolling(timeout_ns);
                return .timeout;
            },
            .darwin_kqueue => |*watcher| watcher.wait(timeout_ns) catch |err| {
                std.log.warn("policy watcher failed; falling back to polling: {}", .{err});
                watcher.deinit();
                self.* = .polling;
                sleepForPolling(timeout_ns);
                return .timeout;
            },
        };
    }
};

fn sleepForPolling(timeout_ns: u64) void {
    std.Io.sleep(runtime.io(), .fromNanoseconds(@intCast(timeout_ns)), .awake) catch |err| {
        std.log.warn("policy polling sleep failed: {}", .{err});
    };
}

fn initLinuxWatcher(allocator: std.mem.Allocator, policy_path: []const u8) !ChangeSource {
    if (builtin.os.tag != .linux) unreachable;

    const watch_path = try splitWatchPath(allocator, policy_path);
    defer allocator.free(watch_path.directory_path);

    const fd = std.c.inotify_init1(std.os.linux.IN.CLOEXEC);
    if (fd < 0) return error.SystemResources;
    errdefer (std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } }).close(runtime.io());

    const watch_mask =
        std.os.linux.IN.CLOSE_WRITE |
        std.os.linux.IN.CREATE |
        std.os.linux.IN.DELETE |
        std.os.linux.IN.MOVED_TO |
        std.os.linux.IN.MOVE_SELF |
        std.os.linux.IN.DELETE_SELF;
    const directory_path_z = try allocator.dupeZ(u8, watch_path.directory_path);
    defer allocator.free(directory_path_z);
    const watch_descriptor = std.c.inotify_add_watch(fd, directory_path_z.ptr, watch_mask);
    if (watch_descriptor < 0) return error.InputOutput;
    errdefer _ = std.c.inotify_rm_watch(fd, watch_descriptor);

    return .{ .linux_inotify = .{
        .allocator = allocator,
        .fd = fd,
        .watch_descriptor = watch_descriptor,
        .filename = try allocator.dupe(u8, watch_path.basename),
    } };
}

fn initDarwinWatcher(allocator: std.mem.Allocator, policy_path: []const u8) !ChangeSource {
    const watch_path = try splitWatchPath(allocator, policy_path);
    defer allocator.free(watch_path.directory_path);

    const kqueue_fd = std.c.kqueue();
    if (kqueue_fd < 0) return error.SystemResources;
    errdefer (std.Io.File{ .handle = kqueue_fd, .flags = .{ .nonblocking = false } }).close(runtime.io());

    const directory_flags = comptime flags: {
        var open_flags = std.posix.O{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .DIRECTORY = true,
        };
        if (@hasField(std.posix.O, "EVTONLY")) open_flags.EVTONLY = true;
        if (@hasField(std.posix.O, "PATH")) open_flags.PATH = true;
        break :flags open_flags;
    };
    const directory_path_z = try allocator.dupeZ(u8, watch_path.directory_path);
    defer allocator.free(directory_path_z);
    const directory_fd = std.c.open(directory_path_z.ptr, directory_flags, @as(std.c.mode_t, 0));
    if (directory_fd < 0) return error.FileNotFound;
    errdefer (std.Io.File{ .handle = directory_fd, .flags = .{ .nonblocking = false } }).close(runtime.io());

    const changes = [_]std.c.Kevent{.{
        .ident = @bitCast(@as(isize, directory_fd)),
        .filter = std.c.EVFILT.VNODE,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.CLEAR,
        .fflags = std.c.NOTE.WRITE | std.c.NOTE.RENAME | std.c.NOTE.DELETE | std.c.NOTE.EXTEND | std.c.NOTE.ATTRIB | std.c.NOTE.REVOKE,
        .data = 0,
        .udata = 0,
    }};
    if (std.c.kevent(kqueue_fd, &changes, changes.len, undefined, 0, null) < 0) return error.InputOutput;

    return .{ .darwin_kqueue = .{
        .kqueue_fd = kqueue_fd,
        .directory_fd = directory_fd,
    } };
}

pub fn splitWatchPath(allocator: std.mem.Allocator, policy_path: []const u8) !struct {
    directory_path: []u8,
    basename: []const u8,
} {
    return .{
        .directory_path = try allocator.dupe(u8, std.fs.path.dirname(policy_path) orelse "."),
        .basename = std.fs.path.basename(policy_path),
    };
}

pub fn nanosToPollTimeoutMs(timeout_ns: u64) i32 {
    const timeout_ms = std.math.divCeil(u64, timeout_ns, std.time.ns_per_ms) catch @panic("divCeil with non-zero divisor");
    if (timeout_ms > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(timeout_ms);
}

pub fn nanosToTimespec(timeout_ns: u64) std.posix.timespec {
    return .{
        .sec = @intCast(timeout_ns / std.time.ns_per_s),
        .nsec = @intCast(timeout_ns % std.time.ns_per_s),
    };
}

test "splitWatchPath separates directory and basename" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const split = try splitWatchPath(alloc, "/tmp/file-snitch/policy.yml");
    try std.testing.expectEqualStrings("/tmp/file-snitch", split.directory_path);
    try std.testing.expectEqualStrings("policy.yml", split.basename);

    const bare = try splitWatchPath(alloc, "policy.yml");
    try std.testing.expectEqualStrings(".", bare.directory_path);
    try std.testing.expectEqualStrings("policy.yml", bare.basename);
}

test "nanosToPollTimeoutMs rounds up and saturates" {
    try std.testing.expectEqual(@as(i32, 1), nanosToPollTimeoutMs(1));
    try std.testing.expectEqual(@as(i32, 1), nanosToPollTimeoutMs(std.time.ns_per_ms));
    try std.testing.expectEqual(@as(i32, 2), nanosToPollTimeoutMs(std.time.ns_per_ms + 1));
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), nanosToPollTimeoutMs(std.math.maxInt(u64)));
}

test "nanosToTimespec splits seconds and nanoseconds" {
    const ts = nanosToTimespec(std.time.ns_per_s + 12);
    try std.testing.expectEqual(@as(@TypeOf(ts.sec), 1), ts.sec);
    try std.testing.expectEqual(@as(@TypeOf(ts.nsec), 12), ts.nsec);
}
