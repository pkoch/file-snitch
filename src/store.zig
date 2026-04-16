const std = @import("std");
const defaults = @import("defaults.zig");

const Allocator = std.mem.Allocator;

pub const Metadata = struct {
    mode: u32,
    uid: u32,
    gid: u32,
    atime_nsec: i128,
    mtime_nsec: i128,
};

pub const Object = struct {
    metadata: Metadata,
    content: []u8,

    pub fn deinit(self: *Object, allocator: Allocator) void {
        allocator.free(self.content);
        self.* = undefined;
    }
};

pub const ObjectView = struct {
    metadata: Metadata,
    content: []const u8,
};

pub const Backend = union(enum) {
    pass: PassBackend,
    mock: MockBackend,

    pub fn initPass(allocator: Allocator) !Backend {
        return .{ .pass = try PassBackend.init(allocator) };
    }

    pub fn initMock(state: *MockState) Backend {
        return .{ .mock = .{ .state = state } };
    }

    pub fn name(self: *const Backend) []const u8 {
        return switch (self.*) {
            .pass => "pass",
            .mock => "mock",
        };
    }

    pub fn deinit(self: *Backend, allocator: Allocator) void {
        switch (self.*) {
            inline else => |*backend| backend.deinit(allocator),
        }
        self.* = undefined;
    }

    pub fn describeRefAlloc(self: *const Backend, allocator: Allocator, object_id: []const u8) ![]u8 {
        return switch (self.*) {
            inline else => |*backend| backend.describeRefAlloc(allocator, object_id),
        };
    }

    pub fn exists(self: *Backend, allocator: Allocator, object_id: []const u8) !bool {
        return switch (self.*) {
            inline else => |*backend| backend.exists(allocator, object_id),
        };
    }

    pub fn loadObject(self: *Backend, allocator: Allocator, object_id: []const u8) !Object {
        return switch (self.*) {
            inline else => |*backend| backend.loadObject(allocator, object_id),
        };
    }

    pub fn putObject(self: *Backend, allocator: Allocator, object_id: []const u8, object: ObjectView) !void {
        return switch (self.*) {
            inline else => |*backend| backend.putObject(allocator, object_id, object),
        };
    }

    pub fn removeObject(self: *Backend, allocator: Allocator, object_id: []const u8) !void {
        return switch (self.*) {
            inline else => |*backend| backend.removeObject(allocator, object_id),
        };
    }
};

pub const PassBackend = struct {
    command: []u8,
    prefix: []u8,

    const store_prefix = "file-snitch";

    fn init(allocator: Allocator) !PassBackend {
        const command = std.process.getEnvVarOwned(allocator, defaults.pass_bin_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try allocator.dupe(u8, "pass"),
            else => return err,
        };
        errdefer allocator.free(command);

        return .{
            .command = command,
            .prefix = try allocator.dupe(u8, store_prefix),
        };
    }

    fn deinit(self: *PassBackend, allocator: Allocator) void {
        allocator.free(self.command);
        allocator.free(self.prefix);
        self.* = undefined;
    }

    fn describeRefAlloc(self: *const PassBackend, allocator: Allocator, object_id: []const u8) ![]u8 {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);
        return std.fmt.allocPrint(allocator, "pass:{s}", .{entry_name});
    }

    fn exists(self: *PassBackend, allocator: Allocator, object_id: []const u8) !bool {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);

        const shown = self.showEntry(allocator, entry_name) catch |err| switch (err) {
            error.ObjectNotFound => return false,
            else => return err,
        };
        allocator.free(shown);
        return true;
    }

    fn loadObject(self: *PassBackend, allocator: Allocator, object_id: []const u8) !Object {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);

        const encoded = try self.showEntry(allocator, entry_name);
        defer allocator.free(encoded);
        return decodeStoredObject(allocator, encoded);
    }

    fn putObject(self: *PassBackend, allocator: Allocator, object_id: []const u8, object: ObjectView) !void {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);

        const encoded = try encodeStoredObject(allocator, object);
        defer allocator.free(encoded);

        const argv = [_][]const u8{
            self.command,
            "insert",
            "--multiline",
            "--force",
            entry_name,
        };
        try self.runCommandWithInput(allocator, &argv, encoded);
    }

    fn removeObject(self: *PassBackend, allocator: Allocator, object_id: []const u8) !void {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);

        const argv = [_][]const u8{
            self.command,
            "rm",
            "--force",
            entry_name,
        };
        const output = try self.runCommandNoInput(allocator, &argv);
        allocator.free(output);
    }

    fn entryNameAlloc(self: *const PassBackend, allocator: Allocator, object_id: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}/{s}", .{ self.prefix, object_id });
    }

    fn showEntry(self: *PassBackend, allocator: Allocator, entry_name: []const u8) ![]u8 {
        const argv = [_][]const u8{
            self.command,
            "show",
            entry_name,
        };
        const result = self.runCommandNoInput(allocator, &argv) catch |err| switch (err) {
            error.StoreCommandFailed => return error.ObjectNotFound,
            else => return err,
        };
        return result;
    }

    fn runCommandNoInput(
        self: *PassBackend,
        allocator: Allocator,
        argv: []const []const u8,
    ) ![]u8 {
        _ = self;
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = argv,
            .max_output_bytes = 1024 * 1024,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.StoreUnavailable,
            else => return err,
        };
        defer allocator.free(result.stderr);
        errdefer allocator.free(result.stdout);

        return switch (result.term) {
            .Exited => |code| switch (code) {
                0 => result.stdout,
                else => error.StoreCommandFailed,
            },
            else => error.StoreCommandFailed,
        };
    }

    fn runCommandWithInput(
        self: *PassBackend,
        allocator: Allocator,
        argv: []const []const u8,
        input: []const u8,
    ) !void {
        _ = self;
        var child = std.process.Child.init(argv, allocator);
        child.stdin_behavior = .Pipe;
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Pipe;

        child.spawn() catch |err| switch (err) {
            error.FileNotFound => return error.StoreUnavailable,
            else => return err,
        };
        errdefer _ = child.kill() catch {};

        if (child.stdin) |stdin_pipe| {
            try stdin_pipe.writeAll(input);
            stdin_pipe.close();
            child.stdin = null;
        }

        var stdout = std.ArrayList(u8).empty;
        defer stdout.deinit(allocator);
        var stderr = std.ArrayList(u8).empty;
        defer stderr.deinit(allocator);
        try child.collectOutput(allocator, &stdout, &stderr, 1024 * 1024);

        const term = try child.wait();
        switch (term) {
            .Exited => |code| {
                if (code != 0) {
                    return error.StoreCommandFailed;
                }
            },
            else => return error.StoreCommandFailed,
        }
    }
};

pub const MockBackend = struct {
    state: *MockState,

    fn deinit(self: *MockBackend, allocator: Allocator) void {
        _ = self;
        _ = allocator;
    }

    fn describeRefAlloc(self: *const MockBackend, allocator: Allocator, object_id: []const u8) ![]u8 {
        _ = self;
        return std.fmt.allocPrint(allocator, "mock:file-snitch/{s}", .{object_id});
    }

    fn exists(self: *MockBackend, allocator: Allocator, object_id: []const u8) !bool {
        return self.state.exists(allocator, object_id);
    }

    fn loadObject(self: *MockBackend, allocator: Allocator, object_id: []const u8) !Object {
        return self.state.loadObject(allocator, object_id);
    }

    fn putObject(self: *MockBackend, allocator: Allocator, object_id: []const u8, object: ObjectView) !void {
        return self.state.putObject(allocator, object_id, object);
    }

    fn removeObject(self: *MockBackend, allocator: Allocator, object_id: []const u8) !void {
        return self.state.removeObject(allocator, object_id);
    }
};

pub const MockState = struct {
    entries: std.StringHashMapUnmanaged(StoredEntry) = .{},

    const StoredEntry = struct {
        metadata: Metadata,
        content: []u8,

        fn deinit(self: *StoredEntry, allocator: Allocator) void {
            allocator.free(self.content);
            self.* = undefined;
        }
    };

    pub fn deinit(self: *MockState, allocator: Allocator) void {
        var iterator = self.entries.iterator();
        while (iterator.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    pub fn exists(self: *MockState, allocator: Allocator, object_id: []const u8) !bool {
        _ = allocator;
        return self.entries.contains(object_id);
    }

    pub fn loadObject(self: *MockState, allocator: Allocator, object_id: []const u8) !Object {
        const entry = self.entries.get(object_id) orelse return error.ObjectNotFound;
        return .{
            .metadata = entry.metadata,
            .content = try allocator.dupe(u8, entry.content),
        };
    }

    pub fn putObject(self: *MockState, allocator: Allocator, object_id: []const u8, object: ObjectView) !void {
        if (self.entries.getPtr(object_id)) |existing| {
            existing.deinit(allocator);
            existing.* = .{
                .metadata = object.metadata,
                .content = try allocator.dupe(u8, object.content),
            };
            return;
        }

        try self.entries.put(allocator, try allocator.dupe(u8, object_id), .{
            .metadata = object.metadata,
            .content = try allocator.dupe(u8, object.content),
        });
    }

    pub fn removeObject(self: *MockState, allocator: Allocator, object_id: []const u8) !void {
        const removed = self.entries.fetchRemove(object_id) orelse return error.ObjectNotFound;
        allocator.free(removed.key);
        var value = removed.value;
        value.deinit(allocator);
    }
};

const SerializedObject = struct {
    version: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    atime_nsec: i128,
    mtime_nsec: i128,
    content_base64: []const u8,
};

fn encodeStoredObject(allocator: Allocator, object: ObjectView) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(object.content.len);
    const encoded_content = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded_content);
    _ = std.base64.standard.Encoder.encode(encoded_content, object.content);
    return std.json.Stringify.valueAlloc(
        allocator,
        SerializedObject{
            .version = 1,
            .mode = object.metadata.mode,
            .uid = object.metadata.uid,
            .gid = object.metadata.gid,
            .atime_nsec = object.metadata.atime_nsec,
            .mtime_nsec = object.metadata.mtime_nsec,
            .content_base64 = encoded_content,
        },
        .{},
    );
}

fn decodeStoredObject(allocator: Allocator, encoded: []const u8) !Object {
    const parsed = try std.json.parseFromSlice(SerializedObject, allocator, encoded, .{});
    defer parsed.deinit();

    if (parsed.value.version != 1) {
        return error.InvalidStoredObject;
    }

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(parsed.value.content_base64);
    const content = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(content);
    try std.base64.standard.Decoder.decode(content, parsed.value.content_base64);

    return .{
        .metadata = .{
            .mode = parsed.value.mode,
            .uid = parsed.value.uid,
            .gid = parsed.value.gid,
            .atime_nsec = parsed.value.atime_nsec,
            .mtime_nsec = parsed.value.mtime_nsec,
        },
        .content = content,
    };
}

test "mock backend round-trips objects" {
    const allocator = std.testing.allocator;

    var state = MockState{};
    defer state.deinit(allocator);

    var backend = Backend.initMock(&state);
    defer backend.deinit(allocator);

    try backend.putObject(allocator, "kube-config", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 501,
            .gid = 20,
            .atime_nsec = 11,
            .mtime_nsec = 22,
        },
        .content = "secret\n",
    });

    try std.testing.expect(try backend.exists(allocator, "kube-config"));

    var loaded = try backend.loadObject(allocator, "kube-config");
    defer loaded.deinit(allocator);

    try std.testing.expectEqual(@as(u32, 0o600), loaded.metadata.mode);
    try std.testing.expectEqual(@as(u32, 501), loaded.metadata.uid);
    try std.testing.expectEqual(@as(u32, 20), loaded.metadata.gid);
    try std.testing.expectEqual(@as(i128, 11), loaded.metadata.atime_nsec);
    try std.testing.expectEqual(@as(i128, 22), loaded.metadata.mtime_nsec);
    try std.testing.expectEqualStrings("secret\n", loaded.content);

    try backend.removeObject(allocator, "kube-config");
    try std.testing.expect(!(try backend.exists(allocator, "kube-config")));
}

test "stored object encoding round-trips metadata and content" {
    const allocator = std.testing.allocator;

    const object: ObjectView = .{
        .metadata = .{
            .mode = 0o640,
            .uid = 42,
            .gid = 7,
            .atime_nsec = 123456789,
            .mtime_nsec = 987654321,
        },
        .content = "top secret bytes",
    };

    const encoded = try encodeStoredObject(allocator, object);
    defer allocator.free(encoded);

    var decoded = try decodeStoredObject(allocator, encoded);
    defer decoded.deinit(allocator);

    try std.testing.expectEqual(object.metadata.mode, decoded.metadata.mode);
    try std.testing.expectEqual(object.metadata.uid, decoded.metadata.uid);
    try std.testing.expectEqual(object.metadata.gid, decoded.metadata.gid);
    try std.testing.expectEqual(object.metadata.atime_nsec, decoded.metadata.atime_nsec);
    try std.testing.expectEqual(object.metadata.mtime_nsec, decoded.metadata.mtime_nsec);
    try std.testing.expectEqualStrings(object.content, decoded.content);
}

test "stored object decode rejects unsupported version" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(
        error.InvalidStoredObject,
        decodeStoredObject(
            allocator,
            "{\"version\":2,\"mode\":384,\"uid\":1,\"gid\":2,\"atime_nsec\":3,\"mtime_nsec\":4,\"content_base64\":\"YQ==\"}",
        ),
    );
}
