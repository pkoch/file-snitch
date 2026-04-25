const std = @import("std");
const defaults = @import("defaults.zig");
const runtime = @import("runtime.zig");

const Allocator = std.mem.Allocator;

const bytes_per_mib = 1024 * 1024;

/// File Snitch stores pass entries as one JSON document with base64 content.
/// This cap is on that serialized pass payload, not on `pass` itself.
pub const pass_payload_limit_bytes: usize = 1 * bytes_per_mib;
pub const pass_payload_limit_label = "1 MiB";

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

    pub fn restoreObjectToFile(
        self: *Backend,
        allocator: Allocator,
        object_id: []const u8,
        target_path: []const u8,
    ) !void {
        return switch (self.*) {
            inline else => |*backend| backend.restoreObjectToFile(allocator, object_id, target_path),
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
    const OutputLimitKind = enum {
        payload,
        command,
    };

    fn init(allocator: Allocator) !PassBackend {
        const command = runtime.getEnvVarOwned(allocator, defaults.pass_bin_env) catch |err| switch (err) {
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

    fn restoreObjectToFile(self: *PassBackend, allocator: Allocator, object_id: []const u8, target_path: []const u8) !void {
        var object = self.loadObject(allocator, object_id) catch |err| switch (err) {
            error.StorePayloadTooLarge => return self.restoreObjectToFileStreaming(allocator, object_id, target_path),
            else => return err,
        };
        defer object.deinit(allocator);

        try writeObjectToFileAtomic(target_path, .{
            .metadata = object.metadata,
            .content = object.content,
        });
    }

    fn putObject(self: *PassBackend, allocator: Allocator, object_id: []const u8, object: ObjectView) !void {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);

        const encoded = try encodeStoredObject(allocator, object);
        defer allocator.free(encoded);
        try ensurePayloadWithinPassLimit(encoded);

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
        const output = try self.runCommandNoInput(allocator, &argv, .command);
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
        const result = self.runCommandNoInput(allocator, &argv, .payload) catch |err| switch (err) {
            error.StoreCommandFailed => return error.ObjectNotFound,
            else => return err,
        };
        return result;
    }

    fn runCommandNoInput(
        self: *PassBackend,
        allocator: Allocator,
        argv: []const []const u8,
        stdout_limit_kind: OutputLimitKind,
    ) ![]u8 {
        _ = self;
        var child = std.process.spawn(runtime.io(), .{
            .argv = argv,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.StoreUnavailable,
            else => return err,
        };
        var child_done = false;
        errdefer if (!child_done) child.kill(runtime.io());

        var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
        var multi_reader: std.Io.File.MultiReader = undefined;
        multi_reader.init(allocator, runtime.io(), multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
        defer multi_reader.deinit();

        const stdout_reader = multi_reader.reader(0);
        const stderr_reader = multi_reader.reader(1);
        while (multi_reader.fill(64, .none)) |_| {
            if (stdout_reader.buffered().len > pass_payload_limit_bytes) {
                return switch (stdout_limit_kind) {
                    .payload => error.StorePayloadTooLarge,
                    .command => error.StoreCommandOutputTooLarge,
                };
            }
            if (stderr_reader.buffered().len > pass_payload_limit_bytes) {
                return error.StoreCommandOutputTooLarge;
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        }
        try multi_reader.checkAnyError();

        const term = try child.wait(runtime.io());
        child_done = true;

        const stdout = try multi_reader.toOwnedSlice(0);
        errdefer allocator.free(stdout);
        const stderr = try multi_reader.toOwnedSlice(1);
        defer allocator.free(stderr);

        return switch (term) {
            .exited => |code| switch (code) {
                0 => stdout,
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
        var child = std.process.spawn(runtime.io(), .{
            .argv = argv,
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.StoreUnavailable,
            else => return err,
        };
        errdefer child.kill(runtime.io());

        if (child.stdin) |stdin_pipe| {
            try stdin_pipe.writeStreamingAll(runtime.io(), input);
            stdin_pipe.close(runtime.io());
            child.stdin = null;
        }

        var multi_reader_buffer: std.Io.File.MultiReader.Buffer(2) = undefined;
        var multi_reader: std.Io.File.MultiReader = undefined;
        multi_reader.init(allocator, runtime.io(), multi_reader_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
        defer multi_reader.deinit();

        const stdout_reader = multi_reader.reader(0);
        const stderr_reader = multi_reader.reader(1);
        while (multi_reader.fill(64, .none)) |_| {
            if (stdout_reader.buffered().len > pass_payload_limit_bytes or
                stderr_reader.buffered().len > pass_payload_limit_bytes)
            {
                return error.StoreCommandOutputTooLarge;
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        }
        try multi_reader.checkAnyError();

        const term = try child.wait(runtime.io());
        switch (term) {
            .exited => |code| {
                if (code != 0) {
                    return error.StoreCommandFailed;
                }
            },
            else => return error.StoreCommandFailed,
        }
    }

    fn restoreObjectToFileStreaming(
        self: *PassBackend,
        allocator: Allocator,
        object_id: []const u8,
        target_path: []const u8,
    ) !void {
        const entry_name = try self.entryNameAlloc(allocator, object_id);
        defer allocator.free(entry_name);

        const argv = [_][]const u8{
            self.command,
            "show",
            entry_name,
        };

        var child = std.process.spawn(runtime.io(), .{
            .argv = &argv,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.StoreUnavailable,
            else => return err,
        };
        errdefer child.kill(runtime.io());

        var stdout_pipe = child.stdout.?;
        defer stdout_pipe.close(runtime.io());

        var read_buffer: [8192]u8 = undefined;
        var file_reader = stdout_pipe.readerStreaming(runtime.io(), &read_buffer);
        var json_reader = std.json.Reader.init(allocator, &file_reader.interface);
        defer json_reader.deinit();

        var atomic_file = AtomicObjectFile{};
        try atomic_file.init(target_path, 0o600);
        defer atomic_file.deinit();

        var write_buffer: [8192]u8 = undefined;
        var file_writer = atomic_file.file.file.writer(runtime.io(), &write_buffer);
        const metadata = decodeStoredObjectToWriter(allocator, &json_reader, &file_writer.interface) catch |err| {
            child.kill(runtime.io());
            return err;
        };
        try file_writer.interface.flush();

        const term = try child.wait(runtime.io());
        switch (term) {
            .exited => |code| {
                if (code != 0) {
                    return error.ObjectNotFound;
                }
            },
            else => return error.StoreCommandFailed,
        }

        try finishAtomicObjectFile(&atomic_file.file, metadata);
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

    fn restoreObjectToFile(self: *MockBackend, allocator: Allocator, object_id: []const u8, target_path: []const u8) !void {
        var object = try self.loadObject(allocator, object_id);
        defer object.deinit(allocator);

        try writeObjectToFileAtomic(target_path, .{
            .metadata = object.metadata,
            .content = object.content,
        });
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

fn ensurePayloadWithinPassLimit(encoded: []const u8) !void {
    if (encoded.len > pass_payload_limit_bytes) {
        return error.StorePayloadTooLarge;
    }
}

fn decodeStoredObject(allocator: Allocator, encoded: []const u8) !Object {
    try ensurePayloadWithinPassLimit(encoded);

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

fn decodeStoredObjectToWriter(allocator: Allocator, json_reader: *std.json.Reader, writer: *std.Io.Writer) !Metadata {
    if (try json_reader.next() != .object_begin) {
        return error.InvalidStoredObject;
    }

    var version: ?u32 = null;
    var metadata: Metadata = undefined;
    var seen_mode = false;
    var seen_uid = false;
    var seen_gid = false;
    var seen_atime_nsec = false;
    var seen_mtime_nsec = false;
    var seen_content = false;

    while (true) {
        const key_token = try json_reader.nextAllocMax(allocator, .alloc_if_needed, 128);

        switch (key_token) {
            .object_end => break,
            .string, .allocated_string => {},
            else => {
                freeAllocatedJsonToken(allocator, key_token);
                return error.InvalidStoredObject;
            },
        }

        const key = jsonTokenString(key_token) orelse return error.InvalidStoredObject;
        const field: enum {
            version,
            mode,
            uid,
            gid,
            atime_nsec,
            mtime_nsec,
            content_base64,
            unknown,
        } = if (std.mem.eql(u8, key, "version"))
            .version
        else if (std.mem.eql(u8, key, "mode"))
            .mode
        else if (std.mem.eql(u8, key, "uid"))
            .uid
        else if (std.mem.eql(u8, key, "gid"))
            .gid
        else if (std.mem.eql(u8, key, "atime_nsec"))
            .atime_nsec
        else if (std.mem.eql(u8, key, "mtime_nsec"))
            .mtime_nsec
        else if (std.mem.eql(u8, key, "content_base64"))
            .content_base64
        else
            .unknown;
        freeAllocatedJsonToken(allocator, key_token);

        if (field == .version) {
            version = try readJsonInteger(u32, allocator, json_reader);
        } else if (field == .mode) {
            metadata.mode = try readJsonInteger(u32, allocator, json_reader);
            seen_mode = true;
        } else if (field == .uid) {
            metadata.uid = try readJsonInteger(u32, allocator, json_reader);
            seen_uid = true;
        } else if (field == .gid) {
            metadata.gid = try readJsonInteger(u32, allocator, json_reader);
            seen_gid = true;
        } else if (field == .atime_nsec) {
            metadata.atime_nsec = try readJsonInteger(i128, allocator, json_reader);
            seen_atime_nsec = true;
        } else if (field == .mtime_nsec) {
            metadata.mtime_nsec = try readJsonInteger(i128, allocator, json_reader);
            seen_mtime_nsec = true;
        } else if (field == .content_base64) {
            try streamJsonBase64StringToWriter(json_reader, writer);
            seen_content = true;
        } else {
            try json_reader.skipValue();
        }
    }

    if (try json_reader.next() != .end_of_document) {
        return error.InvalidStoredObject;
    }

    if (version == null or
        version.? != 1 or
        !seen_mode or
        !seen_uid or
        !seen_gid or
        !seen_atime_nsec or
        !seen_mtime_nsec or
        !seen_content)
    {
        return error.InvalidStoredObject;
    }

    return metadata;
}

fn readJsonInteger(comptime T: type, allocator: Allocator, json_reader: *std.json.Reader) !T {
    const token = try json_reader.nextAllocMax(allocator, .alloc_if_needed, 64);
    defer freeAllocatedJsonToken(allocator, token);

    const number = jsonTokenNumber(token) orelse return error.InvalidStoredObject;
    return std.fmt.parseInt(T, number, 10) catch error.InvalidStoredObject;
}

fn jsonTokenString(token: std.json.Token) ?[]const u8 {
    return switch (token) {
        .string => |value| value,
        .allocated_string => |value| value,
        else => null,
    };
}

fn jsonTokenNumber(token: std.json.Token) ?[]const u8 {
    return switch (token) {
        .number => |value| value,
        .allocated_number => |value| value,
        else => null,
    };
}

fn freeAllocatedJsonToken(allocator: Allocator, token: std.json.Token) void {
    switch (token) {
        .allocated_string => |value| allocator.free(value),
        .allocated_number => |value| allocator.free(value),
        else => {},
    }
}

fn streamJsonBase64StringToWriter(json_reader: *std.json.Reader, writer: *std.Io.Writer) !void {
    var decoder = StreamingBase64Decoder{};

    while (true) {
        switch (try json_reader.next()) {
            .partial_string => |value| try decoder.feed(value, writer),
            .partial_string_escaped_1 => |value| try decoder.feed(value[0..], writer),
            .partial_string_escaped_2 => |value| try decoder.feed(value[0..], writer),
            .partial_string_escaped_3 => |value| try decoder.feed(value[0..], writer),
            .partial_string_escaped_4 => |value| try decoder.feed(value[0..], writer),
            .string => |value| {
                try decoder.feed(value, writer);
                try decoder.finish();
                return;
            },
            else => return error.InvalidStoredObject,
        }
    }
}

const StreamingBase64Decoder = struct {
    quad: [4]u8 = undefined,
    quad_len: usize = 0,
    finished: bool = false,

    fn feed(self: *StreamingBase64Decoder, encoded: []const u8, writer: *std.Io.Writer) !void {
        for (encoded) |byte| {
            try self.feedByte(byte, writer);
        }
    }

    fn feedByte(self: *StreamingBase64Decoder, byte: u8, writer: *std.Io.Writer) !void {
        if (self.finished) {
            return error.InvalidStoredObject;
        }

        self.quad[self.quad_len] = byte;
        self.quad_len += 1;
        if (self.quad_len == self.quad.len) {
            try self.flushQuad(writer);
        }
    }

    fn flushQuad(self: *StreamingBase64Decoder, writer: *std.Io.Writer) !void {
        if (self.quad[0] == '=' or self.quad[1] == '=' or
            (self.quad[2] == '=' and self.quad[3] != '='))
        {
            return error.InvalidStoredObject;
        }

        const source = self.quad[0..];
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(source) catch return error.InvalidStoredObject;
        var decoded: [3]u8 = undefined;
        std.base64.standard.Decoder.decode(decoded[0..decoded_len], source) catch return error.InvalidStoredObject;
        try writer.writeAll(decoded[0..decoded_len]);

        if (self.quad[2] == '=' or self.quad[3] == '=') {
            self.finished = true;
        }
        self.quad_len = 0;
    }

    fn finish(self: *StreamingBase64Decoder) !void {
        if (self.quad_len != 0) {
            return error.InvalidStoredObject;
        }
    }
};

fn writeObjectToFileAtomic(path: []const u8, object: ObjectView) !void {
    var atomic_file = AtomicObjectFile{};
    try atomic_file.init(path, @intCast(object.metadata.mode & 0o777));
    defer atomic_file.deinit();

    var write_buffer: [8192]u8 = undefined;
    var file_writer = atomic_file.file.file.writer(runtime.io(), &write_buffer);
    if (object.content.len != 0) {
        try file_writer.interface.writeAll(object.content);
    }
    try file_writer.interface.flush();

    try finishAtomicObjectFile(&atomic_file.file, object.metadata);
}

const AtomicObjectFile = struct {
    file: std.Io.File.Atomic = undefined,
    initialized: bool = false,

    fn init(self: *AtomicObjectFile, path: []const u8, mode: std.posix.mode_t) !void {
        if (std.fs.path.dirname(path) == null) return error.InvalidPath;
        self.file = try std.Io.Dir.cwd().createFileAtomic(runtime.io(), path, .{
            .permissions = .fromMode(mode),
            .make_path = true,
            .replace = true,
        });
        self.initialized = true;
    }

    fn deinit(self: *AtomicObjectFile) void {
        if (self.initialized) {
            self.file.deinit(runtime.io());
            self.initialized = false;
        }
        self.* = undefined;
    }
};

fn finishAtomicObjectFile(atomic_file: *std.Io.File.Atomic, metadata: Metadata) !void {
    try atomic_file.file.setPermissions(runtime.io(), .fromMode(@intCast(metadata.mode & 0o777)));
    try atomic_file.file.setOwner(runtime.io(), @intCast(metadata.uid), @intCast(metadata.gid));
    try atomic_file.file.setTimestamps(runtime.io(), .{
        .access_timestamp = .{ .new = .fromNanoseconds(@intCast(metadata.atime_nsec)) },
        .modify_timestamp = .{ .new = .fromNanoseconds(@intCast(metadata.mtime_nsec)) },
    });
    try atomic_file.file.sync(runtime.io());
    try atomic_file.replace(runtime.io());
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

test "pass payload limit rejects oversized serialized objects before parsing" {
    const allocator = std.testing.allocator;

    const oversized = try allocator.alloc(u8, pass_payload_limit_bytes + 1);
    defer allocator.free(oversized);
    @memset(oversized, 'x');

    try std.testing.expectError(error.StorePayloadTooLarge, ensurePayloadWithinPassLimit(oversized));
    try std.testing.expectError(error.StorePayloadTooLarge, decodeStoredObject(allocator, oversized));
}

test "streaming object decode can restore payloads beyond the pass capture limit" {
    const allocator = std.testing.allocator;

    const content = try allocator.alloc(u8, pass_payload_limit_bytes);
    defer allocator.free(content);
    for (content, 0..) |*byte, index| {
        byte.* = @intCast('a' + (index % 26));
    }

    const object: ObjectView = .{
        .metadata = .{
            .mode = 0o600,
            .uid = 501,
            .gid = 20,
            .atime_nsec = 111,
            .mtime_nsec = 222,
        },
        .content = content,
    };

    const encoded = try encodeStoredObject(allocator, object);
    defer allocator.free(encoded);
    try std.testing.expect(encoded.len > pass_payload_limit_bytes);
    try std.testing.expectError(error.StorePayloadTooLarge, decodeStoredObject(allocator, encoded));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var payload_file = try tmp.dir.createFile(runtime.io(), "payload.json", .{ .read = true });
    defer payload_file.close(runtime.io());
    try payload_file.writeStreamingAll(runtime.io(), encoded);

    var read_buffer: [4096]u8 = undefined;
    var file_reader = payload_file.reader(runtime.io(), &read_buffer);
    var json_reader = std.json.Reader.init(allocator, &file_reader.interface);
    defer json_reader.deinit();

    var decoded: std.Io.Writer.Allocating = .init(allocator);
    defer decoded.deinit();

    const metadata = try decodeStoredObjectToWriter(allocator, &json_reader, &decoded.writer);
    try std.testing.expectEqual(object.metadata.mode, metadata.mode);
    try std.testing.expectEqual(object.metadata.uid, metadata.uid);
    try std.testing.expectEqual(object.metadata.gid, metadata.gid);
    try std.testing.expectEqual(object.metadata.atime_nsec, metadata.atime_nsec);
    try std.testing.expectEqual(object.metadata.mtime_nsec, metadata.mtime_nsec);
    try std.testing.expectEqualSlices(u8, content, decoded.written());
}
