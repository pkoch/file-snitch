const std = @import("std");
const net = std.net;
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("unistd.h");
});

const protocol_name = "file-snitch-agent";
const protocol_version = "1.0";
const max_frame_len: usize = 999_999;
const max_length_digits: usize = 6;

pub const RequesterContext = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    timeout_ms: u32 = 5_000,
};

pub const Frontend = struct {
    context: ?*anyopaque,
    resolve_fn: *const fn (?*anyopaque, prompt.Request) prompt.Decision,

    pub fn resolve(self: Frontend, request: prompt.Request) prompt.Decision {
        return self.resolve_fn(self.context, request);
    }
};

pub const TerminalPinentryContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = 5_000,
    tty_path: ?[]const u8 = null,
    inherited_cli_context: ?*prompt.CliContext = null,
    mutex: std.Thread.Mutex = .{},
};

pub const AgentServiceContext = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    frontend: Frontend,
};

pub fn defaultSocketPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "FILE_SNITCH_AGENT_SOCKET")) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    if (std.process.getEnvVarOwned(allocator, "XDG_RUNTIME_DIR")) |runtime_dir| {
        defer allocator.free(runtime_dir);
        return std.fmt.allocPrint(allocator, "{s}/file-snitch/agent.sock", .{runtime_dir});
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.local/state/file-snitch/agent.sock", .{home});
}

pub fn socketBroker(context: *RequesterContext) prompt.Broker {
    return .{
        .context = context,
        .resolve_fn = resolveSocket,
    };
}

pub fn terminalPinentryFrontend(context: *TerminalPinentryContext) Frontend {
    return .{
        .context = context,
        .resolve_fn = resolveTerminalPinentry,
    };
}

pub fn defaultTerminalPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "FILE_SNITCH_AGENT_TTY")) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return terminalPathFromStandardFilesAlloc(allocator) catch
        error.NotATerminal;
}

pub fn runAgentService(context: *AgentServiceContext) !void {
    try ensureParentDirectory(context.socket_path);
    removeStaleSocketFile(context.socket_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };

    const address = try net.Address.initUnix(context.socket_path);
    const listener = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(listener);
    defer removeStaleSocketFile(context.socket_path) catch {};

    try std.posix.bind(listener, &address.any, address.getOsSockLen());
    try std.posix.listen(listener, 16);

    while (true) {
        const accepted = std.posix.accept(listener, null, null, std.posix.SOCK.CLOEXEC) catch |err| switch (err) {
            error.ConnectionAborted, error.WouldBlock => continue,
            else => return err,
        };
        var stream = net.Stream{ .handle = accepted };
        defer stream.close();

        handleConnection(context, stream) catch |err| {
            std.log.warn("agent connection failed: {}", .{err});
        };
    }
}

fn resolveSocket(raw_context: ?*anyopaque, request: prompt.Request) prompt.Decision {
    const context = raw_context orelse return .unavailable;
    const requester_context: *RequesterContext = @ptrCast(@alignCast(context));
    return resolveViaAgent(requester_context, request) catch |err| switch (err) {
        error.TimedOut => .timeout,
        else => .unavailable,
    };
}

fn resolveViaAgent(context: *RequesterContext, request: prompt.Request) !prompt.Decision {
    var stream = try net.connectUnixSocket(context.socket_path);
    defer stream.close();

    const hello_frame = try readFrameAlloc(context.allocator, stream, context.timeout_ms);
    defer context.allocator.free(hello_frame);

    try validateHelloFrame(context.allocator, hello_frame);

    const hello_request_id = try requestIdFromFrame(context.allocator, hello_frame);
    defer context.allocator.free(hello_request_id);
    try sendWelcome(stream, hello_request_id);

    const request_id = try generateUlidAlloc(context.allocator);
    defer context.allocator.free(request_id);

    const timeout_seconds = @divTrunc(@as(i64, @intCast(context.timeout_ms)) + 999, 1000);
    const timeout_at = std.time.timestamp() + timeout_seconds;
    const timeout_at_rfc3339 = try formatRfc3339UtcAlloc(context.allocator, timeout_at);
    defer context.allocator.free(timeout_at_rfc3339);

    const display_path = request.label orelse blk: {
        const generated = try std.fmt.allocPrint(
            context.allocator,
            "{s} {s}",
            .{ accessClassLabel(request.access_class), request.path },
        );
        break :blk generated;
    };
    defer if (request.label == null) context.allocator.free(display_path);

    try sendDecide(stream, request_id, request, display_path, timeout_at_rfc3339);

    while (true) {
        const frame = try readFrameAlloc(context.allocator, stream, context.timeout_ms);
        defer context.allocator.free(frame);

        const message_type = try frameTypeFromJson(context.allocator, frame);
        defer context.allocator.free(message_type);

        if (std.mem.eql(u8, message_type, "event")) continue;
        if (std.mem.eql(u8, message_type, "decision")) {
            return try decisionFromFrame(context.allocator, frame);
        }
        if (std.mem.eql(u8, message_type, "error")) {
            return .unavailable;
        }
        return .unavailable;
    }
}

fn handleConnection(context: *AgentServiceContext, stream: net.Stream) !void {
    const hello_request_id = try generateUlidAlloc(context.allocator);
    defer context.allocator.free(hello_request_id);
    try sendHello(stream, hello_request_id);

    const welcome_frame = try readFrameAlloc(context.allocator, stream, null);
    defer context.allocator.free(welcome_frame);
    try validateWelcomeFrame(context.allocator, welcome_frame, hello_request_id);

    while (true) {
        const frame = readFrameAlloc(context.allocator, stream, null) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };
        defer context.allocator.free(frame);

        const message_type = try frameTypeFromJson(context.allocator, frame);
        defer context.allocator.free(message_type);

        if (std.mem.eql(u8, message_type, "query")) {
            const request_id = try requestIdFromFrame(context.allocator, frame);
            defer context.allocator.free(request_id);
            try sendQueryResult(stream, request_id);
            continue;
        }

        if (std.mem.eql(u8, message_type, "decide")) {
            const decision = try decideFromFrame(context.allocator, frame, context.frontend);
            try sendDecision(stream, decision.request_id, decision.decision);
            continue;
        }

        const request_id = try requestIdFromFrame(context.allocator, frame);
        defer context.allocator.free(request_id);
        try sendError(stream, request_id, "unsupported-message-type", "message type not supported");
    }
}

const Header = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: ?[]const u8 = null,
};

const Welcome = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    role: []const u8,
    requester_name: []const u8,
    requester_version: []const u8,
    capabilities: []const []const u8,
};

const DecideMessage = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    subject: struct {
        uid: u32,
        pid: u32,
        executable_path: ?[]const u8 = null,
    },
    request: struct {
        enrolled_path: []const u8,
        approval_class: []const u8,
        operation: []const u8,
        mode: []const u8,
    },
    policy_context: struct {
        default_timeout: []const u8,
        can_remember: bool,
    },
    forwarding: ?struct {
        origin_host: []const u8,
        origin_transport: []const u8,
        forwarded: bool,
    } = null,
    details: ?struct {
        display_path: ?[]const u8 = null,
    } = null,
};

const DecisionMessage = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    outcome: []const u8,
    reason: []const u8,
};

const ResolvedDecision = struct {
    request_id: []const u8,
    decision: prompt.Decision,
};

fn sendHello(stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "hello",
        .request_id = request_id,
        .role = "agent",
        .agent_name = "file-snitch-agent",
        .agent_version = "0.1.0",
        .capabilities = &.{ "decide", "query" },
    });
}

fn sendWelcome(stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "welcome",
        .request_id = request_id,
        .role = "requester",
        .requester_name = "file-snitch-run",
        .requester_version = "0.1.0",
        .capabilities = &.{ "decide", "query" },
    });
}

fn sendQueryResult(stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "query_result",
        .request_id = request_id,
        .capabilities = &.{ "decide", "query" },
    });
}

fn sendDecide(
    stream: net.Stream,
    request_id: []const u8,
    request: prompt.Request,
    display_path: []const u8,
    timeout_at_rfc3339: []const u8,
) !void {
    try sendJsonFrame(stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "decide",
        .request_id = request_id,
        .subject = .{
            .uid = request.uid,
            .pid = request.pid,
            .executable_path = request.executable_path,
        },
        .request = .{
            .enrolled_path = request.path,
            .approval_class = accessClassLabel(request.access_class),
            .operation = operationLabel(request.access_class),
            .mode = modeLabel(request.access_class),
        },
        .policy_context = .{
            .default_timeout = timeout_at_rfc3339,
            .can_remember = false,
        },
        .forwarding = .{
            .origin_host = "local",
            .origin_transport = "local",
            .forwarded = false,
        },
        .details = .{
            .display_path = display_path,
        },
    });
}

fn sendDecision(stream: net.Stream, request_id: []const u8, decision: prompt.Decision) !void {
    try sendJsonFrame(stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "decision",
        .request_id = request_id,
        .outcome = outcomeLabel(decision),
        .reason = decisionReason(decision),
    });
}

fn sendError(stream: net.Stream, request_id: []const u8, code: []const u8, message: []const u8) !void {
    try sendJsonFrame(stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "error",
        .request_id = request_id,
        .code = code,
        .message = message,
    });
}

fn decideFromFrame(allocator: std.mem.Allocator, frame: []const u8, frontend: Frontend) !ResolvedDecision {
    const parsed = try std.json.parseFromSlice(DecideMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const request: prompt.Request = .{
        .path = parsed.value.request.enrolled_path,
        .access_class = try accessClassFromLabel(parsed.value.request.approval_class),
        .label = if (parsed.value.details) |details| details.display_path else null,
        .pid = parsed.value.subject.pid,
        .uid = parsed.value.subject.uid,
        .gid = 0,
        .executable_path = parsed.value.subject.executable_path,
    };

    return .{
        .request_id = parsed.value.request_id,
        .decision = frontend.resolve(request),
    };
}

fn resolveTerminalPinentry(raw_context: ?*anyopaque, request: prompt.Request) prompt.Decision {
    const context = raw_context orelse return .unavailable;
    const pinentry_context: *TerminalPinentryContext = @ptrCast(@alignCast(context));
    pinentry_context.mutex.lock();
    defer pinentry_context.mutex.unlock();

    if (pinentry_context.inherited_cli_context) |cli_context| {
        return prompt.resolveCliWithContext(cli_context, request);
    }

    const tty_path = pinentry_context.tty_path orelse return .unavailable;
    var tty_file = std.fs.openFileAbsolute(tty_path, .{ .mode = .read_write }) catch return .unavailable;
    defer tty_file.close();

    var cli_context = prompt.CliContext{
        .timeout_ms = pinentry_context.timeout_ms,
        .stdin_file = tty_file,
        .stderr_file = tty_file,
    };
    return prompt.resolveCliWithContext(&cli_context, request);
}

fn terminalPathFromStandardFilesAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.fs.File.stderr().isTty()) {
        return terminalPathForFileAlloc(allocator, std.fs.File.stderr());
    }
    if (std.fs.File.stdin().isTty()) {
        return terminalPathForFileAlloc(allocator, std.fs.File.stdin());
    }
    return error.NotATerminal;
}

fn terminalPathForFileAlloc(allocator: std.mem.Allocator, file: std.fs.File) ![]u8 {
    if (!file.isTty()) return error.NotATerminal;

    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const result = c.ttyname_r(file.handle, &buffer, buffer.len);
    if (result != 0) return error.NotATerminal;

    return allocator.dupe(u8, std.mem.sliceTo(&buffer, 0));
}

fn decisionFromFrame(allocator: std.mem.Allocator, frame: []const u8) !prompt.Decision {
    const parsed = try std.json.parseFromSlice(DecisionMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    _ = parsed.value.request_id;
    return switch (parsed.value.outcome[0]) {
        'a' => .allow,
        'd' => .deny,
        't' => .timeout,
        'u' => .unavailable,
        'c' => .deny,
        else => .unavailable,
    };
}

fn validateHelloFrame(allocator: std.mem.Allocator, frame: []const u8) !void {
    const parsed = try std.json.parseFromSlice(Header, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.type, "hello")) return error.InvalidProtocolMessage;
}

fn validateWelcomeFrame(allocator: std.mem.Allocator, frame: []const u8, expected_request_id: []const u8) !void {
    const parsed = try std.json.parseFromSlice(Welcome, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.type, "welcome")) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.role, "requester")) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.request_id, expected_request_id)) return error.InvalidProtocolMessage;
}

fn requestIdFromFrame(allocator: std.mem.Allocator, frame: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(Header, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return allocator.dupe(u8, parsed.value.request_id orelse return error.InvalidProtocolMessage);
}

fn frameTypeFromJson(allocator: std.mem.Allocator, frame: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(Header, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return allocator.dupe(u8, parsed.value.type);
}

fn sendJsonFrame(stream: net.Stream, value: anytype) !void {
    var output: std.io.Writer.Allocating = .init(std.heap.page_allocator);
    defer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    try writeFrame(stream, output.written());
}

fn writeFrame(stream: net.Stream, payload: []const u8) !void {
    var prefix_buffer: [32]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buffer, "{d}:", .{payload.len});
    try stream.writeAll(prefix);
    try stream.writeAll(payload);
    try stream.writeAll("\n");
}

fn readFrameAlloc(allocator: std.mem.Allocator, stream: net.Stream, timeout_ms: ?u32) ![]u8 {
    var length_buffer: [max_length_digits]u8 = undefined;
    var length_len: usize = 0;

    while (true) {
        const next = try readByte(stream, timeout_ms);
        if (next == ':') break;
        if (next < '0' or next > '9') return error.InvalidFrame;
        if (length_len >= max_length_digits) return error.InvalidFrame;
        length_buffer[length_len] = next;
        length_len += 1;
    }

    if (length_len == 0) return error.InvalidFrame;
    if (length_len > 1 and length_buffer[0] == '0') return error.InvalidFrame;

    const payload_len = try std.fmt.parseInt(usize, length_buffer[0..length_len], 10);
    if (payload_len > max_frame_len) return error.InvalidFrame;

    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    try readExact(stream, payload, timeout_ms);

    const trailing = try readByte(stream, timeout_ms);
    if (trailing != '\n') return error.InvalidFrame;
    return payload;
}

fn readExact(stream: net.Stream, buffer: []u8, timeout_ms: ?u32) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        try waitReadable(stream.handle, timeout_ms);
        const count = try stream.read(buffer[offset..]);
        if (count == 0) return error.EndOfStream;
        offset += count;
    }
}

fn readByte(stream: net.Stream, timeout_ms: ?u32) !u8 {
    var byte: [1]u8 = undefined;
    try readExact(stream, &byte, timeout_ms);
    return byte[0];
}

fn waitReadable(fd: std.posix.fd_t, timeout_ms: ?u32) !void {
    if (timeout_ms == null) return;
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&poll_fds, @intCast(timeout_ms.?));
    if (ready == 0) return error.TimedOut;
    if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) {
        return error.InputOutput;
    }
    if ((poll_fds[0].revents & std.posix.POLL.HUP) != 0 and (poll_fds[0].revents & std.posix.POLL.IN) == 0) {
        return error.EndOfStream;
    }
}

fn ensureParentDirectory(path: []const u8) !void {
    const parent_dir = std.fs.path.dirname(path) orelse return error.InvalidPath;
    try std.fs.cwd().makePath(parent_dir);
}

fn removeStaleSocketFile(path: []const u8) !void {
    try std.fs.cwd().deleteFile(path);
}

fn operationLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read, .write => "open",
        .create => "create",
        .rename => "rename",
        .delete => "unlink",
        .metadata => "metadata",
        .xattr => "metadata",
    };
}

fn modeLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read",
        .write, .create, .rename, .delete => "write",
        .metadata, .xattr => "metadata",
    };
}

fn accessClassLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read_like",
        .create, .write, .rename, .delete, .metadata, .xattr => "write_capable",
    };
}

fn accessClassFromLabel(label: []const u8) !policy.AccessClass {
    if (std.mem.eql(u8, label, "read_like")) return .read;
    if (std.mem.eql(u8, label, "write_capable")) return .write;
    return error.InvalidProtocolMessage;
}

fn outcomeLabel(decision: prompt.Decision) []const u8 {
    return switch (decision) {
        .allow => "allow",
        .deny => "deny",
        .timeout => "timeout",
        .unavailable => "unavailable",
    };
}

fn decisionReason(decision: prompt.Decision) []const u8 {
    return switch (decision) {
        .allow => "user-approved",
        .deny => "user-denied",
        .timeout => "agent-timeout",
        .unavailable => "agent-unavailable",
    };
}

fn formatRfc3339UtcAlloc(allocator: std.mem.Allocator, unix_seconds: i64) ![]u8 {
    if (unix_seconds < 0) return error.InvalidTimestamp;
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(unix_seconds) };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.allocPrint(
        allocator,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_seconds.getHoursIntoDay(),
            day_seconds.getMinutesIntoHour(),
            day_seconds.getSecondsIntoMinute(),
        },
    );
}

fn generateUlidAlloc(allocator: std.mem.Allocator) ![]u8 {
    var bytes: [16]u8 = undefined;
    const timestamp_ms: u64 = @intCast(std.time.milliTimestamp());
    bytes[0] = @truncate(timestamp_ms >> 40);
    bytes[1] = @truncate(timestamp_ms >> 32);
    bytes[2] = @truncate(timestamp_ms >> 24);
    bytes[3] = @truncate(timestamp_ms >> 16);
    bytes[4] = @truncate(timestamp_ms >> 8);
    bytes[5] = @truncate(timestamp_ms);
    std.crypto.random.bytes(bytes[6..]);

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

test "frame roundtrip preserves payload" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    const payload = "{\"protocol\":\"file-snitch-agent\"}";
    try list.writer(allocator).print("{d}:{s}\n", .{ payload.len, payload });

    var stream = std.io.fixedBufferStream(list.items);
    const decoded = try readFrameFromReaderAlloc(allocator, stream.reader());
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(payload, decoded);
}

fn readFrameFromReaderAlloc(allocator: std.mem.Allocator, reader: anytype) ![]u8 {
    var length_buffer: [max_length_digits]u8 = undefined;
    var length_len: usize = 0;
    while (true) {
        const next = try reader.readByte();
        if (next == ':') break;
        if (next < '0' or next > '9') return error.InvalidFrame;
        if (length_len >= max_length_digits) return error.InvalidFrame;
        length_buffer[length_len] = next;
        length_len += 1;
    }
    if (length_len == 0) return error.InvalidFrame;
    if (length_len > 1 and length_buffer[0] == '0') return error.InvalidFrame;
    const payload_len = try std.fmt.parseInt(usize, length_buffer[0..length_len], 10);
    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    try reader.readNoEof(payload);
    if (try reader.readByte() != '\n') return error.InvalidFrame;
    return payload;
}

test "generated ulid is well-formed" {
    const allocator = std.testing.allocator;
    const value = try generateUlidAlloc(allocator);
    defer allocator.free(value);
    try std.testing.expectEqual(@as(usize, 26), value.len);
    for (value) |byte| {
        try std.testing.expect(std.mem.indexOfScalar(u8, "0123456789ABCDEFGHJKMNPQRSTVWXYZ", byte) != null);
    }
}

test "default terminal path uses FILE_SNITCH_AGENT_TTY override" {
    const allocator = std.testing.allocator;
    const key = "FILE_SNITCH_AGENT_TTY";
    const value = "/tmp/file-snitch-agent-test-tty";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key, value, 1));
    defer _ = c.unsetenv(key);

    const resolved = try defaultTerminalPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}
