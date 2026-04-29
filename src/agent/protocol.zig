const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const app_meta = @import("../app_meta.zig");
const config = @import("../config.zig");
const defaults = @import("../defaults.zig");
const policy = @import("../policy.zig");
const prompt = @import("../prompt.zig");
const rfc3339 = @import("../rfc3339.zig");
const runtime = @import("../runtime.zig");
const util = @import("util.zig");
const core = @import("core.zig");
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

const protocol_name = "file-snitch-agent";
const protocol_version = "1.0";
pub const max_frame_len: usize = 999_999;
const max_length_digits: usize = 6;

pub const ConnectionWorkerContext = struct {
    allocator: std.mem.Allocator,
    service_context: *@import("core.zig").AgentServiceContext,
    stream: net.Stream,
};

pub const Header = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: ?[]const u8 = null,
};

pub const Welcome = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    role: []const u8,
    requester_name: []const u8,
    requester_version: []const u8,
    capabilities: []const []const u8,
};

pub const DecideMessage = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    subject: struct {
        uid: u32,
        gid: u32,
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

pub const DecisionMessage = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    outcome: []const u8,
    reason: []const u8,
    remember: ?struct {
        kind: []const u8,
        expires_at: ?[]const u8 = null,
    } = null,
};

pub const EventMessage = struct {
    protocol: []const u8,
    version: []const u8,
    type: []const u8,
    request_id: []const u8,
    event: []const u8,
    user_interaction: ?struct {
        deadline: []const u8,
    } = null,
};

pub const ResolvedDecision = struct {
    request_id: []const u8,
    response: prompt.Response,
};

pub fn resolveSocket(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const requester_context: *@import("core.zig").RequesterContext = @ptrCast(@alignCast(context));
    return resolveViaAgent(requester_context, request) catch |err| switch (err) {
        error.TimedOut => .{ .decision = .unavailable },
        else => .{ .decision = .unavailable },
    };
}

fn resolveViaAgent(context: *@import("core.zig").RequesterContext, request: prompt.Request) !prompt.Response {
    const address = try net.UnixAddress.init(context.socket_path);
    var stream = try address.connect(runtime.io());
    defer stream.close(runtime.io());
    try util.assertSameUidPeer(stream);

    const hello_frame = try readFrameAlloc(context.allocator, stream, context.protocol_timeout_ms);
    defer context.allocator.free(hello_frame);

    try validateHelloFrame(context.allocator, hello_frame);

    const hello_request_id = try requestIdFromFrame(context.allocator, hello_frame);
    defer context.allocator.free(hello_request_id);
    try sendWelcome(context.allocator, stream, hello_request_id);

    const request_id = try util.generateUlidAlloc(context.allocator);
    defer context.allocator.free(request_id);

    const display_path = request.label orelse blk: {
        const generated = try std.fmt.allocPrint(
            context.allocator,
            "{s} {s}",
            .{ util.accessClassLabel(request.access_class), request.path },
        );
        break :blk generated;
    };
    defer if (request.label == null) context.allocator.free(display_path);

    try sendDecide(context.allocator, stream, request_id, request, display_path);

    var user_interaction_deadline_ms: ?i64 = null;
    while (true) {
        const frame_timeout_ms = if (user_interaction_deadline_ms) |deadline_ms|
            timeoutUntilDeadlinePlusProtocolMs(deadline_ms, context.protocol_timeout_ms)
        else
            context.protocol_timeout_ms;
        const frame = try readFrameAlloc(context.allocator, stream, frame_timeout_ms);
        defer context.allocator.free(frame);

        const message_type = try frameTypeFromJson(context.allocator, frame);
        defer context.allocator.free(message_type);

        if (std.mem.eql(u8, message_type, "event")) {
            if (try userInteractionDeadlineMsFromEventFrame(context.allocator, frame, request_id)) |deadline_ms| {
                user_interaction_deadline_ms = deadline_ms;
            }
            continue;
        }
        if (std.mem.eql(u8, message_type, "decision")) {
            const response = try responseFromFrame(context.allocator, frame, request_id);
            try persistRememberedDecision(context, request, response);
            return response;
        }
        if (std.mem.eql(u8, message_type, "error")) {
            return .{ .decision = .unavailable };
        }
        return .{ .decision = .unavailable };
    }
}

pub fn timeoutUntilDeadlinePlusProtocolMs(deadline_ms: i64, protocol_timeout_ms: u32) u32 {
    const latest_response_ms = std.math.add(i64, deadline_ms, @intCast(protocol_timeout_ms)) catch std.math.maxInt(i64);
    const remaining_ms = latest_response_ms - runtime.milliTimestamp();
    if (remaining_ms <= 0) return 0;
    return @intCast(@min(remaining_ms, std.math.maxInt(u32)));
}

pub fn userInteractionDeadlineMsFromEventFrame(
    allocator: std.mem.Allocator,
    frame: []const u8,
    expected_request_id: []const u8,
) !?i64 {
    const parsed = try std.json.parseFromSlice(EventMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    if (!std.mem.eql(u8, parsed.value.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.type, "event")) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.request_id, expected_request_id)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.event, "user-interaction-started")) return null;

    const user_interaction = parsed.value.user_interaction orelse return error.InvalidProtocolMessage;
    const deadline_seconds = rfc3339.parseUtcSeconds(user_interaction.deadline) catch return error.InvalidProtocolMessage;
    return try std.math.mul(i64, deadline_seconds, 1_000);
}

fn userInteractionDeadlineFromNowAlloc(allocator: std.mem.Allocator, timeout_ms: u32) ![]u8 {
    const timeout_seconds = @divTrunc(@as(i64, @intCast(timeout_ms)) + 999, 1000);
    return try rfc3339.formatUtcAlloc(allocator, runtime.timestamp() + timeout_seconds);
}

pub fn handleConnection(context: *@import("core.zig").AgentServiceContext, stream: net.Stream) !void {
    const hello_request_id = try util.generateUlidAlloc(context.allocator);
    defer context.allocator.free(hello_request_id);
    try sendHello(context.allocator, stream, hello_request_id);

    const welcome_frame = try readFrameAlloc(context.allocator, stream, defaults.protocol_timeout_ms_default);
    defer context.allocator.free(welcome_frame);
    try validateWelcomeFrame(context.allocator, welcome_frame, hello_request_id);

    while (true) {
        const frame = readFrameAlloc(context.allocator, stream, defaults.protocol_timeout_ms_default) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };
        defer context.allocator.free(frame);

        const message_type = try frameTypeFromJson(context.allocator, frame);
        defer context.allocator.free(message_type);

        if (std.mem.eql(u8, message_type, "query")) {
            const request_id = try requestIdFromFrame(context.allocator, frame);
            defer context.allocator.free(request_id);
            try sendQueryResult(context.allocator, stream, request_id);
            continue;
        }

        if (std.mem.eql(u8, message_type, "decide")) {
            try handleDecideFrame(context, stream, frame);
            continue;
        }

        const request_id = try requestIdFromFrame(context.allocator, frame);
        defer context.allocator.free(request_id);
        try sendError(context.allocator, stream, request_id, "unsupported-message-type", "message type not supported");
    }
}

pub fn runConnectionWorker(worker_context: *ConnectionWorkerContext) void {
    defer cleanupConnectionWorker(worker_context);

    handleConnection(worker_context.service_context, worker_context.stream) catch |err| {
        std.log.warn("agent connection failed: {}", .{err});
    };
}

pub fn cleanupConnectionWorker(worker_context: *ConnectionWorkerContext) void {
    worker_context.stream.close(runtime.io());
    worker_context.allocator.destroy(worker_context);
}

pub fn sendHello(allocator: std.mem.Allocator, stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "hello",
        .request_id = request_id,
        .role = "agent",
        .agent_name = "file-snitch-agent",
        .agent_version = app_meta.version,
        .capabilities = &.{ "decide", "query" },
    });
}

pub fn sendWelcome(allocator: std.mem.Allocator, stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "welcome",
        .request_id = request_id,
        .role = "requester",
        .requester_name = "file-snitch-run",
        .requester_version = app_meta.version,
        .capabilities = &.{ "decide", "query" },
    });
}

pub fn sendQueryResult(allocator: std.mem.Allocator, stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "query_result",
        .request_id = request_id,
        .capabilities = &.{ "decide", "query" },
    });
}

pub fn sendUserInteractionStarted(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    request_id: []const u8,
    deadline_rfc3339: []const u8,
) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "event",
        .request_id = request_id,
        .event = "user-interaction-started",
        .user_interaction = .{
            .deadline = deadline_rfc3339,
        },
    });
}

pub fn sendDecide(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    request_id: []const u8,
    request: prompt.Request,
    display_path: []const u8,
) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "decide",
        .request_id = request_id,
        .subject = .{
            .uid = request.uid,
            .gid = request.gid,
            .pid = request.pid,
            .executable_path = request.executable_path,
        },
        .request = .{
            .enrolled_path = request.path,
            .approval_class = util.accessClassLabel(request.access_class),
            .operation = util.operationLabel(request.access_class),
            .mode = util.modeLabel(request.access_class),
        },
        .policy_context = .{
            .can_remember = request.can_remember,
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

pub fn sendDecision(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    request_id: []const u8,
    response: prompt.Response,
) !void {
    const expires_at = if (response.expires_at_unix_seconds) |unix_seconds|
        try rfc3339.formatUtcAlloc(allocator, unix_seconds)
    else
        null;
    defer if (expires_at) |value| allocator.free(value);

    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "decision",
        .request_id = request_id,
        .outcome = util.outcomeLabel(response.decision),
        .reason = util.decisionReason(response.decision),
        .remember = .{
            .kind = util.rememberKindLabel(response.remember_kind),
            .expires_at = expires_at,
        },
    });
}

pub fn sendError(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    request_id: []const u8,
    code: []const u8,
    message: []const u8,
) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "error",
        .request_id = request_id,
        .code = code,
        .message = message,
    });
}

pub fn decideFromFrame(allocator: std.mem.Allocator, frame: []const u8, frontend_impl: core.Frontend) !ResolvedDecision {
    const parsed = try std.json.parseFromSlice(DecideMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try validateDecideMessage(parsed.value);

    const request_id = try allocator.dupe(u8, parsed.value.request_id);
    errdefer allocator.free(request_id);

    return .{
        .request_id = request_id,
        .response = frontend_impl.resolve(try requestFromDecideMessage(parsed.value)),
    };
}

fn handleDecideFrame(context: *@import("core.zig").AgentServiceContext, stream: net.Stream, frame: []const u8) !void {
    const parsed = try std.json.parseFromSlice(DecideMessage, context.allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try validateDecideMessage(parsed.value);

    const request = try requestFromDecideMessage(parsed.value);

    const interaction_deadline = try userInteractionDeadlineFromNowAlloc(
        context.allocator,
        context.frontend.user_interaction_timeout_ms,
    );
    defer context.allocator.free(interaction_deadline);

    try sendUserInteractionStarted(context.allocator, stream, parsed.value.request_id, interaction_deadline);

    const response = context.frontend.resolve(request);
    sendDecision(context.allocator, stream, parsed.value.request_id, response) catch |err| {
        if (isPeerClosedError(err)) return;
        return err;
    };
}

fn requestFromDecideMessage(message: DecideMessage) !prompt.Request {
    return .{
        .path = message.request.enrolled_path,
        .access_class = try util.accessClassFromLabel(message.request.approval_class),
        .label = if (message.details) |details| details.display_path else null,
        .can_remember = message.policy_context.can_remember,
        .pid = message.subject.pid,
        .uid = message.subject.uid,
        .gid = message.subject.gid,
        .executable_path = message.subject.executable_path,
    };
}

fn validateDecideMessage(message: DecideMessage) !void {
    if (!std.mem.eql(u8, message.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, message.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, message.type, "decide")) return error.InvalidProtocolMessage;
}

pub fn validateHelloFrame(allocator: std.mem.Allocator, frame: []const u8) !void {
    const parsed = try std.json.parseFromSlice(Header, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.type, "hello")) return error.InvalidProtocolMessage;
}

pub fn validateWelcomeFrame(allocator: std.mem.Allocator, frame: []const u8, expected_request_id: []const u8) !void {
    const parsed = try std.json.parseFromSlice(Welcome, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.type, "welcome")) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.role, "requester")) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.request_id, expected_request_id)) return error.InvalidProtocolMessage;
}

pub fn requestIdFromFrame(allocator: std.mem.Allocator, frame: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(Header, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return allocator.dupe(u8, parsed.value.request_id orelse return error.InvalidProtocolMessage);
}

pub fn frameTypeFromJson(allocator: std.mem.Allocator, frame: []const u8) ![]u8 {
    const parsed = try std.json.parseFromSlice(Header, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    return allocator.dupe(u8, parsed.value.type);
}

pub fn sendJsonFrame(allocator: std.mem.Allocator, stream: net.Stream, value: anytype) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    try writeFrame(stream, output.written());
}

pub fn isPeerClosedError(err: anyerror) bool {
    return err == error.BrokenPipe or err == error.ConnectionResetByPeer or err == error.NotOpenForWriting;
}

pub fn writeFrame(stream: net.Stream, payload: []const u8) !void {
    var prefix_buffer: [32]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buffer, "{d}:", .{payload.len});
    try writeAllFd(stream.socket.handle, prefix);
    try writeAllFd(stream.socket.handle, payload);
    try writeAllFd(stream.socket.handle, "\n");
}

pub fn readFrameAlloc(allocator: std.mem.Allocator, stream: net.Stream, timeout_ms: ?u32) ![]u8 {
    const deadline_ms = deadlineFromTimeout(timeout_ms);
    var length_buffer: [max_length_digits]u8 = undefined;
    var length_len: usize = 0;

    while (true) {
        const next = try readByte(stream, remainingTimeoutMs(deadline_ms));
        if (next == ':') break;
        if (next < '0' or next > '9') return error.InvalidFrame;
        if (length_len >= max_length_digits) return error.InvalidFrame;
        length_buffer[length_len] = next;
        length_len += 1;
    }

    const payload_len = try parseFramePayloadLen(length_buffer[0..length_len]);
    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    try readExact(stream, payload, remainingTimeoutMs(deadline_ms));

    const trailing = try readByte(stream, remainingTimeoutMs(deadline_ms));
    if (trailing != '\n') return error.InvalidFrame;
    return payload;
}

fn deadlineFromTimeout(timeout_ms: ?u32) ?i64 {
    const timeout = timeout_ms orelse return null;
    return std.math.add(i64, runtime.milliTimestamp(), timeout) catch std.math.maxInt(i64);
}

fn remainingTimeoutMs(deadline_ms: ?i64) ?u32 {
    const deadline = deadline_ms orelse return null;
    const remaining = deadline - runtime.milliTimestamp();
    if (remaining <= 0) return 0;
    return @intCast(@min(remaining, std.math.maxInt(u32)));
}

pub fn parseFramePayloadLen(length_prefix: []const u8) !usize {
    if (length_prefix.len == 0) return error.InvalidFrame;
    if (length_prefix.len > 1 and length_prefix[0] == '0') return error.InvalidFrame;

    const payload_len = try std.fmt.parseInt(usize, length_prefix, 10);
    if (payload_len > max_frame_len) return error.InvalidFrame;
    return payload_len;
}

fn readExact(stream: net.Stream, buffer: []u8, timeout_ms: ?u32) !void {
    var offset: usize = 0;
    while (offset < buffer.len) {
        try waitReadable(stream.socket.handle, timeout_ms);
        const count = c.read(stream.socket.handle, buffer[offset..].ptr, buffer.len - offset);
        if (count < 0) return error.InputOutput;
        if (count == 0) return error.EndOfStream;
        offset += @intCast(count);
    }
}

fn writeAllFd(fd: std.posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = c.write(fd, bytes[offset..].ptr, bytes.len - offset);
        if (count < 0) return switch (std.c.errno(count)) {
            .PIPE => error.BrokenPipe,
            .CONNRESET => error.ConnectionResetByPeer,
            else => error.InputOutput,
        };
        if (count == 0) return error.EndOfStream;
        offset += @intCast(count);
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

pub fn responseFromFrame(allocator: std.mem.Allocator, frame: []const u8, expected_request_id: []const u8) !prompt.Response {
    const parsed = try std.json.parseFromSlice(DecisionMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.protocol, protocol_name)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.version, protocol_version)) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.type, "decision")) return error.InvalidProtocolMessage;
    if (!std.mem.eql(u8, parsed.value.request_id, expected_request_id)) return error.InvalidProtocolMessage;
    return .{
        .decision = util.outcomeFromLabel(parsed.value.outcome) catch .unavailable,
        .remember_kind = if (parsed.value.remember) |remember|
            util.rememberKindFromLabel(remember.kind) catch .none
        else
            .none,
        .expires_at_unix_seconds = if (parsed.value.remember) |remember|
            try util.parseRememberExpiration(remember.expires_at)
        else
            null,
    };
}

fn persistRememberedDecision(
    context: *@import("core.zig").RequesterContext,
    request: prompt.Request,
    response: prompt.Response,
) !void {
    switch (response.remember_kind) {
        .none, .once => return,
        .temporary, .durable => {},
    }

    const executable_path = request.executable_path orelse return;
    const expires_at = if (response.expires_at_unix_seconds) |unix_seconds|
        try rfc3339.formatUtcAlloc(context.allocator, unix_seconds)
    else
        null;
    defer if (expires_at) |value| context.allocator.free(value);

    var policy_lock = try config.acquirePolicyLock(context.allocator, context.policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(context.allocator, context.policy_path);
    defer loaded_policy.deinit();

    try loaded_policy.upsertDecision(
        executable_path,
        request.path,
        util.accessClassLabel(request.access_class),
        switch (response.decision) {
            .allow => "allow",
            .deny => "deny",
            else => return,
        },
        expires_at,
    );
    try loaded_policy.saveToFile();
}

pub fn readFrameFromReaderAlloc(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]u8 {
    var length_buffer: [max_length_digits]u8 = undefined;
    var length_len: usize = 0;
    while (true) {
        const next = try reader.takeByte();
        if (next == ':') break;
        if (next < '0' or next > '9') return error.InvalidFrame;
        if (length_len >= max_length_digits) return error.InvalidFrame;
        length_buffer[length_len] = next;
        length_len += 1;
    }
    const payload_len = try parseFramePayloadLen(length_buffer[0..length_len]);
    const payload = try allocator.alloc(u8, payload_len);
    errdefer allocator.free(payload);
    try reader.readSliceAll(payload);
    if (try reader.takeByte() != '\n') return error.InvalidFrame;
    return payload;
}
