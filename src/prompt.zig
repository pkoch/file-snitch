const std = @import("std");
const defaults = @import("defaults.zig");
const policy = @import("policy.zig");
const runtime = @import("runtime.zig");

pub const Request = struct {
    path: []const u8,
    access_class: policy.AccessClass,
    label: ?[]const u8 = null,
    can_remember: bool = false,
    pid: u32,
    executable_path: ?[]const u8 = null,
};

pub const Decision = enum(i32) {
    allow = 1,
    deny = 2,
    timeout = 3,
    unavailable = 4,
};

pub const RememberKind = enum {
    none,
    once,
    temporary,
    durable,
};

pub const Response = struct {
    decision: Decision,
    remember_kind: RememberKind = .none,
    expires_at_unix_seconds: ?i64 = null,
};

pub const Broker = struct {
    context: ?*anyopaque,
    resolve_fn: *const fn (?*anyopaque, Request) Response,

    pub fn resolve(self: Broker, request: Request) Response {
        return self.resolve_fn(self.context, request);
    }
};

pub const CliContext = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    stdin_file: std.Io.File = .stdin(),
    stderr_file: std.Io.File = .stderr(),
    mutex: std.Io.Mutex = .init,
    pending_input: [256]u8 = [_]u8{0} ** 256,
    pending_len: usize = 0,
};

pub const ScriptedContext = struct {
    decisions: []const Decision,
    next_index: usize = 0,

    pub fn init(decisions: []const Decision) ScriptedContext {
        return .{ .decisions = decisions };
    }
};

pub fn cliBroker(context: *CliContext) Broker {
    return .{
        .context = context,
        .resolve_fn = resolveCli,
    };
}

pub fn scriptedBroker(context: *ScriptedContext) Broker {
    return .{
        .context = context,
        .resolve_fn = resolveScripted,
    };
}

fn resolveCli(raw_context: ?*anyopaque, request: Request) Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const cli_context: *CliContext = @ptrCast(@alignCast(context));
    return resolveCliWithContext(cli_context, request);
}

pub fn resolveCliWithContext(context: *CliContext, request: Request) Response {
    context.mutex.lockUncancelable(runtime.io());
    defer context.mutex.unlock(runtime.io());

    const label = promptLabel(context.allocator, request) catch return .{ .decision = .unavailable };
    defer if (request.label == null) context.allocator.free(label);

    writePrompt(context, request, label) catch return .{ .decision = .unavailable };

    const response = readResponseWithTimeout(context, request.can_remember) catch |err| switch (err) {
        error.TimedOut => Response{ .decision = .timeout },
        error.EndOfStream => Response{ .decision = .allow, .remember_kind = .once },
        else => Response{ .decision = .unavailable },
    };
    finishPrompt(context, request, label, response) catch |err| {
        std.log.warn("failed to finish terminal prompt cleanly: {}", .{err});
    };
    return response;
}

fn resolveScripted(raw_context: ?*anyopaque, request: Request) Response {
    _ = request;
    const context = raw_context orelse return .{ .decision = .deny, .remember_kind = .once };
    const scripted_context: *ScriptedContext = @ptrCast(@alignCast(context));
    if (scripted_context.next_index >= scripted_context.decisions.len) {
        return .{ .decision = .deny, .remember_kind = .once };
    }

    const decision = scripted_context.decisions[scripted_context.next_index];
    scripted_context.next_index += 1;
    return .{ .decision = decision, .remember_kind = .once };
}

fn writePrompt(context: *CliContext, request: Request, label: []const u8) !void {
    try writePromptJson(context, request, label, null);

    if (context.stderr_file.isTty(runtime.io()) catch false) {
        const human = try std.fmt.allocPrint(
            context.allocator,
            "{s}Authorize:{s} {s}{s}{s}\n",
            .{ ansi_bold, ansi_reset, ansi_bold, label, ansi_reset },
        );
        defer context.allocator.free(human);
        try context.stderr_file.writeStreamingAll(runtime.io(), human);
    }

    const message = if (request.can_remember)
        try std.fmt.allocPrint(
            context.allocator,
            "allow? {s}[Y] once / [5] 5m / [a] always / [n] deny once / [d] always deny{s} ",
            .{ ansi_bold, ansi_reset },
        )
    else
        try std.fmt.allocPrint(
            context.allocator,
            "allow? {s}[Y/n]{s} ",
            .{ ansi_bold, ansi_reset },
        );
    defer context.allocator.free(message);

    try context.stderr_file.writeStreamingAll(runtime.io(), message);
}

fn finishPrompt(context: *CliContext, request: Request, label: []const u8, response: Response) !void {
    try context.stderr_file.writeStreamingAll(runtime.io(), "\n");
    if (context.stderr_file.isTty(runtime.io()) catch false) {
        const human = try std.fmt.allocPrint(
            context.allocator,
            "{s}Decision:{s} {s}{s}{s}{s} for {s}{s}{s}\n",
            .{
                ansi_bold,
                ansi_reset,
                ansi_bold,
                decisionLabel(response.decision),
                ansi_reset,
                rememberSuffix(response),
                ansi_bold,
                label,
                ansi_reset,
            },
        );
        defer context.allocator.free(human);
        try context.stderr_file.writeStreamingAll(runtime.io(), human);
    }
    try writePromptJson(context, request, label, response);
}

fn writePromptJson(
    context: *CliContext,
    request: Request,
    label: []const u8,
    response: ?Response,
) !void {
    var output: std.Io.Writer.Allocating = .init(context.allocator);
    defer output.deinit();

    try std.json.Stringify.value(.{
        .action = "prompt",
        .path = label,
        .request_path = request.path,
        .access_class = accessClassLabel(request.access_class),
        .can_remember = request.can_remember,
        .pid = request.pid,
        .executable_path = request.executable_path,
        .result = if (response) |value| @intFromEnum(value.decision) else null,
        .remember_kind = if (response) |value| @tagName(value.remember_kind) else null,
        .expires_at_unix_seconds = if (response) |value| value.expires_at_unix_seconds else null,
    }, .{}, &output.writer);
    try output.writer.writeByte('\n');
    try context.stderr_file.writeStreamingAll(runtime.io(), output.written());
}

fn promptLabel(allocator: std.mem.Allocator, request: Request) ![]const u8 {
    return request.label orelse std.fmt.allocPrint(
        allocator,
        "{s} {s}",
        .{ accessClassLabel(request.access_class), request.path },
    );
}

const ReadLineError = error{
    TimedOut,
    EndOfStream,
    InputOutput,
    SystemResources,
};

const ParsedInput = union(enum) {
    response: Response,
};

fn readResponseWithTimeout(context: *CliContext, can_remember: bool) ReadLineError!Response {
    while (true) {
        if (consumePendingResponse(context, can_remember)) |response| {
            return response;
        }

        if (context.pending_len == context.pending_input.len) {
            const response = parseResponse(context.pending_input[0..context.pending_len], can_remember);
            context.pending_len = 0;
            return response;
        }

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = context.stdin_file.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};

        const ready = std.posix.poll(&poll_fds, @intCast(context.timeout_ms)) catch |err| switch (err) {
            error.SystemResources => return error.SystemResources,
            else => return error.InputOutput,
        };

        if (ready == 0) {
            return error.TimedOut;
        }

        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) {
            return error.InputOutput;
        }

        if ((poll_fds[0].revents & std.posix.POLL.HUP) != 0 and (poll_fds[0].revents & std.posix.POLL.IN) == 0) {
            return if (context.pending_len == 0) error.EndOfStream else parseResponse(context.pending_input[0..context.pending_len], can_remember);
        }

        const read_count = context.stdin_file.readStreaming(runtime.io(), &.{context.pending_input[context.pending_len..]}) catch return error.InputOutput;
        if (read_count == 0) {
            return if (context.pending_len == 0) error.EndOfStream else parseResponse(context.pending_input[0..context.pending_len], can_remember);
        }

        context.pending_len += read_count;
    }
}

fn consumePendingResponse(context: *CliContext, can_remember: bool) ?Response {
    const newline_index = std.mem.indexOfAny(u8, context.pending_input[0..context.pending_len], "\r\n") orelse return null;
    const response = parseResponse(context.pending_input[0..newline_index], can_remember);
    const remaining_start = skipNewlines(context.pending_input[0..context.pending_len], newline_index);
    const remaining_len = context.pending_len - remaining_start;
    std.mem.copyForwards(u8, context.pending_input[0..remaining_len], context.pending_input[remaining_start..context.pending_len]);
    context.pending_len = remaining_len;
    return response;
}

fn skipNewlines(buffer: []const u8, start: usize) usize {
    var index = start;
    while (index < buffer.len and (buffer[index] == '\r' or buffer[index] == '\n')) : (index += 1) {}
    return index;
}

fn parseResponse(line: []const u8, can_remember: bool) Response {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) {
        return .{ .decision = .allow, .remember_kind = .once };
    }

    if (std.ascii.eqlIgnoreCase(trimmed, "y") or std.ascii.eqlIgnoreCase(trimmed, "yes")) {
        return .{ .decision = .allow, .remember_kind = .once };
    }

    if (std.ascii.eqlIgnoreCase(trimmed, "n") or std.ascii.eqlIgnoreCase(trimmed, "no")) {
        return .{ .decision = .deny, .remember_kind = .once };
    }

    if (can_remember) {
        if (std.mem.eql(u8, trimmed, "5")) {
            return .{
                .decision = .allow,
                .remember_kind = .temporary,
                .expires_at_unix_seconds = runtime.timestamp() + defaults.remember_temporary_seconds,
            };
        }
        if (std.ascii.eqlIgnoreCase(trimmed, "a") or std.ascii.eqlIgnoreCase(trimmed, "always")) {
            return .{ .decision = .allow, .remember_kind = .durable };
        }
        if (std.ascii.eqlIgnoreCase(trimmed, "d") or std.ascii.eqlIgnoreCase(trimmed, "never")) {
            return .{ .decision = .deny, .remember_kind = .durable };
        }
    }

    return .{ .decision = .deny, .remember_kind = .once };
}

fn makePipe() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (std.c.pipe(&fds) != 0) {
        return error.SystemResources;
    }
    return fds;
}

fn closeFd(fd: std.posix.fd_t) void {
    var file = std.Io.File{ .handle = fd, .flags = .{ .nonblocking = false } };
    file.close(runtime.io());
}

fn accessClassLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read",
        .create => "create",
        .write => "write",
        .rename => "rename",
        .delete => "delete",
        .metadata => "metadata",
        .xattr => "xattr",
    };
}

fn decisionLabel(decision: Decision) []const u8 {
    return switch (decision) {
        .allow => "ALLOW",
        .deny => "DENY",
        .timeout => "TIMEOUT",
        .unavailable => "UNAVAILABLE",
    };
}

fn rememberSuffix(response: Response) []const u8 {
    return switch (response.remember_kind) {
        .none, .once => "",
        .temporary => " (5 min)",
        .durable => switch (response.decision) {
            .allow => " (always)",
            .deny => " (always)",
            else => "",
        },
    };
}

const ansi_bold = "\x1b[1m";
const ansi_reset = "\x1b[0m";

test "scripted broker returns configured decisions in order" {
    var context = ScriptedContext.init(&.{ .allow, .deny });
    const broker = scriptedBroker(&context);
    const request: Request = .{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 1,
    };

    try std.testing.expectEqual(Decision.allow, broker.resolve(request).decision);
    try std.testing.expectEqual(Decision.deny, broker.resolve(request).decision);
    try std.testing.expectEqual(Decision.deny, broker.resolve(request).decision);
}

test "cli broker allows yes" {
    const fds = try makePipe();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const stderr_fds = try makePipe();
    defer closeFd(stderr_fds[0]);
    defer closeFd(stderr_fds[1]);

    const writer = std.Io.File{ .handle = fds[1], .flags = .{ .nonblocking = false } };
    try writer.writeStreamingAll(runtime.io(), "yes\n");

    var context = CliContext{
        .allocator = std.testing.allocator,
        .timeout_ms = 50,
        .stdin_file = .{ .handle = fds[0], .flags = .{ .nonblocking = false } },
        .stderr_file = .{ .handle = stderr_fds[1], .flags = .{ .nonblocking = false } },
    };
    const broker = cliBroker(&context);

    const decision = broker.resolve(.{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 10,
    });

    try std.testing.expectEqual(Decision.allow, decision.decision);
    try std.testing.expectEqual(RememberKind.once, decision.remember_kind);
}

test "cli broker allows empty response by default" {
    const fds = try makePipe();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const stderr_fds = try makePipe();
    defer closeFd(stderr_fds[0]);
    defer closeFd(stderr_fds[1]);

    const writer = std.Io.File{ .handle = fds[1], .flags = .{ .nonblocking = false } };
    try writer.writeStreamingAll(runtime.io(), "\n");

    var context = CliContext{
        .allocator = std.testing.allocator,
        .timeout_ms = 50,
        .stdin_file = .{ .handle = fds[0], .flags = .{ .nonblocking = false } },
        .stderr_file = .{ .handle = stderr_fds[1], .flags = .{ .nonblocking = false } },
    };
    const broker = cliBroker(&context);

    const decision = broker.resolve(.{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 10,
    });

    try std.testing.expectEqual(Decision.allow, decision.decision);
    try std.testing.expectEqual(RememberKind.once, decision.remember_kind);
}

test "cli broker times out to deny path" {
    const fds = try makePipe();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const stderr_fds = try makePipe();
    defer closeFd(stderr_fds[0]);
    defer closeFd(stderr_fds[1]);

    var context = CliContext{
        .allocator = std.testing.allocator,
        .timeout_ms = 10,
        .stdin_file = .{ .handle = fds[0], .flags = .{ .nonblocking = false } },
        .stderr_file = .{ .handle = stderr_fds[1], .flags = .{ .nonblocking = false } },
    };
    const broker = cliBroker(&context);

    const decision = broker.resolve(.{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 10,
    });

    try std.testing.expectEqual(Decision.timeout, decision.decision);
}

test "cli broker can request remembered allow" {
    const fds = try makePipe();
    defer closeFd(fds[0]);
    defer closeFd(fds[1]);

    const stderr_fds = try makePipe();
    defer closeFd(stderr_fds[0]);
    defer closeFd(stderr_fds[1]);

    const writer = std.Io.File{ .handle = fds[1], .flags = .{ .nonblocking = false } };
    try writer.writeStreamingAll(runtime.io(), "a\n");

    var context = CliContext{
        .allocator = std.testing.allocator,
        .timeout_ms = 50,
        .stdin_file = .{ .handle = fds[0], .flags = .{ .nonblocking = false } },
        .stderr_file = .{ .handle = stderr_fds[1], .flags = .{ .nonblocking = false } },
    };
    const broker = cliBroker(&context);

    const decision = broker.resolve(.{
        .path = "/prompted.txt",
        .access_class = .read,
        .can_remember = true,
        .pid = 10,
        .executable_path = "/usr/bin/cat",
    });

    try std.testing.expectEqual(Decision.allow, decision.decision);
    try std.testing.expectEqual(RememberKind.durable, decision.remember_kind);
}
