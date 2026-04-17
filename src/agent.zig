const std = @import("std");
const net = std.net;
const app_meta = @import("app_meta.zig");
const config = @import("config.zig");
const defaults = @import("defaults.zig");
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
    policy_path: []const u8,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
};

pub const FrontendKind = enum {
    terminal_pinentry,
    macos_ui,
    linux_ui,
};

pub const Frontend = struct {
    context: ?*anyopaque,
    resolve_fn: *const fn (?*anyopaque, prompt.Request) prompt.Response,
    supports_concurrent_requests: bool = true,

    pub fn resolve(self: Frontend, request: prompt.Request) prompt.Response {
        return self.resolve_fn(self.context, request);
    }
};

pub const TerminalPinentryContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    tty_path: ?[]const u8 = null,
    inherited_cli_context: ?*prompt.CliContext = null,
    mutex: std.Thread.Mutex = .{},
};

pub const MacosUiContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    osascript_path: []const u8,
};

pub const LinuxUiContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    zenity_path: []const u8,
};

pub const AgentServiceContext = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    frontend: Frontend,
};

pub const SocketPathError = error{
    SocketPathInUse,
    InvalidSocketPath,
};

const ConnectionWorkerContext = struct {
    allocator: std.mem.Allocator,
    service_context: *AgentServiceContext,
    stream: net.Stream,
};

pub fn defaultSocketPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, defaults.agent_socket_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    const base = try defaults.xdgBasePathAlloc(allocator, "XDG_RUNTIME_DIR", ".local/state");
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, "file-snitch", "agent.sock" });
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
        .supports_concurrent_requests = true,
    };
}

pub fn macosUiFrontend(context: *MacosUiContext) Frontend {
    return .{
        .context = context,
        .resolve_fn = resolveMacosUi,
        .supports_concurrent_requests = false,
    };
}

pub fn linuxUiFrontend(context: *LinuxUiContext) Frontend {
    return .{
        .context = context,
        .resolve_fn = resolveLinuxUi,
        .supports_concurrent_requests = false,
    };
}

pub fn defaultTerminalPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, defaults.agent_tty_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return terminalPathFromStandardFilesAlloc(allocator) catch
        error.NotATerminal;
}

pub fn defaultOsascriptPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, defaults.osascript_bin_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return allocator.dupe(u8, "osascript");
}

pub fn defaultZenityPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, defaults.zenity_bin_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return allocator.dupe(u8, "zenity");
}

pub fn runAgentService(context: *AgentServiceContext) !void {
    try ensureParentDirectory(context.socket_path);
    try removeSocketFileIfStale(context.socket_path);

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
        var stream: net.Stream = .{ .handle = accepted };
        if (!context.frontend.supports_concurrent_requests) {
            // GUI frontends shell out to helper processes. On Linux, doing that
            // from a worker thread would fork a multithreaded process.
            defer stream.close();
            handleConnection(context, stream) catch |err| {
                std.log.warn("agent connection failed: {}", .{err});
            };
            continue;
        }

        const worker_context = try context.allocator.create(ConnectionWorkerContext);
        errdefer context.allocator.destroy(worker_context);
        worker_context.* = .{
            .allocator = context.allocator,
            .service_context = context,
            .stream = stream,
        };

        const thread = try std.Thread.spawn(.{}, runConnectionWorker, .{worker_context});
        thread.detach();
    }
}

fn runConnectionWorker(worker_context: *ConnectionWorkerContext) void {
    defer cleanupConnectionWorker(worker_context);

    handleConnection(worker_context.service_context, worker_context.stream) catch |err| {
        std.log.warn("agent connection failed: {}", .{err});
    };
}

fn cleanupConnectionWorker(worker_context: *ConnectionWorkerContext) void {
    worker_context.stream.close();
    worker_context.allocator.destroy(worker_context);
}

fn resolveSocket(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const requester_context: *RequesterContext = @ptrCast(@alignCast(context));
    return resolveViaAgent(requester_context, request) catch |err| switch (err) {
        error.TimedOut => .{ .decision = .timeout },
        else => .{ .decision = .unavailable },
    };
}

fn resolveViaAgent(context: *RequesterContext, request: prompt.Request) !prompt.Response {
    var stream = try net.connectUnixSocket(context.socket_path);
    defer stream.close();

    const hello_frame = try readFrameAlloc(context.allocator, stream, context.timeout_ms);
    defer context.allocator.free(hello_frame);

    try validateHelloFrame(context.allocator, hello_frame);

    const hello_request_id = try requestIdFromFrame(context.allocator, hello_frame);
    defer context.allocator.free(hello_request_id);
    try sendWelcome(context.allocator, stream, hello_request_id);

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

    try sendDecide(context.allocator, stream, request_id, request, display_path, timeout_at_rfc3339);

    while (true) {
        const frame = try readFrameAlloc(context.allocator, stream, context.timeout_ms);
        defer context.allocator.free(frame);

        const message_type = try frameTypeFromJson(context.allocator, frame);
        defer context.allocator.free(message_type);

        if (std.mem.eql(u8, message_type, "event")) continue;
        if (std.mem.eql(u8, message_type, "decision")) {
            const response = try responseFromFrame(context.allocator, frame);
            try persistRememberedDecision(context, request, response);
            return response;
        }
        if (std.mem.eql(u8, message_type, "error")) {
            return .{ .decision = .unavailable };
        }
        return .{ .decision = .unavailable };
    }
}

fn handleConnection(context: *AgentServiceContext, stream: net.Stream) !void {
    const hello_request_id = try generateUlidAlloc(context.allocator);
    defer context.allocator.free(hello_request_id);
    try sendHello(context.allocator, stream, hello_request_id);

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
            try sendQueryResult(context.allocator, stream, request_id);
            continue;
        }

        if (std.mem.eql(u8, message_type, "decide")) {
            const decision = try decideFromFrame(context.allocator, frame, context.frontend);
            defer context.allocator.free(decision.request_id);
            sendDecision(context.allocator, stream, decision.request_id, decision.response) catch |err| {
                if (isPeerClosedError(err)) return;
                return err;
            };
            continue;
        }

        const request_id = try requestIdFromFrame(context.allocator, frame);
        defer context.allocator.free(request_id);
        try sendError(context.allocator, stream, request_id, "unsupported-message-type", "message type not supported");
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
    remember: ?struct {
        kind: []const u8,
        expires_at: ?[]const u8 = null,
    } = null,
};

const ResolvedDecision = struct {
    request_id: []const u8,
    response: prompt.Response,
};

fn sendHello(allocator: std.mem.Allocator, stream: net.Stream, request_id: []const u8) !void {
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

fn sendWelcome(allocator: std.mem.Allocator, stream: net.Stream, request_id: []const u8) !void {
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

fn sendQueryResult(allocator: std.mem.Allocator, stream: net.Stream, request_id: []const u8) !void {
    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "query_result",
        .request_id = request_id,
        .capabilities = &.{ "decide", "query" },
    });
}

fn sendDecide(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    request_id: []const u8,
    request: prompt.Request,
    display_path: []const u8,
    timeout_at_rfc3339: []const u8,
) !void {
    try sendJsonFrame(allocator, stream, .{
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
            .can_remember = request.executable_path != null,
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

fn sendDecision(
    allocator: std.mem.Allocator,
    stream: net.Stream,
    request_id: []const u8,
    response: prompt.Response,
) !void {
    const expires_at = if (response.expires_at_unix_seconds) |unix_seconds|
        try formatRfc3339UtcAlloc(allocator, unix_seconds)
    else
        null;
    defer if (expires_at) |value| allocator.free(value);

    try sendJsonFrame(allocator, stream, .{
        .protocol = protocol_name,
        .version = protocol_version,
        .type = "decision",
        .request_id = request_id,
        .outcome = outcomeLabel(response.decision),
        .reason = decisionReason(response.decision),
        .remember = .{
            .kind = rememberKindLabel(response.remember_kind),
            .expires_at = expires_at,
        },
    });
}

fn sendError(
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

fn decideFromFrame(allocator: std.mem.Allocator, frame: []const u8, frontend: Frontend) !ResolvedDecision {
    const parsed = try std.json.parseFromSlice(DecideMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const request: prompt.Request = .{
        .path = parsed.value.request.enrolled_path,
        .access_class = try accessClassFromLabel(parsed.value.request.approval_class),
        .label = if (parsed.value.details) |details| details.display_path else null,
        .can_remember = parsed.value.policy_context.can_remember,
        .pid = parsed.value.subject.pid,
        .uid = parsed.value.subject.uid,
        .gid = 0,
        .executable_path = parsed.value.subject.executable_path,
    };

    const request_id = try allocator.dupe(u8, parsed.value.request_id);
    errdefer allocator.free(request_id);

    return .{
        .request_id = request_id,
        .response = frontend.resolve(request),
    };
}

fn resolveTerminalPinentry(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const pinentry_context: *TerminalPinentryContext = @ptrCast(@alignCast(context));
    pinentry_context.mutex.lock();
    defer pinentry_context.mutex.unlock();

    if (pinentry_context.inherited_cli_context) |cli_context| {
        return prompt.resolveCliWithContext(cli_context, request);
    }

    const tty_path = pinentry_context.tty_path orelse return .{ .decision = .unavailable };
    var tty_file = std.fs.openFileAbsolute(tty_path, .{ .mode = .read_write }) catch return .{ .decision = .unavailable };
    defer tty_file.close();

    var cli_context = prompt.CliContext{
        .allocator = pinentry_context.allocator,
        .timeout_ms = pinentry_context.timeout_ms,
        .stdin_file = tty_file,
        .stderr_file = tty_file,
    };
    return prompt.resolveCliWithContext(&cli_context, request);
}

fn resolveMacosUi(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const ui_context: *MacosUiContext = @ptrCast(@alignCast(context));

    const script = buildMacosDialogScriptAlloc(ui_context.allocator, request, ui_context.timeout_ms) catch
        return .{ .decision = .unavailable };
    defer ui_context.allocator.free(script);

    const argv = [_][]const u8{
        ui_context.osascript_path,
        "-e",
        script,
    };
    const result = std.process.Child.run(.{
        .allocator = ui_context.allocator,
        .argv = &argv,
    }) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(result.stdout);
    defer ui_context.allocator.free(result.stderr);

    if (result.term.Exited != 0) return .{ .decision = .unavailable };
    return parseMacosUiResponse(result.stdout) catch .{ .decision = .unavailable };
}

fn resolveLinuxUi(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const ui_context: *LinuxUiContext = @ptrCast(@alignCast(context));

    const prompt_text = buildDialogPromptAlloc(ui_context.allocator, request) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(prompt_text);

    const timeout_seconds = @max(@divTrunc(@as(i64, @intCast(ui_context.timeout_ms)) + 999, 1000), 1);
    const timeout_text = std.fmt.allocPrint(ui_context.allocator, "{d}", .{timeout_seconds}) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(timeout_text);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(ui_context.allocator);
    argv.appendSlice(ui_context.allocator, &.{
        ui_context.zenity_path,
        "--list",
        "--radiolist",
        "--title=File Snitch",
        "--text",
        prompt_text,
        "--column=Pick",
        "--column=Decision",
        "TRUE",
        "Allow once",
        "FALSE",
        "Deny once",
    }) catch return .{ .decision = .unavailable };
    if (request.can_remember) {
        argv.appendSlice(ui_context.allocator, &.{
            "FALSE",
            "Allow 5 min",
            "FALSE",
            "Always allow",
            "FALSE",
            "Always deny",
        }) catch return .{ .decision = .unavailable };
    }
    argv.appendSlice(ui_context.allocator, &.{
        "--timeout",
        timeout_text,
        "--width=520",
    }) catch return .{ .decision = .unavailable };

    const result = std.process.Child.run(.{
        .allocator = ui_context.allocator,
        .argv = argv.items,
    }) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(result.stdout);
    defer ui_context.allocator.free(result.stderr);

    return parseLinuxUiResponse(result.term, result.stdout) catch .{ .decision = .unavailable };
}

fn buildMacosDialogScriptAlloc(allocator: std.mem.Allocator, request: prompt.Request, timeout_ms: u32) ![]u8 {
    const title = "File Snitch";
    const prompt_text = try buildDialogPromptAlloc(allocator, request);
    defer allocator.free(prompt_text);

    const escaped_title = try appleScriptStringLiteralContentsAlloc(allocator, title);
    defer allocator.free(escaped_title);
    const escaped_prompt = try appleScriptStringLiteralContentsAlloc(allocator, prompt_text);
    defer allocator.free(escaped_prompt);

    const timeout_seconds = @max(@divTrunc(@as(i64, @intCast(timeout_ms)) + 999, 1000), 1);
    if (!request.can_remember) {
        return std.fmt.allocPrint(
            allocator,
            \\try
            \\  set prompt_text to "{s}"
            \\  set decision to display dialog prompt_text with title "{s}" buttons {{"Deny", "Allow"}} default button "Allow" giving up after {d} with icon caution
            \\  if gave up of decision then
            \\    return "timeout"
            \\  end if
            \\  if button returned of decision is "Allow" then
            \\    return "allow"
            \\  end if
            \\  return "deny"
            \\on error number -128
            \\  return "deny"
            \\end try
        ,
            .{ escaped_prompt, escaped_title, timeout_seconds },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        \\try
        \\  set prompt_text to "{s}"
        \\  set choices to {{"Allow once", "Deny once", "Allow 5 min", "Always allow", "Always deny"}}
        \\  set selected to choose from list choices with title "{s}" with prompt prompt_text default items {{"Allow once"}} OK button name "Select" cancel button name "Deny once" giving up after {d}
        \\  if selected is false then
        \\    return "deny"
        \\  end if
        \\  set answer to item 1 of selected
        \\  if answer is "Allow once" then return "allow"
        \\  if answer is "Deny once" then return "deny"
        \\  if answer is "Allow 5 min" then return "allow-5m"
        \\  if answer is "Always allow" then return "always-allow"
        \\  if answer is "Always deny" then return "always-deny"
        \\  return "deny"
        \\on error number -128
        \\  return "deny"
        \\end try
    ,
        .{ escaped_prompt, escaped_title, timeout_seconds },
    );
}

fn buildDialogPromptAlloc(allocator: std.mem.Allocator, request: prompt.Request) ![]u8 {
    const label = request.label orelse blk: {
        const generated = try std.fmt.allocPrint(
            allocator,
            "{s} {s}",
            .{ accessClassLabel(request.access_class), request.path },
        );
        break :blk generated;
    };
    defer if (request.label == null) allocator.free(label);

    const executable_path = request.executable_path orelse "unknown executable";
    return std.fmt.allocPrint(
        allocator,
        "{s}\n\nProcess: {s}\nPID: {d}\nUID: {d}",
        .{ label, executable_path, request.pid, request.uid },
    );
}

fn appleScriptStringLiteralContentsAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    for (raw) |byte| switch (byte) {
        '"' => try output.appendSlice(allocator, "\\\""),
        '\\' => try output.appendSlice(allocator, "\\\\"),
        '\n' => try output.appendSlice(allocator, "\\n"),
        '\r' => {},
        else => try output.append(allocator, byte),
    };

    return output.toOwnedSlice(allocator);
}

fn parseMacosUiResponse(raw_output: []const u8) !prompt.Response {
    const trimmed = std.mem.trim(u8, raw_output, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "allow")) return .{ .decision = .allow, .remember_kind = .once };
    if (std.mem.eql(u8, trimmed, "deny")) return .{ .decision = .deny, .remember_kind = .once };
    if (std.mem.eql(u8, trimmed, "timeout")) return .{ .decision = .timeout };
    if (std.mem.eql(u8, trimmed, "allow-5m")) return .{
        .decision = .allow,
        .remember_kind = .temporary,
        .expires_at_unix_seconds = std.time.timestamp() + defaults.remember_temporary_seconds,
    };
    if (std.mem.eql(u8, trimmed, "always-allow")) return .{ .decision = .allow, .remember_kind = .durable };
    if (std.mem.eql(u8, trimmed, "always-deny")) return .{ .decision = .deny, .remember_kind = .durable };
    return error.InvalidProtocolMessage;
}

fn parseLinuxUiResponse(term: std.process.Child.Term, raw_output: []const u8) !prompt.Response {
    return switch (term) {
        .Exited => |code| switch (code) {
            0 => parseLinuxUiSelection(raw_output),
            1 => .{ .decision = .deny, .remember_kind = .once },
            5 => .{ .decision = .timeout },
            else => error.InvalidProtocolMessage,
        },
        else => error.InvalidProtocolMessage,
    };
}

fn parseLinuxUiSelection(raw_output: []const u8) !prompt.Response {
    const trimmed = std.mem.trim(u8, raw_output, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "Allow once") or std.mem.eql(u8, trimmed, "allow")) {
        return .{ .decision = .allow, .remember_kind = .once };
    }
    if (std.mem.eql(u8, trimmed, "Deny once") or std.mem.eql(u8, trimmed, "deny")) {
        return .{ .decision = .deny, .remember_kind = .once };
    }
    if (std.mem.eql(u8, trimmed, "Allow 5 min") or std.mem.eql(u8, trimmed, "allow-5m")) return .{
        .decision = .allow,
        .remember_kind = .temporary,
        .expires_at_unix_seconds = std.time.timestamp() + defaults.remember_temporary_seconds,
    };
    if (std.mem.eql(u8, trimmed, "Always allow") or std.mem.eql(u8, trimmed, "always-allow")) {
        return .{ .decision = .allow, .remember_kind = .durable };
    }
    if (std.mem.eql(u8, trimmed, "Always deny") or std.mem.eql(u8, trimmed, "always-deny")) {
        return .{ .decision = .deny, .remember_kind = .durable };
    }
    return error.InvalidProtocolMessage;
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

fn responseFromFrame(allocator: std.mem.Allocator, frame: []const u8) !prompt.Response {
    const parsed = try std.json.parseFromSlice(DecisionMessage, allocator, frame, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    _ = parsed.value.request_id;
    return .{
        .decision = switch (parsed.value.outcome[0]) {
            'a' => .allow,
            'd' => .deny,
            't' => .timeout,
            'u' => .unavailable,
            'c' => .deny,
            else => .unavailable,
        },
        .remember_kind = if (parsed.value.remember) |remember|
            rememberKindFromLabel(remember.kind) catch .none
        else
            .none,
        .expires_at_unix_seconds = if (parsed.value.remember) |remember|
            try parseRememberExpiration(remember.expires_at)
        else
            null,
    };
}

fn persistRememberedDecision(
    context: *RequesterContext,
    request: prompt.Request,
    response: prompt.Response,
) !void {
    switch (response.remember_kind) {
        .none, .once => return,
        .temporary, .durable => {},
    }

    const executable_path = request.executable_path orelse return;
    const expires_at = if (response.expires_at_unix_seconds) |unix_seconds|
        try formatRfc3339UtcAlloc(context.allocator, unix_seconds)
    else
        null;
    defer if (expires_at) |value| context.allocator.free(value);

    var policy_lock = try config.acquirePolicyLock(context.allocator, context.policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(context.allocator, context.policy_path);
    defer loaded_policy.deinit();

    try loaded_policy.upsertDecision(
        executable_path,
        request.uid,
        request.path,
        accessClassLabel(request.access_class),
        switch (response.decision) {
            .allow => "allow",
            .deny => "deny",
            else => return,
        },
        expires_at,
    );
    try loaded_policy.saveToFile();
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

fn sendJsonFrame(allocator: std.mem.Allocator, stream: net.Stream, value: anytype) !void {
    var output: std.io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try std.json.Stringify.value(value, .{}, &output.writer);
    try writeFrame(stream, output.written());
}

fn isPeerClosedError(err: anyerror) bool {
    return err == error.BrokenPipe or err == error.ConnectionResetByPeer or err == error.NotOpenForWriting;
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

fn removeSocketFileIfStale(path: []const u8) !void {
    const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .unix_domain_socket) return error.InvalidSocketPath;

    var stream = net.connectUnixSocket(path) catch |err| switch (err) {
        error.FileNotFound => return,
        error.ConnectionRefused, error.ConnectionResetByPeer => {
            try removeStaleSocketFile(path);
            return;
        },
        error.AddressInUse,
        error.AccessDenied,
        error.PermissionDenied,
        error.ConnectionTimedOut,
        error.WouldBlock,
        error.NetworkUnreachable,
        error.AddressNotAvailable,
        error.AddressFamilyNotSupported,
        error.SystemResources,
        error.ConnectionPending,
        => return error.SocketPathInUse,
        else => return err,
    };
    stream.close();
    return error.SocketPathInUse;
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

fn rememberKindLabel(kind: prompt.RememberKind) []const u8 {
    return switch (kind) {
        .none => "none",
        .once => "once",
        .temporary => "temporary",
        .durable => "durable",
    };
}

fn rememberKindFromLabel(label: []const u8) !prompt.RememberKind {
    if (std.mem.eql(u8, label, "none")) return .none;
    if (std.mem.eql(u8, label, "once")) return .once;
    if (std.mem.eql(u8, label, "temporary")) return .temporary;
    if (std.mem.eql(u8, label, "durable")) return .durable;
    return error.InvalidProtocolMessage;
}

fn decisionReason(decision: prompt.Decision) []const u8 {
    return switch (decision) {
        .allow => "user-approved",
        .deny => "user-denied",
        .timeout => "agent-timeout",
        .unavailable => "agent-unavailable",
    };
}

fn parseRememberExpiration(value: ?[]const u8) !?i64 {
    const raw = value orelse return null;
    return try parseRfc3339Utc(raw);
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

fn parseRfc3339Utc(raw: []const u8) !i64 {
    if (raw.len != "2006-01-02T15:04:05Z".len) return error.InvalidProtocolMessage;
    if (raw[4] != '-' or raw[7] != '-' or raw[10] != 'T' or raw[13] != ':' or raw[16] != ':' or raw[19] != 'Z') {
        return error.InvalidProtocolMessage;
    }

    const year = try std.fmt.parseInt(i64, raw[0..4], 10);
    const month = try std.fmt.parseInt(u8, raw[5..7], 10);
    const day = try std.fmt.parseInt(u8, raw[8..10], 10);
    const hour = try std.fmt.parseInt(i64, raw[11..13], 10);
    const minute = try std.fmt.parseInt(i64, raw[14..16], 10);
    const second = try std.fmt.parseInt(i64, raw[17..19], 10);

    if (month < 1 or month > 12) return error.InvalidProtocolMessage;
    if (day < 1 or day > daysInMonth(year, month)) return error.InvalidProtocolMessage;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidProtocolMessage;

    const days = try daysSinceUnixEpoch(year, month, day);
    const day_seconds = hour * 3600 + minute * 60 + second;
    return try std.math.add(i64, days * 86400, day_seconds);
}

fn daysSinceUnixEpoch(year: i64, month: u8, day: u8) !i64 {
    var adjusted_year = year;
    if (month <= 2) adjusted_year -= 1;

    const era = @divFloor(if (adjusted_year >= 0) adjusted_year else adjusted_year - 399, 400);
    const year_of_era = adjusted_year - era * 400;
    const adjusted_month: i64 = if (month > 2) month - 3 else month + 9;
    const day_of_year = @divFloor(153 * adjusted_month + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return try std.math.sub(i64, era * 146097 + day_of_era, 719468);
}

fn daysInMonth(year: i64, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i64) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
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
    const key = defaults.agent_tty_env;
    const value = "/tmp/file-snitch-agent-test-tty";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key, value, 1));
    defer _ = c.unsetenv(key);

    const resolved = try defaultTerminalPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}

test "default osascript path uses FILE_SNITCH_OSASCRIPT_BIN override" {
    const allocator = std.testing.allocator;
    const key = defaults.osascript_bin_env;
    const value = "/tmp/file-snitch-test-osascript";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key, value, 1));
    defer _ = c.unsetenv(key);

    const resolved = try defaultOsascriptPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}

test "default zenity path uses FILE_SNITCH_ZENITY_BIN override" {
    const allocator = std.testing.allocator;
    const key = defaults.zenity_bin_env;
    const value = "/tmp/file-snitch-test-zenity";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key, value, 1));
    defer _ = c.unsetenv(key);

    const resolved = try defaultZenityPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}

test "gui frontends serialize requests" {
    const allocator = std.testing.allocator;

    var terminal_context = TerminalPinentryContext{
        .allocator = allocator,
    };
    try std.testing.expect(terminalPinentryFrontend(&terminal_context).supports_concurrent_requests);

    var macos_context = MacosUiContext{
        .allocator = allocator,
        .osascript_path = "osascript",
    };
    try std.testing.expect(!macosUiFrontend(&macos_context).supports_concurrent_requests);

    var linux_context = LinuxUiContext{
        .allocator = allocator,
        .zenity_path = "zenity",
    };
    try std.testing.expect(!linuxUiFrontend(&linux_context).supports_concurrent_requests);
}

test "parse macos ui response accepts known values" {
    try std.testing.expectEqual(prompt.Decision.allow, (try parseMacosUiResponse("allow\n")).decision);
    try std.testing.expectEqual(prompt.RememberKind.once, (try parseMacosUiResponse("allow\n")).remember_kind);
    try std.testing.expectEqual(prompt.Decision.deny, (try parseMacosUiResponse("deny\r\n")).decision);
    try std.testing.expectEqual(prompt.Decision.timeout, (try parseMacosUiResponse("timeout")).decision);
    const remembered = try parseMacosUiResponse("always-allow");
    try std.testing.expectEqual(prompt.Decision.allow, remembered.decision);
    try std.testing.expectEqual(prompt.RememberKind.durable, remembered.remember_kind);
}

test "parse linux ui response accepts known exit codes" {
    try std.testing.expectEqual(prompt.Decision.allow, (try parseLinuxUiResponse(.{ .Exited = 0 }, "Allow once")).decision);
    try std.testing.expectEqual(prompt.Decision.deny, (try parseLinuxUiResponse(.{ .Exited = 1 }, "")).decision);
    try std.testing.expectEqual(prompt.Decision.timeout, (try parseLinuxUiResponse(.{ .Exited = 5 }, "")).decision);
    const remembered = try parseLinuxUiResponse(.{ .Exited = 0 }, "Always deny");
    try std.testing.expectEqual(prompt.Decision.deny, remembered.decision);
    try std.testing.expectEqual(prompt.RememberKind.durable, remembered.remember_kind);
}

test "stale socket cleanup rejects regular files" {
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-regular-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(path);
    defer std.fs.cwd().deleteFile(path) catch {};

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    file.close();

    try std.testing.expectError(error.InvalidSocketPath, removeSocketFileIfStale(path));
}

test "stale socket cleanup preserves live sockets" {
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-socket-{d}.sock", .{std.time.nanoTimestamp()});
    defer allocator.free(path);
    defer std.fs.cwd().deleteFile(path) catch {};

    const address = try net.Address.initUnix(path);
    const listener = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(listener);
    try std.posix.bind(listener, &address.any, address.getOsSockLen());
    try std.posix.listen(listener, 1);

    try std.testing.expectError(error.SocketPathInUse, removeSocketFileIfStale(path));
    _ = try std.fs.cwd().statFile(path);
}

const BlockingFrontendContext = struct {
    first_started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release_first: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    call_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

fn resolveBlockingFrontend(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    _ = request;
    const context = raw_context orelse return .{ .decision = .unavailable };
    const blocking_context: *BlockingFrontendContext = @ptrCast(@alignCast(context));
    const call_index = blocking_context.call_count.fetchAdd(1, .acq_rel);
    if (call_index == 0) {
        blocking_context.first_started.store(true, .release);
        while (!blocking_context.release_first.load(.acquire)) {
            std.Thread.sleep(5 * std.time.ns_per_ms);
        }
    }
    return .{ .decision = .allow, .remember_kind = .once };
}

fn runRequesterThread(done: *std.atomic.Value(bool), context: *RequesterContext, request: prompt.Request) void {
    _ = resolveViaAgent(context, request) catch {};
    done.store(true, .release);
}

fn resolveAllowFrontend(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    _ = raw_context;
    _ = request;
    return .{ .decision = .allow, .remember_kind = .once };
}

fn runTestConnectionWorker(worker_context: *ConnectionWorkerContext) void {
    defer cleanupConnectionWorker(worker_context);

    handleConnection(worker_context.service_context, worker_context.stream) catch |err| {
        std.log.warn("test agent connection failed: {}", .{err});
    };
}

const TestAgentServiceContext = struct {
    service_context: *AgentServiceContext,
};

fn runTestAgentServiceThread(context: *TestAgentServiceContext) void {
    runTestAgentService(context) catch {};
}

fn runTestAgentService(context: *TestAgentServiceContext) !void {
    const service_context = context.service_context;

    try ensureParentDirectory(service_context.socket_path);
    try removeSocketFileIfStale(service_context.socket_path);

    const address = try net.Address.initUnix(service_context.socket_path);
    const listener = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(listener);
    defer removeStaleSocketFile(service_context.socket_path) catch {};

    try std.posix.bind(listener, &address.any, address.getOsSockLen());
    try std.posix.listen(listener, 16);

    const first_accepted = try std.posix.accept(listener, null, null, std.posix.SOCK.CLOEXEC);
    const first_worker_context = try service_context.allocator.create(ConnectionWorkerContext);
    errdefer service_context.allocator.destroy(first_worker_context);
    first_worker_context.* = .{
        .allocator = service_context.allocator,
        .service_context = service_context,
        .stream = .{ .handle = first_accepted },
    };
    const first_worker = try std.Thread.spawn(.{}, runTestConnectionWorker, .{first_worker_context});
    defer first_worker.join();

    const second_accepted = try std.posix.accept(listener, null, null, std.posix.SOCK.CLOEXEC);
    var second_stream: net.Stream = .{ .handle = second_accepted };
    defer second_stream.close();
    try handleConnection(service_context, second_stream);
}

fn waitForPathToExist(path: []const u8) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        if (std.fs.cwd().statFile(path)) |_| return else |_| {}
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
    return error.FileNotFound;
}

test "decideFromFrame returns an owned request id" {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const frame =
        \\{"protocol":"file-snitch-agent","version":"1.0","type":"decide","request_id":"req-copy-check","subject":{"uid":501,"pid":42,"executable_path":"/bin/cat"},"request":{"enrolled_path":"/known_hosts.old","approval_class":"read_like","operation":"open","mode":"read"},"policy_context":{"default_timeout":"2026-04-10T12:00:00Z","can_remember":true},"details":{"display_path":"open O_RDONLY /known_hosts.old"}}
    ;

    const decision = try decideFromFrame(allocator, frame, .{
        .context = null,
        .resolve_fn = resolveAllowFrontend,
    });
    defer allocator.free(decision.request_id);

    var reuse_allocations: [64][]u8 = undefined;
    for (&reuse_allocations, 0..) |*slot, index| {
        slot.* = try allocator.alloc(u8, decision.request_id.len);
        @memset(slot.*, @as(u8, @intCast('a' + @as(u8, @intCast(index % 26)))));
    }
    defer for (reuse_allocations) |allocation| allocator.free(allocation);

    try std.testing.expectEqualStrings("req-copy-check", decision.request_id);
}

const DelayedDecisionServerContext = struct {
    service_context: *AgentServiceContext,
    socket_path: []const u8,
    failed: *std.atomic.Value(bool),
};

fn runDelayedDecisionServerThread(context: *DelayedDecisionServerContext) void {
    runDelayedDecisionServer(context) catch {
        context.failed.store(true, .release);
    };
}

fn runDelayedDecisionServer(context: *DelayedDecisionServerContext) !void {
    try ensureParentDirectory(context.socket_path);
    try removeSocketFileIfStale(context.socket_path);

    const address = try net.Address.initUnix(context.socket_path);
    const listener = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(listener);
    defer removeStaleSocketFile(context.socket_path) catch {};

    try std.posix.bind(listener, &address.any, address.getOsSockLen());
    try std.posix.listen(listener, 1);

    const accepted = try std.posix.accept(listener, null, null, std.posix.SOCK.CLOEXEC);
    var stream: net.Stream = .{ .handle = accepted };
    defer stream.close();
    try handleConnection(context.service_context, stream);
}

test "handleConnection ignores requester disconnect after prompt timeout" {
    const allocator = std.testing.allocator;
    const socket_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-disconnect-{d}.sock", .{std.time.nanoTimestamp()});
    defer allocator.free(socket_path);

    const blocking_context = try allocator.create(BlockingFrontendContext);
    defer allocator.destroy(blocking_context);
    blocking_context.* = .{};

    const service_context = try allocator.create(AgentServiceContext);
    defer allocator.destroy(service_context);
    service_context.* = .{
        .allocator = allocator,
        .socket_path = socket_path,
        .frontend = .{
            .context = blocking_context,
            .resolve_fn = resolveBlockingFrontend,
        },
    };

    const failed = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(failed);
    failed.* = std.atomic.Value(bool).init(false);

    const server_context = try allocator.create(DelayedDecisionServerContext);
    defer allocator.destroy(server_context);
    server_context.* = .{
        .service_context = service_context,
        .socket_path = socket_path,
        .failed = failed,
    };

    const server_thread = try std.Thread.spawn(.{}, runDelayedDecisionServerThread, .{server_context});
    try waitForPathToExist(socket_path);

    var client_stream = try net.connectUnixSocket(socket_path);

    const hello_frame = try readFrameAlloc(allocator, client_stream, 1_000);
    defer allocator.free(hello_frame);
    try validateHelloFrame(allocator, hello_frame);

    const hello_request_id = try requestIdFromFrame(allocator, hello_frame);
    defer allocator.free(hello_request_id);
    try sendWelcome(allocator, client_stream, hello_request_id);

    const request: prompt.Request = .{
        .path = "/known_hosts.old",
        .access_class = .read,
        .label = "open O_RDONLY /known_hosts.old",
        .can_remember = true,
        .pid = 21065,
        .uid = 501,
        .gid = 0,
        .executable_path = "/bin/cat",
    };
    try sendDecide(allocator, client_stream, "disconnect-check", request, request.label.?, "2026-04-10T12:00:00Z");
    client_stream.close();

    var wait_attempts: usize = 0;
    while (!blocking_context.first_started.load(.acquire) and wait_attempts < 200) : (wait_attempts += 1) {
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expect(blocking_context.first_started.load(.acquire));

    blocking_context.release_first.store(true, .release);
    server_thread.join();

    try std.testing.expect(!failed.load(.acquire));
}

test "agent accepts later connections while one prompt is blocked" {
    const allocator = std.testing.allocator;
    const socket_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-concurrency-{d}.sock", .{std.time.nanoTimestamp()});
    defer allocator.free(socket_path);

    const blocking_context = try allocator.create(BlockingFrontendContext);
    defer allocator.destroy(blocking_context);
    blocking_context.* = .{};

    const service_context = try allocator.create(AgentServiceContext);
    defer allocator.destroy(service_context);
    service_context.* = .{
        .allocator = allocator,
        .socket_path = socket_path,
        .frontend = .{
            .context = blocking_context,
            .resolve_fn = resolveBlockingFrontend,
        },
    };

    const test_service_context = try allocator.create(TestAgentServiceContext);
    defer allocator.destroy(test_service_context);
    test_service_context.* = .{
        .service_context = service_context,
    };

    const policy_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-concurrency-{d}.yml", .{std.time.nanoTimestamp()});
    defer allocator.free(policy_path);
    const first_done = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(first_done);
    first_done.* = std.atomic.Value(bool).init(false);
    const second_done = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(second_done);
    second_done.* = std.atomic.Value(bool).init(false);

    const first_requester = try allocator.create(RequesterContext);
    defer allocator.destroy(first_requester);
    first_requester.* = .{
        .allocator = allocator,
        .socket_path = socket_path,
        .policy_path = policy_path,
        .timeout_ms = 1_000,
    };
    const second_requester = try allocator.create(RequesterContext);
    defer allocator.destroy(second_requester);
    second_requester.* = first_requester.*;

    const service_thread = try std.Thread.spawn(.{}, runTestAgentServiceThread, .{test_service_context});
    defer service_thread.join();
    try waitForPathToExist(socket_path);

    const request = prompt.Request{
        .path = "/tmp/demo-secret",
        .access_class = .read,
        .can_remember = false,
        .pid = 1234,
        .uid = 1000,
        .gid = 1000,
        .executable_path = "/usr/bin/demo",
    };

    const first_thread = try std.Thread.spawn(.{}, runRequesterThread, .{ first_done, first_requester, request });
    defer first_thread.join();

    var wait_attempts: usize = 0;
    while (!blocking_context.first_started.load(.acquire) and wait_attempts < 200) : (wait_attempts += 1) {
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expect(blocking_context.first_started.load(.acquire));

    const second_thread = try std.Thread.spawn(.{}, runRequesterThread, .{ second_done, second_requester, request });
    defer second_thread.join();

    var second_completed = false;
    wait_attempts = 0;
    while (wait_attempts < 200) : (wait_attempts += 1) {
        if (second_done.load(.acquire)) {
            second_completed = true;
            break;
        }
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }
    try std.testing.expect(second_completed);

    blocking_context.release_first.store(true, .release);
}

test "apple script escaping covers control characters" {
    const allocator = std.testing.allocator;
    const escaped = try appleScriptStringLiteralContentsAlloc(allocator, "quoted \"value\"\npath\\name\r");
    defer allocator.free(escaped);

    try std.testing.expectEqualStrings("quoted \\\"value\\\"\\npath\\\\name", escaped);
}
