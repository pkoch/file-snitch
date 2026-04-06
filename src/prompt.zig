const std = @import("std");
const policy = @import("policy.zig");

pub const Request = struct {
    path: []const u8,
    access_class: policy.AccessClass,
    label: ?[]const u8 = null,
    pid: u32,
    uid: u32,
    gid: u32,
};

pub const Decision = enum(i32) {
    allow = 1,
    deny = 2,
    timeout = 3,
    unavailable = 4,
};

pub const Broker = struct {
    context: ?*anyopaque,
    resolve_fn: *const fn (?*anyopaque, Request) Decision,

    pub fn resolve(self: Broker, request: Request) Decision {
        return self.resolve_fn(self.context, request);
    }
};

pub const CliContext = struct {
    timeout_ms: u32 = 5_000,
    stdin_file: std.fs.File = .stdin(),
    stderr_file: std.fs.File = .stderr(),
    mutex: std.Thread.Mutex = .{},
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

fn resolveCli(raw_context: ?*anyopaque, request: Request) Decision {
    const context = raw_context orelse return .unavailable;
    const cli_context: *CliContext = @ptrCast(@alignCast(context));
    return resolveCliWithContext(cli_context, request);
}

fn resolveCliWithContext(context: *CliContext, request: Request) Decision {
    context.mutex.lock();
    defer context.mutex.unlock();

    writePrompt(context, request) catch return .unavailable;

    return readDecisionWithTimeout(context) catch |err| switch (err) {
        error.TimedOut => return .timeout,
        error.EndOfStream => return .deny,
        else => return .unavailable,
    };
}

fn resolveScripted(raw_context: ?*anyopaque, request: Request) Decision {
    _ = request;
    const context = raw_context orelse return .deny;
    const scripted_context: *ScriptedContext = @ptrCast(@alignCast(context));
    if (scripted_context.next_index >= scripted_context.decisions.len) {
        return .deny;
    }

    const decision = scripted_context.decisions[scripted_context.next_index];
    scripted_context.next_index += 1;
    return decision;
}

fn writePrompt(context: *CliContext, request: Request) !void {
    const label = request.label orelse blk: {
        break :blk try std.fmt.allocPrint(
            std.heap.page_allocator,
            "{s} {s}",
            .{ accessClassLabel(request.access_class), request.path },
        );
    };
    defer if (request.label == null) std.heap.page_allocator.free(label);

    const message = try std.fmt.allocPrint(
        std.heap.page_allocator,
        "file-snitch prompt: {s} pid={d} uid={d} gid={d} [y/N] ",
        .{
            label,
            request.pid,
            request.uid,
            request.gid,
        },
    );
    defer std.heap.page_allocator.free(message);

    try context.stderr_file.writeAll(message);
}

const ReadLineError = error{
    TimedOut,
    EndOfStream,
    InputOutput,
    SystemResources,
};

fn readDecisionWithTimeout(context: *CliContext) ReadLineError!Decision {
    while (true) {
        if (consumePendingDecision(context)) |decision| {
            return decision;
        }

        if (context.pending_len == context.pending_input.len) {
            const decision = parseDecision(context.pending_input[0..context.pending_len]);
            context.pending_len = 0;
            return decision;
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
            return if (context.pending_len == 0) error.EndOfStream else parseDecision(context.pending_input[0..context.pending_len]);
        }

        const read_count = context.stdin_file.read(context.pending_input[context.pending_len..]) catch return error.InputOutput;
        if (read_count == 0) {
            return if (context.pending_len == 0) error.EndOfStream else parseDecision(context.pending_input[0..context.pending_len]);
        }

        context.pending_len += read_count;
    }
}

fn consumePendingDecision(context: *CliContext) ?Decision {
    const newline_index = std.mem.indexOfAny(u8, context.pending_input[0..context.pending_len], "\r\n") orelse return null;
    const decision = parseDecision(context.pending_input[0..newline_index]);
    const remaining_start = skipNewlines(context.pending_input[0..context.pending_len], newline_index);
    const remaining_len = context.pending_len - remaining_start;
    std.mem.copyForwards(u8, context.pending_input[0..remaining_len], context.pending_input[remaining_start..context.pending_len]);
    context.pending_len = remaining_len;
    return decision;
}

fn skipNewlines(buffer: []const u8, start: usize) usize {
    var index = start;
    while (index < buffer.len and (buffer[index] == '\r' or buffer[index] == '\n')) : (index += 1) {}
    return index;
}

fn parseDecision(line: []const u8) Decision {
    const trimmed = std.mem.trim(u8, line, " \t\r\n");
    if (trimmed.len == 0) {
        return .deny;
    }

    if (std.ascii.eqlIgnoreCase(trimmed, "y") or std.ascii.eqlIgnoreCase(trimmed, "yes")) {
        return .allow;
    }

    if (std.ascii.eqlIgnoreCase(trimmed, "n") or std.ascii.eqlIgnoreCase(trimmed, "no")) {
        return .deny;
    }

    return .deny;
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

test "scripted broker returns configured decisions in order" {
    var context = ScriptedContext.init(&.{ .allow, .deny });
    const broker = scriptedBroker(&context);
    const request: Request = .{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 1,
        .uid = 2,
        .gid = 3,
    };

    try std.testing.expectEqual(Decision.allow, broker.resolve(request));
    try std.testing.expectEqual(Decision.deny, broker.resolve(request));
    try std.testing.expectEqual(Decision.deny, broker.resolve(request));
}

test "cli broker allows yes" {
    const fds = try std.posix.pipe();
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);

    const stderr_fds = try std.posix.pipe();
    defer std.posix.close(stderr_fds[0]);
    defer std.posix.close(stderr_fds[1]);

    const writer = std.fs.File{ .handle = fds[1] };
    try writer.writeAll("yes\n");

    var context = CliContext{
        .timeout_ms = 50,
        .stdin_file = .{ .handle = fds[0] },
        .stderr_file = .{ .handle = stderr_fds[1] },
    };
    const broker = cliBroker(&context);

    const decision = broker.resolve(.{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 10,
        .uid = 20,
        .gid = 30,
    });

    try std.testing.expectEqual(Decision.allow, decision);
}

test "cli broker times out to deny path" {
    const fds = try std.posix.pipe();
    defer std.posix.close(fds[0]);
    defer std.posix.close(fds[1]);

    const stderr_fds = try std.posix.pipe();
    defer std.posix.close(stderr_fds[0]);
    defer std.posix.close(stderr_fds[1]);

    var context = CliContext{
        .timeout_ms = 10,
        .stdin_file = .{ .handle = fds[0] },
        .stderr_file = .{ .handle = stderr_fds[1] },
    };
    const broker = cliBroker(&context);

    const decision = broker.resolve(.{
        .path = "/prompted.txt",
        .access_class = .create,
        .pid = 10,
        .uid = 20,
        .gid = 30,
    });

    try std.testing.expectEqual(Decision.timeout, decision);
}
