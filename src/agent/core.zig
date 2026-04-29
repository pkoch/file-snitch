const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const config = @import("../config.zig");
const defaults = @import("../defaults.zig");
const policy = @import("../policy.zig");
const prompt = @import("../prompt.zig");
const runtime = @import("../runtime.zig");
const frontend = @import("frontend.zig");
const protocol = @import("protocol.zig");
const util = @import("util.zig");
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

pub const RequesterContext = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    policy_path: []const u8,
    protocol_timeout_ms: u32 = defaults.protocol_timeout_ms_default,
};

pub const FrontendKind = enum {
    terminal_pinentry,
    macos_ui,
    linux_ui,
};

pub const Frontend = struct {
    context: ?*anyopaque,
    resolve_fn: *const fn (?*anyopaque, prompt.Request) prompt.Response,
    user_interaction_timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    supports_concurrent_requests: bool = true,

    pub fn resolve(self: Frontend, request: prompt.Request) prompt.Response {
        return self.resolve_fn(self.context, request);
    }
};

pub const AgentServiceContext = struct {
    allocator: std.mem.Allocator,
    socket_path: []const u8,
    frontend: Frontend,
};

pub const SocketPathError = error{
    SocketPathInUse,
    InvalidSocketPath,
    UnauthorizedPeer,
};

pub fn defaultSocketPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (runtime.getEnvVarOwned(allocator, defaults.agent_socket_env)) |value| {
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
        .resolve_fn = protocol.resolveSocket,
    };
}

pub fn runAgentService(context: *AgentServiceContext) !void {
    try util.ensureParentDirectory(context.socket_path);
    try util.removeSocketFileIfStale(context.socket_path);

    const address = try net.UnixAddress.init(context.socket_path);
    var server = try address.listen(runtime.io(), .{ .kernel_backlog = 16 });
    defer server.deinit(runtime.io());
    defer util.removeStaleSocketFileForCleanup(context.socket_path);

    while (true) {
        const stream = server.accept(runtime.io()) catch |err| switch (err) {
            error.ConnectionAborted, error.WouldBlock => continue,
            else => return err,
        };
        util.assertSameUidPeer(stream) catch |err| {
            stream.close(runtime.io());
            std.log.warn("agent rejected socket peer: {}", .{err});
            continue;
        };
        if (!context.frontend.supports_concurrent_requests) {
            // GUI frontends shell out to helper processes. On Linux, doing that
            // from a worker thread would fork a multithreaded process.
            defer stream.close(runtime.io());
            protocol.handleConnection(context, stream) catch |err| {
                std.log.warn("agent connection failed: {}", .{err});
            };
            continue;
        }

        const worker_context = try context.allocator.create(protocol.ConnectionWorkerContext);
        errdefer context.allocator.destroy(worker_context);
        worker_context.* = .{
            .allocator = context.allocator,
            .service_context = context,
            .stream = stream,
        };
        errdefer stream.close(runtime.io());

        const thread = try std.Thread.spawn(.{}, protocol.runConnectionWorker, .{worker_context});
        thread.detach();
    }
}
