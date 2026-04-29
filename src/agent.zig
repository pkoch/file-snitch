const std = @import("std");
const builtin = @import("builtin");
const net = std.Io.net;
const app_meta = @import("app_meta.zig");
const config = @import("config.zig");
const defaults = @import("defaults.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");
const runtime = @import("runtime.zig");
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

// Re-export from submodules
pub const core = @import("agent/core.zig");
pub const frontend = @import("agent/frontend.zig");
pub const protocol = @import("agent/protocol.zig");
pub const util = @import("agent/util.zig");

// Re-export commonly used types from core
pub const RequesterContext = core.RequesterContext;
pub const FrontendKind = core.FrontendKind;
pub const Frontend = core.Frontend;
pub const AgentServiceContext = core.AgentServiceContext;
pub const SocketPathError = core.SocketPathError;

// Re-export commonly used functions from core
pub const defaultSocketPathAlloc = core.defaultSocketPathAlloc;
pub const socketBroker = core.socketBroker;
pub const runAgentService = core.runAgentService;

// Re-export commonly used types from frontend
pub const TerminalPinentryContext = frontend.TerminalPinentryContext;
pub const MacosUiContext = frontend.MacosUiContext;
pub const LinuxUiContext = frontend.LinuxUiContext;

// Re-export commonly used functions from frontend
pub const terminalPinentryFrontend = frontend.terminalPinentryFrontend;
pub const macosUiFrontend = frontend.macosUiFrontend;
pub const linuxUiFrontend = frontend.linuxUiFrontend;
pub const defaultTerminalPathAlloc = frontend.defaultTerminalPathAlloc;
pub const defaultOsascriptPathAlloc = frontend.defaultOsascriptPathAlloc;
pub const defaultZenityPathAlloc = frontend.defaultZenityPathAlloc;

// Re-export commonly used functions from protocol
pub const readFrameAlloc = protocol.readFrameAlloc;
pub const readFrameFromReaderAlloc = protocol.readFrameFromReaderAlloc;
pub const isPeerClosedError = protocol.isPeerClosedError;

// Re-export commonly used functions from util
pub const generateUlidAlloc = util.generateUlidAlloc;

// Constants
const protocol_name = "file-snitch-agent";
const protocol_version = "1.0";

// Test helper functions and types
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
            std.Io.sleep(runtime.io(), .fromMilliseconds(5), .awake) catch |err| {
                std.log.warn("blocking frontend sleep failed: {}", .{err});
                return .{ .decision = .unavailable };
            };
        }
    }
    return .{ .decision = .allow, .remember_kind = .once };
}

fn runRequesterThread(
    done: *std.atomic.Value(bool),
    failed: *std.atomic.Value(bool),
    context: *core.RequesterContext,
    request: prompt.Request,
) void {
    const response = protocol.resolveSocket(context, request);
    if (response.decision == .unavailable) {
        failed.store(true, .release);
    }
    done.store(true, .release);
}

fn resolveAllowFrontend(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    _ = raw_context;
    _ = request;
    return .{ .decision = .allow, .remember_kind = .once };
}

fn runTestConnectionWorker(worker_context: *protocol.ConnectionWorkerContext) void {
    defer protocol.cleanupConnectionWorker(worker_context);
    protocol.handleConnection(worker_context.service_context, worker_context.stream) catch |err| {
        std.log.warn("test agent connection failed: {}", .{err});
    };
}

const TestAgentServiceContext = struct {
    service_context: *core.AgentServiceContext,
    failed: *std.atomic.Value(bool),
};

fn runTestAgentServiceThread(context: *TestAgentServiceContext) void {
    runTestAgentService(context) catch |err| {
        std.log.warn("test agent service failed: {}", .{err});
        context.failed.store(true, .release);
    };
}

fn runTestAgentService(context: *TestAgentServiceContext) !void {
    const service_context = context.service_context;

    try util.ensureParentDirectory(service_context.socket_path);
    try util.removeSocketFileIfStale(service_context.socket_path);

    const address = try net.UnixAddress.init(service_context.socket_path);
    var server = try address.listen(runtime.io(), .{ .kernel_backlog = 16 });
    defer server.deinit(runtime.io());
    defer util.removeStaleSocketFileForCleanup(service_context.socket_path);

    const first_stream = try server.accept(runtime.io());
    errdefer first_stream.close(runtime.io());
    try util.assertSameUidPeer(first_stream);
    const first_worker_context = try service_context.allocator.create(protocol.ConnectionWorkerContext);
    errdefer service_context.allocator.destroy(first_worker_context);
    first_worker_context.* = .{
        .allocator = service_context.allocator,
        .service_context = service_context,
        .stream = first_stream,
    };
    const first_worker = try std.Thread.spawn(.{}, protocol.runConnectionWorker, .{first_worker_context});
    defer first_worker.join();

    const second_stream = try server.accept(runtime.io());
    defer second_stream.close(runtime.io());
    try util.assertSameUidPeer(second_stream);
    try protocol.handleConnection(service_context, second_stream);
}

fn waitForPathToExist(path: []const u8) !void {
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        if (std.Io.Dir.cwd().statFile(runtime.io(), path, .{})) |_| return else |_| {}
        try std.Io.sleep(runtime.io(), .fromMilliseconds(10), .awake);
    }
    return error.FileNotFound;
}

fn tempAgentSocketPathAlloc(allocator: std.mem.Allocator, prefix: []const u8) ![]u8 {
    const parent_dir = try std.fmt.allocPrint(allocator, "/tmp/{s}-{d}", .{ prefix, runtime.nanoTimestamp() });
    defer allocator.free(parent_dir);
    return std.fs.path.join(allocator, &.{ parent_dir, "agent.sock" });
}

fn deleteParentDirectory(path: []const u8) void {
    const parent_dir = std.fs.path.dirname(path) orelse return;
    std.Io.Dir.cwd().deleteTree(runtime.io(), parent_dir) catch |err| {
        std.debug.panic("failed to delete test parent directory {s}: {}", .{ parent_dir, err });
    };
}

fn deleteFileIfPresent(path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(runtime.io(), path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.debug.panic("failed to delete test file {s}: {}", .{ path, err }),
    };
}

test "frame roundtrip preserves payload" {
    const allocator = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    const payload = "{\"protocol\":\"file-snitch-agent\"}";
    try list.print(allocator, "{d}:{s}\n", .{ payload.len, payload });

    var reader: std.Io.Reader = .fixed(list.items);
    const decoded = try protocol.readFrameFromReaderAlloc(allocator, &reader);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(payload, decoded);
}

test "frame length parser rejects invalid prefixes" {
    try std.testing.expectError(error.InvalidFrame, protocol.parseFramePayloadLen(""));
    try std.testing.expectError(error.InvalidFrame, protocol.parseFramePayloadLen("01"));
    try std.testing.expectError(error.InvalidFrame, protocol.parseFramePayloadLen("1000000"));
    try std.testing.expectEqual(@as(usize, protocol.max_frame_len), try protocol.parseFramePayloadLen("999999"));
}

test "generated ulid is well-formed" {
    const allocator = std.testing.allocator;
    const value = try util.generateUlidAlloc(allocator);
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

    const resolved = try frontend.defaultTerminalPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}

test "default osascript path uses FILE_SNITCH_OSASCRIPT_BIN override" {
    const allocator = std.testing.allocator;
    const key = defaults.osascript_bin_env;
    const value = "/tmp/file-snitch-test-osascript";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key, value, 1));
    defer _ = c.unsetenv(key);

    const resolved = try frontend.defaultOsascriptPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}

test "default zenity path uses FILE_SNITCH_ZENITY_BIN override" {
    const allocator = std.testing.allocator;
    const key = defaults.zenity_bin_env;
    const value = "/tmp/file-snitch-test-zenity";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(key, value, 1));
    defer _ = c.unsetenv(key);

    const resolved = try frontend.defaultZenityPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(value, resolved);
}

test "gui frontends serialize requests" {
    const allocator = std.testing.allocator;

    var terminal_context = frontend.TerminalPinentryContext{
        .allocator = allocator,
    };
    try std.testing.expect(frontend.terminalPinentryFrontend(&terminal_context).supports_concurrent_requests);

    var macos_context = frontend.MacosUiContext{
        .allocator = allocator,
        .osascript_path = "osascript",
    };
    try std.testing.expect(!frontend.macosUiFrontend(&macos_context).supports_concurrent_requests);

    var linux_context = frontend.LinuxUiContext{
        .allocator = allocator,
        .zenity_path = "zenity",
    };
    try std.testing.expect(!frontend.linuxUiFrontend(&linux_context).supports_concurrent_requests);
}

test "parse macos ui response accepts known values" {
    try std.testing.expectEqual(prompt.Decision.allow, (try frontend.parseMacosUiResponse("allow\n")).decision);
    try std.testing.expectEqual(prompt.RememberKind.once, (try frontend.parseMacosUiResponse("allow\n")).remember_kind);
    try std.testing.expectEqual(prompt.Decision.deny, (try frontend.parseMacosUiResponse("deny\r\n")).decision);
    try std.testing.expectEqual(prompt.Decision.timeout, (try frontend.parseMacosUiResponse("timeout")).decision);
    const remembered = try frontend.parseMacosUiResponse("always-allow");
    try std.testing.expectEqual(prompt.Decision.allow, remembered.decision);
    try std.testing.expectEqual(prompt.RememberKind.durable, remembered.remember_kind);
}

test "macos ui remembered dialog uses compilable timeout block" {
    const allocator = std.testing.allocator;
    const script = try frontend.buildMacosDialogScriptAlloc(allocator, .{
        .path = "/Users/test/secrets/gist",
        .access_class = .read,
        .label = "open O_RDONLY /gist",
        .can_remember = true,
        .pid = 42,
        .uid = 501,
        .gid = 20,
        .executable_path = "/bin/cat",
    }, 5_000);
    defer allocator.free(script);

    try std.testing.expect(std.mem.indexOf(u8, script, "with timeout of 5 seconds") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "giving up after") == null);
    try std.testing.expect(std.mem.indexOf(u8, script, "on error number error_number") != null);
    try std.testing.expect(std.mem.indexOf(u8, script, "if error_number is -1712 then return \"timeout\"") != null);
}

test "parse linux ui response accepts known exit codes" {
    try std.testing.expectEqual(prompt.Decision.allow, (try frontend.parseLinuxUiResponse(.{ .exited = 0 }, "Allow once")).decision);
    try std.testing.expectEqual(prompt.Decision.deny, (try frontend.parseLinuxUiResponse(.{ .exited = 1 }, "")).decision);
    try std.testing.expectEqual(prompt.Decision.timeout, (try frontend.parseLinuxUiResponse(.{ .exited = 5 }, "")).decision);
    const remembered = try frontend.parseLinuxUiResponse(.{ .exited = 0 }, "Always deny");
    try std.testing.expectEqual(prompt.Decision.deny, remembered.decision);
    try std.testing.expectEqual(prompt.RememberKind.durable, remembered.remember_kind);
}

test "parse linux ui response rejects hidden machine labels" {
    try std.testing.expectError(error.InvalidProtocolMessage, frontend.parseLinuxUiResponse(.{ .exited = 0 }, "allow"));
    try std.testing.expectError(error.InvalidProtocolMessage, frontend.parseLinuxUiResponse(.{ .exited = 0 }, "deny"));
    try std.testing.expectError(error.InvalidProtocolMessage, frontend.parseLinuxUiResponse(.{ .exited = 0 }, "allow-5m"));
    try std.testing.expectError(error.InvalidProtocolMessage, frontend.parseLinuxUiResponse(.{ .exited = 0 }, "always-allow"));
    try std.testing.expectError(error.InvalidProtocolMessage, frontend.parseLinuxUiResponse(.{ .exited = 0 }, "always-deny"));
}

test "stale socket cleanup rejects regular files" {
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-regular-{d}", .{runtime.nanoTimestamp()});
    defer allocator.free(path);
    defer deleteFileIfPresent(path);

    const file = try std.Io.Dir.createFileAbsolute(runtime.io(), path, .{ .truncate = true });
    file.close(runtime.io());

    try std.testing.expectError(error.InvalidSocketPath, util.removeSocketFileIfStale(path));
}

test "stale socket cleanup preserves live sockets" {
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-socket-{d}.sock", .{runtime.nanoTimestamp()});
    defer allocator.free(path);
    defer deleteFileIfPresent(path);

    const address = try net.UnixAddress.init(path);
    var server = try address.listen(runtime.io(), .{ .kernel_backlog = 1 });
    defer server.deinit(runtime.io());

    try std.testing.expectError(error.SocketPathInUse, util.removeSocketFileIfStale(path));
    _ = try std.Io.Dir.cwd().statFile(runtime.io(), path, .{});
}

test "stale socket cleanup removes dead sockets" {
    const allocator = std.testing.allocator;
    const path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-dead-socket-{d}.sock", .{runtime.nanoTimestamp()});
    defer allocator.free(path);
    defer deleteFileIfPresent(path);

    const address = try net.UnixAddress.init(path);
    var server = try address.listen(runtime.io(), .{ .kernel_backlog = 1 });
    server.deinit(runtime.io());

    try util.removeSocketFileIfStale(path);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().statFile(runtime.io(), path, .{}));
}

test "agent socket parent directory is created private" {
    const allocator = std.testing.allocator;
    const socket_path = try tempAgentSocketPathAlloc(allocator, "file-snitch-agent-private-parent");
    defer allocator.free(socket_path);
    defer deleteParentDirectory(socket_path);

    try util.ensureParentDirectory(socket_path);

    const parent_dir = std.fs.path.dirname(socket_path) orelse return error.InvalidPath;
    const stat = try util.statPath(parent_dir);
    try std.testing.expectEqual(c.getuid(), stat.st_uid);
    try std.testing.expectEqual(@as(c.mode_t, 0o700), stat.st_mode & 0o777);
}

test "agent socket parent directory rejects shared permissions" {
    const allocator = std.testing.allocator;
    const socket_path = try tempAgentSocketPathAlloc(allocator, "file-snitch-agent-shared-parent");
    defer allocator.free(socket_path);
    defer deleteParentDirectory(socket_path);

    const parent_dir = std.fs.path.dirname(socket_path) orelse return error.InvalidPath;
    try std.Io.Dir.cwd().createDirPath(runtime.io(), parent_dir);
    try util.chmodPath(parent_dir, 0o755);

    try std.testing.expectError(error.InvalidSocketPath, util.ensureParentDirectory(socket_path));
}

test "decideFromFrame returns an owned request id" {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const frame =
        \\{"protocol":"file-snitch-agent","version":"1.0","type":"decide","request_id":"req-copy-check","subject":{"uid":501,"gid":20,"pid":42,"executable_path":"/bin/cat"},"request":{"enrolled_path":"/known_hosts.old","approval_class":"read_like","operation":"open","mode":"read"},"policy_context":{"can_remember":true},"details":{"display_path":"open O_RDONLY /known_hosts.old"}}
    ;

    const decision = try protocol.decideFromFrame(allocator, frame, .{
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

test "decideFromFrame rejects mismatched metadata" {
    const allocator = std.testing.allocator;
    const frame =
        \\{"protocol":"file-snitch-agent","version":"1.0","type":"query","request_id":"req-bad-type","subject":{"uid":501,"gid":20,"pid":42,"executable_path":"/bin/cat"},"request":{"enrolled_path":"/known_hosts.old","approval_class":"read_like","operation":"open","mode":"read"},"policy_context":{"can_remember":true},"details":{"display_path":"open O_RDONLY /known_hosts.old"}}
    ;

    try std.testing.expectError(error.InvalidProtocolMessage, protocol.decideFromFrame(allocator, frame, .{
        .context = null,
        .resolve_fn = resolveAllowFrontend,
    }));
}

test "requester waits through user interaction deadline and protocol timeout" {
    const deadline_ms = runtime.milliTimestamp() + 30_000;
    const timeout_ms = protocol.timeoutUntilDeadlinePlusProtocolMs(deadline_ms, 1_000);
    try std.testing.expect(timeout_ms > 29_000);
    try std.testing.expect(timeout_ms <= 31_000);

    const expired_deadline_ms = runtime.milliTimestamp() - 2_000;
    try std.testing.expectEqual(@as(u32, 0), protocol.timeoutUntilDeadlinePlusProtocolMs(expired_deadline_ms, 1_000));
}

const DelayedDecisionServerContext = struct {
    service_context: *core.AgentServiceContext,
    socket_path: []const u8,
    failed: *std.atomic.Value(bool),
};

fn runDelayedDecisionServerThread(context: *DelayedDecisionServerContext) void {
    runDelayedDecisionServer(context) catch {
        context.failed.store(true, .release);
    };
}

fn runDelayedDecisionServer(context: *DelayedDecisionServerContext) !void {
    try util.ensureParentDirectory(context.socket_path);
    try util.removeSocketFileIfStale(context.socket_path);

    const address = try net.UnixAddress.init(context.socket_path);
    var server = try address.listen(runtime.io(), .{ .kernel_backlog = 1 });
    defer server.deinit(runtime.io());
    defer util.removeStaleSocketFileForCleanup(context.socket_path);

    const stream = try server.accept(runtime.io());
    defer stream.close(runtime.io());
    try util.assertSameUidPeer(stream);
    try protocol.handleConnection(context.service_context, stream);
}

test "handleConnection ignores requester disconnect after prompt timeout" {
    const allocator = std.testing.allocator;
    const socket_path = try tempAgentSocketPathAlloc(allocator, "file-snitch-agent-disconnect");
    defer allocator.free(socket_path);
    defer deleteParentDirectory(socket_path);

    const blocking_context = try allocator.create(BlockingFrontendContext);
    defer allocator.destroy(blocking_context);
    blocking_context.* = .{};

    const service_context = try allocator.create(core.AgentServiceContext);
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

    const client_address = try net.UnixAddress.init(socket_path);
    var client_stream = try client_address.connect(runtime.io());

    const hello_frame = try protocol.readFrameAlloc(allocator, client_stream, 1_000);
    defer allocator.free(hello_frame);
    try protocol.validateHelloFrame(allocator, hello_frame);

    const hello_request_id = try protocol.requestIdFromFrame(allocator, hello_frame);
    defer allocator.free(hello_request_id);
    try protocol.sendWelcome(allocator, client_stream, hello_request_id);

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
    try protocol.sendDecide(allocator, client_stream, "disconnect-check", request, request.label.?);

    const event_frame = try protocol.readFrameAlloc(allocator, client_stream, 1_000);
    defer allocator.free(event_frame);
    try std.testing.expect((try protocol.userInteractionDeadlineMsFromEventFrame(allocator, event_frame, "disconnect-check")) != null);

    client_stream.close(runtime.io());

    var wait_attempts: usize = 0;
    while (!blocking_context.first_started.load(.acquire) and wait_attempts < 200) : (wait_attempts += 1) {
        try std.Io.sleep(runtime.io(), .fromMilliseconds(5), .awake);
    }
    try std.testing.expect(blocking_context.first_started.load(.acquire));

    blocking_context.release_first.store(true, .release);
    server_thread.join();

    try std.testing.expect(!failed.load(.acquire));
}

test "agent accepts later connections while one prompt is blocked" {
    const allocator = std.testing.allocator;
    const socket_path = try tempAgentSocketPathAlloc(allocator, "file-snitch-agent-concurrency");
    defer allocator.free(socket_path);
    defer deleteParentDirectory(socket_path);

    const blocking_context = try allocator.create(BlockingFrontendContext);
    defer allocator.destroy(blocking_context);
    blocking_context.* = .{};

    const service_context = try allocator.create(core.AgentServiceContext);
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
    const service_failed = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(service_failed);
    service_failed.* = std.atomic.Value(bool).init(false);
    test_service_context.* = .{
        .service_context = service_context,
        .failed = service_failed,
    };

    const policy_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-agent-concurrency-{d}.yml", .{runtime.nanoTimestamp()});
    defer allocator.free(policy_path);
    const first_done = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(first_done);
    first_done.* = std.atomic.Value(bool).init(false);
    const first_failed = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(first_failed);
    first_failed.* = std.atomic.Value(bool).init(false);
    const second_done = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(second_done);
    second_done.* = std.atomic.Value(bool).init(false);
    const second_failed = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(second_failed);
    second_failed.* = std.atomic.Value(bool).init(false);

    const first_requester = try allocator.create(core.RequesterContext);
    defer allocator.destroy(first_requester);
    first_requester.* = .{
        .allocator = allocator,
        .socket_path = socket_path,
        .policy_path = policy_path,
        .protocol_timeout_ms = 1_000,
    };
    const second_requester = try allocator.create(core.RequesterContext);
    defer allocator.destroy(second_requester);
    second_requester.* = first_requester.*;

    const service_thread = try std.Thread.spawn(.{}, runTestAgentServiceThread, .{test_service_context});
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

    const first_thread = try std.Thread.spawn(.{}, runRequesterThread, .{ first_done, first_failed, first_requester, request });

    var wait_attempts: usize = 0;
    while (!blocking_context.first_started.load(.acquire) and wait_attempts < 200) : (wait_attempts += 1) {
        try std.Io.sleep(runtime.io(), .fromMilliseconds(5), .awake);
    }
    try std.testing.expect(blocking_context.first_started.load(.acquire));

    const second_thread = try std.Thread.spawn(.{}, runRequesterThread, .{ second_done, second_failed, second_requester, request });

    var second_completed = false;
    wait_attempts = 0;
    while (wait_attempts < 200) : (wait_attempts += 1) {
        if (second_done.load(.acquire)) {
            second_completed = true;
            break;
        }
        try std.Io.sleep(runtime.io(), .fromMilliseconds(5), .awake);
    }
    try std.testing.expect(second_completed);

    blocking_context.release_first.store(true, .release);
    service_thread.join();
    first_thread.join();
    second_thread.join();

    try std.testing.expect(!service_failed.load(.acquire));
    try std.testing.expect(!first_failed.load(.acquire));
    try std.testing.expect(!second_failed.load(.acquire));
}
