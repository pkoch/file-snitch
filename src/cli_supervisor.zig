const std = @import("std");
const builtin = @import("builtin");

const config = @import("config.zig");
const defaults = @import("defaults.zig");
const policy = @import("policy.zig");
const policy_watch = @import("cli_policy_watch.zig");

const allocator = std.heap.page_allocator;

var supervisor_shutdown_signal = std.atomic.Value(i32).init(0);

pub const RunCommand = struct {
    policy_path: []const u8,
    default_mutation_outcome: policy.Outcome,
    prompt_timeout_ms: u32,
    status_fifo_path: ?[]const u8 = null,
    mount_path_filter: ?[]const u8 = null,

    pub fn deinit(self: RunCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.policy_path);
        if (self.status_fifo_path) |path| {
            alloc.free(path);
        }
        if (self.mount_path_filter) |path| {
            alloc.free(path);
        }
    }
};

const PolicyMarker = config.PolicyMarker;

const ManagedMountChild = struct {
    child: std.process.Child,
    argv: []const []const u8,
    mount_path: []u8,
    alive: bool,
    term: ?std.process.Child.Term = null,

    fn deinit(self: *ManagedMountChild) void {
        allocator.free(self.mount_path);
        allocator.free(self.argv);
        self.* = undefined;
    }
};

pub fn reconcilePolicyInForeground(command: RunCommand) !void {
    const signal_handlers = installSupervisorSignalHandlers();
    defer signal_handlers.restore();

    var children: std.ArrayListUnmanaged(ManagedMountChild) = .{};
    defer stopManagedMountChildren(&children);

    var change_source = policy_watch.ChangeSource.init(allocator, command.policy_path);
    defer change_source.deinit();

    var last_marker: ?PolicyMarker = null;
    var needs_reconcile = true;
    var next_expiration_unix_seconds: ?i64 = null;

    while (true) {
        const shutdown_signal = supervisor_shutdown_signal.load(.acquire);
        if (shutdown_signal != 0) {
            break;
        }

        if (next_expiration_unix_seconds) |expires_at| {
            if (std.time.timestamp() >= expires_at) {
                needs_reconcile = true;
            }
        }

        const marker = config.currentPolicyMarker(allocator, command.policy_path) catch |err| {
            std.log.warn("failed to inspect policy marker at {s}: {}", .{ command.policy_path, err });
            changeSourceWait(&change_source, next_expiration_unix_seconds, &needs_reconcile);
            continue;
        };
        if (needs_reconcile or last_marker == null or !last_marker.?.eql(marker)) {
            next_expiration_unix_seconds = try reconcileManagedMountChildren(command, marker, &children);
            last_marker = marker;
            needs_reconcile = false;
        }

        if (reapExitedMountChildren(&children)) {
            needs_reconcile = true;
        }

        changeSourceWait(&change_source, next_expiration_unix_seconds, &needs_reconcile);
    }
}

fn changeSourceWait(change_source: *policy_watch.ChangeSource, next_expiration_unix_seconds: ?i64, needs_reconcile: *bool) void {
    if (!needs_reconcile.*) {
        switch (change_source.wait(reconcileSleepNanos(next_expiration_unix_seconds))) {
            .changed => needs_reconcile.* = true,
            .timeout => {},
        }
    }
}

fn reconcileManagedMountChildren(
    command: RunCommand,
    marker: PolicyMarker,
    children: *std.ArrayListUnmanaged(ManagedMountChild),
) !?i64 {
    _ = marker;

    var policy_lock = config.acquirePolicyLock(allocator, command.policy_path) catch |err| {
        std.log.err("failed to lock policy at {s}: {}", .{ command.policy_path, err });
        return null;
    };
    defer policy_lock.deinit();

    var loaded_policy = config.loadFromFile(allocator, command.policy_path) catch |err| {
        std.log.err("failed to reload policy from {s}: {}", .{ command.policy_path, err });
        return null;
    };
    defer loaded_policy.deinit();

    const trimmed_expired_decisions = loaded_policy.pruneExpiredDecisions(std.time.timestamp()) catch |err| {
        std.log.err("failed to prune expired decisions from {s}: {}", .{ loaded_policy.source_path, err });
        return null;
    };
    if (trimmed_expired_decisions) {
        loaded_policy.saveToFile() catch |err| {
            std.log.err("failed to save pruned policy to {s}: {}", .{ loaded_policy.source_path, err });
            return null;
        };
    }

    const next_expiration_unix_seconds = loaded_policy.nextDecisionExpirationUnixSeconds() catch |err| {
        std.log.err("failed to inspect decision expirations from {s}: {}", .{ loaded_policy.source_path, err });
        return null;
    };

    var compiled_rule_views = loaded_policy.compilePolicyRuleViews(allocator) catch |err| {
        std.log.err("failed to compile policy rules from {s}: {}", .{ loaded_policy.source_path, err });
        return next_expiration_unix_seconds;
    };
    defer compiled_rule_views.deinit();

    var mount_plan = loaded_policy.deriveMountPlan(allocator) catch |err| {
        std.log.err("failed to derive mount plan from {s}: {}", .{ loaded_policy.source_path, err });
        return next_expiration_unix_seconds;
    };
    defer mount_plan.deinit();

    stopManagedMountChildren(children);

    if (mount_plan.paths.len == 0) {
        return next_expiration_unix_seconds;
    }

    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    for (mount_plan.paths) |mount_path| {
        var child = try spawnManagedMountChild(exe_path, command, mount_path);
        children.append(allocator, child) catch |err| {
            std.posix.kill(child.child.id, std.posix.SIG.INT) catch {};
            _ = pollMountChild(&child);
            child.deinit();
            return err;
        };
    }

    return next_expiration_unix_seconds;
}

fn reconcileSleepNanos(next_expiration_unix_seconds: ?i64) u64 {
    const default_sleep_ns = 250 * std.time.ns_per_ms;
    const expires_at = next_expiration_unix_seconds orelse return default_sleep_ns;
    const now = std.time.timestamp();
    if (expires_at <= now) return 0;

    const remaining_seconds: u64 = @intCast(expires_at - now);
    const remaining_ns = remaining_seconds * std.time.ns_per_s;
    return @min(default_sleep_ns, remaining_ns);
}

fn spawnManagedMountChild(
    exe_path: []const u8,
    command: RunCommand,
    mount_path: []const u8,
) !ManagedMountChild {
    const mount_path_owned = try allocator.dupe(u8, mount_path);
    errdefer allocator.free(mount_path_owned);

    const argv = try allocator.alloc([]const u8, 5);
    errdefer allocator.free(argv);

    argv[0] = exe_path;
    argv[1] = "run";
    argv[2] = outcomeArg(command.default_mutation_outcome);
    argv[3] = "--policy";
    argv[4] = command.policy_path;

    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Inherit;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    var env_map = try buildMountChildEnv(command, mount_path_owned);
    defer env_map.deinit();
    child.env_map = &env_map;
    try child.spawn();

    return .{
        .child = child,
        .argv = argv,
        .mount_path = mount_path_owned,
        .alive = true,
    };
}

fn buildMountChildEnv(command: RunCommand, mount_path: []const u8) !std.process.EnvMap {
    var env_map = try std.process.getEnvMap(allocator);
    errdefer env_map.deinit();

    try env_map.put(defaults.internal_mount_path_env, mount_path);
    if (command.status_fifo_path) |status_fifo_path| {
        try env_map.put(defaults.internal_status_fifo_env, status_fifo_path);
    } else {
        _ = env_map.remove(defaults.internal_status_fifo_env);
    }

    return env_map;
}

fn reapExitedMountChildren(children: *std.ArrayListUnmanaged(ManagedMountChild)) bool {
    var reaped_any = false;

    for (children.items) |*runner| {
        if (!runner.alive) continue;

        if (pollMountChild(runner)) |term| {
            runner.alive = false;
            runner.term = term;
            reaped_any = true;

            switch (term) {
                .Exited => |code| std.log.warn("mount child for {s} exited with code {d}", .{ runner.mount_path, code }),
                .Signal => |sig| std.log.warn("mount child for {s} exited on signal {d}", .{ runner.mount_path, sig }),
                else => std.log.warn("mount child for {s} terminated unexpectedly", .{runner.mount_path}),
            }
        }
    }

    return reaped_any;
}

fn pollMountChild(runner: *ManagedMountChild) ?std.process.Child.Term {
    const waited = std.posix.waitpid(runner.child.id, std.posix.W.NOHANG);
    if (waited.pid == 0) return null;
    return termFromWaitStatus(waited.status);
}

fn stopManagedMountChildren(children: *std.ArrayListUnmanaged(ManagedMountChild)) void {
    defer {
        for (children.items) |*runner| {
            runner.deinit();
        }
        children.clearAndFree(allocator);
    }

    if (children.items.len == 0) return;

    for (children.items) |*runner| {
        if (!runner.alive) continue;
        std.posix.kill(runner.child.id, std.posix.SIG.INT) catch {};
    }

    if (waitForManagedChildren(children, 20)) {
        return;
    }

    for (children.items) |*runner| {
        if (!runner.alive) continue;
        bestEffortUnmount(runner.mount_path);
    }

    if (waitForManagedChildren(children, 20)) {
        return;
    }

    for (children.items) |*runner| {
        if (!runner.alive) continue;
        std.posix.kill(runner.child.id, std.posix.SIG.TERM) catch {};
    }

    _ = waitForManagedChildren(children, 20);
}

fn waitForManagedChildren(children: *std.ArrayListUnmanaged(ManagedMountChild), attempts: usize) bool {
    var remaining = true;
    var attempt: usize = 0;

    while (attempt < attempts) : (attempt += 1) {
        remaining = false;

        for (children.items) |*runner| {
            if (!runner.alive) continue;
            if (pollMountChild(runner)) |term| {
                runner.alive = false;
                runner.term = term;
            } else {
                remaining = true;
            }
        }

        if (!remaining) {
            return true;
        }

        std.Thread.sleep(50 * std.time.ns_per_ms);
    }

    return false;
}

fn bestEffortUnmount(mount_path: []const u8) void {
    switch (builtin.os.tag) {
        .macos => {
            _ = runUnmountCommand(&.{ "umount", mount_path });
        },
        .linux => {
            if (!runUnmountCommand(&.{ "fusermount3", "-u", mount_path })) {
                if (!runUnmountCommand(&.{ "fusermount", "-u", mount_path })) {
                    _ = runUnmountCommand(&.{ "umount", mount_path });
                }
            }
        },
        else => {},
    }
}

fn runUnmountCommand(argv: []const []const u8) bool {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
        .max_output_bytes = 4096,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return false,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn signalChildrenForShutdown(children: anytype, signal: u8) void {
    for (children) |runner| {
        if (!runner.alive) continue;
        std.posix.kill(runner.child.id, signal) catch {};
    }
}

fn termFromWaitStatus(status: u32) std.process.Child.Term {
    if ((status & 0x7f) == 0) {
        return .{ .Exited = @intCast((status >> 8) & 0xff) };
    }
    if ((status & 0xff) == 0x7f) {
        return .{ .Stopped = @intCast((status >> 8) & 0xff) };
    }
    return .{ .Signal = @intCast(status & 0x7f) };
}

fn outcomeArg(outcome: policy.Outcome) []const u8 {
    return switch (outcome) {
        .allow => "allow",
        .deny => "deny",
        .prompt => "prompt",
    };
}

const SupervisorSignalHandlers = struct {
    previous_int: std.posix.Sigaction,
    previous_term: std.posix.Sigaction,

    fn restore(self: SupervisorSignalHandlers) void {
        std.posix.sigaction(std.posix.SIG.INT, &self.previous_int, null);
        std.posix.sigaction(std.posix.SIG.TERM, &self.previous_term, null);
        supervisor_shutdown_signal.store(0, .release);
    }
};

fn installSupervisorSignalHandlers() SupervisorSignalHandlers {
    supervisor_shutdown_signal.store(0, .release);

    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = handleSupervisorSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    var previous_int: std.posix.Sigaction = undefined;
    var previous_term: std.posix.Sigaction = undefined;
    std.posix.sigaction(std.posix.SIG.INT, &action, &previous_int);
    std.posix.sigaction(std.posix.SIG.TERM, &action, &previous_term);
    return .{
        .previous_int = previous_int,
        .previous_term = previous_term,
    };
}

fn handleSupervisorSignal(signal_number: i32) callconv(.c) void {
    supervisor_shutdown_signal.store(signal_number, .release);
}

test "reconcileSleepNanos returns default when no expiration is set" {
    const default_ns = 250 * std.time.ns_per_ms;
    try std.testing.expectEqual(@as(u64, default_ns), reconcileSleepNanos(null));
}

test "reconcileSleepNanos returns zero when expiration is in the past" {
    const past = std.time.timestamp() - 60;
    try std.testing.expectEqual(@as(u64, 0), reconcileSleepNanos(past));
}

test "reconcileSleepNanos clamps to remaining time when below default" {
    const future = std.time.timestamp() + 1;
    const ns = reconcileSleepNanos(future);
    try std.testing.expect(ns <= 1 * std.time.ns_per_s);
}

test "outcomeArg maps each policy outcome to its CLI token" {
    try std.testing.expectEqualStrings("allow", outcomeArg(.allow));
    try std.testing.expectEqualStrings("deny", outcomeArg(.deny));
    try std.testing.expectEqualStrings("prompt", outcomeArg(.prompt));
}

test "termFromWaitStatus decodes exit, signal, and stop encodings" {
    const exit_status: u32 = (5 << 8);
    switch (termFromWaitStatus(exit_status)) {
        .Exited => |code| try std.testing.expectEqual(@as(u8, 5), code),
        else => try std.testing.expect(false),
    }

    const signal_status: u32 = 9;
    switch (termFromWaitStatus(signal_status)) {
        .Signal => |sig| try std.testing.expectEqual(@as(u8, 9), sig),
        else => try std.testing.expect(false),
    }

    const stopped_status: u32 = 0x7f | (3 << 8);
    switch (termFromWaitStatus(stopped_status)) {
        .Stopped => |code| try std.testing.expectEqual(@as(u8, 3), code),
        else => try std.testing.expect(false),
    }
}

test "buildMountChildEnv sets mount path and removes status fifo when missing" {
    const command = RunCommand{
        .policy_path = "/tmp/policy.yml",
        .default_mutation_outcome = .deny,
        .prompt_timeout_ms = 100,
        .status_fifo_path = null,
        .mount_path_filter = null,
    };

    var env = try buildMountChildEnv(command, "/tmp/mount");
    defer env.deinit();

    try std.testing.expectEqualStrings("/tmp/mount", env.get(defaults.internal_mount_path_env).?);
    try std.testing.expect(env.get(defaults.internal_status_fifo_env) == null);
}

test "buildMountChildEnv propagates status fifo when provided" {
    const command = RunCommand{
        .policy_path = "/tmp/policy.yml",
        .default_mutation_outcome = .allow,
        .prompt_timeout_ms = 100,
        .status_fifo_path = "/tmp/status.fifo",
        .mount_path_filter = null,
    };

    var env = try buildMountChildEnv(command, "/tmp/mount");
    defer env.deinit();

    try std.testing.expectEqualStrings("/tmp/mount", env.get(defaults.internal_mount_path_env).?);
    try std.testing.expectEqualStrings("/tmp/status.fifo", env.get(defaults.internal_status_fifo_env).?);
}
