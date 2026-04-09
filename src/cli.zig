const std = @import("std");
const agent = @import("agent.zig");
const config = @import("config.zig");
const daemon = @import("daemon.zig");
const enrollment_ops = @import("enrollment.zig");
const filesystem = @import("filesystem.zig");
const policy = @import("policy.zig");
const policy_commands = @import("policy_commands.zig");
const prompt = @import("prompt.zig");
const store = @import("store.zig");
const builtin = @import("builtin");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const allocator = std.heap.page_allocator;
var supervisor_shutdown_signal = std.atomic.Value(i32).init(0);
const internal_mount_path_env = "FILE_SNITCH_INTERNAL_MOUNT_PATH";
const internal_status_fifo_env = "FILE_SNITCH_INTERNAL_STATUS_FIFO";

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    run(args[1..]) catch |err| switch (err) {
        error.InvalidUsage, error.DoctorFailed, error.RunFailed => std.process.exit(1),
        error.DaemonizeFailed => {
            std.debug.print("error: failed to daemonize `run`\n", .{});
            std.process.exit(1);
        },
        error.StoreUnavailable => {
            std.debug.print("error: `pass` was not found; install it or set FILE_SNITCH_PASS_BIN\n", .{});
            std.process.exit(1);
        },
        error.StoreCommandFailed => {
            std.debug.print("error: the `pass` backend command failed\n", .{});
            std.process.exit(1);
        },
        error.ObjectNotFound => {
            std.debug.print("error: guarded object missing from the configured store\n", .{});
            std.process.exit(1);
        },
        error.InvalidStoredObject => {
            std.debug.print("error: guarded object is corrupt or has an unsupported format\n", .{});
            std.process.exit(1);
        },
        else => return err,
    };
}

pub fn run(args: []const []const u8) !void {
    switch (try parseCommand(args)) {
        .help => printUsage(),
        .agent => |command| {
            defer command.deinit(allocator);
            try runAgent(command);
        },
        .run => |command| {
            defer command.deinit(allocator);
            try runWithPolicy(command);
        },
        .enroll => |command| {
            defer command.deinit(allocator);
            try policy_commands.enroll(allocator, command.policy_path, command.target_path);
        },
        .unenroll => |command| {
            defer command.deinit(allocator);
            try policy_commands.unenroll(allocator, command.policy_path, command.target_path);
        },
        .status => |command| {
            defer command.deinit(allocator);
            try policy_commands.status(allocator, command.policy_path);
        },
        .doctor => |command| {
            defer command.deinit(allocator);
            try policy_commands.doctor(allocator, command.policy_path);
        },
    }
}

const Command = union(enum) {
    help,
    agent: AgentCommand,
    run: RunCommand,
    enroll: PathCommand,
    unenroll: PathCommand,
    status: PolicyCommand,
    doctor: PolicyCommand,
};

const AgentCommand = struct {
    socket_path: []const u8,
    run_in_foreground: bool,

    fn deinit(self: AgentCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.socket_path);
    }
};

const RunCommand = struct {
    policy_path: []const u8,
    default_mutation_outcome: policy.Outcome,
    prompt_timeout_ms: u32,
    run_in_foreground: bool,
    status_fifo_path: ?[]const u8 = null,
    mount_path_filter: ?[]const u8 = null,

    fn deinit(self: RunCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.policy_path);
        if (self.status_fifo_path) |path| {
            alloc.free(path);
        }
        if (self.mount_path_filter) |path| {
            alloc.free(path);
        }
    }
};

const PathCommand = struct {
    policy_path: []const u8,
    target_path: []const u8,

    fn deinit(self: PathCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.policy_path);
        alloc.free(self.target_path);
    }
};

const PolicyCommand = struct {
    policy_path: []const u8,

    fn deinit(self: PolicyCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.policy_path);
    }
};

fn parseCommand(args: []const []const u8) !Command {
    if (args.len == 0) {
        printUsage();
        return error.InvalidUsage;
    }

    if (std.mem.eql(u8, args[0], "run")) {
        return .{ .run = try parseRunCommand(args[1..]) };
    }
    if (std.mem.eql(u8, args[0], "agent")) {
        return .{ .agent = try parseAgentCommand(args[1..]) };
    }
    if (std.mem.eql(u8, args[0], "enroll")) {
        return .{ .enroll = try parsePathCommand(args[1..], true) };
    }
    if (std.mem.eql(u8, args[0], "unenroll")) {
        return .{ .unenroll = try parsePathCommand(args[1..], false) };
    }
    if (std.mem.eql(u8, args[0], "status")) {
        return .{ .status = try parsePolicyCommand(args[1..]) };
    }
    if (std.mem.eql(u8, args[0], "doctor")) {
        return .{ .doctor = try parsePolicyCommand(args[1..]) };
    }
    if (std.mem.eql(u8, args[0], "help") or std.mem.eql(u8, args[0], "--help")) {
        return .help;
    }

    printUsage();
    return error.InvalidUsage;
}

fn parseRunCommand(args: []const []const u8) !RunCommand {
    const policy_path = try config.defaultPolicyPathAlloc(allocator);
    errdefer allocator.free(policy_path);

    var command: RunCommand = .{
        .policy_path = policy_path,
        .default_mutation_outcome = .deny,
        .prompt_timeout_ms = try loadPromptTimeoutMs(),
        .run_in_foreground = undefined,
        .status_fifo_path = try loadOptionalInternalPath(internal_status_fifo_env),
        .mount_path_filter = try loadOptionalInternalPath(internal_mount_path_env),
    };
    errdefer command.deinit(allocator);

    var selected_execution_mode: ?bool = null;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];

        if (parseOutcome(arg)) |outcome| {
            command.default_mutation_outcome = outcome;
            continue;
        }
        if (std.mem.eql(u8, arg, "--foreground")) {
            if (selected_execution_mode != null) return invalidUsage("error: choose either --foreground or --daemon\n", .{});
            selected_execution_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--daemon")) {
            if (selected_execution_mode != null) return invalidUsage("error: choose either --foreground or --daemon\n", .{});
            selected_execution_mode = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--policy")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            allocator.free(command.policy_path);
            command.policy_path = try resolvePathArgument(args[index]);
            continue;
        }
        printUsage();
        return error.InvalidUsage;
    }

    if (selected_execution_mode == null) {
        return invalidUsage("error: `run` requires exactly one of --foreground or --daemon\n", .{});
    }
    command.run_in_foreground = selected_execution_mode.?;

    return command;
}

fn parseAgentCommand(args: []const []const u8) !AgentCommand {
    const socket_path = try agent.defaultSocketPathAlloc(allocator);
    errdefer allocator.free(socket_path);

    var command: AgentCommand = .{
        .socket_path = socket_path,
        .run_in_foreground = undefined,
    };
    errdefer command.deinit(allocator);

    var selected_execution_mode: ?bool = null;
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];

        if (std.mem.eql(u8, arg, "--foreground")) {
            if (selected_execution_mode != null) return invalidUsage("error: choose either --foreground or --daemon\n", .{});
            selected_execution_mode = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--daemon")) {
            if (selected_execution_mode != null) return invalidUsage("error: choose either --foreground or --daemon\n", .{});
            selected_execution_mode = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--socket")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            allocator.free(command.socket_path);
            command.socket_path = try resolvePathArgument(args[index]);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
    }

    if (selected_execution_mode == null) {
        return invalidUsage("error: `agent` requires exactly one of --foreground or --daemon\n", .{});
    }

    command.run_in_foreground = selected_execution_mode.?;
    if (!command.run_in_foreground) {
        return invalidUsage("error: the TTY agent currently requires --foreground\n", .{});
    }

    return command;
}

fn parsePolicyCommand(args: []const []const u8) !PolicyCommand {
    const policy_path = try config.defaultPolicyPathAlloc(allocator);
    errdefer allocator.free(policy_path);

    var command: PolicyCommand = .{
        .policy_path = policy_path,
    };
    errdefer command.deinit(allocator);

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--policy")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            allocator.free(command.policy_path);
            command.policy_path = try resolvePathArgument(args[index]);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
    }

    return command;
}

fn parsePathCommand(args: []const []const u8, require_existing_target: bool) !PathCommand {
    if (args.len == 0) {
        printUsage();
        return error.InvalidUsage;
    }

    const target_path = if (require_existing_target)
        try resolveExistingRegularFileArgument("target file", args[0])
    else
        try resolveEnrolledPathArgument(args[0]);
    errdefer allocator.free(target_path);

    const policy_path = try config.defaultPolicyPathAlloc(allocator);
    errdefer allocator.free(policy_path);

    var command: PathCommand = .{
        .policy_path = policy_path,
        .target_path = target_path,
    };
    errdefer command.deinit(allocator);

    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--policy")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            allocator.free(command.policy_path);
            command.policy_path = try resolvePathArgument(args[index]);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
    }

    return command;
}

fn parseOutcome(arg: []const u8) ?policy.Outcome {
    if (std.mem.eql(u8, arg, "mutable") or std.mem.eql(u8, arg, "allow")) return .allow;
    if (std.mem.eql(u8, arg, "readonly") or std.mem.eql(u8, arg, "deny")) return .deny;
    if (std.mem.eql(u8, arg, "prompt")) return .prompt;
    return null;
}

fn runWithPolicy(command: RunCommand) !void {
    if (command.mount_path_filter == null and !command.run_in_foreground) {
        var foreground_command = command;
        foreground_command.run_in_foreground = true;
        try daemonizeSupervisor();
        try reconcilePolicyInForeground(foreground_command);
        return;
    }

    if (command.mount_path_filter == null and command.run_in_foreground) {
        try reconcilePolicyInForeground(command);
        return;
    }

    try runStaticPolicy(command);
}

fn runAgent(command: AgentCommand) !void {
    std.debug.assert(command.run_in_foreground);

    var cli_context = prompt.CliContext{
        .timeout_ms = try loadPromptTimeoutMs(),
    };
    var tty_agent_context = agent.TtyAgentContext{
        .allocator = allocator,
        .socket_path = command.socket_path,
        .cli_context = &cli_context,
    };
    try agent.runTtyAgent(&tty_agent_context);
}

fn daemonizeSupervisor() !void {
    const child_pid = std.posix.fork() catch return error.DaemonizeFailed;
    if (child_pid != 0) {
        std.process.exit(0);
    }

    _ = std.posix.setsid() catch return error.DaemonizeFailed;
}

fn runStaticPolicy(command: RunCommand) !void {
    var loaded_policy = try config.loadFromFile(allocator, command.policy_path);
    defer loaded_policy.deinit();

    if (!loaded_policy.hasEnrollments()) {
        std.debug.print("file-snitch: no enrollments configured in {s}; nothing to do\n", .{loaded_policy.source_path});
        return;
    }

    var compiled_rules = try loaded_policy.compilePolicyRules(allocator);
    defer compiled_rules.deinit();

    var mount_plan = try loaded_policy.deriveMountPlan(allocator);
    defer mount_plan.deinit();

    if (command.mount_path_filter) |filtered_mount| {
        var filtered: usize = 0;
        for (mount_plan.paths) |mount_path| {
            if (std.mem.eql(u8, mount_path, filtered_mount)) {
                mount_plan.paths[0] = mount_path;
                filtered = 1;
                break;
            }
        }
        mount_plan.paths.len = filtered;
        if (filtered == 0) {
            std.debug.print("error: requested mount path is not part of the current plan: {s}\n", .{filtered_mount});
            return error.InvalidUsage;
        }
    }

    if (mount_plan.paths.len == 0) {
        std.debug.print("file-snitch: no planned mounts derived from {s}; nothing to do\n", .{loaded_policy.source_path});
        return;
    }

    if (!command.run_in_foreground and mount_plan.paths.len != 1) {
        std.debug.print(
            "error: multi-mount `run --daemon` is not supported yet; got {d} planned mounts in {s}\n",
            .{ mount_plan.paths.len, loaded_policy.source_path },
        );
        return error.InvalidUsage;
    }

    if (mount_plan.paths.len > 1 and command.mount_path_filter == null) {
        try superviseMountChildren(command, mount_plan.paths);
        return;
    }

    const status_output_file = if (command.status_fifo_path) |path|
        try openStatusFifo(path)
    else
        null;
    defer {
        if (status_output_file) |file| file.close();
    }

    const prompt_requester = if (command.default_mutation_outcome == .prompt)
        agent.RequesterContext{
            .allocator = allocator,
            .socket_path = try agent.defaultSocketPathAlloc(allocator),
            .timeout_ms = command.prompt_timeout_ms,
        }
    else
        null;
    defer if (prompt_requester) |requester| allocator.free(requester.socket_path);

    const PlannedMount = struct {
        mount_path: []const u8,
        guarded_entries: []filesystem.GuardedEntryConfig,
    };

    var planned_mounts = try allocator.alloc(PlannedMount, mount_plan.paths.len);
    defer {
        for (planned_mounts) |planned| {
            for (planned.guarded_entries) |entry| {
                allocator.free(entry.relative_path);
                allocator.free(entry.object_id);
                allocator.free(entry.lock_anchor_path);
            }
            allocator.free(planned.guarded_entries);
        }
        allocator.free(planned_mounts);
    }

    var guarded_store = try store.Backend.initPass(allocator);
    errdefer guarded_store.deinit(allocator);

    for (mount_plan.paths, 0..) |mount_path, mount_index| {
        var entry_count: usize = 0;
        for (loaded_policy.enrollments) |enrollment| {
            if (coversEnrollmentPath(mount_path, enrollment.path)) {
                entry_count += 1;
            }
        }

        var guarded_entries = try allocator.alloc(filesystem.GuardedEntryConfig, entry_count);
        var entry_index: usize = 0;
        for (loaded_policy.enrollments) |enrollment| {
            if (!coversEnrollmentPath(mount_path, enrollment.path)) continue;
            guarded_entries[entry_index] = .{
                .relative_path = try relativeEnrollmentPath(allocator, mount_path, enrollment.path),
                .object_id = try allocator.dupe(u8, enrollment.object_id),
                .lock_anchor_path = try enrollment_ops.defaultLockAnchorPathAlloc(allocator, enrollment.object_id),
            };
            entry_index += 1;
        }

        planned_mounts[mount_index] = .{
            .mount_path = mount_path,
            .guarded_entries = guarded_entries,
        };
    }

    if (planned_mounts.len == 1) {
        try daemon.mountEnrolledParent(allocator, .{
            .mount_path = planned_mounts[0].mount_path,
            .guarded_entries = planned_mounts[0].guarded_entries,
            .guarded_store = guarded_store,
            .run_in_foreground = command.run_in_foreground,
            .default_mutation_outcome = command.default_mutation_outcome,
            .policy_rules = compiled_rules.items,
            .prompt_broker = if (command.default_mutation_outcome == .prompt)
                agent.socketBroker(@constCast(&prompt_requester.?))
            else
                null,
            .status_output_file = status_output_file,
            .audit_output_file = std.fs.File.stdout(),
        });
        return;
    }
}

fn resolveExistingRegularFileArgument(label: []const u8, raw_path: []const u8) ![]const u8 {
    const resolved = std.fs.realpathAlloc(allocator, raw_path) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: {s} does not exist: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        else => return err,
    };
    errdefer allocator.free(resolved);

    switch (enrollment_ops.pathKind(resolved)) {
        .file => {},
        .directory => return invalidUsageWithOwnedPath("error: target file is a directory: {s}\n", resolved),
        .other => return invalidUsageWithOwnedPath("error: target file is not a regular file: {s}\n", resolved),
        .missing => return invalidUsageWithOwnedPath("error: target file does not exist: {s}\n", resolved),
    }

    try requireSupportedEnrollmentTargetPath(label, resolved);
    return resolved;
}

fn resolvePathArgument(raw_path: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(raw_path)) {
        return allocator.dupe(u8, raw_path);
    }

    const cwd = try std.fs.realpathAlloc(allocator, ".");
    defer allocator.free(cwd);
    return std.fs.path.resolve(allocator, &.{ cwd, raw_path });
}

fn resolveEnrolledPathArgument(raw_path: []const u8) ![]const u8 {
    const lexical_path = try resolvePathArgument(raw_path);
    errdefer allocator.free(lexical_path);

    if (enrollment_ops.pathExists(lexical_path)) {
        const canonical = std.fs.realpathAlloc(allocator, lexical_path) catch |err| switch (err) {
            else => return err,
        };
        allocator.free(lexical_path);
        return canonical;
    }

    const parent_dir = std.fs.path.dirname(lexical_path) orelse {
        std.debug.print("error: invalid target path: {s}\n", .{lexical_path});
        return error.InvalidUsage;
    };
    const canonical_parent = std.fs.realpathAlloc(allocator, parent_dir) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: parent directory does not exist: {s}\n", .{parent_dir});
            return error.InvalidUsage;
        },
        else => return err,
    };
    defer allocator.free(canonical_parent);

    const canonical = try std.fs.path.join(allocator, &.{ canonical_parent, std.fs.path.basename(lexical_path) });
    allocator.free(lexical_path);
    return canonical;
}

fn requireSupportedEnrollmentTargetPath(label: []const u8, target_path: []const u8) !void {
    const home_dir = try enrollment_ops.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);

    if (!enrollment_ops.pathIsWithinDirectory(target_path, home_dir)) {
        std.debug.print(
            "error: {s} is outside the current user's home directory: {s}\n",
            .{ label, target_path },
        );
        std.debug.print(
            "file-snitch currently targets a single user's home-directory secrets\n",
            .{},
        );
        return error.InvalidUsage;
    }

    const owned_by_current_user = enrollment_ops.pathOwnedByCurrentUser(target_path) catch |err| switch (err) {
        else => return err,
    };
    if (!owned_by_current_user) {
        std.debug.print(
            "error: {s} is not owned by the current user: {s}\n",
            .{ label, target_path },
        );
        std.debug.print(
            "file-snitch currently targets one user's own secret-bearing files\n",
            .{},
        );
        return error.InvalidUsage;
    }
}

fn loadPromptTimeoutMs() !u32 {
    const raw_value = std.process.getEnvVarOwned(allocator, "FILE_SNITCH_PROMPT_TIMEOUT_MS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return 5_000,
        else => return err,
    };
    defer allocator.free(raw_value);

    return std.fmt.parseInt(u32, raw_value, 10);
}

fn loadOptionalInternalPath(env_name: []const u8) !?[]const u8 {
    const raw_value = std.process.getEnvVarOwned(allocator, env_name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return null,
        else => return err,
    };
    errdefer allocator.free(raw_value);

    const resolved = try resolvePathArgument(raw_value);
    allocator.free(raw_value);
    return resolved;
}

fn openStatusFifo(path: []const u8) !std.fs.File {
    const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => return invalidUsage("error: status fifo does not exist: {s}\n", .{path}),
        else => return err,
    };

    if (stat.kind != .named_pipe) {
        return invalidUsage("error: status fifo is not a named pipe: {s}\n", .{path});
    }

    return std.fs.cwd().openFile(path, .{ .mode = .write_only });
}

fn relativeEnrollmentPath(
    alloc: std.mem.Allocator,
    mount_path: []const u8,
    enrollment_path: []const u8,
) ![]u8 {
    if (!std.mem.startsWith(u8, enrollment_path, mount_path)) {
        return error.InvalidPath;
    }
    if (enrollment_path.len <= mount_path.len or enrollment_path[mount_path.len] != '/') {
        return error.InvalidPath;
    }
    return alloc.dupe(u8, enrollment_path[mount_path.len + 1 ..]);
}

fn coversEnrollmentPath(mount_path: []const u8, enrollment_path: []const u8) bool {
    return std.mem.startsWith(u8, enrollment_path, mount_path) and
        enrollment_path.len > mount_path.len and
        enrollment_path[mount_path.len] == '/';
}

fn superviseMountChildren(command: RunCommand, mount_paths: []const []const u8) !void {
    const signal_handlers = installSupervisorSignalHandlers();
    defer signal_handlers.restore();

    const exe_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(exe_path);

    const ChildRunner = struct {
        child: std.process.Child,
        argv: []const []const u8,
        mount_path: []const u8,
        alive: bool = false,
        term: ?std.process.Child.Term = null,
    };

    var children = try allocator.alloc(ChildRunner, mount_paths.len);
    defer {
        for (children) |runner| {
            allocator.free(runner.argv);
        }
        allocator.free(children);
    }

    for (mount_paths, 0..) |mount_path, index| {
        const argv = try allocator.alloc([]const u8, 6);
        argv[0] = exe_path;
        argv[1] = "run";
        argv[2] = outcomeArg(command.default_mutation_outcome);
        argv[3] = "--foreground";
        argv[4] = "--policy";
        argv[5] = command.policy_path;

        var child = std.process.Child.init(argv, allocator);
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;
        var env_map = try buildMountChildEnv(command, mount_path);
        defer env_map.deinit();
        child.env_map = &env_map;

        children[index] = .{
            .child = child,
            .argv = argv,
            .mount_path = mount_path,
        };
        try children[index].child.spawn();
        children[index].alive = true;
    }

    var remaining = children.len;
    var shutdown_requested = false;
    while (remaining > 0) {
        const shutdown_signal = supervisor_shutdown_signal.load(.acquire);
        if (shutdown_signal != 0 and !shutdown_requested) {
            shutdown_requested = true;
            signalChildrenForShutdown(children, @intCast(shutdown_signal));
        }

        var reaped_any = false;
        for (children, 0..) |runner, child_index| {
            if (!runner.alive) continue;

            const waited = std.posix.waitpid(runner.child.id, std.posix.W.NOHANG);
            if (waited.pid == 0) continue;

            reaped_any = true;
            children[child_index].alive = false;
            children[child_index].term = termFromWaitStatus(waited.status);
            remaining -= 1;

            if (!shutdown_requested) {
                shutdown_requested = true;
                signalChildrenForShutdown(children, std.posix.SIG.INT);
            }
        }

        if (!reaped_any and remaining > 0) {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }

    for (children) |runner| {
        switch (runner.term orelse continue) {
            .Exited => |code| {
                if (code != 0) {
                    std.debug.print("error: mount child exited non-zero for {s}: {d}\n", .{ runner.mount_path, code });
                    return error.RunFailed;
                }
            },
            .Signal => |sig| {
                if (sig != std.posix.SIG.INT and sig != std.posix.SIG.TERM) {
                    std.debug.print("error: mount child died from signal for {s}: {d}\n", .{ runner.mount_path, sig });
                    return error.RunFailed;
                }
            },
            else => {
                std.debug.print("error: mount child terminated unexpectedly for {s}\n", .{runner.mount_path});
                return error.RunFailed;
            },
        }
    }
}

const PolicyMarker = struct {
    exists: bool,
    size: u64 = 0,
    mtime: i128 = 0,

    fn eql(a: PolicyMarker, b: PolicyMarker) bool {
        return a.exists == b.exists and
            a.size == b.size and
            a.mtime == b.mtime;
    }
};

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

fn reconcilePolicyInForeground(command: RunCommand) !void {
    const signal_handlers = installSupervisorSignalHandlers();
    defer signal_handlers.restore();

    var children: std.ArrayListUnmanaged(ManagedMountChild) = .{};
    defer stopManagedMountChildren(&children);

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

        const marker = currentPolicyMarker(command.policy_path);
        if (needs_reconcile or last_marker == null or !last_marker.?.eql(marker)) {
            next_expiration_unix_seconds = try reconcileManagedMountChildren(command, marker, &children);
            last_marker = marker;
            needs_reconcile = false;
        }

        if (reapExitedMountChildren(&children)) {
            needs_reconcile = true;
        }

        std.Thread.sleep(reconcileSleepNanos(next_expiration_unix_seconds));
    }
}

fn currentPolicyMarker(policy_path: []const u8) PolicyMarker {
    const stat = std.fs.cwd().statFile(policy_path) catch |err| switch (err) {
        error.FileNotFound => return .{ .exists = false },
        else => return .{ .exists = false },
    };

    return .{
        .exists = true,
        .size = stat.size,
        .mtime = stat.mtime,
    };
}

fn reconcileManagedMountChildren(
    command: RunCommand,
    marker: PolicyMarker,
    children: *std.ArrayListUnmanaged(ManagedMountChild),
) !?i64 {
    _ = marker;

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

    var compiled_rules = loaded_policy.compilePolicyRules(allocator) catch |err| {
        std.log.err("failed to compile policy rules from {s}: {}", .{ loaded_policy.source_path, err });
        return next_expiration_unix_seconds;
    };
    defer compiled_rules.deinit();

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
        errdefer child.deinit();
        try children.append(allocator, child);
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

    const argv = try allocator.alloc([]const u8, 6);
    errdefer allocator.free(argv);

    argv[0] = exe_path;
    argv[1] = "run";
    argv[2] = outcomeArg(command.default_mutation_outcome);
    argv[3] = "--foreground";
    argv[4] = "--policy";
    argv[5] = command.policy_path;

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

    try env_map.put(internal_mount_path_env, mount_path);
    if (command.status_fifo_path) |status_fifo_path| {
        try env_map.put(internal_status_fifo_env, status_fifo_path);
    } else {
        _ = env_map.remove(internal_status_fifo_env);
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

fn invalidUsage(comptime format: []const u8, args: anytype) error{InvalidUsage} {
    std.debug.print(format, args);
    return error.InvalidUsage;
}

fn invalidUsageWithOwnedPath(comptime format: []const u8, owned_path: []const u8) error{InvalidUsage} {
    defer allocator.free(owned_path);
    std.debug.print(format, .{owned_path});
    return error.InvalidUsage;
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  file-snitch agent (--daemon|--foreground) [--socket <path>]
        \\  file-snitch run [allow|deny|prompt] (--daemon|--foreground) [--policy <path>]
        \\  file-snitch enroll <path> [--policy <path>]
        \\  file-snitch unenroll <path> [--policy <path>]
        \\  file-snitch status [--policy <path>]
        \\  file-snitch doctor [--policy <path>]
        \\
        \\notes:
        \\  - `agent --foreground` starts the local TTY decision agent on a Unix socket
        \\  - `run` is the long-running daemon entrypoint and requires explicit foreground/background mode
        \\  - foreground and daemon mode now share the same policy-reconciliation model
        \\  - `run` stays alive on an empty policy and reconciles mount workers as `policy.yml` changes
        \\  - prompt mode now talks to the local agent socket instead of reading from the daemon's stdin
        \\  - `enroll` migrates the plaintext file into the guarded store and records it in `policy.yml`
        \\  - `unenroll` restores the guarded file to its original path and removes remembered decisions for that path
        \\  - `status` and `doctor` inspect `policy.yml`; `doctor` exits non-zero on actionable problems
        \\
    , .{});
}
