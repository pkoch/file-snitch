const std = @import("std");
const agent = @import("agent.zig");
const app_meta = @import("app_meta.zig");
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
        error.StoreUnavailable => {
            std.debug.print("error: `pass` was not found; install it or set FILE_SNITCH_PASS_BIN\n", .{});
            std.debug.print("hint: `file-snitch doctor` will also report the detected pass command and runtime state\n", .{});
            std.process.exit(1);
        },
        error.StoreCommandFailed => {
            std.debug.print("error: the `pass` backend command failed\n", .{});
            std.debug.print("hint: run `pass ls` directly and fix that first, then rerun `file-snitch doctor`\n", .{});
            std.process.exit(1);
        },
        error.ObjectNotFound => {
            std.debug.print("error: guarded object missing from the configured store\n", .{});
            std.debug.print("hint: run `file-snitch doctor` to identify the missing store entry or broken enrollment\n", .{});
            std.process.exit(1);
        },
        error.InvalidStoredObject => {
            std.debug.print("error: guarded object is corrupt or has an unsupported format\n", .{});
            std.debug.print("hint: run `file-snitch doctor` and inspect the affected `pass:file-snitch/...` entry before reenrolling\n", .{});
            std.process.exit(1);
        },
        error.SocketPathInUse => {
            std.debug.print("error: another file-snitch agent is already using the configured socket path\n", .{});
            std.debug.print("hint: stop the existing agent or choose a different `--socket` path\n", .{});
            std.process.exit(1);
        },
        error.InvalidSocketPath => {
            std.debug.print("error: the configured agent socket path points at a non-socket file\n", .{});
            std.debug.print("hint: remove or rename that file, or choose a different `--socket` path\n", .{});
            std.process.exit(1);
        },
        else => return err,
    };
}

pub fn run(args: []const []const u8) !void {
    switch (try parseCommand(args)) {
        .help => printUsage(),
        .version => printVersion(),
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
            try policy_commands.doctor(allocator, .{
                .policy_path = command.policy_path,
                .export_debug_dossier_path = command.export_debug_dossier_path,
            });
        },
    }
}

const Command = union(enum) {
    help,
    version,
    agent: AgentCommand,
    run: RunCommand,
    enroll: PathCommand,
    unenroll: PathCommand,
    status: PolicyCommand,
    doctor: DoctorCommand,
};

const AgentCommand = struct {
    socket_path: []const u8,
    frontend_kind: agent.FrontendKind,
    tty_path: ?[]const u8 = null,

    fn deinit(self: AgentCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.socket_path);
        if (self.tty_path) |path| {
            alloc.free(path);
        }
    }
};

const RunCommand = struct {
    policy_path: []const u8,
    default_mutation_outcome: policy.Outcome,
    prompt_timeout_ms: u32,
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

const DoctorCommand = struct {
    policy_path: []const u8,
    export_debug_dossier_path: ?[]const u8 = null,

    fn deinit(self: DoctorCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.policy_path);
        if (self.export_debug_dossier_path) |path| {
            alloc.free(path);
        }
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
        return .{ .doctor = try parseDoctorCommand(args[1..]) };
    }
    if (std.mem.eql(u8, args[0], "--version") or std.mem.eql(u8, args[0], "-V") or std.mem.eql(u8, args[0], "version")) {
        return .version;
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
        .status_fifo_path = try loadOptionalInternalPath(internal_status_fifo_env),
        .mount_path_filter = try loadOptionalInternalPath(internal_mount_path_env),
    };
    errdefer command.deinit(allocator);

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];

        if (parseOutcome(arg)) |outcome| {
            command.default_mutation_outcome = outcome;
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

    return command;
}

fn parseAgentCommand(args: []const []const u8) !AgentCommand {
    const socket_path = try agent.defaultSocketPathAlloc(allocator);
    errdefer allocator.free(socket_path);

    var command: AgentCommand = .{
        .socket_path = socket_path,
        .frontend_kind = .terminal_pinentry,
        .tty_path = null,
    };
    errdefer command.deinit(allocator);

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
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
        if (std.mem.eql(u8, arg, "--frontend")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            command.frontend_kind = parseFrontendKind(args[index]) orelse {
                std.debug.print("error: unsupported agent frontend: {s}\n", .{args[index]});
                return error.InvalidUsage;
            };
            continue;
        }
        if (std.mem.eql(u8, arg, "--tty")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            if (command.tty_path) |path| allocator.free(path);
            command.tty_path = try resolvePathArgument(args[index]);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
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

fn parseDoctorCommand(args: []const []const u8) !DoctorCommand {
    const policy_path = try config.defaultPolicyPathAlloc(allocator);
    errdefer allocator.free(policy_path);

    var command: DoctorCommand = .{
        .policy_path = policy_path,
        .export_debug_dossier_path = null,
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
        if (std.mem.eql(u8, args[index], "--export-debug-dossier")) {
            index += 1;
            if (index >= args.len) {
                return invalidUsage(
                    "error: `doctor --export-debug-dossier` requires an output path\n",
                    .{},
                );
            }
            if (command.export_debug_dossier_path) |path| allocator.free(path);
            command.export_debug_dossier_path = try resolvePathArgument(args[index]);
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
    if (command.mount_path_filter == null) {
        try reconcilePolicyInForeground(command);
        return;
    }

    try runStaticPolicy(command);
}

fn runAgent(command: AgentCommand) !void {
    const timeout_ms = try loadPromptTimeoutMs();
    var cli_context = prompt.CliContext{
        .timeout_ms = timeout_ms,
    };

    var derived_osascript_path: ?[]const u8 = null;
    defer if (derived_osascript_path) |path| allocator.free(path);
    var derived_zenity_path: ?[]const u8 = null;
    defer if (derived_zenity_path) |path| allocator.free(path);

    var terminal_pinentry_context: ?agent.TerminalPinentryContext = null;
    var macos_ui_context: ?agent.MacosUiContext = null;
    var linux_ui_context: ?agent.LinuxUiContext = null;
    const frontend = switch (command.frontend_kind) {
        .terminal_pinentry => blk: {
            const tty_path = if (command.tty_path) |path| path else null;

            terminal_pinentry_context = .{
                .allocator = allocator,
                .timeout_ms = timeout_ms,
                .tty_path = tty_path,
                .inherited_cli_context = if (tty_path == null) &cli_context else null,
            };
            break :blk agent.terminalPinentryFrontend(&terminal_pinentry_context.?);
        },
        .macos_ui => blk: {
            if (command.tty_path != null) {
                return invalidUsage(
                    "error: `agent --frontend macos-ui` does not accept --tty\n",
                    .{},
                );
            }

            derived_osascript_path = try agent.defaultOsascriptPathAlloc(allocator);
            macos_ui_context = .{
                .allocator = allocator,
                .timeout_ms = timeout_ms,
                .osascript_path = derived_osascript_path.?,
            };
            break :blk agent.macosUiFrontend(&macos_ui_context.?);
        },
        .linux_ui => blk: {
            if (command.tty_path != null) {
                return invalidUsage(
                    "error: `agent --frontend linux-ui` does not accept --tty\n",
                    .{},
                );
            }

            derived_zenity_path = try agent.defaultZenityPathAlloc(allocator);
            linux_ui_context = .{
                .allocator = allocator,
                .timeout_ms = timeout_ms,
                .zenity_path = derived_zenity_path.?,
            };
            break :blk agent.linuxUiFrontend(&linux_ui_context.?);
        },
    };

    var service_context = agent.AgentServiceContext{
        .allocator = allocator,
        .socket_path = command.socket_path,
        .frontend = frontend,
    };

    try agent.runAgentService(&service_context);
}

fn runStaticPolicy(command: RunCommand) !void {
    var loaded_policy = try config.loadFromFile(allocator, command.policy_path);
    defer loaded_policy.deinit();

    if (!loaded_policy.hasEnrollments()) {
        std.debug.print("file-snitch: no enrollments configured in {s}; nothing to do\n", .{loaded_policy.source_path});
        return;
    }

    var compiled_rule_views = try loaded_policy.compilePolicyRuleViews(allocator);
    defer compiled_rule_views.deinit();

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
            .policy_path = command.policy_path,
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
            .run_in_foreground = true,
            .default_mutation_outcome = command.default_mutation_outcome,
            .policy_path = command.policy_path,
            .policy_rule_views = compiled_rule_views.items,
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

fn parseFrontendKind(raw: []const u8) ?agent.FrontendKind {
    if (std.mem.eql(u8, raw, "terminal-pinentry")) return .terminal_pinentry;
    if (std.mem.eql(u8, raw, "macos-ui")) return .macos_ui;
    if (std.mem.eql(u8, raw, "linux-ui")) return .linux_ui;
    return null;
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
        const argv = try allocator.alloc([]const u8, 5);
        argv[0] = exe_path;
        argv[1] = "run";
        argv[2] = outcomeArg(command.default_mutation_outcome);
        argv[3] = "--policy";
        argv[4] = command.policy_path;

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

const PolicyMarker = config.PolicyMarker;

const PolicyWatchOutcome = enum {
    timeout,
    changed,
};

const LinuxPolicyWatcher = if (builtin.os.tag == .linux) struct {
    fd: std.posix.fd_t,
    watch_descriptor: i32,
    filename: []u8,

    fn deinit(self: *LinuxPolicyWatcher) void {
        if (builtin.os.tag == .linux) {
            std.posix.inotify_rm_watch(self.fd, self.watch_descriptor);
            std.posix.close(self.fd);
        }
        allocator.free(self.filename);
        self.* = undefined;
    }

    fn wait(self: *LinuxPolicyWatcher, timeout_ns: u64) !PolicyWatchOutcome {
        if (builtin.os.tag != .linux) unreachable;

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = self.fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&poll_fds, nanosToPollTimeoutMs(timeout_ns));
        if (ready == 0) return .timeout;

        var buffer: [4096]u8 align(@alignOf(std.os.linux.inotify_event)) = undefined;
        const bytes_read = try std.posix.read(self.fd, &buffer);
        if (bytes_read == 0) return .timeout;

        var offset: usize = 0;
        while (offset + @sizeOf(std.os.linux.inotify_event) <= bytes_read) {
            const event: *const std.os.linux.inotify_event = @ptrCast(@alignCast(buffer[offset .. offset + @sizeOf(std.os.linux.inotify_event)]));
            const event_size = @sizeOf(std.os.linux.inotify_event) + event.len;
            if (offset + event_size > bytes_read) break;
            offset += event_size;

            const event_name = event.getName() orelse continue;
            if (!std.mem.eql(u8, std.mem.sliceTo(event_name, 0), self.filename)) continue;
            return .changed;
        }

        return .timeout;
    }
} else struct {
    fn deinit(self: *LinuxPolicyWatcher) void {
        _ = self;
        unreachable;
    }

    fn wait(self: *LinuxPolicyWatcher, timeout_ns: u64) !PolicyWatchOutcome {
        _ = self;
        _ = timeout_ns;
        unreachable;
    }
};

const DarwinPolicyWatcher = if (builtin.os.tag == .macos) struct {
    kqueue_fd: std.posix.fd_t,
    directory_fd: std.posix.fd_t,

    fn deinit(self: *DarwinPolicyWatcher) void {
        std.posix.close(self.directory_fd);
        std.posix.close(self.kqueue_fd);
        self.* = undefined;
    }

    fn wait(self: *DarwinPolicyWatcher, timeout_ns: u64) !PolicyWatchOutcome {
        var timespec = nanosToTimespec(timeout_ns);
        var event_buffer: [1]std.posix.Kevent = undefined;
        const count = try std.posix.kevent(self.kqueue_fd, &.{}, &event_buffer, &timespec);
        if (count == 0) return .timeout;
        return .changed;
    }
} else struct {
    fn deinit(self: *DarwinPolicyWatcher) void {
        _ = self;
        unreachable;
    }

    fn wait(self: *DarwinPolicyWatcher, timeout_ns: u64) !PolicyWatchOutcome {
        _ = self;
        _ = timeout_ns;
        unreachable;
    }
};

const PolicyChangeSource = union(enum) {
    polling,
    linux_inotify: LinuxPolicyWatcher,
    darwin_kqueue: DarwinPolicyWatcher,

    fn init(policy_path: []const u8) PolicyChangeSource {
        return switch (builtin.os.tag) {
            .linux => initLinuxPolicyWatcher(policy_path) catch |err| {
                std.log.warn("falling back to polling for policy changes at {s}: {}", .{ policy_path, err });
                return .polling;
            },
            .macos => initDarwinPolicyWatcher(policy_path) catch |err| {
                std.log.warn("falling back to polling for policy changes at {s}: {}", .{ policy_path, err });
                return .polling;
            },
            else => .polling,
        };
    }

    fn deinit(self: *PolicyChangeSource) void {
        switch (self.*) {
            .polling => {},
            .linux_inotify => |*watcher| watcher.deinit(),
            .darwin_kqueue => |*watcher| watcher.deinit(),
        }
    }

    fn wait(self: *PolicyChangeSource, timeout_ns: u64) PolicyWatchOutcome {
        return switch (self.*) {
            .polling => {
                std.Thread.sleep(timeout_ns);
                return .timeout;
            },
            .linux_inotify => |*watcher| watcher.wait(timeout_ns) catch |err| {
                std.log.warn("policy watcher failed; falling back to polling: {}", .{err});
                watcher.deinit();
                self.* = .polling;
                std.Thread.sleep(timeout_ns);
                return .timeout;
            },
            .darwin_kqueue => |*watcher| watcher.wait(timeout_ns) catch |err| {
                std.log.warn("policy watcher failed; falling back to polling: {}", .{err});
                watcher.deinit();
                self.* = .polling;
                std.Thread.sleep(timeout_ns);
                return .timeout;
            },
        };
    }
};

fn initLinuxPolicyWatcher(policy_path: []const u8) !PolicyChangeSource {
    if (builtin.os.tag != .linux) unreachable;

    const watch_path = try splitPolicyWatchPath(policy_path);
    defer allocator.free(watch_path.directory_path);

    const fd = try std.posix.inotify_init1(std.os.linux.IN.CLOEXEC);
    errdefer std.posix.close(fd);

    const watch_mask =
        std.os.linux.IN.CLOSE_WRITE |
        std.os.linux.IN.CREATE |
        std.os.linux.IN.DELETE |
        std.os.linux.IN.MOVED_TO |
        std.os.linux.IN.MOVE_SELF |
        std.os.linux.IN.DELETE_SELF;
    const watch_descriptor = try std.posix.inotify_add_watch(fd, watch_path.directory_path, watch_mask);
    errdefer std.posix.inotify_rm_watch(fd, watch_descriptor);

    return .{ .linux_inotify = .{
        .fd = fd,
        .watch_descriptor = watch_descriptor,
        .filename = try allocator.dupe(u8, watch_path.basename),
    } };
}

fn initDarwinPolicyWatcher(policy_path: []const u8) !PolicyChangeSource {
    const watch_path = try splitPolicyWatchPath(policy_path);
    defer allocator.free(watch_path.directory_path);

    const kqueue_fd = try std.posix.kqueue();
    errdefer std.posix.close(kqueue_fd);

    const directory_flags = comptime flags: {
        var open_flags = std.posix.O{
            .ACCMODE = .RDONLY,
            .CLOEXEC = true,
            .DIRECTORY = true,
        };
        if (@hasField(std.posix.O, "EVTONLY")) open_flags.EVTONLY = true;
        if (@hasField(std.posix.O, "PATH")) open_flags.PATH = true;
        break :flags open_flags;
    };
    const directory_fd = try std.posix.open(watch_path.directory_path, directory_flags, 0);
    errdefer std.posix.close(directory_fd);

    const changes = [_]std.posix.Kevent{.{
        .ident = @bitCast(@as(isize, directory_fd)),
        .filter = std.c.EVFILT.VNODE,
        .flags = std.c.EV.ADD | std.c.EV.ENABLE | std.c.EV.CLEAR,
        .fflags = std.c.NOTE.WRITE | std.c.NOTE.RENAME | std.c.NOTE.DELETE | std.c.NOTE.EXTEND | std.c.NOTE.ATTRIB | std.c.NOTE.REVOKE,
        .data = 0,
        .udata = 0,
    }};
    _ = try std.posix.kevent(kqueue_fd, &changes, &.{}, null);

    return .{ .darwin_kqueue = .{
        .kqueue_fd = kqueue_fd,
        .directory_fd = directory_fd,
    } };
}

fn splitPolicyWatchPath(policy_path: []const u8) !struct {
    directory_path: []u8,
    basename: []const u8,
} {
    return .{
        .directory_path = try allocator.dupe(u8, std.fs.path.dirname(policy_path) orelse "."),
        .basename = std.fs.path.basename(policy_path),
    };
}

fn nanosToPollTimeoutMs(timeout_ns: u64) i32 {
    const timeout_ms = std.math.divCeil(u64, timeout_ns, std.time.ns_per_ms) catch unreachable;
    if (timeout_ms > std.math.maxInt(i32)) return std.math.maxInt(i32);
    return @intCast(timeout_ms);
}

fn nanosToTimespec(timeout_ns: u64) std.posix.timespec {
    return .{
        .sec = @intCast(timeout_ns / std.time.ns_per_s),
        .nsec = @intCast(timeout_ns % std.time.ns_per_s),
    };
}

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

    var change_source = PolicyChangeSource.init(command.policy_path);
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
            change_sourceWait(&change_source, next_expiration_unix_seconds, &needs_reconcile);
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

        change_sourceWait(&change_source, next_expiration_unix_seconds, &needs_reconcile);
    }
}

fn change_sourceWait(change_source: *PolicyChangeSource, next_expiration_unix_seconds: ?i64, needs_reconcile: *bool) void {
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
        \\  file-snitch --version
        \\  file-snitch agent [--socket <path>] [--frontend <terminal-pinentry|macos-ui|linux-ui>] [--tty <path>]
        \\  file-snitch run [allow|deny|prompt] [--policy <path>]
        \\  file-snitch enroll <path> [--policy <path>]
        \\  file-snitch unenroll <path> [--policy <path>]
        \\  file-snitch status [--policy <path>]
        \\  file-snitch doctor [--policy <path>] [--export-debug-dossier <path>]
        \\
        \\defaults:
        \\  agent:
        \\    --socket <path>
        \\      $FILE_SNITCH_AGENT_SOCKET
        \\      else $XDG_RUNTIME_DIR/file-snitch/agent.sock
        \\      else $HOME/.local/state/file-snitch/agent.sock
        \\    --frontend <kind>
        \\      terminal-pinentry
        \\    --tty <path>
        \\      inherited stdio
        \\
        \\  run:
        \\    [allow|deny|prompt]
        \\      deny
        \\    --policy <path>
        \\      $FILE_SNITCH_POLICY_PATH
        \\      else $XDG_CONFIG_HOME/file-snitch/policy.yml
        \\      else $HOME/.config/file-snitch/policy.yml
        \\    prompt timeout
        \\      5000 ms
        \\      override with $FILE_SNITCH_PROMPT_TIMEOUT_MS
        \\
        \\  enroll | unenroll | status:
        \\    --policy <path>
        \\      $FILE_SNITCH_POLICY_PATH
        \\      else $XDG_CONFIG_HOME/file-snitch/policy.yml
        \\      else $HOME/.config/file-snitch/policy.yml
        \\
        \\  doctor:
        \\    --policy <path>
        \\      $FILE_SNITCH_POLICY_PATH
        \\      else $XDG_CONFIG_HOME/file-snitch/policy.yml
        \\      else $HOME/.config/file-snitch/policy.yml
        \\    --export-debug-dossier <path>
        \\      omitted by default
        \\
        \\notes:
        \\  - `agent` starts the local agent service on a Unix socket
        \\  - `agent --frontend macos-ui` uses `osascript` and does not accept --tty
        \\  - `agent --frontend linux-ui` uses `zenity` and does not accept --tty
        \\  - `run` is the long-running policy reconciler entrypoint
        \\  - `run` stays alive on an empty policy and reconciles mount workers as `policy.yml` changes
        \\  - prompt mode now talks to the local agent socket instead of reading from the daemon's stdin
        \\  - `enroll` migrates the plaintext file into the guarded store and records it in `policy.yml`
        \\  - `unenroll` restores the guarded file to its original path and removes remembered decisions for that path
        \\  - `status` inspects `policy.yml`; `doctor` also exits non-zero on actionable problems and can export a shareable debug dossier
        \\
    , .{});
}

fn printVersion() void {
    var buffer: [64]u8 = undefined;
    const line = std.fmt.bufPrint(&buffer, "file-snitch {s}\n", .{app_meta.version}) catch @panic("failed to format version");
    std.fs.File.stdout().writeAll(line) catch @panic("failed to write version");
}
