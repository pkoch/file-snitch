const std = @import("std");
const agent = @import("agent.zig");
const app_meta = @import("app_meta.zig");
const completion = @import("cli_completion.zig");
const config = @import("config.zig");
const daemon = @import("daemon.zig");
const defaults = @import("defaults.zig");
const enrollment_ops = @import("enrollment.zig");
const filesystem = @import("filesystem.zig");
const policy = @import("policy.zig");
const policy_commands = @import("policy_commands.zig");
const supervisor = @import("cli_supervisor.zig");
const prompt = @import("prompt.zig");
const runtime = @import("runtime.zig");
const store = @import("store.zig");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const allocator = std.heap.page_allocator;
const RunCommand = supervisor.RunCommand;

pub fn main(init_info: std.process.Init) !void {
    runtime.init(init_info);
    const args = try init_info.minimal.args.toSlice(init_info.arena.allocator());

    run(args[1..]) catch |err| switch (err) {
        error.InvalidUsage, error.DoctorFailed => std.process.exit(1),
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
        error.GuardedSourceFileTooLarge => {
            std.debug.print("error: guarded source file is too large for the current store read limit ({s})\n", .{store.pass_payload_limit_label});
            std.debug.print("hint: File Snitch currently targets small secret/config files and stores them as JSON/base64 in `pass`\n", .{});
            std.process.exit(1);
        },
        error.StorePayloadTooLarge => {
            std.debug.print("error: guarded object exceeds the pass payload limit ({s})\n", .{store.pass_payload_limit_label});
            std.debug.print("hint: the limit applies to File Snitch's JSON/base64 payload, not to `pass` itself\n", .{});
            std.debug.print("hint: `file-snitch unenroll <path>` can stream the object back out as a recovery path\n", .{});
            std.process.exit(1);
        },
        error.StoreCommandOutputTooLarge => {
            std.debug.print("error: pass backend command output exceeded the capture limit ({s})\n", .{store.pass_payload_limit_label});
            std.debug.print("hint: run `file-snitch doctor` and inspect the affected `pass:file-snitch/...` entry\n", .{});
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
        .completion => |shell| try completion.print(shell),
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
    completion: completion.Shell,
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
    if (std.mem.eql(u8, args[0], "completion")) {
        return .{ .completion = try parseCompletionCommand(args[1..]) };
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
    var command: RunCommand = .{
        .policy_path = &.{},
        .default_mutation_outcome = .deny,
        .protocol_timeout_ms = defaults.protocol_timeout_ms_default,
        .status_fifo_path = null,
        .mount_path_filter = null,
    };
    errdefer command.deinit(allocator);

    command.policy_path = try config.defaultPolicyPathAlloc(allocator);
    command.protocol_timeout_ms = try loadProtocolTimeoutMs();
    command.status_fifo_path = try loadOptionalInternalPath(defaults.internal_status_fifo_env);
    command.mount_path_filter = try loadOptionalInternalPath(defaults.internal_mount_path_env);

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];

        if (parseOutcome(arg)) |outcome| {
            command.default_mutation_outcome = outcome;
            continue;
        }
        if (std.mem.eql(u8, arg, "--policy")) {
            try parsePolicyFlag(args, &index, &command.policy_path);
            continue;
        }
        printUsage();
        return error.InvalidUsage;
    }

    return command;
}

fn parseCompletionCommand(args: []const []const u8) !completion.Shell {
    if (args.len != 1) {
        printUsage();
        return error.InvalidUsage;
    }

    return completion.parseShell(args[0]) orelse
        invalidUsage("error: unsupported completion shell: {s}\n", .{args[0]});
}

fn parseAgentCommand(args: []const []const u8) !AgentCommand {
    const socket_path = try agent.defaultSocketPathAlloc(allocator);

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

    var command: PolicyCommand = .{
        .policy_path = policy_path,
    };
    errdefer command.deinit(allocator);

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--policy")) {
            try parsePolicyFlag(args, &index, &command.policy_path);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
    }

    return command;
}

fn parseDoctorCommand(args: []const []const u8) !DoctorCommand {
    const policy_path = try config.defaultPolicyPathAlloc(allocator);

    var command: DoctorCommand = .{
        .policy_path = policy_path,
        .export_debug_dossier_path = null,
    };
    errdefer command.deinit(allocator);

    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--policy")) {
            try parsePolicyFlag(args, &index, &command.policy_path);
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

    var command: PathCommand = .{
        .policy_path = &.{},
        .target_path = &.{},
    };
    errdefer command.deinit(allocator);

    command.target_path = if (require_existing_target)
        try resolveExistingRegularFileArgument("target file", args[0])
    else
        try resolveEnrolledPathArgument(args[0]);

    command.policy_path = try config.defaultPolicyPathAlloc(allocator);

    var index: usize = 1;
    while (index < args.len) : (index += 1) {
        if (std.mem.eql(u8, args[index], "--policy")) {
            try parsePolicyFlag(args, &index, &command.policy_path);
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
        try supervisor.reconcilePolicyInForeground(command);
        return;
    }

    try runStaticPolicy(command);
}

fn runAgent(command: AgentCommand) !void {
    const timeout_ms = try loadPromptTimeoutMs();
    var cli_context = prompt.CliContext{
        .allocator = allocator,
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
            terminal_pinentry_context = .{
                .allocator = allocator,
                .timeout_ms = timeout_ms,
                .tty_path = command.tty_path,
                .inherited_cli_context = if (command.tty_path == null) &cli_context else null,
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

    const status_output_file = if (command.status_fifo_path) |path|
        try openStatusFifo(path)
    else
        null;
    defer {
        if (status_output_file) |file| file.close(runtime.io());
    }

    const prompt_requester = if (command.default_mutation_outcome == .prompt)
        agent.RequesterContext{
            .allocator = allocator,
            .socket_path = try agent.defaultSocketPathAlloc(allocator),
            .policy_path = command.policy_path,
            .protocol_timeout_ms = command.protocol_timeout_ms,
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
            .guarded_store = &guarded_store,
            .run_in_foreground = true,
            .default_mutation_outcome = command.default_mutation_outcome,
            .policy_path = command.policy_path,
            .policy_rule_views = compiled_rule_views.items,
            .prompt_broker = if (command.default_mutation_outcome == .prompt)
                agent.socketBroker(@constCast(&prompt_requester.?))
            else
                null,
            .status_output_file = status_output_file,
            .audit_output_file = std.Io.File.stdout(),
        });
        return;
    }
}

fn resolveExistingRegularFileArgument(label: []const u8, raw_path: []const u8) ![]const u8 {
    const resolved = std.Io.Dir.realPathFileAbsoluteAlloc(runtime.io(), raw_path, allocator) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: {s} does not exist: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        else => return err,
    };
    errdefer allocator.free(resolved);

    const target_kind = enrollment_ops.pathKind(resolved) catch |err| {
        if (err == error.NoDevice) {
            return invalidUsageWithOwnedPath(
                "error: target file is on a stale or inaccessible device: {s}\nhint: restart `file-snitch run`; if this persists, unmount the affected parent directory and retry\n",
                resolved,
            );
        }
        std.debug.print("error: target file could not be inspected: {s}: {}\n", .{ resolved, err });
        return error.InvalidUsage;
    };

    switch (target_kind) {
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

    const cwd = try std.process.currentPathAlloc(runtime.io(), allocator);
    defer allocator.free(cwd);
    return std.fs.path.resolve(allocator, &.{ cwd, raw_path });
}

fn resolveEnrolledPathArgument(raw_path: []const u8) ![]const u8 {
    const lexical_path = try resolvePathArgument(raw_path);
    errdefer allocator.free(lexical_path);

    if (try enrollment_ops.pathExists(lexical_path)) {
        const canonical = try std.Io.Dir.realPathFileAbsoluteAlloc(runtime.io(), lexical_path, allocator);
        allocator.free(lexical_path);
        return canonical;
    }

    const parent_dir = std.fs.path.dirname(lexical_path) orelse {
        std.debug.print("error: invalid target path: {s}\n", .{lexical_path});
        return error.InvalidUsage;
    };
    const canonical_parent = std.Io.Dir.realPathFileAbsoluteAlloc(runtime.io(), parent_dir, allocator) catch |err| switch (err) {
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

    const owned_by_current_user = try enrollment_ops.pathOwnedByCurrentUser(target_path);
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
    const raw_value = runtime.getEnvVarOwned(allocator, defaults.prompt_timeout_ms_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return defaults.prompt_timeout_ms_default,
        else => return err,
    };
    defer allocator.free(raw_value);

    return std.fmt.parseInt(u32, raw_value, 10) catch
        return invalidUsage(
            "error: {s} must be a non-negative integer (milliseconds), got: {s}\n",
            .{ defaults.prompt_timeout_ms_env, raw_value },
        );
}

fn loadProtocolTimeoutMs() !u32 {
    const raw_value = runtime.getEnvVarOwned(allocator, defaults.protocol_timeout_ms_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return defaults.protocol_timeout_ms_default,
        else => return err,
    };
    defer allocator.free(raw_value);

    return std.fmt.parseInt(u32, raw_value, 10) catch
        return invalidUsage(
            "error: {s} must be a non-negative integer (milliseconds), got: {s}\n",
            .{ defaults.protocol_timeout_ms_env, raw_value },
        );
}

fn loadOptionalInternalPath(env_name: []const u8) !?[]const u8 {
    const raw_value = runtime.getEnvVarOwned(allocator, env_name) catch |err| switch (err) {
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

fn openStatusFifo(path: []const u8) !std.Io.File {
    const stat = std.Io.Dir.cwd().statFile(runtime.io(), path, .{}) catch |err| switch (err) {
        error.FileNotFound => return invalidUsage("error: status fifo does not exist: {s}\n", .{path}),
        else => return err,
    };

    if (stat.kind != .named_pipe) {
        return invalidUsage("error: status fifo is not a named pipe: {s}\n", .{path});
    }

    return std.Io.Dir.cwd().openFile(runtime.io(), path, .{ .mode = .write_only });
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

fn parsePolicyFlag(args: []const []const u8, index: *usize, policy_path: *[]const u8) !void {
    index.* += 1;
    if (index.* >= args.len) {
        printUsage();
        return error.InvalidUsage;
    }
    const new_path = try resolvePathArgument(args[index.*]);
    allocator.free(policy_path.*);
    policy_path.* = new_path;
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
        \\  file-snitch completion <bash|zsh|fish>
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
        \\    user interaction timeout
        \\      5000 ms
        \\      override with $FILE_SNITCH_PROMPT_TIMEOUT_MS
        \\
        \\  run:
        \\    [allow|deny|prompt]
        \\      deny
        \\    --policy <path>
        \\      $FILE_SNITCH_POLICY_PATH
        \\      else $XDG_CONFIG_HOME/file-snitch/policy.yml
        \\      else $HOME/.config/file-snitch/policy.yml
        \\    agent protocol timeout
        \\      1000 ms
        \\      override with $FILE_SNITCH_PROTOCOL_TIMEOUT_MS
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
        \\  - `completion` prints shell completion scripts for bash, zsh, and fish
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
    std.Io.File.stdout().writeStreamingAll(runtime.io(), line) catch @panic("failed to write version");
}

test "parse command routes completion subcommand" {
    const command = try parseCommand(&.{ "completion", "bash" });
    try std.testing.expectEqual(completion.Shell.bash, command.completion);
}

test "parse command rejects unsupported completion shell" {
    try std.testing.expectError(error.InvalidUsage, parseCommand(&.{ "completion", "elvish" }));
}
