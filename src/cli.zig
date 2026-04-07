const std = @import("std");
const config = @import("config.zig");
const daemon = @import("daemon.zig");
const filesystem = @import("filesystem.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const allocator = std.heap.page_allocator;
var supervisor_shutdown_signal = std.atomic.Value(i32).init(0);

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    run(args[1..]) catch |err| switch (err) {
        error.InvalidUsage, error.DoctorFailed, error.RunFailed => std.process.exit(1),
        else => return err,
    };
}

pub fn run(args: []const []const u8) !void {
    switch (try parseCommand(args)) {
        .help => printUsage(),
        .run => |command| {
            defer command.deinit(allocator);
            try runWithPolicy(command);
        },
        .enroll => |command| {
            defer command.deinit(allocator);
            try enrollPath(command);
        },
        .unenroll => |command| {
            defer command.deinit(allocator);
            try unenrollPath(command);
        },
        .status => |command| {
            defer command.deinit(allocator);
            try showStatus(command);
        },
        .doctor => |command| {
            defer command.deinit(allocator);
            try runDoctor(command);
        },
        .mount => |command| {
            defer command.deinit(allocator);
            try runLegacyMount(command);
        },
    }
}

const Command = union(enum) {
    help,
    run: RunCommand,
    enroll: PathCommand,
    unenroll: PathCommand,
    status: PolicyCommand,
    doctor: PolicyCommand,
    mount: MountCommand,
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

const MountCommand = struct {
    mount_path: []const u8,
    backing_store_path: []const u8,
    default_mutation_outcome: policy.Outcome,
    prompt_timeout_ms: u32,
    status_fifo_path: ?[]const u8 = null,

    fn deinit(self: MountCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.mount_path);
        alloc.free(self.backing_store_path);
        if (self.status_fifo_path) |path| {
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
    if (std.mem.eql(u8, args[0], "mount")) {
        return .{ .mount = try parseMountCommand(args[1..]) };
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
        if (std.mem.eql(u8, arg, "--status-fifo")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            command.status_fifo_path = try allocator.dupe(u8, args[index]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--mount-path")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            command.mount_path_filter = try resolvePathArgument(args[index]);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
    }

    if (selected_execution_mode == null) {
        return invalidUsage("error: `run` requires exactly one of --foreground or --daemon\n", .{});
    }
    command.run_in_foreground = selected_execution_mode.?;

    if (!command.run_in_foreground and command.default_mutation_outcome == .prompt) {
        return invalidUsage("error: `run prompt` requires --foreground because the current broker is interactive\n", .{});
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

fn parseMountCommand(args: []const []const u8) !MountCommand {
    if (args.len < 2) {
        printUsage();
        return error.InvalidUsage;
    }

    const mount_path = try resolveDirectoryArgument("mount path", args[0]);
    errdefer allocator.free(mount_path);
    const backing_store_path = try resolveDirectoryArgument("backing store path", args[1]);
    errdefer allocator.free(backing_store_path);

    var command: MountCommand = .{
        .mount_path = mount_path,
        .backing_store_path = backing_store_path,
        .default_mutation_outcome = .deny,
        .prompt_timeout_ms = try loadPromptTimeoutMs(),
    };
    errdefer command.deinit(allocator);

    var index: usize = 2;
    while (index < args.len) : (index += 1) {
        if (parseOutcome(args[index])) |outcome| {
            command.default_mutation_outcome = outcome;
            continue;
        }
        if (std.mem.eql(u8, args[index], "--status-fifo")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            command.status_fifo_path = try allocator.dupe(u8, args[index]);
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

    if (mount_plan.paths.len > 1 and command.default_mutation_outcome == .prompt) {
        std.debug.print("error: multi-mount `run prompt` is not supported yet\n", .{});
        return error.InvalidUsage;
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

    var cli_prompt_context = prompt.CliContext{
        .timeout_ms = command.prompt_timeout_ms,
    };
    const PlannedMount = struct {
        mount_path: []const u8,
        guarded_entries: []filesystem.GuardedEntryConfig,
    };

    var planned_mounts = try allocator.alloc(PlannedMount, mount_plan.paths.len);
    defer {
        for (planned_mounts) |planned| {
            for (planned.guarded_entries) |entry| {
                allocator.free(entry.relative_path);
                allocator.free(entry.backing_file_path);
            }
            allocator.free(planned.guarded_entries);
        }
        allocator.free(planned_mounts);
    }

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
                .backing_file_path = try config.defaultGuardedObjectPathAlloc(allocator, enrollment.object_id),
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
            .run_in_foreground = command.run_in_foreground,
            .default_mutation_outcome = command.default_mutation_outcome,
            .policy_rules = compiled_rules.items,
            .prompt_broker = if (command.default_mutation_outcome == .prompt)
                prompt.cliBroker(&cli_prompt_context)
            else
                null,
            .status_output_file = status_output_file,
            .audit_output_file = std.fs.File.stdout(),
        });
        return;
    }
}

fn enrollPath(command: PathCommand) !void {
    var loaded_policy = try config.loadFromFile(allocator, command.policy_path);
    defer loaded_policy.deinit();

    if (loaded_policy.findEnrollmentIndex(command.target_path) != null) {
        std.debug.print("error: already enrolled: {s}\n", .{command.target_path});
        return error.InvalidUsage;
    }

    const object_id = try allocateObjectId();
    defer allocator.free(object_id);

    const object_path = try config.defaultGuardedObjectPathAlloc(allocator, object_id);
    defer allocator.free(object_path);

    try ensureParentDirectory(object_path);
    try moveFileIntoGuardedStore(command.target_path, object_path);
    errdefer moveGuardedFileBack(object_path, command.target_path) catch {};

    try loaded_policy.appendEnrollment(command.target_path, object_id);
    errdefer {
        const enrollment_index = loaded_policy.findEnrollmentIndex(command.target_path).?;
        var removed = loaded_policy.removeEnrollmentAt(enrollment_index);
        removed.deinit(allocator);
    }

    try loaded_policy.saveToFile();

    std.debug.print(
        "file-snitch: enrolled {s} as {s} in {s}\n",
        .{ command.target_path, object_id, loaded_policy.source_path },
    );
}

fn unenrollPath(command: PathCommand) !void {
    var loaded_policy = try config.loadFromFile(allocator, command.policy_path);
    defer loaded_policy.deinit();

    const enrollment_index = findEnrollmentIndexByArgument(&loaded_policy, command.target_path) orelse {
        std.debug.print("error: not enrolled: {s}\n", .{command.target_path});
        return error.InvalidUsage;
    };

    const enrolled_path = loaded_policy.enrollments[enrollment_index].path;
    if (pathExists(enrolled_path)) {
        std.debug.print(
            "error: target path currently exists: {s}\nstop the active projection before unenrolling\n",
            .{enrolled_path},
        );
        return error.InvalidUsage;
    }

    const object_path = try config.defaultGuardedObjectPathAlloc(
        allocator,
        loaded_policy.enrollments[enrollment_index].object_id,
    );
    defer allocator.free(object_path);

    try moveGuardedFileBack(object_path, enrolled_path);
    errdefer moveFileIntoGuardedStore(enrolled_path, object_path) catch {};

    loaded_policy.removeDecisionsForPath(enrolled_path);
    var removed = loaded_policy.removeEnrollmentAt(enrollment_index);
    defer removed.deinit(allocator);

    try loaded_policy.saveToFile();

    std.debug.print(
        "file-snitch: unenrolled {s} from {s}\n",
        .{ removed.path, loaded_policy.source_path },
    );
}

fn showStatus(command: PolicyCommand) !void {
    var loaded_policy = try config.loadFromFile(allocator, command.policy_path);
    defer loaded_policy.deinit();

    var mount_plan = try loaded_policy.deriveMountPlan(allocator);
    defer mount_plan.deinit();

    std.debug.print("policy: {s}\n", .{loaded_policy.source_path});
    std.debug.print("enrollments: {d}\n", .{loaded_policy.enrollments.len});
    std.debug.print("decisions: {d}\n", .{loaded_policy.decisions.len});
    std.debug.print("planned_mounts: {d}\n", .{mount_plan.paths.len});

    for (mount_plan.paths) |mount_path| {
        std.debug.print("mount: {s}\n", .{mount_path});
    }

    for (loaded_policy.enrollments) |enrollment| {
        const object_path = try config.defaultGuardedObjectPathAlloc(allocator, enrollment.object_id);
        defer allocator.free(object_path);
        std.debug.print(
            "enrollment: path={s} object_id={s} guarded_object={s}\n",
            .{ enrollment.path, enrollment.object_id, object_path },
        );
    }

    for (loaded_policy.decisions) |decision| {
        std.debug.print(
            "decision: executable_path={s} uid={d} path={s} approval_class={s} outcome={s} expires_at={s}\n",
            .{
                decision.executable_path,
                decision.uid,
                decision.path,
                decision.approval_class,
                decision.outcome,
                decision.expires_at orelse "null",
            },
        );
    }
}

fn runDoctor(command: PolicyCommand) !void {
    var loaded_policy = try config.loadFromFile(allocator, command.policy_path);
    defer loaded_policy.deinit();

    var mount_plan = try loaded_policy.deriveMountPlan(allocator);
    defer mount_plan.deinit();

    var has_errors = false;

    std.debug.print("policy: ok ({s})\n", .{loaded_policy.source_path});
    std.debug.print("mount_plan: {d} mounts for {d} enrollments\n", .{ mount_plan.paths.len, loaded_policy.enrollments.len });

    for (loaded_policy.enrollments) |enrollment| {
        const parent_dir = std.fs.path.dirname(enrollment.path) orelse {
            has_errors = true;
            std.debug.print("error: invalid enrollment path: {s}\n", .{enrollment.path});
            continue;
        };

        if (!directoryExists(parent_dir)) {
            has_errors = true;
            std.debug.print("error: parent directory missing: {s}\n", .{parent_dir});
        } else {
            std.debug.print("ok: parent directory exists: {s}\n", .{parent_dir});
        }

        const object_path = try config.defaultGuardedObjectPathAlloc(allocator, enrollment.object_id);
        defer allocator.free(object_path);

        switch (pathKind(object_path)) {
            .file => std.debug.print("ok: guarded object exists: {s}\n", .{object_path}),
            .missing => {
                has_errors = true;
                std.debug.print("error: guarded object missing: {s}\n", .{object_path});
            },
            else => {
                has_errors = true;
                std.debug.print("error: guarded object is not a regular file: {s}\n", .{object_path});
            },
        }

        switch (pathKind(enrollment.path)) {
            .missing => std.debug.print("ok: target path currently absent: {s}\n", .{enrollment.path}),
            .file => std.debug.print(
                "warn: target path currently exists: {s}\nexpected only while actively projected or before migration cleanup\n",
                .{enrollment.path},
            ),
            .directory => {
                has_errors = true;
                std.debug.print("error: target path is a directory: {s}\n", .{enrollment.path});
            },
            .other => {
                has_errors = true;
                std.debug.print("error: target path has unsupported type: {s}\n", .{enrollment.path});
            },
        }
    }

    for (loaded_policy.decisions) |decision| {
        if (loaded_policy.findEnrollmentIndex(decision.path) == null) {
            has_errors = true;
            std.debug.print(
                "error: decision path is not enrolled: executable_path={s} uid={d} path={s}\n",
                .{ decision.executable_path, decision.uid, decision.path },
            );
        }
    }

    if (has_errors) {
        return error.DoctorFailed;
    }
}

fn runLegacyMount(command: MountCommand) !void {
    var cli_prompt_context = prompt.CliContext{
        .timeout_ms = command.prompt_timeout_ms,
    };
    const status_output_file = if (command.status_fifo_path) |path|
        try openStatusFifo(path)
    else
        null;
    defer if (status_output_file) |file| file.close();

    daemon.mount(allocator, .{
        .mount_path = command.mount_path,
        .backing_store_path = command.backing_store_path,
        .default_mutation_outcome = command.default_mutation_outcome,
        .prompt_broker = if (command.default_mutation_outcome == .prompt)
            prompt.cliBroker(&cli_prompt_context)
        else
            null,
        .status_output_file = status_output_file,
        .audit_output_file = std.fs.File.stdout(),
    }) catch |err| switch (err) {
        error.MountPathNotEmpty => {
            std.debug.print("error: mount path is not empty: {s}\n", .{command.mount_path});
            return error.InvalidUsage;
        },
        else => return err,
    };
}

fn resolveDirectoryArgument(label: []const u8, raw_path: []const u8) ![]const u8 {
    return std.fs.realpathAlloc(allocator, raw_path) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: {s} does not exist: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        error.NotDir => {
            std.debug.print("error: {s} is not a directory: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        else => return err,
    };
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

    switch (pathKind(resolved)) {
        .file => return resolved,
        .directory => return invalidUsageWithOwnedPath("error: target file is a directory: {s}\n", resolved),
        .other => return invalidUsageWithOwnedPath("error: target file is not a regular file: {s}\n", resolved),
        .missing => return invalidUsageWithOwnedPath("error: target file does not exist: {s}\n", resolved),
    }
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

    if (pathExists(lexical_path)) {
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

fn loadPromptTimeoutMs() !u32 {
    const raw_value = std.process.getEnvVarOwned(allocator, "FILE_SNITCH_PROMPT_TIMEOUT_MS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return 5_000,
        else => return err,
    };
    defer allocator.free(raw_value);

    return std.fmt.parseInt(u32, raw_value, 10);
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

fn findEnrollmentIndexByArgument(loaded_policy: *const config.PolicyFile, requested_path: []const u8) ?usize {
    if (loaded_policy.findEnrollmentIndex(requested_path)) |index| {
        return index;
    }

    const canonical = std.fs.realpathAlloc(allocator, requested_path) catch return null;
    defer allocator.free(canonical);
    return loaded_policy.findEnrollmentIndex(canonical);
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
        const extra_args: usize = if (command.status_fifo_path != null) 2 else 0;
        const argv = try allocator.alloc([]const u8, 8 + extra_args);
        argv[0] = exe_path;
        argv[1] = "run";
        argv[2] = outcomeArg(command.default_mutation_outcome);
        argv[3] = "--foreground";
        argv[4] = "--policy";
        argv[5] = command.policy_path;
        argv[6] = "--mount-path";
        argv[7] = mount_path;
        if (command.status_fifo_path) |status_fifo_path| {
            argv[8] = "--status-fifo";
            argv[9] = status_fifo_path;
        }

        var child = std.process.Child.init(argv, allocator);
        child.stdin_behavior = .Inherit;
        child.stdout_behavior = .Inherit;
        child.stderr_behavior = .Inherit;

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

fn allocateObjectId() ![]u8 {
    var bytes: [16]u8 = undefined;
    var object_id_buffer: [32]u8 = undefined;

    while (true) {
        std.crypto.random.bytes(&bytes);
        object_id_buffer = std.fmt.bytesToHex(bytes, .lower);
        const object_id = try allocator.dupe(u8, &object_id_buffer);
        errdefer allocator.free(object_id);

        const object_path = try config.defaultGuardedObjectPathAlloc(allocator, object_id);
        defer allocator.free(object_path);
        if (!pathExists(object_path)) {
            return object_id;
        }
    }
}

fn ensureParentDirectory(path: []const u8) !void {
    const parent_dir = std.fs.path.dirname(path) orelse return error.InvalidPath;
    try std.fs.cwd().makePath(parent_dir);
}

fn moveFileIntoGuardedStore(source_path: []const u8, object_path: []const u8) !void {
    try ensureParentDirectory(object_path);
    try std.fs.copyFileAbsolute(source_path, object_path, .{});
    errdefer std.fs.deleteFileAbsolute(object_path) catch {};
    try std.fs.deleteFileAbsolute(source_path);
}

fn moveGuardedFileBack(object_path: []const u8, target_path: []const u8) !void {
    try ensureParentDirectory(target_path);
    try std.fs.copyFileAbsolute(object_path, target_path, .{});
    errdefer std.fs.deleteFileAbsolute(target_path) catch {};
    try std.fs.deleteFileAbsolute(object_path);
}

const PathKind = enum {
    missing,
    file,
    directory,
    other,
};

fn pathKind(path: []const u8) PathKind {
    const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .other,
    };

    return switch (stat.kind) {
        .file => .file,
        .directory => .directory,
        else => .other,
    };
}

fn pathExists(path: []const u8) bool {
    return pathKind(path) != .missing;
}

fn directoryExists(path: []const u8) bool {
    return pathKind(path) == .directory;
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
        \\  file-snitch run [allow|deny|prompt] (--daemon|--foreground) [--policy <path>] [--status-fifo <path>]
        \\  file-snitch enroll <path> [--policy <path>]
        \\  file-snitch unenroll <path> [--policy <path>]
        \\  file-snitch status [--policy <path>]
        \\  file-snitch doctor [--policy <path>]
        \\  file-snitch mount <mount-path> <backing-store-path> [allow|deny|prompt] [--status-fifo <path>]
        \\
        \\notes:
        \\  - `run` is the long-running daemon entrypoint and requires explicit foreground/background mode
        \\  - `run` exits cleanly when no enrollments are configured
        \\  - `run --foreground` supports multiple planned mounts by supervising one child mount process per path
        \\  - `run prompt` and multi-mount `run --daemon` are still unsupported
        \\  - `enroll` migrates the plaintext file into the guarded store and records it in `policy.yml`
        \\  - `unenroll` restores the guarded file to its original path and removes remembered decisions for that path
        \\  - `status` and `doctor` inspect `policy.yml`; `doctor` exits non-zero on actionable problems
        \\  - `mount` is the legacy guarded-root spike entrypoint
        \\
    , .{});
}
