const std = @import("std");
const config = @import("config.zig");
const daemon = @import("daemon.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const allocator = std.heap.page_allocator;

pub fn main() !void {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    run(args[1..]) catch |err| switch (err) {
        error.InvalidUsage, error.DoctorFailed => std.process.exit(1),
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

    fn deinit(self: RunCommand, alloc: std.mem.Allocator) void {
        alloc.free(self.policy_path);
        if (self.status_fifo_path) |path| {
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

    if (loaded_policy.enrollments.len != 1 or mount_plan.paths.len != 1) {
        std.debug.print(
            "error: `run` currently supports exactly one enrolled file; got {d} enrollments and {d} planned mounts in {s}\n",
            .{ loaded_policy.enrollments.len, mount_plan.paths.len, loaded_policy.source_path },
        );
        return error.InvalidUsage;
    }

    const enrollment = loaded_policy.enrollments[0];
    const guarded_file_name = std.fs.path.basename(enrollment.path);
    const guarded_backing_file_path = try config.defaultGuardedObjectPathAlloc(allocator, enrollment.object_id);
    defer allocator.free(guarded_backing_file_path);

    var cli_prompt_context = prompt.CliContext{
        .timeout_ms = command.prompt_timeout_ms,
    };
    const status_output_file = if (command.status_fifo_path) |path|
        try openStatusFifo(path)
    else
        null;
    defer if (status_output_file) |file| file.close();

    try daemon.mountEnrolledParent(allocator, .{
        .mount_path = mount_plan.paths[0],
        .guarded_file_name = guarded_file_name,
        .guarded_backing_file_path = guarded_backing_file_path,
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

    if (loaded_policy.enrollments.len > 1 or mount_plan.paths.len > 1) {
        has_errors = true;
        std.debug.print(
            "error: current `run` path still supports exactly one enrolled file and one planned mount\n",
            .{},
        );
    }

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
        \\  - `run` currently supports exactly one enrolled file
        \\  - `enroll` migrates the plaintext file into the guarded store and records it in `policy.yml`
        \\  - `unenroll` restores the guarded file to its original path and removes remembered decisions for that path
        \\  - `status` and `doctor` inspect `policy.yml`; `doctor` exits non-zero on actionable problems
        \\  - `mount` is the legacy guarded-root spike entrypoint
        \\
    , .{});
}
