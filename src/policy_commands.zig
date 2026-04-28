const std = @import("std");
const agent = @import("agent.zig");
const app_meta = @import("app_meta.zig");
const builtin = @import("builtin");
const config = @import("config.zig");
const defaults = @import("defaults.zig");
const enrollment = @import("enrollment.zig");
const fuse = @import("fuse/shim.zig");
const runtime = @import("runtime.zig");
const store = @import("store.zig");
const user_services = @import("user_services.zig");

const projection_teardown_timeout_ms = 10_000;
const projection_teardown_poll_ms = 100;

pub fn enroll(allocator: std.mem.Allocator, policy_path: []const u8, target_path: []const u8) !void {
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();
    var guarded_store = try store.Backend.initPass(allocator);
    defer guarded_store.deinit(allocator);

    try ensureProjectionServiceCanLoadPass(allocator);

    if (loaded_policy.findEnrollmentIndex(target_path) != null) {
        std.debug.print("error: already enrolled: {s}\n", .{target_path});
        return error.InvalidUsage;
    }

    const object_id = try enrollment.allocateObjectId(allocator, &guarded_store);
    defer allocator.free(object_id);

    try enrollment.moveFileIntoGuardedStore(allocator, &guarded_store, target_path, object_id);
    errdefer enrollment.moveGuardedFileBack(allocator, &guarded_store, object_id, target_path) catch |err| {
        std.debug.panic("failed to roll back enrollment for {s}: {}", .{ target_path, err });
    };

    try loaded_policy.appendEnrollment(target_path, object_id);
    errdefer {
        const enrollment_index = loaded_policy.findEnrollmentIndex(target_path).?;
        var removed = loaded_policy.removeEnrollmentAt(enrollment_index);
        removed.deinit(allocator);
    }

    try loaded_policy.saveToFile();

    std.debug.print(
        "file-snitch: enrolled {s} as {s} in {s}\n",
        .{ target_path, object_id, loaded_policy.source_path },
    );
}

pub fn unenroll(allocator: std.mem.Allocator, policy_path: []const u8, target_path: []const u8) !void {
    var guarded_store = try store.Backend.initPass(allocator);
    defer guarded_store.deinit(allocator);

    var pending = try beginUnenrollPolicyUpdate(allocator, policy_path, target_path);
    defer pending.deinit(allocator);

    var restore_policy_on_error = true;
    errdefer if (restore_policy_on_error) {
        rollbackUnenrollPolicyUpdate(allocator, policy_path, pending.enrolled_path, pending.object_id) catch |err| {
            std.debug.panic("failed to roll back unenrollment policy update for {s}: {}", .{ pending.enrolled_path, err });
        };
    };

    if (try enrollment.pathExists(pending.enrolled_path)) {
        std.debug.print(
            "file-snitch: waiting for active projection to stop: {s}\n",
            .{pending.enrolled_path},
        );
        try waitForTargetPathToDisappear(pending.enrolled_path);
    }

    try restoreGuardedFileBackIfStillUnenrolled(allocator, policy_path, &guarded_store, pending.object_id, pending.enrolled_path);
    restore_policy_on_error = false;
    removeDecisionsForUnenrolledPath(allocator, policy_path, pending.enrolled_path) catch |err| {
        std.debug.print(
            "warn: unenrolled {s}, but failed to remove remembered decisions: {}\n",
            .{ pending.enrolled_path, err },
        );
    };

    std.debug.print(
        "file-snitch: unenrolled {s} from {s}\n",
        .{ pending.enrolled_path, pending.policy_source_path },
    );
}

const PendingUnenroll = struct {
    enrolled_path: []u8,
    object_id: []u8,
    policy_source_path: []u8,

    fn deinit(self: *PendingUnenroll, allocator: std.mem.Allocator) void {
        allocator.free(self.enrolled_path);
        allocator.free(self.object_id);
        allocator.free(self.policy_source_path);
        self.* = undefined;
    }
};

fn beginUnenrollPolicyUpdate(
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    target_path: []const u8,
) !PendingUnenroll {
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();

    const enrollment_index = findEnrollmentIndexByArgument(allocator, &loaded_policy, target_path) orelse {
        std.debug.print("error: not enrolled: {s}\n", .{target_path});
        return error.InvalidUsage;
    };

    const policy_source_path = try allocator.dupe(u8, loaded_policy.source_path);
    errdefer allocator.free(policy_source_path);

    var removed = loaded_policy.removeEnrollmentAt(enrollment_index);
    errdefer removed.deinit(allocator);

    try loaded_policy.saveToFile();

    return .{
        .enrolled_path = removed.path,
        .object_id = removed.object_id,
        .policy_source_path = policy_source_path,
    };
}

fn rollbackUnenrollPolicyUpdate(
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    enrolled_path: []const u8,
    object_id: []const u8,
) !void {
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();

    if (loaded_policy.findEnrollmentIndex(enrolled_path) != null) {
        return;
    }

    try loaded_policy.appendEnrollment(enrolled_path, object_id);
    try loaded_policy.saveToFile();
}

fn restoreGuardedFileBackIfStillUnenrolled(
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    guarded_store: *store.Backend,
    object_id: []const u8,
    enrolled_path: []const u8,
) !void {
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();

    if (loaded_policy.findEnrollmentIndex(enrolled_path) != null) {
        std.debug.print("error: enrollment reappeared during unenroll: {s}\n", .{enrolled_path});
        return error.InvalidUsage;
    }

    try enrollment.moveGuardedFileBack(allocator, guarded_store, object_id, enrolled_path);
}

fn removeDecisionsForUnenrolledPath(
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    enrolled_path: []const u8,
) !void {
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();

    if (loaded_policy.findEnrollmentIndex(enrolled_path) != null) {
        std.debug.print("error: enrollment reappeared during unenroll: {s}\n", .{enrolled_path});
        return error.InvalidUsage;
    }

    loaded_policy.removeDecisionsForPath(enrolled_path);
    try loaded_policy.saveToFile();
}

fn waitForTargetPathToDisappear(enrolled_path: []const u8) !void {
    const deadline_ms = runtime.milliTimestamp() + projection_teardown_timeout_ms;
    while (runtime.milliTimestamp() < deadline_ms) {
        if (!try enrollment.pathExists(enrolled_path)) {
            return;
        }

        std.Io.sleep(runtime.io(), .fromMilliseconds(projection_teardown_poll_ms), .awake) catch |err| {
            std.debug.print("warn: projection teardown wait sleep failed: {}\n", .{err});
        };
    }

    if (!try enrollment.pathExists(enrolled_path)) {
        return;
    }

    std.debug.print(
        "error: target path still exists after policy update: {s}\n",
        .{enrolled_path},
    );
    std.debug.print(
        "hint: file-snitch restored the policy enrollment; stop the projection or remove the stale target path before retrying\n",
        .{},
    );
    return error.InvalidUsage;
}

pub fn status(allocator: std.mem.Allocator, policy_path: []const u8) !void {
    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();
    var guarded_store: ?store.Backend = if (loaded_policy.enrollments.len != 0)
        try store.Backend.initPass(allocator)
    else
        null;
    defer if (guarded_store) |*backend| backend.deinit(allocator);

    var projection_plan = try loaded_policy.deriveProjectionPlan(allocator);
    defer projection_plan.deinit();

    std.debug.print("policy: {s}\n", .{loaded_policy.source_path});
    std.debug.print("enrollments: {d}\n", .{loaded_policy.enrollments.len});
    std.debug.print("decisions: {d}\n", .{loaded_policy.decisions.len});
    if (projection_plan.entries.len == 0) {
        std.debug.print("projection: absent\n", .{});
    } else {
        std.debug.print("projection: {s}\n", .{projection_plan.root_path});
    }

    for (loaded_policy.enrollments) |entry| {
        const store_ref = try guarded_store.?.describeRefAlloc(allocator, entry.object_id);
        defer allocator.free(store_ref);
        std.debug.print(
            "enrollment: path={s} object_id={s} store_ref={s}\n",
            .{ entry.path, entry.object_id, store_ref },
        );
    }

    for (loaded_policy.decisions) |decision| {
        std.debug.print(
            "decision: executable_path={s} path={s} approval_class={s} outcome={s} expires_at={s}\n",
            .{
                decision.executable_path,
                decision.path,
                decision.approval_class,
                decision.outcome,
                decision.expires_at orelse "null",
            },
        );
    }
}

pub const DoctorOptions = struct {
    policy_path: []const u8,
    export_debug_dossier_path: ?[]const u8 = null,
};

pub fn doctor(allocator: std.mem.Allocator, options: DoctorOptions) !void {
    var loaded_policy = try config.loadFromFile(allocator, options.policy_path);
    defer loaded_policy.deinit();
    var guarded_store: ?store.Backend = if (loaded_policy.enrollments.len != 0)
        try store.Backend.initPass(allocator)
    else
        null;
    defer if (guarded_store) |*backend| backend.deinit(allocator);

    var projection_plan = try loaded_policy.deriveProjectionPlan(allocator);
    defer projection_plan.deinit();

    var report = std.ArrayList(u8).empty;
    defer report.deinit(allocator);
    var report_allocating_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &report);
    const report_writer = &report_allocating_writer.writer;

    var has_errors = false;
    const home_dir = try enrollment.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);
    const agent_socket_path = try agent.defaultSocketPathAlloc(allocator);
    defer allocator.free(agent_socket_path);

    try report_writer.print("policy: ok ({s})\n", .{loaded_policy.source_path});
    if (projection_plan.entries.len == 0) {
        try report_writer.print("projection: absent for {d} enrollments\n", .{loaded_policy.enrollments.len});
    } else {
        try report_writer.print("projection: {s} for {d} enrollments\n", .{ projection_plan.root_path, loaded_policy.enrollments.len });
    }
    try report_writer.print("store_limit: pass JSON/base64 payload <= {s}\n", .{store.pass_payload_limit_label});
    try appendFuseReport(report_writer, &has_errors);

    const pass_command = try detectPassCommandAlloc(allocator);
    defer allocator.free(pass_command);
    if (try passBackendIsUsable(allocator, pass_command)) {
        try report_writer.print("ok: pass backend is usable: {s}\n", .{pass_command});
    } else {
        has_errors = true;
        try report_writer.print("error: pass backend is not usable: {s}\n", .{pass_command});
        try report_writer.writeAll("hint: run `pass ls` and fix the reported issue before trying File Snitch again\n");
        try report_writer.writeAll("hint: check that GPG works for this shell and that GNUPGHOME points at a usable keyring\n");
    }

    const agent_socket_exists = enrollment.pathExists(agent_socket_path) catch |err| blk: {
        has_errors = true;
        try report_writer.print("error: agent socket path could not be inspected: {s}: {}\n", .{ agent_socket_path, err });
        break :blk false;
    };
    if (agent_socket_exists) {
        try report_writer.print("ok: agent socket path exists: {s}\n", .{agent_socket_path});
    } else {
        try report_writer.print("warn: agent socket path is absent: {s}\n", .{agent_socket_path});
        try report_writer.writeAll("hint: start `file-snitch agent` or install the per-user agent service\n");
    }

    switch (builtin.os.tag) {
        .macos => {
            const helper_command = try detectGuiHelperCommandAlloc(allocator, defaults.osascript_bin_env, "osascript");
            defer allocator.free(helper_command);
            if (try commandExists(allocator, helper_command)) {
                try report_writer.print("ok: macos-ui helper is available: {s}\n", .{helper_command});
            } else {
                try report_writer.print("warn: macos-ui helper is not available: {s}\n", .{helper_command});
                try report_writer.writeAll("hint: install or expose `osascript`, or use `--frontend terminal-pinentry`\n");
            }

            try appendUserServicesReport(allocator, report_writer, &has_errors, .macos, pass_command);
        },
        .linux => {
            const helper_command = try detectGuiHelperCommandAlloc(allocator, defaults.zenity_bin_env, "zenity");
            defer allocator.free(helper_command);
            if (try commandExists(allocator, helper_command)) {
                try report_writer.print("ok: linux-ui helper is available: {s}\n", .{helper_command});
            } else {
                try report_writer.print("warn: linux-ui helper is not available: {s}\n", .{helper_command});
                try report_writer.writeAll("hint: install `zenity`, or use `--frontend terminal-pinentry`\n");
            }

            try appendUserServicesReport(allocator, report_writer, &has_errors, .linux, pass_command);
        },
        else => {},
    }

    for (loaded_policy.enrollments, projection_plan.entries) |entry, projection_entry| {
        if (!enrollment.pathIsWithinDirectory(entry.path, home_dir)) {
            has_errors = true;
            try report_writer.print(
                "error: enrollment is outside the current user's home directory: {s}\n",
                .{entry.path},
            );
        }

        const parent_dir = std.fs.path.dirname(entry.path) orelse {
            has_errors = true;
            try report_writer.print("error: invalid enrollment path: {s}\n", .{entry.path});
            continue;
        };

        const parent_exists = enrollment.directoryExists(parent_dir) catch |err| {
            has_errors = true;
            try report_writer.print("error: parent directory could not be inspected: {s}: {}\n", .{ parent_dir, err });
            continue;
        };
        if (!parent_exists) {
            has_errors = true;
            try report_writer.print("error: parent directory missing: {s}\n", .{parent_dir});
        } else {
            try report_writer.print("ok: parent directory exists: {s}\n", .{parent_dir});
        }

        const store_ref = try guarded_store.?.describeRefAlloc(allocator, entry.object_id);
        defer allocator.free(store_ref);

        const object_exists = guarded_store.?.exists(allocator, entry.object_id) catch |err| switch (err) {
            error.StorePayloadTooLarge => {
                has_errors = true;
                try report_writer.print("error: guarded object exceeds pass payload limit ({s}): {s}\n", .{
                    store.pass_payload_limit_label,
                    store_ref,
                });
                try report_writer.writeAll("hint: the limit applies to File Snitch's JSON/base64 payload, not to `pass` itself\n");
                try report_writer.print("hint: run `file-snitch unenroll {s}` to stream the object back to disk and remove the enrollment\n", .{entry.path});
                continue;
            },
            error.StoreCommandOutputTooLarge => {
                has_errors = true;
                try report_writer.print("error: pass backend command output exceeded capture limit ({s}): {s}\n", .{
                    store.pass_payload_limit_label,
                    store_ref,
                });
                continue;
            },
            else => return err,
        };

        if (object_exists) {
            try report_writer.print("ok: guarded object exists in store: {s}\n", .{store_ref});
        } else {
            has_errors = true;
            try report_writer.print("error: guarded object missing from store: {s}\n", .{store_ref});
        }

        try appendTargetPathReport(allocator, report_writer, &has_errors, entry.path, projection_entry.projection_path);
    }

    for (loaded_policy.decisions) |decision| {
        if (loaded_policy.findEnrollmentIndex(decision.path) == null) {
            has_errors = true;
            try report_writer.print(
                "error: decision path is not enrolled: executable_path={s} path={s}\n",
                .{ decision.executable_path, decision.path },
            );
        }
    }

    report = report_allocating_writer.toArrayList();
    try runtime.stdoutWriteAll(report.items);

    if (options.export_debug_dossier_path) |path| {
        try writeDebugDossier(
            allocator,
            &loaded_policy,
            if (guarded_store) |*backend| backend else null,
            if (projection_plan.entries.len == 0) null else projection_plan.root_path,
            home_dir,
            report.items,
            path,
        );
    }

    if (has_errors) {
        return error.DoctorFailed;
    }
}

fn appendTargetPathReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    target_path: []const u8,
    projection_path: []const u8,
) !void {
    if (try enrollment.symlinkTargetAlloc(allocator, target_path)) |symlink_target| {
        defer allocator.free(symlink_target);
        if (std.mem.eql(u8, symlink_target, projection_path)) {
            const projection_kind = enrollment.pathKind(projection_path) catch |err| {
                has_errors.* = true;
                try writer.print(
                    "error: target path is a dangling projection symlink: {s} -> {s}: {}\n",
                    .{ target_path, projection_path, err },
                );
                return;
            };
            if (projection_kind == .missing) {
                has_errors.* = true;
                try writer.print(
                    "error: target path is a dangling projection symlink: {s} -> {s}\n",
                    .{ target_path, projection_path },
                );
                return;
            }
        }
    }

    const target_kind = enrollment.pathKind(target_path) catch |err| {
        has_errors.* = true;
        if (err == error.NoDevice) {
            try writer.print(
                "error: target path is on a stale or inaccessible device: {s}\nhint: restart `file-snitch run`; if this persists, unmount the affected parent directory and retry\n",
                .{target_path},
            );
            return;
        }
        try writer.print("error: target path could not be inspected: {s}: {}\n", .{ target_path, err });
        return;
    };

    switch (target_kind) {
        .missing => try writer.print("ok: target path currently absent: {s}\n", .{target_path}),
        .file => try writer.print(
            "warn: target path currently exists: {s}\nexpected only while actively projected or before migration cleanup\n",
            .{target_path},
        ),
        .directory => {
            has_errors.* = true;
            try writer.print("error: target path is a directory: {s}\n", .{target_path});
        },
        .other => {
            has_errors.* = true;
            try writer.print("error: target path has unsupported type: {s}\n", .{target_path});
        },
    }
}

fn findEnrollmentIndexByArgument(
    allocator: std.mem.Allocator,
    loaded_policy: *const config.PolicyFile,
    requested_path: []const u8,
) ?usize {
    if (loaded_policy.findEnrollmentIndex(requested_path)) |index| {
        return index;
    }

    const canonical = if (std.fs.path.isAbsolute(requested_path))
        std.Io.Dir.realPathFileAbsoluteAlloc(runtime.io(), requested_path, allocator) catch return null
    else
        std.Io.Dir.cwd().realPathFileAlloc(runtime.io(), requested_path, allocator) catch return null;
    defer allocator.free(canonical);
    return loaded_policy.findEnrollmentIndex(canonical);
}

fn writeDebugDossier(
    allocator: std.mem.Allocator,
    loaded_policy: *const config.PolicyFile,
    guarded_store: ?*store.Backend,
    projection_path: ?[]const u8,
    home_dir: []const u8,
    report: []const u8,
    output_path: []const u8,
) !void {
    const output_dir = std.fs.path.dirname(output_path) orelse ".";
    try std.Io.Dir.cwd().createDirPath(runtime.io(), output_dir);

    var dossier = std.ArrayList(u8).empty;
    defer dossier.deinit(allocator);
    var dossier_allocating_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &dossier);
    const writer = &dossier_allocating_writer.writer;

    var file = try std.Io.Dir.cwd().createFile(runtime.io(), output_path, .{ .truncate = true });
    defer file.close(runtime.io());

    const generated_at = runtime.timestamp();
    const executable_path = std.process.executablePathAlloc(runtime.io(), allocator) catch try allocator.dupe(u8, "unknown");
    defer allocator.free(executable_path);
    const pass_command = try detectPassCommandAlloc(allocator);
    defer allocator.free(pass_command);
    const gpg_command = try allocator.dupe(u8, "gpg");
    defer allocator.free(gpg_command);
    const agent_socket_path = try agent.defaultSocketPathAlloc(allocator);
    defer allocator.free(agent_socket_path);
    const pass_version = try summarizeCommandVersionAlloc(allocator, pass_command);
    defer allocator.free(pass_version);
    const gpg_version = try summarizeCommandVersionAlloc(allocator, gpg_command);
    defer allocator.free(gpg_version);

    try writer.writeAll("# File Snitch Debug Dossier\n\n");
    try writer.print("- generated_at_unix: {d}\n", .{generated_at});
    try writer.print("- executable: `{s}`\n", .{executable_path});
    try writer.print("- file_snitch: `{s}`\n", .{app_meta.version});
    try writer.print("- os: `{s}`\n", .{@tagName(builtin.os.tag)});
    try writer.print("- arch: `{s}`\n", .{@tagName(builtin.cpu.arch)});
    try writer.print("- zig: `{s}`\n", .{builtin.zig_version_string});
    try writer.print("- policy: `{s}`\n", .{loaded_policy.source_path});
    try writer.print("- agent_socket: `{s}`\n", .{agent_socket_path});
    try writer.print("- pass_command: `{s}`\n", .{pass_command});
    try writer.print("- gpg_command: `{s}`\n\n", .{gpg_command});

    try writer.writeAll("## Tool Versions\n\n");
    try writer.print("- pass: {s}\n", .{pass_version});
    try writer.print("- gpg: {s}\n\n", .{gpg_version});

    try writer.writeAll("## Policy Summary\n\n");
    try writer.print("- enrollments: {d}\n", .{loaded_policy.enrollments.len});
    try writer.print("- decisions: {d}\n", .{loaded_policy.decisions.len});
    if (projection_path) |path| {
        const redacted = try redactHomePathAlloc(allocator, home_dir, path);
        defer allocator.free(redacted);
        try writer.print("- projection: `{s}`\n", .{redacted});
    } else {
        try writer.writeAll("- projection: absent\n");
    }
    try writer.print("- store_backend: `{s}`\n", .{backendName(guarded_store)});
    try writer.print("- store_payload_limit: `pass JSON/base64 payload <= {s}`\n\n", .{store.pass_payload_limit_label});

    if (loaded_policy.enrollments.len != 0) {
        try writer.writeAll("### Enrollments\n\n");
        for (loaded_policy.enrollments) |entry| {
            const redacted = try redactHomePathAlloc(allocator, home_dir, entry.path);
            defer allocator.free(redacted);
            const store_ref = try describeStoreRefAlloc(allocator, guarded_store, entry.object_id);
            defer allocator.free(store_ref);
            try writer.print("- path: `{s}` object_id: `{s}` store_ref: `{s}`\n", .{
                redacted,
                entry.object_id,
                store_ref,
            });
        }
        try writer.writeByte('\n');
    }

    if (loaded_policy.decisions.len != 0) {
        try writer.writeAll("### Durable Decisions\n\n");
        for (loaded_policy.decisions) |decision| {
            const redacted = try redactHomePathAlloc(allocator, home_dir, decision.path);
            defer allocator.free(redacted);
            try writer.print(
                "- executable_path: `{s}` path: `{s}` approval_class: `{s}` outcome: `{s}` expires_at: `{s}`\n",
                .{
                    decision.executable_path,
                    redacted,
                    decision.approval_class,
                    decision.outcome,
                    decision.expires_at orelse "null",
                },
            );
        }
        try writer.writeByte('\n');
    }

    const redacted_report = try redactHomeOccurrencesAlloc(allocator, home_dir, report);
    defer allocator.free(redacted_report);

    try writer.writeAll("## Doctor Output\n\n```text\n");
    try writer.writeAll(redacted_report);
    if (report.len == 0 or report[report.len - 1] != '\n') {
        try writer.writeByte('\n');
    }
    try writer.writeAll("```\n");
    dossier = dossier_allocating_writer.toArrayList();
    try file.writeStreamingAll(runtime.io(), dossier.items);
}

fn detectPassCommandAlloc(allocator: std.mem.Allocator) ![]u8 {
    return runtime.getEnvVarOwned(allocator, defaults.pass_bin_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, "pass"),
        else => return err,
    };
}

fn detectGuiHelperCommandAlloc(
    allocator: std.mem.Allocator,
    env_name: []const u8,
    default_value: []const u8,
) ![]u8 {
    return runtime.getEnvVarOwned(allocator, env_name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, default_value),
        else => return err,
    };
}

fn summarizeCommandVersionAlloc(allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ command, "--version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch |err| switch (err) {
        error.FileNotFound => return allocator.dupe(u8, "not found"),
        else => return err,
    };
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                return allocator.dupe(u8, "unavailable");
            }
        },
        else => return allocator.dupe(u8, "unavailable"),
    }

    const output = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (output.len == 0) {
        return allocator.dupe(u8, "unavailable");
    }

    const first_line = std.mem.sliceTo(output, '\n');
    return allocator.dupe(u8, first_line);
}

fn passBackendIsUsable(allocator: std.mem.Allocator, command: []const u8) !bool {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ command, "ls" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn commandExists(allocator: std.mem.Allocator, command: []const u8) !bool {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ "sh", "-lc", "command -v \"$1\" >/dev/null 2>&1", "sh", command },
        .stdout_limit = .limited(1),
        .stderr_limit = .limited(1),
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn commandExistsInPath(allocator: std.mem.Allocator, command: []const u8, path: []const u8) !bool {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ "sh", "-lc", "PATH=\"$2\"; command -v \"$1\" >/dev/null 2>&1", "sh", command, path },
        .stdout_limit = .limited(1),
        .stderr_limit = .limited(1),
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

const launchd_default_path = "/usr/bin:/bin:/usr/sbin:/sbin";

const ServicePassProbe = struct {
    command: []u8,
    available: bool,
    source: []const u8,

    fn deinit(self: *ServicePassProbe, allocator: std.mem.Allocator) void {
        allocator.free(self.command);
        self.* = undefined;
    }
};

fn ensureProjectionServiceCanLoadPass(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .macos) return;

    const home_dir = try enrollment.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);
    const run_service_path = try user_services.macosLaunchAgentPathAlloc(allocator, home_dir, "dev.file-snitch.run.plist");
    defer allocator.free(run_service_path);

    const service_exists = enrollment.pathExists(run_service_path) catch |err| {
        std.debug.print("error: launchd run service file could not be inspected: {s}: {}\n", .{ run_service_path, err });
        return error.InvalidUsage;
    };
    if (!service_exists) return;

    var probe = macosRunServicePassProbeAlloc(allocator, run_service_path) catch |err| {
        std.debug.print(
            "error: launchd run service pass probe failed: {s}: {}\n",
            .{ run_service_path, err },
        );
        std.debug.print("hint: enrollment was aborted before moving the file into the guarded store\n", .{});
        std.debug.print(
            "hint: reinstall the service with `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n",
            .{},
        );
        return error.InvalidUsage;
    };
    defer probe.deinit(allocator);
    if (probe.available) return;

    std.debug.print(
        "error: launchd run service cannot find `pass` in its configured environment: {s}\n",
        .{probe.command},
    );
    std.debug.print("hint: enrollment was aborted before moving the file into the guarded store\n", .{});
    std.debug.print(
        "hint: reinstall the service with `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n",
        .{},
    );
    std.debug.print("hint: or set FILE_SNITCH_PASS_BIN in {s}\n", .{run_service_path});
    return error.InvalidUsage;
}

fn appendMacosRunServicePassReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    run_service_path: []const u8,
) !void {
    const service_exists = enrollment.pathExists(run_service_path) catch |err| {
        has_errors.* = true;
        try writer.print("error: launchd run service file could not be inspected for pass access: {s}: {}\n", .{ run_service_path, err });
        return;
    };
    if (!service_exists) return;

    var probe = macosRunServicePassProbeAlloc(allocator, run_service_path) catch |err| {
        has_errors.* = true;
        try writer.print(
            "error: launchd run service pass probe failed: {s}: {}\n",
            .{ run_service_path, err },
        );
        try writer.writeAll("hint: reinstall the services to refresh the run LaunchAgent\n");
        return;
    };
    defer probe.deinit(allocator);

    if (probe.available) {
        try writer.print(
            "ok: launchd run service pass backend is available via {s}: {s}\n",
            .{ probe.source, probe.command },
        );
        return;
    }

    has_errors.* = true;
    try writer.print(
        "error: launchd run service cannot find `pass` via {s}: {s}\n",
        .{ probe.source, probe.command },
    );
    try writer.writeAll("hint: the run service uses launchd's restricted environment, not your interactive shell PATH\n");
    try writer.writeAll("hint: reinstall the services with `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n");
    try writer.print("hint: or set FILE_SNITCH_PASS_BIN in {s}\n", .{run_service_path});
}

fn macosRunServicePassProbeAlloc(allocator: std.mem.Allocator, run_service_path: []const u8) !ServicePassProbe {
    if (try macosRunServicePassProbeFromLaunchctlAlloc(allocator)) |probe| {
        return probe;
    }
    return macosRunServicePassProbeFromPlistAlloc(allocator, run_service_path);
}

fn macosRunServicePassProbeFromLaunchctlAlloc(allocator: std.mem.Allocator) !?ServicePassProbe {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ "sh", "-lc", "launchctl print \"gui/$(id -u)/dev.file-snitch.run\"" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(4096),
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) return null;
        },
        else => return null,
    }

    return try macosRunServicePassProbeFromTextAlloc(
        allocator,
        result.stdout,
        launchctlStringValueAlloc,
        .{
            .pass_bin = "loaded launchd FILE_SNITCH_PASS_BIN",
            .path = "loaded launchd PATH",
            .default_path = "loaded launchd default PATH",
        },
    );
}

fn macosRunServicePassProbeFromPlistAlloc(allocator: std.mem.Allocator, run_service_path: []const u8) !ServicePassProbe {
    const contents = try std.Io.Dir.cwd().readFileAlloc(runtime.io(), run_service_path, allocator, .limited(64 * 1024));
    defer allocator.free(contents);

    return (try macosRunServicePassProbeFromTextAlloc(
        allocator,
        contents,
        plistStringValueAlloc,
        .{
            .pass_bin = defaults.pass_bin_env,
            .path = "launchd PATH",
            .default_path = "launchd default PATH",
        },
    )).?;
}

const ServicePassProbeSources = struct {
    pass_bin: []const u8,
    path: []const u8,
    default_path: []const u8,
};

fn macosRunServicePassProbeFromTextAlloc(
    allocator: std.mem.Allocator,
    contents: []const u8,
    comptime stringValueAlloc: fn (std.mem.Allocator, []const u8, []const u8) anyerror!?[]u8,
    sources: ServicePassProbeSources,
) !?ServicePassProbe {
    if (try stringValueAlloc(allocator, contents, defaults.pass_bin_env)) |command| {
        errdefer allocator.free(command);
        const available = if (std.fs.path.isAbsolute(command))
            try commandExists(allocator, command)
        else blk: {
            const service_path = (try stringValueAlloc(allocator, contents, "PATH")) orelse try allocator.dupe(u8, launchd_default_path);
            defer allocator.free(service_path);
            break :blk try commandExistsInPath(allocator, command, service_path);
        };
        return .{
            .command = command,
            .available = available,
            .source = sources.pass_bin,
        };
    }

    const service_path = (try stringValueAlloc(allocator, contents, "PATH")) orelse try allocator.dupe(u8, launchd_default_path);
    defer allocator.free(service_path);
    return .{
        .command = try allocator.dupe(u8, "pass"),
        .available = try commandExistsInPath(allocator, "pass", service_path),
        .source = if (std.mem.eql(u8, service_path, launchd_default_path)) sources.default_path else sources.path,
    };
}

fn launchctlStringValueAlloc(allocator: std.mem.Allocator, contents: []const u8, key: []const u8) !?[]u8 {
    var value: ?[]u8 = null;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r\n");
        if (!std.mem.startsWith(u8, trimmed, key)) continue;

        const after_key = std.mem.trim(u8, trimmed[key.len..], " \t");
        if (!std.mem.startsWith(u8, after_key, "=>")) continue;

        if (value) |previous| allocator.free(previous);
        value = try allocator.dupe(u8, std.mem.trim(u8, after_key[2..], " \t\r\n"));
    }
    return value;
}

fn plistStringValueAlloc(allocator: std.mem.Allocator, contents: []const u8, key: []const u8) !?[]u8 {
    const key_tag = try std.fmt.allocPrint(allocator, "<key>{s}</key>", .{key});
    defer allocator.free(key_tag);
    const key_index = std.mem.indexOf(u8, contents, key_tag) orelse return null;
    const after_key = contents[key_index + key_tag.len ..];
    const open_tag = "<string>";
    const close_tag = "</string>";
    const open_index = std.mem.indexOf(u8, after_key, open_tag) orelse return null;
    const value_start = open_index + open_tag.len;
    const after_open = after_key[value_start..];
    const close_index = std.mem.indexOf(u8, after_open, close_tag) orelse return null;
    return @as(?[]u8, try allocator.dupe(u8, std.mem.trim(u8, after_open[0..close_index], " \t\r\n")));
}

fn backendName(guarded_store: ?*store.Backend) []const u8 {
    if (guarded_store) |value| return value.name();
    return "none";
}

fn describeStoreRefAlloc(
    allocator: std.mem.Allocator,
    guarded_store: ?*store.Backend,
    object_id: []const u8,
) ![]u8 {
    if (guarded_store) |backend| {
        return backend.describeRefAlloc(allocator, object_id);
    }
    return std.fmt.allocPrint(allocator, "unknown:{s}", .{object_id});
}

fn redactHomePathAlloc(allocator: std.mem.Allocator, home_dir: []const u8, path: []const u8) ![]u8 {
    if (!enrollment.pathIsWithinDirectory(path, home_dir) and !std.mem.eql(u8, path, home_dir)) {
        return allocator.dupe(u8, path);
    }
    if (std.mem.eql(u8, path, home_dir)) {
        return allocator.dupe(u8, "~");
    }
    const suffix = path[home_dir.len..];
    return std.fmt.allocPrint(allocator, "~{s}", .{suffix});
}

fn redactHomeOccurrencesAlloc(allocator: std.mem.Allocator, home_dir: []const u8, text: []const u8) ![]u8 {
    const replacement = "~";
    const count = std.mem.count(u8, text, home_dir);
    if (count == 0) {
        return allocator.dupe(u8, text);
    }

    const redacted_len = text.len - (count * home_dir.len) + (count * replacement.len);
    const redacted = try allocator.alloc(u8, redacted_len);
    _ = std.mem.replace(u8, text, home_dir, replacement, redacted);
    return redacted;
}

fn appendUserServicesReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    platform: user_services.Platform,
    pass_command: []const u8,
) !void {
    var rendered = user_services.renderExpectedAlloc(allocator, .{
        .platform = platform,
        .pass_bin_path = pass_command,
    }) catch |err| {
        has_errors.* = true;
        try writer.print("error: could not render expected user services from this binary: {}\n", .{err});
        try writer.writeAll("hint: make sure `file-snitch` and `pass` are executable, or pass explicit paths to `file-snitch services install`\n");
        return;
    };
    defer rendered.deinit(allocator);

    switch (platform) {
        .macos => {
            try appendRenderedServiceReport(allocator, writer, has_errors, rendered, rendered.agent, "launchd agent");
            try appendRenderedServiceReport(allocator, writer, has_errors, rendered, rendered.run, "launchd run");
            try appendMacosRunServicePassReport(allocator, writer, has_errors, rendered.run.install_path);
        },
        .linux => {
            try appendRenderedServiceReport(allocator, writer, has_errors, rendered, rendered.agent, "systemd user agent");
            try appendRenderedServiceReport(allocator, writer, has_errors, rendered, rendered.run, "systemd user run");
        },
    }
}

fn appendRenderedServiceReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    rendered: user_services.RenderedServices,
    service: user_services.RenderedService,
    label: []const u8,
) !void {
    const installed_matches = try appendRenderedServiceFileReport(
        allocator,
        writer,
        has_errors,
        service,
        label,
    );
    try appendLoadedServiceReport(
        allocator,
        writer,
        has_errors,
        rendered,
        service,
        label,
        installed_matches,
    );
}

fn appendRenderedServiceFileReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    service: user_services.RenderedService,
    label: []const u8,
) !bool {
    const installed = std.Io.Dir.cwd().readFileAlloc(runtime.io(), service.install_path, allocator, .limited(128 * 1024)) catch |err| switch (err) {
        error.FileNotFound => {
            try writer.print("warn: {s} service file is absent: {s}\n", .{ label, service.install_path });
            try writer.writeAll("hint: run `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n");
            return false;
        },
        else => {
            has_errors.* = true;
            try writer.print("error: {s} service file could not be inspected: {s}: {}\n", .{ label, service.install_path, err });
            return false;
        },
    };
    defer allocator.free(installed);

    if (std.mem.eql(u8, installed, service.contents)) {
        try writer.print("ok: {s} service file matches current render: {s}\n", .{ label, service.install_path });
        return true;
    }

    has_errors.* = true;
    try writer.print("error: {s} service file is stale: {s}\n", .{ label, service.install_path });
    try writer.writeAll("hint: rerun `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n");
    return false;
}

fn appendLoadedServiceReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    rendered: user_services.RenderedServices,
    service: user_services.RenderedService,
    label: []const u8,
    installed_matches: bool,
) !void {
    const loaded = user_services.loadedConfigAlloc(allocator, rendered.platform, service) catch |err| {
        has_errors.* = true;
        try writer.print("error: {s} loaded config could not be inspected: {}\n", .{ label, err });
        return;
    } orelse {
        if (installed_matches) {
            has_errors.* = true;
            try writer.print("error: {s} service file matches current render, but the service manager has no loaded config\n", .{label});
            try writer.writeAll("hint: rerun `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n");
        } else {
            try writer.print("warn: {s} loaded config is absent\n", .{label});
        }
        return;
    };
    defer allocator.free(loaded);

    const matches_loaded = switch (rendered.platform) {
        .macos => try macosLoadedServiceMatchesRender(allocator, rendered, service, loaded),
        .linux => blk: {
            const body = try user_services.systemdCatBodyAlloc(allocator, loaded);
            defer allocator.free(body);
            break :blk std.mem.eql(
                u8,
                std.mem.trim(u8, body, "\n"),
                std.mem.trim(u8, service.contents, "\n"),
            );
        },
    };

    if (matches_loaded) {
        try writer.print("ok: {s} loaded config matches current render\n", .{label});
        return;
    }

    has_errors.* = true;
    try writer.print("error: {s} loaded config is stale\n", .{label});
    switch (rendered.platform) {
        .macos => try writer.writeAll("hint: rerun `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"` so launchd reloads the current plist\n"),
        .linux => try writer.writeAll("hint: rerun `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"` so systemd reloads the current unit\n"),
    }
}

fn macosLoadedServiceMatchesRender(
    allocator: std.mem.Allocator,
    rendered: user_services.RenderedServices,
    service: user_services.RenderedService,
    loaded: []const u8,
) !bool {
    if (std.mem.indexOf(u8, loaded, rendered.bin_path) == null) return false;

    if (std.mem.eql(u8, service.label, "dev.file-snitch.agent")) {
        return std.mem.indexOf(u8, loaded, "agent") != null and
            std.mem.indexOf(u8, loaded, "--frontend") != null and
            std.mem.indexOf(u8, loaded, "macos-ui") != null;
    }

    if (std.mem.indexOf(u8, loaded, "run") == null or std.mem.indexOf(u8, loaded, "prompt") == null) {
        return false;
    }

    const loaded_pass_bin = (try launchctlStringValueAlloc(allocator, loaded, defaults.pass_bin_env)) orelse return false;
    defer allocator.free(loaded_pass_bin);
    const loaded_path = (try launchctlStringValueAlloc(allocator, loaded, "PATH")) orelse return false;
    defer allocator.free(loaded_path);

    return std.mem.eql(u8, loaded_pass_bin, rendered.pass_bin_path) and
        std.mem.eql(u8, loaded_path, rendered.service_path);
}

fn appendFuseReport(writer: anytype, has_errors: *bool) !void {
    const environment = fuse.probe() catch {
        has_errors.* = true;
        try writer.writeAll("error: FUSE runtime is not available\n");
        switch (builtin.os.tag) {
            .macos => try writer.writeAll("hint: install macFUSE and allow its system extension before running File Snitch\n"),
            .linux => try writer.writeAll("hint: install distro FUSE packages and confirm `/dev/fuse` is available to your user\n"),
            else => try writer.writeAll("hint: install a supported FUSE runtime for this platform\n"),
        }
        return;
    };

    try writer.print(
        "ok: FUSE runtime is available: backend={s} fuse={d}.{d}\n",
        .{ environment.backend_name, environment.fuse_major_version, environment.fuse_minor_version },
    );
}
