const std = @import("std");
const builtin = @import("builtin");
const config = @import("../config.zig");
const enrollment = @import("../enrollment.zig");
const runtime = @import("../runtime.zig");
const store = @import("../store.zig");
const user_services = @import("../user_services.zig");

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

    try loaded_policy.appendEnrollment(target_path, object_id);
    var enrollment_persisted = false;
    errdefer {
        if (enrollment_persisted) {
            removePersistedEnrollment(&loaded_policy, target_path) catch |err| {
                std.debug.panic("failed to roll back enrollment policy update for {s}: {}", .{ target_path, err });
            };
        } else {
            removeEnrollmentFromMemory(&loaded_policy, target_path);
        }
    }
    try loaded_policy.saveToFile();
    enrollment_persisted = true;

    try enrollment.moveFileIntoGuardedStore(allocator, &guarded_store, target_path, object_id);

    std.debug.print(
        "file-snitch: enrolled {s} as {s} in {s}\n",
        .{ target_path, object_id, loaded_policy.source_path },
    );
}

fn ensureProjectionServiceCanLoadPass(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag != .macos) return;

    const home_dir = try enrollment.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);
    const run_service_path = try user_services.macosLaunchAgentPathAlloc(allocator, home_dir, "dev.file-snitch.run.plist");
    defer allocator.free(run_service_path);

    const service_exists = enrollment.pathExists(allocator, run_service_path) catch |err| {
        std.debug.print("error: launchd run service file could not be inspected: {s}: {}\n", .{ run_service_path, err });
        return error.InvalidUsage;
    };
    if (!service_exists) return;

    var probe = user_services.macosRunServicePassProbeAlloc(allocator, run_service_path) catch |err| {
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

    if (try enrollment.pathExists(allocator, pending.enrolled_path)) {
        std.debug.print(
            "file-snitch: waiting for active projection to stop: {s}\n",
            .{pending.enrolled_path},
        );
        try waitForTargetPathToDisappear(allocator, pending.enrolled_path);
    }

    try restoreGuardedFileBackIfStillUnenrolled(allocator, policy_path, &guarded_store, pending.object_id, pending.enrolled_path);
    restore_policy_on_error = false;
    removePendingUnenrollRecord(allocator, pending.policy_source_path, pending.object_id) catch |err| {
        std.debug.print(
            "warn: unenrolled {s}, but failed to remove pending unenroll record: {}\n",
            .{ pending.enrolled_path, err },
        );
    };
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

    // The saved policy must drop this enrollment so the projection tears down,
    // so keep the object mapping durable until the guarded file is restored.
    try writePendingUnenrollRecord(allocator, loaded_policy.source_path, removed.path, removed.object_id);
    errdefer removePendingUnenrollRecord(allocator, loaded_policy.source_path, removed.object_id) catch |err| {
        std.debug.panic("failed to roll back pending unenroll record for {s}: {}", .{ removed.path, err });
    };

    try loaded_policy.saveToFile();

    return .{
        .enrolled_path = removed.path,
        .object_id = removed.object_id,
        .policy_source_path = policy_source_path,
    };
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
        removePendingUnenrollRecord(allocator, loaded_policy.source_path, object_id) catch |err| {
            std.debug.print(
                "warn: failed to remove stale pending unenroll record for {s}: {}\n",
                .{ enrolled_path, err },
            );
        };
        return;
    }

    try loaded_policy.appendEnrollment(enrolled_path, object_id);
    try loaded_policy.saveToFile();
    removePendingUnenrollRecord(allocator, loaded_policy.source_path, object_id) catch |err| {
        std.debug.print(
            "warn: restored policy enrollment for {s}, but failed to remove pending unenroll record: {}\n",
            .{ enrolled_path, err },
        );
    };
}

fn removeEnrollmentFromMemory(loaded_policy: *config.PolicyFile, enrolled_path: []const u8) void {
    const enrollment_index = loaded_policy.findEnrollmentIndex(enrolled_path) orelse return;
    var removed = loaded_policy.removeEnrollmentAt(enrollment_index);
    removed.deinit(loaded_policy.allocator);
}

fn removePersistedEnrollment(loaded_policy: *config.PolicyFile, enrolled_path: []const u8) !void {
    removeEnrollmentFromMemory(loaded_policy, enrolled_path);
    try loaded_policy.saveToFile();
}

const PendingUnenrollRecord = struct {
    version: u32 = 1,
    path: []const u8,
    object_id: []const u8,
};

fn pendingUnenrollPathAlloc(allocator: std.mem.Allocator, policy_path: []const u8, object_id: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.pending-unenroll.{s}", .{ policy_path, object_id });
}

fn writePendingUnenrollRecord(
    allocator: std.mem.Allocator,
    policy_path: []const u8,
    enrolled_path: []const u8,
    object_id: []const u8,
) !void {
    const pending_path = try pendingUnenrollPathAlloc(allocator, policy_path, object_id);
    defer allocator.free(pending_path);
    const parent_dir_path = std.fs.path.dirname(pending_path) orelse return error.InvalidPolicyPath;

    var parent_dir = try std.Io.Dir.openDirAbsolute(runtime.io(), parent_dir_path, .{});
    defer parent_dir.close(runtime.io());

    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    var allocating_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &buffer);
    try std.json.Stringify.value(PendingUnenrollRecord{
        .path = enrolled_path,
        .object_id = object_id,
    }, .{}, &allocating_writer.writer);
    buffer = allocating_writer.toArrayList();

    var atomic_file = try parent_dir.createFileAtomic(runtime.io(), std.fs.path.basename(pending_path), .{
        .permissions = .fromMode(0o600),
        .replace = true,
    });
    defer atomic_file.deinit(runtime.io());

    try atomic_file.file.writeStreamingAll(runtime.io(), buffer.items);
    try atomic_file.replace(runtime.io());
}

fn removePendingUnenrollRecord(allocator: std.mem.Allocator, policy_path: []const u8, object_id: []const u8) !void {
    const pending_path = try pendingUnenrollPathAlloc(allocator, policy_path, object_id);
    defer allocator.free(pending_path);
    std.Io.Dir.deleteFileAbsolute(runtime.io(), pending_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
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

fn waitForTargetPathToDisappear(allocator: std.mem.Allocator, enrolled_path: []const u8) !void {
    const deadline_ms = runtime.milliTimestamp() + projection_teardown_timeout_ms;
    while (runtime.milliTimestamp() < deadline_ms) {
        if (!try enrollment.pathExists(allocator, enrolled_path)) {
            return;
        }

        std.Io.sleep(runtime.io(), .fromMilliseconds(projection_teardown_poll_ms), .awake) catch |err| {
            std.debug.print("warn: projection teardown wait sleep failed: {}\n", .{err});
        };
    }

    if (!try enrollment.pathExists(allocator, enrolled_path)) {
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
