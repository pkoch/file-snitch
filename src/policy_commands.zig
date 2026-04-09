const std = @import("std");
const config = @import("config.zig");
const enrollment = @import("enrollment.zig");
const store = @import("store.zig");

pub fn enroll(allocator: std.mem.Allocator, policy_path: []const u8, target_path: []const u8) !void {
    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();
    var guarded_store = try store.Backend.initPass(allocator);
    defer guarded_store.deinit(allocator);

    if (loaded_policy.findEnrollmentIndex(target_path) != null) {
        std.debug.print("error: already enrolled: {s}\n", .{target_path});
        return error.InvalidUsage;
    }

    const object_id = try enrollment.allocateObjectId(allocator, &guarded_store);
    defer allocator.free(object_id);

    try enrollment.moveFileIntoGuardedStore(allocator, &guarded_store, target_path, object_id);
    errdefer enrollment.moveGuardedFileBack(allocator, &guarded_store, object_id, target_path) catch {};

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
    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();
    var guarded_store = try store.Backend.initPass(allocator);
    defer guarded_store.deinit(allocator);

    const enrollment_index = findEnrollmentIndexByArgument(allocator, &loaded_policy, target_path) orelse {
        std.debug.print("error: not enrolled: {s}\n", .{target_path});
        return error.InvalidUsage;
    };

    const enrolled_path = loaded_policy.enrollments[enrollment_index].path;
    if (enrollment.pathExists(enrolled_path)) {
        std.debug.print(
            "error: target path currently exists: {s}\nstop the active projection before unenrolling\n",
            .{enrolled_path},
        );
        return error.InvalidUsage;
    }

    const object_id = loaded_policy.enrollments[enrollment_index].object_id;
    try enrollment.moveGuardedFileBack(allocator, &guarded_store, object_id, enrolled_path);
    errdefer enrollment.moveFileIntoGuardedStore(allocator, &guarded_store, enrolled_path, object_id) catch {};

    loaded_policy.removeDecisionsForPath(enrolled_path);
    var removed = loaded_policy.removeEnrollmentAt(enrollment_index);
    defer removed.deinit(allocator);

    try loaded_policy.saveToFile();

    std.debug.print(
        "file-snitch: unenrolled {s} from {s}\n",
        .{ removed.path, loaded_policy.source_path },
    );
}

pub fn status(allocator: std.mem.Allocator, policy_path: []const u8) !void {
    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();
    var guarded_store: ?store.Backend = if (loaded_policy.enrollments.len != 0)
        try store.Backend.initPass(allocator)
    else
        null;
    defer if (guarded_store) |*backend| backend.deinit(allocator);

    var mount_plan = try loaded_policy.deriveMountPlan(allocator);
    defer mount_plan.deinit();

    std.debug.print("policy: {s}\n", .{loaded_policy.source_path});
    std.debug.print("enrollments: {d}\n", .{loaded_policy.enrollments.len});
    std.debug.print("decisions: {d}\n", .{loaded_policy.decisions.len});
    std.debug.print("planned_mounts: {d}\n", .{mount_plan.paths.len});

    for (mount_plan.paths) |mount_path| {
        std.debug.print("mount: {s}\n", .{mount_path});
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

pub fn doctor(allocator: std.mem.Allocator, policy_path: []const u8) !void {
    var loaded_policy = try config.loadFromFile(allocator, policy_path);
    defer loaded_policy.deinit();
    var guarded_store: ?store.Backend = if (loaded_policy.enrollments.len != 0)
        try store.Backend.initPass(allocator)
    else
        null;
    defer if (guarded_store) |*backend| backend.deinit(allocator);

    var mount_plan = try loaded_policy.deriveMountPlan(allocator);
    defer mount_plan.deinit();

    var has_errors = false;

    std.debug.print("policy: ok ({s})\n", .{loaded_policy.source_path});
    std.debug.print("mount_plan: {d} mounts for {d} enrollments\n", .{ mount_plan.paths.len, loaded_policy.enrollments.len });

    for (loaded_policy.enrollments) |entry| {
        const parent_dir = std.fs.path.dirname(entry.path) orelse {
            has_errors = true;
            std.debug.print("error: invalid enrollment path: {s}\n", .{entry.path});
            continue;
        };

        if (!enrollment.directoryExists(parent_dir)) {
            has_errors = true;
            std.debug.print("error: parent directory missing: {s}\n", .{parent_dir});
        } else {
            std.debug.print("ok: parent directory exists: {s}\n", .{parent_dir});
        }

        const store_ref = try guarded_store.?.describeRefAlloc(allocator, entry.object_id);
        defer allocator.free(store_ref);

        if (try guarded_store.?.exists(allocator, entry.object_id)) {
            std.debug.print("ok: guarded object exists in store: {s}\n", .{store_ref});
        } else {
            has_errors = true;
            std.debug.print("error: guarded object missing from store: {s}\n", .{store_ref});
        }

        switch (enrollment.pathKind(entry.path)) {
            .missing => std.debug.print("ok: target path currently absent: {s}\n", .{entry.path}),
            .file => std.debug.print(
                "warn: target path currently exists: {s}\nexpected only while actively projected or before migration cleanup\n",
                .{entry.path},
            ),
            .directory => {
                has_errors = true;
                std.debug.print("error: target path is a directory: {s}\n", .{entry.path});
            },
            .other => {
                has_errors = true;
                std.debug.print("error: target path has unsupported type: {s}\n", .{entry.path});
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

fn findEnrollmentIndexByArgument(
    allocator: std.mem.Allocator,
    loaded_policy: *const config.PolicyFile,
    requested_path: []const u8,
) ?usize {
    if (loaded_policy.findEnrollmentIndex(requested_path)) |index| {
        return index;
    }

    const canonical = std.fs.realpathAlloc(allocator, requested_path) catch return null;
    defer allocator.free(canonical);
    return loaded_policy.findEnrollmentIndex(canonical);
}
