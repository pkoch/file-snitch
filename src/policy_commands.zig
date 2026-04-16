const std = @import("std");
const agent = @import("agent.zig");
const app_meta = @import("app_meta.zig");
const builtin = @import("builtin");
const config = @import("config.zig");
const defaults = @import("defaults.zig");
const enrollment = @import("enrollment.zig");
const fuse = @import("fuse/shim.zig");
const store = @import("store.zig");

pub fn enroll(allocator: std.mem.Allocator, policy_path: []const u8, target_path: []const u8) !void {
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

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
    var policy_lock = try config.acquirePolicyLock(allocator, policy_path);
    defer policy_lock.deinit();

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

    var mount_plan = try loaded_policy.deriveMountPlan(allocator);
    defer mount_plan.deinit();

    var report = std.ArrayList(u8).empty;
    defer report.deinit(allocator);
    const report_writer = report.writer(allocator);

    var has_errors = false;
    const home_dir = enrollment.currentUserHomeAlloc(allocator) catch |err| switch (err) {
        else => return err,
    };
    defer allocator.free(home_dir);
    const agent_socket_path = try agent.defaultSocketPathAlloc(allocator);
    defer allocator.free(agent_socket_path);

    try report_writer.print("policy: ok ({s})\n", .{loaded_policy.source_path});
    try report_writer.print("mount_plan: {d} mounts for {d} enrollments\n", .{ mount_plan.paths.len, loaded_policy.enrollments.len });
    appendFuseReport(report_writer, &has_errors) catch |err| switch (err) {
        else => return err,
    };

    if (loaded_policy.enrollments.len != 0) {
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
    }

    if (enrollment.pathExists(agent_socket_path)) {
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

            const agent_service_path = try defaultMacosLaunchAgentPathAlloc(allocator, home_dir, "dev.file-snitch.agent.plist");
            defer allocator.free(agent_service_path);
            const run_service_path = try defaultMacosLaunchAgentPathAlloc(allocator, home_dir, "dev.file-snitch.run.plist");
            defer allocator.free(run_service_path);
            try appendServicePathReport(report_writer, "launchd agent", agent_service_path);
            try appendServicePathReport(report_writer, "launchd run", run_service_path);
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

            const agent_service_path = try defaultLinuxUserUnitPathAlloc(allocator, home_dir, "file-snitch-agent.service");
            defer allocator.free(agent_service_path);
            const run_service_path = try defaultLinuxUserUnitPathAlloc(allocator, home_dir, "file-snitch-run.service");
            defer allocator.free(run_service_path);
            try appendServicePathReport(report_writer, "systemd user agent", agent_service_path);
            try appendServicePathReport(report_writer, "systemd user run", run_service_path);
        },
        else => {},
    }

    for (loaded_policy.enrollments) |entry| {
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

        if (!enrollment.directoryExists(parent_dir)) {
            has_errors = true;
            try report_writer.print("error: parent directory missing: {s}\n", .{parent_dir});
        } else {
            try report_writer.print("ok: parent directory exists: {s}\n", .{parent_dir});
        }

        const store_ref = try guarded_store.?.describeRefAlloc(allocator, entry.object_id);
        defer allocator.free(store_ref);

        if (try guarded_store.?.exists(allocator, entry.object_id)) {
            try report_writer.print("ok: guarded object exists in store: {s}\n", .{store_ref});
        } else {
            has_errors = true;
            try report_writer.print("error: guarded object missing from store: {s}\n", .{store_ref});
        }

        switch (enrollment.pathKind(entry.path)) {
            .missing => try report_writer.print("ok: target path currently absent: {s}\n", .{entry.path}),
            .file => try report_writer.print(
                "warn: target path currently exists: {s}\nexpected only while actively projected or before migration cleanup\n",
                .{entry.path},
            ),
            .directory => {
                has_errors = true;
                try report_writer.print("error: target path is a directory: {s}\n", .{entry.path});
            },
            .other => {
                has_errors = true;
                try report_writer.print("error: target path has unsupported type: {s}\n", .{entry.path});
            },
        }
    }

    for (loaded_policy.decisions) |decision| {
        if (loaded_policy.findEnrollmentIndex(decision.path) == null) {
            has_errors = true;
            try report_writer.print(
                "error: decision path is not enrolled: executable_path={s} uid={d} path={s}\n",
                .{ decision.executable_path, decision.uid, decision.path },
            );
        }
    }

    try std.fs.File.stdout().writeAll(report.items);

    if (options.export_debug_dossier_path) |path| {
        try writeDebugDossier(
            allocator,
            &loaded_policy,
            guarded_store,
            mount_plan.paths,
            home_dir,
            report.items,
            path,
        );
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

fn writeDebugDossier(
    allocator: std.mem.Allocator,
    loaded_policy: *const config.PolicyFile,
    guarded_store: ?store.Backend,
    mount_paths: []const []const u8,
    home_dir: []const u8,
    report: []const u8,
    output_path: []const u8,
) !void {
    const output_dir = std.fs.path.dirname(output_path) orelse ".";
    try std.fs.cwd().makePath(output_dir);

    var dossier = std.ArrayList(u8).empty;
    defer dossier.deinit(allocator);
    const writer = dossier.writer(allocator);

    var file = try std.fs.cwd().createFile(output_path, .{ .truncate = true });
    defer file.close();

    const generated_at = std.time.timestamp();
    const executable_path = std.fs.selfExePathAlloc(allocator) catch try allocator.dupe(u8, "unknown");
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
    try writer.print("- planned_mounts: {d}\n", .{mount_paths.len});
    try writer.print("- store_backend: `{s}`\n\n", .{backendName(guarded_store)});

    if (mount_paths.len != 0) {
        try writer.writeAll("### Planned Mounts\n\n");
        for (mount_paths) |mount_path| {
            const redacted = try redactHomePathAlloc(allocator, home_dir, mount_path);
            defer allocator.free(redacted);
            try writer.print("- `{s}`\n", .{redacted});
        }
        try writer.writeByte('\n');
    }

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
                "- executable_path: `{s}` uid: `{d}` path: `{s}` approval_class: `{s}` outcome: `{s}` expires_at: `{s}`\n",
                .{
                    decision.executable_path,
                    decision.uid,
                    redacted,
                    decision.approval_class,
                    decision.outcome,
                    decision.expires_at orelse "null",
                },
            );
        }
        try writer.writeByte('\n');
    }

    try writer.writeAll("## Doctor Output\n\n```text\n");
    try writer.writeAll(report);
    if (report.len == 0 or report[report.len - 1] != '\n') {
        try writer.writeByte('\n');
    }
    try writer.writeAll("```\n");
    try file.writeAll(dossier.items);
}

fn detectPassCommandAlloc(allocator: std.mem.Allocator) ![]u8 {
    return std.process.getEnvVarOwned(allocator, defaults.pass_bin_env) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, "pass"),
        else => return err,
    };
}

fn detectGuiHelperCommandAlloc(
    allocator: std.mem.Allocator,
    env_name: []const u8,
    default_value: []const u8,
) ![]u8 {
    return std.process.getEnvVarOwned(allocator, env_name) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => try allocator.dupe(u8, default_value),
        else => return err,
    };
}

fn summarizeCommandVersionAlloc(allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ command, "--version" },
        .max_output_bytes = 4096,
    }) catch |err| switch (err) {
        error.FileNotFound => return allocator.dupe(u8, "not found"),
        else => return err,
    };
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);

    switch (result.term) {
        .Exited => |code| {
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
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ command, "ls" },
        .max_output_bytes = 4096,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn commandExists(allocator: std.mem.Allocator, command: []const u8) !bool {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "sh", "-lc", "command -v \"$1\" >/dev/null 2>&1", "sh", command },
        .max_output_bytes = 1,
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn backendName(guarded_store: ?store.Backend) []const u8 {
    if (guarded_store == null) return "none";
    return switch (guarded_store.?) {
        .pass => "pass",
        .mock => "mock",
    };
}

fn describeStoreRefAlloc(
    allocator: std.mem.Allocator,
    guarded_store: ?store.Backend,
    object_id: []const u8,
) ![]u8 {
    if (guarded_store) |backend_value| {
        var backend = backend_value;
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

fn appendServicePathReport(
    writer: anytype,
    label: []const u8,
    path: []const u8,
) !void {
    if (enrollment.pathExists(path)) {
        try writer.print("ok: {s} service file exists: {s}\n", .{ label, path });
    } else {
        try writer.print("warn: {s} service file is absent: {s}\n", .{ label, path });
        try writer.writeAll("hint: run `./scripts/services/install-user-services.sh --bin \"$(command -v file-snitch)\"`\n");
    }
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

fn defaultMacosLaunchAgentPathAlloc(
    allocator: std.mem.Allocator,
    home_dir: []const u8,
    filename: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ home_dir, "Library", "LaunchAgents", filename });
}

fn defaultLinuxUserUnitPathAlloc(
    allocator: std.mem.Allocator,
    home_dir: []const u8,
    filename: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ home_dir, ".config", "systemd", "user", filename });
}
