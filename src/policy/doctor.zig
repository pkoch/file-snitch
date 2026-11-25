const std = @import("std");
const agent = @import("../agent.zig");
const app_meta = @import("../app_meta.zig");
const builtin = @import("builtin");
const config = @import("../config.zig");
const defaults = @import("../defaults.zig");
const enrollment = @import("../enrollment.zig");
const fuse = @import("../fuse/shim.zig");
const runtime = @import("../runtime.zig");
const store = @import("../store.zig");
const user_services = @import("../user_services.zig");

pub const Options = struct {
    policy_path: []const u8,
    export_debug_dossier_path: ?[]const u8 = null,
};

pub fn run(allocator: std.mem.Allocator, options: Options) !void {
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

    const agent_socket_exists = enrollment.pathExists(allocator, agent_socket_path) catch |err| blk: {
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
            if (try user_services.commandAvailable(allocator, helper_command)) {
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
            if (try user_services.commandAvailable(allocator, helper_command)) {
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

        const parent_exists = enrollment.directoryExists(allocator, parent_dir) catch |err| {
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
    const maybe_symlink_target = enrollment.symlinkTargetAlloc(allocator, target_path) catch |err| {
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
    if (maybe_symlink_target) |symlink_target| {
        defer allocator.free(symlink_target);
        if (!std.mem.eql(u8, symlink_target, projection_path)) {
            has_errors.* = true;
            try writer.print(
                "error: target path points at an unexpected symlink target: {s} -> {s} (expected {s})\n",
                .{ target_path, symlink_target, projection_path },
            );
            return;
        }

        const symlink_inspect_path_owned = !std.fs.path.isAbsolute(symlink_target);
        const symlink_inspect_path = if (symlink_inspect_path_owned)
            try std.fs.path.join(allocator, &.{ std.fs.path.dirname(target_path) orelse ".", symlink_target })
        else
            symlink_target;
        defer if (symlink_inspect_path_owned) allocator.free(symlink_inspect_path);

        const symlink_kind = enrollment.pathKind(allocator, symlink_inspect_path) catch |err| {
            has_errors.* = true;
            if (err == error.NoDevice) {
                try writer.print(
                    "error: target path symlink target is on a stale or inaccessible device: {s} -> {s}\nhint: restart `file-snitch run`; if this persists, unmount the affected parent directory and retry\n",
                    .{ target_path, symlink_target },
                );
                return;
            }
            try writer.print(
                "error: target path is a broken enrolled-target symlink: {s} -> {s}: {}\n",
                .{ target_path, symlink_target, err },
            );
            return;
        };
        if (symlink_kind == .missing) {
            has_errors.* = true;
            try writer.print(
                "error: target path is a dangling enrolled-target symlink: {s} -> {s}\n",
                .{ target_path, symlink_target },
            );
            return;
        } else if (symlink_kind == .directory) {
            has_errors.* = true;
            try writer.print(
                "error: target path is a symlink to a directory: {s} -> {s}\n",
                .{ target_path, symlink_target },
            );
            return;
        } else if (symlink_kind == .other) {
            has_errors.* = true;
            try writer.print(
                "error: target path is a symlink to an unsupported type: {s} -> {s}\n",
                .{ target_path, symlink_target },
            );
            return;
        }
    }

    const target_kind = enrollment.pathKind(allocator, target_path) catch |err| {
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

    var file = try std.Io.Dir.cwd().createFile(runtime.io(), output_path, .{
        .truncate = true,
        .permissions = .fromMode(0o600),
    });
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
    const header_executable_redacted = try redactHomePathAlloc(allocator, home_dir, executable_path);
    defer allocator.free(header_executable_redacted);
    const policy_redacted = try redactHomePathAlloc(allocator, home_dir, loaded_policy.source_path);
    defer allocator.free(policy_redacted);
    const agent_socket_redacted = try redactHomePathAlloc(allocator, home_dir, agent_socket_path);
    defer allocator.free(agent_socket_redacted);
    const pass_command_redacted = try redactHomePathAlloc(allocator, home_dir, pass_command);
    defer allocator.free(pass_command_redacted);
    const gpg_command_redacted = try redactHomePathAlloc(allocator, home_dir, gpg_command);
    defer allocator.free(gpg_command_redacted);

    try writer.writeAll("# File Snitch Debug Dossier\n\n");
    try writer.print("- generated_at_unix: {d}\n", .{generated_at});
    try writer.print("- executable: `{s}`\n", .{header_executable_redacted});
    try writer.print("- file_snitch: `{s}`\n", .{app_meta.version});
    try writer.print("- os: `{s}`\n", .{@tagName(builtin.os.tag)});
    try writer.print("- arch: `{s}`\n", .{@tagName(builtin.cpu.arch)});
    try writer.print("- zig: `{s}`\n", .{builtin.zig_version_string});
    try writer.print("- policy: `{s}`\n", .{policy_redacted});
    try writer.print("- agent_socket: `{s}`\n", .{agent_socket_redacted});
    try writer.print("- pass_command: `{s}`\n", .{pass_command_redacted});
    try writer.print("- gpg_command: `{s}`\n\n", .{gpg_command_redacted});

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
            const executable_redacted = try redactHomePathAlloc(allocator, home_dir, decision.executable_path);
            defer allocator.free(executable_redacted);
            const path_redacted = try redactHomePathAlloc(allocator, home_dir, decision.path);
            defer allocator.free(path_redacted);
            try writer.print(
                "- executable_path: `{s}` path: `{s}` approval_class: `{s}` outcome: `{s}` expires_at: `{s}`\n",
                .{
                    executable_redacted,
                    path_redacted,
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
    // Diagnostic bundles may contain embedded paths in command output; redacting
    // raw byte occurrences favors privacy even if it over-redacts path-like text.
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

fn appendMacosRunServicePassReport(
    allocator: std.mem.Allocator,
    writer: anytype,
    has_errors: *bool,
    run_service_path: []const u8,
) !void {
    const service_exists = enrollment.pathExists(allocator, run_service_path) catch |err| {
        has_errors.* = true;
        try writer.print("error: launchd run service file could not be inspected for pass access: {s}: {}\n", .{ run_service_path, err });
        return;
    };
    if (!service_exists) return;

    var probe = user_services.macosRunServicePassProbeAlloc(allocator, run_service_path) catch |err| {
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
    if (!installed_matches) {
        return;
    }
    try appendLoadedServiceReport(
        allocator,
        writer,
        has_errors,
        rendered,
        service,
        label,
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
) !void {
    const loaded = user_services.loadedConfigAlloc(allocator, rendered.platform, service) catch |err| {
        has_errors.* = true;
        try writer.print("error: {s} loaded config could not be inspected: {}\n", .{ label, err });
        return;
    } orelse {
        has_errors.* = true;
        try writer.print("error: {s} service file matches current render, but the service manager has no loaded config\n", .{label});
        try writer.writeAll("hint: rerun `file-snitch services install --bin \"$(command -v file-snitch)\" --pass-bin \"$(command -v pass)\"`\n");
        return;
    };
    defer allocator.free(loaded);

    const matches_loaded = switch (rendered.platform) {
        .macos => try user_services.macosLoadedServiceMatchesRender(allocator, rendered, service, loaded),
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
