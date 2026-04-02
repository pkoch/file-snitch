const std = @import("std");
const app_src = @import("app_src");
const daemon = app_src.daemon;
const filesystem = app_src.filesystem;
const policy = app_src.policy;
const prompt = app_src.prompt;

const seed_name = "seed-from-store.txt";
const seed_path = "/" ++ seed_name;
const status_path = "/file-snitch-status";
const audit_path = "/file-snitch-audit";
const created_note_path = "/demo-note.txt";
const note_path = "/renamed-note.txt";
const blocked_note_path = "/blocked-note.txt";
const prompted_note_path = "/prompted-note.txt";
const allowed_prompt_note_path = "/allowed-prompt-note.txt";

const Fixture = struct {
    allocator: std.mem.Allocator,
    mount_path: []u8,
    backing_store_path: []u8,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const run_id = std.time.nanoTimestamp();
        const mount_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.test-mount-{d}", .{run_id});
        errdefer allocator.free(mount_path);
        const backing_store_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.test-store-{d}", .{run_id});
        errdefer allocator.free(backing_store_path);

        try std.fs.makeDirAbsolute(mount_path);
        errdefer std.fs.deleteTreeAbsolute(mount_path) catch {};
        try std.fs.makeDirAbsolute(backing_store_path);
        errdefer std.fs.deleteTreeAbsolute(backing_store_path) catch {};

        const seed_host_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ backing_store_path, seed_name });
        defer allocator.free(seed_host_path);

        var seed_file = try std.fs.createFileAbsolute(seed_host_path, .{ .truncate = true });
        defer seed_file.close();
        try seed_file.writeAll("seeded from backing store\n");

        return .{
            .allocator = allocator,
            .mount_path = mount_path,
            .backing_store_path = backing_store_path,
        };
    }

    fn deinit(self: Fixture) void {
        std.fs.deleteTreeAbsolute(self.mount_path) catch {};
        std.fs.deleteTreeAbsolute(self.backing_store_path) catch {};
        self.allocator.free(self.mount_path);
        self.allocator.free(self.backing_store_path);
    }
};

test "session exercise is covered by integration assertions" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
    });
    defer session.deinit();

    try session.debugCreateFile(created_note_path, 0o600);
    try session.debugWriteFile(created_note_path, "hello from file-snitch\n");
    try session.debugRenameFile(created_note_path, note_path);
    try session.debugSyncFile(note_path, false);

    const description = try session.describe();
    try std.testing.expect(!description.mount_implemented);
    try std.testing.expect(description.has_session_state);
    try std.testing.expect(description.has_daemon_state);
    try std.testing.expect(description.has_init_callback);
    try std.testing.expect(description.run_in_foreground);
    try std.testing.expectEqual(policy.Outcome.allow, description.default_mutation_outcome);
    try std.testing.expectEqualStrings(fixture.mount_path, description.mount_path);
    try std.testing.expectEqualStrings(fixture.backing_store_path, description.backing_store_path);
    try std.testing.expect(description.configured_operation_count >= 1);

    const plan = try session.executionPlan(allocator);
    defer session.freeExecutionPlan(allocator, plan);
    try std.testing.expectEqual(@as(usize, 3), plan.args.len);
    try std.testing.expectEqualStrings("file-snitch", plan.args[0]);
    try std.testing.expectEqualStrings("-f", plan.args[1]);
    try std.testing.expectEqualStrings(fixture.mount_path, plan.args[2]);

    const root = try session.inspectPath("/");
    const audit = try session.inspectPath(audit_path);
    const seed = try session.inspectPath(seed_path);
    const status = try session.inspectPath(status_path);
    const note = try session.inspectPath(note_path);
    try std.testing.expectEqual(filesystem.NodeKind.directory, root.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, audit.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, seed.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, status.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, note.kind);

    const entries = try session.rootEntries(allocator);
    defer allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 4), entries.len);
    try std.testing.expectEqualStrings("file-snitch-status", entries[0]);
    try std.testing.expectEqualStrings("file-snitch-audit", entries[1]);
    try std.testing.expectEqualStrings(seed_name, entries[2]);
    try std.testing.expectEqualStrings(note_path[1..], entries[3]);

    const seed_content = try session.readPath(allocator, seed_path);
    defer allocator.free(seed_content);
    try std.testing.expectEqualStrings("seeded from backing store\n", seed_content);

    const note_content = try session.readPath(allocator, note_path);
    defer allocator.free(note_content);
    try std.testing.expectEqualStrings("hello from file-snitch\n", note_content);

    const status_content = try session.readPath(allocator, status_path);
    defer allocator.free(status_content);
    try std.testing.expect(std.mem.indexOf(u8, status_content, "files=2") != null);

    const audit_content = try session.readPath(allocator, audit_path);
    defer allocator.free(audit_content);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "\"action\":\"rename\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, audit_content, "\"path\":\"/demo-note.txt -> /renamed-note.txt\"") != null);

    const audit_events = try session.auditEvents(allocator);
    defer allocator.free(audit_events);
    try expectAuditEvent(audit_events, "create", created_note_path, 0);
    try expectAuditEvent(audit_events, "write", created_note_path, 23);
    try expectAuditEvent(audit_events, "rename", "/demo-note.txt -> /renamed-note.txt", 0);
    try expectAuditEvent(audit_events, "fsync", note_path, 0);

    var reloaded_session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .deny,
    });
    defer reloaded_session.deinit();

    const reloaded_note = try reloaded_session.readPath(allocator, note_path);
    defer allocator.free(reloaded_note);
    try std.testing.expectEqualStrings("hello from file-snitch\n", reloaded_note);
    try std.testing.expectEqual(@as(usize, 0), session.state.run_attempts);
}

test "policy and prompt paths are covered by integration assertions" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var base_session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
    });
    defer base_session.deinit();
    try base_session.debugCreateFile(created_note_path, 0o600);
    try base_session.debugWriteFile(created_note_path, "hello from file-snitch\n");
    try base_session.debugRenameFile(created_note_path, note_path);

    var readonly_session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .deny,
    });
    defer readonly_session.deinit();

    try std.testing.expectError(
        error.DebugCreateFailed,
        readonly_session.debugCreateFile(blocked_note_path, 0o600),
    );

    var policy_session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
        .policy_rules = &.{
            .{
                .path_prefix = note_path,
                .access_class = .read,
                .outcome = .prompt,
            },
            .{
                .path_prefix = prompted_note_path,
                .access_class = .create,
                .outcome = .deny,
            },
        },
    });
    defer policy_session.deinit();

    try std.testing.expectError(
        error.DebugReadFailed,
        policy_session.readPath(allocator, note_path),
    );
    try std.testing.expectError(
        error.DebugCreateFailed,
        policy_session.debugCreateFile(prompted_note_path, 0o600),
    );

    var allow_prompt_context = prompt.ScriptedContext.init(&.{.allow});
    var allowed_prompt_session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
        .policy_rules = &.{
            .{
                .path_prefix = allowed_prompt_note_path,
                .access_class = .create,
                .outcome = .prompt,
            },
        },
        .prompt_broker = prompt.scriptedBroker(&allow_prompt_context),
    });
    defer allowed_prompt_session.deinit();

    try allowed_prompt_session.debugCreateFile(allowed_prompt_note_path, 0o600);

    const readonly_audit = try readonly_session.auditEvents(allocator);
    defer allocator.free(readonly_audit);
    try expectAuditEvent(readonly_audit, "policy", "create /blocked-note.txt", 2);
    try expectAuditEvent(readonly_audit, "create", blocked_note_path, -13);

    const policy_audit = try policy_session.auditEvents(allocator);
    defer allocator.free(policy_audit);
    try expectAuditEvent(policy_audit, "prompt", "read /renamed-note.txt", 4);
    try expectAuditEvent(policy_audit, "read", note_path, -13);
    try expectAuditEvent(policy_audit, "policy", "create /prompted-note.txt", 2);
    try expectAuditEvent(policy_audit, "create", prompted_note_path, -13);

    const allowed_prompt_audit = try allowed_prompt_session.auditEvents(allocator);
    defer allocator.free(allowed_prompt_audit);
    try expectAuditEvent(allowed_prompt_audit, "prompt", "create /allowed-prompt-note.txt", 1);
    try expectAuditEvent(allowed_prompt_audit, "create", allowed_prompt_note_path, 0);

    const allowed_note = try allowed_prompt_session.readPath(allocator, allowed_prompt_note_path);
    defer allocator.free(allowed_note);
    try std.testing.expectEqualStrings("", allowed_note);
}

test "directory operations fail explicitly in the file-only spike" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
    });
    defer session.deinit();

    try std.testing.expectError(
        error.DebugMkdirFailed,
        session.debugCreateDirectory("/empty-dir", 0o755),
    );
    try std.testing.expectError(
        error.DebugRmdirFailed,
        session.debugRemoveDirectory("/empty-dir"),
    );
    try std.testing.expectEqual(
        filesystem.NodeKind.missing,
        (try session.inspectPath("/empty-dir")).kind,
    );

    const host_path = try std.fmt.allocPrint(allocator, "{s}/empty-dir", .{fixture.backing_store_path});
    defer allocator.free(host_path);
    try std.testing.expectError(error.FileNotFound, std.fs.openDirAbsolute(host_path, .{}));

    const not_supported = -@as(i32, @intFromEnum(std.posix.E.OPNOTSUPP));
    const audit_events = try session.auditEvents(allocator);
    defer allocator.free(audit_events);
    try expectAuditEvent(audit_events, "mkdir", "/empty-dir", not_supported);
    try expectAuditEvent(audit_events, "rmdir", "/empty-dir", not_supported);
}

test "transient rename rollback keeps source entry when persist fails" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
    });
    defer session.deinit();

    try session.debugCreateFile("/._rename-source.txt", 0o600);
    try session.debugWriteFile("/._rename-source.txt", "transient contents");

    try std.fs.deleteTreeAbsolute(fixture.backing_store_path);

    try std.testing.expectError(
        error.DebugRenameFailed,
        session.debugRenameFile("/._rename-source.txt", "/rename-target.txt"),
    );

    const source = try session.readPath(allocator, "/._rename-source.txt");
    defer allocator.free(source);
    try std.testing.expectEqualStrings("transient contents", source);

    try std.testing.expectEqual(
        filesystem.NodeKind.missing,
        (try session.inspectPath("/rename-target.txt")).kind,
    );
}

fn expectAuditEvent(
    events: []const daemon.AuditEvent,
    action: []const u8,
    path: []const u8,
    result: i32,
) !void {
    for (events) |event| {
        if (!std.mem.eql(u8, event.action, action)) {
            continue;
        }
        if (!std.mem.eql(u8, event.path, path)) {
            continue;
        }
        if (event.result != result) {
            continue;
        }
        return;
    }

    std.debug.print(
        "missing audit event action={s} path={s} result={d}\n",
        .{ action, path, result },
    );
    return error.TestExpectedAuditEvent;
}
