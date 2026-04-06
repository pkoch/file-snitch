const std = @import("std");
const app_src = @import("app_src");
const config = app_src.config;
const daemon = app_src.daemon;
const filesystem = app_src.filesystem;
const policy = app_src.policy;
const prompt = app_src.prompt;

pub const std_options: std.Options = .{
    .log_level = .info,
};

const seed_name = "seed-from-store.txt";
const seed_path = "/" ++ seed_name;
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
    const seed = try session.inspectPath(seed_path);
    const note = try session.inspectPath(note_path);
    try std.testing.expectEqual(filesystem.NodeKind.directory, root.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, seed.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, note.kind);

    const entries = try session.rootEntries(allocator);
    defer allocator.free(entries);
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings(seed_name, entries[0]);
    try std.testing.expectEqualStrings(note_path[1..], entries[1]);

    const seed_content = try session.readPath(allocator, seed_path);
    defer allocator.free(seed_content);
    try std.testing.expectEqualStrings("seeded from backing store\n", seed_content);

    const note_content = try session.readPath(allocator, note_path);
    defer allocator.free(note_content);
    try std.testing.expectEqualStrings("hello from file-snitch\n", note_content);

    const audit_events = try session.auditEvents(allocator);
    defer allocator.free(audit_events);
    try expectAuditEvent(audit_events, "create", created_note_path, 0);
    try expectAuditEvent(audit_events, "write", created_note_path, 23);
    try expectAuditEvent(audit_events, "rename", created_note_path, 0);
    try expectRenameAudit(audit_events, created_note_path, note_path, 0);
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

    var default_prompt_context = prompt.ScriptedContext.init(&.{.allow});
    var default_prompt_session = try daemon.Session.init(allocator, .{
        .mount_path = fixture.mount_path,
        .backing_store_path = fixture.backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .prompt,
        .prompt_broker = prompt.scriptedBroker(&default_prompt_context),
    });
    defer default_prompt_session.deinit();

    const prompted_read = try default_prompt_session.readPath(allocator, note_path);
    defer allocator.free(prompted_read);
    try std.testing.expectEqualStrings("hello from file-snitch\n", prompted_read);

    const default_prompt_audit = try default_prompt_session.auditEvents(allocator);
    defer allocator.free(default_prompt_audit);
    try expectAuditEvent(default_prompt_audit, "prompt", "read /renamed-note.txt", 1);
    try expectAuditEvent(default_prompt_audit, "read", note_path, 23);
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

test "policy file loader treats empty file as a no-op" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "empty");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    file.close();

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(u32, 1), loaded.version);
    try std.testing.expectEqual(@as(usize, 0), loaded.enrollments.len);
    try std.testing.expectEqual(@as(usize, 0), loaded.decisions.len);

    var mount_plan = try loaded.deriveMountPlan(allocator);
    defer mount_plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), mount_plan.paths.len);
}

test "policy file loader parses enrollments and collapses mount plan" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "planned");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: /home/pkoch/.kube/config
        \\    object_id: kube-config
        \\  - path: /home/pkoch/.config/gh/hosts.yml
        \\    object_id: gh-hosts
        \\  - path: /home/pkoch/.config/gh/extensions/foo/token.json
        \\    object_id: gh-extension-token
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    uid: 1000
        \\    path: /home/pkoch/.kube/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
    ;

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(usize, 3), loaded.enrollments.len);
    try std.testing.expectEqualStrings("/home/pkoch/.kube/config", loaded.enrollments[0].path);
    try std.testing.expectEqualStrings("kube-config", loaded.enrollments[0].object_id);
    try std.testing.expectEqual(@as(usize, 1), loaded.decisions.len);
    try std.testing.expectEqualStrings("/usr/bin/kubectl", loaded.decisions[0].executable_path);
    try std.testing.expectEqualStrings("read_like", loaded.decisions[0].approval_class);
    try std.testing.expectEqualStrings("allow", loaded.decisions[0].outcome);
    try std.testing.expect(loaded.decisions[0].expires_at == null);

    var mount_plan = try loaded.deriveMountPlan(allocator);
    defer mount_plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), mount_plan.paths.len);
    try std.testing.expectEqualStrings("/home/pkoch/.kube", mount_plan.paths[0]);
    try std.testing.expectEqualStrings("/home/pkoch/.config/gh", mount_plan.paths[1]);
}

test "policy file save round-trips appended enrollments" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "roundtrip");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    try loaded.appendEnrollment("/home/pkoch/.kube/config", "kube-config");
    try loaded.appendEnrollment("/home/pkoch/.ssh/id_ed25519", "ssh-main");
    try loaded.saveToFile();

    var reloaded = try config.loadFromFile(allocator, path);
    defer reloaded.deinit();

    try std.testing.expectEqual(@as(usize, 2), reloaded.enrollments.len);
    try std.testing.expectEqualStrings("/home/pkoch/.kube/config", reloaded.enrollments[0].path);
    try std.testing.expectEqualStrings("kube-config", reloaded.enrollments[0].object_id);
    try std.testing.expectEqualStrings("/home/pkoch/.ssh/id_ed25519", reloaded.enrollments[1].path);
    try std.testing.expectEqualStrings("ssh-main", reloaded.enrollments[1].object_id);
    try std.testing.expectEqual(@as(usize, 0), reloaded.decisions.len);
}

test "policy file save removes enrollment and attached decisions" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "remove");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: /home/pkoch/.kube/config
        \\    object_id: kube-config
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    uid: 1000
        \\    path: /home/pkoch/.kube/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
    ;

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    const index = loaded.findEnrollmentIndex("/home/pkoch/.kube/config").?;
    loaded.removeDecisionsForPath("/home/pkoch/.kube/config");
    var removed = loaded.removeEnrollmentAt(index);
    defer removed.deinit(allocator);
    try loaded.saveToFile();

    var reloaded = try config.loadFromFile(allocator, path);
    defer reloaded.deinit();

    try std.testing.expectEqual(@as(usize, 0), reloaded.enrollments.len);
    try std.testing.expectEqual(@as(usize, 0), reloaded.decisions.len);
}

test "compiled durable decisions respect executable path and uid" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "compiled-rules");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: /tmp/guarded/config
        \\    object_id: kube-config
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    uid: 1000
        \\    path: /tmp/guarded/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
        \\  - executable_path: /usr/bin/kubectl
        \\    uid: 1000
        \\    path: /tmp/guarded/config
        \\    approval_class: write_capable
        \\    outcome: deny
        \\    expires_at: null
    ;

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    var compiled = try loaded.compilePolicyRules(allocator);
    defer compiled.deinit();

    var engine = try policy.Engine.init(allocator, .allow, compiled.items);
    defer engine.deinit();

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluate(.{
        .path = "/tmp/guarded/config",
        .access_class = .read,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }));

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluate(.{
        .path = "/tmp/guarded/config",
        .access_class = .write,
        .pid = 42,
        .uid = 999,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }));

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluate(.{
        .path = "/tmp/guarded/config",
        .access_class = .write,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/bash",
    }));

    try std.testing.expectEqual(policy.Outcome.deny, engine.evaluate(.{
        .path = "/tmp/guarded/config",
        .access_class = .write,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }));
}

test "enrolled parent shadows the guarded file and passes through siblings" {
    const allocator = std.testing.allocator;
    const run_id = std.time.nanoTimestamp();
    const source_parent = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.enrolled-parent-{d}", .{run_id});
    defer allocator.free(source_parent);
    const backing_file_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.guarded-object-{d}", .{run_id});
    defer allocator.free(backing_file_path);
    const source_guarded_path = try std.fmt.allocPrint(allocator, "{s}/config", .{source_parent});
    defer allocator.free(source_guarded_path);
    const sibling_path = try std.fmt.allocPrint(allocator, "{s}/sibling.txt", .{source_parent});
    defer allocator.free(sibling_path);

    try std.fs.makeDirAbsolute(source_parent);
    defer std.fs.deleteTreeAbsolute(source_parent) catch {};
    defer std.fs.deleteFileAbsolute(backing_file_path) catch {};

    var source_guarded_file = try std.fs.createFileAbsolute(source_guarded_path, .{ .truncate = true });
    defer source_guarded_file.close();
    try source_guarded_file.writeAll("host kubeconfig\n");

    var sibling_file = try std.fs.createFileAbsolute(sibling_path, .{ .truncate = true });
    defer sibling_file.close();
    try sibling_file.writeAll("plain sibling\n");

    var backing_file = try std.fs.createFileAbsolute(backing_file_path, .{ .truncate = true });
    defer backing_file.close();
    try backing_file.writeAll("guarded kubeconfig\n");

    var session = try daemon.Session.initEnrolledParent(allocator, .{
        .mount_path = source_parent,
        .guarded_file_name = "config",
        .guarded_backing_file_path = backing_file_path,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
    });
    defer session.deinit();

    const guarded_node = try session.inspectPath("/config");
    const sibling_node = try session.inspectPath("/sibling.txt");
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, guarded_node.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, sibling_node.kind);

    const guarded_contents = try session.readPath(allocator, "/config");
    defer allocator.free(guarded_contents);
    try std.testing.expectEqualStrings("guarded kubeconfig\n", guarded_contents);

    const sibling_contents = try session.readPath(allocator, "/sibling.txt");
    defer allocator.free(sibling_contents);
    try std.testing.expectEqualStrings("plain sibling\n", sibling_contents);

    try session.debugWriteFile("/config", "updated guarded kubeconfig\n");
    try session.debugWriteFile("/sibling.txt", "updated sibling\n");

    const backing_contents = try readFileAbsoluteAlloc(allocator, backing_file_path);
    defer allocator.free(backing_contents);
    try std.testing.expectEqualStrings("updated guarded kubeconfig\n", backing_contents);

    const source_guarded_contents = try readFileAbsoluteAlloc(allocator, source_guarded_path);
    defer allocator.free(source_guarded_contents);
    try std.testing.expectEqualStrings("host kubeconfig\n", source_guarded_contents);

    const sibling_host_contents = try readFileAbsoluteAlloc(allocator, sibling_path);
    defer allocator.free(sibling_host_contents);
    try std.testing.expectEqualStrings("updated sibling\n", sibling_host_contents);
}

fn tempPolicyPath(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "/tmp/file-snitch.policy-{s}-{d}.yml",
        .{ name, std.time.nanoTimestamp() },
    );
}

fn readFileAbsoluteAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    return file.readToEndAlloc(allocator, 1024 * 1024);
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

fn expectRenameAudit(
    events: []const daemon.AuditEvent,
    from: []const u8,
    to: []const u8,
    result: i32,
) !void {
    for (events) |event| {
        if (!std.mem.eql(u8, event.action, "rename")) continue;
        if (!std.mem.eql(u8, event.path, from)) continue;
        if (event.result != result) continue;
        const rename = event.rename orelse continue;
        if (!std.mem.eql(u8, rename.from, from)) continue;
        if (!std.mem.eql(u8, rename.to, to)) continue;
        return;
    }

    std.debug.print(
        "missing rename audit from={s} to={s} result={d}\n",
        .{ from, to, result },
    );
    return error.TestExpectedAuditEvent;
}
