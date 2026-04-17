const std = @import("std");
const app_src = @import("app_src");
const builtin = @import("builtin");
const config = app_src.config;
const daemon = app_src.daemon;
const filesystem = app_src.filesystem;
const policy = app_src.policy;
const prompt = app_src.prompt;
const store = app_src.store;

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

const CountingPromptContext = struct {
    count: usize = 0,
    response: prompt.Response,
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    mount_path: []u8,
    mock_state: store.MockState = .{},
    backend: store.Backend = undefined,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const run_id = std.time.nanoTimestamp();
        const mount_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.test-mount-{d}", .{run_id});
        errdefer allocator.free(mount_path);

        try std.fs.makeDirAbsolute(mount_path);
        errdefer std.fs.deleteTreeAbsolute(mount_path) catch {};

        const seed_host_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ mount_path, seed_name });
        defer allocator.free(seed_host_path);

        var seed_file = try std.fs.createFileAbsolute(seed_host_path, .{ .truncate = true });
        defer seed_file.close();
        try seed_file.writeAll("seeded from source dir\n");

        return .{
            .allocator = allocator,
            .mount_path = mount_path,
        };
    }

    fn deinit(self: *Fixture) void {
        self.mock_state.deinit(self.allocator);
        std.fs.deleteTreeAbsolute(self.mount_path) catch {};
        self.allocator.free(self.mount_path);
    }

    fn guardedStore(self: *Fixture) *store.Backend {
        self.backend = store.Backend.initMock(&self.mock_state);
        return &self.backend;
    }
};

fn initSession(
    allocator: std.mem.Allocator,
    fixture: *Fixture,
    guarded_entries: []const filesystem.GuardedEntryConfig,
    default_mutation_outcome: policy.Outcome,
    policy_rule_views: []const policy.RuleView,
    prompt_broker: ?prompt.Broker,
) !daemon.Session {
    return daemon.Session.initEnrolledParent(allocator, .{
        .mount_path = fixture.mount_path,
        .guarded_entries = guarded_entries,
        .guarded_store = fixture.guardedStore(),
        .run_in_foreground = true,
        .default_mutation_outcome = default_mutation_outcome,
        .policy_path = null,
        .policy_rule_views = policy_rule_views,
        .prompt_broker = prompt_broker,
    });
}

fn countingPromptBroker(context: *CountingPromptContext) prompt.Broker {
    return .{
        .context = context,
        .resolve_fn = resolveCountingPrompt,
    };
}

fn resolveCountingPrompt(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    _ = request;
    const context = raw_context orelse return .{ .decision = .unavailable };
    const counting_context: *CountingPromptContext = @ptrCast(@alignCast(context));
    counting_context.count += 1;
    return counting_context.response;
}

fn expectEntriesContain(entries: []const []const u8, expected: []const []const u8) !void {
    try std.testing.expectEqual(expected.len, entries.len);
    for (expected) |expected_entry| {
        var found = false;
        for (entries) |entry| {
            if (std.mem.eql(u8, entry, expected_entry)) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "session exercise is covered by core assertions" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try initSession(allocator, &fixture, &.{}, .allow, &.{}, null);
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
    try std.testing.expect(description.configured_operation_count >= 1);

    var plan = try session.executionPlan(allocator);
    defer plan.deinit();
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
    defer {
        for (entries) |entry| allocator.free(entry);
        allocator.free(entries);
    }
    try expectEntriesContain(entries, &.{ seed_name, note_path[1..] });

    const seed_content = try session.readPath(allocator, seed_path);
    defer allocator.free(seed_content);
    try std.testing.expectEqualStrings("seeded from source dir\n", seed_content);

    const note_content = try session.readPath(allocator, note_path);
    defer allocator.free(note_content);
    try std.testing.expectEqualStrings("hello from file-snitch\n", note_content);

    var audit_snapshot = try session.auditEventSnapshot(allocator);
    defer audit_snapshot.deinit();
    try expectAuditEvent(audit_snapshot.items, "create", created_note_path, 0);
    try expectAuditEvent(audit_snapshot.items, "write", created_note_path, 23);
    try expectAuditEvent(audit_snapshot.items, "rename", created_note_path, 0);
    try expectRenameAudit(audit_snapshot.items, created_note_path, note_path, 0);
    try expectAuditEvent(audit_snapshot.items, "fsync", note_path, 0);

    var reloaded_session = try initSession(allocator, &fixture, &.{}, .deny, &.{}, null);
    defer reloaded_session.deinit();

    const reloaded_note = try reloaded_session.readPath(allocator, note_path);
    defer allocator.free(reloaded_note);
    try std.testing.expectEqualStrings("hello from file-snitch\n", reloaded_note);
    try std.testing.expectEqual(@as(usize, 0), session.state.run_attempts);
}

test "session helper snapshots survive session teardown" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try initSession(allocator, &fixture, &.{}, .allow, &.{}, null);
    try session.debugCreateFile(created_note_path, 0o600);

    var plan = try session.executionPlan(allocator);
    errdefer plan.deinit();

    var audit_snapshot = try session.auditEventSnapshot(allocator);
    errdefer audit_snapshot.deinit();

    session.deinit();

    try std.testing.expectEqual(@as(usize, 3), plan.args.len);
    try std.testing.expectEqualStrings("file-snitch", plan.args[0]);
    try std.testing.expectEqualStrings(fixture.mount_path, plan.args[2]);
    try expectAuditEvent(audit_snapshot.items, "create", created_note_path, 0);

    plan.deinit();
    audit_snapshot.deinit();
}

test "policy and prompt paths are covered by core assertions" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    const guarded_note_path = "/guarded-note.txt";
    const lock_anchor_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.guard-policy-lock-{d}", .{std.time.nanoTimestamp()});
    defer allocator.free(lock_anchor_path);
    defer std.fs.deleteFileAbsolute(lock_anchor_path) catch {};

    var preseed_store = fixture.guardedStore();
    try preseed_store.putObject(allocator, "guarded-note", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded note\n",
    });

    const guarded_entries = &.{filesystem.GuardedEntryConfig{
        .relative_path = "guarded-note.txt",
        .object_id = "guarded-note",
        .lock_anchor_path = lock_anchor_path,
    }};

    var readonly_session = try initSession(allocator, &fixture, guarded_entries, .deny, &.{}, null);
    defer readonly_session.deinit();

    try std.testing.expectError(
        error.DebugWriteFailed,
        readonly_session.debugWriteFile(guarded_note_path, "blocked\n"),
    );

    var policy_session = try initSession(allocator, &fixture, guarded_entries, .allow, &.{
        .{
            .path_prefix = guarded_note_path,
            .access_class = .read,
            .outcome = .prompt,
        },
        .{
            .path_prefix = guarded_note_path,
            .access_class = .write,
            .outcome = .deny,
        },
    }, null);
    defer policy_session.deinit();

    try std.testing.expectError(
        error.DebugReadFailed,
        policy_session.readPath(allocator, guarded_note_path),
    );
    try std.testing.expectError(
        error.DebugWriteFailed,
        policy_session.debugWriteFile(guarded_note_path, "denied\n"),
    );

    var allow_prompt_context = prompt.ScriptedContext.init(&.{.allow});
    var allowed_prompt_session = try initSession(allocator, &fixture, guarded_entries, .allow, &.{
        .{
            .path_prefix = guarded_note_path,
            .access_class = .write,
            .outcome = .prompt,
        },
    }, prompt.scriptedBroker(&allow_prompt_context));
    defer allowed_prompt_session.deinit();

    try allowed_prompt_session.debugWriteFile(guarded_note_path, "updated guarded note\n");

    var readonly_audit = try readonly_session.auditEventSnapshot(allocator);
    defer readonly_audit.deinit();
    try expectAuditEvent(readonly_audit.items, "policy", "write /guarded-note.txt", 2);
    try expectAuditEvent(readonly_audit.items, "write", guarded_note_path, -13);

    var policy_audit = try policy_session.auditEventSnapshot(allocator);
    defer policy_audit.deinit();
    try expectAuditEvent(policy_audit.items, "prompt", "read /guarded-note.txt", 4);
    try expectAuditEvent(policy_audit.items, "read", guarded_note_path, -13);
    try expectAuditEvent(policy_audit.items, "policy", "write /guarded-note.txt", 2);
    try expectAuditEvent(policy_audit.items, "write", guarded_note_path, -13);

    var allowed_prompt_audit = try allowed_prompt_session.auditEventSnapshot(allocator);
    defer allowed_prompt_audit.deinit();
    try expectAuditEvent(allowed_prompt_audit.items, "prompt", "write /guarded-note.txt", 1);
    try expectAuditEvent(allowed_prompt_audit.items, "write", guarded_note_path, 21);

    {
        var stored = try fixture.mock_state.loadObject(allocator, "guarded-note");
        defer stored.deinit(allocator);
        try std.testing.expectEqualStrings("updated guarded note\n", stored.content);
    }

    var default_prompt_context = prompt.ScriptedContext.init(&.{.allow});
    var default_prompt_session = try initSession(
        allocator,
        &fixture,
        guarded_entries,
        .prompt,
        &.{},
        prompt.scriptedBroker(&default_prompt_context),
    );
    defer default_prompt_session.deinit();

    const prompted_read = try default_prompt_session.readPath(allocator, guarded_note_path);
    defer allocator.free(prompted_read);
    try std.testing.expectEqualStrings("updated guarded note\n", prompted_read);

    var default_prompt_audit = try default_prompt_session.auditEventSnapshot(allocator);
    defer default_prompt_audit.deinit();
    try expectAuditEvent(default_prompt_audit.items, "prompt", "read /guarded-note.txt", 1);
    try expectAuditEvent(default_prompt_audit.items, "read", guarded_note_path, 21);
}

test "directory operations fail explicitly in the file-only spike" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try initSession(allocator, &fixture, &.{}, .allow, &.{}, null);
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

    const host_path = try std.fmt.allocPrint(allocator, "{s}/empty-dir", .{fixture.mount_path});
    defer allocator.free(host_path);
    try std.testing.expectError(error.FileNotFound, std.fs.openDirAbsolute(host_path, .{}));

    const not_supported = -@as(i32, @intFromEnum(std.posix.E.OPNOTSUPP));
    var audit_snapshot = try session.auditEventSnapshot(allocator);
    defer audit_snapshot.deinit();
    try expectAuditEvent(audit_snapshot.items, "mkdir", "/empty-dir", not_supported);
    try expectAuditEvent(audit_snapshot.items, "rmdir", "/empty-dir", not_supported);
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

    var compiled = try loaded.compilePolicyRuleViews(allocator);
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

test "compiled durable decisions ignore expired entries" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "compiled-rules-expiration");
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
        \\    outcome: deny
        \\    expires_at: '1970-01-01T00:00:01Z'
        \\  - executable_path: /usr/bin/kubectl
        \\    uid: 1000
        \\    path: /tmp/guarded/config
        \\    approval_class: write_capable
        \\    outcome: deny
        \\    expires_at: '2100-01-01T00:00:00Z'
    ;

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    var compiled = try loaded.compilePolicyRuleViews(allocator);
    defer compiled.deinit();

    var engine = try policy.Engine.init(allocator, .allow, compiled.items);
    defer engine.deinit();

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluateAt(.{
        .path = "/tmp/guarded/config",
        .access_class = .read,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }, 1_900_000_000));

    try std.testing.expectEqual(policy.Outcome.deny, engine.evaluateAt(.{
        .path = "/tmp/guarded/config",
        .access_class = .write,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }, 1_900_000_000));
}

test "policy loader rejects invalid decision expiration" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "invalid-decision-expiration");
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
        \\    expires_at: later-ish
    ;

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    try std.testing.expectError(error.InvalidDecisionExpiration, config.loadFromFile(allocator, path));
}

test "policy file prunes expired decisions in place" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "prune-expired-decisions");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    const source =
        \\version: 1
        \\enrollments: []
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    uid: 1000
        \\    path: /tmp/guarded/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: '1970-01-01T00:00:01Z'
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

    try std.testing.expect(try loaded.pruneExpiredDecisions(10));
    try std.testing.expectEqual(@as(usize, 1), loaded.decisions.len);
    try std.testing.expectEqualStrings("write_capable", loaded.decisions[0].approval_class);
    try std.testing.expect(!try loaded.pruneExpiredDecisions(10));
}

test "upsertDecision replaces matching durable decision" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "upsert-decision");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        allocator.free(path);
    }

    const source =
        \\version: 1
        \\enrollments: []
        \\decisions: []
    ;

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    try loaded.upsertDecision(
        "/usr/bin/kubectl",
        1000,
        "/tmp/guarded/config",
        "read_like",
        "allow",
        null,
    );
    try loaded.upsertDecision(
        "/usr/bin/kubectl",
        1000,
        "/tmp/guarded/config",
        "read_like",
        "deny",
        "2100-01-01T00:00:00Z",
    );

    try std.testing.expectEqual(@as(usize, 1), loaded.decisions.len);
    try std.testing.expectEqualStrings("deny", loaded.decisions[0].outcome);
    try std.testing.expectEqualStrings("2100-01-01T00:00:00Z", loaded.decisions[0].expires_at.?);
}

test "policy lock prevents a second concurrent writer" {
    const allocator = std.testing.allocator;
    const path = try tempPolicyPath(allocator, "policy-lock");
    defer {
        std.fs.deleteFileAbsolute(path) catch {};
        const lock_path = std.fmt.allocPrint(allocator, "{s}.lock", .{path}) catch null;
        if (lock_path) |owned| {
            std.fs.deleteFileAbsolute(owned) catch {};
            allocator.free(owned);
        }
        allocator.free(path);
    }

    var first_lock = try config.acquirePolicyLock(allocator, path);
    defer first_lock.deinit();

    const second_file = try std.fs.openFileAbsolute(first_lock.lock_path, .{ .mode = .read_write });
    defer second_file.close();

    try std.testing.expect(!(try second_file.tryLock(.exclusive)));
}

test "current policy marker treats missing file as absent" {
    const allocator = std.testing.allocator;
    const policy_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-cli-marker-missing-{d}.yml", .{std.time.nanoTimestamp()});
    defer allocator.free(policy_path);

    const marker = try config.currentPolicyMarker(allocator, policy_path);
    try std.testing.expect(!marker.exists);
}

test "current policy marker preserves access errors" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    const policy_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-cli-marker-denied-{d}.yml", .{std.time.nanoTimestamp()});
    defer allocator.free(policy_path);
    defer std.fs.cwd().deleteFile(policy_path) catch {};

    var file = try std.fs.createFileAbsolute(policy_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll("version: 1\nenrollments: []\ndecisions: []\n");

    try file.chmod(0);
    defer file.chmod(0o600) catch {};

    try std.testing.expectError(error.AccessDenied, config.currentPolicyMarker(allocator, policy_path));
}

test "current policy marker hashes policy contents beyond one megabyte" {
    const allocator = std.testing.allocator;
    const policy_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch-cli-marker-large-{d}.yml", .{std.time.nanoTimestamp()});
    defer allocator.free(policy_path);
    defer std.fs.cwd().deleteFile(policy_path) catch {};

    {
        var file = try std.fs.createFileAbsolute(policy_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("version: 1\nenrollments: []\ndecisions:\n  - executable_path: \"/usr/bin/demo\"\n");
        const filler = try allocator.alloc(u8, 1_100_000);
        defer allocator.free(filler);
        @memset(filler, 'a');
        try file.writeAll(filler);
    }
    const first_marker = try config.currentPolicyMarker(allocator, policy_path);

    {
        var file = try std.fs.createFileAbsolute(policy_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("version: 1\nenrollments: []\ndecisions:\n  - executable_path: \"/usr/bin/demo\"\n");
        const filler = try allocator.alloc(u8, 1_100_000);
        defer allocator.free(filler);
        @memset(filler, 'a');
        filler[filler.len - 1] = 'b';
        try file.writeAll(filler);
    }
    const second_marker = try config.currentPolicyMarker(allocator, policy_path);

    try std.testing.expect(first_marker.exists);
    try std.testing.expect(second_marker.exists);
    try std.testing.expectEqual(first_marker.size, second_marker.size);
    try std.testing.expect(first_marker.content_hash != second_marker.content_hash);
}

test "live policy reload suppresses repeated prompt without remount" {
    const allocator = std.testing.allocator;
    const run_id = std.time.nanoTimestamp();
    const source_parent = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.live-policy-reload-{d}", .{run_id});
    defer allocator.free(source_parent);
    const source_guarded_path = try std.fmt.allocPrint(allocator, "{s}/config", .{source_parent});
    defer allocator.free(source_guarded_path);
    const policy_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.live-policy-{d}.yml", .{run_id});
    defer allocator.free(policy_path);
    const lock_anchor_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.live-policy-lock-{d}", .{run_id});
    defer allocator.free(lock_anchor_path);

    try std.fs.makeDirAbsolute(source_parent);
    defer std.fs.deleteTreeAbsolute(source_parent) catch {};
    defer std.fs.cwd().deleteFile(policy_path) catch {};

    {
        var file = try std.fs.createFileAbsolute(source_guarded_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host kubeconfig\n");
    }

    var policy_file = try config.loadFromFile(allocator, policy_path);
    defer policy_file.deinit();
    try policy_file.saveToFile();

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "kube-config", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded kubeconfig\n",
    });

    var prompt_context = CountingPromptContext{
        .response = .{
            .decision = .allow,
            .remember_kind = .once,
        },
    };

    var session = try daemon.Session.initEnrolledParent(allocator, .{
        .mount_path = source_parent,
        .guarded_entries = &.{.{
            .relative_path = "config",
            .object_id = "kube-config",
            .lock_anchor_path = lock_anchor_path,
        }},
        .guarded_store = &guarded_store,
        .run_in_foreground = true,
        .default_mutation_outcome = .prompt,
        .policy_path = policy_path,
        .policy_rule_views = &.{},
        .prompt_broker = countingPromptBroker(&prompt_context),
    });
    defer session.deinit();

    var buffer: [64]u8 = undefined;
    const access_context: filesystem.AccessContext = .{
        .pid = 1234,
        .uid = 1000,
        .gid = 1000,
        .executable_path = "/usr/bin/demo",
    };

    const first_len = session.state.filesystem.readInto("/config", 0, &buffer, access_context, null);
    try std.testing.expect(first_len > 0);
    try std.testing.expectEqualStrings("guarded kubeconfig\n", buffer[0..@intCast(first_len)]);
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);

    {
        var writable_policy = try config.loadFromFile(allocator, policy_path);
        defer writable_policy.deinit();
        try writable_policy.upsertDecision(
            "/usr/bin/demo",
            1000,
            "/config",
            "read_like",
            "allow",
            null,
        );
        try writable_policy.saveToFile();
    }

    const second_len = session.state.filesystem.readInto("/config", 0, &buffer, access_context, null);
    try std.testing.expect(second_len > 0);
    try std.testing.expectEqualStrings("guarded kubeconfig\n", buffer[0..@intCast(second_len)]);
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);
}

test "generated policy engine behavior survives source teardown" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5eed_cafe);
    const random = prng.random();

    for (0..24) |case_index| {
        const path = try tempPolicyPath(allocator, "generated-engine-teardown");
        defer {
            std.fs.deleteFileAbsolute(path) catch {};
            allocator.free(path);
        }

        try writeGeneratedPolicyFile(allocator, path, random, 1 + (case_index % 6));

        var loaded = try config.loadFromFile(allocator, path);
        errdefer loaded.deinit();
        var compiled = try loaded.compilePolicyRuleViews(allocator);
        errdefer compiled.deinit();
        var engine = try policy.Engine.init(allocator, .allow, compiled.items);
        defer engine.deinit();

        var requests: [20]policy.Request = undefined;
        var before: [20]policy.Outcome = undefined;
        for (&requests, &before) |*request, *outcome| {
            request.* = randomPolicyRequest(random);
            outcome.* = engine.evaluateAt(request.*, 1_900_000_000);
        }

        compiled.deinit();
        loaded.deinit();

        for (requests, before) |request, expected| {
            try std.testing.expectEqual(expected, engine.evaluateAt(request, 1_900_000_000));
        }
    }
}

test "generated policy save load preserves engine behavior" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x51a0_1eed);
    const random = prng.random();

    for (0..24) |case_index| {
        const path = try tempPolicyPath(allocator, "generated-policy-roundtrip");
        defer {
            std.fs.deleteFileAbsolute(path) catch {};
            allocator.free(path);
        }

        var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
        file.close();

        var loaded = try config.loadFromFile(allocator, path);
        defer loaded.deinit();

        const enrollment_count = 1 + (case_index % generated_enrollments.len);
        for (generated_enrollments[0..enrollment_count]) |entry| {
            try loaded.appendEnrollment(entry.path, entry.object_id);
        }

        const decision_count = 2 + (case_index % 6);
        for (0..decision_count) |_| {
            const executable_path = generated_executable_paths[random.uintLessThan(usize, generated_executable_paths.len)];
            const uid = generated_uids[random.uintLessThan(usize, generated_uids.len)];
            const enrollment = generated_enrollments[random.uintLessThan(usize, generated_enrollments.len)];
            const approval_class = generated_approval_classes[random.uintLessThan(usize, generated_approval_classes.len)];
            const outcome = generated_outcomes[random.uintLessThan(usize, generated_outcomes.len)];
            const expires_at = generated_expirations[random.uintLessThan(usize, generated_expirations.len)];
            try loaded.upsertDecision(executable_path, uid, enrollment.path, approval_class, outcome, expires_at);
        }

        var compiled_before = try loaded.compilePolicyRuleViews(allocator);
        defer compiled_before.deinit();
        var engine_before = try policy.Engine.init(allocator, .allow, compiled_before.items);
        defer engine_before.deinit();

        try loaded.saveToFile();

        var reloaded = try config.loadFromFile(allocator, path);
        defer reloaded.deinit();
        var compiled_after = try reloaded.compilePolicyRuleViews(allocator);
        defer compiled_after.deinit();
        var engine_after = try policy.Engine.init(allocator, .allow, compiled_after.items);
        defer engine_after.deinit();

        for (0..20) |_| {
            const request = randomPolicyRequest(random);
            const before = engine_before.evaluateAt(request, 1_900_000_000);
            const after = engine_after.evaluateAt(request, 1_900_000_000);
            try std.testing.expectEqual(before, after);
        }
    }
}

test "audit event snapshots remain immutable after later writes" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try initSession(allocator, &fixture, &.{}, .allow, &.{}, null);
    defer session.deinit();

    for (0..8) |index| {
        const current_path_raw = try std.fmt.allocPrint(allocator, "/property-note-{d}.txt", .{index});
        defer allocator.free(current_path_raw);
        const current_path = try allocator.dupeZ(u8, current_path_raw);
        defer allocator.free(current_path);

        const first_contents = try repeatedByteStringZAlloc(allocator, 'a', 5 + index);
        defer allocator.free(first_contents);
        const second_contents = try repeatedByteStringZAlloc(allocator, 'b', 17 + index);
        defer allocator.free(second_contents);

        try session.debugCreateFile(current_path, 0o600);
        try session.debugWriteFile(current_path, first_contents);

        var first_snapshot = try session.auditEventSnapshot(allocator);
        defer first_snapshot.deinit();

        try expectAuditEvent(first_snapshot.items, "write", current_path, @intCast(first_contents.len));
        try expectNoAuditEvent(first_snapshot.items, "write", current_path, @intCast(second_contents.len));

        try session.debugWriteFile(current_path, second_contents);

        var second_snapshot = try session.auditEventSnapshot(allocator);
        defer second_snapshot.deinit();

        try expectAuditEvent(first_snapshot.items, "write", current_path, @intCast(first_contents.len));
        try expectNoAuditEvent(first_snapshot.items, "write", current_path, @intCast(second_contents.len));
        try expectAuditEvent(second_snapshot.items, "write", current_path, @intCast(second_contents.len));
    }
}

test "enrolled parent shadows the guarded file and passes through siblings" {
    const allocator = std.testing.allocator;
    const run_id = std.time.nanoTimestamp();
    const source_parent = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.enrolled-parent-{d}", .{run_id});
    defer allocator.free(source_parent);
    const lock_anchor_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.lock-anchor-{d}", .{run_id});
    defer allocator.free(lock_anchor_path);
    const source_guarded_path = try std.fmt.allocPrint(allocator, "{s}/config", .{source_parent});
    defer allocator.free(source_guarded_path);
    const sibling_path = try std.fmt.allocPrint(allocator, "{s}/sibling.txt", .{source_parent});
    defer allocator.free(sibling_path);

    try std.fs.makeDirAbsolute(source_parent);
    defer std.fs.deleteTreeAbsolute(source_parent) catch {};

    var source_guarded_file = try std.fs.createFileAbsolute(source_guarded_path, .{ .truncate = true });
    defer source_guarded_file.close();
    try source_guarded_file.writeAll("host kubeconfig\n");

    var sibling_file = try std.fs.createFileAbsolute(sibling_path, .{ .truncate = true });
    defer sibling_file.close();
    try sibling_file.writeAll("plain sibling\n");

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "kube-config", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded kubeconfig\n",
    });

    var session = try daemon.Session.initEnrolledParent(allocator, .{
        .mount_path = source_parent,
        .guarded_entries = &.{.{
            .relative_path = "config",
            .object_id = "kube-config",
            .lock_anchor_path = lock_anchor_path,
        }},
        .guarded_store = &guarded_store,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
        .policy_path = null,
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

    {
        var object = try mock_state.loadObject(allocator, "kube-config");
        defer object.deinit(allocator);
        try std.testing.expectEqualStrings("updated guarded kubeconfig\n", object.content);
    }

    const source_guarded_contents = try readFileAbsoluteAlloc(allocator, source_guarded_path);
    defer allocator.free(source_guarded_contents);
    try std.testing.expectEqualStrings("host kubeconfig\n", source_guarded_contents);

    const sibling_host_contents = try readFileAbsoluteAlloc(allocator, sibling_path);
    defer allocator.free(sibling_host_contents);
    try std.testing.expectEqualStrings("updated sibling\n", sibling_host_contents);
}

test "enrolled parent can shadow multiple guarded siblings under one mount" {
    const allocator = std.testing.allocator;
    const run_id = std.time.nanoTimestamp();
    const source_parent = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.enrolled-parent-multi-{d}", .{run_id});
    defer allocator.free(source_parent);
    const first_lock_anchor_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.lock-anchor-a-{d}", .{run_id});
    defer allocator.free(first_lock_anchor_path);
    const second_lock_anchor_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.lock-anchor-b-{d}", .{run_id});
    defer allocator.free(second_lock_anchor_path);
    const first_source_path = try std.fmt.allocPrint(allocator, "{s}/a.key", .{source_parent});
    defer allocator.free(first_source_path);
    const second_source_path = try std.fmt.allocPrint(allocator, "{s}/b.key", .{source_parent});
    defer allocator.free(second_source_path);
    const sibling_path = try std.fmt.allocPrint(allocator, "{s}/pubring.kbx", .{source_parent});
    defer allocator.free(sibling_path);

    try std.fs.makeDirAbsolute(source_parent);
    defer std.fs.deleteTreeAbsolute(source_parent) catch {};

    {
        var file = try std.fs.createFileAbsolute(first_source_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host first\n");
    }
    {
        var file = try std.fs.createFileAbsolute(second_source_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host second\n");
    }
    {
        var file = try std.fs.createFileAbsolute(sibling_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host sibling\n");
    }

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "first-key", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded first\n",
    });
    try guarded_store.putObject(allocator, "second-key", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded second\n",
    });

    var session = try daemon.Session.initEnrolledParent(allocator, .{
        .mount_path = source_parent,
        .guarded_entries = &.{
            .{
                .relative_path = "a.key",
                .object_id = "first-key",
                .lock_anchor_path = first_lock_anchor_path,
            },
            .{
                .relative_path = "b.key",
                .object_id = "second-key",
                .lock_anchor_path = second_lock_anchor_path,
            },
        },
        .guarded_store = &guarded_store,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
        .policy_path = null,
    });
    defer session.deinit();

    const first_contents = try session.readPath(allocator, "/a.key");
    defer allocator.free(first_contents);
    try std.testing.expectEqualStrings("guarded first\n", first_contents);

    const second_contents = try session.readPath(allocator, "/b.key");
    defer allocator.free(second_contents);
    try std.testing.expectEqualStrings("guarded second\n", second_contents);

    const sibling_contents = try session.readPath(allocator, "/pubring.kbx");
    defer allocator.free(sibling_contents);
    try std.testing.expectEqualStrings("host sibling\n", sibling_contents);

    try session.debugWriteFile("/a.key", "updated guarded first\n");
    try session.debugWriteFile("/b.key", "updated guarded second\n");
    try session.debugWriteFile("/pubring.kbx", "updated sibling\n");

    {
        var object = try mock_state.loadObject(allocator, "first-key");
        defer object.deinit(allocator);
        try std.testing.expectEqualStrings("updated guarded first\n", object.content);
    }
    {
        var object = try mock_state.loadObject(allocator, "second-key");
        defer object.deinit(allocator);
        try std.testing.expectEqualStrings("updated guarded second\n", object.content);
    }
    {
        const contents = try readFileAbsoluteAlloc(allocator, first_source_path);
        defer allocator.free(contents);
        try std.testing.expectEqualStrings("host first\n", contents);
    }
    {
        const contents = try readFileAbsoluteAlloc(allocator, second_source_path);
        defer allocator.free(contents);
        try std.testing.expectEqualStrings("host second\n", contents);
    }
    {
        const contents = try readFileAbsoluteAlloc(allocator, sibling_path);
        defer allocator.free(contents);
        try std.testing.expectEqualStrings("updated sibling\n", contents);
    }
}

test "enrolled parent can project a guarded file below a synthetic subdirectory" {
    const allocator = std.testing.allocator;
    const run_id = std.time.nanoTimestamp();
    const source_parent = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.enrolled-parent-nested-{d}", .{run_id});
    defer allocator.free(source_parent);
    const lock_anchor_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.lock-anchor-nested-{d}", .{run_id});
    defer allocator.free(lock_anchor_path);
    const real_dir_path = try std.fmt.allocPrint(allocator, "{s}/extensions/foo", .{source_parent});
    defer allocator.free(real_dir_path);
    const real_sibling_path = try std.fmt.allocPrint(allocator, "{s}/hosts.yml", .{source_parent});
    defer allocator.free(real_sibling_path);

    try std.fs.makeDirAbsolute(source_parent);
    try std.fs.cwd().makePath(real_dir_path);
    defer std.fs.deleteTreeAbsolute(source_parent) catch {};

    {
        var file = try std.fs.createFileAbsolute(real_sibling_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("plain hosts\n");
    }

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "nested-token", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded nested token\n",
    });

    var session = try daemon.Session.initEnrolledParent(allocator, .{
        .mount_path = source_parent,
        .guarded_entries = &.{.{
            .relative_path = "extensions/foo/token.json",
            .object_id = "nested-token",
            .lock_anchor_path = lock_anchor_path,
        }},
        .guarded_store = &guarded_store,
        .run_in_foreground = true,
        .default_mutation_outcome = .allow,
        .policy_path = null,
    });
    defer session.deinit();

    try std.testing.expectEqual(filesystem.NodeKind.directory, (try session.inspectPath("/extensions")).kind);
    try std.testing.expectEqual(filesystem.NodeKind.directory, (try session.inspectPath("/extensions/foo")).kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try session.inspectPath("/extensions/foo/token.json")).kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try session.inspectPath("/hosts.yml")).kind);

    const nested_contents = try session.readPath(allocator, "/extensions/foo/token.json");
    defer allocator.free(nested_contents);
    try std.testing.expectEqualStrings("guarded nested token\n", nested_contents);

    const sibling_contents = try session.readPath(allocator, "/hosts.yml");
    defer allocator.free(sibling_contents);
    try std.testing.expectEqualStrings("plain hosts\n", sibling_contents);

    try session.debugWriteFile("/extensions/foo/token.json", "updated nested token\n");
    try session.debugWriteFile("/hosts.yml", "updated hosts\n");

    {
        var object = try mock_state.loadObject(allocator, "nested-token");
        defer object.deinit(allocator);
        try std.testing.expectEqualStrings("updated nested token\n", object.content);
    }
    {
        const contents = try readFileAbsoluteAlloc(allocator, real_sibling_path);
        defer allocator.free(contents);
        try std.testing.expectEqualStrings("updated hosts\n", contents);
    }
}

fn tempPolicyPath(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "/tmp/file-snitch.policy-{s}-{d}.yml",
        .{ name, std.time.nanoTimestamp() },
    );
}

const GeneratedEnrollment = struct {
    path: []const u8,
    object_id: []const u8,
};

const generated_enrollments = [_]GeneratedEnrollment{
    .{ .path = "/tmp/generated/config", .object_id = "generated-config" },
    .{ .path = "/tmp/generated/hosts", .object_id = "generated-hosts" },
    .{ .path = "/tmp/generated/token", .object_id = "generated-token" },
};

const generated_executable_paths = [_][]const u8{
    "/usr/bin/kubectl",
    "/usr/bin/git",
    "/usr/bin/cat",
    "/usr/bin/python3",
};

const generated_uids = [_]u32{ 1000, 1001, 501 };
const generated_approval_classes = [_][]const u8{ "read_like", "write_capable" };
const generated_outcomes = [_][]const u8{ "allow", "deny" };
const generated_expirations = [_]?[]const u8{ null, "1970-01-01T00:00:01Z", "2100-01-01T00:00:00Z" };
const generated_query_paths = [_][]const u8{
    "/tmp/generated/config",
    "/tmp/generated/hosts",
    "/tmp/generated/token",
    "/tmp/generated/unmatched",
};
const generated_access_classes = [_]policy.AccessClass{
    .read,
    .create,
    .write,
    .rename,
    .delete,
    .metadata,
    .xattr,
};
const generated_query_executable_paths = [_]?[]const u8{
    "/usr/bin/kubectl",
    "/usr/bin/git",
    "/usr/bin/cat",
    "/usr/bin/python3",
    "/usr/bin/bash",
    null,
};

fn writeGeneratedPolicyFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    random: std.Random,
    decision_count: usize,
) !void {
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(allocator);

    try source.writer(allocator).writeAll("version: 1\nenrollments:\n");
    for (generated_enrollments) |entry| {
        try source.writer(allocator).print(
            "  - path: {s}\n    object_id: {s}\n",
            .{ entry.path, entry.object_id },
        );
    }
    try source.writer(allocator).writeAll("decisions:\n");
    for (0..decision_count) |_| {
        const executable_path = generated_executable_paths[random.uintLessThan(usize, generated_executable_paths.len)];
        const uid = generated_uids[random.uintLessThan(usize, generated_uids.len)];
        const enrollment = generated_enrollments[random.uintLessThan(usize, generated_enrollments.len)];
        const approval_class = generated_approval_classes[random.uintLessThan(usize, generated_approval_classes.len)];
        const outcome = generated_outcomes[random.uintLessThan(usize, generated_outcomes.len)];
        const expires_at = generated_expirations[random.uintLessThan(usize, generated_expirations.len)];
        try source.writer(allocator).print(
            "  - executable_path: {s}\n    uid: {d}\n    path: {s}\n    approval_class: {s}\n    outcome: {s}\n    expires_at: {s}\n",
            .{
                executable_path,
                uid,
                enrollment.path,
                approval_class,
                outcome,
                expires_at orelse "null",
            },
        );
    }

    var file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source.items);
}

fn randomPolicyRequest(random: std.Random) policy.Request {
    return .{
        .path = generated_query_paths[random.uintLessThan(usize, generated_query_paths.len)],
        .access_class = generated_access_classes[random.uintLessThan(usize, generated_access_classes.len)],
        .pid = @intCast(1 + random.uintLessThan(u32, 4_000)),
        .uid = generated_uids[random.uintLessThan(usize, generated_uids.len)],
        .gid = 20,
        .executable_path = generated_query_executable_paths[random.uintLessThan(usize, generated_query_executable_paths.len)],
    };
}

fn repeatedByteStringZAlloc(allocator: std.mem.Allocator, byte: u8, len: usize) ![:0]u8 {
    const value = try allocator.allocSentinel(u8, len, 0);
    @memset(value[0..len], byte);
    return value;
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

fn expectNoAuditEvent(
    events: []const daemon.AuditEvent,
    action: []const u8,
    path: []const u8,
    result: i32,
) !void {
    for (events) |event| {
        if (!std.mem.eql(u8, event.action, action)) continue;
        if (!std.mem.eql(u8, event.path, path)) continue;
        if (event.result != result) continue;
        std.debug.print(
            "unexpected audit event action={s} path={s} result={d}\n",
            .{ action, path, result },
        );
        return error.TestUnexpectedAuditEvent;
    }
}
