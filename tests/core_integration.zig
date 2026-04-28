const std = @import("std");
const app_src = @import("app_src");
const builtin = @import("builtin");
const config = app_src.config;
const daemon = app_src.daemon;
const enrollment_ops = app_src.enrollment;
const filesystem = app_src.filesystem;
const policy = app_src.policy;
const prompt = app_src.prompt;
const runtime = app_src.runtime;
const store = app_src.store;
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("stdlib.h");
});

pub const std_options: std.Options = .{
    .log_level = .info,
};

const created_note_path = "/._demo-note.txt";
const note_path = "/._renamed-note.txt";
const blocked_note_path = "/blocked-note.txt";
const prompted_note_path = "/prompted-note.txt";
const allowed_prompt_note_path = "/allowed-prompt-note.txt";

const TestFile = struct {
    file: std.Io.File,

    fn close(self: TestFile) void {
        self.file.close(runtime.io());
    }

    fn writeAll(self: TestFile, bytes: []const u8) !void {
        try self.file.writeStreamingAll(runtime.io(), bytes);
    }

    fn readToEndAlloc(self: TestFile, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
        var buffer: [4096]u8 = undefined;
        var reader = self.file.reader(runtime.io(), &buffer);
        return reader.interface.allocRemaining(allocator, .limited(max_bytes));
    }

    fn tryLock(self: TestFile, lock: std.Io.File.Lock) !bool {
        return self.file.tryLock(runtime.io(), lock);
    }

    fn chmod(self: TestFile, mode: u32) !void {
        try self.file.setPermissions(runtime.io(), .fromMode(@intCast(mode)));
    }
};

fn makeDirAbsolute(path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(runtime.io(), path);
}

fn makePath(path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(runtime.io(), path);
}

fn deleteTreeAbsolute(path: []const u8) !void {
    try std.Io.Dir.cwd().deleteTree(runtime.io(), path);
}

fn createFileAbsolute(path: []const u8, options: std.Io.Dir.CreateFileOptions) !TestFile {
    return .{ .file = try std.Io.Dir.createFileAbsolute(runtime.io(), path, options) };
}

fn openFileAbsolute(path: []const u8, options: std.Io.Dir.OpenFileOptions) !TestFile {
    return .{ .file = try std.Io.Dir.openFileAbsolute(runtime.io(), path, options) };
}

const CountingPromptContext = struct {
    count: usize = 0,
    response: prompt.Response,
};

const CapturingPromptContext = struct {
    count: usize = 0,
    response: prompt.Response,
    expected_path: []const u8,
    expected_label: []const u8,
    saw_expected_path: bool = false,
    saw_expected_label: bool = false,
};

const TempDir = struct {
    allocator: std.mem.Allocator,
    path: []u8,

    fn init(allocator: std.mem.Allocator, name: []const u8) !TempDir {
        var attempts: usize = 0;
        while (attempts < 32) : (attempts += 1) {
            var random_bytes: [16]u8 = undefined;
            runtime.io().random(&random_bytes);
            const suffix = std.fmt.bytesToHex(random_bytes, .lower);
            const path = try std.fmt.allocPrint(
                allocator,
                "/tmp/file-snitch.test-{s}-{s}",
                .{ name, suffix },
            );
            errdefer allocator.free(path);

            std.Io.Dir.createDirAbsolute(runtime.io(), path, .default_dir) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(path);
                    continue;
                },
                else => return err,
            };

            return .{
                .allocator = allocator,
                .path = path,
            };
        }

        return error.TempDirCollision;
    }

    fn deinit(self: *TempDir) void {
        deleteTreeAbsolute(self.path) catch |err| {
            std.debug.panic("failed to delete test directory {s}: {}", .{ self.path, err });
        };
        self.allocator.free(self.path);
        self.* = undefined;
    }

    fn childPathAlloc(self: *TempDir, name: []const u8) ![]u8 {
        return std.fs.path.join(self.allocator, &.{ self.path, name });
    }
};

const TempPolicyFile = struct {
    dir: TempDir,
    path: []u8,

    fn init(allocator: std.mem.Allocator, name: []const u8) !TempPolicyFile {
        var dir = try TempDir.init(allocator, name);
        errdefer dir.deinit();

        const path = try dir.childPathAlloc("policy.yml");
        errdefer allocator.free(path);

        return .{
            .dir = dir,
            .path = path,
        };
    }

    fn deinit(self: *TempPolicyFile) void {
        const allocator = self.dir.allocator;
        allocator.free(self.path);
        self.dir.deinit();
        self.* = undefined;
    }
};

const ScopedHome = struct {
    allocator: std.mem.Allocator,
    old_home_z: ?[:0]u8,

    fn init(allocator: std.mem.Allocator, home_dir: []const u8) !ScopedHome {
        const old_home = runtime.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        errdefer if (old_home) |value| allocator.free(value);

        const old_home_z = if (old_home) |value| blk: {
            const value_z = try allocator.dupeZ(u8, value);
            allocator.free(value);
            break :blk value_z;
        } else null;
        errdefer if (old_home_z) |value| allocator.free(value);

        const home_dir_z = try allocator.dupeZ(u8, home_dir);
        defer allocator.free(home_dir_z);
        try std.testing.expectEqual(@as(c_int, 0), c.setenv("HOME", home_dir_z.ptr, 1));

        return .{
            .allocator = allocator,
            .old_home_z = old_home_z,
        };
    }

    fn deinit(self: *ScopedHome) void {
        if (self.old_home_z) |value| {
            _ = c.setenv("HOME", value.ptr, 1);
            self.allocator.free(value);
        } else {
            _ = c.unsetenv("HOME");
        }
        self.* = undefined;
    }
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    temp_dir: TempDir,
    mount_path: []u8,
    mock_state: store.MockState = .{},
    backend: store.Backend = undefined,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var temp_dir = try TempDir.init(allocator, "fixture");
        errdefer temp_dir.deinit();

        const mount_path = try temp_dir.childPathAlloc("mount");
        errdefer allocator.free(mount_path);

        try makeDirAbsolute(mount_path);

        return .{
            .allocator = allocator,
            .temp_dir = temp_dir,
            .mount_path = mount_path,
        };
    }

    fn deinit(self: *Fixture) void {
        self.mock_state.deinit(self.allocator);
        self.allocator.free(self.mount_path);
        self.temp_dir.deinit();
        self.* = undefined;
    }

    fn guardedStore(self: *Fixture) *store.Backend {
        self.backend = store.Backend.initMock(&self.mock_state);
        return &self.backend;
    }

    fn childPathAlloc(self: *Fixture, name: []const u8) ![]u8 {
        return self.temp_dir.childPathAlloc(name);
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
    return daemon.Session.initProjection(allocator, .{
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

fn capturingPromptBroker(context: *CapturingPromptContext) prompt.Broker {
    return .{
        .context = context,
        .resolve_fn = resolveCapturingPrompt,
    };
}

fn resolveCountingPrompt(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    _ = request;
    const context = raw_context orelse return .{ .decision = .unavailable };
    const counting_context: *CountingPromptContext = @ptrCast(@alignCast(context));
    counting_context.count += 1;
    return counting_context.response;
}

fn resolveCapturingPrompt(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const capturing_context: *CapturingPromptContext = @ptrCast(@alignCast(context));
    capturing_context.count += 1;
    capturing_context.saw_expected_path = std.mem.eql(u8, request.path, capturing_context.expected_path);
    capturing_context.saw_expected_label = if (request.label) |label|
        std.mem.eql(u8, label, capturing_context.expected_label)
    else
        false;
    return capturing_context.response;
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

fn freeEntries(allocator: std.mem.Allocator, entries: []const []const u8) void {
    for (entries) |entry| allocator.free(entry);
    allocator.free(entries);
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
    const note = try session.inspectPath(note_path);
    try std.testing.expectEqual(filesystem.NodeKind.directory, root.kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, note.kind);

    const entries = try session.rootEntries(allocator);
    defer freeEntries(allocator, entries);
    try expectEntriesContain(entries, &.{note_path[1..]});

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

    try std.testing.expectEqual(@as(usize, 0), session.state.run_attempts);
}

test "directory entry composition is owned by Zig" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var preseed_store = fixture.guardedStore();
    try preseed_store.putObject(allocator, "ghost-secret", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded secret\n",
    });

    const lock_anchor_path = try fixture.childPathAlloc("ghost.lock");
    defer allocator.free(lock_anchor_path);

    const guarded_entries = &.{filesystem.GuardedEntryConfig{
        .object_id = "ghost-secret",
        .lock_anchor_path = lock_anchor_path,
    }};

    var session = try initSession(allocator, &fixture, guarded_entries, .allow, &.{}, null);
    defer session.deinit();

    const root_entries = try session.rootEntries(allocator);
    defer freeEntries(allocator, root_entries);
    try expectEntriesContain(root_entries, &.{"ghost-secret"});

    try std.testing.expectEqual(filesystem.NodeKind.missing, (try session.inspectPath("/nested")).kind);
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

test "transient files cannot rename into regular projection entries" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var session = try initSession(allocator, &fixture, &.{}, .allow, &.{}, null);
    defer session.deinit();
    const context: filesystem.AccessContext = .{ .pid = 1234, .uid = 1000, .gid = 1000 };

    try std.testing.expectEqual(
        -@as(i32, @intFromEnum(std.posix.E.NOENT)),
        session.state.filesystem.openFile("/._missing", .{ .flags = c.O_RDONLY, .handle_id = 0xfeed }, context),
    );

    try session.debugCreateFile("/._tmp", 0o600);
    try std.testing.expectError(
        error.DebugRenameFailed,
        session.debugRenameFile("/._tmp", "/regular"),
    );
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try session.inspectPath("/._tmp")).kind);
    try std.testing.expectEqual(filesystem.NodeKind.missing, (try session.inspectPath("/regular")).kind);

    try session.debugRenameFile("/._tmp", "/._renamed-tmp");
    try std.testing.expectEqual(filesystem.NodeKind.missing, (try session.inspectPath("/._tmp")).kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try session.inspectPath("/._renamed-tmp")).kind);

    try session.debugCreateFile("/._nested-source", 0o600);
    try std.testing.expectError(
        error.DebugRenameFailed,
        session.debugRenameFile("/._nested-source", "/._nested/._target"),
    );
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try session.inspectPath("/._nested-source")).kind);

    var preseed_store = fixture.guardedStore();
    try preseed_store.putObject(allocator, "regular", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded regular\n",
    });
    const lock_anchor_path = try fixture.childPathAlloc("regular.lock");
    defer allocator.free(lock_anchor_path);
    var guarded_session = try initSession(allocator, &fixture, &.{.{
        .object_id = "regular",
        .lock_anchor_path = lock_anchor_path,
    }}, .allow, &.{}, null);
    defer guarded_session.deinit();

    try guarded_session.debugCreateFile("/._tmp", 0o600);
    try std.testing.expectError(
        error.DebugRenameFailed,
        guarded_session.debugRenameFile("/._tmp", "/regular"),
    );
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try guarded_session.inspectPath("/._tmp")).kind);
    try std.testing.expectEqual(filesystem.NodeKind.regular_file, (try guarded_session.inspectPath("/regular")).kind);
}

test "policy and prompt paths are covered by core assertions" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    const guarded_note_path = "/guarded-note.txt";
    const guarded_note_policy_path = try std.fmt.allocPrint(allocator, "{s}/guarded-note.txt", .{fixture.mount_path});
    defer allocator.free(guarded_note_policy_path);
    const lock_anchor_path = try fixture.childPathAlloc("guard-policy.lock");
    defer allocator.free(lock_anchor_path);

    var preseed_store = fixture.guardedStore();
    try preseed_store.putObject(allocator, "guarded-note.txt", .{
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
        .object_id = "guarded-note.txt",
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
            .path_prefix = guarded_note_policy_path,
            .access_class = .read,
            .outcome = .prompt,
        },
        .{
            .path_prefix = guarded_note_policy_path,
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
            .path_prefix = guarded_note_policy_path,
            .access_class = .write,
            .outcome = .prompt,
        },
    }, prompt.scriptedBroker(&allow_prompt_context));
    defer allowed_prompt_session.deinit();

    try allowed_prompt_session.debugWriteFile(guarded_note_path, "updated guarded note\n");

    var readonly_audit = try readonly_session.auditEventSnapshot(allocator);
    defer readonly_audit.deinit();
    const guarded_note_policy_label = try std.fmt.allocPrint(allocator, "write {s}", .{guarded_note_policy_path});
    defer allocator.free(guarded_note_policy_label);
    const guarded_note_read_prompt_label = try std.fmt.allocPrint(allocator, "read {s}", .{guarded_note_policy_path});
    defer allocator.free(guarded_note_read_prompt_label);

    try expectAuditEvent(readonly_audit.items, "policy", guarded_note_policy_label, 2);
    try expectAuditEvent(readonly_audit.items, "write", guarded_note_path, -13);

    var policy_audit = try policy_session.auditEventSnapshot(allocator);
    defer policy_audit.deinit();
    try expectAuditEvent(policy_audit.items, "prompt", guarded_note_read_prompt_label, 4);
    try expectAuditEvent(policy_audit.items, "read", guarded_note_path, -13);
    try expectAuditEvent(policy_audit.items, "policy", guarded_note_policy_label, 2);
    try expectAuditEvent(policy_audit.items, "write", guarded_note_path, -13);

    var allowed_prompt_audit = try allowed_prompt_session.auditEventSnapshot(allocator);
    defer allowed_prompt_audit.deinit();
    try expectAuditEvent(allowed_prompt_audit.items, "prompt", guarded_note_policy_label, 1);
    try expectAuditEvent(allowed_prompt_audit.items, "write", guarded_note_path, 21);

    {
        var stored = try fixture.mock_state.loadObject(allocator, "guarded-note.txt");
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
    try expectAuditEvent(default_prompt_audit.items, "prompt", guarded_note_read_prompt_label, 1);
    try expectAuditEvent(default_prompt_audit.items, "read", guarded_note_path, 21);
}

test "daemon sends home-relative display labels to prompt broker" {
    const allocator = std.testing.allocator;
    var home = try TempDir.init(allocator, "home");
    defer home.deinit();

    var canonical_home_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const canonical_home_len = try std.Io.Dir.realPathFileAbsolute(runtime.io(), home.path, &canonical_home_buffer);
    const canonical_home = canonical_home_buffer[0..canonical_home_len];

    var scoped_home = try ScopedHome.init(allocator, canonical_home);
    defer scoped_home.deinit();

    const source_parent = try std.fs.path.join(allocator, &.{ canonical_home, ".kube" });
    defer allocator.free(source_parent);
    try makeDirAbsolute(source_parent);

    const source_guarded_path = try std.fs.path.join(allocator, &.{ source_parent, "config" });
    defer allocator.free(source_guarded_path);
    const projection_root = try std.fs.path.join(allocator, &.{ canonical_home, ".local/state/file-snitch/projection" });
    defer allocator.free(projection_root);

    const lock_anchor_path = try home.childPathAlloc("config.lock");
    defer allocator.free(lock_anchor_path);

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "config", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded kubeconfig\n",
    });

    var prompt_context = CapturingPromptContext{
        .response = .{ .decision = .allow },
        .expected_path = source_guarded_path,
        .expected_label = "read ~/.kube/config",
    };

    var session = try daemon.Session.initProjection(allocator, .{
        .mount_path = projection_root,
        .guarded_entries = &.{.{
            .object_id = "config",
            .lock_anchor_path = lock_anchor_path,
            .policy_path = source_guarded_path,
        }},
        .guarded_store = &guarded_store,
        .run_in_foreground = true,
        .default_mutation_outcome = .prompt,
        .policy_path = null,
        .policy_rule_views = &.{},
        .prompt_broker = capturingPromptBroker(&prompt_context),
    });
    defer session.deinit();

    var buffer: [64]u8 = undefined;
    const context: filesystem.AccessContext = .{ .pid = 1234, .uid = 1000, .gid = 1000 };

    const read_len = session.state.filesystem.readInto("/config", 0, &buffer, context, null);
    try std.testing.expect(read_len > 0);
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);
    try std.testing.expect(prompt_context.saw_expected_path);
    try std.testing.expect(prompt_context.saw_expected_label);

    prompt_context.expected_label = "open O_RDONLY ~/.kube/config";
    prompt_context.saw_expected_path = false;
    prompt_context.saw_expected_label = false;

    const open_request: filesystem.FileRequestInfo = .{
        .flags = c.O_RDONLY,
        .handle_id = 0xfeed,
    };
    try std.testing.expectEqual(@as(i32, 0), session.state.filesystem.openFile("/config", open_request, context));
    try std.testing.expectEqual(@as(usize, 2), prompt_context.count);
    try std.testing.expect(prompt_context.saw_expected_path);
    try std.testing.expect(prompt_context.saw_expected_label);

    const handle_read_len = session.state.filesystem.readInto("/config", 0, &buffer, context, open_request);
    try std.testing.expect(handle_read_len > 0);
    try std.testing.expectEqual(@as(usize, 3), prompt_context.count);
}

test "open write handle grants mutation access until release" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    const guarded_note_path = "/handle-granted-note.txt";
    const lock_anchor_path = try fixture.childPathAlloc("handle-granted-note.lock");
    defer allocator.free(lock_anchor_path);

    var preseed_store = fixture.guardedStore();
    try preseed_store.putObject(allocator, "handle-granted-note.txt", .{
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
        .object_id = "handle-granted-note.txt",
        .lock_anchor_path = lock_anchor_path,
    }};

    var prompt_context = CountingPromptContext{
        .response = .{ .decision = .allow },
    };
    var session = try initSession(
        allocator,
        &fixture,
        guarded_entries,
        .prompt,
        &.{},
        countingPromptBroker(&prompt_context),
    );
    defer session.deinit();

    const context: filesystem.AccessContext = .{ .pid = 1234, .uid = 1000, .gid = 1000 };
    const request: filesystem.FileRequestInfo = .{
        .flags = c.O_RDWR,
        .handle_id = 0xfeed,
    };

    try std.testing.expectEqual(@as(i32, 0), session.state.filesystem.openFile(guarded_note_path, request, context));
    session.state.filesystem.recordOpen(guarded_note_path, context, request, 0, null);
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);

    try std.testing.expectEqual(@as(i32, 0), session.state.filesystem.truncateFile(guarded_note_path, 7, context));
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);

    session.state.filesystem.recordRelease(guarded_note_path, context, request, 0, null);
    try std.testing.expectEqual(@as(i32, 0), session.state.filesystem.truncateFile(guarded_note_path, 4, context));
    try std.testing.expectEqual(@as(usize, 2), prompt_context.count);

    try std.testing.expectEqual(
        @as(i32, 4),
        session.state.filesystem.writeFileWithRequest(guarded_note_path, 0, "edit", context, request),
    );
    try std.testing.expectEqual(@as(usize, 3), prompt_context.count);
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
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.openDirAbsolute(runtime.io(), host_path, .{}));

    const not_supported = -@as(i32, @intFromEnum(std.posix.E.OPNOTSUPP));
    var audit_snapshot = try session.auditEventSnapshot(allocator);
    defer audit_snapshot.deinit();
    try expectAuditEvent(audit_snapshot.items, "mkdir", "/empty-dir", not_supported);
    try expectAuditEvent(audit_snapshot.items, "rmdir", "/empty-dir", not_supported);
}

test "policy file loader treats empty file as a no-op" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "empty");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    file.close();

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    try std.testing.expectEqual(@as(u32, 1), loaded.version);
    try std.testing.expectEqual(@as(usize, 0), loaded.enrollments.len);
    try std.testing.expectEqual(@as(usize, 0), loaded.decisions.len);

    var projection_plan = try loaded.deriveProjectionPlan(allocator);
    defer projection_plan.deinit();
    try std.testing.expectEqual(@as(usize, 0), projection_plan.entries.len);
}

test "policy file loader parses enrollments and derives projection plan" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "planned");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: ~/.kube/config
        \\    object_id: kube-config
        \\  - path: ~/.config/gh/hosts.yml
        \\    object_id: gh-hosts
        \\  - path: ~/.config/gh/extensions/foo/token.json
        \\    object_id: gh-extension-token
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/.kube/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    const kube_config_path = try currentHomePathAlloc(allocator, ".kube/config");
    defer allocator.free(kube_config_path);
    const projection_root = try config.defaultProjectionRootPathAlloc(allocator);
    defer allocator.free(projection_root);
    const kube_projection_path = try std.fs.path.join(allocator, &.{ projection_root, "kube-config" });
    defer allocator.free(kube_projection_path);

    try std.testing.expectEqual(@as(usize, 3), loaded.enrollments.len);
    try std.testing.expectEqualStrings(kube_config_path, loaded.enrollments[0].path);
    try std.testing.expectEqualStrings("kube-config", loaded.enrollments[0].object_id);
    try std.testing.expectEqual(@as(usize, 1), loaded.decisions.len);
    try std.testing.expectEqualStrings("/usr/bin/kubectl", loaded.decisions[0].executable_path);
    try std.testing.expectEqualStrings("read_like", loaded.decisions[0].approval_class);
    try std.testing.expectEqualStrings("allow", loaded.decisions[0].outcome);
    try std.testing.expect(loaded.decisions[0].expires_at == null);

    var projection_plan = try loaded.deriveProjectionPlan(allocator);
    defer projection_plan.deinit();
    try std.testing.expectEqual(@as(usize, 3), projection_plan.entries.len);
    try std.testing.expectEqualStrings(projection_root, projection_plan.root_path);
    try std.testing.expectEqualStrings(kube_config_path, projection_plan.entries[0].target_path);
    try std.testing.expectEqualStrings(kube_projection_path, projection_plan.entries[0].projection_path);
    try std.testing.expectEqualStrings("kube-config", projection_plan.entries[0].object_id);
}

test "policy file save round-trips appended enrollments" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "roundtrip");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    const kube_config_path = try currentHomePathAlloc(allocator, ".kube/config");
    defer allocator.free(kube_config_path);
    const ssh_key_path = try currentHomePathAlloc(allocator, ".ssh/id_ed25519");
    defer allocator.free(ssh_key_path);

    try loaded.appendEnrollment(kube_config_path, "kube-config");
    try std.testing.expectError(error.InvalidEnrollmentObjectId, loaded.appendEnrollment(ssh_key_path, "kube-config"));
    try loaded.appendEnrollment(ssh_key_path, "ssh-main");
    try loaded.saveToFile();

    var reloaded = try config.loadFromFile(allocator, path);
    defer reloaded.deinit();

    try std.testing.expectEqual(@as(usize, 2), reloaded.enrollments.len);
    try std.testing.expectEqualStrings(kube_config_path, reloaded.enrollments[0].path);
    try std.testing.expectEqualStrings("kube-config", reloaded.enrollments[0].object_id);
    try std.testing.expectEqualStrings(ssh_key_path, reloaded.enrollments[1].path);
    try std.testing.expectEqualStrings("ssh-main", reloaded.enrollments[1].object_id);
    try std.testing.expectEqual(@as(usize, 0), reloaded.decisions.len);
}

test "policy file expands and saves home-relative paths" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "home-relative-policy");
    defer temp_dir.deinit();

    const home_dir = try temp_dir.childPathAlloc("home");
    defer allocator.free(home_dir);
    try makeDirAbsolute(home_dir);

    var scoped_home = try ScopedHome.init(allocator, home_dir);
    defer scoped_home.deinit();

    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);
    const source =
        \\version: 1
        \\enrollments:
        \\  - path: ~/secrets/gist
        \\    object_id: gist-secret
        \\decisions:
        \\  - executable_path: /usr/bin/cat
        \\    path: ~/secrets/gist
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
    ;

    var file = try createFileAbsolute(policy_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var canonical_home_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const canonical_home_len = try std.Io.Dir.realPathFileAbsolute(runtime.io(), home_dir, &canonical_home_buffer);
    const canonical_home_dir = canonical_home_buffer[0..canonical_home_len];
    const expanded_secret_path = try std.fs.path.join(allocator, &.{ canonical_home_dir, "secrets", "gist" });
    defer allocator.free(expanded_secret_path);

    var loaded = try config.loadFromFile(allocator, policy_path);
    defer loaded.deinit();
    try std.testing.expectEqualStrings(expanded_secret_path, loaded.enrollments[0].path);
    try std.testing.expectEqualStrings(expanded_secret_path, loaded.decisions[0].path);

    try loaded.saveToFile();
    const saved = try readFileAbsoluteAlloc(allocator, policy_path);
    defer allocator.free(saved);
    try std.testing.expect(std.mem.indexOf(u8, saved, "path: '~/secrets/gist'") != null);
    try std.testing.expect(std.mem.indexOf(u8, saved, home_dir) == null);
}

test "policy file rejects object ids that are unsafe projection path components" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "reserved-object-id-policy");
    defer temp_dir.deinit();

    const home_dir = try temp_dir.childPathAlloc("home");
    defer allocator.free(home_dir);
    try makeDirAbsolute(home_dir);

    var scoped_home = try ScopedHome.init(allocator, home_dir);
    defer scoped_home.deinit();

    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);

    const unsafe_ids = [_][]const u8{ ".", "..", "._tmp", "foo/bar", "foo bar" };
    for (unsafe_ids) |object_id| {
        var file = try createFileAbsolute(policy_path, .{ .truncate = true });
        try file.writeAll(
            \\version: 1
            \\enrollments:
            \\  - path: ~/secrets/token
        );
        try file.writeAll("\n    object_id: '");
        try file.writeAll(object_id);
        try file.writeAll("'\ndecisions: []\n");
        file.close();

        try std.testing.expectError(error.InvalidEnrollmentObjectId, config.loadFromFile(allocator, policy_path));
    }
}

test "policy file rejects duplicate object ids" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "duplicate-object-id-policy");
    defer temp_dir.deinit();

    const home_dir = try temp_dir.childPathAlloc("home");
    defer allocator.free(home_dir);
    try makeDirAbsolute(home_dir);

    var scoped_home = try ScopedHome.init(allocator, home_dir);
    defer scoped_home.deinit();

    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);

    var file = try createFileAbsolute(policy_path, .{ .truncate = true });
    try file.writeAll(
        \\version: 1
        \\enrollments:
        \\  - path: ~/secrets/one
        \\    object_id: duplicate
        \\  - path: ~/secrets/two
        \\    object_id: duplicate
        \\decisions: []
        \\
    );
    file.close();

    try std.testing.expectError(error.InvalidEnrollmentObjectId, config.loadFromFile(allocator, policy_path));
}

test "policy file rejects paths outside the current home" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "outside-home-policy");
    defer temp_dir.deinit();

    const home_dir = try temp_dir.childPathAlloc("home");
    defer allocator.free(home_dir);
    try makeDirAbsolute(home_dir);

    var scoped_home = try ScopedHome.init(allocator, home_dir);
    defer scoped_home.deinit();

    const outside_path = try temp_dir.childPathAlloc("outside/config");
    defer allocator.free(outside_path);

    const enrollment_policy_path = try temp_dir.childPathAlloc("outside-enrollment.yml");
    defer allocator.free(enrollment_policy_path);
    {
        var file = try createFileAbsolute(enrollment_policy_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("version: 1\nenrollments:\n");
        try file.writeAll("  - path: ");
        try file.writeAll(outside_path);
        try file.writeAll("\n    object_id: outside-secret\ndecisions: []\n");
    }
    try std.testing.expectError(error.InvalidEnrollmentPath, config.loadFromFile(allocator, enrollment_policy_path));

    const decision_policy_path = try temp_dir.childPathAlloc("outside-decision.yml");
    defer allocator.free(decision_policy_path);
    {
        var file = try createFileAbsolute(decision_policy_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("version: 1\nenrollments: []\ndecisions:\n");
        try file.writeAll("  - executable_path: /usr/bin/cat\n    path: ");
        try file.writeAll(outside_path);
        try file.writeAll("\n    approval_class: read_like\n    outcome: allow\n    expires_at: null\n");
    }
    try std.testing.expectError(error.InvalidDecisionPath, config.loadFromFile(allocator, decision_policy_path));
}

test "policy file save removes enrollment and attached decisions" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "remove");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: ~/.kube/config
        \\    object_id: kube-config
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/.kube/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    const kube_config_path = try currentHomePathAlloc(allocator, ".kube/config");
    defer allocator.free(kube_config_path);

    const index = loaded.findEnrollmentIndex(kube_config_path).?;
    loaded.removeDecisionsForPath(kube_config_path);
    var removed = loaded.removeEnrollmentAt(index);
    defer removed.deinit(allocator);
    try loaded.saveToFile();

    var reloaded = try config.loadFromFile(allocator, path);
    defer reloaded.deinit();

    try std.testing.expectEqual(@as(usize, 0), reloaded.enrollments.len);
    try std.testing.expectEqual(@as(usize, 0), reloaded.decisions.len);
}

test "compiled durable decisions respect executable path" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "compiled-rules");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: ~/guarded/config
        \\    object_id: kube-config
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: write_capable
        \\    outcome: deny
        \\    expires_at: null
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();
    const guarded_config_path = loaded.enrollments[0].path;

    var compiled = try loaded.compilePolicyRuleViews(allocator);
    defer compiled.deinit();

    var engine = try policy.Engine.init(allocator, .allow, compiled.items);
    defer engine.deinit();

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluate(.{
        .path = guarded_config_path,
        .access_class = .read,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }));

    try std.testing.expectEqual(policy.Outcome.deny, engine.evaluate(.{
        .path = guarded_config_path,
        .access_class = .write,
        .pid = 42,
        .uid = 999,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }));

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluate(.{
        .path = guarded_config_path,
        .access_class = .write,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/bash",
    }));

    try std.testing.expectEqual(policy.Outcome.deny, engine.evaluate(.{
        .path = guarded_config_path,
        .access_class = .write,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }));
}

test "compiled durable decisions ignore expired entries" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "compiled-rules-expiration");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: ~/guarded/config
        \\    object_id: kube-config
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: read_like
        \\    outcome: deny
        \\    expires_at: '1970-01-01T00:00:01Z'
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: write_capable
        \\    outcome: deny
        \\    expires_at: '2100-01-01T00:00:00Z'
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();
    const guarded_config_path = loaded.enrollments[0].path;

    var compiled = try loaded.compilePolicyRuleViews(allocator);
    defer compiled.deinit();

    var engine = try policy.Engine.init(allocator, .allow, compiled.items);
    defer engine.deinit();

    try std.testing.expectEqual(policy.Outcome.allow, engine.evaluateAt(.{
        .path = guarded_config_path,
        .access_class = .read,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }, 1_900_000_000));

    try std.testing.expectEqual(policy.Outcome.deny, engine.evaluateAt(.{
        .path = guarded_config_path,
        .access_class = .write,
        .pid = 42,
        .uid = 1000,
        .gid = 20,
        .executable_path = "/usr/bin/kubectl",
    }, 1_900_000_000));
}

test "policy loader rejects invalid decision expiration" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "invalid-decision-expiration");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments:
        \\  - path: ~/guarded/config
        \\    object_id: kube-config
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: later-ish
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    try std.testing.expectError(error.InvalidDecisionExpiration, config.loadFromFile(allocator, path));
}

test "policy file prunes expired decisions in place" {
    const allocator = std.testing.allocator;
    var temp_policy = try TempPolicyFile.init(allocator, "prune-expired-decisions");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments: []
        \\decisions:
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: '1970-01-01T00:00:01Z'
        \\  - executable_path: /usr/bin/kubectl
        \\    path: ~/guarded/config
        \\    approval_class: write_capable
        \\    outcome: deny
        \\    expires_at: null
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
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
    var temp_policy = try TempPolicyFile.init(allocator, "upsert-decision");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    const source =
        \\version: 1
        \\enrollments: []
        \\decisions: []
    ;

    var file = try createFileAbsolute(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(source);

    var loaded = try config.loadFromFile(allocator, path);
    defer loaded.deinit();

    try loaded.upsertDecision(
        "/usr/bin/kubectl",
        "/tmp/guarded/config",
        "read_like",
        "allow",
        null,
    );
    try loaded.upsertDecision(
        "/usr/bin/kubectl",
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
    var temp_policy = try TempPolicyFile.init(allocator, "policy-lock");
    defer temp_policy.deinit();
    const path = temp_policy.path;

    var first_lock = try config.acquirePolicyLock(allocator, path);
    defer first_lock.deinit();

    const second_file = try openFileAbsolute(first_lock.lock_path, .{ .mode = .read_write });
    defer second_file.close();

    try std.testing.expect(!(try second_file.tryLock(.exclusive)));
}

test "current policy marker treats missing file as absent" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "cli-marker-missing");
    defer temp_dir.deinit();
    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);

    const marker = try config.currentPolicyMarker(allocator, policy_path);
    try std.testing.expect(!marker.exists);
}

test "current policy marker preserves access errors" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "cli-marker-denied");
    defer temp_dir.deinit();
    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);

    var file = try createFileAbsolute(policy_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll("version: 1\nenrollments: []\ndecisions: []\n");

    try file.chmod(0);
    defer file.chmod(0o600) catch |err| {
        std.debug.panic("failed to restore test policy permissions: {}", .{err});
    };

    try std.testing.expectError(error.AccessDenied, config.currentPolicyMarker(allocator, policy_path));
}

test "current policy marker hashes policy contents beyond one megabyte" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "cli-marker-large");
    defer temp_dir.deinit();
    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);

    {
        var file = try createFileAbsolute(policy_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("version: 1\nenrollments: []\ndecisions:\n  - executable_path: \"/usr/bin/demo\"\n");
        const filler = try allocator.alloc(u8, 1_100_000);
        defer allocator.free(filler);
        @memset(filler, 'a');
        try file.writeAll(filler);
    }
    const first_marker = try config.currentPolicyMarker(allocator, policy_path);

    {
        var file = try createFileAbsolute(policy_path, .{ .truncate = true });
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
    var temp_dir = try TempDir.init(allocator, "live-policy-reload");
    defer temp_dir.deinit();
    var scoped_home = try ScopedHome.init(allocator, temp_dir.path);
    defer scoped_home.deinit();

    const source_parent = try currentHomePathAlloc(allocator, "source");
    defer allocator.free(source_parent);
    const source_guarded_path = try std.fmt.allocPrint(allocator, "{s}/config", .{source_parent});
    defer allocator.free(source_guarded_path);
    const projection_root = try currentHomePathAlloc(allocator, ".local/state/file-snitch/projection");
    defer allocator.free(projection_root);
    const policy_path = try temp_dir.childPathAlloc("policy.yml");
    defer allocator.free(policy_path);
    const lock_anchor_path = try temp_dir.childPathAlloc("live-policy.lock");
    defer allocator.free(lock_anchor_path);

    try makeDirAbsolute(source_parent);

    {
        var file = try createFileAbsolute(source_guarded_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host kubeconfig\n");
    }

    var policy_file = try config.loadFromFile(allocator, policy_path);
    defer policy_file.deinit();
    try policy_file.appendEnrollment(source_guarded_path, "kube-config");
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

    var session = try daemon.Session.initProjection(allocator, .{
        .mount_path = projection_root,
        .guarded_entries = &.{.{
            .object_id = "kube-config",
            .lock_anchor_path = lock_anchor_path,
            .policy_path = source_guarded_path,
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

    const first_len = session.state.filesystem.readInto("/kube-config", 0, &buffer, access_context, null);
    try std.testing.expect(first_len > 0);
    try std.testing.expectEqualStrings("guarded kubeconfig\n", buffer[0..@intCast(first_len)]);
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);

    {
        var writable_policy = try config.loadFromFile(allocator, policy_path);
        defer writable_policy.deinit();
        try writable_policy.upsertDecision(
            "/usr/bin/demo",
            source_guarded_path,
            "read_like",
            "allow",
            null,
        );
        try writable_policy.saveToFile();
    }

    const second_len = session.state.filesystem.readInto("/kube-config", 0, &buffer, access_context, null);
    try std.testing.expect(second_len > 0);
    try std.testing.expectEqualStrings("guarded kubeconfig\n", buffer[0..@intCast(second_len)]);
    try std.testing.expectEqual(@as(usize, 1), prompt_context.count);
}

test "generated policy engine behavior survives source teardown" {
    const allocator = std.testing.allocator;
    var scoped_home = try ScopedHome.init(allocator, "/");
    defer scoped_home.deinit();

    var prng = std.Random.DefaultPrng.init(0x5eed_cafe);
    const random = prng.random();

    for (0..24) |case_index| {
        var temp_policy = try TempPolicyFile.init(allocator, "generated-engine-teardown");
        defer temp_policy.deinit();
        const path = temp_policy.path;

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
    var scoped_home = try ScopedHome.init(allocator, "/");
    defer scoped_home.deinit();

    var prng = std.Random.DefaultPrng.init(0x51a0_1eed);
    const random = prng.random();

    for (0..24) |case_index| {
        var temp_policy = try TempPolicyFile.init(allocator, "generated-policy-roundtrip");
        defer temp_policy.deinit();
        const path = temp_policy.path;

        var file = try createFileAbsolute(path, .{ .truncate = true });
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
            const enrollment = generated_enrollments[random.uintLessThan(usize, generated_enrollments.len)];
            const approval_class = generated_approval_classes[random.uintLessThan(usize, generated_approval_classes.len)];
            const outcome = generated_outcomes[random.uintLessThan(usize, generated_outcomes.len)];
            const expires_at = generated_expirations[random.uintLessThan(usize, generated_expirations.len)];
            try loaded.upsertDecision(executable_path, enrollment.path, approval_class, outcome, expires_at);
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
        const current_path_raw = try std.fmt.allocPrint(allocator, "/._property-note-{d}.txt", .{index});
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

test "projection exposes the guarded file without backing siblings" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "projection");
    defer temp_dir.deinit();
    const source_parent = try temp_dir.childPathAlloc("source");
    defer allocator.free(source_parent);
    const lock_anchor_path = try temp_dir.childPathAlloc("guarded.lock");
    defer allocator.free(lock_anchor_path);
    const source_guarded_path = try std.fmt.allocPrint(allocator, "{s}/config", .{source_parent});
    defer allocator.free(source_guarded_path);
    const sibling_path = try std.fmt.allocPrint(allocator, "{s}/sibling.txt", .{source_parent});
    defer allocator.free(sibling_path);

    try makeDirAbsolute(source_parent);

    var source_guarded_file = try createFileAbsolute(source_guarded_path, .{ .truncate = true });
    defer source_guarded_file.close();
    try source_guarded_file.writeAll("host kubeconfig\n");

    var sibling_file = try createFileAbsolute(sibling_path, .{ .truncate = true });
    defer sibling_file.close();
    try sibling_file.writeAll("plain sibling\n");

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "config", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded kubeconfig\n",
    });

    var session = try daemon.Session.initProjection(allocator, .{
        .mount_path = source_parent,
        .guarded_entries = &.{.{
            .object_id = "config",
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
    try std.testing.expectEqual(filesystem.NodeKind.missing, sibling_node.kind);

    const guarded_contents = try session.readPath(allocator, "/config");
    defer allocator.free(guarded_contents);
    try std.testing.expectEqualStrings("guarded kubeconfig\n", guarded_contents);

    try session.debugWriteFile("/config", "updated guarded kubeconfig\n");

    {
        var object = try mock_state.loadObject(allocator, "config");
        defer object.deinit(allocator);
        try std.testing.expectEqualStrings("updated guarded kubeconfig\n", object.content);
    }

    const source_guarded_contents = try readFileAbsoluteAlloc(allocator, source_guarded_path);
    defer allocator.free(source_guarded_contents);
    try std.testing.expectEqualStrings("host kubeconfig\n", source_guarded_contents);

    const sibling_host_contents = try readFileAbsoluteAlloc(allocator, sibling_path);
    defer allocator.free(sibling_host_contents);
    try std.testing.expectEqualStrings("plain sibling\n", sibling_host_contents);
}

test "projection can expose multiple guarded siblings under one mount" {
    const allocator = std.testing.allocator;
    var temp_dir = try TempDir.init(allocator, "projection-multi");
    defer temp_dir.deinit();
    const source_parent = try temp_dir.childPathAlloc("source");
    defer allocator.free(source_parent);
    const first_lock_anchor_path = try temp_dir.childPathAlloc("first.lock");
    defer allocator.free(first_lock_anchor_path);
    const second_lock_anchor_path = try temp_dir.childPathAlloc("second.lock");
    defer allocator.free(second_lock_anchor_path);
    const first_source_path = try std.fmt.allocPrint(allocator, "{s}/a.key", .{source_parent});
    defer allocator.free(first_source_path);
    const second_source_path = try std.fmt.allocPrint(allocator, "{s}/b.key", .{source_parent});
    defer allocator.free(second_source_path);
    const sibling_path = try std.fmt.allocPrint(allocator, "{s}/pubring.kbx", .{source_parent});
    defer allocator.free(sibling_path);

    try makeDirAbsolute(source_parent);

    {
        var file = try createFileAbsolute(first_source_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host first\n");
    }
    {
        var file = try createFileAbsolute(second_source_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host second\n");
    }
    {
        var file = try createFileAbsolute(sibling_path, .{ .truncate = true });
        defer file.close();
        try file.writeAll("host sibling\n");
    }

    var mock_state: store.MockState = .{};
    defer mock_state.deinit(allocator);
    var guarded_store = store.Backend.initMock(&mock_state);
    try guarded_store.putObject(allocator, "a.key", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded first\n",
    });
    try guarded_store.putObject(allocator, "b.key", .{
        .metadata = .{
            .mode = 0o600,
            .uid = 1000,
            .gid = 1000,
            .atime_nsec = 0,
            .mtime_nsec = 0,
        },
        .content = "guarded second\n",
    });

    var session = try daemon.Session.initProjection(allocator, .{
        .mount_path = source_parent,
        .guarded_entries = &.{
            .{
                .object_id = "a.key",
                .lock_anchor_path = first_lock_anchor_path,
            },
            .{
                .object_id = "b.key",
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

    try std.testing.expectEqual(filesystem.NodeKind.missing, (try session.inspectPath("/pubring.kbx")).kind);

    try session.debugWriteFile("/a.key", "updated guarded first\n");
    try session.debugWriteFile("/b.key", "updated guarded second\n");

    {
        var object = try mock_state.loadObject(allocator, "a.key");
        defer object.deinit(allocator);
        try std.testing.expectEqualStrings("updated guarded first\n", object.content);
    }
    {
        var object = try mock_state.loadObject(allocator, "b.key");
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
        try std.testing.expectEqualStrings("host sibling\n", contents);
    }
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

    try source.appendSlice(allocator, "version: 1\nenrollments:\n");
    for (generated_enrollments) |entry| {
        try source.print(
            allocator,
            "  - path: {s}\n    object_id: {s}\n",
            .{ entry.path, entry.object_id },
        );
    }
    try source.appendSlice(allocator, "decisions:\n");
    for (0..decision_count) |_| {
        const executable_path = generated_executable_paths[random.uintLessThan(usize, generated_executable_paths.len)];
        const enrollment = generated_enrollments[random.uintLessThan(usize, generated_enrollments.len)];
        const approval_class = generated_approval_classes[random.uintLessThan(usize, generated_approval_classes.len)];
        const outcome = generated_outcomes[random.uintLessThan(usize, generated_outcomes.len)];
        const expires_at = generated_expirations[random.uintLessThan(usize, generated_expirations.len)];
        try source.print(
            allocator,
            "  - executable_path: {s}\n    path: {s}\n    approval_class: {s}\n    outcome: {s}\n    expires_at: {s}\n",
            .{
                executable_path,
                enrollment.path,
                approval_class,
                outcome,
                expires_at orelse "null",
            },
        );
    }

    var file = try createFileAbsolute(path, .{ .truncate = true });
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
    var file = try openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    return file.readToEndAlloc(allocator, 1024 * 1024);
}

fn currentHomePathAlloc(allocator: std.mem.Allocator, relative_path: []const u8) ![]u8 {
    const home_dir = try enrollment_ops.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);
    return std.fs.path.join(allocator, &.{ home_dir, relative_path });
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
