const std = @import("std");
const daemon = @import("daemon.zig");
const fuse = @import("fuse/shim.zig");

pub fn run(args: []const []const u8) !void {
    if (args.len == 0 or std.mem.eql(u8, args[0], "demo")) {
        return runDemo();
    }

    if (std.mem.eql(u8, args[0], "mount")) {
        return runMount(args[1..]);
    }

    if (std.mem.eql(u8, args[0], "help") or std.mem.eql(u8, args[0], "--help")) {
        printUsage();
        return;
    }

    printUsage();
    return error.InvalidUsage;
}

fn runDemo() !void {
    const allocator = std.heap.page_allocator;
    const environment = try fuse.probe();
    const audit_path = "/file-snitch-audit";
    const created_note_path = "/demo-note.txt";
    const note_path = "/renamed-note.txt";
    const blocked_note_path = "/blocked-note.txt";
    const seed_path = "/seed-from-store.txt";
    const status_path = "/file-snitch-status";
    const run_id = std.time.nanoTimestamp();
    const mount_path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.mount-{d}", .{run_id});
    defer allocator.free(mount_path);
    var backing_store = try prepareBackingStoreFixture(allocator, run_id);
    defer backing_store.deinit(allocator);
    var session = try daemon.Session.init(allocator, .{
        .mount_path = mount_path,
        .backing_store_path = backing_store.path,
        .run_in_foreground = true,
        .allow_mutations = true,
    });
    defer session.deinit();

    try session.debugCreateFile(created_note_path, 0o600);
    try session.debugWriteFile(created_note_path, "hello from file-snitch\n");
    try session.debugRenameFile(created_note_path, note_path);
    try session.debugSyncFile(note_path, false);

    var readonly_session = try daemon.Session.init(allocator, .{
        .mount_path = mount_path,
        .backing_store_path = backing_store.path,
        .run_in_foreground = true,
        .allow_mutations = false,
    });
    defer readonly_session.deinit();

    const description = try session.describe();
    const plan = try session.executionPlan(allocator);
    defer session.freeExecutionPlan(allocator, plan);
    const root = try session.inspectPath("/");
    const audit = try session.inspectPath(audit_path);
    const readonly_note = try readonly_session.inspectPath(note_path);
    const seed = try session.inspectPath(seed_path);
    const status = try session.inspectPath(status_path);
    const note = try session.inspectPath(note_path);
    const entries = try session.rootEntries(allocator);
    defer allocator.free(entries);
    const seed_content = try session.readPath(allocator, seed_path);
    defer allocator.free(seed_content);
    const status_content = try session.readPath(allocator, status_path);
    defer allocator.free(status_content);
    const audit_content = try session.readPath(allocator, audit_path);
    defer allocator.free(audit_content);
    const note_content = try session.readPath(allocator, note_path);
    defer allocator.free(note_content);
    const readonly_note_content = try readonly_session.readPath(allocator, note_path);
    defer allocator.free(readonly_note_content);

    std.debug.print(
        "file-snitch scaffold: backend={s} fuse={d}.{d} env_ops={d} c_shim={any}\n",
        .{
            environment.backend_name,
            environment.fuse_major_version,
            environment.fuse_minor_version,
            environment.high_level_ops_size,
            environment.uses_c_shim,
        },
    );

    std.debug.print(
        "prepared session: mount={s} backing={s} session_ops={d} configured_ops={d} argv={d} state={any} daemon_state={any} init_cb={any} mount_impl={any} foreground={any} mutations={any}\n",
        .{
            description.mount_path,
            description.backing_store_path,
            description.high_level_ops_size,
            description.configured_operation_count,
            description.planned_argument_count,
            description.has_session_state,
            description.has_daemon_state,
            description.has_init_callback,
            description.mount_implemented,
            description.run_in_foreground,
            description.allow_mutations,
        },
    );

    std.debug.print(
        "reloaded session: note(kind={s} size={d} inode={d})\n",
        .{ @tagName(readonly_note.kind), readonly_note.size, readonly_note.inode },
    );

    std.debug.print(
        "debug inspect: root(kind={s} inode={d}) audit(kind={s} size={d} inode={d}) seed(kind={s} size={d} inode={d}) status(kind={s} size={d} inode={d}) note(kind={s} size={d} inode={d}) entries={d}\n",
        .{
            @tagName(root.kind),
            root.inode,
            @tagName(audit.kind),
            audit.size,
            audit.inode,
            @tagName(seed.kind),
            seed.size,
            seed.inode,
            @tagName(status.kind),
            status.size,
            status.inode,
            @tagName(note.kind),
            note.size,
            note.inode,
            entries.len,
        },
    );

    for (entries, 0..) |entry, index| {
        std.debug.print("root[{d}]={s}\n", .{ index, entry });
    }

    std.debug.print(
        "synthetic control files, a seeded backing-store file, and an in-memory demo note are ready; directory passthrough is still one level only\n",
        .{},
    );

    std.debug.print("seed file contents:\n{s}", .{seed_content});
    std.debug.print("status file contents:\n{s}", .{status_content});
    std.debug.print("audit file contents:\n{s}", .{audit_content});
    std.debug.print("note file contents:\n{s}", .{note_content});
    std.debug.print("reloaded note contents:\n{s}", .{readonly_note_content});

    for (plan.args, 0..) |arg, index| {
        std.debug.print("argv[{d}]={s}\n", .{ index, arg });
    }

    std.debug.print(
        "run path is implemented but not invoked from the demo app to avoid mounting side effects\n",
        .{},
    );

    readonly_session.debugCreateFile(blocked_note_path, 0o600) catch |err| switch (err) {
        error.DebugCreateFailed => std.debug.print(
            "read-only session blocked create as expected (mutations={any})\n",
            .{readonly_session.state.allow_mutations},
        ),
        else => return err,
    };

    const audit_events = try session.auditEvents(allocator);
    defer allocator.free(audit_events);
    const readonly_audit_events = try readonly_session.auditEvents(allocator);
    defer allocator.free(readonly_audit_events);

    for (audit_events, 0..) |event, index| {
        std.debug.print(
            "audit[{d}] action={s} path={s} result={d}\n",
            .{ index, event.action, event.path, event.result },
        );
    }

    for (readonly_audit_events, 0..) |event, index| {
        std.debug.print(
            "readonly_audit[{d}] action={s} path={s} result={d}\n",
            .{ index, event.action, event.path, event.result },
        );
    }

    if (session.state.run_attempts != 0) {
        return error.Unexpected;
    }
}

fn runMount(args: []const []const u8) !void {
    if (args.len < 2 or args.len > 3) {
        printUsage();
        return error.InvalidUsage;
    }

    const allocator = std.heap.page_allocator;
    const mount_path = try std.fs.realpathAlloc(allocator, args[0]);
    defer allocator.free(mount_path);
    const backing_store_path = try std.fs.realpathAlloc(allocator, args[1]);
    defer allocator.free(backing_store_path);
    const allow_mutations = if (args.len == 3)
        try parseMountPolicy(args[2])
    else
        false;

    try requireEmptyDirectory(mount_path);
    try ensureDirectory(backing_store_path);

    var session = try daemon.Session.init(allocator, .{
        .mount_path = mount_path,
        .backing_store_path = backing_store_path,
        .run_in_foreground = true,
        .allow_mutations = allow_mutations,
    });
    defer session.deinit();

    const description = try session.describe();
    std.debug.print(
        "mounting file-snitch: mount={s} backing={s} configured_ops={d} mutations={any}\n",
        .{
            description.mount_path,
            description.backing_store_path,
            description.configured_operation_count,
            description.allow_mutations,
        },
    );

    try session.run();
}

fn parseMountPolicy(arg: []const u8) !bool {
    if (std.mem.eql(u8, arg, "mutable")) {
        return true;
    }

    if (std.mem.eql(u8, arg, "readonly")) {
        return false;
    }

    printUsage();
    return error.InvalidUsage;
}

fn requireEmptyDirectory(path: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
    defer dir.close();

    var iterator = dir.iterate();
    if (try iterator.next() != null) {
        return error.MountPathNotEmpty;
    }
}

fn ensureDirectory(path: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(path, .{});
    dir.close();
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  file-snitch [demo]
        \\  file-snitch mount <mount-path> <backing-store-path> [mutable|readonly]
        \\
        \\notes:
        \\  - `demo` is the side-effect-free dry-run inspection path
        \\  - `mount` requires an existing empty mount directory
        \\  - `mount` defaults to `readonly` unless `mutable` is specified
        \\
    , .{});
}

const BackingStoreFixture = struct {
    path: []u8,

    fn deinit(self: BackingStoreFixture, allocator: std.mem.Allocator) void {
        std.fs.deleteTreeAbsolute(self.path) catch {};
        allocator.free(self.path);
    }
};

fn prepareBackingStoreFixture(allocator: std.mem.Allocator, run_id: i128) !BackingStoreFixture {
    const path = try std.fmt.allocPrint(allocator, "/tmp/file-snitch.store-{d}", .{run_id});
    errdefer allocator.free(path);

    try std.fs.makeDirAbsolute(path);

    {
        const seed_host_path = try std.fmt.allocPrint(allocator, "{s}/seed-from-store.txt", .{path});
        defer allocator.free(seed_host_path);

        var seed_file = try std.fs.createFileAbsolute(seed_host_path, .{ .truncate = true });
        defer seed_file.close();

        try seed_file.writeAll("seeded from backing store\n");
    }

    return .{ .path = path };
}
