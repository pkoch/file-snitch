const std = @import("std");
const daemon = @import("daemon.zig");
const fuse = @import("fuse/shim.zig");

pub fn run() !void {
    const allocator = std.heap.page_allocator;
    const environment = try fuse.probe();
    const note_path = "/demo-note.txt";
    const status_path = "/file-snitch-status";
    var session = try daemon.Session.init(allocator, .{
        .mount_path = "/tmp/file-snitch.mount",
        .backing_store_path = "/tmp/file-snitch.store",
        .run_in_foreground = true,
    });
    defer session.deinit();

    try session.debugCreateFile(note_path, 0o600);
    try session.debugWriteFile(note_path, "hello from file-snitch\n");

    const description = try session.describe();
    const plan = try session.executionPlan(allocator);
    defer session.freeExecutionPlan(allocator, plan);
    const root = try session.inspectPath("/");
    const status = try session.inspectPath(status_path);
    const note = try session.inspectPath(note_path);
    const entries = try session.rootEntries(allocator);
    defer allocator.free(entries);
    const status_content = try session.readPath(allocator, status_path);
    defer allocator.free(status_content);
    const note_content = try session.readPath(allocator, note_path);
    defer allocator.free(note_content);

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
        "prepared session: mount={s} backing={s} session_ops={d} configured_ops={d} argv={d} state={any} daemon_state={any} init_cb={any} mount_impl={any} foreground={any}\n",
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
        },
    );

    std.debug.print(
        "debug inspect: root(kind={s} inode={d}) status(kind={s} size={d} inode={d}) note(kind={s} size={d} inode={d}) entries={d}\n",
        .{
            @tagName(root.kind),
            root.inode,
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
        "synthetic root directory, status file, and in-memory demo note are ready; other file access still returns ENOENT\n",
        .{},
    );

    std.debug.print("status file contents:\n{s}", .{status_content});
    std.debug.print("note file contents:\n{s}", .{note_content});

    for (plan.args, 0..) |arg, index| {
        std.debug.print("argv[{d}]={s}\n", .{ index, arg });
    }

    std.debug.print(
        "run path is implemented but not invoked from the demo app to avoid mounting side effects\n",
        .{},
    );

    if (session.state.run_attempts != 0) {
        return error.Unexpected;
    }
}
