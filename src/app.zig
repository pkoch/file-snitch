const std = @import("std");
const daemon = @import("daemon.zig");
const fuse = @import("fuse/shim.zig");

pub fn run() !void {
    const allocator = std.heap.page_allocator;
    const environment = try fuse.probe();
    var session = try daemon.Session.init(allocator, .{
        .mount_path = "/tmp/file-snitch.mount",
        .backing_store_path = "/tmp/file-snitch.store",
        .run_in_foreground = true,
    });
    defer session.deinit();

    const description = try session.describe();
    const plan = try session.executionPlan(allocator);
    defer session.freeExecutionPlan(allocator, plan);

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
        "synthetic root directory and status file are ready; other file access still returns ENOENT\n",
        .{},
    );

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
