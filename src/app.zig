const std = @import("std");
const daemon = @import("daemon.zig");
const fuse = @import("fuse/shim.zig");

pub fn run() !void {
    const environment = try fuse.probe();
    var session = try daemon.Session.init(std.heap.page_allocator, .{
        .mount_path = "/tmp/file-snitch.mount",
        .backing_store_path = "/tmp/file-snitch.store",
        .run_in_foreground = true,
    });
    defer session.deinit();

    const description = try session.describe();

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
        "prepared session: mount={s} backing={s} session_ops={d} configured_ops={d} state={any} daemon_state={any} init_cb={any} mount_impl={any} foreground={any}\n",
        .{
            description.mount_path,
            description.backing_store_path,
            description.high_level_ops_size,
            description.configured_operation_count,
            description.has_session_state,
            description.has_daemon_state,
            description.has_init_callback,
            description.mount_implemented,
            description.run_in_foreground,
        },
    );

    session.run() catch |err| switch (err) {
        error.SessionRunNotImplemented => std.debug.print(
            "run result: not implemented yet after {d} attempt(s)\n",
            .{session.state.run_attempts},
        ),
        else => return err,
    };
}
