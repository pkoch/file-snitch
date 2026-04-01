const std = @import("std");
const fuse = @import("fuse/shim.zig");

pub fn run() !void {
    const environment = try fuse.probe();

    std.debug.print(
        "file-snitch scaffold: backend={s} fuse={d}.{d} ops_size={d} c_shim={any}\n",
        .{
            environment.backend_name,
            environment.fuse_major_version,
            environment.fuse_minor_version,
            environment.high_level_ops_size,
            environment.uses_c_shim,
        },
    );
}
