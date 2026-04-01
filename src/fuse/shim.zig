const std = @import("std");

const c = struct {
    pub const RawEnvironment = extern struct {
        fuse_major_version: u32,
        fuse_minor_version: u32,
        high_level_ops_size: usize,
        uses_c_shim: u8,
        reserved: [7]u8,
    };

    extern fn fsn_fuse_probe(out: *RawEnvironment) c_int;
    extern fn fsn_fuse_backend_name() [*:0]const u8;
};

pub const Environment = struct {
    backend_name: []const u8,
    fuse_major_version: u32,
    fuse_minor_version: u32,
    high_level_ops_size: usize,
    uses_c_shim: bool,
};

pub const Error = error{
    ProbeFailed,
};

pub fn probe() Error!Environment {
    var raw: c.RawEnvironment = std.mem.zeroes(c.RawEnvironment);
    const result = c.fsn_fuse_probe(&raw);
    if (result != 0) {
        return error.ProbeFailed;
    }

    return .{
        .backend_name = std.mem.span(c.fsn_fuse_backend_name()),
        .fuse_major_version = raw.fuse_major_version,
        .fuse_minor_version = raw.fuse_minor_version,
        .high_level_ops_size = raw.high_level_ops_size,
        .uses_c_shim = raw.uses_c_shim != 0,
    };
}
