const std = @import("std");

var active_io: ?std.Io = null;
var active_env: ?*const std.process.Environ.Map = null;

pub fn init(process_init: std.process.Init) void {
    active_io = process_init.io;
    active_env = process_init.environ_map;
}

pub fn io() std.Io {
    return active_io orelse std.Options.debug_io;
}

pub fn timestamp() i64 {
    return std.Io.Clock.real.now(io()).toSeconds();
}

pub fn milliTimestamp() i64 {
    return std.Io.Clock.real.now(io()).toMilliseconds();
}

pub fn nanoTimestamp() i128 {
    return @intCast(std.Io.Clock.real.now(io()).toNanoseconds());
}

pub fn getEnvVarOwned(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const name_z = try allocator.dupeZ(u8, name);
    defer allocator.free(name_z);

    const value = std.c.getenv(name_z) orelse return error.EnvironmentVariableNotFound;
    return allocator.dupe(u8, std.mem.span(value));
}

pub fn envMap() ?*const std.process.Environ.Map {
    return active_env;
}

pub fn stdoutWriteAll(bytes: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(io(), bytes);
}
