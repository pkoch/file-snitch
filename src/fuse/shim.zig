const std = @import("std");

const c = struct {
    pub const OpaqueSession = opaque {};

    pub const RawEnvironment = extern struct {
        fuse_major_version: u32,
        fuse_minor_version: u32,
        high_level_ops_size: usize,
        uses_c_shim: u8,
        reserved: [7]u8,
    };

    pub const RawSessionConfig = extern struct {
        mount_path: [*:0]const u8,
        backing_store_path: [*:0]const u8,
        daemon_state: ?*anyopaque,
        run_in_foreground: u8,
        reserved: [3]u8,
    };

    pub const RawSessionInfo = extern struct {
        high_level_ops_size: usize,
        configured_operation_count: u32,
        mount_implemented: u8,
        has_session_state: u8,
        has_daemon_state: u8,
        has_init_callback: u8,
        run_in_foreground: u8,
        reserved: [3]u8,
    };

    extern fn fsn_fuse_probe(out: *RawEnvironment) c_int;
    extern fn fsn_fuse_backend_name() [*:0]const u8;
    extern fn fsn_fuse_session_create(config: *const RawSessionConfig, out: *?*OpaqueSession) c_int;
    extern fn fsn_fuse_session_destroy(session: *OpaqueSession) void;
    extern fn fsn_fuse_session_describe(session: *const OpaqueSession, out: *RawSessionInfo) c_int;
    extern fn fsn_fuse_session_run(session: *OpaqueSession) c_int;
    extern fn fsn_fuse_session_mount_path(session: *const OpaqueSession) ?[*:0]const u8;
    extern fn fsn_fuse_session_backing_store_path(session: *const OpaqueSession) ?[*:0]const u8;
    extern fn fsn_fuse_status_label(status: c_int) [*:0]const u8;
};

pub const Environment = struct {
    backend_name: []const u8,
    fuse_major_version: u32,
    fuse_minor_version: u32,
    high_level_ops_size: usize,
    uses_c_shim: bool,
};

pub const SessionConfig = struct {
    mount_path: [*:0]const u8,
    backing_store_path: [*:0]const u8,
    daemon_state: ?*anyopaque = null,
    run_in_foreground: bool,
};

pub const SessionDescription = struct {
    backend_name: []const u8,
    mount_path: []const u8,
    backing_store_path: []const u8,
    high_level_ops_size: usize,
    configured_operation_count: u32,
    mount_implemented: bool,
    has_session_state: bool,
    has_daemon_state: bool,
    has_init_callback: bool,
    run_in_foreground: bool,
};

pub const Error = error{
    ProbeFailed,
    SessionCreateFailed,
    SessionDescribeFailed,
    SessionRunFailed,
    SessionRunNotImplemented,
    MissingSessionPath,
};

pub const RawSession = c.OpaqueSession;

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

pub fn createSession(config: SessionConfig) Error!*RawSession {
    var raw_config = c.RawSessionConfig{
        .mount_path = config.mount_path,
        .backing_store_path = config.backing_store_path,
        .daemon_state = config.daemon_state,
        .run_in_foreground = @intFromBool(config.run_in_foreground),
        .reserved = std.mem.zeroes([3]u8),
    };
    var session: ?*RawSession = null;
    const result = c.fsn_fuse_session_create(&raw_config, &session);
    if (result != 0 or session == null) {
        return error.SessionCreateFailed;
    }

    return session.?;
}

pub fn destroySession(session: *RawSession) void {
    c.fsn_fuse_session_destroy(session);
}

pub fn describeSession(session: *const RawSession) Error!SessionDescription {
    var raw: c.RawSessionInfo = std.mem.zeroes(c.RawSessionInfo);
    const result = c.fsn_fuse_session_describe(session, &raw);
    if (result != 0) {
        return error.SessionDescribeFailed;
    }

    const mount_path = c.fsn_fuse_session_mount_path(session) orelse {
        return error.MissingSessionPath;
    };
    const backing_store_path = c.fsn_fuse_session_backing_store_path(session) orelse {
        return error.MissingSessionPath;
    };

    return .{
        .backend_name = std.mem.span(c.fsn_fuse_backend_name()),
        .mount_path = std.mem.span(mount_path),
        .backing_store_path = std.mem.span(backing_store_path),
        .high_level_ops_size = raw.high_level_ops_size,
        .configured_operation_count = raw.configured_operation_count,
        .mount_implemented = raw.mount_implemented != 0,
        .has_session_state = raw.has_session_state != 0,
        .has_daemon_state = raw.has_daemon_state != 0,
        .has_init_callback = raw.has_init_callback != 0,
        .run_in_foreground = raw.run_in_foreground != 0,
    };
}

pub fn runSession(session: *RawSession) Error!void {
    const result = c.fsn_fuse_session_run(session);
    switch (result) {
        0 => return,
        -3 => return error.SessionRunNotImplemented,
        else => return error.SessionRunFailed,
    }
}

pub fn statusLabel(status: c_int) []const u8 {
    return std.mem.span(c.fsn_fuse_status_label(status));
}
