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
        allow_mutations: u8,
        reserved: [2]u8,
    };

    pub const RawSessionInfo = extern struct {
        high_level_ops_size: usize,
        configured_operation_count: u32,
        planned_argument_count: u32,
        mount_implemented: u8,
        has_session_state: u8,
        has_daemon_state: u8,
        has_init_callback: u8,
        run_in_foreground: u8,
        allow_mutations: u8,
        reserved: [6]u8,
    };

    pub const RawNodeInfo = extern struct {
        kind: u32,
        mode: u32,
        size: u64,
        inode: u64,
    };

    pub const RawAuditEvent = extern struct {
        action: ?[*:0]const u8,
        path: ?[*:0]const u8,
        result: i32,
    };

    extern fn fsn_fuse_probe(out: *RawEnvironment) c_int;
    extern fn fsn_fuse_backend_name() [*:0]const u8;
    extern fn fsn_fuse_session_create(config: *const RawSessionConfig, out: *?*OpaqueSession) c_int;
    extern fn fsn_fuse_session_destroy(session: *OpaqueSession) void;
    extern fn fsn_fuse_session_describe(session: *const OpaqueSession, out: *RawSessionInfo) c_int;
    extern fn fsn_fuse_session_run(session: *OpaqueSession) c_int;
    extern fn fsn_fuse_session_argument_count(session: *const OpaqueSession) u32;
    extern fn fsn_fuse_session_argument_at(session: *const OpaqueSession, index: u32) ?[*:0]const u8;
    extern fn fsn_fuse_debug_getattr(session: *const OpaqueSession, path: [*:0]const u8, out: *RawNodeInfo) c_int;
    extern fn fsn_fuse_debug_root_entry_count(session: *const OpaqueSession) u32;
    extern fn fsn_fuse_debug_root_entry_at(session: *const OpaqueSession, index: u32) ?[*:0]const u8;
    extern fn fsn_fuse_debug_read(
        session: *const OpaqueSession,
        path: [*:0]const u8,
        offset: u64,
        size: usize,
        buf: [*]u8,
    ) c_int;
    extern fn fsn_fuse_debug_create_file(session: *OpaqueSession, path: [*:0]const u8, mode: u32) c_int;
    extern fn fsn_fuse_debug_write_file(
        session: *OpaqueSession,
        path: [*:0]const u8,
        offset: u64,
        size: usize,
        buf: [*:0]const u8,
    ) c_int;
    extern fn fsn_fuse_debug_truncate_file(session: *OpaqueSession, path: [*:0]const u8, size: u64) c_int;
    extern fn fsn_fuse_debug_remove_file(session: *OpaqueSession, path: [*:0]const u8) c_int;
    extern fn fsn_fuse_debug_audit_count(session: *const OpaqueSession) u32;
    extern fn fsn_fuse_debug_audit_event_at(session: *const OpaqueSession, index: u32, out: *RawAuditEvent) c_int;
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
    allow_mutations: bool = false,
};

pub const SessionDescription = struct {
    backend_name: []const u8,
    mount_path: []const u8,
    backing_store_path: []const u8,
    high_level_ops_size: usize,
    configured_operation_count: u32,
    planned_argument_count: u32,
    mount_implemented: bool,
    has_session_state: bool,
    has_daemon_state: bool,
    has_init_callback: bool,
    run_in_foreground: bool,
    allow_mutations: bool,
};

pub const NodeKind = enum(u32) {
    missing = 0,
    directory = 1,
    regular_file = 2,
};

pub const NodeInfo = struct {
    kind: NodeKind,
    mode: u32,
    size: u64,
    inode: u64,
};

pub const AuditEvent = struct {
    action: []const u8,
    path: []const u8,
    result: i32,
};

pub const Error = error{
    OutOfMemory,
    ProbeFailed,
    SessionCreateFailed,
    SessionDescribeFailed,
    SessionRunFailed,
    MissingSessionPath,
    MissingSessionArgument,
    DebugInspectFailed,
    DebugReadFailed,
    DebugCreateFailed,
    DebugWriteFailed,
    DebugTruncateFailed,
    DebugRemoveFailed,
    DebugAuditFailed,
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
        .allow_mutations = @intFromBool(config.allow_mutations),
        .reserved = std.mem.zeroes([2]u8),
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
        .planned_argument_count = raw.planned_argument_count,
        .mount_implemented = raw.mount_implemented != 0,
        .has_session_state = raw.has_session_state != 0,
        .has_daemon_state = raw.has_daemon_state != 0,
        .has_init_callback = raw.has_init_callback != 0,
        .run_in_foreground = raw.run_in_foreground != 0,
        .allow_mutations = raw.allow_mutations != 0,
    };
}

pub fn runSession(session: *RawSession) Error!void {
    const result = c.fsn_fuse_session_run(session);
    switch (result) {
        0 => return,
        else => return error.SessionRunFailed,
    }
}

pub fn sessionArgumentCount(session: *const RawSession) u32 {
    return c.fsn_fuse_session_argument_count(session);
}

pub fn sessionArgument(session: *const RawSession, index: u32) Error![]const u8 {
    const value = c.fsn_fuse_session_argument_at(session, index) orelse {
        return error.MissingSessionArgument;
    };

    return std.mem.span(value);
}

pub fn debugGetattr(session: *const RawSession, path: [*:0]const u8) Error!NodeInfo {
    var raw: c.RawNodeInfo = std.mem.zeroes(c.RawNodeInfo);
    const result = c.fsn_fuse_debug_getattr(session, path, &raw);
    if (result != 0) {
        return error.DebugInspectFailed;
    }

    return .{
        .kind = @enumFromInt(raw.kind),
        .mode = raw.mode,
        .size = raw.size,
        .inode = raw.inode,
    };
}

pub fn debugRootEntryCount(session: *const RawSession) u32 {
    return c.fsn_fuse_debug_root_entry_count(session);
}

pub fn debugRootEntry(session: *const RawSession, index: u32) Error![]const u8 {
    const value = c.fsn_fuse_debug_root_entry_at(session, index) orelse {
        return error.MissingSessionArgument;
    };

    return std.mem.span(value);
}

pub fn debugRead(session: *const RawSession, path: [*:0]const u8, allocator: std.mem.Allocator) Error![]u8 {
    const node = try debugGetattr(session, path);
    const buffer = try allocator.alloc(u8, @intCast(node.size));
    errdefer allocator.free(buffer);

    const result = c.fsn_fuse_debug_read(session, path, 0, buffer.len, buffer.ptr);
    if (result < 0) {
        return error.DebugReadFailed;
    }

    return buffer[0..@intCast(result)];
}

pub fn debugCreateFile(session: *RawSession, path: [*:0]const u8, mode: u32) Error!void {
    if (c.fsn_fuse_debug_create_file(session, path, mode) != 0) {
        return error.DebugCreateFailed;
    }
}

pub fn debugWriteFile(session: *RawSession, path: [*:0]const u8, contents: [*:0]const u8) Error!void {
    const length = std.mem.len(contents);
    const result = c.fsn_fuse_debug_write_file(session, path, 0, length, contents);
    if (result < 0) {
        return error.DebugWriteFailed;
    }
}

pub fn debugTruncateFile(session: *RawSession, path: [*:0]const u8, size: u64) Error!void {
    if (c.fsn_fuse_debug_truncate_file(session, path, size) != 0) {
        return error.DebugTruncateFailed;
    }
}

pub fn debugRemoveFile(session: *RawSession, path: [*:0]const u8) Error!void {
    if (c.fsn_fuse_debug_remove_file(session, path) != 0) {
        return error.DebugRemoveFailed;
    }
}

pub fn debugAuditCount(session: *const RawSession) u32 {
    return c.fsn_fuse_debug_audit_count(session);
}

pub fn debugAuditEvent(session: *const RawSession, index: u32) Error!AuditEvent {
    var raw: c.RawAuditEvent = std.mem.zeroes(c.RawAuditEvent);
    if (c.fsn_fuse_debug_audit_event_at(session, index, &raw) != 0) {
        return error.DebugAuditFailed;
    }

    return .{
        .action = std.mem.span(raw.action orelse return error.DebugAuditFailed),
        .path = std.mem.span(raw.path orelse return error.DebugAuditFailed),
        .result = raw.result,
    };
}

pub fn statusLabel(status: c_int) []const u8 {
    return std.mem.span(c.fsn_fuse_status_label(status));
}
