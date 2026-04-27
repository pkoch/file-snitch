const std = @import("std");

const c_header = @cImport({
    @cInclude("libfuse_shim.h");
});

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
        daemon_state: ?*anyopaque,
        run_in_foreground: u8,
        reserved: [7]u8,
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
        reserved: [7]u8,
    };

    extern fn fsn_fuse_probe(out: *RawEnvironment) c_int;
    extern fn fsn_fuse_backend_name() [*:0]const u8;
    extern fn fsn_fuse_session_create(config: *const RawSessionConfig, out: *?*OpaqueSession) c_int;
    extern fn fsn_fuse_session_destroy(session: *OpaqueSession) void;
    extern fn fsn_fuse_session_describe(session: *const OpaqueSession, out: *RawSessionInfo) c_int;
    extern fn fsn_fuse_session_run(session: *OpaqueSession) c_int;
    extern fn fsn_fuse_session_argument_count(session: *const OpaqueSession) u32;
    extern fn fsn_fuse_session_argument_at(session: *const OpaqueSession, index: u32) ?[*:0]const u8;
    extern fn fsn_fuse_status_label(status: c_int) [*:0]const u8;
};

comptime {
    assertAbi(c.RawEnvironment, c_header.struct_fsn_fuse_environment, &.{
        .{ "fuse_major_version", "fuse_major_version" },
        .{ "fuse_minor_version", "fuse_minor_version" },
        .{ "high_level_ops_size", "high_level_ops_size" },
        .{ "uses_c_shim", "uses_c_shim" },
        .{ "reserved", "reserved" },
    });
    assertAbi(c.RawSessionConfig, c_header.struct_fsn_fuse_session_config, &.{
        .{ "mount_path", "mount_path" },
        .{ "daemon_state", "daemon_state" },
        .{ "run_in_foreground", "run_in_foreground" },
        .{ "reserved", "reserved" },
    });
    assertAbi(c.RawSessionInfo, c_header.struct_fsn_fuse_session_info, &.{
        .{ "high_level_ops_size", "high_level_ops_size" },
        .{ "configured_operation_count", "configured_operation_count" },
        .{ "planned_argument_count", "planned_argument_count" },
        .{ "mount_implemented", "mount_implemented" },
        .{ "has_session_state", "has_session_state" },
        .{ "has_daemon_state", "has_daemon_state" },
        .{ "has_init_callback", "has_init_callback" },
        .{ "run_in_foreground", "run_in_foreground" },
        .{ "reserved", "reserved" },
    });
}

fn assertAbi(
    comptime ZigStruct: type,
    comptime CStruct: type,
    comptime fields: []const struct { []const u8, []const u8 },
) void {
    if (@sizeOf(ZigStruct) != @sizeOf(CStruct)) {
        @compileError(std.fmt.comptimePrint(
            "ABI size mismatch: Zig {s}={d} bytes, C {s}={d} bytes",
            .{ @typeName(ZigStruct), @sizeOf(ZigStruct), @typeName(CStruct), @sizeOf(CStruct) },
        ));
    }
    if (@alignOf(ZigStruct) != @alignOf(CStruct)) {
        @compileError(std.fmt.comptimePrint(
            "ABI alignment mismatch: Zig {s}={d}, C {s}={d}",
            .{ @typeName(ZigStruct), @alignOf(ZigStruct), @typeName(CStruct), @alignOf(CStruct) },
        ));
    }
    for (fields) |pair| {
        const zig_offset = @offsetOf(ZigStruct, pair[0]);
        const c_offset = @offsetOf(CStruct, pair[1]);
        if (zig_offset != c_offset) {
            @compileError(std.fmt.comptimePrint(
                "ABI field offset mismatch: Zig {s}.{s}={d}, C {s}.{s}={d}",
                .{ @typeName(ZigStruct), pair[0], zig_offset, @typeName(CStruct), pair[1], c_offset },
            ));
        }
        const ZigField = @FieldType(ZigStruct, pair[0]);
        const CField = @FieldType(CStruct, pair[1]);
        if (@sizeOf(ZigField) != @sizeOf(CField)) {
            @compileError(std.fmt.comptimePrint(
                "ABI field size mismatch: Zig {s}.{s}={d} bytes, C {s}.{s}={d} bytes",
                .{ @typeName(ZigStruct), pair[0], @sizeOf(ZigField), @typeName(CStruct), pair[1], @sizeOf(CField) },
            ));
        }
        if (@alignOf(ZigField) != @alignOf(CField)) {
            @compileError(std.fmt.comptimePrint(
                "ABI field alignment mismatch: Zig {s}.{s}={d}, C {s}.{s}={d}",
                .{ @typeName(ZigStruct), pair[0], @alignOf(ZigField), @typeName(CStruct), pair[1], @alignOf(CField) },
            ));
        }
    }
}

fn assertFnAbi(comptime name: []const u8, comptime ZigFn: type, comptime CFn: type) void {
    const zig_info = @typeInfo(ZigFn).@"fn";
    const c_info = @typeInfo(CFn).@"fn";
    if (zig_info.params.len != c_info.params.len) {
        @compileError(std.fmt.comptimePrint(
            "ABI fn arity mismatch for {s}: Zig={d} params, C={d} params",
            .{ name, zig_info.params.len, c_info.params.len },
        ));
    }
    inline for (zig_info.params, c_info.params, 0..) |zp, cp, i| {
        const ZT = zp.type orelse @compileError("ABI fn param missing Zig type: " ++ name);
        const CT = cp.type orelse @compileError("ABI fn param missing C type: " ++ name);
        if (@sizeOf(ZT) != @sizeOf(CT)) {
            @compileError(std.fmt.comptimePrint(
                "ABI fn {s} param[{d}] size mismatch: Zig={d}, C={d}",
                .{ name, i, @sizeOf(ZT), @sizeOf(CT) },
            ));
        }
        if (@alignOf(ZT) != @alignOf(CT)) {
            @compileError(std.fmt.comptimePrint(
                "ABI fn {s} param[{d}] alignment mismatch: Zig={d}, C={d}",
                .{ name, i, @alignOf(ZT), @alignOf(CT) },
            ));
        }
    }
    const ZR = zig_info.return_type orelse @compileError("ABI fn missing Zig return type: " ++ name);
    const CR = c_info.return_type orelse @compileError("ABI fn missing C return type: " ++ name);
    if (@sizeOf(ZR) != @sizeOf(CR)) {
        @compileError(std.fmt.comptimePrint(
            "ABI fn {s} return size mismatch: Zig={d}, C={d}",
            .{ name, @sizeOf(ZR), @sizeOf(CR) },
        ));
    }
    if (@alignOf(ZR) != @alignOf(CR)) {
        @compileError(std.fmt.comptimePrint(
            "ABI fn {s} return alignment mismatch: Zig={d}, C={d}",
            .{ name, @alignOf(ZR), @alignOf(CR) },
        ));
    }
}

comptime {
    assertFnAbi("fsn_fuse_probe", @TypeOf(c.fsn_fuse_probe), @TypeOf(c_header.fsn_fuse_probe));
    assertFnAbi("fsn_fuse_backend_name", @TypeOf(c.fsn_fuse_backend_name), @TypeOf(c_header.fsn_fuse_backend_name));
    assertFnAbi("fsn_fuse_session_create", @TypeOf(c.fsn_fuse_session_create), @TypeOf(c_header.fsn_fuse_session_create));
    assertFnAbi("fsn_fuse_session_destroy", @TypeOf(c.fsn_fuse_session_destroy), @TypeOf(c_header.fsn_fuse_session_destroy));
    assertFnAbi("fsn_fuse_session_describe", @TypeOf(c.fsn_fuse_session_describe), @TypeOf(c_header.fsn_fuse_session_describe));
    assertFnAbi("fsn_fuse_session_run", @TypeOf(c.fsn_fuse_session_run), @TypeOf(c_header.fsn_fuse_session_run));
    assertFnAbi("fsn_fuse_session_argument_count", @TypeOf(c.fsn_fuse_session_argument_count), @TypeOf(c_header.fsn_fuse_session_argument_count));
    assertFnAbi("fsn_fuse_session_argument_at", @TypeOf(c.fsn_fuse_session_argument_at), @TypeOf(c_header.fsn_fuse_session_argument_at));
    assertFnAbi("fsn_fuse_status_label", @TypeOf(c.fsn_fuse_status_label), @TypeOf(c_header.fsn_fuse_status_label));
}

comptime {
    const status_pairs = [_]struct { c_int, c_int }{
        .{ 0, c_header.FSN_FUSE_STATUS_OK },
        .{ -1, c_header.FSN_FUSE_STATUS_INVALID_ARGUMENT },
        .{ -2, c_header.FSN_FUSE_STATUS_OUT_OF_MEMORY },
        .{ -4, c_header.FSN_FUSE_STATUS_PLAN_BUILD_FAILED },
        .{ -5, c_header.FSN_FUSE_STATUS_SETUP_FAILED },
        .{ -6, c_header.FSN_FUSE_STATUS_LOOP_FAILED },
    };
    for (status_pairs) |pair| {
        if (pair[0] != pair[1]) {
            @compileError(std.fmt.comptimePrint(
                "fsn_fuse_status value drift: expected {d}, header has {d}",
                .{ pair[0], pair[1] },
            ));
        }
    }
}

pub const Environment = struct {
    backend_name: []const u8,
    fuse_major_version: u32,
    fuse_minor_version: u32,
    high_level_ops_size: usize,
    uses_c_shim: bool,
};

pub const SessionConfig = struct {
    mount_path: [*:0]const u8,
    daemon_state: ?*anyopaque = null,
    run_in_foreground: bool,
};

pub const SessionDescription = struct {
    backend_name: []const u8,
    high_level_ops_size: usize,
    configured_operation_count: u32,
    planned_argument_count: u32,
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
    MissingSessionArgument,
};

pub const RawSession = c.OpaqueSession;

pub fn probe() Error!Environment {
    var raw: c.RawEnvironment = std.mem.zeroes(c.RawEnvironment);
    if (c.fsn_fuse_probe(&raw) != 0) {
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
        .daemon_state = config.daemon_state,
        .run_in_foreground = @intFromBool(config.run_in_foreground),
        .reserved = std.mem.zeroes([7]u8),
    };
    var session: ?*RawSession = null;
    if (c.fsn_fuse_session_create(&raw_config, &session) != 0 or session == null) {
        return error.SessionCreateFailed;
    }

    return session.?;
}

pub fn destroySession(session: *RawSession) void {
    c.fsn_fuse_session_destroy(session);
}

pub fn describeSession(session: *const RawSession) Error!SessionDescription {
    var raw: c.RawSessionInfo = std.mem.zeroes(c.RawSessionInfo);
    if (c.fsn_fuse_session_describe(session, &raw) != 0) {
        return error.SessionDescribeFailed;
    }

    return .{
        .backend_name = std.mem.span(c.fsn_fuse_backend_name()),
        .high_level_ops_size = raw.high_level_ops_size,
        .configured_operation_count = raw.configured_operation_count,
        .planned_argument_count = raw.planned_argument_count,
        .mount_implemented = raw.mount_implemented != 0,
        .has_session_state = raw.has_session_state != 0,
        .has_daemon_state = raw.has_daemon_state != 0,
        .has_init_callback = raw.has_init_callback != 0,
        .run_in_foreground = raw.run_in_foreground != 0,
    };
}

pub fn runSession(session: *RawSession) Error!void {
    if (c.fsn_fuse_session_run(session) != 0) {
        return error.SessionRunFailed;
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

pub fn statusLabel(status: c_int) []const u8 {
    return std.mem.span(c.fsn_fuse_status_label(status));
}
