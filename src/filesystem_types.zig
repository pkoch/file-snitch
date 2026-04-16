//! Public data contract for `src/filesystem.zig`. Pure types that callers
//! (daemon, CLI, tests) consume without pulling in the Model implementation.

pub const NodeKind = enum(u32) {
    missing = 0,
    directory = 1,
    regular_file = 2,
};

pub const OpenKind = enum(u8) {
    missing = 0,
    directory = 1,
    synthetic_readonly = 2,
    user_file = 3,
};

pub const AccessContext = struct {
    pid: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    umask: u32 = 0,
    executable_path: ?[]const u8 = null,
};

pub const Timestamp = struct {
    sec: i64,
    nsec: u32,
};

pub const RuntimeStats = struct {
    configured_operation_count: u32 = 0,
    planned_argument_count: u32 = 0,
};

pub const NodeInfo = struct {
    kind: NodeKind,
    mode: u32,
    nlink: u32,
    size: u64,
    block_size: u32,
    block_count: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,
};

pub const Lookup = struct {
    node: NodeInfo,
    open_kind: OpenKind,
    guarded: bool,
};

pub const FileRequestInfo = struct {
    flags: i32,
    handle_id: ?u64 = null,
};

pub const AuditFileInfo = struct {
    flags: i32,
    fh_old: u64,
    writepage: i32,
    direct_io: u8,
    keep_cache: u8,
    flush: u8,
    nonseekable: u8,
    flock_release: u8,
    padding_bits: u32,
    purge_attr: u8,
    purge_ubc: u8,
    fh: u64,
    lock_owner: u64,
};

pub const AuditLockInfo = struct {
    cmd: i32,
    lock_type: i16,
    whence: i16,
    pid: i32,
    start: i64,
    len: i64,
};

pub const AuditFlockInfo = struct {
    operation: i32,
};

pub const AuditXattrInfo = struct {
    name: ?[]const u8 = null,
    size: ?u64 = null,
    flags: ?i32 = null,
    position: ?u32 = null,
};

pub const AuditRenameInfo = struct {
    from: []const u8,
    to: []const u8,
};

pub const AuditSyncInfo = struct {
    datasync: bool,
};

pub const AuditMetadata = struct {
    context: AccessContext = .{},
    file_info: ?AuditFileInfo = null,
    lock: ?AuditLockInfo = null,
    flock: ?AuditFlockInfo = null,
    xattr: ?AuditXattrInfo = null,
    rename: ?AuditRenameInfo = null,
    fsync: ?AuditSyncInfo = null,
};

pub const AuditEvent = struct {
    action: []const u8,
    path: []const u8,
    result: i32,
    timestamp: Timestamp,
    pid: u32,
    uid: u32,
    gid: u32,
    executable_path: ?[]const u8,
    file_info: ?AuditFileInfo,
    lock: ?AuditLockInfo,
    flock: ?AuditFlockInfo,
    xattr: ?AuditXattrInfo,
    rename: ?AuditRenameInfo,
    fsync: ?AuditSyncInfo,
};

pub const GuardedEntryConfig = struct {
    relative_path: []const u8,
    object_id: []const u8,
    lock_anchor_path: []const u8,
};
