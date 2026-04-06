const std = @import("std");
const builtin = @import("builtin");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
    @cInclude("sys/xattr.h");
});

const root_inode: u64 = 1;
const first_dynamic_inode: u64 = 4;

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
    persistent: bool,
};

pub const Layout = enum {
    guarded_root,
    enrolled_parent,
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

const StoredAuditEvent = struct {
    action: []u8,
    path: []u8,
    result: i32,
    timestamp: Timestamp,
    pid: u32,
    uid: u32,
    gid: u32,
    executable_path: ?[]u8,
    file_info: ?AuditFileInfo,
    lock: ?AuditLockInfo,
    flock: ?AuditFlockInfo,
    xattr: ?StoredAuditXattrInfo,
    rename: ?StoredAuditRenameInfo,
    fsync: ?AuditSyncInfo,

    fn deinit(self: *StoredAuditEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.action);
        allocator.free(self.path);
        if (self.executable_path) |value| {
            allocator.free(value);
        }
        if (self.xattr) |*xattr| {
            xattr.deinit(allocator);
        }
        if (self.rename) |*rename| {
            rename.deinit(allocator);
        }
        self.* = undefined;
    }
};

const StoredAuditXattrInfo = struct {
    name: ?[]u8 = null,
    size: ?u64 = null,
    flags: ?i32 = null,
    position: ?u32 = null,

    fn deinit(self: *StoredAuditXattrInfo, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        self.* = undefined;
    }
};

const StoredAuditRenameInfo = struct {
    from: []u8,
    to: []u8,

    fn deinit(self: *StoredAuditRenameInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.from);
        allocator.free(self.to);
        self.* = undefined;
    }
};

const StoredFile = struct {
    name: [:0]u8,
    path: [:0]u8,
    content: std.ArrayListUnmanaged(u8) = .{},
    mode: u32,
    uid: u32,
    gid: u32,
    inode: u64,
    atime: Timestamp,
    mtime: Timestamp,
    ctime: Timestamp,

    fn deinit(self: *StoredFile, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.path);
        self.content.deinit(allocator);
        self.* = undefined;
    }
};

const MetadataSnapshot = struct {
    mode: u32,
    uid: u32,
    gid: u32,
};

const HandleGrant = struct {
    can_read: bool,
    can_write: bool,
    pid: u32,
    path: []u8,

    fn deinit(self: *HandleGrant, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

const RenameMutation = struct {
    source_index: usize,
    original_name: [:0]u8,
    original_path: [:0]u8,
    replaced_target_index: ?usize,
    replaced_target: ?StoredFile,
};

pub const Config = struct {
    mount_path: []const u8,
    backing_store_path: []const u8,
    default_mutation_outcome: policy.Outcome = .deny,
    policy_rules: []const policy.Rule = &.{},
    prompt_broker: ?prompt.Broker = null,
    status_output_file: ?std.fs.File = null,
    audit_output_file: ?std.fs.File = null,
};

pub const EnrolledParentConfig = struct {
    mount_path: []const u8,
    guarded_file_name: []const u8,
    guarded_backing_file_path: []const u8,
    default_mutation_outcome: policy.Outcome = .deny,
    policy_rules: []const policy.Rule = &.{},
    prompt_broker: ?prompt.Broker = null,
    status_output_file: ?std.fs.File = null,
    audit_output_file: ?std.fs.File = null,
};

pub const Model = struct {
    allocator: std.mem.Allocator,
    layout: Layout,
    mount_path: []u8,
    backing_store_path: []u8,
    source_dir: ?std.fs.Dir = null,
    guarded_file_name: ?[]u8 = null,
    guarded_virtual_path: ?[]u8 = null,
    policy_engine: policy.Engine,
    prompt_broker: ?prompt.Broker,
    status_output_file: ?std.fs.File,
    audit_output_file: ?std.fs.File,
    files: std.ArrayListUnmanaged(StoredFile) = .{},
    audit_events: std.ArrayListUnmanaged(StoredAuditEvent) = .{},
    handle_grants: std.AutoHashMapUnmanaged(u64, HandleGrant) = .{},
    next_inode: u64 = first_dynamic_inode,
    runtime_stats: RuntimeStats = .{},
    root_timestamp: Timestamp,
    output_mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, config: Config) !Model {
        const now = currentTimestamp();
        var model = Model{
            .allocator = allocator,
            .layout = .guarded_root,
            .mount_path = try allocator.dupe(u8, config.mount_path),
            .backing_store_path = try allocator.dupe(u8, config.backing_store_path),
            .policy_engine = try policy.Engine.init(
                allocator,
                config.default_mutation_outcome,
                config.policy_rules,
            ),
            .prompt_broker = config.prompt_broker,
            .status_output_file = config.status_output_file,
            .audit_output_file = config.audit_output_file,
            .root_timestamp = now,
        };
        errdefer model.deinit();

        return model;
    }

    pub fn initEnrolledParent(allocator: std.mem.Allocator, config: EnrolledParentConfig) !Model {
        const guarded_virtual_path = try std.fmt.allocPrint(allocator, "/{s}", .{config.guarded_file_name});
        errdefer allocator.free(guarded_virtual_path);

        var source_dir = try std.fs.openDirAbsolute(config.mount_path, .{ .iterate = true });
        errdefer source_dir.close();

        var model = Model{
            .allocator = allocator,
            .layout = .enrolled_parent,
            .mount_path = try allocator.dupe(u8, config.mount_path),
            .backing_store_path = try allocator.dupe(u8, config.guarded_backing_file_path),
            .source_dir = source_dir,
            .guarded_file_name = try allocator.dupe(u8, config.guarded_file_name),
            .guarded_virtual_path = guarded_virtual_path,
            .policy_engine = try policy.Engine.init(
                allocator,
                config.default_mutation_outcome,
                config.policy_rules,
            ),
            .prompt_broker = config.prompt_broker,
            .status_output_file = config.status_output_file,
            .audit_output_file = config.audit_output_file,
            .root_timestamp = currentTimestamp(),
        };
        errdefer model.deinit();

        try model.loadGuardedBackingFile();
        return model;
    }

    pub fn loadBackingStore(self: *Model) !void {
        if (self.layout != .guarded_root) {
            return error.InvalidLayout;
        }

        if (self.files.items.len != 0) {
            return error.BackingStoreAlreadyLoaded;
        }

        try ensureBackingStoreDirectory(self.backing_store_path);

        var directory = try std.fs.openDirAbsolute(self.backing_store_path, .{ .iterate = true });
        defer directory.close();

        var iterator = directory.iterate();
        while (try iterator.next()) |entry| {
            if (isTransientSidecarName(entry.name)) {
                continue;
            }

            const virtual_path = try std.fmt.allocPrint(self.allocator, "/{s}", .{entry.name});
            defer self.allocator.free(virtual_path);

            if (entry.kind != .file) {
                continue;
            }

            var file = try directory.openFile(entry.name, .{ .mode = .read_only });
            defer file.close();

            const stat = try file.stat();
            const posix_stat = try std.posix.fstat(file.handle);
            const imported = try self.appendFile(
                virtual_path,
                @intCast(stat.mode & 0o777),
                @intCast(posix_stat.uid),
                @intCast(posix_stat.gid),
            );
            const imported_now = currentTimestamp();
            imported.atime = imported_now;
            imported.mtime = imported_now;
            imported.ctime = imported_now;

            if (stat.size > 0) {
                try imported.content.ensureTotalCapacityPrecise(self.allocator, @intCast(stat.size));
                imported.content.items.len = @intCast(stat.size);
                const read_count = try file.readAll(imported.content.items);
                if (read_count != imported.content.items.len) {
                    return error.UnexpectedEof;
                }
            }
        }
    }

    fn loadGuardedBackingFile(self: *Model) !void {
        if (self.layout != .enrolled_parent) {
            return error.InvalidLayout;
        }

        if (self.files.items.len != 0) {
            return error.BackingStoreAlreadyLoaded;
        }

        const guarded_path = self.guarded_virtual_path orelse return error.InvalidLayout;
        var file = try std.fs.openFileAbsolute(self.backing_store_path, .{ .mode = .read_only });
        defer file.close();

        const stat = try file.stat();
        const posix_stat = try std.posix.fstat(file.handle);
        const imported = try self.appendFile(
            guarded_path,
            @intCast(stat.mode & 0o777),
            @intCast(posix_stat.uid),
            @intCast(posix_stat.gid),
        );
        imported.atime = timestampFromStatNanos(stat.atime);
        imported.mtime = timestampFromStatNanos(stat.mtime);
        imported.ctime = timestampFromStatNanos(stat.ctime);

        if (stat.size > 0) {
            try imported.content.ensureTotalCapacityPrecise(self.allocator, @intCast(stat.size));
            imported.content.items.len = @intCast(stat.size);
            const read_count = try file.readAll(imported.content.items);
            if (read_count != imported.content.items.len) {
                return error.UnexpectedEof;
            }
        }
    }

    pub fn deinit(self: *Model) void {
        for (self.files.items) |*file| {
            file.deinit(self.allocator);
        }
        self.files.deinit(self.allocator);

        for (self.audit_events.items) |*event| {
            event.deinit(self.allocator);
        }
        self.audit_events.deinit(self.allocator);
        var grant_iterator = self.handle_grants.valueIterator();
        while (grant_iterator.next()) |grant| {
            grant.deinit(self.allocator);
        }
        self.handle_grants.deinit(self.allocator);

        self.policy_engine.deinit();
        if (self.source_dir) |*dir| {
            dir.close();
        }
        if (self.guarded_file_name) |value| {
            self.allocator.free(value);
        }
        if (self.guarded_virtual_path) |value| {
            self.allocator.free(value);
        }
        self.allocator.free(self.mount_path);
        self.allocator.free(self.backing_store_path);
        self.* = undefined;
    }

    pub fn setRuntimeStats(self: *Model, stats: RuntimeStats) void {
        self.runtime_stats = stats;
    }

    pub fn publishStatus(self: *Model) void {
        self.emitStatusSnapshot();
    }

    pub fn defaultMutationOutcome(self: *const Model) policy.Outcome {
        return self.policy_engine.default_mutation_outcome;
    }

    pub fn lookupPath(self: *const Model, path: []const u8) Lookup {
        if (self.layout == .enrolled_parent) {
            return self.lookupEnrolledParentPath(path);
        }

        if (isRootPath(path)) {
            return .{
                .node = .{
                    .kind = .directory,
                    .mode = 0o755,
                    .nlink = 2,
                    .size = 0,
                    .block_size = 4096,
                    .block_count = 0,
                    .inode = root_inode,
                    .uid = currentUid(),
                    .gid = currentGid(),
                    .atime = self.root_timestamp,
                    .mtime = self.root_timestamp,
                    .ctime = self.root_timestamp,
                },
                .open_kind = .directory,
                .persistent = false,
            };
        }

        if (self.findFile(path)) |file| {
            return .{
                .node = .{
                    .kind = .regular_file,
                    .mode = file.mode,
                    .size = file.content.items.len,
                    .nlink = 1,
                    .block_size = 4096,
                    .block_count = blockCountForSize(@intCast(file.content.items.len)),
                    .inode = file.inode,
                    .uid = file.uid,
                    .gid = file.gid,
                    .atime = file.atime,
                    .mtime = file.mtime,
                    .ctime = file.ctime,
                },
                .open_kind = .user_file,
                .persistent = shouldPersistPath(path),
            };
        }

        return .{
            .node = .{
                .kind = .missing,
                .mode = 0,
                .nlink = 0,
                .size = 0,
                .block_size = 0,
                .block_count = 0,
                .inode = 0,
                .uid = 0,
                .gid = 0,
                .atime = .{ .sec = 0, .nsec = 0 },
                .mtime = .{ .sec = 0, .nsec = 0 },
                .ctime = .{ .sec = 0, .nsec = 0 },
            },
            .open_kind = .missing,
            .persistent = false,
        };
    }

    pub fn rootEntryCount(self: *const Model) u32 {
        if (self.layout == .enrolled_parent) {
            var count: u32 = 0;
            for (self.files.items) |file| {
                if (self.guarded_virtual_path) |guarded_path| {
                    if (std.mem.eql(u8, file.path, guarded_path)) continue;
                }
                count += 1;
            }
            return count;
        }
        return @intCast(self.files.items.len);
    }

    pub fn rootEntryNameAt(self: *const Model, index: u32) ?[*:0]const u8 {
        if (self.layout == .enrolled_parent) {
            var visible_index: u32 = 0;
            for (self.files.items) |file| {
                if (self.guarded_virtual_path) |guarded_path| {
                    if (std.mem.eql(u8, file.path, guarded_path)) continue;
                }
                if (visible_index == index) return file.name.ptr;
                visible_index += 1;
            }
            return null;
        }
        const file_index: usize = @intCast(index);
        if (file_index >= self.files.items.len) {
            return null;
        }

        return self.files.items[file_index].name.ptr;
    }

    fn lookupEnrolledParentPath(self: *const Model, path: []const u8) Lookup {
        if (isRootPath(path)) {
            return self.lookupSourceDirectoryNode(path);
        }

        if (self.findFile(path)) |file| {
            return .{
                .node = .{
                    .kind = .regular_file,
                    .mode = file.mode,
                    .size = file.content.items.len,
                    .nlink = 1,
                    .block_size = 4096,
                    .block_count = blockCountForSize(@intCast(file.content.items.len)),
                    .inode = file.inode,
                    .uid = file.uid,
                    .gid = file.gid,
                    .atime = file.atime,
                    .mtime = file.mtime,
                    .ctime = file.ctime,
                },
                .open_kind = .user_file,
                .persistent = self.isGuardedPath(path),
            };
        }

        if (self.guarded_virtual_path) |guarded_path| {
            if (std.mem.eql(u8, path, guarded_path)) {
                return missingLookup();
            }
        }

        return self.lookupPassthroughPath(path);
    }

    fn lookupSourceDirectoryNode(self: *const Model, path: []const u8) Lookup {
        const dir = self.source_dir orelse return missingLookup();
        const stat = dir.stat() catch return missingLookup();
        const posix_stat = std.posix.fstat(dir.fd) catch return missingLookup();
        _ = path;
        return .{
            .node = .{
                .kind = .directory,
                .mode = @intCast(stat.mode & 0o777),
                .nlink = @intCast(posix_stat.nlink),
                .size = 0,
                .block_size = @intCast(posix_stat.blksize),
                .block_count = @intCast(posix_stat.blocks),
                .inode = posix_stat.ino,
                .uid = @intCast(posix_stat.uid),
                .gid = @intCast(posix_stat.gid),
                .atime = timestampFromStatNanos(stat.atime),
                .mtime = timestampFromStatNanos(stat.mtime),
                .ctime = timestampFromStatNanos(stat.ctime),
            },
            .open_kind = .directory,
            .persistent = false,
        };
    }

    fn lookupPassthroughPath(self: *const Model, path: []const u8) Lookup {
        const dir = self.source_dir orelse return missingLookup();
        const relative_path = relativeMountedPath(path) orelse return missingLookup();
        const stat = dir.statFile(relative_path) catch |err| switch (err) {
            error.FileNotFound => return missingLookup(),
            else => return missingLookup(),
        };
        const posix_stat = std.posix.fstatat(dir.fd, relative_path, 0) catch return missingLookup();

        const kind: NodeKind = switch (stat.kind) {
            .directory => .directory,
            .file => .regular_file,
            else => .missing,
        };
        if (kind == .missing) {
            return missingLookup();
        }

        return .{
            .node = .{
                .kind = kind,
                .mode = @intCast(stat.mode & 0o777),
                .nlink = @intCast(posix_stat.nlink),
                .size = @intCast(stat.size),
                .block_size = @intCast(posix_stat.blksize),
                .block_count = @intCast(posix_stat.blocks),
                .inode = posix_stat.ino,
                .uid = @intCast(posix_stat.uid),
                .gid = @intCast(posix_stat.gid),
                .atime = timestampFromStatNanos(stat.atime),
                .mtime = timestampFromStatNanos(stat.mtime),
                .ctime = timestampFromStatNanos(stat.ctime),
            },
            .open_kind = switch (kind) {
                .directory => .directory,
                .regular_file => .user_file,
                .missing => .missing,
            },
            .persistent = false,
        };
    }

    pub fn authorizeAccess(
        self: *Model,
        path: []const u8,
        access_class: policy.AccessClass,
        context: AccessContext,
    ) i32 {
        return self.authorizeAccessDetailed(path, access_class, context, null);
    }

    pub fn openFile(
        self: *Model,
        path: []const u8,
        file_request: FileRequestInfo,
        context: AccessContext,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            const lookup = self.lookupPath(path);
            return switch (lookup.open_kind) {
                .directory => errnoCode(.ISDIR),
                .missing => errnoCode(.NOENT),
                else => if ((file_request.flags & c.O_TRUNC) != 0 and (file_request.flags & c.O_ACCMODE) != c.O_RDONLY)
                    self.truncateOpenedPassthroughFile(path)
                else
                    0,
            };
        }

        const access_class = accessClassForOpenFlags(file_request.flags);
        const label = formatOpenPromptLabel(self.allocator, "open", path, file_request.flags) catch {
            return errnoCode(.NOMEM);
        };
        defer self.allocator.free(label);
        const auth_result = self.authorizeAccessDetailed(path, access_class, context, label);
        if (auth_result != 0) {
            return auth_result;
        }

        if ((file_request.flags & c.O_TRUNC) != 0 and (file_request.flags & c.O_ACCMODE) != c.O_RDONLY) {
            return self.truncateOpenedFile(path);
        }

        return 0;
    }

    fn authorizeAccessDetailed(
        self: *Model,
        path: []const u8,
        access_class: policy.AccessClass,
        context: AccessContext,
        label: ?[]const u8,
    ) i32 {
        const request: policy.Request = .{
            .path = path,
            .access_class = access_class,
            .pid = context.pid,
            .uid = context.uid,
            .gid = context.gid,
        };

        return switch (self.policy_engine.evaluate(request)) {
            .allow => 0,
            .deny => blk: {
                self.recordPolicyAudit(access_class, path, .deny, context, label);
                break :blk errnoCode(.ACCES);
            },
            .prompt => self.resolvePromptDecision(request, context, label),
        };
    }

    pub fn readInto(
        self: *Model,
        path: []const u8,
        offset: u64,
        buffer: []u8,
        context: AccessContext,
        file_request: ?FileRequestInfo,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            const result = self.readPassthroughInto(path, offset, buffer);
            self.recordAuditLiteral("read", path, result, context);
            return result;
        }

        const auth_result = if (file_request) |request|
            authorizeReadFromOpenFlags(request.flags)
        else
            self.authorizeAccess(path, .read, context);
        if (auth_result != 0) {
            self.recordAuditLiteral("read", path, auth_result, context);
            return auth_result;
        }

        if (offset > std.math.maxInt(usize)) {
            self.recordAuditLiteral("read", path, errnoCode(.INVAL), context);
            return errnoCode(.INVAL);
        }

        const file = self.findFile(path) orelse {
            self.recordAuditLiteral("read", path, errnoCode(.NOENT), context);
            return errnoCode(.NOENT);
        };
        touchFileAtime(file);

        const result = copySlice(file.content.items, buffer, @intCast(offset));
        self.recordAuditLiteral("read", path, result, context);
        return result;
    }

    pub fn createFile(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const result = self.createFileInternal(path, mode, context, null);
        self.recordAuditLiteral("create", path, result, context);
        return result;
    }

    pub fn createFileWithRequest(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
        file_request: FileRequestInfo,
    ) i32 {
        const result = self.createFileInternal(path, mode, context, file_request.flags);
        self.recordAuditLiteral("create", path, result, context);
        return result;
    }

    pub fn createDirectory(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const result = createDirectoryNotSupported(path, mode, context);
        self.recordAuditLiteral("mkdir", path, result, context);
        return result;
    }

    pub fn writeFile(
        self: *Model,
        path: []const u8,
        offset: u64,
        bytes: []const u8,
        context: AccessContext,
    ) i32 {
        const result = self.writeFileInternal(path, offset, bytes, context, null);
        self.recordAuditLiteral("write", path, result, context);
        return result;
    }

    pub fn writeFileWithRequest(
        self: *Model,
        path: []const u8,
        offset: u64,
        bytes: []const u8,
        context: AccessContext,
        file_request: FileRequestInfo,
    ) i32 {
        const result = self.writeFileInternal(path, offset, bytes, context, file_request);
        self.recordAuditLiteral("write", path, result, context);
        return result;
    }

    pub fn truncateFile(
        self: *Model,
        path: []const u8,
        size: u64,
        context: AccessContext,
    ) i32 {
        const result = self.truncateFileInternal(path, size, context);
        self.recordAuditLiteral("truncate", path, result, context);
        return result;
    }

    pub fn chmodFile(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const result = self.chmodFileInternal(path, mode, context);
        self.recordAuditLiteral("chmod", path, result, context);
        return result;
    }

    pub fn chownFile(
        self: *Model,
        path: []const u8,
        uid: u32,
        gid: u32,
        context: AccessContext,
    ) i32 {
        const result = self.chownFileInternal(path, uid, gid, context);
        self.recordAuditLiteral("chown", path, result, context);
        return result;
    }

    pub fn flushPath(
        self: *Model,
        path: []const u8,
        context: AccessContext,
        file_info: ?AuditFileInfo,
    ) i32 {
        const result = self.syncPathInternal(path);
        self.recordAudit("flush", path, result, .{
            .context = context,
            .file_info = file_info,
        }) catch {};
        return result;
    }

    pub fn fsyncPath(
        self: *Model,
        path: []const u8,
        datasync: bool,
        context: AccessContext,
        file_info: ?AuditFileInfo,
    ) i32 {
        const result = self.syncPathInternal(path);
        self.recordAudit("fsync", path, result, .{
            .context = context,
            .file_info = file_info,
            .fsync = .{ .datasync = datasync },
        }) catch {};
        return result;
    }

    pub fn setXattr(
        self: *Model,
        path: []const u8,
        name: []const u8,
        value: []const u8,
        flags: i32,
        position: u32,
        context: AccessContext,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, errnoCode(.OPNOTSUPP))) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const name_z = self.allocator.dupeZ(u8, name) catch return errnoCode(.NOMEM);
        defer self.allocator.free(name_z);

        const result = if (builtin.os.tag == .macos)
            (if (c.setxattr(host_path.ptr, name_z.ptr, value.ptr, value.len, position, flags) == 0)
                0
            else
                errnoCode(std.posix.errno(-1)))
        else
            (if (c.setxattr(host_path.ptr, name_z.ptr, value.ptr, value.len, flags) == 0)
                0
            else
                errnoCode(std.posix.errno(-1)));
        if (result == 0) {
            if (self.findFile(path)) |file| {
                touchFileChange(file);
            }
        }
        self.recordAudit("setxattr", path, result, .{
            .context = context,
            .xattr = .{
                .name = name,
                .size = value.len,
                .flags = flags,
                .position = position,
            },
        }) catch {};
        return result;
    }

    pub fn getXattr(
        self: *Model,
        path: []const u8,
        name: []const u8,
        value: []u8,
        position: u32,
        context: AccessContext,
    ) i32 {
        _ = context;
        const missing_xattr = if (builtin.os.tag == .macos) std.posix.E.NOATTR else std.posix.E.NODATA;
        const host_path = switch (self.hostXattrPathAllocZ(path, errnoCode(missing_xattr))) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const name_z = self.allocator.dupeZ(u8, name) catch return errnoCode(.NOMEM);
        defer self.allocator.free(name_z);

        const result = if (builtin.os.tag == .macos)
            c.getxattr(host_path.ptr, name_z.ptr, if (value.len == 0) null else value.ptr, value.len, position, 0)
        else
            c.getxattr(host_path.ptr, name_z.ptr, if (value.len == 0) null else value.ptr, value.len);
        if (result < 0) {
            return errnoCode(std.posix.errno(-1));
        }
        if (self.findFile(path)) |file| {
            touchFileAtime(file);
        }

        return @intCast(result);
    }

    pub fn listXattr(
        self: *Model,
        path: []const u8,
        list: []u8,
        context: AccessContext,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, 0)) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const result = if (builtin.os.tag == .macos)
            c.listxattr(host_path.ptr, if (list.len == 0) null else list.ptr, list.len, 0)
        else
            c.listxattr(host_path.ptr, if (list.len == 0) null else list.ptr, list.len);
        if (result < 0) {
            return errnoCode(std.posix.errno(-1));
        }
        if (self.findFile(path)) |file| {
            touchFileAtime(file);
        }

        self.recordAudit("listxattr", path, @intCast(result), .{
            .context = context,
            .xattr = .{ .size = list.len },
        }) catch {};
        return @intCast(result);
    }

    pub fn removeXattr(
        self: *Model,
        path: []const u8,
        name: []const u8,
        context: AccessContext,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, errnoCode(.OPNOTSUPP))) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const name_z = self.allocator.dupeZ(u8, name) catch return errnoCode(.NOMEM);
        defer self.allocator.free(name_z);

        const result = if (builtin.os.tag == .macos)
            (if (c.removexattr(host_path.ptr, name_z.ptr, 0) == 0)
                0
            else
                errnoCode(std.posix.errno(-1)))
        else
            (if (c.removexattr(host_path.ptr, name_z.ptr) == 0)
                0
            else
                errnoCode(std.posix.errno(-1)));
        if (result == 0) {
            if (self.findFile(path)) |file| {
                touchFileChange(file);
            }
        }
        self.recordAudit("removexattr", path, result, .{
            .context = context,
            .xattr = .{ .name = name },
        }) catch {};
        return result;
    }

    pub fn recordOpen(
        self: *Model,
        path: []const u8,
        context: AccessContext,
        file_request: FileRequestInfo,
        result: i32,
        file_info: ?AuditFileInfo,
    ) void {
        if (result == 0) {
            if (file_request.handle_id) |handle_id| {
                const base_grant = grantForOpenFlags(file_request.flags);
                const grant: HandleGrant = .{
                    .can_read = base_grant.can_read,
                    .can_write = base_grant.can_write,
                    .pid = context.pid,
                    .path = self.allocator.dupe(u8, path) catch {
                        self.recordAudit("open", path, result, .{
                            .context = context,
                            .file_info = file_info,
                        }) catch {};
                        return;
                    },
                };
                self.handle_grants.put(self.allocator, handle_id, grant) catch {
                    self.allocator.free(grant.path);
                    self.recordAudit("open", path, result, .{
                        .context = context,
                        .file_info = file_info,
                    }) catch {};
                    return;
                };
            }
        }
        self.recordAudit("open", path, result, .{
            .context = context,
            .file_info = file_info,
        }) catch {};
    }

    pub fn recordRelease(
        self: *Model,
        path: []const u8,
        context: AccessContext,
        file_request: FileRequestInfo,
        result: i32,
        file_info: ?AuditFileInfo,
    ) void {
        if (file_request.handle_id) |handle_id| {
            if (self.handle_grants.fetchRemove(handle_id)) |entry| {
                var grant = entry.value;
                grant.deinit(self.allocator);
            }
        }
        self.recordAudit("release", path, result, .{
            .context = context,
            .file_info = file_info,
        }) catch {};
    }

    pub fn removeFile(
        self: *Model,
        path: []const u8,
        context: AccessContext,
    ) i32 {
        const result = self.removeFileInternal(path, context);
        self.recordAuditLiteral("unlink", path, result, context);
        return result;
    }

    pub fn removeDirectory(
        self: *Model,
        path: []const u8,
        context: AccessContext,
    ) i32 {
        const result = removeDirectoryNotSupported(path, context);
        self.recordAuditLiteral("rmdir", path, result, context);
        return result;
    }

    pub fn renameFile(
        self: *Model,
        from: []const u8,
        to: []const u8,
        context: AccessContext,
    ) i32 {
        const result = self.renameFileInternal(from, to, context);
        self.recordRenameAudit(from, to, result, context);
        return result;
    }

    pub fn auditCount(self: *const Model) u32 {
        return @intCast(self.audit_events.items.len);
    }

    pub fn auditEvent(self: *const Model, index: u32) ?AuditEvent {
        const usize_index: usize = @intCast(index);
        if (usize_index >= self.audit_events.items.len) {
            return null;
        }

        const stored = self.audit_events.items[usize_index];
        return .{
            .action = stored.action,
            .path = stored.path,
            .result = stored.result,
            .timestamp = stored.timestamp,
            .pid = stored.pid,
            .uid = stored.uid,
            .gid = stored.gid,
            .executable_path = stored.executable_path,
            .file_info = stored.file_info,
            .lock = stored.lock,
            .flock = stored.flock,
            .xattr = if (stored.xattr) |xattr| .{
                .name = xattr.name,
                .size = xattr.size,
                .flags = xattr.flags,
                .position = xattr.position,
            } else null,
            .rename = if (stored.rename) |rename| .{
                .from = rename.from,
                .to = rename.to,
            } else null,
            .fsync = stored.fsync,
        };
    }

    pub fn recordPlatformAudit(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        metadata: AuditMetadata,
    ) void {
        self.recordAudit(action, path, result, metadata) catch {};
    }

    fn createFileInternal(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
        open_flags: ?i32,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.createPassthroughFile(path, mode, open_flags);
        }

        if (!isUserFilePath(path)) {
            return errnoCode(.INVAL);
        }

        if (self.findFile(path) != null) {
            return errnoCode(.EXIST);
        }

        const auth_result = if (open_flags) |flags| blk: {
            const label = formatOpenPromptLabel(self.allocator, "create", path, flags) catch {
                break :blk errnoCode(.NOMEM);
            };
            defer self.allocator.free(label);
            break :blk self.authorizeAccessDetailed(path, .create, context, label);
        } else self.authorizeAccess(path, .create, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const file = self.appendFile(path, mode, currentUid(), currentGid()) catch |err| {
            return mapFsError(err);
        };
        errdefer self.removeFileAtIndex(self.files.items.len - 1);

        if (shouldPersistPath(path)) {
            const persist_result = self.syncFileToBackingStore(file);
            if (persist_result != 0) {
                self.removeFileAtIndex(self.files.items.len - 1);
                return persist_result;
            }
        }

        self.touchStatus();
        return 0;
    }

    fn writeFileInternal(
        self: *Model,
        path: []const u8,
        offset: u64,
        bytes: []const u8,
        context: AccessContext,
        file_request: ?FileRequestInfo,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.writePassthroughFile(path, offset, bytes, file_request);
        }

        const auth_result = if (file_request) |request|
            authorizeWriteFromOpenFlags(request.flags)
        else
            self.authorizeAccess(path, .write, context);
        if (auth_result != 0) {
            return auth_result;
        }

        if (offset > std.math.maxInt(usize)) {
            return errnoCode(.INVAL);
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = self.snapshotFileContent(file) catch |err| return mapFsError(err);
        defer self.allocator.free(snapshot);

        writeIntoArrayList(self.allocator, &file.content, @intCast(offset), bytes) catch |err| {
            return mapFsError(err);
        };
        touchFileContent(file);

        return self.finishContentMutation(path, file, snapshot, @intCast(bytes.len));
    }

    fn truncateFileInternal(
        self: *Model,
        path: []const u8,
        size: u64,
        context: AccessContext,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.truncatePassthroughFile(path, size);
        }

        const auth_result = if (hasActiveWriteGrant(self, path, context.pid))
            0
        else
            self.authorizeAccess(path, .write, context);
        if (auth_result != 0) {
            return auth_result;
        }

        if (size > std.math.maxInt(usize)) {
            return errnoCode(.INVAL);
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = self.snapshotFileContent(file) catch |err| return mapFsError(err);
        defer self.allocator.free(snapshot);

        resizeArrayList(self.allocator, &file.content, @intCast(size)) catch |err| {
            return mapFsError(err);
        };
        touchFileContent(file);

        return self.finishContentMutation(path, file, snapshot, 0);
    }

    fn truncateOpenedFile(self: *Model, path: []const u8) i32 {
        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = self.snapshotFileContent(file) catch |err| return mapFsError(err);
        defer self.allocator.free(snapshot);

        resizeArrayList(self.allocator, &file.content, 0) catch |err| {
            return mapFsError(err);
        };
        touchFileContent(file);

        return self.finishContentMutation(path, file, snapshot, 0);
    }

    fn truncateOpenedPassthroughFile(self: *Model, path: []const u8) i32 {
        return self.truncatePassthroughFile(path, 0);
    }

    fn chmodFileInternal(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.chmodPassthroughFile(path, mode);
        }

        const auth_result = self.authorizeAccess(path, .metadata, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = snapshotFileMetadata(file);
        file.mode = mode & 0o777;
        touchFileChange(file);

        return self.finishMetadataMutation(path, file, snapshot, applyModeToHost);
    }

    fn chownFileInternal(
        self: *Model,
        path: []const u8,
        uid: u32,
        gid: u32,
        context: AccessContext,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.chownPassthroughFile(path, uid, gid);
        }

        const auth_result = self.authorizeAccess(path, .metadata, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = snapshotFileMetadata(file);
        file.uid = uid;
        file.gid = gid;
        touchFileChange(file);

        return self.finishMetadataMutation(path, file, snapshot, applyOwnershipToHost);
    }

    fn syncPathInternal(self: *Model, path: []const u8) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.syncPassthroughPath(path);
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        if (!shouldPersistPath(path)) {
            return 0;
        }

        return self.syncFileToBackingStore(file);
    }

    fn removeFileInternal(
        self: *Model,
        path: []const u8,
        context: AccessContext,
    ) i32 {
        if (self.layout == .enrolled_parent and !self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.removePassthroughFile(path);
        }

        const auth_result = self.authorizeAccess(path, .delete, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const index = self.findFileIndex(path) orelse return errnoCode(.NOENT);
        if (shouldPersistPath(path)) {
            const host_path = self.hostPathAlloc(path) catch |err| return mapFsError(err);
            defer self.allocator.free(host_path);
            std.fs.deleteFileAbsolute(host_path) catch |err| return mapFsError(err);
        }

        self.removeFileAtIndex(index);
        self.touchStatus();
        return 0;
    }

    fn renameFileInternal(
        self: *Model,
        from: []const u8,
        to: []const u8,
        context: AccessContext,
    ) i32 {
        if (self.layout == .enrolled_parent and !isTransientVirtualPath(from) and !isTransientVirtualPath(to)) {
            return self.renameEnrolledParentPath(from, to, context);
        }

        if (!isUserFilePath(from) or !isUserFilePath(to)) {
            return errnoCode(.INVAL);
        }

        if (std.mem.eql(u8, from, to)) {
            return 0;
        }

        const source_auth = self.authorizeAccess(from, .rename, context);
        if (source_auth != 0) {
            return source_auth;
        }

        const target_auth = self.authorizeAccess(to, .rename, context);
        if (target_auth != 0) {
            return target_auth;
        }

        const source_index = self.findFileIndex(from) orelse return errnoCode(.NOENT);
        const target_index = self.findFileIndex(to);
        const source_persistent = shouldPersistPath(from);
        const target_persistent = shouldPersistPath(to);

        const persist_result = self.applyRenameBackingStoreTransition(from, to, source_persistent, target_persistent);
        if (persist_result != 0) {
            return persist_result;
        }

        const rename_mutation = self.renameStoredFile(source_index, target_index, to) catch |err| {
            return mapFsError(err);
        };
        var rename_committed = false;
        defer if (!rename_committed) self.rollbackRenameMutation(rename_mutation);

        if (!source_persistent and target_persistent) {
            const file = &self.files.items[rename_mutation.source_index];
            const sync_result = self.syncFileToBackingStore(file);
            if (sync_result != 0) {
                return sync_result;
            }
        }

        self.commitRenameMutation(rename_mutation);
        rename_committed = true;
        if (self.findFile(to)) |file| {
            touchFileChange(file);
        }
        self.touchStatus();
        return 0;
    }

    fn renameEnrolledParentPath(
        self: *Model,
        from: []const u8,
        to: []const u8,
        context: AccessContext,
    ) i32 {
        const from_guarded = self.isGuardedPath(from);
        const to_guarded = self.isGuardedPath(to);

        if (!from_guarded and !to_guarded) {
            return self.renamePassthroughPath(from, to);
        }

        if (from_guarded and to_guarded) {
            return if (std.mem.eql(u8, from, to)) 0 else errnoCode(.INVAL);
        }

        if (to_guarded) {
            const auth_result = self.authorizeAccess(to, .rename, context);
            if (auth_result != 0) {
                return auth_result;
            }
            return self.replaceGuardedFileFromPassthrough(from);
        }

        const auth_result = self.authorizeAccess(from, .rename, context);
        if (auth_result != 0) {
            return auth_result;
        }
        return self.moveGuardedFileToPassthrough(to);
    }

    fn readPassthroughInto(
        self: *Model,
        path: []const u8,
        offset: u64,
        buffer: []u8,
    ) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        var file = dir.openFile(relative_path, .{ .mode = .read_only }) catch |err| return mapFsError(err);
        defer file.close();

        file.seekTo(offset) catch |err| return mapFsError(err);
        const read_count = file.read(buffer) catch |err| return mapFsError(err);
        return @intCast(read_count);
    }

    fn createPassthroughFile(self: *Model, path: []const u8, mode: u32, open_flags: ?i32) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const flags = open_flags orelse (c.O_CREAT | c.O_EXCL | c.O_WRONLY);
        const truncate = (flags & c.O_TRUNC) != 0;

        var file = dir.createFile(relative_path, .{
            .read = (flags & c.O_ACCMODE) != c.O_WRONLY,
            .truncate = truncate,
            .exclusive = (flags & c.O_EXCL) != 0,
        }) catch |err| return mapFsError(err);
        defer file.close();

        file.chmod(@intCast(mode & 0o777)) catch |err| return mapFsError(err);
        return 0;
    }

    fn writePassthroughFile(
        self: *Model,
        path: []const u8,
        offset: u64,
        bytes: []const u8,
        file_request: ?FileRequestInfo,
    ) i32 {
        if (file_request) |request| {
            const auth_result = authorizeWriteFromOpenFlags(request.flags);
            if (auth_result != 0) {
                return auth_result;
            }
        }

        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        var file = dir.openFile(relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close();

        file.seekTo(offset) catch |err| return mapFsError(err);
        file.writeAll(bytes) catch |err| return mapFsError(err);
        return @intCast(bytes.len);
    }

    fn truncatePassthroughFile(self: *Model, path: []const u8, size: u64) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        var file = dir.openFile(relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close();
        file.setEndPos(size) catch |err| return mapFsError(err);
        return 0;
    }

    fn chmodPassthroughFile(self: *Model, path: []const u8, mode: u32) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        var file = dir.openFile(relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close();
        file.chmod(@intCast(mode & 0o777)) catch |err| return mapFsError(err);
        return 0;
    }

    fn chownPassthroughFile(self: *Model, path: []const u8, uid: u32, gid: u32) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        var file = dir.openFile(relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close();
        file.chown(uid, gid) catch |err| return mapFsError(err);
        return 0;
    }

    fn syncPassthroughPath(self: *Model, path: []const u8) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        var file = dir.openFile(relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close();
        file.sync() catch |err| return mapFsError(err);
        return 0;
    }

    fn removePassthroughFile(self: *Model, path: []const u8) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        dir.deleteFile(relative_path) catch |err| return mapFsError(err);
        return 0;
    }

    fn renamePassthroughPath(self: *Model, from: []const u8, to: []const u8) i32 {
        const from_relative = relativeMountedPath(from) orelse return errnoCode(.INVAL);
        const to_relative = relativeMountedPath(to) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        dir.rename(from_relative, to_relative) catch |err| return mapFsError(err);
        return 0;
    }

    fn replaceGuardedFileFromPassthrough(self: *Model, from: []const u8) i32 {
        const from_relative = relativeMountedPath(from) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = self.findGuardedFile() orelse return errnoCode(.NOENT);
        var source_file = dir.openFile(from_relative, .{ .mode = .read_only }) catch |err| return mapFsError(err);
        defer source_file.close();

        const contents = source_file.readToEndAlloc(self.allocator, 1024 * 1024) catch |err| return mapFsError(err);
        defer self.allocator.free(contents);
        const source_stat = source_file.stat() catch |err| return mapFsError(err);
        const posix_stat = std.posix.fstat(source_file.handle) catch |err| return mapFsError(err);

        file.content.clearRetainingCapacity();
        file.content.appendSlice(self.allocator, contents) catch return errnoCode(.NOMEM);
        file.mode = @intCast(source_stat.mode & 0o777);
        file.uid = @intCast(posix_stat.uid);
        file.gid = @intCast(posix_stat.gid);
        touchFileContent(file);

        const sync_result = self.syncFileToBackingStore(file);
        if (sync_result != 0) {
            return sync_result;
        }

        dir.deleteFile(from_relative) catch |err| return mapFsError(err);
        self.touchStatus();
        return 0;
    }

    fn moveGuardedFileToPassthrough(self: *Model, to: []const u8) i32 {
        const to_relative = relativeMountedPath(to) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = self.findGuardedFile() orelse return errnoCode(.NOENT);
        var target_file = dir.createFile(to_relative, .{ .read = true, .truncate = true }) catch |err| return mapFsError(err);
        defer target_file.close();

        if (file.content.items.len != 0) {
            target_file.writeAll(file.content.items) catch |err| return mapFsError(err);
        }
        target_file.chmod(@intCast(file.mode)) catch |err| return mapFsError(err);
        target_file.chown(file.uid, file.gid) catch |err| return mapFsError(err);
        target_file.sync() catch |err| return mapFsError(err);

        const remove_result = self.removeGuardedBackingFile();
        if (remove_result != 0) {
            return remove_result;
        }

        self.removeFileAtIndex(0);
        self.touchStatus();
        return 0;
    }

    fn snapshotFileContent(self: *Model, file: *const StoredFile) ![]u8 {
        return self.allocator.dupe(u8, file.content.items);
    }

    fn snapshotFileMetadata(file: *const StoredFile) MetadataSnapshot {
        return .{
            .mode = file.mode,
            .uid = file.uid,
            .gid = file.gid,
        };
    }

    fn finishContentMutation(
        self: *Model,
        path: []const u8,
        file: *StoredFile,
        snapshot: []const u8,
        success_result: i32,
    ) i32 {
        if (!shouldPersistPath(path)) {
            return success_result;
        }

        const persist_result = self.syncFileToBackingStore(file);
        if (persist_result != 0) {
            self.restoreFileContent(file, snapshot);
            return persist_result;
        }

        return success_result;
    }

    fn restoreFileContent(self: *Model, file: *StoredFile, snapshot: []const u8) void {
        file.content.clearRetainingCapacity();
        file.content.appendSlice(self.allocator, snapshot) catch unreachable;
    }

    fn finishMetadataMutation(
        self: *Model,
        path: []const u8,
        file: *StoredFile,
        snapshot: MetadataSnapshot,
        apply_to_host: *const fn (*std.fs.File, *const StoredFile) anyerror!void,
    ) i32 {
        if (!shouldPersistPath(path)) {
            return 0;
        }

        const host_path = self.hostPathAlloc(path) catch |err| {
            restoreFileMetadata(file, snapshot);
            return mapFsError(err);
        };
        defer self.allocator.free(host_path);

        var host_file = std.fs.openFileAbsolute(host_path, .{ .mode = .read_write }) catch |err| {
            restoreFileMetadata(file, snapshot);
            return mapFsError(err);
        };
        defer host_file.close();

        apply_to_host(&host_file, file) catch |err| {
            restoreFileMetadata(file, snapshot);
            return mapFsError(err);
        };

        return 0;
    }

    fn restoreFileMetadata(file: *StoredFile, snapshot: MetadataSnapshot) void {
        file.mode = snapshot.mode;
        file.uid = snapshot.uid;
        file.gid = snapshot.gid;
    }

    fn applyRenameBackingStoreTransition(
        self: *Model,
        from: []const u8,
        to: []const u8,
        source_persistent: bool,
        target_persistent: bool,
    ) i32 {
        if (source_persistent and target_persistent) {
            const from_host_path = self.hostPathAlloc(from) catch |err| return mapFsError(err);
            defer self.allocator.free(from_host_path);
            const to_host_path = self.hostPathAlloc(to) catch |err| return mapFsError(err);
            defer self.allocator.free(to_host_path);

            std.fs.renameAbsolute(from_host_path, to_host_path) catch |err| return mapFsError(err);
            return 0;
        }

        if (source_persistent and !target_persistent) {
            const from_host_path = self.hostPathAlloc(from) catch |err| return mapFsError(err);
            defer self.allocator.free(from_host_path);

            std.fs.deleteFileAbsolute(from_host_path) catch |err| return mapFsError(err);
        }

        return 0;
    }

    fn renameStoredFile(
        self: *Model,
        source_index: usize,
        target_index: ?usize,
        to: []const u8,
    ) !RenameMutation {
        const new_name = try self.allocator.dupeZ(u8, to[1..]);
        errdefer self.allocator.free(new_name);
        const new_path = try self.allocator.dupeZ(u8, to);
        errdefer self.allocator.free(new_path);

        var adjusted_source_index = source_index;
        var replaced_target: ?StoredFile = null;
        if (target_index) |index| {
            replaced_target = self.takeFileAtIndex(index);
            if (index < adjusted_source_index) {
                adjusted_source_index -= 1;
            }
        }

        const file = &self.files.items[adjusted_source_index];
        const mutation: RenameMutation = .{
            .source_index = adjusted_source_index,
            .original_name = file.name,
            .original_path = file.path,
            .replaced_target_index = target_index,
            .replaced_target = replaced_target,
        };
        file.name = new_name;
        file.path = new_path;
        return mutation;
    }

    fn rollbackRenameMutation(self: *Model, mutation: RenameMutation) void {
        const file = &self.files.items[mutation.source_index];
        self.allocator.free(file.name);
        self.allocator.free(file.path);
        file.name = mutation.original_name;
        file.path = mutation.original_path;

        if (mutation.replaced_target_index) |index| {
            self.files.insert(self.allocator, index, mutation.replaced_target.?) catch unreachable;
        }
    }

    fn commitRenameMutation(self: *Model, mutation: RenameMutation) void {
        self.allocator.free(mutation.original_name);
        self.allocator.free(mutation.original_path);
        if (mutation.replaced_target) |file| {
            var removed = file;
            removed.deinit(self.allocator);
        }
    }

    fn applyModeToHost(host_file: *std.fs.File, file: *const StoredFile) !void {
        try host_file.chmod(@intCast(file.mode));
    }

    fn applyOwnershipToHost(host_file: *std.fs.File, file: *const StoredFile) !void {
        try host_file.chown(file.uid, file.gid);
    }

    fn appendFile(
        self: *Model,
        path: []const u8,
        mode: u32,
        uid: u32,
        gid: u32,
    ) !*StoredFile {
        const now = currentTimestamp();
        const name = try self.allocator.dupeZ(u8, path[1..]);
        errdefer self.allocator.free(name);
        const owned_path = try self.allocator.dupeZ(u8, path);
        errdefer self.allocator.free(owned_path);

        try self.files.append(self.allocator, .{
            .name = name,
            .path = owned_path,
            .mode = mode & 0o777,
            .uid = uid,
            .gid = gid,
            .inode = self.next_inode,
            .atime = now,
            .mtime = now,
            .ctime = now,
        });
        self.next_inode += 1;
        return &self.files.items[self.files.items.len - 1];
    }

    fn removeFileAtIndex(self: *Model, index: usize) void {
        self.files.items[index].deinit(self.allocator);
        if (index + 1 < self.files.items.len) {
            std.mem.copyBackwards(StoredFile, self.files.items[index .. self.files.items.len - 1], self.files.items[index + 1 ..]);
        }
        self.files.items.len -= 1;
    }

    fn takeFileAtIndex(self: *Model, index: usize) StoredFile {
        const removed = self.files.items[index];
        if (index + 1 < self.files.items.len) {
            std.mem.copyBackwards(StoredFile, self.files.items[index .. self.files.items.len - 1], self.files.items[index + 1 ..]);
        }
        self.files.items.len -= 1;
        return removed;
    }

    fn findFile(self: *const Model, path: []const u8) ?*StoredFile {
        const index = self.findFileIndex(path) orelse return null;
        return @constCast(&self.files.items[index]);
    }

    fn findGuardedFile(self: *const Model) ?*StoredFile {
        const guarded_path = self.guarded_virtual_path orelse return null;
        return self.findFile(guarded_path);
    }

    fn findFileIndex(self: *const Model, path: []const u8) ?usize {
        for (self.files.items, 0..) |file, index| {
            if (std.mem.eql(u8, file.path, path)) {
                return index;
            }
        }
        return null;
    }

    fn syncFileToBackingStore(self: *Model, file: *const StoredFile) i32 {
        const host_path = self.hostPathAlloc(file.path) catch |err| return mapFsError(err);
        defer self.allocator.free(host_path);

        var host_file = std.fs.createFileAbsolute(host_path, .{
            .truncate = true,
            .read = true,
        }) catch |err| return mapFsError(err);
        defer host_file.close();

        if (file.content.items.len != 0) {
            host_file.writeAll(file.content.items) catch |err| return mapFsError(err);
        }

        host_file.chmod(@intCast(file.mode)) catch |err| return mapFsError(err);
        host_file.chown(file.uid, file.gid) catch |err| return mapFsError(err);
        host_file.sync() catch |err| return mapFsError(err);
        return 0;
    }

    fn removeGuardedBackingFile(self: *Model) i32 {
        std.fs.deleteFileAbsolute(self.backing_store_path) catch |err| return mapFsError(err);
        return 0;
    }

    fn isGuardedPath(self: *const Model, path: []const u8) bool {
        if (self.layout != .enrolled_parent) {
            return true;
        }
        const guarded_path = self.guarded_virtual_path orelse return false;
        return std.mem.eql(u8, path, guarded_path);
    }

    fn hostXattrPathAllocZ(
        self: *const Model,
        path: []const u8,
        missing_result: i32,
    ) union(enum) {
        ok: [:0]u8,
        err: i32,
    } {
        const lookup = self.lookupPath(path);
        if (lookup.open_kind != .user_file or !lookup.persistent) {
            return .{ .err = missing_result };
        }

        if (self.findFile(path) == null) {
            return .{ .err = errnoCode(.NOENT) };
        }

        const host_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.backing_store_path, path[1..] }) catch {
            return .{ .err = errnoCode(.NOMEM) };
        };
        defer self.allocator.free(host_path);

        const host_path_z = self.allocator.dupeZ(u8, host_path) catch {
            return .{ .err = errnoCode(.NOMEM) };
        };
        return .{ .ok = host_path_z };
    }

    fn hostPathAlloc(self: *const Model, path: []const u8) ![]u8 {
        return switch (self.layout) {
            .guarded_root => blk: {
                if (!isUserFilePath(path)) {
                    break :blk error.InvalidPath;
                }

                break :blk std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.backing_store_path, path[1..] });
            },
            .enrolled_parent => blk: {
                if (!self.isGuardedPath(path)) {
                    break :blk error.InvalidPath;
                }

                break :blk self.allocator.dupe(u8, self.backing_store_path);
            },
        };
    }

    fn createDirectoryNotSupported(path: []const u8, mode: u32, context: AccessContext) i32 {
        _ = path;
        _ = mode;
        _ = context;
        return errnoCode(.OPNOTSUPP);
    }

    fn removeDirectoryNotSupported(path: []const u8, context: AccessContext) i32 {
        _ = path;
        _ = context;
        return errnoCode(.OPNOTSUPP);
    }

    fn recordPolicyAudit(
        self: *Model,
        access_class: policy.AccessClass,
        path: []const u8,
        outcome: policy.Outcome,
        context: AccessContext,
        label: ?[]const u8,
    ) void {
        const audit_event_path = label orelse blk: {
            break :blk std.fmt.allocPrint(
                self.allocator,
                "{s} {s}",
                .{ accessClassLabel(access_class), path },
            ) catch return;
        };
        defer if (label == null) self.allocator.free(audit_event_path);
        self.recordAudit("policy", audit_event_path, @intCast(@intFromEnum(outcome)), .{
            .context = context,
        }) catch {};
    }

    fn resolvePromptDecision(self: *Model, request: policy.Request, context: AccessContext, label: ?[]const u8) i32 {
        const audit_event_path = label orelse blk: {
            break :blk std.fmt.allocPrint(
                self.allocator,
                "{s} {s}",
                .{ accessClassLabel(request.access_class), request.path },
            ) catch return errnoCode(.NOMEM);
        };
        defer if (label == null) self.allocator.free(audit_event_path);

        const decision = if (self.prompt_broker) |broker|
            broker.resolve(.{
                .path = request.path,
                .access_class = request.access_class,
                .label = label,
                .pid = request.pid,
                .uid = request.uid,
                .gid = request.gid,
                .executable_path = context.executable_path,
            })
        else
            prompt.Decision.unavailable;

        self.recordAudit("prompt", audit_event_path, @intFromEnum(decision), .{
            .context = context,
        }) catch {};
        return switch (decision) {
            .allow => 0,
            .deny, .timeout, .unavailable => errnoCode(.ACCES),
        };
    }

    fn recordRenameAudit(self: *Model, from: []const u8, to: []const u8, result: i32, context: AccessContext) void {
        self.recordAudit("rename", from, result, .{
            .context = context,
            .rename = .{
                .from = from,
                .to = to,
            },
        }) catch {};
    }

    fn recordAuditLiteral(self: *Model, action: []const u8, path: []const u8, result: i32, context: AccessContext) void {
        self.recordAudit(action, path, result, .{ .context = context }) catch {};
    }

    fn recordAudit(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        metadata: AuditMetadata,
    ) !void {
        const timestamp = currentTimestamp();
        try self.audit_events.append(self.allocator, .{
            .action = try self.allocator.dupe(u8, action),
            .path = try self.allocator.dupe(u8, path),
            .result = result,
            .timestamp = timestamp,
            .pid = metadata.context.pid,
            .uid = metadata.context.uid,
            .gid = metadata.context.gid,
            .executable_path = if (metadata.context.executable_path) |value| try self.allocator.dupe(u8, value) else null,
            .file_info = metadata.file_info,
            .lock = metadata.lock,
            .flock = metadata.flock,
            .xattr = if (metadata.xattr) |xattr| .{
                .name = if (xattr.name) |name| try self.allocator.dupe(u8, name) else null,
                .size = xattr.size,
                .flags = xattr.flags,
                .position = xattr.position,
            } else null,
            .rename = if (metadata.rename) |rename| .{
                .from = try self.allocator.dupe(u8, rename.from),
                .to = try self.allocator.dupe(u8, rename.to),
            } else null,
            .fsync = metadata.fsync,
        });
        self.emitAuditLine(action, path, result, timestamp, metadata);
    }

    fn touchStatus(self: *Model) void {
        self.emitStatusSnapshot();
    }

    fn emitStatusSnapshot(self: *Model) void {
        const output_file = self.status_output_file orelse return;

        var line: std.io.Writer.Allocating = .init(self.allocator);
        defer line.deinit();

        std.json.Stringify.value(.{
            .action = "status",
            .backend = "libfuse",
            .mount_path = self.mount_path,
            .backing_store = self.backing_store_path,
            .configured_ops = self.runtime_stats.configured_operation_count,
            .planned_args = self.runtime_stats.planned_argument_count,
            .backing_files = self.files.items.len,
        }, .{}, &line.writer) catch return;
        line.writer.writeByte('\n') catch return;

        self.output_mutex.lock();
        defer self.output_mutex.unlock();
        output_file.writeAll(line.written()) catch {};
    }

    fn emitAuditLine(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        timestamp: Timestamp,
        metadata: AuditMetadata,
    ) void {
        const output_file = self.audit_output_file orelse return;

        var line: std.io.Writer.Allocating = .init(self.allocator);
        defer line.deinit();

        std.json.Stringify.value(.{
            .action = action,
            .path = path,
            .result = result,
            .timestamp = timestamp,
            .pid = metadata.context.pid,
            .uid = metadata.context.uid,
            .gid = metadata.context.gid,
            .executable_path = metadata.context.executable_path,
            .file_info = metadata.file_info,
            .lock = metadata.lock,
            .flock = metadata.flock,
            .xattr = metadata.xattr,
            .rename = metadata.rename,
            .fsync = metadata.fsync,
        }, .{}, &line.writer) catch return;
        line.writer.writeByte('\n') catch return;

        self.output_mutex.lock();
        defer self.output_mutex.unlock();
        output_file.writeAll(line.written()) catch {};
    }
};

fn ensureBackingStoreDirectory(path: []const u8) !void {
    std.fs.makeDirAbsolute(path) catch |err| switch (err) {
        error.PathAlreadyExists => {
            var dir = try std.fs.openDirAbsolute(path, .{});
            dir.close();
        },
        else => return err,
    };
}

fn writeIntoArrayList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(u8),
    offset: usize,
    bytes: []const u8,
) !void {
    const end = offset + bytes.len;
    try list.ensureTotalCapacityPrecise(allocator, end);
    if (list.items.len < end) {
        const old_len = list.items.len;
        list.items.len = end;
        @memset(list.items[old_len..end], 0);
    }
    @memcpy(list.items[offset..end], bytes);
}

fn resizeArrayList(
    allocator: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(u8),
    size: usize,
) !void {
    try list.ensureTotalCapacityPrecise(allocator, size);
    if (list.items.len < size) {
        const old_len = list.items.len;
        list.items.len = size;
        @memset(list.items[old_len..size], 0);
        return;
    }

    list.items.len = size;
}

fn copySlice(source: []const u8, buffer: []u8, offset: usize) i32 {
    if (offset >= source.len) {
        return 0;
    }

    const length = @min(source.len - offset, buffer.len);
    @memcpy(buffer[0..length], source[offset .. offset + length]);
    return @intCast(length);
}

fn currentTimestamp() Timestamp {
    const now = std.time.nanoTimestamp();
    return .{
        .sec = @intCast(@divTrunc(now, std.time.ns_per_s)),
        .nsec = @intCast(@mod(now, std.time.ns_per_s)),
    };
}

fn timestampFromStatNanos(nanos: i128) Timestamp {
    return .{
        .sec = @intCast(@divTrunc(nanos, std.time.ns_per_s)),
        .nsec = @intCast(@mod(nanos, std.time.ns_per_s)),
    };
}

fn timestampFromPosixStat(sec: i64, nsec: u64) Timestamp {
    return .{
        .sec = sec,
        .nsec = @intCast(nsec),
    };
}

fn missingLookup() Lookup {
    return .{
        .node = .{
            .kind = .missing,
            .mode = 0,
            .nlink = 0,
            .size = 0,
            .block_size = 0,
            .block_count = 0,
            .inode = 0,
            .uid = 0,
            .gid = 0,
            .atime = .{ .sec = 0, .nsec = 0 },
            .mtime = .{ .sec = 0, .nsec = 0 },
            .ctime = .{ .sec = 0, .nsec = 0 },
        },
        .open_kind = .missing,
        .persistent = false,
    };
}

fn relativeMountedPath(path: []const u8) ?[]const u8 {
    if (path.len < 2 or path[0] != '/') {
        return null;
    }
    return path[1..];
}

fn blockCountForSize(size: u64) u64 {
    if (size == 0) {
        return 0;
    }
    return (size + 511) / 512;
}

fn touchFileAtime(file: *StoredFile) void {
    file.atime = currentTimestamp();
}

fn touchFileChange(file: *StoredFile) void {
    const now = currentTimestamp();
    file.ctime = now;
}

fn touchFileContent(file: *StoredFile) void {
    const now = currentTimestamp();
    file.mtime = now;
    file.ctime = now;
}

fn currentUid() u32 {
    return @intCast(std.posix.getuid());
}

fn currentGid() u32 {
    return @intCast(c.getgid());
}

fn accessClassForOpenFlags(flags: i32) policy.AccessClass {
    return switch (flags & c.O_ACCMODE) {
        c.O_WRONLY, c.O_RDWR => .write,
        else => .read,
    };
}

fn grantForOpenFlags(flags: i32) HandleGrant {
    return switch (flags & c.O_ACCMODE) {
        c.O_WRONLY => .{ .can_read = false, .can_write = true, .pid = 0, .path = undefined },
        c.O_RDWR => .{ .can_read = true, .can_write = true, .pid = 0, .path = undefined },
        else => .{ .can_read = true, .can_write = false, .pid = 0, .path = undefined },
    };
}

fn hasActiveWriteGrant(self: *const Model, path: []const u8, pid: u32) bool {
    var iterator = self.handle_grants.valueIterator();
    while (iterator.next()) |grant| {
        if (grant.can_write and grant.pid == pid and std.mem.eql(u8, grant.path, path)) {
            return true;
        }
    }
    return false;
}

fn authorizeReadFromOpenFlags(flags: i32) i32 {
    return switch (flags & c.O_ACCMODE) {
        c.O_WRONLY => errnoCode(.BADF),
        else => 0,
    };
}

fn authorizeWriteFromOpenFlags(flags: i32) i32 {
    return switch (flags & c.O_ACCMODE) {
        c.O_RDONLY => errnoCode(.BADF),
        else => 0,
    };
}

fn formatOpenPromptLabel(
    allocator: std.mem.Allocator,
    operation: []const u8,
    path: []const u8,
    flags: i32,
) ![]u8 {
    var mode: std.ArrayList(u8) = .{};
    defer mode.deinit(allocator);

    switch (flags & c.O_ACCMODE) {
        c.O_WRONLY => try mode.appendSlice(allocator, "O_WRONLY"),
        c.O_RDWR => try mode.appendSlice(allocator, "O_RDWR"),
        else => try mode.appendSlice(allocator, "O_RDONLY"),
    }

    const flag_bits = [_]struct {
        mask: i32,
        name: []const u8,
    }{
        .{ .mask = c.O_APPEND, .name = "O_APPEND" },
        .{ .mask = c.O_CREAT, .name = "O_CREAT" },
        .{ .mask = c.O_EXCL, .name = "O_EXCL" },
        .{ .mask = c.O_TRUNC, .name = "O_TRUNC" },
    };

    for (flag_bits) |flag_bit| {
        if ((flags & flag_bit.mask) != 0) {
            try mode.appendSlice(allocator, "|");
            try mode.appendSlice(allocator, flag_bit.name);
        }
    }

    return std.fmt.allocPrint(allocator, "{s} {s} {s}", .{ operation, mode.items, path });
}

fn accessClassLabel(access_class: policy.AccessClass) []const u8 {
    return switch (access_class) {
        .read => "read",
        .create => "create",
        .write => "write",
        .rename => "rename",
        .delete => "delete",
        .metadata => "metadata",
        .xattr => "xattr",
    };
}

fn isRootPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/");
}

fn isTransientSidecarName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "._");
}

fn isTransientVirtualPath(path: []const u8) bool {
    return path.len > 3 and path[0] == '/' and isTransientSidecarName(path[1..]);
}

fn isUserFilePath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/') {
        return false;
    }

    return std.mem.indexOfScalarPos(u8, path, 1, '/') == null;
}

fn shouldPersistPath(path: []const u8) bool {
    return !(path.len >= 3 and path[0] == '/' and path[1] == '.' and path[2] == '_');
}

fn errnoCode(err: std.posix.E) i32 {
    return -@as(i32, @intFromEnum(err));
}

fn mapFsError(err: anyerror) i32 {
    return switch (err) {
        error.AccessDenied => errnoCode(.ACCES),
        error.FileNotFound => errnoCode(.NOENT),
        error.PathAlreadyExists => errnoCode(.EXIST),
        error.NameTooLong => errnoCode(.NAMETOOLONG),
        error.NotDir => errnoCode(.NOTDIR),
        error.IsDir => errnoCode(.ISDIR),
        error.FileBusy, error.Locked => errnoCode(.BUSY),
        error.ReadOnlyFileSystem => errnoCode(.ROFS),
        error.NoSpaceLeft => errnoCode(.NOSPC),
        error.DiskQuota => errnoCode(.DQUOT),
        error.OutOfMemory, error.SystemResources => errnoCode(.NOMEM),
        else => errnoCode(.IO),
    };
}
