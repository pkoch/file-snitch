const std = @import("std");
const builtin = @import("builtin");
const config = @import("config.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");
const runtime = @import("runtime.zig");
const store = @import("store.zig");
const types = @import("filesystem_types.zig");
const util = @import("filesystem_util.zig");
const c = @cImport({
    @cInclude("fcntl.h");
    @cInclude("sys/stat.h");
    @cInclude("unistd.h");
    @cInclude("sys/xattr.h");
});

const first_dynamic_inode = util.first_dynamic_inode;

pub const NodeKind = types.NodeKind;
pub const OpenKind = types.OpenKind;
pub const AccessContext = types.AccessContext;
pub const Timestamp = types.Timestamp;
pub const RuntimeStats = types.RuntimeStats;
pub const NodeInfo = types.NodeInfo;
pub const Lookup = types.Lookup;
pub const FileRequestInfo = types.FileRequestInfo;
pub const AuditFileInfo = types.AuditFileInfo;
pub const AuditLockInfo = types.AuditLockInfo;
pub const AuditFlockInfo = types.AuditFlockInfo;
pub const AuditXattrInfo = types.AuditXattrInfo;
pub const AuditRenameInfo = types.AuditRenameInfo;
pub const AuditSyncInfo = types.AuditSyncInfo;
pub const AuditMetadata = types.AuditMetadata;
pub const AuditEvent = types.AuditEvent;

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
    backing_object_id: ?[]u8 = null,
    lock_anchor_path: ?[]u8 = null,
    content: std.ArrayListUnmanaged(u8) = .empty,
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
        if (self.backing_object_id) |value| {
            allocator.free(value);
        }
        if (self.lock_anchor_path) |value| {
            allocator.free(value);
        }
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

    fn initOpen(
        allocator: std.mem.Allocator,
        path: []const u8,
        pid: u32,
        flags: i32,
    ) !HandleGrant {
        const can_read, const can_write = switch (flags & c.O_ACCMODE) {
            c.O_WRONLY => .{ false, true },
            c.O_RDWR => .{ true, true },
            else => .{ true, false },
        };
        return .{
            .can_read = can_read,
            .can_write = can_write,
            .pid = pid,
            .path = try allocator.dupe(u8, path),
        };
    }

    fn deinit(self: *HandleGrant, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        self.* = undefined;
    }
};

const HandleGrantTable = struct {
    entries: std.AutoHashMapUnmanaged(u64, HandleGrant) = .empty,

    fn grantOpen(
        self: *HandleGrantTable,
        allocator: std.mem.Allocator,
        handle_id: u64,
        grant: HandleGrant,
    ) !void {
        var owned_grant = grant;
        errdefer owned_grant.deinit(allocator);

        const entry = try self.entries.getOrPut(allocator, handle_id);
        if (entry.found_existing) {
            entry.value_ptr.deinit(allocator);
        }
        entry.value_ptr.* = owned_grant;
    }

    fn release(self: *HandleGrantTable, allocator: std.mem.Allocator, handle_id: u64) void {
        if (self.entries.fetchRemove(handle_id)) |entry| {
            var grant = entry.value;
            grant.deinit(allocator);
        }
    }

    fn hasActiveWriteGrant(self: *const HandleGrantTable, path: []const u8, pid: u32) bool {
        var iterator = self.entries.valueIterator();
        while (iterator.next()) |grant| {
            if (grant.can_write and grant.pid == pid and std.mem.eql(u8, grant.path, path)) {
                return true;
            }
        }
        return false;
    }

    fn deinit(self: *HandleGrantTable, allocator: std.mem.Allocator) void {
        var iterator = self.entries.valueIterator();
        while (iterator.next()) |grant| {
            grant.deinit(allocator);
        }
        self.entries.deinit(allocator);
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

pub const GuardedEntryConfig = types.GuardedEntryConfig;

pub const EnrolledParentConfig = struct {
    mount_path: []const u8,
    guarded_entries: []const GuardedEntryConfig,
    /// Borrowed; the caller retains ownership and is the sole `deinit` site.
    guarded_store: *store.Backend,
    default_mutation_outcome: policy.Outcome = .deny,
    policy_path: ?[]const u8 = null,
    // Borrowed views that must stay valid until Model.init deep-copies them
    // into the policy engine.
    policy_rule_views: []const policy.RuleView = &.{},
    prompt_broker: ?prompt.Broker = null,
    status_output_file: ?std.Io.File = null,
    audit_output_file: ?std.Io.File = null,
};

pub const Model = struct {
    allocator: std.mem.Allocator,
    mount_path: []u8,
    source_dir: ?std.Io.Dir = null,
    /// Borrowed when set; the owner (CLI / policy command) is responsible for `deinit`.
    guarded_store: ?*store.Backend = null,
    live_policy_path: ?[]u8 = null,
    last_policy_marker: ?config.PolicyMarker = null,
    policy_engine: policy.Engine,
    policy_mutex: std.Io.Mutex = .init,
    prompt_broker: ?prompt.Broker,
    status_output_file: ?std.Io.File,
    audit_output_file: ?std.Io.File,
    files: std.ArrayListUnmanaged(StoredFile) = .empty,
    audit_events: std.ArrayListUnmanaged(StoredAuditEvent) = .empty,
    handle_grants: HandleGrantTable = .{},
    next_inode: u64 = first_dynamic_inode,
    runtime_stats: RuntimeStats = .{},
    root_timestamp: Timestamp,
    output_mutex: std.Io.Mutex = .init,

    pub fn initEnrolledParent(allocator: std.mem.Allocator, init_config: EnrolledParentConfig) !Model {
        var source_dir = try std.Io.Dir.openDirAbsolute(runtime.io(), init_config.mount_path, .{ .iterate = true });
        errdefer source_dir.close(runtime.io());

        var model = Model{
            .allocator = allocator,
            .mount_path = try allocator.dupe(u8, init_config.mount_path),
            .source_dir = source_dir,
            .guarded_store = init_config.guarded_store,
            .live_policy_path = if (init_config.policy_path) |policy_path|
                try allocator.dupe(u8, policy_path)
            else
                null,
            .policy_engine = try policy.Engine.init(
                allocator,
                init_config.default_mutation_outcome,
                init_config.policy_rule_views,
            ),
            .prompt_broker = init_config.prompt_broker,
            .status_output_file = init_config.status_output_file,
            .audit_output_file = init_config.audit_output_file,
            .root_timestamp = currentTimestamp(),
        };
        errdefer model.deinit();

        try model.loadGuardedBackingFiles(init_config.guarded_entries);
        return model;
    }

    fn loadGuardedBackingFiles(self: *Model, guarded_entries: []const GuardedEntryConfig) !void {
        if (self.files.items.len != 0) {
            return error.FilesAlreadyLoaded;
        }

        const guarded_store = self.guarded_store orelse return error.MissingGuardedStore;
        for (guarded_entries) |entry| {
            const guarded_path = try std.fmt.allocPrint(self.allocator, "/{s}", .{entry.relative_path});
            defer self.allocator.free(guarded_path);

            var object = try guarded_store.loadObject(self.allocator, entry.object_id);
            defer object.deinit(self.allocator);
            const imported = try self.appendFile(
                guarded_path,
                object.metadata.mode,
                object.metadata.uid,
                object.metadata.gid,
                entry.object_id,
                entry.lock_anchor_path,
            );
            imported.atime = timestampFromNanos(object.metadata.atime_nsec);
            imported.mtime = timestampFromNanos(object.metadata.mtime_nsec);
            imported.ctime = currentTimestamp();

            if (object.content.len > 0) {
                try imported.content.appendSlice(self.allocator, object.content);
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
        self.handle_grants.deinit(self.allocator);

        self.policy_engine.deinit();
        // `guarded_store` is borrowed; the owning caller deinits it.
        if (self.live_policy_path) |path| {
            self.allocator.free(path);
        }
        if (self.source_dir) |*dir| {
            dir.close(runtime.io());
        }
        self.allocator.free(self.mount_path);
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

    pub fn lookupPath(self: *const Model, path: []const u8) !Lookup {
        return self.lookupEnrolledParentPath(path);
    }

    pub fn syntheticEntryCount(self: *const Model, directory_path: []const u8) !u32 {
        var count: u32 = 0;
        for (self.files.items, 0..) |file, index| {
            const child_name = (try self.syntheticChildNameForFile(directory_path, &file)) orelse continue;
            if (try self.syntheticChildAlreadySeen(directory_path, child_name, index)) continue;
            count += 1;
        }
        return count;
    }

    pub fn syntheticEntryNameAt(self: *const Model, directory_path: []const u8, index: u32, buffer: []u8) !?usize {
        var visible_index: u32 = 0;
        for (self.files.items, 0..) |file, file_index| {
            const child_name = (try self.syntheticChildNameForFile(directory_path, &file)) orelse continue;
            if (try self.syntheticChildAlreadySeen(directory_path, child_name, file_index)) continue;
            if (visible_index != index) {
                visible_index += 1;
                continue;
            }
            if (child_name.len + 1 > buffer.len) {
                return null;
            }
            @memcpy(buffer[0..child_name.len], child_name);
            buffer[child_name.len] = 0;
            return child_name.len;
        }
        return null;
    }

    pub fn forEachDirectoryEntry(
        self: *const Model,
        directory_path: []const u8,
        context: anytype,
        comptime emit: fn (@TypeOf(context), []const u8) anyerror!bool,
    ) !void {
        try self.requireDirectoryPath(directory_path);

        if (self.openSourceDirectory(directory_path)) |dir_handle| {
            var dir = dir_handle;
            defer dir.close(runtime.io());

            var iterator = dir.iterate();
            while (try iterator.next(runtime.io())) |entry| {
                if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
                if (!try emit(context, entry.name)) return;
            }
        } else |err| {
            if (err != error.FileNotFound) return err;
        }

        for (self.files.items, 0..) |file, file_index| {
            const child_name = (try self.syntheticChildNameForFile(directory_path, &file)) orelse continue;
            if (try self.syntheticChildAlreadySeen(directory_path, child_name, file_index)) continue;
            if (!try emit(context, child_name)) return;
        }
    }

    fn openSourceDirectory(self: *const Model, path: []const u8) !std.Io.Dir {
        const dir = self.source_dir orelse return error.FileNotFound;
        if (isRootPath(path)) {
            return dir.openDir(runtime.io(), ".", .{ .iterate = true });
        }
        const relative_path = relativeMountedPath(path) orelse return error.InvalidPath;
        return dir.openDir(runtime.io(), relative_path, .{ .iterate = true });
    }

    fn requireDirectoryPath(self: *const Model, path: []const u8) !void {
        return switch ((try self.lookupPath(path)).open_kind) {
            .directory => {},
            .missing => error.FileNotFound,
            else => error.NotDir,
        };
    }

    fn lookupEnrolledParentPath(self: *const Model, path: []const u8) !Lookup {
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
                .guarded = self.isGuardedPath(path),
            };
        }

        if (self.hasGuardedDescendant(path)) {
            return self.lookupGuardedDirectoryPath(path);
        }

        return self.lookupPassthroughPath(path);
    }

    fn lookupSourceDirectoryNode(self: *const Model, path: []const u8) !Lookup {
        const dir = self.source_dir orelse return error.FileNotFound;
        const stat = try dir.stat(runtime.io());
        const posix_stat = try fstatFd(dir.handle);
        _ = path;
        return .{
            .node = .{
                .kind = .directory,
                .mode = @intCast(stat.permissions.toMode() & 0o777),
                .nlink = @intCast(posix_stat.st_nlink),
                .size = 0,
                .block_size = @intCast(posix_stat.st_blksize),
                .block_count = @intCast(posix_stat.st_blocks),
                .inode = @intCast(posix_stat.st_ino),
                .uid = @intCast(posix_stat.st_uid),
                .gid = @intCast(posix_stat.st_gid),
                .atime = timestampFromStatNanos(if (stat.atime) |atime| atime.toNanoseconds() else 0),
                .mtime = timestampFromStatNanos(stat.mtime.toNanoseconds()),
                .ctime = timestampFromStatNanos(stat.ctime.toNanoseconds()),
            },
            .open_kind = .directory,
            .guarded = false,
        };
    }

    fn lookupPassthroughPath(self: *const Model, path: []const u8) !Lookup {
        const dir = self.source_dir orelse return error.FileNotFound;
        const relative_path = relativeMountedPath(path) orelse return error.InvalidPath;
        const stat = dir.statFile(runtime.io(), relative_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return missingLookup(),
            else => return err,
        };
        const posix_stat = try fstatatDir(dir, relative_path);

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
                .mode = @intCast(stat.permissions.toMode() & 0o777),
                .nlink = @intCast(posix_stat.st_nlink),
                .size = @intCast(stat.size),
                .block_size = @intCast(posix_stat.st_blksize),
                .block_count = @intCast(posix_stat.st_blocks),
                .inode = @intCast(posix_stat.st_ino),
                .uid = @intCast(posix_stat.st_uid),
                .gid = @intCast(posix_stat.st_gid),
                .atime = timestampFromStatNanos(if (stat.atime) |atime| atime.toNanoseconds() else 0),
                .mtime = timestampFromStatNanos(stat.mtime.toNanoseconds()),
                .ctime = timestampFromStatNanos(stat.ctime.toNanoseconds()),
            },
            .open_kind = switch (kind) {
                .directory => .directory,
                .regular_file => .user_file,
                .missing => .missing,
            },
            .guarded = false,
        };
    }

    fn lookupGuardedDirectoryPath(self: *const Model, path: []const u8) !Lookup {
        const passthrough = try self.lookupPassthroughPath(path);
        if (passthrough.node.kind == .directory) {
            return passthrough;
        }

        return .{
            .node = .{
                .kind = .directory,
                .mode = 0o755,
                .nlink = 2,
                .size = 0,
                .block_size = 4096,
                .block_count = 0,
                .inode = syntheticDirectoryInode(path),
                .uid = currentUid(),
                .gid = currentGid(),
                .atime = self.root_timestamp,
                .mtime = self.root_timestamp,
                .ctime = self.root_timestamp,
            },
            .open_kind = .directory,
            .guarded = false,
        };
    }

    fn hasGuardedDescendant(self: *const Model, path: []const u8) bool {
        for (self.files.items) |file| {
            if (isDescendantPath(path, file.path)) {
                return true;
            }
        }
        return false;
    }

    fn syntheticChildNameForFile(self: *const Model, directory_path: []const u8, file: *const StoredFile) !?[]const u8 {
        const child_name = directChildName(directory_path, file.path) orelse return null;
        if (try self.realChildExists(directory_path, child_name)) {
            return null;
        }
        return child_name;
    }

    fn syntheticChildAlreadySeen(
        self: *const Model,
        directory_path: []const u8,
        child_name: []const u8,
        before_index: usize,
    ) !bool {
        for (self.files.items[0..before_index]) |file| {
            const previous = (try self.syntheticChildNameForFile(directory_path, &file)) orelse continue;
            if (std.mem.eql(u8, previous, child_name)) {
                return true;
            }
        }
        return false;
    }

    fn realChildExists(self: *const Model, directory_path: []const u8, child_name: []const u8) !bool {
        const dir = self.source_dir orelse return false;
        const child_path = try joinVirtualPath(self.allocator, directory_path, child_name);
        defer self.allocator.free(child_path);
        const relative_path = relativeMountedPath(child_path) orelse return false;
        _ = fstatatDir(dir, relative_path) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
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
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            const lookup = self.lookupPath(path) catch |err| return mapFsError(err);
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
            .executable_path = context.executable_path,
        };

        const outcome = blk: {
            self.policy_mutex.lockUncancelable(runtime.io());
            defer self.policy_mutex.unlock(runtime.io());
            self.refreshPolicyEngineIfNeeded();
            break :blk self.policy_engine.evaluate(request);
        };

        return switch (outcome) {
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
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
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
        self.recordAuditOrFallback("flush", path, result, .{
            .context = context,
            .file_info = file_info,
        });
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
        self.recordAuditOrFallback("fsync", path, result, .{
            .context = context,
            .file_info = file_info,
            .fsync = .{ .datasync = datasync },
        });
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
        self.recordAuditOrFallback("setxattr", path, result, .{
            .context = context,
            .xattr = .{
                .name = name,
                .size = value.len,
                .flags = flags,
                .position = position,
            },
        });
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

        self.recordAuditOrFallback("listxattr", path, @intCast(result), .{
            .context = context,
            .xattr = .{ .size = list.len },
        });
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
        self.recordAuditOrFallback("removexattr", path, result, .{
            .context = context,
            .xattr = .{ .name = name },
        });
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
                const grant = HandleGrant.initOpen(self.allocator, path, context.pid, file_request.flags) catch {
                    self.recordAuditOrFallback("open", path, result, .{
                        .context = context,
                        .file_info = file_info,
                    });
                    return;
                };
                self.handle_grants.grantOpen(self.allocator, handle_id, grant) catch {
                    self.recordAuditOrFallback("open", path, result, .{
                        .context = context,
                        .file_info = file_info,
                    });
                    return;
                };
            }
        }
        self.recordAuditOrFallback("open", path, result, .{
            .context = context,
            .file_info = file_info,
        });
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
            self.handle_grants.release(self.allocator, handle_id);
        }
        self.recordAuditOrFallback("release", path, result, .{
            .context = context,
            .file_info = file_info,
        });
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
        self.recordAuditOrFallback(action, path, result, metadata);
    }

    fn createFileInternal(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
        open_flags: ?i32,
    ) i32 {
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.createPassthroughFile(path, mode, open_flags);
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

        const file = self.appendFile(path, mode, currentUid(), currentGid(), null, null) catch |err| {
            return mapFsError(err);
        };
        errdefer self.removeFileAtIndex(self.files.items.len - 1);

        if (shouldPersistPath(path)) {
            const persist_result = self.syncFileToContentRoot(file);
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
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
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
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.truncatePassthroughFile(path, size);
        }

        const auth_result = if (self.handle_grants.hasActiveWriteGrant(path, context.pid))
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
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
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

        return self.finishMetadataMutation(path, file, snapshot);
    }

    fn chownFileInternal(
        self: *Model,
        path: []const u8,
        uid: u32,
        gid: u32,
        context: AccessContext,
    ) i32 {
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
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

        return self.finishMetadataMutation(path, file, snapshot);
    }

    fn syncPathInternal(self: *Model, path: []const u8) i32 {
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.syncPassthroughPath(path);
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        if (!shouldPersistPath(path)) {
            return 0;
        }

        return self.syncFileToContentRoot(file);
    }

    fn removeFileInternal(
        self: *Model,
        path: []const u8,
        context: AccessContext,
    ) i32 {
        if (!self.isGuardedPath(path) and !isTransientVirtualPath(path)) {
            return self.removePassthroughFile(path);
        }

        const auth_result = self.authorizeAccess(path, .delete, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const index = self.findFileIndex(path) orelse return errnoCode(.NOENT);
        if (shouldPersistPath(path)) {
            const file = &self.files.items[index];
            if (file.backing_object_id != null) {
                const remove_result = self.removeGuardedBackingFile(file);
                if (remove_result != 0) {
                    return remove_result;
                }
            }
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
        if (!isTransientVirtualPath(from) and !isTransientVirtualPath(to)) {
            return self.renameEnrolledParentPath(from, to, context);
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
        const rename_mutation = self.renameStoredFile(source_index, target_index, to) catch |err| {
            return mapFsError(err);
        };
        var rename_committed = false;
        defer if (!rename_committed) self.rollbackRenameMutation(rename_mutation);

        if (!isTransientVirtualPath(from) or !isTransientVirtualPath(to)) {
            return errnoCode(.INVAL);
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
            return self.replaceGuardedFileFromPassthrough(from, to);
        }

        const auth_result = self.authorizeAccess(from, .rename, context);
        if (auth_result != 0) {
            return auth_result;
        }
        return self.moveGuardedFileToPassthrough(from, to);
    }

    fn readPassthroughInto(
        self: *Model,
        path: []const u8,
        offset: u64,
        buffer: []u8,
    ) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = dir.openFile(runtime.io(), relative_path, .{ .mode = .read_only }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());

        const read_count = file.readPositional(runtime.io(), &.{buffer}, offset) catch |err| return mapFsError(err);
        return @intCast(read_count);
    }

    fn createPassthroughFile(self: *Model, path: []const u8, mode: u32, open_flags: ?i32) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const flags = open_flags orelse (c.O_CREAT | c.O_EXCL | c.O_WRONLY);
        const truncate = (flags & c.O_TRUNC) != 0;

        const file = dir.createFile(runtime.io(), relative_path, .{
            .read = (flags & c.O_ACCMODE) != c.O_WRONLY,
            .truncate = truncate,
            .exclusive = (flags & c.O_EXCL) != 0,
        }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());

        file.setPermissions(runtime.io(), .fromMode(@intCast(mode & 0o777))) catch |err| return mapFsError(err);
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
        const file = dir.openFile(runtime.io(), relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());

        file.writePositionalAll(runtime.io(), bytes, offset) catch |err| return mapFsError(err);
        return @intCast(bytes.len);
    }

    fn truncatePassthroughFile(self: *Model, path: []const u8, size: u64) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = dir.openFile(runtime.io(), relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());
        truncateIoFile(file, size) catch |err| return mapFsError(err);
        return 0;
    }

    fn chmodPassthroughFile(self: *Model, path: []const u8, mode: u32) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = dir.openFile(runtime.io(), relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());
        file.setPermissions(runtime.io(), .fromMode(@intCast(mode & 0o777))) catch |err| return mapFsError(err);
        return 0;
    }

    fn chownPassthroughFile(self: *Model, path: []const u8, uid: u32, gid: u32) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = dir.openFile(runtime.io(), relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());
        file.setOwner(runtime.io(), @intCast(uid), @intCast(gid)) catch |err| return mapFsError(err);
        return 0;
    }

    fn syncPassthroughPath(self: *Model, path: []const u8) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = dir.openFile(runtime.io(), relative_path, .{ .mode = .read_write }) catch |err| return mapFsError(err);
        defer file.close(runtime.io());
        file.sync(runtime.io()) catch |err| return mapFsError(err);
        return 0;
    }

    fn removePassthroughFile(self: *Model, path: []const u8) i32 {
        const relative_path = relativeMountedPath(path) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        dir.deleteFile(runtime.io(), relative_path) catch |err| return mapFsError(err);
        return 0;
    }

    fn renamePassthroughPath(self: *Model, from: []const u8, to: []const u8) i32 {
        const from_relative = relativeMountedPath(from) orelse return errnoCode(.INVAL);
        const to_relative = relativeMountedPath(to) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        std.Io.Dir.rename(dir, from_relative, dir, to_relative, runtime.io()) catch |err| return mapFsError(err);
        return 0;
    }

    fn replaceGuardedFileFromPassthrough(self: *Model, from: []const u8, to: []const u8) i32 {
        const from_relative = relativeMountedPath(from) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = self.findFile(to) orelse return errnoCode(.NOENT);
        if (file.backing_object_id == null) {
            return errnoCode(.NOENT);
        }
        const source_file = dir.openFile(runtime.io(), from_relative, .{ .mode = .read_only }) catch |err| return mapFsError(err);
        defer source_file.close(runtime.io());

        const contents = readFileToEndAlloc(source_file, self.allocator, 1024 * 1024) catch |err| return mapFsError(err);
        defer self.allocator.free(contents);
        const source_stat = source_file.stat(runtime.io()) catch |err| return mapFsError(err);
        const posix_stat = fstatFd(source_file.handle) catch |err| return mapFsError(err);

        file.content.clearRetainingCapacity();
        file.content.appendSlice(self.allocator, contents) catch return errnoCode(.NOMEM);
        file.mode = @intCast(source_stat.permissions.toMode() & 0o777);
        file.uid = @intCast(posix_stat.st_uid);
        file.gid = @intCast(posix_stat.st_gid);
        touchFileContent(file);

        const sync_result = self.syncFileToContentRoot(file);
        if (sync_result != 0) {
            return sync_result;
        }

        dir.deleteFile(runtime.io(), from_relative) catch |err| return mapFsError(err);
        self.touchStatus();
        return 0;
    }

    fn moveGuardedFileToPassthrough(self: *Model, from: []const u8, to: []const u8) i32 {
        const to_relative = relativeMountedPath(to) orelse return errnoCode(.INVAL);
        const dir = self.source_dir orelse return errnoCode(.IO);
        const file = self.findFile(from) orelse return errnoCode(.NOENT);
        if (file.backing_object_id == null) {
            return errnoCode(.NOENT);
        }
        const target_file = dir.createFile(runtime.io(), to_relative, .{ .read = true, .truncate = true }) catch |err| return mapFsError(err);
        defer target_file.close(runtime.io());

        if (file.content.items.len != 0) {
            target_file.writeStreamingAll(runtime.io(), file.content.items) catch |err| return mapFsError(err);
        }
        target_file.setPermissions(runtime.io(), .fromMode(@intCast(file.mode))) catch |err| return mapFsError(err);
        target_file.setOwner(runtime.io(), @intCast(file.uid), @intCast(file.gid)) catch |err| return mapFsError(err);
        target_file.sync(runtime.io()) catch |err| return mapFsError(err);

        const remove_result = self.removeGuardedBackingFile(file);
        if (remove_result != 0) {
            return remove_result;
        }

        const source_index = self.findFileIndex(from) orelse return errnoCode(.NOENT);
        self.removeFileAtIndex(source_index);
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

        const persist_result = self.syncFileToContentRoot(file);
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
    ) i32 {
        if (!shouldPersistPath(path)) {
            return 0;
        }

        if (file.backing_object_id != null) {
            const persist_result = self.syncFileToContentRoot(file);
            if (persist_result != 0) {
                restoreFileMetadata(file, snapshot);
            }
            return persist_result;
        }
        return 0;
    }

    fn restoreFileMetadata(file: *StoredFile, snapshot: MetadataSnapshot) void {
        file.mode = snapshot.mode;
        file.uid = snapshot.uid;
        file.gid = snapshot.gid;
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

    fn appendFile(
        self: *Model,
        path: []const u8,
        mode: u32,
        uid: u32,
        gid: u32,
        backing_object_id: ?[]const u8,
        lock_anchor_path: ?[]const u8,
    ) !*StoredFile {
        const now = currentTimestamp();
        const name = try self.allocator.dupeZ(u8, path[1..]);
        errdefer self.allocator.free(name);
        const owned_path = try self.allocator.dupeZ(u8, path);
        errdefer self.allocator.free(owned_path);
        const owned_backing_object_id = if (backing_object_id) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_backing_object_id) |value| self.allocator.free(value);
        const owned_lock_anchor_path = if (lock_anchor_path) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_lock_anchor_path) |value| self.allocator.free(value);

        try self.files.append(self.allocator, .{
            .name = name,
            .path = owned_path,
            .backing_object_id = owned_backing_object_id,
            .lock_anchor_path = owned_lock_anchor_path,
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

    fn findFileIndex(self: *const Model, path: []const u8) ?usize {
        for (self.files.items, 0..) |file, index| {
            if (std.mem.eql(u8, file.path, path)) {
                return index;
            }
        }
        return null;
    }

    fn syncFileToContentRoot(self: *Model, file: *const StoredFile) i32 {
        if (file.backing_object_id) |object_id| {
            const guarded_store = self.guarded_store orelse return errnoCode(.IO);
            guarded_store.putObject(self.allocator, object_id, .{
                .metadata = .{
                    .mode = file.mode,
                    .uid = file.uid,
                    .gid = file.gid,
                    .atime_nsec = nanosFromTimestamp(file.atime),
                    .mtime_nsec = nanosFromTimestamp(file.mtime),
                },
                .content = file.content.items,
            }) catch return errnoCode(.IO);
            return 0;
        }

        return errnoCode(.IO);
    }

    fn removeGuardedBackingFile(self: *Model, file: *const StoredFile) i32 {
        const object_id = file.backing_object_id orelse return errnoCode(.NOENT);
        const guarded_store = self.guarded_store orelse return errnoCode(.IO);
        guarded_store.removeObject(self.allocator, object_id) catch |err| return mapFsError(err);
        return 0;
    }

    fn isGuardedPath(self: *const Model, path: []const u8) bool {
        const file = self.findFile(path) orelse return false;
        return file.backing_object_id != null;
    }

    fn hostXattrPathAllocZ(
        self: *const Model,
        path: []const u8,
        missing_result: i32,
    ) union(enum) {
        ok: [:0]u8,
        err: i32,
    } {
        const lookup = self.lookupPath(path) catch |err| return .{ .err = mapFsError(err) };
        if (lookup.open_kind != .user_file or !lookup.guarded) {
            return .{ .err = missing_result };
        }
        return .{ .err = missing_result };
    }

    pub fn openGuardedLockFd(self: *const Model, path: []const u8, requested_flags: i32) i32 {
        _ = requested_flags;
        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const lock_anchor_path = file.lock_anchor_path orelse return errnoCode(.NOENT);
        ensureParentDirectoryAbsolute(lock_anchor_path) catch |err| return mapFsError(err);

        const lock_anchor_z = self.allocator.dupeZ(u8, lock_anchor_path) catch return errnoCode(.NOMEM);
        defer self.allocator.free(lock_anchor_z);

        const descriptor = c.open(lock_anchor_z.ptr, c.O_RDWR | c.O_CREAT, @as(std.posix.mode_t, 0o600));
        if (descriptor < 0) {
            return -std.c._errno().*;
        }

        return descriptor;
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
        self.recordAuditOrFallback("policy", audit_event_path, @intCast(@intFromEnum(outcome)), .{
            .context = context,
        });
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

        const response = if (self.prompt_broker) |broker|
            broker.resolve(.{
                .path = request.path,
                .access_class = request.access_class,
                .label = label,
                .can_remember = request.executable_path != null,
                .pid = request.pid,
                .uid = request.uid,
                .gid = request.gid,
                .executable_path = context.executable_path,
            })
        else
            prompt.Response{ .decision = .unavailable };

        self.recordAuditOrFallback("prompt", audit_event_path, @intFromEnum(response.decision), .{
            .context = context,
        });
        return switch (response.decision) {
            .allow => 0,
            .deny, .timeout, .unavailable => errnoCode(.ACCES),
        };
    }

    fn refreshPolicyEngineIfNeeded(self: *Model) void {
        const policy_path = self.live_policy_path orelse return;
        const marker = config.currentPolicyMarker(self.allocator, policy_path) catch |err| {
            std.log.warn("failed to inspect live policy at {s}: {}", .{ policy_path, err });
            return;
        };
        if (self.last_policy_marker) |last_marker| {
            if (last_marker.eql(marker)) return;
        }

        var loaded_policy = config.loadFromFile(self.allocator, policy_path) catch |err| {
            std.log.warn("failed to reload live policy at {s}: {}", .{ policy_path, err });
            return;
        };
        defer loaded_policy.deinit();

        var compiled_rule_views = loaded_policy.compilePolicyRuleViews(self.allocator) catch |err| {
            std.log.warn("failed to compile live policy at {s}: {}", .{ policy_path, err });
            return;
        };
        defer compiled_rule_views.deinit();

        const next_engine = policy.Engine.init(
            self.allocator,
            self.policy_engine.default_mutation_outcome,
            compiled_rule_views.items,
        ) catch |err| {
            std.log.warn("failed to build live policy engine for {s}: {}", .{ policy_path, err });
            return;
        };

        self.policy_engine.deinit();
        self.policy_engine = next_engine;
        self.last_policy_marker = marker;
    }

    fn recordRenameAudit(self: *Model, from: []const u8, to: []const u8, result: i32, context: AccessContext) void {
        self.recordAuditOrFallback("rename", from, result, .{
            .context = context,
            .rename = .{
                .from = from,
                .to = to,
            },
        });
    }

    fn recordAuditLiteral(self: *Model, action: []const u8, path: []const u8, result: i32, context: AccessContext) void {
        self.recordAuditOrFallback(action, path, result, .{ .context = context });
    }

    /// Best-effort audit recording. On failure, falls back to emitAuditLine, then std.log.err.
    fn recordAuditOrFallback(self: *Model, action: []const u8, path: []const u8, result: i32, metadata: AuditMetadata) void {
        self.recordAudit(action, path, result, metadata) catch |err| {
            const timestamp = currentTimestamp();
            if (!self.emitAuditLineNoAlloc(action, path, result, timestamp, metadata)) {
                std.log.err("failed to record audit event action={s} path={s} result={d}: {}", .{ action, path, result, err });
            }
        };
    }

    fn recordAudit(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        metadata: AuditMetadata,
    ) !void {
        const timestamp = currentTimestamp();
        const owned_action = try self.allocator.dupe(u8, action);
        var action_owned = true;
        errdefer if (action_owned) self.allocator.free(owned_action);

        const owned_path = try self.allocator.dupe(u8, path);
        var path_owned = true;
        errdefer if (path_owned) self.allocator.free(owned_path);

        var event: StoredAuditEvent = .{
            .action = owned_action,
            .path = owned_path,
            .result = result,
            .timestamp = timestamp,
            .pid = metadata.context.pid,
            .uid = metadata.context.uid,
            .gid = metadata.context.gid,
            .executable_path = null,
            .file_info = metadata.file_info,
            .lock = metadata.lock,
            .flock = metadata.flock,
            .xattr = null,
            .rename = null,
            .fsync = metadata.fsync,
        };
        action_owned = false;
        path_owned = false;
        errdefer event.deinit(self.allocator);

        if (metadata.context.executable_path) |value| {
            event.executable_path = try self.allocator.dupe(u8, value);
        }
        if (metadata.xattr) |xattr| {
            event.xattr = .{
                .name = if (xattr.name) |name| try self.allocator.dupe(u8, name) else null,
                .size = xattr.size,
                .flags = xattr.flags,
                .position = xattr.position,
            };
        }
        if (metadata.rename) |rename| {
            const from = try self.allocator.dupe(u8, rename.from);
            var from_owned = true;
            errdefer if (from_owned) self.allocator.free(from);
            const to = try self.allocator.dupe(u8, rename.to);
            event.rename = .{
                .from = from,
                .to = to,
            };
            from_owned = false;
        }

        try self.audit_events.append(self.allocator, event);
        _ = self.emitAuditLine(action, path, result, timestamp, metadata);
    }

    fn touchStatus(self: *Model) void {
        self.emitStatusSnapshot();
    }

    fn emitStatusSnapshot(self: *Model) void {
        const output_file = self.status_output_file orelse return;

        var line: std.Io.Writer.Allocating = .init(self.allocator);
        defer line.deinit();

        std.json.Stringify.value(.{
            .action = "status",
            .backend = "libfuse",
            .mount_path = self.mount_path,
            .configured_ops = self.runtime_stats.configured_operation_count,
            .planned_args = self.runtime_stats.planned_argument_count,
            .tracked_files = self.files.items.len,
        }, .{}, &line.writer) catch return;
        line.writer.writeByte('\n') catch return;

        self.output_mutex.lockUncancelable(runtime.io());
        defer self.output_mutex.unlock(runtime.io());
        output_file.writeStreamingAll(runtime.io(), line.written()) catch return;
    }

    fn emitAuditLine(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        timestamp: Timestamp,
        metadata: AuditMetadata,
    ) bool {
        const output_file = self.audit_output_file orelse return false;

        var line: std.Io.Writer.Allocating = .init(self.allocator);
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
        }, .{}, &line.writer) catch return false;
        line.writer.writeByte('\n') catch return false;

        self.output_mutex.lockUncancelable(runtime.io());
        defer self.output_mutex.unlock(runtime.io());
        output_file.writeStreamingAll(runtime.io(), line.written()) catch return false;
        return true;
    }

    fn emitAuditLineNoAlloc(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        timestamp: Timestamp,
        metadata: AuditMetadata,
    ) bool {
        const output_file = self.audit_output_file orelse return false;

        var buffer: [16 * 1024]u8 = undefined;
        var line: std.Io.Writer = .fixed(&buffer);

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
        }, .{}, &line) catch return false;
        line.writeByte('\n') catch return false;

        self.output_mutex.lockUncancelable(runtime.io());
        defer self.output_mutex.unlock(runtime.io());
        output_file.writeStreamingAll(runtime.io(), line.buffered()) catch return false;
        return true;
    }
};

const writeIntoArrayList = util.writeIntoArrayList;
const resizeArrayList = util.resizeArrayList;
const copySlice = util.copySlice;
const currentTimestamp = util.currentTimestamp;
const ensureParentDirectoryAbsolute = util.ensureParentDirectoryAbsolute;
const nanosFromTimestamp = util.nanosFromTimestamp;
const timestampFromNanos = util.timestampFromNanos;
const timestampFromStatNanos = util.timestampFromStatNanos;

fn fstatFd(fd: std.posix.fd_t) !c.struct_stat {
    var stat: c.struct_stat = undefined;
    if (c.fstat(fd, &stat) != 0) return posixStatError(std.posix.errno(-1));
    return stat;
}

fn fstatatDir(dir: std.Io.Dir, path: []const u8) !c.struct_stat {
    const path_z = try std.heap.page_allocator.dupeZ(u8, path);
    defer std.heap.page_allocator.free(path_z);
    var stat: c.struct_stat = undefined;
    if (c.fstatat(dir.handle, path_z.ptr, &stat, 0) != 0) return posixStatError(std.posix.errno(-1));
    return stat;
}

fn posixStatError(err: std.posix.E) anyerror {
    return switch (err) {
        .NOENT => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        .NAMETOOLONG => error.NameTooLong,
        .NOTDIR => error.NotDir,
        .INTR => error.Interrupted,
        .IO => error.InputOutput,
        .NOMEM => error.OutOfMemory,
        else => error.Unexpected,
    };
}

fn truncateIoFile(file: std.Io.File, size: u64) !void {
    if (c.ftruncate(file.handle, @intCast(size)) != 0) return error.InputOutput;
}

fn readFileToEndAlloc(file: std.Io.File, allocator: std.mem.Allocator, max_bytes: usize) ![]u8 {
    var buffer: [4096]u8 = undefined;
    var reader = file.reader(runtime.io(), &buffer);
    return reader.interface.allocRemaining(allocator, .limited(max_bytes));
}
const missingLookup = util.missingLookup;
const relativeMountedPath = util.relativeMountedPath;
const joinVirtualPath = util.joinVirtualPath;
const directChildName = util.directChildName;
const isDescendantPath = util.isDescendantPath;
const syntheticDirectoryInode = util.syntheticDirectoryInode;
const blockCountForSize = util.blockCountForSize;
const currentUid = util.currentUid;
const currentGid = util.currentGid;
const accessClassForOpenFlags = util.accessClassForOpenFlags;
const authorizeReadFromOpenFlags = util.authorizeReadFromOpenFlags;
const authorizeWriteFromOpenFlags = util.authorizeWriteFromOpenFlags;
const formatOpenPromptLabel = util.formatOpenPromptLabel;
const accessClassLabel = util.accessClassLabel;
const isRootPath = util.isRootPath;
const isTransientVirtualPath = util.isTransientVirtualPath;
const shouldPersistPath = util.shouldPersistPath;
const errnoCode = util.errnoCode;
const mapFsError = util.mapFsError;

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
