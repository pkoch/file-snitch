const std = @import("std");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");
const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("sys/xattr.h");
});

const status_name: [:0]const u8 = "file-snitch-status";
const status_path: [:0]const u8 = "/file-snitch-status";
const audit_name: [:0]const u8 = "file-snitch-audit";
const audit_path: [:0]const u8 = "/file-snitch-audit";

const root_inode: u64 = 1;
const status_inode: u64 = 2;
const audit_inode: u64 = 3;
const first_dynamic_inode: u64 = 16;

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
};

pub const RuntimeStats = struct {
    configured_operation_count: u32 = 0,
    planned_argument_count: u32 = 0,
};

pub const NodeInfo = struct {
    kind: NodeKind,
    mode: u32,
    size: u64,
    inode: u64,
    uid: u32,
    gid: u32,
};

pub const Lookup = struct {
    node: NodeInfo,
    open_kind: OpenKind,
    persistent: bool,
};

pub const AuditEvent = struct {
    action: []const u8,
    path: []const u8,
    result: i32,
    detail: ?[]const u8,
};

const StoredAuditEvent = struct {
    action: []u8,
    path: []u8,
    result: i32,
    detail: ?[]u8,

    fn deinit(self: *StoredAuditEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.action);
        allocator.free(self.path);
        if (self.detail) |detail| {
            allocator.free(detail);
        }
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
};

pub const Model = struct {
    allocator: std.mem.Allocator,
    mount_path: []u8,
    backing_store_path: []u8,
    policy_engine: policy.Engine,
    prompt_broker: ?prompt.Broker,
    files: std.ArrayListUnmanaged(StoredFile) = .{},
    audit_events: std.ArrayListUnmanaged(StoredAuditEvent) = .{},
    next_inode: u64 = first_dynamic_inode,
    runtime_stats: RuntimeStats = .{},

    pub fn init(allocator: std.mem.Allocator, config: Config) !Model {
        var model = Model{
            .allocator = allocator,
            .mount_path = try allocator.dupe(u8, config.mount_path),
            .backing_store_path = try allocator.dupe(u8, config.backing_store_path),
            .policy_engine = try policy.Engine.init(
                allocator,
                config.default_mutation_outcome,
                config.policy_rules,
            ),
            .prompt_broker = config.prompt_broker,
        };
        errdefer model.deinit();

        return model;
    }

    pub fn loadBackingStore(self: *Model) !void {
        if (self.files.items.len != 0) {
            return error.BackingStoreAlreadyLoaded;
        }

        try ensureBackingStoreDirectory(self.backing_store_path);

        var directory = try std.fs.openDirAbsolute(self.backing_store_path, .{ .iterate = true });
        defer directory.close();

        var iterator = directory.iterate();
        while (try iterator.next()) |entry| {
            if (isReservedName(entry.name) or isTransientSidecarName(entry.name)) {
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
                stat.mode & 0o777,
                @intCast(posix_stat.uid),
                @intCast(posix_stat.gid),
            );

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

    pub fn deinit(self: *Model) void {
        for (self.files.items) |*file| {
            file.deinit(self.allocator);
        }
        self.files.deinit(self.allocator);

        for (self.audit_events.items) |*event| {
            event.deinit(self.allocator);
        }
        self.audit_events.deinit(self.allocator);

        self.policy_engine.deinit();
        self.allocator.free(self.mount_path);
        self.allocator.free(self.backing_store_path);
        self.* = undefined;
    }

    pub fn setRuntimeStats(self: *Model, stats: RuntimeStats) void {
        self.runtime_stats = stats;
    }

    pub fn defaultMutationOutcome(self: *const Model) policy.Outcome {
        return self.policy_engine.default_mutation_outcome;
    }

    pub fn lookupPath(self: *const Model, path: []const u8) Lookup {
        if (isRootPath(path)) {
            return .{
                .node = .{
                    .kind = .directory,
                    .mode = 0o755,
                    .size = 0,
                    .inode = root_inode,
                    .uid = currentUid(),
                    .gid = currentGid(),
                },
                .open_kind = .directory,
                .persistent = false,
            };
        }

        if (isStatusPath(path)) {
            return .{
                .node = .{
                    .kind = .regular_file,
                    .mode = 0o444,
                    .size = self.renderStatusContentLength(),
                    .inode = status_inode,
                    .uid = currentUid(),
                    .gid = currentGid(),
                },
                .open_kind = .synthetic_readonly,
                .persistent = false,
            };
        }

        if (isAuditPath(path)) {
            return .{
                .node = .{
                    .kind = .regular_file,
                    .mode = 0o444,
                    .size = self.renderAuditContentLength(),
                    .inode = audit_inode,
                    .uid = currentUid(),
                    .gid = currentGid(),
                },
                .open_kind = .synthetic_readonly,
                .persistent = false,
            };
        }

        if (self.findFile(path)) |file| {
            return .{
                .node = .{
                    .kind = .regular_file,
                    .mode = file.mode,
                    .size = file.content.items.len,
                    .inode = file.inode,
                    .uid = file.uid,
                    .gid = file.gid,
                },
                .open_kind = .user_file,
                .persistent = shouldPersistPath(path),
            };
        }

        return .{
            .node = .{
                .kind = .missing,
                .mode = 0,
                .size = 0,
                .inode = 0,
                .uid = 0,
                .gid = 0,
            },
            .open_kind = .missing,
            .persistent = false,
        };
    }

    pub fn rootEntryCount(self: *const Model) u32 {
        return @intCast(2 + self.files.items.len);
    }

    pub fn rootEntryNameAt(self: *const Model, index: u32) ?[*:0]const u8 {
        if (index == 0) {
            return status_name.ptr;
        }

        if (index == 1) {
            return audit_name.ptr;
        }

        const file_index: usize = @intCast(index - 2);
        if (file_index >= self.files.items.len) {
            return null;
        }

        return self.files.items[file_index].name.ptr;
    }

    pub fn authorizeAccess(
        self: *Model,
        path: []const u8,
        access_class: policy.AccessClass,
        context: AccessContext,
    ) i32 {
        if (access_class == .read and (isStatusPath(path) or isAuditPath(path))) {
            return 0;
        }

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
                self.recordPolicyAudit(access_class, path, .deny);
                break :blk errnoCode(.ACCES);
            },
            .prompt => self.resolvePromptDecision(request),
        };
    }

    pub fn readInto(
        self: *Model,
        path: []const u8,
        offset: u64,
        buffer: []u8,
        context: AccessContext,
    ) i32 {
        const auth_result = self.authorizeAccess(path, .read, context);
        if (auth_result != 0) {
            self.recordAuditLiteral("read", path, auth_result);
            return auth_result;
        }

        if (offset > std.math.maxInt(usize)) {
            self.recordAuditLiteral("read", path, errnoCode(.INVAL));
            return errnoCode(.INVAL);
        }

        if (isStatusPath(path)) {
            const content = self.renderStatusContent() catch {
                self.recordAuditLiteral("read", path, errnoCode(.NOMEM));
                return errnoCode(.NOMEM);
            };
            defer self.allocator.free(content);

            const result = copySlice(content, buffer, @intCast(offset));
            self.recordAuditLiteral("read", path, result);
            return result;
        }

        if (isAuditPath(path)) {
            const content = self.renderAuditContent() catch {
                return errnoCode(.NOMEM);
            };
            defer self.allocator.free(content);
            return copySlice(content, buffer, @intCast(offset));
        }

        const file = self.findFile(path) orelse {
            self.recordAuditLiteral("read", path, errnoCode(.NOENT));
            return errnoCode(.NOENT);
        };

        const result = copySlice(file.content.items, buffer, @intCast(offset));
        self.recordAuditLiteral("read", path, result);
        return result;
    }

    pub fn createFile(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const result = self.createFileInternal(path, mode, context);
        self.recordAuditLiteral("create", path, result);
        return result;
    }

    pub fn createDirectory(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const result = createDirectoryNotSupported(path, mode, context);
        self.recordAuditLiteral("mkdir", path, result);
        return result;
    }

    pub fn writeFile(
        self: *Model,
        path: []const u8,
        offset: u64,
        bytes: []const u8,
        context: AccessContext,
    ) i32 {
        const result = self.writeFileInternal(path, offset, bytes, context);
        self.recordAuditLiteral("write", path, result);
        return result;
    }

    pub fn truncateFile(
        self: *Model,
        path: []const u8,
        size: u64,
        context: AccessContext,
    ) i32 {
        const result = self.truncateFileInternal(path, size, context);
        self.recordAuditLiteral("truncate", path, result);
        return result;
    }

    pub fn chmodFile(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const result = self.chmodFileInternal(path, mode, context);
        self.recordAuditLiteral("chmod", path, result);
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
        self.recordAuditLiteral("chown", path, result);
        return result;
    }

    pub fn flushPath(
        self: *Model,
        path: []const u8,
    ) i32 {
        const result = self.syncPathInternal(path);
        self.recordAuditLiteral("flush", path, result);
        return result;
    }

    pub fn fsyncPath(
        self: *Model,
        path: []const u8,
        datasync: bool,
    ) i32 {
        const result = self.syncPathInternal(path);
        self.recordAudit("fsync", path, result, if (datasync) "datasync" else null) catch {};
        return result;
    }

    pub fn setXattr(
        self: *Model,
        path: []const u8,
        name: []const u8,
        value: []const u8,
        flags: i32,
        position: u32,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, errnoCode(.OPNOTSUPP))) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const name_z = self.allocator.dupeZ(u8, name) catch return errnoCode(.NOMEM);
        defer self.allocator.free(name_z);

        const result = if (c.setxattr(host_path.ptr, name_z.ptr, value.ptr, value.len, position, flags) == 0)
            0
        else
            errnoCode(std.posix.errno(-1));
        self.recordAudit("setxattr", path, result, name) catch {};
        return result;
    }

    pub fn getXattr(
        self: *Model,
        path: []const u8,
        name: []const u8,
        value: []u8,
        position: u32,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, errnoCode(.NOATTR))) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const name_z = self.allocator.dupeZ(u8, name) catch return errnoCode(.NOMEM);
        defer self.allocator.free(name_z);

        const result = c.getxattr(host_path.ptr, name_z.ptr, if (value.len == 0) null else value.ptr, value.len, position, 0);
        if (result < 0) {
            return errnoCode(std.posix.errno(-1));
        }

        return @intCast(result);
    }

    pub fn listXattr(
        self: *Model,
        path: []const u8,
        list: []u8,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, 0)) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const result = c.listxattr(host_path.ptr, if (list.len == 0) null else list.ptr, list.len, 0);
        if (result < 0) {
            return errnoCode(std.posix.errno(-1));
        }

        self.recordAudit("listxattr", path, @intCast(result), null) catch {};
        return @intCast(result);
    }

    pub fn removeXattr(
        self: *Model,
        path: []const u8,
        name: []const u8,
    ) i32 {
        const host_path = switch (self.hostXattrPathAllocZ(path, errnoCode(.OPNOTSUPP))) {
            .ok => |host_path_z| host_path_z,
            .err => |code| return code,
        };
        defer self.allocator.free(host_path);

        const name_z = self.allocator.dupeZ(u8, name) catch return errnoCode(.NOMEM);
        defer self.allocator.free(name_z);

        const result = if (c.removexattr(host_path.ptr, name_z.ptr, 0) == 0)
            0
        else
            errnoCode(std.posix.errno(-1));
        self.recordAudit("removexattr", path, result, name) catch {};
        return result;
    }

    pub fn removeFile(
        self: *Model,
        path: []const u8,
        context: AccessContext,
    ) i32 {
        const result = self.removeFileInternal(path, context);
        self.recordAuditLiteral("unlink", path, result);
        return result;
    }

    pub fn removeDirectory(
        self: *Model,
        path: []const u8,
        context: AccessContext,
    ) i32 {
        const result = removeDirectoryNotSupported(path, context);
        self.recordAuditLiteral("rmdir", path, result);
        return result;
    }

    pub fn renameFile(
        self: *Model,
        from: []const u8,
        to: []const u8,
        context: AccessContext,
    ) i32 {
        const result = self.renameFileInternal(from, to, context);
        self.recordRenameAudit(from, to, result);
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
            .detail = stored.detail,
        };
    }

    pub fn recordPlatformAudit(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        detail: ?[]const u8,
    ) void {
        self.recordAudit(action, path, result, detail) catch {};
    }

    fn createFileInternal(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        if (!isUserFilePath(path) or isReservedPath(path)) {
            return errnoCode(.INVAL);
        }

        if (self.findFile(path) != null) {
            return errnoCode(.EXIST);
        }

        const auth_result = self.authorizeAccess(path, .create, context);
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

        return 0;
    }

    fn writeFileInternal(
        self: *Model,
        path: []const u8,
        offset: u64,
        bytes: []const u8,
        context: AccessContext,
    ) i32 {
        const auth_result = self.authorizeAccess(path, .write, context);
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

        return self.finishContentMutation(path, file, snapshot, @intCast(bytes.len));
    }

    fn truncateFileInternal(
        self: *Model,
        path: []const u8,
        size: u64,
        context: AccessContext,
    ) i32 {
        const auth_result = self.authorizeAccess(path, .write, context);
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

        return self.finishContentMutation(path, file, snapshot, 0);
    }

    fn chmodFileInternal(
        self: *Model,
        path: []const u8,
        mode: u32,
        context: AccessContext,
    ) i32 {
        const auth_result = self.authorizeAccess(path, .metadata, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = snapshotFileMetadata(file);
        file.mode = mode & 0o777;

        return self.finishMetadataMutation(path, file, snapshot, applyModeToHost);
    }

    fn chownFileInternal(
        self: *Model,
        path: []const u8,
        uid: u32,
        gid: u32,
        context: AccessContext,
    ) i32 {
        const auth_result = self.authorizeAccess(path, .metadata, context);
        if (auth_result != 0) {
            return auth_result;
        }

        const file = self.findFile(path) orelse return errnoCode(.NOENT);
        const snapshot = snapshotFileMetadata(file);
        file.uid = uid;
        file.gid = gid;

        return self.finishMetadataMutation(path, file, snapshot, applyOwnershipToHost);
    }

    fn syncPathInternal(self: *Model, path: []const u8) i32 {
        if (isReservedPath(path)) {
            return 0;
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
        if (isReservedPath(path)) {
            return errnoCode(.ACCES);
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
        return 0;
    }

    fn renameFileInternal(
        self: *Model,
        from: []const u8,
        to: []const u8,
        context: AccessContext,
    ) i32 {
        if (!isUserFilePath(from) or !isUserFilePath(to)) {
            return errnoCode(.INVAL);
        }

        if (isReservedPath(from) or isReservedPath(to)) {
            return errnoCode(.ACCES);
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
        if (!isUserFilePath(path)) {
            return error.InvalidPath;
        }

        return std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.backing_store_path, path[1..] });
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

    fn renderStatusContent(self: *const Model) ![]u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "backend=libfuse\nmount_path={s}\nbacking_store={s}\nconfigured_ops={d}\nplanned_args={d}\nbacking_files={d}\n",
            .{
                self.mount_path,
                self.backing_store_path,
                self.runtime_stats.configured_operation_count,
                self.runtime_stats.planned_argument_count,
                self.files.items.len,
            },
        );
    }

    fn renderStatusContentLength(self: *const Model) u64 {
        const content = self.renderStatusContent() catch return 0;
        defer self.allocator.free(content);
        return content.len;
    }

    fn renderAuditContent(self: *const Model) ![]u8 {
        if (self.audit_events.items.len == 0) {
            return self.allocator.dupe(u8, "[]\n");
        }

        var content: std.ArrayList(u8) = .empty;
        defer content.deinit(self.allocator);

        for (self.audit_events.items) |event| {
            if (event.detail) |detail| {
                try content.writer(self.allocator).print(
                    "{{\"action\":\"{s}\",\"path\":\"{s}\",\"result\":{d},\"detail\":\"{s}\"}}\n",
                    .{ event.action, event.path, event.result, detail },
                );
            } else {
                try content.writer(self.allocator).print(
                    "{{\"action\":\"{s}\",\"path\":\"{s}\",\"result\":{d}}}\n",
                    .{ event.action, event.path, event.result },
                );
            }
        }

        return content.toOwnedSlice(self.allocator);
    }

    fn renderAuditContentLength(self: *const Model) u64 {
        const content = self.renderAuditContent() catch return 0;
        defer self.allocator.free(content);
        return content.len;
    }

    fn recordPolicyAudit(
        self: *Model,
        access_class: policy.AccessClass,
        path: []const u8,
        outcome: policy.Outcome,
    ) void {
        const audit_event_path = std.fmt.allocPrint(
            self.allocator,
            "{s} {s}",
            .{ accessClassLabel(access_class), path },
        ) catch return;
        defer self.allocator.free(audit_event_path);
        self.recordAudit("policy", audit_event_path, @intCast(@intFromEnum(outcome)), null) catch {};
    }

    fn resolvePromptDecision(self: *Model, request: policy.Request) i32 {
        const audit_event_path = std.fmt.allocPrint(
            self.allocator,
            "{s} {s}",
            .{ accessClassLabel(request.access_class), request.path },
        ) catch return errnoCode(.NOMEM);
        defer self.allocator.free(audit_event_path);

        const decision = if (self.prompt_broker) |broker|
            broker.resolve(.{
                .path = request.path,
                .access_class = request.access_class,
                .pid = request.pid,
                .uid = request.uid,
                .gid = request.gid,
            })
        else
            prompt.Decision.unavailable;

        self.recordAudit("prompt", audit_event_path, @intFromEnum(decision), null) catch {};
        return switch (decision) {
            .allow => 0,
            .deny, .timeout, .unavailable => errnoCode(.ACCES),
        };
    }

    fn recordRenameAudit(self: *Model, from: []const u8, to: []const u8, result: i32) void {
        const audit_event_path = std.fmt.allocPrint(self.allocator, "{s} -> {s}", .{ from, to }) catch return;
        defer self.allocator.free(audit_event_path);
        self.recordAudit("rename", audit_event_path, result, null) catch {};
    }

    fn recordAuditLiteral(self: *Model, action: []const u8, path: []const u8, result: i32) void {
        self.recordAudit(action, path, result, null) catch {};
    }

    fn recordAudit(
        self: *Model,
        action: []const u8,
        path: []const u8,
        result: i32,
        detail: ?[]const u8,
    ) !void {
        try self.audit_events.append(self.allocator, .{
            .action = try self.allocator.dupe(u8, action),
            .path = try self.allocator.dupe(u8, path),
            .result = result,
            .detail = if (detail) |value| try self.allocator.dupe(u8, value) else null,
        });
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

fn currentUid() u32 {
    return @intCast(std.posix.getuid());
}

fn currentGid() u32 {
    return @intCast(c.getgid());
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

fn isStatusPath(path: []const u8) bool {
    return std.mem.eql(u8, path, status_path);
}

fn isAuditPath(path: []const u8) bool {
    return std.mem.eql(u8, path, audit_path);
}

fn isReservedPath(path: []const u8) bool {
    return isStatusPath(path) or isAuditPath(path);
}

fn isReservedName(name: []const u8) bool {
    return std.mem.eql(u8, name, status_name) or std.mem.eql(u8, name, audit_name);
}

fn isTransientSidecarName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "._");
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
