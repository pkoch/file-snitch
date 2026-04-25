const std = @import("std");
const yaml = @import("yaml");
const defaults = @import("defaults.zig");
const policy = @import("policy.zig");
const runtime = @import("runtime.zig");
const c = @cImport({
    @cInclude("stdlib.h");
});

pub const Enrollment = struct {
    path: []u8,
    object_id: []u8,

    pub fn deinit(self: *Enrollment, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.object_id);
        self.* = undefined;
    }
};

pub const Decision = struct {
    executable_path: []u8,
    uid: u32,
    path: []u8,
    approval_class: []u8,
    outcome: []u8,
    expires_at: ?[]u8,

    pub fn deinit(self: *Decision, allocator: std.mem.Allocator) void {
        allocator.free(self.executable_path);
        allocator.free(self.path);
        allocator.free(self.approval_class);
        allocator.free(self.outcome);
        if (self.expires_at) |expires_at| {
            allocator.free(expires_at);
        }
        self.* = undefined;
    }
};

pub const MountPlan = struct {
    allocator: std.mem.Allocator,
    paths: [][]u8,

    pub fn deinit(self: *MountPlan) void {
        for (self.paths) |path| {
            self.allocator.free(path);
        }
        self.allocator.free(self.paths);
        self.* = undefined;
    }
};

pub const CompiledRuleViews = struct {
    allocator: std.mem.Allocator,
    // Owns the outer slice only. Each RuleView aliases PolicyFile.decisions.
    items: []policy.RuleView,

    pub fn deinit(self: *CompiledRuleViews) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

pub const PolicyLock = struct {
    allocator: std.mem.Allocator,
    lock_path: []u8,
    file: std.Io.File,

    pub fn deinit(self: *PolicyLock) void {
        self.file.unlock(runtime.io());
        self.file.close(runtime.io());
        self.allocator.free(self.lock_path);
        self.* = undefined;
    }
};

pub const PolicyMarker = struct {
    exists: bool,
    size: u64 = 0,
    mtime: i128 = 0,
    content_hash: u64 = 0,

    pub fn eql(a: PolicyMarker, b: PolicyMarker) bool {
        return a.exists == b.exists and
            a.size == b.size and
            a.mtime == b.mtime and
            a.content_hash == b.content_hash;
    }
};

pub const PolicyFile = struct {
    allocator: std.mem.Allocator,
    source_path: []u8,
    version: u32,
    enrollments: []Enrollment,
    decisions: []Decision,

    pub fn deinit(self: *PolicyFile) void {
        for (self.enrollments) |*enrollment| {
            enrollment.deinit(self.allocator);
        }
        self.allocator.free(self.enrollments);
        for (self.decisions) |*decision| {
            decision.deinit(self.allocator);
        }
        self.allocator.free(self.decisions);
        self.allocator.free(self.source_path);
        self.* = undefined;
    }

    pub fn hasEnrollments(self: *const PolicyFile) bool {
        return self.enrollments.len != 0;
    }

    pub fn findEnrollmentIndex(self: *const PolicyFile, enrolled_path: []const u8) ?usize {
        for (self.enrollments, 0..) |enrollment, index| {
            if (std.mem.eql(u8, enrollment.path, enrolled_path)) {
                return index;
            }
        }

        return null;
    }

    pub fn appendEnrollment(self: *PolicyFile, enrolled_path: []const u8, object_id: []const u8) !void {
        try validateEnrollment(.{
            .path = enrolled_path,
            .object_id = object_id,
        });

        const owned_path = try self.allocator.dupe(u8, enrolled_path);
        errdefer self.allocator.free(owned_path);
        const owned_object_id = try self.allocator.dupe(u8, object_id);
        errdefer self.allocator.free(owned_object_id);

        const previous_len = self.enrollments.len;
        self.enrollments = try self.allocator.realloc(self.enrollments, previous_len + 1);

        self.enrollments[previous_len] = .{
            .path = owned_path,
            .object_id = owned_object_id,
        };
    }

    pub fn removeEnrollmentAt(self: *PolicyFile, index: usize) Enrollment {
        const removed = self.enrollments[index];
        for (index..self.enrollments.len - 1) |cursor| {
            self.enrollments[cursor] = self.enrollments[cursor + 1];
        }

        self.enrollments = self.allocator.realloc(self.enrollments, self.enrollments.len - 1) catch self.enrollments[0 .. self.enrollments.len - 1];
        return removed;
    }

    pub fn removeDecisionsForPath(self: *PolicyFile, enrolled_path: []const u8) void {
        var write_index: usize = 0;
        var read_index: usize = 0;
        while (read_index < self.decisions.len) : (read_index += 1) {
            if (std.mem.eql(u8, self.decisions[read_index].path, enrolled_path)) {
                var removed = self.decisions[read_index];
                removed.deinit(self.allocator);
                continue;
            }

            if (write_index != read_index) {
                self.decisions[write_index] = self.decisions[read_index];
            }
            write_index += 1;
        }

        self.decisions = self.allocator.realloc(self.decisions, write_index) catch self.decisions[0..write_index];
    }

    pub fn upsertDecision(
        self: *PolicyFile,
        executable_path: []const u8,
        uid: u32,
        enrolled_path: []const u8,
        approval_class: []const u8,
        outcome: []const u8,
        expires_at: ?[]const u8,
    ) !void {
        try validateDecision(.{
            .executable_path = executable_path,
            .uid = uid,
            .path = enrolled_path,
            .approval_class = approval_class,
            .outcome = outcome,
            .expires_at = expires_at orelse "null",
        });

        for (self.decisions) |*decision| {
            if (!std.mem.eql(u8, decision.executable_path, executable_path)) continue;
            if (decision.uid != uid) continue;
            if (!std.mem.eql(u8, decision.path, enrolled_path)) continue;
            if (!std.mem.eql(u8, decision.approval_class, approval_class)) continue;

            const owned_outcome = try self.allocator.dupe(u8, outcome);
            errdefer self.allocator.free(owned_outcome);
            const owned_expires_at = if (expires_at) |value|
                try self.allocator.dupe(u8, value)
            else
                null;
            errdefer if (owned_expires_at) |value| self.allocator.free(value);

            self.allocator.free(decision.outcome);
            decision.outcome = owned_outcome;
            if (decision.expires_at) |existing| {
                self.allocator.free(existing);
            }
            decision.expires_at = owned_expires_at;
            return;
        }

        const owned_executable_path = try self.allocator.dupe(u8, executable_path);
        errdefer self.allocator.free(owned_executable_path);
        const owned_path = try self.allocator.dupe(u8, enrolled_path);
        errdefer self.allocator.free(owned_path);
        const owned_approval_class = try self.allocator.dupe(u8, approval_class);
        errdefer self.allocator.free(owned_approval_class);
        const owned_outcome = try self.allocator.dupe(u8, outcome);
        errdefer self.allocator.free(owned_outcome);
        const owned_expires_at = if (expires_at) |value|
            try self.allocator.dupe(u8, value)
        else
            null;
        errdefer if (owned_expires_at) |value| self.allocator.free(value);

        const previous_len = self.decisions.len;
        self.decisions = try self.allocator.realloc(self.decisions, previous_len + 1);

        self.decisions[previous_len] = .{
            .executable_path = owned_executable_path,
            .uid = uid,
            .path = owned_path,
            .approval_class = owned_approval_class,
            .outcome = owned_outcome,
            .expires_at = owned_expires_at,
        };
    }

    pub fn pruneExpiredDecisions(self: *PolicyFile, now_unix_seconds: i64) !bool {
        var changed = false;
        var write_index: usize = 0;
        var read_index: usize = 0;
        while (read_index < self.decisions.len) : (read_index += 1) {
            const expires_at_unix_seconds = try parseOptionalDecisionExpiration(self.decisions[read_index].expires_at);
            if (expires_at_unix_seconds) |expires_at| {
                if (now_unix_seconds >= expires_at) {
                    var removed = self.decisions[read_index];
                    removed.deinit(self.allocator);
                    changed = true;
                    continue;
                }
            }

            if (write_index != read_index) {
                self.decisions[write_index] = self.decisions[read_index];
            }
            write_index += 1;
        }

        if (changed) {
            self.decisions = self.allocator.realloc(self.decisions, write_index) catch self.decisions[0..write_index];
        }
        return changed;
    }

    pub fn nextDecisionExpirationUnixSeconds(self: *const PolicyFile) !?i64 {
        var next_expiration: ?i64 = null;

        for (self.decisions) |decision| {
            const expires_at_unix_seconds = try parseOptionalDecisionExpiration(decision.expires_at) orelse continue;
            if (next_expiration == null or expires_at_unix_seconds < next_expiration.?) {
                next_expiration = expires_at_unix_seconds;
            }
        }

        return next_expiration;
    }

    pub fn deriveMountPlan(self: *const PolicyFile, allocator: std.mem.Allocator) !MountPlan {
        var parents: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (parents.items) |path| {
                allocator.free(path);
            }
            parents.deinit(allocator);
        }

        for (self.enrollments) |enrollment| {
            const parent = std.fs.path.dirname(enrollment.path) orelse return error.InvalidEnrollmentPath;
            try parents.append(allocator, try allocator.dupe(u8, parent));
        }

        std.mem.sort([]u8, parents.items, {}, lessThanPathLength);

        var planned: std.ArrayListUnmanaged([]u8) = .empty;
        errdefer {
            for (planned.items) |path| {
                allocator.free(path);
            }
            planned.deinit(allocator);
        }

        for (parents.items) |candidate| {
            if (isCoveredByExistingMount(planned.items, candidate)) {
                continue;
            }
            try planned.append(allocator, try allocator.dupe(u8, candidate));
        }

        return .{
            .allocator = allocator,
            .paths = try planned.toOwnedSlice(allocator),
        };
    }

    pub fn compilePolicyRuleViews(self: *const PolicyFile, allocator: std.mem.Allocator) !CompiledRuleViews {
        var compiled: std.ArrayListUnmanaged(policy.RuleView) = .empty;
        errdefer compiled.deinit(allocator);

        for (self.decisions) |decision| {
            const outcome = try parseDecisionOutcome(decision.outcome);
            const access_classes = try accessClassesForApprovalClass(decision.approval_class);
            const expires_at_unix_seconds = try parseOptionalDecisionExpiration(decision.expires_at);
            for (access_classes) |access_class| {
                try compiled.append(allocator, .{
                    .path_prefix = decision.path,
                    .access_class = access_class,
                    .outcome = outcome,
                    .uid = decision.uid,
                    .executable_path = decision.executable_path,
                    .exact_path = true,
                    .expires_at_unix_seconds = expires_at_unix_seconds,
                });
            }
        }

        return .{
            .allocator = allocator,
            .items = try compiled.toOwnedSlice(allocator),
        };
    }

    pub fn saveToFile(self: *const PolicyFile) !void {
        const parent_dir_path = std.fs.path.dirname(self.source_path) orelse return error.InvalidPolicyPath;
        try ensureDirectoryPath(parent_dir_path);

        var parent_dir = try std.Io.Dir.openDirAbsolute(runtime.io(), parent_dir_path, .{});
        defer parent_dir.close(runtime.io());

        var buffer: std.ArrayList(u8) = .empty;
        defer buffer.deinit(self.allocator);
        var allocating_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &buffer);
        try self.writeYaml(&allocating_writer.writer);
        buffer = allocating_writer.toArrayList();

        var atomic_file = try parent_dir.createFileAtomic(runtime.io(), std.fs.path.basename(self.source_path), .{
            .permissions = .fromMode(0o600),
            .replace = true,
        });
        defer atomic_file.deinit(runtime.io());

        try atomic_file.file.writeStreamingAll(runtime.io(), buffer.items);
        try atomic_file.replace(runtime.io());
    }

    fn writeYaml(self: *const PolicyFile, writer: anytype) !void {
        try writer.print("version: {d}\n", .{self.version});

        if (self.enrollments.len == 0) {
            try writer.writeAll("enrollments: []\n");
        } else {
            try writer.writeAll("enrollments:\n");
            for (self.enrollments) |enrollment| {
                try writer.writeAll("  - path: ");
                try writeYamlString(writer, enrollment.path);
                try writer.writeByte('\n');
                try writer.writeAll("    object_id: ");
                try writeYamlString(writer, enrollment.object_id);
                try writer.writeByte('\n');
            }
        }

        if (self.decisions.len == 0) {
            try writer.writeAll("decisions: []\n");
            return;
        }

        try writer.writeAll("decisions:\n");
        for (self.decisions) |decision| {
            try writer.writeAll("  - executable_path: ");
            try writeYamlString(writer, decision.executable_path);
            try writer.writeByte('\n');
            try writer.print("    uid: {d}\n", .{decision.uid});
            try writer.writeAll("    path: ");
            try writeYamlString(writer, decision.path);
            try writer.writeByte('\n');
            try writer.writeAll("    approval_class: ");
            try writeYamlString(writer, decision.approval_class);
            try writer.writeByte('\n');
            try writer.writeAll("    outcome: ");
            try writeYamlString(writer, decision.outcome);
            try writer.writeByte('\n');
            try writer.writeAll("    expires_at: ");
            if (decision.expires_at) |expires_at| {
                try writeYamlString(writer, expires_at);
            } else {
                try writer.writeAll("null");
            }
            try writer.writeByte('\n');
        }
    }
};

pub fn currentPolicyMarker(allocator: std.mem.Allocator, policy_path: []const u8) !PolicyMarker {
    _ = allocator;
    var file = std.Io.Dir.cwd().openFile(runtime.io(), policy_path, .{ .mode = .read_only }) catch |err| switch (err) {
        error.FileNotFound => return .{ .exists = false },
        else => return err,
    };
    defer file.close(runtime.io());

    const stat = try file.stat(runtime.io());

    return .{
        .exists = true,
        .size = stat.size,
        .mtime = stat.mtime.toNanoseconds(),
        .content_hash = try hashPolicyContents(&file),
    };
}

fn hashPolicyContents(file: *std.Io.File) !u64 {
    var hasher = std.hash.Wyhash.init(0);
    var buffer: [4096]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const bytes_read = try file.readPositionalAll(runtime.io(), &buffer, offset);
        if (bytes_read == 0) break;
        hasher.update(buffer[0..bytes_read]);
        offset += bytes_read;
    }
    return hasher.final();
}

const RawEnrollment = struct {
    path: []const u8,
    object_id: []const u8,
};

const RawDecision = struct {
    executable_path: []const u8,
    uid: u32,
    path: []const u8,
    approval_class: []const u8,
    outcome: []const u8,
    expires_at: []const u8 = "null",
};

const RawPolicyFile = struct {
    version: u32 = 1,
    enrollments: ?[]const RawEnrollment = null,
    decisions: ?[]const RawDecision = null,
};

pub fn acquirePolicyLock(allocator: std.mem.Allocator, policy_path: []const u8) !PolicyLock {
    const lock_path = try std.fmt.allocPrint(allocator, "{s}.lock", .{policy_path});
    errdefer allocator.free(lock_path);

    const parent_dir_path = std.fs.path.dirname(lock_path) orelse return error.InvalidPolicyPath;
    try ensureDirectoryPath(parent_dir_path);

    const lock_file = std.Io.Dir.createFileAbsolute(runtime.io(), lock_path, .{
        .read = true,
        .truncate = false,
        .permissions = .fromMode(0o600),
        .lock = .exclusive,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => try std.Io.Dir.openFileAbsolute(runtime.io(), lock_path, .{ .mode = .read_write, .lock = .exclusive }),
        else => return err,
    };
    errdefer lock_file.close(runtime.io());

    return .{
        .allocator = allocator,
        .lock_path = lock_path,
        .file = lock_file,
    };
}

fn ensureDirectoryPath(path: []const u8) !void {
    if (std.Io.Dir.cwd().statFile(runtime.io(), path, .{})) |stat| {
        if (stat.kind == .directory) return;
        return error.NotDir;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    try std.Io.Dir.cwd().createDirPath(runtime.io(), path);
}

pub fn loadFromFile(allocator: std.mem.Allocator, path: []const u8) !PolicyFile {
    const source_path = try allocator.dupe(u8, path);
    errdefer allocator.free(source_path);

    const source = loadPolicySource(allocator, path) catch |err| switch (err) {
        error.FileNotFound => return try emptyPolicy(allocator, source_path),
        else => return err,
    };
    defer allocator.free(source);

    if (std.mem.trim(u8, source, &std.ascii.whitespace).len == 0) {
        return try emptyPolicy(allocator, source_path);
    }

    var document: yaml.Yaml = .{ .source = source };
    defer document.deinit(allocator);

    document.load(allocator) catch |err| switch (err) {
        error.ParseFailure => {
            if (document.parse_errors.errorMessageCount() > 0) {
                try document.parse_errors.renderToStderr(runtime.io(), .{}, .off);
            }
            return error.InvalidPolicyFile;
        },
        else => return err,
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const raw = parseRawPolicyDocument(arena.allocator(), document.docs.items[0]) catch {
        return error.InvalidPolicyFile;
    };

    if (raw.version != 1) {
        return error.UnsupportedPolicyVersion;
    }

    const enrollments = try copyEnrollments(allocator, raw.enrollments orelse &.{});
    errdefer freeEnrollmentsAndSlice(allocator, enrollments);
    const decisions = try copyDecisions(allocator, raw.decisions orelse &.{});
    errdefer freeDecisionsAndSlice(allocator, decisions);

    return .{
        .allocator = allocator,
        .source_path = source_path,
        .version = raw.version,
        .enrollments = enrollments,
        .decisions = decisions,
    };
}

pub fn defaultPolicyPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (runtime.getEnvVarOwned(allocator, defaults.policy_path_env)) |policy_path| {
        return policy_path;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    const base = try defaults.xdgBasePathAlloc(allocator, "XDG_CONFIG_HOME", ".config");
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, "file-snitch", "policy.yml" });
}

fn loadPolicySource(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(runtime.io(), path, .{ .mode = .read_only });
    defer file.close(runtime.io());
    var file_reader = file.reader(runtime.io(), &.{});
    return file_reader.interface.allocRemaining(allocator, .limited(1024 * 1024));
}

fn emptyPolicy(allocator: std.mem.Allocator, source_path: []u8) !PolicyFile {
    return .{
        .allocator = allocator,
        .source_path = source_path,
        .version = 1,
        .enrollments = try allocator.alloc(Enrollment, 0),
        .decisions = try allocator.alloc(Decision, 0),
    };
}

fn parseRawPolicyDocument(arena: std.mem.Allocator, root: yaml.Yaml.Value) !RawPolicyFile {
    const map = try valueAsMap(root);

    var raw = RawPolicyFile{};
    if (mapGet(map, "version")) |value| {
        raw.version = @intCast(try valueAsInt(value));
    }
    if (mapGet(map, "enrollments")) |value| {
        raw.enrollments = try parseRawEnrollments(arena, value);
    }
    if (mapGet(map, "decisions")) |value| {
        raw.decisions = try parseRawDecisions(arena, value);
    }
    return raw;
}

fn parseRawEnrollments(arena: std.mem.Allocator, value: yaml.Yaml.Value) ![]const RawEnrollment {
    const list = try valueAsList(value);
    var enrollments = try arena.alloc(RawEnrollment, list.len);
    for (list, 0..) |entry, index| {
        const map = try valueAsMap(entry);
        enrollments[index] = .{
            .path = try requiredStringField(arena, map, "path"),
            .object_id = try requiredStringField(arena, map, "object_id"),
        };
    }
    return enrollments;
}

fn parseRawDecisions(arena: std.mem.Allocator, value: yaml.Yaml.Value) ![]const RawDecision {
    const list = try valueAsList(value);
    var decisions = try arena.alloc(RawDecision, list.len);
    for (list, 0..) |entry, index| {
        const map = try valueAsMap(entry);
        decisions[index] = .{
            .executable_path = try requiredStringField(arena, map, "executable_path"),
            .uid = @intCast(try requiredIntField(map, "uid")),
            .path = try requiredStringField(arena, map, "path"),
            .approval_class = try requiredStringField(arena, map, "approval_class"),
            .outcome = try requiredStringField(arena, map, "outcome"),
            .expires_at = try optionalExpirationField(map, "expires_at", "null"),
        };
    }
    return decisions;
}

fn requiredStringField(arena: std.mem.Allocator, map: yaml.Yaml.Map, field_name: []const u8) ![]const u8 {
    const value = mapGet(map, field_name) orelse return error.StructFieldMissing;
    return try scalarFieldToString(arena, value);
}

fn requiredIntField(map: yaml.Yaml.Map, field_name: []const u8) !i64 {
    const value = mapGet(map, field_name) orelse return error.StructFieldMissing;
    return try valueAsInt(value);
}

fn optionalScalarField(
    arena: std.mem.Allocator,
    map: yaml.Yaml.Map,
    field_name: []const u8,
    default_value: []const u8,
) ![]const u8 {
    const value = mapGet(map, field_name) orelse return default_value;
    return try scalarFieldToString(arena, value);
}

fn optionalExpirationField(map: yaml.Yaml.Map, field_name: []const u8, default_value: []const u8) ![]const u8 {
    const value = mapGet(map, field_name) orelse return default_value;
    return switch (value) {
        .scalar => |scalar| scalar,
        .empty => default_value,
        else => error.TypeMismatch,
    };
}

fn scalarFieldToString(_: std.mem.Allocator, value: yaml.Yaml.Value) ![]const u8 {
    return switch (value) {
        .scalar => |scalar| scalar,
        .empty => "null",
        else => error.TypeMismatch,
    };
}

fn valueAsMap(value: yaml.Yaml.Value) !yaml.Yaml.Map {
    return value.asMap() orelse error.TypeMismatch;
}

fn valueAsList(value: yaml.Yaml.Value) !yaml.Yaml.List {
    return value.asList() orelse error.TypeMismatch;
}

fn valueAsInt(value: yaml.Yaml.Value) !i64 {
    const scalar = value.asScalar() orelse return error.TypeMismatch;
    return try std.fmt.parseInt(i64, scalar, 0);
}

fn mapGet(map: yaml.Yaml.Map, field_name: []const u8) ?yaml.Yaml.Value {
    if (map.get(field_name)) |value| {
        return value;
    }
    return null;
}

fn copyEnrollments(allocator: std.mem.Allocator, raw_enrollments: []const RawEnrollment) ![]Enrollment {
    const enrollments = try allocator.alloc(Enrollment, raw_enrollments.len);
    var initialized: usize = 0;
    errdefer {
        freeEnrollments(allocator, enrollments[0..initialized]);
        allocator.free(enrollments);
    }

    for (raw_enrollments, 0..) |raw, index| {
        try validateEnrollment(raw);
        const owned_path = try allocator.dupe(u8, raw.path);
        errdefer allocator.free(owned_path);
        const owned_object_id = try allocator.dupe(u8, raw.object_id);
        errdefer allocator.free(owned_object_id);
        enrollments[index] = .{
            .path = owned_path,
            .object_id = owned_object_id,
        };
        initialized += 1;
    }

    return enrollments;
}

fn freeEnrollments(allocator: std.mem.Allocator, enrollments: []Enrollment) void {
    for (enrollments) |*enrollment| {
        enrollment.deinit(allocator);
    }
}

fn freeEnrollmentsAndSlice(allocator: std.mem.Allocator, enrollments: []Enrollment) void {
    freeEnrollments(allocator, enrollments);
    allocator.free(enrollments);
}

fn copyDecisions(allocator: std.mem.Allocator, raw_decisions: []const RawDecision) ![]Decision {
    const decisions = try allocator.alloc(Decision, raw_decisions.len);
    var initialized: usize = 0;
    errdefer {
        freeDecisions(allocator, decisions[0..initialized]);
        allocator.free(decisions);
    }

    for (raw_decisions, 0..) |raw, index| {
        try validateDecision(raw);
        const owned_executable_path = try allocator.dupe(u8, raw.executable_path);
        errdefer allocator.free(owned_executable_path);
        const owned_path = try allocator.dupe(u8, raw.path);
        errdefer allocator.free(owned_path);
        const owned_approval_class = try allocator.dupe(u8, raw.approval_class);
        errdefer allocator.free(owned_approval_class);
        const owned_outcome = try allocator.dupe(u8, raw.outcome);
        errdefer allocator.free(owned_outcome);
        const owned_expires_at = if (normalizeScalar(raw.expires_at)) |expires_at|
            try allocator.dupe(u8, expires_at)
        else
            null;
        errdefer if (owned_expires_at) |value| allocator.free(value);
        decisions[index] = .{
            .executable_path = owned_executable_path,
            .uid = raw.uid,
            .path = owned_path,
            .approval_class = owned_approval_class,
            .outcome = owned_outcome,
            .expires_at = owned_expires_at,
        };
        initialized += 1;
    }

    return decisions;
}

fn freeDecisions(allocator: std.mem.Allocator, decisions: []Decision) void {
    for (decisions) |*decision| {
        decision.deinit(allocator);
    }
}

fn freeDecisionsAndSlice(allocator: std.mem.Allocator, decisions: []Decision) void {
    freeDecisions(allocator, decisions);
    allocator.free(decisions);
}

fn validateEnrollment(raw: RawEnrollment) !void {
    if (!std.fs.path.isAbsolute(raw.path) or raw.path.len <= 1) {
        return error.InvalidEnrollmentPath;
    }
    if (raw.object_id.len == 0) {
        return error.InvalidEnrollmentObjectId;
    }
}

fn validateDecision(raw: RawDecision) !void {
    if (raw.executable_path.len == 0) {
        return error.InvalidDecisionExecutablePath;
    }
    if (!std.fs.path.isAbsolute(raw.path) or raw.path.len <= 1) {
        return error.InvalidDecisionPath;
    }
    if (raw.approval_class.len == 0 or raw.outcome.len == 0) {
        return error.InvalidDecision;
    }

    _ = try parseDecisionOutcome(raw.outcome);
    _ = try accessClassesForApprovalClass(raw.approval_class);
    _ = try parseRawDecisionExpiration(raw.expires_at);
}

fn normalizeScalar(value: []const u8) ?[]const u8 {
    const raw = value;
    if (std.ascii.eqlIgnoreCase(raw, "null")) {
        return null;
    }
    if (std.mem.eql(u8, raw, "~")) {
        return null;
    }
    return raw;
}

fn normalizeOptionalScalar(value: ?[]const u8) ?[]const u8 {
    const raw = value orelse return null;
    return normalizeScalar(raw);
}

fn parseRawDecisionExpiration(value: []const u8) !?i64 {
    const normalized = normalizeScalar(value) orelse return null;
    return try parseExpirationTimestamp(normalized);
}

fn parseOptionalDecisionExpiration(value: ?[]const u8) !?i64 {
    const normalized = normalizeOptionalScalar(value) orelse return null;
    return try parseExpirationTimestamp(normalized);
}

fn parseExpirationTimestamp(value: []const u8) !i64 {
    return parseRfc3339UtcSeconds(value);
}

fn parseRfc3339UtcSeconds(value: []const u8) !i64 {
    if (value.len != 20 or
        value[4] != '-' or
        value[7] != '-' or
        value[10] != 'T' or
        value[13] != ':' or
        value[16] != ':' or
        value[19] != 'Z')
    {
        return error.InvalidDecisionExpiration;
    }

    const year = try std.fmt.parseInt(i64, value[0..4], 10);
    const month = try std.fmt.parseInt(u8, value[5..7], 10);
    const day = try std.fmt.parseInt(u8, value[8..10], 10);
    const hour = try std.fmt.parseInt(u8, value[11..13], 10);
    const minute = try std.fmt.parseInt(u8, value[14..16], 10);
    const second = try std.fmt.parseInt(u8, value[17..19], 10);

    if (month < 1 or month > 12) return error.InvalidDecisionExpiration;
    if (day < 1 or day > daysInMonth(year, month)) return error.InvalidDecisionExpiration;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidDecisionExpiration;

    const days_since_epoch = try daysSinceUnixEpoch(year, month, day);
    const seconds_per_day = std.time.s_per_day;
    const day_seconds = try std.math.mul(i64, days_since_epoch, seconds_per_day);
    const time_seconds = @as(i64, hour) * std.time.s_per_hour +
        @as(i64, minute) * std.time.s_per_min +
        second;
    return try std.math.add(i64, day_seconds, time_seconds);
}

fn daysInMonth(year: i64, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: i64) bool {
    return (@mod(year, 4) == 0 and @mod(year, 100) != 0) or @mod(year, 400) == 0;
}

fn daysSinceUnixEpoch(year: i64, month: u8, day: u8) !i64 {
    var adjusted_year = year;
    if (month <= 2) adjusted_year -= 1;

    const era = @divFloor(if (adjusted_year >= 0) adjusted_year else adjusted_year - 399, 400);
    const year_of_era = adjusted_year - era * 400;
    const adjusted_month: i64 = if (month > 2) month - 3 else month + 9;
    const day_of_year = @divFloor(153 * adjusted_month + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) - @divFloor(year_of_era, 100) + day_of_year;
    return try std.math.sub(i64, era * 146097 + day_of_era, 719468);
}

fn writeYamlString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('\'');
    for (value) |byte| {
        if (byte == '\'') {
            try writer.writeAll("''");
        } else {
            try writer.writeByte(byte);
        }
    }
    try writer.writeByte('\'');
}

fn parseDecisionOutcome(value: []const u8) !policy.Outcome {
    if (std.mem.eql(u8, value, "allow")) return .allow;
    if (std.mem.eql(u8, value, "deny")) return .deny;
    if (std.mem.eql(u8, value, "prompt")) return .prompt;
    return error.InvalidDecisionOutcome;
}

fn accessClassesForApprovalClass(value: []const u8) ![]const policy.AccessClass {
    if (std.mem.eql(u8, value, "read_like")) {
        return &.{.read};
    }
    if (std.mem.eql(u8, value, "write_capable")) {
        return &.{
            .create,
            .write,
            .rename,
            .delete,
            .metadata,
            .xattr,
        };
    }
    return error.InvalidApprovalClass;
}

fn lessThanPathLength(_: void, left: []u8, right: []u8) bool {
    if (left.len != right.len) {
        return left.len < right.len;
    }
    return std.mem.lessThan(u8, left, right);
}

fn isCoveredByExistingMount(existing: []const []u8, candidate: []const u8) bool {
    for (existing) |mount_path| {
        if (std.mem.eql(u8, mount_path, candidate)) {
            return true;
        }
        if (isDescendantPath(mount_path, candidate)) {
            return true;
        }
    }
    return false;
}

fn isDescendantPath(base: []const u8, candidate: []const u8) bool {
    if (!std.mem.startsWith(u8, candidate, base)) {
        return false;
    }
    if (candidate.len == base.len) {
        return true;
    }
    if (std.mem.eql(u8, base, "/")) {
        return true;
    }
    return candidate[base.len] == '/';
}

test "parse decision expiration accepts RFC3339 UTC" {
    try std.testing.expectEqual(@as(?i64, null), try parseOptionalDecisionExpiration(null));
    try std.testing.expectEqual(@as(?i64, null), try parseRawDecisionExpiration("null"));
    try std.testing.expectEqual(@as(?i64, 4_102_444_800), try parseRawDecisionExpiration("2100-01-01T00:00:00Z"));
}

test "default policy path uses FILE_SNITCH_POLICY_PATH override" {
    const allocator = std.testing.allocator;
    const policy_key = defaults.policy_path_env;
    const policy_value = "/tmp/file-snitch-test-policy.yml";
    const xdg_key = "XDG_CONFIG_HOME";
    const xdg_value = "/tmp/file-snitch-test-config-home";
    const home_key = "HOME";
    const home_value = "/tmp/file-snitch-test-home";

    try std.testing.expectEqual(@as(c_int, 0), c.setenv(policy_key, policy_value, 1));
    defer _ = c.unsetenv(policy_key);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(xdg_key, xdg_value, 1));
    defer _ = c.unsetenv(xdg_key);
    try std.testing.expectEqual(@as(c_int, 0), c.setenv(home_key, home_value, 1));
    defer _ = c.unsetenv(home_key);

    const resolved = try defaultPolicyPathAlloc(allocator);
    defer allocator.free(resolved);
    try std.testing.expectEqualStrings(policy_value, resolved);
}

test "parse decision expiration rejects invalid values" {
    try std.testing.expectError(error.InvalidDecisionExpiration, parseRawDecisionExpiration("later-ish"));
    try std.testing.expectError(error.InvalidDecisionExpiration, parseRawDecisionExpiration("4102444800"));
    try std.testing.expectError(error.InvalidDecisionExpiration, parseRawDecisionExpiration("2026-13-01T00:00:00Z"));
}

fn checkAppendEnrollmentAllocationFailures(allocator: std.mem.Allocator) !void {
    const source_path = try allocator.dupe(u8, "/tmp/file-snitch-alloc-failure.yml");
    var policy_file = try emptyPolicy(allocator, source_path);
    defer policy_file.deinit();

    try policy_file.appendEnrollment("/tmp/demo-secret", "object-1");
}

test "appendEnrollment handles allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkAppendEnrollmentAllocationFailures,
        .{},
    );
}

fn checkUpsertDecisionInsertAllocationFailures(allocator: std.mem.Allocator) !void {
    const source_path = try allocator.dupe(u8, "/tmp/file-snitch-alloc-failure.yml");
    var policy_file = try emptyPolicy(allocator, source_path);
    defer policy_file.deinit();

    try policy_file.upsertDecision(
        "/bin/cat",
        501,
        "/tmp/demo-secret",
        "read_like",
        "allow",
        "2026-04-10T12:00:00Z",
    );
}

test "upsertDecision insert handles allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkUpsertDecisionInsertAllocationFailures,
        .{},
    );
}

fn checkUpsertDecisionUpdateAllocationFailures(allocator: std.mem.Allocator) !void {
    const source_path = try allocator.dupe(u8, "/tmp/file-snitch-alloc-failure.yml");
    var policy_file = try emptyPolicy(allocator, source_path);
    defer policy_file.deinit();

    try policy_file.upsertDecision(
        "/bin/cat",
        501,
        "/tmp/demo-secret",
        "read_like",
        "allow",
        null,
    );
    try policy_file.upsertDecision(
        "/bin/cat",
        501,
        "/tmp/demo-secret",
        "read_like",
        "deny",
        "2026-04-10T12:00:00Z",
    );
}

test "upsertDecision update handles allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkUpsertDecisionUpdateAllocationFailures,
        .{},
    );
}

fn checkCopyEnrollmentsAllocationFailures(allocator: std.mem.Allocator) !void {
    const enrollments = try copyEnrollments(allocator, &.{.{
        .path = "/tmp/demo-secret",
        .object_id = "object-1",
    }});
    defer freeEnrollmentsAndSlice(allocator, enrollments);
}

test "copyEnrollments handles allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCopyEnrollmentsAllocationFailures,
        .{},
    );
}

fn checkCopyDecisionsAllocationFailures(allocator: std.mem.Allocator) !void {
    const decisions = try copyDecisions(allocator, &.{.{
        .executable_path = "/bin/cat",
        .uid = 501,
        .path = "/tmp/demo-secret",
        .approval_class = "read_like",
        .outcome = "allow",
        .expires_at = "2026-04-10T12:00:00Z",
    }});
    defer freeDecisionsAndSlice(allocator, decisions);
}

test "copyDecisions handles allocation failures" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCopyDecisionsAllocationFailures,
        .{},
    );
}
