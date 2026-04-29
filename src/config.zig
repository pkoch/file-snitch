const std = @import("std");
const yaml = @import("yaml");
const defaults = @import("defaults.zig");
const policy = @import("policy.zig");
const runtime = @import("runtime.zig");
const rfc3339 = @import("rfc3339.zig");
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

pub const ProjectionEntry = struct {
    target_path: []u8,
    projection_path: []u8,
    object_id: []u8,

    fn deinit(self: *ProjectionEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.target_path);
        allocator.free(self.projection_path);
        allocator.free(self.object_id);
        self.* = undefined;
    }
};

pub const ProjectionPlan = struct {
    allocator: std.mem.Allocator,
    root_path: []u8,
    entries: []ProjectionEntry,

    pub fn deinit(self: *ProjectionPlan) void {
        for (self.entries) |*entry| {
            entry.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
        self.allocator.free(self.root_path);
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

    fn findEnrollmentObjectIdIndex(self: *const PolicyFile, object_id: []const u8) ?usize {
        for (self.enrollments, 0..) |enrollment, index| {
            if (std.mem.eql(u8, enrollment.object_id, object_id)) {
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
        if (self.findEnrollmentObjectIdIndex(object_id) != null) {
            return error.InvalidEnrollmentObjectId;
        }

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
        enrolled_path: []const u8,
        approval_class: []const u8,
        outcome: []const u8,
        expires_at: ?[]const u8,
    ) !void {
        try validateDecision(.{
            .executable_path = executable_path,
            .path = enrolled_path,
            .approval_class = approval_class,
            .outcome = outcome,
            .expires_at = expires_at orelse "null",
        });

        for (self.decisions) |*decision| {
            if (!std.mem.eql(u8, decision.executable_path, executable_path)) continue;
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

    pub fn deriveProjectionPlan(self: *const PolicyFile, allocator: std.mem.Allocator) !ProjectionPlan {
        const root_path = try defaultProjectionRootPathAlloc(allocator);
        errdefer allocator.free(root_path);

        // Keep entries in enrollment order; policy doctor pairs them with
        // enrollments when reporting target/projection state.
        var entries = try allocator.alloc(ProjectionEntry, self.enrollments.len);
        errdefer allocator.free(entries);

        var initialized: usize = 0;
        errdefer {
            for (entries[0..initialized]) |*entry| {
                entry.deinit(allocator);
            }
        }

        for (self.enrollments) |enrollment| {
            const projection_path = try std.fs.path.join(allocator, &.{ root_path, enrollment.object_id });
            errdefer allocator.free(projection_path);
            const target_path = try allocator.dupe(u8, enrollment.path);
            errdefer allocator.free(target_path);
            const object_id = try allocator.dupe(u8, enrollment.object_id);
            errdefer allocator.free(object_id);

            entries[initialized] = .{
                .target_path = target_path,
                .projection_path = projection_path,
                .object_id = object_id,
            };
            initialized += 1;
        }

        return .{
            .allocator = allocator,
            .root_path = root_path,
            .entries = entries,
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
                const serialized_path = try homeRelativePolicyPathAlloc(self.allocator, enrollment.path);
                defer self.allocator.free(serialized_path);

                try writer.writeAll("  - path: ");
                try writeYamlString(writer, serialized_path);
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
            const serialized_path = try homeRelativePolicyPathAlloc(self.allocator, decision.path);
            defer self.allocator.free(serialized_path);

            try writer.writeAll("  - executable_path: ");
            try writeYamlString(writer, decision.executable_path);
            try writer.writeByte('\n');
            try writer.writeAll("    path: ");
            try writeYamlString(writer, serialized_path);
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

pub fn defaultProjectionRootPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    const base = try defaults.xdgBasePathAlloc(allocator, defaults.xdg_state_path_env, ".local/state");
    defer allocator.free(base);
    return std.fs.path.join(allocator, &.{ base, "file-snitch", "projection" });
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
    const map = try root.asMap();

    var raw = RawPolicyFile{};
    if (mapGet(map, "version")) |value| {
        raw.version = @intCast(try value.asInt());
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
    const list = try value.asList();
    var enrollments = try arena.alloc(RawEnrollment, list.len);
    for (list, 0..) |entry, index| {
        const map = try entry.asMap();
        enrollments[index] = .{
            .path = try requiredStringField(arena, map, "path"),
            .object_id = try requiredStringField(arena, map, "object_id"),
        };
    }
    return enrollments;
}

fn parseRawDecisions(arena: std.mem.Allocator, value: yaml.Yaml.Value) ![]const RawDecision {
    const list = try value.asList();
    var decisions = try arena.alloc(RawDecision, list.len);
    for (list, 0..) |entry, index| {
        const map = try entry.asMap();
        decisions[index] = .{
            .executable_path = try requiredStringField(arena, map, "executable_path"),
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
    return try value.asInt();
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
        .string => |string| string,
        .empty => default_value,
        else => error.TypeMismatch,
    };
}

fn scalarFieldToString(arena: std.mem.Allocator, value: yaml.Yaml.Value) ![]const u8 {
    return switch (value) {
        .string => |string| string,
        .int => |int| try std.fmt.allocPrint(arena, "{d}", .{int}),
        .empty => "null",
        else => error.TypeMismatch,
    };
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
        const owned_path = try expandHomeRelativePolicyPathAlloc(allocator, raw.path);
        errdefer allocator.free(owned_path);
        try validateEnrollment(.{
            .path = owned_path,
            .object_id = raw.object_id,
        });
        try requirePolicyPathWithinHome(allocator, owned_path, error.InvalidEnrollmentPath);
        for (enrollments[0..initialized]) |existing| {
            if (std.mem.eql(u8, existing.object_id, raw.object_id)) {
                return error.InvalidEnrollmentObjectId;
            }
        }
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
        const owned_path = try expandHomeRelativePolicyPathAlloc(allocator, raw.path);
        errdefer allocator.free(owned_path);
        try validateDecision(.{
            .executable_path = raw.executable_path,
            .path = owned_path,
            .approval_class = raw.approval_class,
            .outcome = raw.outcome,
            .expires_at = raw.expires_at,
        });
        try requirePolicyPathWithinHome(allocator, owned_path, error.InvalidDecisionPath);
        const owned_executable_path = try allocator.dupe(u8, raw.executable_path);
        errdefer allocator.free(owned_executable_path);
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
    if (raw.object_id.len == 0 or raw.object_id[0] == '.') {
        return error.InvalidEnrollmentObjectId;
    }
    for (raw.object_id) |byte| {
        if (!isEnrollmentObjectIdByte(byte)) {
            return error.InvalidEnrollmentObjectId;
        }
    }
}

fn isEnrollmentObjectIdByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.';
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
    if (std.mem.eql(u8, raw, "null")) {
        return null;
    }
    return raw;
}

fn normalizeOptionalScalar(value: ?[]const u8) ?[]const u8 {
    const raw = value orelse return null;
    return normalizeScalar(raw);
}

fn expandHomeRelativePolicyPathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    if (!isHomeRelativePolicyPath(path)) {
        return allocator.dupe(u8, path);
    }

    const home_dir = try currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);

    if (path.len == 1) {
        return allocator.dupe(u8, home_dir);
    }

    return std.fs.path.join(allocator, &.{ home_dir, path[2..] });
}

fn homeRelativePolicyPathAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const home_dir = currentUserHomeAlloc(allocator) catch |err| switch (err) {
        error.EnvironmentVariableNotFound, error.FileNotFound => return allocator.dupe(u8, path),
        else => return err,
    };
    defer allocator.free(home_dir);

    if (std.mem.eql(u8, path, home_dir)) {
        return allocator.dupe(u8, "~");
    }
    if (isDescendantPath(home_dir, path)) {
        const relative_path = if (std.mem.eql(u8, home_dir, "/"))
            path[1..]
        else
            path[home_dir.len + 1 ..];
        return std.fmt.allocPrint(allocator, "~/{s}", .{relative_path});
    }
    return allocator.dupe(u8, path);
}

fn isHomeRelativePolicyPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "~") or std.mem.startsWith(u8, path, "~/");
}

fn requirePolicyPathWithinHome(allocator: std.mem.Allocator, path: []const u8, err: anyerror) !void {
    const home_dir = try currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);

    if (!isDescendantPath(home_dir, path)) {
        return err;
    }
}

fn currentUserHomeAlloc(allocator: std.mem.Allocator) ![]u8 {
    const home = try runtime.getEnvVarOwned(allocator, "HOME");
    errdefer allocator.free(home);
    var canonical_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const canonical_len = try std.Io.Dir.realPathFileAbsolute(runtime.io(), home, &canonical_buffer);
    const canonical = try allocator.dupe(u8, canonical_buffer[0..canonical_len]);
    allocator.free(home);
    return canonical;
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
    return rfc3339.parseUtcSeconds(value) catch |err| switch (err) {
        error.InvalidRfc3339Utc => return error.InvalidDecisionExpiration,
    };
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
    try std.testing.expectError(error.InvalidDecisionExpiration, parseRawDecisionExpiration("NULL"));
    try std.testing.expectError(error.InvalidDecisionExpiration, parseRawDecisionExpiration("Null"));
    try std.testing.expectError(error.InvalidDecisionExpiration, parseRawDecisionExpiration("~"));
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
        "/tmp/demo-secret",
        "read_like",
        "allow",
        null,
    );
    try policy_file.upsertDecision(
        "/bin/cat",
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

fn setHomeForTest(home: [:0]const u8) !?[:0]u8 {
    const allocator = std.testing.allocator;
    const old_home = runtime.getEnvVarOwned(allocator, "HOME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    errdefer if (old_home) |value| allocator.free(value);

    const old_home_z = if (old_home) |value| blk: {
        const value_z = try allocator.dupeZ(u8, value);
        allocator.free(value);
        break :blk value_z;
    } else null;
    errdefer if (old_home_z) |value| allocator.free(value);

    try std.testing.expectEqual(@as(c_int, 0), c.setenv("HOME", home.ptr, 1));
    return old_home_z;
}

fn restoreHomeForTest(old_home_z: ?[:0]u8) void {
    const allocator = std.testing.allocator;
    if (old_home_z) |value| {
        _ = c.setenv("HOME", value.ptr, 1);
        allocator.free(value);
    } else {
        _ = c.unsetenv("HOME");
    }
}

fn checkCopyEnrollmentsAllocationFailures(allocator: std.mem.Allocator) !void {
    const enrollments = try copyEnrollments(allocator, &.{.{
        .path = "/tmp/demo-secret",
        .object_id = "object-1",
    }});
    defer freeEnrollmentsAndSlice(allocator, enrollments);
}

test "copyEnrollments handles allocation failures" {
    const old_home_z = try setHomeForTest("/");
    defer restoreHomeForTest(old_home_z);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCopyEnrollmentsAllocationFailures,
        .{},
    );
}

fn checkCopyDecisionsAllocationFailures(allocator: std.mem.Allocator) !void {
    const decisions = try copyDecisions(allocator, &.{.{
        .executable_path = "/bin/cat",
        .path = "/tmp/demo-secret",
        .approval_class = "read_like",
        .outcome = "allow",
        .expires_at = "2026-04-10T12:00:00Z",
    }});
    defer freeDecisionsAndSlice(allocator, decisions);
}

test "copyDecisions handles allocation failures" {
    const old_home_z = try setHomeForTest("/");
    defer restoreHomeForTest(old_home_z);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCopyDecisionsAllocationFailures,
        .{},
    );
}
