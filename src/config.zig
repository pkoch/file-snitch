const std = @import("std");
const yaml = @import("yaml");

pub const Enrollment = struct {
    path: []u8,
    object_id: []u8,

    fn deinit(self: *Enrollment, allocator: std.mem.Allocator) void {
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

    fn deinit(self: *Decision, allocator: std.mem.Allocator) void {
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

    pub fn deriveMountPlan(self: *const PolicyFile, allocator: std.mem.Allocator) !MountPlan {
        var parents: std.ArrayListUnmanaged([]u8) = .{};
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

        var planned: std.ArrayListUnmanaged([]u8) = .{};
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
};

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
    expires_at: ?[]const u8 = null,
};

const RawPolicyFile = struct {
    version: u32 = 1,
    enrollments: ?[]const RawEnrollment = null,
    decisions: ?[]const RawDecision = null,
};

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
                document.parse_errors.renderToStdErr(.{
                    .ttyconf = std.io.tty.detectConfig(std.fs.File.stderr()),
                });
            }
            return error.InvalidPolicyFile;
        },
        else => return err,
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const raw = document.parse(arena.allocator(), RawPolicyFile) catch {
        return error.InvalidPolicyFile;
    };

    if (raw.version != 1) {
        return error.UnsupportedPolicyVersion;
    }

    const enrollments = try copyEnrollments(allocator, raw.enrollments orelse &.{});
    errdefer freeEnrollments(allocator, enrollments);
    const decisions = try copyDecisions(allocator, raw.decisions orelse &.{});
    errdefer freeDecisions(allocator, decisions);

    return .{
        .allocator = allocator,
        .source_path = source_path,
        .version = raw.version,
        .enrollments = enrollments,
        .decisions = decisions,
    };
}

pub fn defaultPolicyPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, "XDG_CONFIG_HOME")) |xdg_config_home| {
        defer allocator.free(xdg_config_home);
        return std.fmt.allocPrint(allocator, "{s}/file-snitch/policy.yml", .{xdg_config_home});
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fmt.allocPrint(allocator, "{s}/.config/file-snitch/policy.yml", .{home});
}

pub fn defaultGuardedObjectPathAlloc(allocator: std.mem.Allocator, object_id: []const u8) ![]u8 {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fmt.allocPrint(
        allocator,
        "{s}/.var/file-snitch/guarded-secrets/{s}",
        .{ home, object_id },
    );
}

fn loadPolicySource(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });
    defer file.close();
    return file.readToEndAlloc(allocator, 1024 * 1024);
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

fn copyEnrollments(allocator: std.mem.Allocator, raw_enrollments: []const RawEnrollment) ![]Enrollment {
    const enrollments = try allocator.alloc(Enrollment, raw_enrollments.len);
    var initialized: usize = 0;
    errdefer {
        freeEnrollments(allocator, enrollments[0..initialized]);
        allocator.free(enrollments);
    }

    for (raw_enrollments, 0..) |raw, index| {
        try validateEnrollment(raw);
        enrollments[index] = .{
            .path = try allocator.dupe(u8, raw.path),
            .object_id = try allocator.dupe(u8, raw.object_id),
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

fn copyDecisions(allocator: std.mem.Allocator, raw_decisions: []const RawDecision) ![]Decision {
    const decisions = try allocator.alloc(Decision, raw_decisions.len);
    var initialized: usize = 0;
    errdefer {
        freeDecisions(allocator, decisions[0..initialized]);
        allocator.free(decisions);
    }

    for (raw_decisions, 0..) |raw, index| {
        try validateDecision(raw);
        decisions[index] = .{
            .executable_path = try allocator.dupe(u8, raw.executable_path),
            .uid = raw.uid,
            .path = try allocator.dupe(u8, raw.path),
            .approval_class = try allocator.dupe(u8, raw.approval_class),
            .outcome = try allocator.dupe(u8, raw.outcome),
            .expires_at = if (normalizeOptionalScalar(raw.expires_at)) |expires_at|
                try allocator.dupe(u8, expires_at)
            else
                null,
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
}

fn normalizeOptionalScalar(value: ?[]const u8) ?[]const u8 {
    const raw = value orelse return null;
    if (std.ascii.eqlIgnoreCase(raw, "null")) {
        return null;
    }
    if (std.mem.eql(u8, raw, "~")) {
        return null;
    }
    return raw;
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
