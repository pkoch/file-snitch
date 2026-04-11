const std = @import("std");

pub const AccessClass = enum(u32) {
    read = 1,
    create = 2,
    write = 3,
    rename = 4,
    delete = 5,
    metadata = 6,
    xattr = 7,
};

pub const Outcome = enum(u32) {
    allow = 1,
    deny = 2,
    prompt = 3,
};

pub const RuleView = struct {
    path_prefix: []const u8,
    access_class: AccessClass,
    outcome: Outcome,
    uid: ?u32 = null,
    executable_path: ?[]const u8 = null,
    exact_path: bool = false,
    expires_at_unix_seconds: ?i64 = null,
};

pub const Request = struct {
    path: []const u8,
    access_class: AccessClass,
    pid: u32,
    uid: u32,
    gid: u32,
    executable_path: ?[]const u8 = null,
};

const StoredRule = struct {
    path_prefix: []u8,
    access_class: AccessClass,
    outcome: Outcome,
    uid: ?u32,
    executable_path: ?[]u8,
    exact_path: bool,
    expires_at_unix_seconds: ?i64,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    default_mutation_outcome: Outcome,
    rules: std.ArrayListUnmanaged(StoredRule) = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        default_mutation_outcome: Outcome,
        source_rules: []const RuleView,
    ) !Engine {
        var engine = Engine{
            .allocator = allocator,
            .default_mutation_outcome = default_mutation_outcome,
        };
        errdefer engine.deinit();

        for (source_rules) |rule| {
            const path_prefix = try allocator.dupe(u8, rule.path_prefix);
            errdefer allocator.free(path_prefix);
            const executable_path = if (rule.executable_path) |value|
                try allocator.dupe(u8, value)
            else
                null;
            errdefer if (executable_path) |value| allocator.free(value);

            try engine.rules.append(allocator, .{
                .path_prefix = path_prefix,
                .access_class = rule.access_class,
                .outcome = rule.outcome,
                .uid = rule.uid,
                .executable_path = executable_path,
                .exact_path = rule.exact_path,
                .expires_at_unix_seconds = rule.expires_at_unix_seconds,
            });
        }

        return engine;
    }

    pub fn deinit(self: *Engine) void {
        for (self.rules.items) |rule| {
            self.allocator.free(rule.path_prefix);
            if (rule.executable_path) |value| {
                self.allocator.free(value);
            }
        }
        self.rules.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn evaluate(self: *const Engine, request: Request) Outcome {
        return self.evaluateAt(request, std.time.timestamp());
    }

    pub fn evaluateAt(self: *const Engine, request: Request, now_unix_seconds: i64) Outcome {
        var best_match: ?Outcome = null;
        var best_length: usize = 0;

        for (self.rules.items) |rule| {
            if (rule.access_class != request.access_class) {
                continue;
            }

            if (rule.expires_at_unix_seconds) |expires_at_unix_seconds| {
                if (now_unix_seconds >= expires_at_unix_seconds) {
                    continue;
                }
            }

            if (!matchesPath(rule.path_prefix, request.path, rule.exact_path)) {
                continue;
            }

            if (rule.uid) |uid| {
                if (uid != request.uid) {
                    continue;
                }
            }

            if (rule.executable_path) |executable_path| {
                const request_executable_path = request.executable_path orelse continue;
                if (!std.mem.eql(u8, executable_path, request_executable_path)) {
                    continue;
                }
            }

            if (rule.path_prefix.len < best_length) {
                continue;
            }

            best_length = rule.path_prefix.len;
            best_match = rule.outcome;
        }

        if (best_match) |outcome| {
            return outcome;
        }

        return switch (request.access_class) {
            .read => switch (self.default_mutation_outcome) {
                .prompt => .prompt,
                else => .allow,
            },
            else => self.default_mutation_outcome,
        };
    }
};

fn matchesPath(prefix: []const u8, path: []const u8, exact_path: bool) bool {
    if (exact_path) {
        return std.mem.eql(u8, prefix, path);
    }

    if (std.mem.eql(u8, prefix, "/")) {
        return path.len != 0 and path[0] == '/';
    }

    if (!std.mem.startsWith(u8, path, prefix)) {
        return false;
    }

    if (path.len == prefix.len) {
        return true;
    }

    if (prefix.len == 0) {
        return false;
    }

    return prefix[prefix.len - 1] == '/' or path[prefix.len] == '/';
}
