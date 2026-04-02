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

pub const Rule = struct {
    path_prefix: []const u8,
    access_class: AccessClass,
    outcome: Outcome,
};

pub const RawRequest = extern struct {
    path: ?[*:0]const u8,
    access_class: u32,
    pid: u32,
    uid: u32,
    gid: u32,
    reserved: [4]u8,
};

pub const Request = struct {
    path: []const u8,
    access_class: AccessClass,
    pid: u32,
    uid: u32,
    gid: u32,
};

const StoredRule = struct {
    path_prefix: []u8,
    access_class: AccessClass,
    outcome: Outcome,
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    default_mutation_outcome: Outcome,
    rules: std.ArrayListUnmanaged(StoredRule) = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        default_mutation_outcome: Outcome,
        source_rules: []const Rule,
    ) !Engine {
        var engine = Engine{
            .allocator = allocator,
            .default_mutation_outcome = default_mutation_outcome,
        };
        errdefer engine.deinit();

        for (source_rules) |rule| {
            const path_prefix = try allocator.dupe(u8, rule.path_prefix);
            errdefer allocator.free(path_prefix);

            try engine.rules.append(allocator, .{
                .path_prefix = path_prefix,
                .access_class = rule.access_class,
                .outcome = rule.outcome,
            });
        }

        return engine;
    }

    pub fn deinit(self: *Engine) void {
        for (self.rules.items) |rule| {
            self.allocator.free(rule.path_prefix);
        }
        self.rules.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn evaluate(self: *const Engine, request: Request) Outcome {
        var best_match: ?Outcome = null;
        var best_length: usize = 0;

        for (self.rules.items) |rule| {
            if (rule.access_class != request.access_class) {
                continue;
            }

            if (!matchesPathPrefix(rule.path_prefix, request.path)) {
                continue;
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

pub const Error = error{
    InvalidRequest,
};

pub fn requestFromRaw(raw: *const RawRequest) Error!Request {
    const path = raw.path orelse return error.InvalidRequest;
    const access_class = std.meta.intToEnum(AccessClass, raw.access_class) catch {
        return error.InvalidRequest;
    };

    return .{
        .path = std.mem.span(path),
        .access_class = access_class,
        .pid = raw.pid,
        .uid = raw.uid,
        .gid = raw.gid,
    };
}

fn matchesPathPrefix(prefix: []const u8, path: []const u8) bool {
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
