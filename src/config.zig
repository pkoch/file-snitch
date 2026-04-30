const std = @import("std");

pub const core = @import("config/core.zig");

pub const Enrollment = core.Enrollment;
pub const Decision = core.Decision;
pub const ProjectionEntry = core.ProjectionEntry;
pub const ProjectionPlan = core.ProjectionPlan;
pub const CompiledRuleViews = core.CompiledRuleViews;
pub const PolicyLock = core.PolicyLock;
pub const PolicyMarker = core.PolicyMarker;
pub const PolicyFile = core.PolicyFile;

pub const currentPolicyMarker = core.currentPolicyMarker;
pub const acquirePolicyLock = core.acquirePolicyLock;
pub const loadFromFile = core.loadFromFile;
pub const defaultPolicyPathAlloc = core.defaultPolicyPathAlloc;
pub const defaultProjectionRootPathAlloc = core.defaultProjectionRootPathAlloc;

test {
    std.testing.refAllDecls(core);
}

test "policy file rejects empty decision paths" {
    const allocator = std.testing.allocator;

    const old_home_z = try setHomeForTest("/tmp");
    defer restoreHomeForTest(old_home_z);

    try std.Io.Dir.cwd().createDirPath(runtime.io(), "/tmp/test-empty-decision-path");
    defer std.Io.Dir.cwd().deleteTree(runtime.io(), "/tmp/test-empty-decision-path") catch {};

    var file = try std.Io.Dir.createFileAbsolute(runtime.io(), "/tmp/test-empty-decision-path/policy.yml", .{ .truncate = true });
    defer file.close(runtime.io());
    try file.writeStreamingAll(runtime.io(),
        \\version: 1
        \\enrollments: []
        \\decisions:
        \\  - executable_path: /usr/bin/cat
        \\    path: ""
        \\    approval_class: read_like
        \\    outcome: allow
        \\    expires_at: null
        \\
    );

    try std.testing.expectError(error.InvalidDecisionPath, loadFromFile(allocator, "/tmp/test-empty-decision-path/policy.yml"));
}
