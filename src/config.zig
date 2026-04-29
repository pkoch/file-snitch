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
