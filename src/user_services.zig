const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const defaults = @import("defaults.zig");
const enrollment = @import("enrollment.zig");
const runtime = @import("runtime.zig");

pub const Platform = enum {
    macos,
    linux,

    pub fn parse(raw: []const u8) ?Platform {
        if (std.mem.eql(u8, raw, "macos")) return .macos;
        if (std.mem.eql(u8, raw, "linux")) return .linux;
        return null;
    }

    pub fn detect() !Platform {
        return switch (builtin.os.tag) {
            .macos => .macos,
            .linux => .linux,
            else => error.UnsupportedPlatform,
        };
    }
};

pub const RenderOptions = struct {
    platform: ?Platform = null,
    bin_path: ?[]const u8 = null,
    pass_bin_path: ?[]const u8 = null,
};

pub const RenderedService = struct {
    label: []const u8,
    file_name: []const u8,
    install_path: []u8,
    contents: []u8,

    fn deinit(self: *RenderedService, allocator: std.mem.Allocator) void {
        allocator.free(self.install_path);
        allocator.free(self.contents);
        self.* = undefined;
    }
};

pub const RenderedServices = struct {
    platform: Platform,
    bin_path: []u8,
    pass_bin_path: []u8,
    service_path: []u8,
    log_dir: []u8,
    agent: RenderedService,
    run: RenderedService,

    pub fn deinit(self: *RenderedServices, allocator: std.mem.Allocator) void {
        self.agent.deinit(allocator);
        self.run.deinit(allocator);
        allocator.free(self.bin_path);
        allocator.free(self.pass_bin_path);
        allocator.free(self.service_path);
        allocator.free(self.log_dir);
        self.* = undefined;
    }
};

pub fn renderExpectedAlloc(allocator: std.mem.Allocator, options: RenderOptions) !RenderedServices {
    const platform = options.platform orelse try Platform.detect();

    const resolved_bin_path = if (options.bin_path) |raw|
        try resolveExecutablePathAlloc(allocator, raw, "file-snitch binary")
    else
        try std.process.executablePathAlloc(runtime.io(), allocator);
    errdefer allocator.free(resolved_bin_path);
    try requireExecutablePath(resolved_bin_path, "file-snitch binary");

    var owned_default_pass_bin_path: ?[]u8 = null;
    defer if (owned_default_pass_bin_path) |path| allocator.free(path);
    const raw_pass_bin_path = options.pass_bin_path orelse passDefault: {
        owned_default_pass_bin_path = runtime.getEnvVarOwned(allocator, defaults.pass_bin_env) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => break :passDefault "pass",
            else => return err,
        };
        break :passDefault owned_default_pass_bin_path.?;
    };
    const resolved_pass_bin_path = try resolveExecutablePathAlloc(allocator, raw_pass_bin_path, "pass binary");
    errdefer allocator.free(resolved_pass_bin_path);

    const service_path = try buildServicePathAlloc(allocator, resolved_bin_path, resolved_pass_bin_path);
    errdefer allocator.free(service_path);
    const log_dir = try defaultLogDirAlloc(allocator);
    errdefer allocator.free(log_dir);

    const home_dir = try enrollment.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);

    return switch (platform) {
        .macos => .{
            .platform = platform,
            .bin_path = resolved_bin_path,
            .pass_bin_path = resolved_pass_bin_path,
            .service_path = service_path,
            .log_dir = log_dir,
            .agent = .{
                .label = "dev.file-snitch.agent",
                .file_name = "dev.file-snitch.agent.plist",
                .install_path = try macosLaunchAgentPathAlloc(allocator, home_dir, "dev.file-snitch.agent.plist"),
                .contents = try renderTemplateAlloc(allocator, launchd_agent_template, log_dir, resolved_bin_path, resolved_pass_bin_path, service_path),
            },
            .run = .{
                .label = "dev.file-snitch.run",
                .file_name = "dev.file-snitch.run.plist",
                .install_path = try macosLaunchAgentPathAlloc(allocator, home_dir, "dev.file-snitch.run.plist"),
                .contents = try renderTemplateAlloc(allocator, launchd_run_template, log_dir, resolved_bin_path, resolved_pass_bin_path, service_path),
            },
        },
        .linux => .{
            .platform = platform,
            .bin_path = resolved_bin_path,
            .pass_bin_path = resolved_pass_bin_path,
            .service_path = service_path,
            .log_dir = log_dir,
            .agent = .{
                .label = "file-snitch-agent.service",
                .file_name = "file-snitch-agent.service",
                .install_path = try linuxUserUnitPathAlloc(allocator, home_dir, "file-snitch-agent.service"),
                .contents = try renderTemplateAlloc(allocator, systemd_agent_template, log_dir, resolved_bin_path, resolved_pass_bin_path, service_path),
            },
            .run = .{
                .label = "file-snitch-run.service",
                .file_name = "file-snitch-run.service",
                .install_path = try linuxUserUnitPathAlloc(allocator, home_dir, "file-snitch-run.service"),
                .contents = try renderTemplateAlloc(allocator, systemd_run_template, log_dir, resolved_bin_path, resolved_pass_bin_path, service_path),
            },
        },
    };
}

pub fn renderToDirectory(allocator: std.mem.Allocator, options: RenderOptions, output_dir: []const u8) !void {
    var rendered = try renderExpectedAlloc(allocator, options);
    defer rendered.deinit(allocator);

    try std.Io.Dir.cwd().createDirPath(runtime.io(), output_dir);
    const agent_path = try std.fs.path.join(allocator, &.{ output_dir, rendered.agent.file_name });
    defer allocator.free(agent_path);
    const run_path = try std.fs.path.join(allocator, &.{ output_dir, rendered.run.file_name });
    defer allocator.free(run_path);

    try writeFileAbsolute(agent_path, rendered.agent.contents);
    try writeFileAbsolute(run_path, rendered.run.contents);
}

pub fn install(allocator: std.mem.Allocator, options: RenderOptions) !void {
    var rendered = try renderExpectedAlloc(allocator, options);
    defer rendered.deinit(allocator);

    switch (rendered.platform) {
        .macos => {
            try requireCommandAvailable(allocator, "launchctl", "launchctl is required on macOS");
            try std.Io.Dir.cwd().createDirPath(runtime.io(), rendered.log_dir);
            try writeFileAbsolute(rendered.agent.install_path, rendered.agent.contents);
            try writeFileAbsolute(rendered.run.install_path, rendered.run.contents);

            const uid = std.c.getuid();
            const gui_domain = try std.fmt.allocPrint(allocator, "gui/{d}", .{uid});
            defer allocator.free(gui_domain);
            const agent_domain = try serviceDomainAlloc(allocator, uid, rendered.agent.label);
            defer allocator.free(agent_domain);
            const run_domain = try serviceDomainAlloc(allocator, uid, rendered.run.label);
            defer allocator.free(run_domain);

            _ = runCommand(allocator, &.{ "launchctl", "bootout", agent_domain }) catch {};
            _ = runCommand(allocator, &.{ "launchctl", "bootout", run_domain }) catch {};

            try runCommandChecked(allocator, &.{ "launchctl", "bootstrap", gui_domain, rendered.agent.install_path });
            try runCommandChecked(allocator, &.{ "launchctl", "enable", agent_domain });
            try runCommandChecked(allocator, &.{ "launchctl", "kickstart", "-k", agent_domain });
            try runCommandChecked(allocator, &.{ "launchctl", "bootstrap", gui_domain, rendered.run.install_path });
            try runCommandChecked(allocator, &.{ "launchctl", "enable", run_domain });
            try runCommandChecked(allocator, &.{ "launchctl", "kickstart", "-k", run_domain });
        },
        .linux => {
            try requireCommandAvailable(allocator, "systemctl", "systemctl is required on Linux");
            try requireCommandAvailable(allocator, "zenity", "zenity is required for the linux-ui agent frontend");
            try std.Io.Dir.cwd().createDirPath(runtime.io(), rendered.log_dir);
            try writeFileAbsolute(rendered.agent.install_path, rendered.agent.contents);
            try writeFileAbsolute(rendered.run.install_path, rendered.run.contents);
            try runCommandChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
            try runCommandChecked(allocator, &.{ "systemctl", "--user", "enable", "--now", rendered.agent.label });
            try runCommandChecked(allocator, &.{ "systemctl", "--user", "enable", "--now", rendered.run.label });
        },
    }
}

pub fn uninstall(allocator: std.mem.Allocator, platform_override: ?Platform) !void {
    const platform = platform_override orelse try Platform.detect();
    const home_dir = try enrollment.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);

    switch (platform) {
        .macos => {
            try requireCommandAvailable(allocator, "launchctl", "launchctl is required on macOS");
            const uid = std.c.getuid();
            for ([_][]const u8{ "dev.file-snitch.run", "dev.file-snitch.agent" }) |label| {
                const service_domain = try serviceDomainAlloc(allocator, uid, label);
                defer allocator.free(service_domain);
                _ = runCommand(allocator, &.{ "launchctl", "bootout", service_domain }) catch {};
                const file_name = try std.fmt.allocPrint(allocator, "{s}.plist", .{label});
                defer allocator.free(file_name);
                const path = try macosLaunchAgentPathAlloc(allocator, home_dir, file_name);
                defer allocator.free(path);
                deleteFileIfPresent(path);
            }
        },
        .linux => {
            try requireCommandAvailable(allocator, "systemctl", "systemctl is required on Linux");
            _ = runCommand(allocator, &.{ "systemctl", "--user", "disable", "--now", "file-snitch-agent.service" }) catch {};
            _ = runCommand(allocator, &.{ "systemctl", "--user", "disable", "--now", "file-snitch-run.service" }) catch {};
            const agent_path = try linuxUserUnitPathAlloc(allocator, home_dir, "file-snitch-agent.service");
            defer allocator.free(agent_path);
            const run_path = try linuxUserUnitPathAlloc(allocator, home_dir, "file-snitch-run.service");
            defer allocator.free(run_path);
            deleteFileIfPresent(agent_path);
            deleteFileIfPresent(run_path);
            try runCommandChecked(allocator, &.{ "systemctl", "--user", "daemon-reload" });
        },
    }
}

pub fn loadedConfigAlloc(allocator: std.mem.Allocator, platform: Platform, service: RenderedService) !?[]u8 {
    switch (platform) {
        .macos => {
            const uid = std.c.getuid();
            const service_domain = try serviceDomainAlloc(allocator, uid, service.label);
            defer allocator.free(service_domain);
            return runLoadedConfigCommandAlloc(allocator, &.{ "launchctl", "print", service_domain });
        },
        .linux => return runLoadedConfigCommandAlloc(allocator, &.{ "systemctl", "--user", "cat", service.label }),
    }
}

fn runLoadedConfigCommandAlloc(allocator: std.mem.Allocator, argv: []const []const u8) !?[]u8 {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = argv,
        .stdout_limit = .limited(128 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                allocator.free(result.stdout);
                return null;
            }
        },
        else => {
            allocator.free(result.stdout);
            return null;
        },
    }

    return result.stdout;
}

pub fn systemdCatBodyAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var saw_content = false;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "#")) continue;
        if (!saw_content and std.mem.trim(u8, line, " \t\r\n").len == 0) continue;
        saw_content = true;
        try body.appendSlice(allocator, line);
        try body.append(allocator, '\n');
    }
    return body.toOwnedSlice(allocator);
}

pub fn commandAvailable(allocator: std.mem.Allocator, command: []const u8) !bool {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ "sh", "-lc", "command -v \"$1\" >/dev/null 2>&1", "sh", command },
        .stdout_limit = .limited(1),
        .stderr_limit = .limited(1),
    }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

pub fn macosLaunchAgentPathAlloc(allocator: std.mem.Allocator, home_dir: []const u8, filename: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ home_dir, "Library", "LaunchAgents", filename });
}

pub fn linuxUserUnitPathAlloc(allocator: std.mem.Allocator, home_dir: []const u8, filename: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ home_dir, ".config", "systemd", "user", filename });
}

fn renderTemplateAlloc(
    allocator: std.mem.Allocator,
    template: []const u8,
    log_dir: []const u8,
    bin_path: []const u8,
    pass_bin_path: []const u8,
    service_path: []const u8,
) ![]u8 {
    var rendered = try std.mem.replaceOwned(u8, allocator, template, "{{LOG_DIR}}", log_dir);
    errdefer allocator.free(rendered);
    rendered = try replaceOwnedFree(allocator, rendered, "{{FILE_SNITCH_BIN}}", bin_path);
    errdefer allocator.free(rendered);
    rendered = try replaceOwnedFree(allocator, rendered, "{{PASS_BIN}}", pass_bin_path);
    errdefer allocator.free(rendered);
    rendered = try replaceOwnedFree(allocator, rendered, "{{SERVICE_PATH}}", service_path);
    return rendered;
}

fn replaceOwnedFree(
    allocator: std.mem.Allocator,
    input: []u8,
    needle: []const u8,
    replacement: []const u8,
) ![]u8 {
    const output = try std.mem.replaceOwned(u8, allocator, input, needle, replacement);
    allocator.free(input);
    return output;
}

fn resolveExecutablePathAlloc(allocator: std.mem.Allocator, raw_path: []const u8, label: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(raw_path)) {
        const resolved = try allocator.dupe(u8, raw_path);
        errdefer allocator.free(resolved);
        try requireExecutablePath(resolved, label);
        return resolved;
    }

    const result = std.process.run(allocator, runtime.io(), .{
        .argv = &.{ "sh", "-lc", "command -v \"$1\"", "sh", raw_path },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: could not resolve {s}: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        else => return err,
    };
    defer allocator.free(result.stderr);
    defer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| {
            if (code != 0) {
                std.debug.print("error: could not resolve {s}: {s}\n", .{ label, raw_path });
                return error.InvalidUsage;
            }
        },
        else => {
            std.debug.print("error: could not resolve {s}: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    const first_line = std.mem.sliceTo(trimmed, '\n');
    const resolved = try allocator.dupe(u8, first_line);
    errdefer allocator.free(resolved);
    try requireExecutablePath(resolved, label);
    return resolved;
}

fn requireExecutablePath(path: []const u8, label: []const u8) !void {
    const stat = std.Io.Dir.cwd().statFile(runtime.io(), path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: {s} is not executable: {s}\n", .{ label, path });
            return error.InvalidUsage;
        },
        else => return err,
    };
    if (stat.kind != .file or (std.Io.File.Permissions.has_executable_bit and stat.permissions.toMode() & 0o111 == 0)) {
        std.debug.print("error: {s} is not executable: {s}\n", .{ label, path });
        return error.InvalidUsage;
    }
}

fn defaultLogDirAlloc(allocator: std.mem.Allocator) ![]u8 {
    const home_dir = try enrollment.currentUserHomeAlloc(allocator);
    defer allocator.free(home_dir);
    return std.fs.path.join(allocator, &.{ home_dir, ".local", "state", "file-snitch", "log" });
}

fn appendPathComponent(allocator: std.mem.Allocator, current: []const u8, component: []const u8) ![]u8 {
    if (component.len == 0) return allocator.dupe(u8, current);
    var parts = std.mem.splitScalar(u8, current, ':');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, component)) return allocator.dupe(u8, current);
    }
    if (current.len == 0) return allocator.dupe(u8, component);
    return std.fmt.allocPrint(allocator, "{s}:{s}", .{ current, component });
}

fn buildServicePathAlloc(allocator: std.mem.Allocator, bin_path: []const u8, pass_bin_path: []const u8) ![]u8 {
    var service_path = try allocator.dupe(u8, "");
    errdefer allocator.free(service_path);

    const components = [_][]const u8{
        std.fs.path.dirname(bin_path) orelse "",
        std.fs.path.dirname(pass_bin_path) orelse "",
        "/opt/homebrew/opt/gnu-getopt/bin",
        "/usr/local/opt/gnu-getopt/bin",
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    };
    for (components) |component| {
        const next = try appendPathComponent(allocator, service_path, component);
        allocator.free(service_path);
        service_path = next;
    }
    return service_path;
}

fn writeFileAbsolute(path: []const u8, contents: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return error.InvalidPath;
    try std.Io.Dir.cwd().createDirPath(runtime.io(), parent);
    try std.Io.Dir.cwd().writeFile(runtime.io(), .{
        .sub_path = path,
        .data = contents,
        .flags = .{ .truncate = true, .permissions = .fromMode(0o644) },
    });
}

fn requireCommandAvailable(allocator: std.mem.Allocator, command: []const u8, message: []const u8) !void {
    if (try commandAvailable(allocator, command)) return;
    std.debug.print("error: {s}\n", .{message});
    return error.InvalidUsage;
}

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) !std.process.Child.Term {
    const result = try std.process.run(allocator, runtime.io(), .{
        .argv = argv,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return result.term;
}

fn runCommandChecked(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const result = std.process.run(allocator, runtime.io(), .{
        .argv = argv,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    }) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: command not found: {s}\n", .{argv[0]});
            return error.InvalidUsage;
        },
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }

    std.debug.print("error: service command failed: {s}\n", .{argv[0]});
    if (result.stderr.len != 0) std.debug.print("{s}", .{result.stderr});
    return error.InvalidUsage;
}

fn serviceDomainAlloc(allocator: std.mem.Allocator, uid: std.c.uid_t, label: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "gui/{d}/{s}", .{ uid, label });
}

fn deleteFileIfPresent(path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(runtime.io(), path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.log.warn("failed to delete service file {s}: {}", .{ path, err }),
    };
}

const launchd_agent_template = build_options.launchd_agent_template;
const launchd_run_template = build_options.launchd_run_template;
const systemd_agent_template = build_options.systemd_agent_template;
const systemd_run_template = build_options.systemd_run_template;

test "systemd cat body drops source comments" {
    const body = try systemdCatBodyAlloc(std.testing.allocator,
        \\# /path/file-snitch-agent.service
        \\[Unit]
        \\Description=File Snitch local agent
        \\
    );
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings(
        \\[Unit]
        \\Description=File Snitch local agent
        \\
        \\
    , body);
}
