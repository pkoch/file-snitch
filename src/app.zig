const std = @import("std");
const daemon = @import("daemon.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");

pub fn run(args: []const []const u8) !void {
    if (args.len == 0) {
        printUsage();
        return error.InvalidUsage;
    }

    if (std.mem.eql(u8, args[0], "mount")) {
        return runMount(args[1..]);
    }

    if (std.mem.eql(u8, args[0], "help") or std.mem.eql(u8, args[0], "--help")) {
        printUsage();
        return;
    }

    printUsage();
    return error.InvalidUsage;
}

fn runMount(args: []const []const u8) !void {
    if (args.len < 2 or args.len > 3) {
        printUsage();
        return error.InvalidUsage;
    }

    const allocator = std.heap.page_allocator;
    const mount_path = try std.fs.realpathAlloc(allocator, args[0]);
    defer allocator.free(mount_path);
    const backing_store_path = try std.fs.realpathAlloc(allocator, args[1]);
    defer allocator.free(backing_store_path);
    const default_mutation_outcome = if (args.len == 3)
        try parseMountPolicy(args[2])
    else
        policy.Outcome.deny;
    var cli_prompt_context = prompt.CliContext{
        .timeout_ms = try loadPromptTimeoutMs(),
    };

    try requireEmptyDirectory(mount_path);
    try ensureDirectory(backing_store_path);

    var session = try daemon.Session.init(allocator, .{
        .mount_path = mount_path,
        .backing_store_path = backing_store_path,
        .run_in_foreground = true,
        .default_mutation_outcome = default_mutation_outcome,
        .prompt_broker = if (default_mutation_outcome == .prompt) prompt.cliBroker(&cli_prompt_context) else null,
    });
    defer session.deinit();

    const description = try session.describe();
    std.debug.print(
        "mounting file-snitch: mount={s} backing={s} configured_ops={d} default_mutation={s}\n",
        .{
            description.mount_path,
            description.backing_store_path,
            description.configured_operation_count,
            @tagName(description.default_mutation_outcome),
        },
    );

    try session.run();
}

fn parseMountPolicy(arg: []const u8) !policy.Outcome {
    if (std.mem.eql(u8, arg, "mutable")) {
        return .allow;
    }

    if (std.mem.eql(u8, arg, "readonly")) {
        return .deny;
    }

    if (std.mem.eql(u8, arg, "prompt")) {
        return .prompt;
    }

    printUsage();
    return error.InvalidUsage;
}

fn loadPromptTimeoutMs() !u32 {
    const allocator = std.heap.page_allocator;
    const raw_value = std.process.getEnvVarOwned(allocator, "FILE_SNITCH_PROMPT_TIMEOUT_MS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return 5_000,
        else => return err,
    };
    defer allocator.free(raw_value);

    return std.fmt.parseInt(u32, raw_value, 10);
}

fn requireEmptyDirectory(path: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(path, .{ .iterate = true });
    defer dir.close();

    var iterator = dir.iterate();
    if (try iterator.next() != null) {
        return error.MountPathNotEmpty;
    }
}

fn ensureDirectory(path: []const u8) !void {
    var dir = try std.fs.openDirAbsolute(path, .{});
    dir.close();
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  file-snitch mount <mount-path> <backing-store-path> [mutable|readonly|prompt]
        \\
        \\notes:
        \\  - `mount` requires an existing empty mount directory
        \\  - `mount` defaults to `readonly` unless another policy is specified
        \\
    , .{});
}
