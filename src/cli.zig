const std = @import("std");
const daemon = @import("daemon.zig");
const policy = @import("policy.zig");
const prompt = @import("prompt.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    run(args[1..]) catch |err| switch (err) {
        error.InvalidUsage => std.process.exit(1),
        else => return err,
    };
}

pub fn run(args: []const []const u8) !void {
    switch (try parseCommand(args)) {
        .help => printUsage(),
        .mount => |command| {
            defer command.deinit(std.heap.page_allocator);
            var cli_prompt_context = prompt.CliContext{
                .timeout_ms = command.prompt_timeout_ms,
            };
            const status_output_file = if (command.status_fifo_path) |path|
                try openStatusFifo(path)
            else
                null;
            defer if (status_output_file) |file| file.close();

            daemon.mount(std.heap.page_allocator, .{
                .mount_path = command.mount_path,
                .backing_store_path = command.backing_store_path,
                .default_mutation_outcome = command.default_mutation_outcome,
                .prompt_broker = if (command.default_mutation_outcome == .prompt)
                    prompt.cliBroker(&cli_prompt_context)
                else
                    null,
                .status_output_file = status_output_file,
                .audit_output_file = std.fs.File.stdout(),
            }) catch |err| switch (err) {
                error.MountPathNotEmpty => {
                    std.debug.print(
                        "error: mount path is not empty: {s}\n",
                        .{command.mount_path},
                    );
                    return error.InvalidUsage;
                },
                else => return err,
            };
        },
    }
}

const Command = union(enum) {
    help,
    mount: MountCommand,
};

const MountCommand = struct {
    mount_path: []const u8,
    backing_store_path: []const u8,
    default_mutation_outcome: policy.Outcome,
    prompt_timeout_ms: u32,
    status_fifo_path: ?[]const u8 = null,

    fn deinit(self: MountCommand, allocator: std.mem.Allocator) void {
        allocator.free(self.mount_path);
        allocator.free(self.backing_store_path);
        if (self.status_fifo_path) |path| {
            allocator.free(path);
        }
    }
};

fn parseCommand(args: []const []const u8) !Command {
    if (args.len == 0) {
        printUsage();
        return error.InvalidUsage;
    }

    if (std.mem.eql(u8, args[0], "mount")) {
        return .{ .mount = try parseMountCommand(args[1..]) };
    }

    if (std.mem.eql(u8, args[0], "help") or std.mem.eql(u8, args[0], "--help")) {
        return .help;
    }

    printUsage();
    return error.InvalidUsage;
}

fn parseMountCommand(args: []const []const u8) !MountCommand {
    if (args.len < 2) {
        printUsage();
        return error.InvalidUsage;
    }

    const allocator = std.heap.page_allocator;
    const mount_path = try resolveDirectoryArgument(allocator, "mount path", args[0]);
    errdefer allocator.free(mount_path);
    const backing_store_path = try resolveDirectoryArgument(allocator, "backing store path", args[1]);
    errdefer allocator.free(backing_store_path);

    var command: MountCommand = .{
        .mount_path = mount_path,
        .backing_store_path = backing_store_path,
        .default_mutation_outcome = policy.Outcome.deny,
        .prompt_timeout_ms = try loadPromptTimeoutMs(),
    };
    errdefer command.deinit(allocator);

    var index: usize = 2;
    while (index < args.len) : (index += 1) {
        const arg = args[index];

        if (std.mem.eql(u8, arg, "mutable") or std.mem.eql(u8, arg, "readonly") or std.mem.eql(u8, arg, "prompt")) {
            command.default_mutation_outcome = try parseMountPolicy(arg);
            continue;
        }

        if (std.mem.eql(u8, arg, "--status-fifo")) {
            index += 1;
            if (index >= args.len) {
                printUsage();
                return error.InvalidUsage;
            }
            command.status_fifo_path = try allocator.dupe(u8, args[index]);
            continue;
        }

        printUsage();
        return error.InvalidUsage;
    }

    return command;
}

fn resolveDirectoryArgument(
    allocator: std.mem.Allocator,
    label: []const u8,
    raw_path: []const u8,
) ![]const u8 {
    return std.fs.realpathAlloc(allocator, raw_path) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: {s} does not exist: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        error.NotDir => {
            std.debug.print("error: {s} is not a directory: {s}\n", .{ label, raw_path });
            return error.InvalidUsage;
        },
        else => return err,
    };
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

fn openStatusFifo(path: []const u8) !std.fs.File {
    const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
        error.FileNotFound => {
            std.debug.print("error: status fifo does not exist: {s}\n", .{path});
            return error.InvalidUsage;
        },
        else => return err,
    };

    if (stat.kind != .named_pipe) {
        std.debug.print("error: status fifo is not a named pipe: {s}\n", .{path});
        return error.InvalidUsage;
    }

    return std.fs.cwd().openFile(path, .{ .mode = .write_only });
}

fn printUsage() void {
    std.debug.print(
        \\usage:
        \\  file-snitch mount <mount-path> <backing-store-path> [mutable|readonly|prompt] [--status-fifo <path>]
        \\
        \\notes:
        \\  - `mount` requires an existing empty mount directory
        \\  - `mount` defaults to `readonly` unless another policy is specified
        \\  - `mount` streams audit JSON to stdout
        \\  - `--status-fifo` writes status JSON snapshots to an existing named pipe
        \\
    , .{});
}
