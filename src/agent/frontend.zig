const std = @import("std");
const builtin = @import("builtin");
const prompt = @import("../prompt.zig");
const defaults = @import("../defaults.zig");
const runtime = @import("../runtime.zig");
const util = @import("util.zig");
const core = @import("core.zig");
const c = @cImport({
    @cInclude("stdlib.h");
    @cInclude("unistd.h");
});

pub const TerminalPinentryContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    tty_path: ?[]const u8 = null,
    inherited_cli_context: ?*prompt.CliContext = null,
    mutex: std.Io.Mutex = .init,
};

pub const MacosUiContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    osascript_path: []const u8,
};

pub const LinuxUiContext = struct {
    allocator: std.mem.Allocator,
    timeout_ms: u32 = defaults.prompt_timeout_ms_default,
    zenity_path: []const u8,
};

pub fn terminalPinentryFrontend(context: *TerminalPinentryContext) core.Frontend {
    return .{
        .context = context,
        .resolve_fn = resolveTerminalPinentry,
        .user_interaction_timeout_ms = context.timeout_ms,
        .supports_concurrent_requests = true,
    };
}

pub fn macosUiFrontend(context: *MacosUiContext) core.Frontend {
    return .{
        .context = context,
        .resolve_fn = resolveMacosUi,
        .user_interaction_timeout_ms = context.timeout_ms,
        .supports_concurrent_requests = false,
    };
}

pub fn linuxUiFrontend(context: *LinuxUiContext) core.Frontend {
    return .{
        .context = context,
        .resolve_fn = resolveLinuxUi,
        .user_interaction_timeout_ms = context.timeout_ms,
        .supports_concurrent_requests = false,
    };
}

pub fn defaultTerminalPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (runtime.getEnvVarOwned(allocator, defaults.agent_tty_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return terminalPathFromStandardFilesAlloc(allocator) catch
        error.NotATerminal;
}

pub fn defaultOsascriptPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (runtime.getEnvVarOwned(allocator, defaults.osascript_bin_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return allocator.dupe(u8, "osascript");
}

pub fn defaultZenityPathAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (runtime.getEnvVarOwned(allocator, defaults.zenity_bin_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    return allocator.dupe(u8, "zenity");
}

fn resolveTerminalPinentry(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const pinentry_context: *TerminalPinentryContext = @ptrCast(@alignCast(context));
    pinentry_context.mutex.lockUncancelable(runtime.io());
    defer pinentry_context.mutex.unlock(runtime.io());

    if (pinentry_context.inherited_cli_context) |cli_context| {
        return prompt.resolveCliWithContext(cli_context, request);
    }

    const tty_path = pinentry_context.tty_path orelse return .{ .decision = .unavailable };
    const tty_file = std.Io.Dir.openFileAbsolute(runtime.io(), tty_path, .{ .mode = .read_write }) catch return .{ .decision = .unavailable };
    defer tty_file.close(runtime.io());

    var cli_context = prompt.CliContext{
        .allocator = pinentry_context.allocator,
        .timeout_ms = pinentry_context.timeout_ms,
        .stdin_file = tty_file,
        .stderr_file = tty_file,
    };
    return prompt.resolveCliWithContext(&cli_context, request);
}

fn resolveMacosUi(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const ui_context: *MacosUiContext = @ptrCast(@alignCast(context));

    const script = buildMacosDialogScriptAlloc(ui_context.allocator, request, ui_context.timeout_ms) catch
        return .{ .decision = .unavailable };
    defer ui_context.allocator.free(script);

    const argv = [_][]const u8{
        ui_context.osascript_path,
        "-e",
        script,
    };
    const result = std.process.run(ui_context.allocator, runtime.io(), .{
        .argv = &argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(ui_context.timeout_ms),
            .clock = .awake,
        } },
    }) catch |err| {
        if (err == error.Timeout) {
            std.log.warn("macos-ui prompt helper timed out after {d} ms", .{ui_context.timeout_ms});
            return .{ .decision = .timeout };
        }
        std.log.warn("macos-ui prompt helper failed to start: {}", .{err});
        return .{ .decision = .unavailable };
    };
    defer ui_context.allocator.free(result.stdout);
    defer ui_context.allocator.free(result.stderr);

    switch (result.term) {
        .exited => |code| if (code != 0) {
            std.log.warn("macos-ui prompt helper exited with code {d}: {s}", .{ code, result.stderr });
            return .{ .decision = .unavailable };
        },
        else => {
            std.log.warn("macos-ui prompt helper ended unexpectedly: {}", .{result.term});
            return .{ .decision = .unavailable };
        },
    }
    return parseMacosUiResponse(result.stdout) catch |err| {
        std.log.warn("macos-ui prompt helper returned an invalid response: {}", .{err});
        return .{ .decision = .unavailable };
    };
}

fn resolveLinuxUi(raw_context: ?*anyopaque, request: prompt.Request) prompt.Response {
    const context = raw_context orelse return .{ .decision = .unavailable };
    const ui_context: *LinuxUiContext = @ptrCast(@alignCast(context));

    const prompt_text = buildDialogPromptAlloc(ui_context.allocator, request) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(prompt_text);

    const timeout_seconds = @max(@divTrunc(@as(i64, @intCast(ui_context.timeout_ms)) + 999, 1000), 1);
    const timeout_text = std.fmt.allocPrint(ui_context.allocator, "{d}", .{timeout_seconds}) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(timeout_text);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(ui_context.allocator);
    argv.appendSlice(ui_context.allocator, &.{
        ui_context.zenity_path,
        "--list",
        "--radiolist",
        "--title=File Snitch",
        "--text",
        prompt_text,
        "--column=Pick",
        "--column=Decision",
        "TRUE",
        "Allow once",
        "FALSE",
        "Deny once",
    }) catch return .{ .decision = .unavailable };
    if (request.can_remember) {
        argv.appendSlice(ui_context.allocator, &.{
            "FALSE",
            "Allow 5 min",
            "FALSE",
            "Always allow",
            "FALSE",
            "Always deny",
        }) catch return .{ .decision = .unavailable };
    }
    argv.appendSlice(ui_context.allocator, &.{
        "--timeout",
        timeout_text,
        "--width=520",
    }) catch return .{ .decision = .unavailable };

    const result = std.process.run(ui_context.allocator, runtime.io(), .{
        .argv = argv.items,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }) catch return .{ .decision = .unavailable };
    defer ui_context.allocator.free(result.stdout);
    defer ui_context.allocator.free(result.stderr);

    return parseLinuxUiResponse(result.term, result.stdout) catch .{ .decision = .unavailable };
}

pub fn buildMacosDialogScriptAlloc(allocator: std.mem.Allocator, request: prompt.Request, timeout_ms: u32) ![]u8 {
    const title = "File Snitch";
    const prompt_text = try buildDialogPromptAlloc(allocator, request);
    defer allocator.free(prompt_text);

    const escaped_title = try appleScriptStringLiteralContentsAlloc(allocator, title);
    defer allocator.free(escaped_title);
    const escaped_prompt = try appleScriptStringLiteralContentsAlloc(allocator, prompt_text);
    defer allocator.free(escaped_prompt);

    const timeout_seconds = @max(@divTrunc(@as(i64, @intCast(timeout_ms)) + 999, 1000), 1);
    if (!request.can_remember) {
        return std.fmt.allocPrint(
            allocator,
            \\try
            \\  set prompt_text to "{s}"
            \\  set decision to display dialog prompt_text with title "{s}" buttons {{"Deny", "Allow"}} default button "Allow" giving up after {d} with icon caution
            \\  if gave up of decision then
            \\    return "timeout"
            \\  end if
            \\  if button returned of decision is "Allow" then
            \\    return "allow"
            \\  end if
            \\  return "deny"
            \\on error number -128
            \\  return "deny"
            \\end try
        ,
            .{ escaped_prompt, escaped_title, timeout_seconds },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        \\try
        \\  set prompt_text to "{s}"
        \\  set choices to {{"Allow once", "Deny once", "Allow 5 min", "Always allow", "Always deny"}}
        \\  with timeout of {d} seconds
        \\    set selected to choose from list choices with title "{s}" with prompt prompt_text default items {{"Allow once"}} OK button name "Select" cancel button name "Deny once"
        \\  end timeout
        \\  if selected is false then
        \\    return "deny"
        \\  end if
        \\  set answer to item 1 of selected
        \\  if answer is "Allow once" then return "allow"
        \\  if answer is "Deny once" then return "deny"
        \\  if answer is "Allow 5 min" then return "allow-5m"
        \\  if answer is "Always allow" then return "always-allow"
        \\  if answer is "Always deny" then return "always-deny"
        \\  return "deny"
        \\on error number error_number
        \\  if error_number is -1712 then return "timeout"
        \\  if error_number is -128 then return "deny"
        \\  return "deny"
        \\end try
    ,
        .{ escaped_prompt, timeout_seconds, escaped_title },
    );
}

fn buildDialogPromptAlloc(allocator: std.mem.Allocator, request: prompt.Request) ![]u8 {
    const label = request.label orelse blk: {
        const generated = try std.fmt.allocPrint(
            allocator,
            "{s} {s}",
            .{ util.accessClassLabel(request.access_class), request.path },
        );
        break :blk generated;
    };
    defer if (request.label == null) allocator.free(label);

    const executable_path = request.executable_path orelse "unknown executable";
    return std.fmt.allocPrint(
        allocator,
        "{s}\n\nProcess: {s}\nPID: {d}",
        .{ label, executable_path, request.pid },
    );
}

pub fn appleScriptStringLiteralContentsAlloc(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    for (raw) |byte| switch (byte) {
        '"' => try output.appendSlice(allocator, "\\\""),
        '\\' => try output.appendSlice(allocator, "\\\\"),
        '\n' => try output.appendSlice(allocator, "\\n"),
        '\r' => {},
        else => try output.append(allocator, byte),
    };

    return output.toOwnedSlice(allocator);
}

pub fn parseMacosUiResponse(raw_output: []const u8) !prompt.Response {
    const trimmed = std.mem.trim(u8, raw_output, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "allow")) return .{ .decision = .allow, .remember_kind = .once };
    if (std.mem.eql(u8, trimmed, "deny")) return .{ .decision = .deny, .remember_kind = .once };
    if (std.mem.eql(u8, trimmed, "timeout")) return .{ .decision = .timeout };
    if (std.mem.eql(u8, trimmed, "allow-5m")) return .{
        .decision = .allow,
        .remember_kind = .temporary,
        .expires_at_unix_seconds = runtime.timestamp() + defaults.remember_temporary_seconds,
    };
    if (std.mem.eql(u8, trimmed, "always-allow")) return .{ .decision = .allow, .remember_kind = .durable };
    if (std.mem.eql(u8, trimmed, "always-deny")) return .{ .decision = .deny, .remember_kind = .durable };
    return error.InvalidProtocolMessage;
}

pub fn parseLinuxUiResponse(term: std.process.Child.Term, raw_output: []const u8) !prompt.Response {
    return switch (term) {
        .exited => |code| switch (code) {
            0 => parseLinuxUiSelection(raw_output),
            1 => .{ .decision = .deny, .remember_kind = .once },
            5 => .{ .decision = .timeout },
            else => error.InvalidProtocolMessage,
        },
        else => error.InvalidProtocolMessage,
    };
}

fn parseLinuxUiSelection(raw_output: []const u8) !prompt.Response {
    const trimmed = std.mem.trim(u8, raw_output, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "Allow once")) {
        return .{ .decision = .allow, .remember_kind = .once };
    }
    if (std.mem.eql(u8, trimmed, "Deny once")) {
        return .{ .decision = .deny, .remember_kind = .once };
    }
    if (std.mem.eql(u8, trimmed, "Allow 5 min")) return .{
        .decision = .allow,
        .remember_kind = .temporary,
        .expires_at_unix_seconds = runtime.timestamp() + defaults.remember_temporary_seconds,
    };
    if (std.mem.eql(u8, trimmed, "Always allow")) {
        return .{ .decision = .allow, .remember_kind = .durable };
    }
    if (std.mem.eql(u8, trimmed, "Always deny")) {
        return .{ .decision = .deny, .remember_kind = .durable };
    }
    return error.InvalidProtocolMessage;
}

fn terminalPathFromStandardFilesAlloc(allocator: std.mem.Allocator) ![]u8 {
    if (try std.Io.File.stderr().isTty(runtime.io())) {
        return util.terminalPathForFileAlloc(allocator, std.Io.File.stderr());
    }
    if (try std.Io.File.stdin().isTty(runtime.io())) {
        return util.terminalPathForFileAlloc(allocator, std.Io.File.stdin());
    }
    return error.NotATerminal;
}
