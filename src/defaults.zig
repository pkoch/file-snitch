const std = @import("std");
const runtime = @import("runtime.zig");

/// Single source of truth for the runtime `FILE_SNITCH_*` environment variable
/// names used by `src/`, the small numeric defaults the rest of the code
/// shares, and the XDG-or-HOME base-path resolver they all branch on.
///
/// New runtime env vars and numeric defaults belong here so the doctor
/// dossier, the unit tests, and the actual lookups cannot drift. Help text
/// in `cli.zig` intentionally still hard-codes the env names so the multi-line
/// help blocks stay readable; if a new env var lands, update both places.
/// Override the policy file path. Falls back to `XDG_CONFIG_HOME` then `HOME`.
pub const policy_path_env = "FILE_SNITCH_POLICY_PATH";

/// Override the local agent Unix socket path. Falls back to
/// `XDG_RUNTIME_DIR` then `HOME`.
pub const agent_socket_env = "FILE_SNITCH_AGENT_SOCKET";

/// Override the tty device the terminal-pinentry frontend prompts on.
pub const agent_tty_env = "FILE_SNITCH_AGENT_TTY";

/// Override the macOS `osascript` binary used by the macos-ui frontend.
pub const osascript_bin_env = "FILE_SNITCH_OSASCRIPT_BIN";

/// Override the Linux `zenity` binary used by the linux-ui frontend.
pub const zenity_bin_env = "FILE_SNITCH_ZENITY_BIN";

/// Override the `pass` binary used by the pass guarded-store backend.
pub const pass_bin_env = "FILE_SNITCH_PASS_BIN";

/// Override the state directory used for the FUSE projection root. Falls back
/// to `$HOME/.local/state`.
pub const xdg_state_path_env = "XDG_STATE_PATH";

/// Override the prompt timeout in milliseconds. Parsed as an unsigned integer.
pub const prompt_timeout_ms_env = "FILE_SNITCH_PROMPT_TIMEOUT_MS";

/// Override requester/agent socket liveness timeout in milliseconds.
pub const protocol_timeout_ms_env = "FILE_SNITCH_PROTOCOL_TIMEOUT_MS";

/// Internal: marker for a spawned `run` child that should execute one static
/// projection instead of supervising policy changes. Set by the supervisor,
/// never by users.
pub const internal_projection_child_env = "FILE_SNITCH_INTERNAL_PROJECTION_CHILD";

/// Internal: projection child status FIFO path. Set by the supervisor.
pub const internal_status_fifo_env = "FILE_SNITCH_INTERNAL_STATUS_FIFO";

/// Default prompt timeout when `FILE_SNITCH_PROMPT_TIMEOUT_MS` is unset.
pub const prompt_timeout_ms_default: u32 = 30_000;

/// Default protocol timeout for local agent socket messages.
pub const protocol_timeout_ms_default: u32 = 1_000;

/// Duration of the "allow 5 min" remembered decision, in seconds. Shared
/// across the terminal, macOS, and Linux frontends so the label and the
/// stored expiry agree.
pub const remember_temporary_seconds: i64 = 5 * 60;

/// Resolve `$xdg_env` if set, otherwise fall back to `$HOME/<home_relative_fallback>`.
/// Caller owns the returned slice. Used by every File Snitch path that follows the
/// XDG-or-HOME shape so the fallback rule lives in one place.
pub fn xdgBasePathAlloc(
    allocator: std.mem.Allocator,
    xdg_env: []const u8,
    home_relative_fallback: []const u8,
) ![]u8 {
    if (runtime.getEnvVarOwned(allocator, xdg_env)) |value| {
        return value;
    } else |err| switch (err) {
        error.EnvironmentVariableNotFound => {},
        else => return err,
    }

    const home = try runtime.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);
    return std.fs.path.join(allocator, &.{ home, home_relative_fallback });
}
