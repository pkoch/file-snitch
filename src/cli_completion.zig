const std = @import("std");
const runtime = @import("runtime.zig");

pub const Shell = enum {
    bash,
    zsh,
    fish,
};

pub fn parseShell(raw: []const u8) ?Shell {
    if (std.mem.eql(u8, raw, "bash")) return .bash;
    if (std.mem.eql(u8, raw, "zsh")) return .zsh;
    if (std.mem.eql(u8, raw, "fish")) return .fish;
    return null;
}

pub fn print(shell: Shell) !void {
    try runtime.stdoutWriteAll(scriptFor(shell));
}

pub fn scriptFor(shell: Shell) []const u8 {
    return switch (shell) {
        .bash => bash_script,
        .zsh => zsh_script,
        .fish => fish_script,
    };
}

const bash_script =
    \\_file_snitch_has_word() {
    \\    local needle="$1"
    \\    shift
    \\    local word
    \\    for word in "$@"; do
    \\        if [[ "$word" == "$needle" ]]; then
    \\            return 0
    \\        fi
    \\    done
    \\    return 1
    \\}
    \\
    \\_file_snitch() {
    \\    local cur prev cmd
    \\    COMPREPLY=()
    \\    cur="${COMP_WORDS[COMP_CWORD]}"
    \\    prev="${COMP_WORDS[COMP_CWORD-1]}"
    \\
    \\    case "$prev" in
    \\        --policy|--socket|--tty|--export-debug-dossier|--bin|--pass-bin|--output-dir)
    \\            COMPREPLY=( $(compgen -f -- "$cur") )
    \\            return 0
    \\            ;;
    \\        --platform)
    \\            COMPREPLY=( $(compgen -W "macos linux" -- "$cur") )
    \\            return 0
    \\            ;;
    \\        --frontend)
    \\            COMPREPLY=( $(compgen -W "terminal-pinentry macos-ui linux-ui" -- "$cur") )
    \\            return 0
    \\            ;;
    \\    esac
    \\
    \\    if [[ ${COMP_CWORD} -eq 1 ]]; then
    \\        COMPREPLY=( $(compgen -W "agent run enroll unenroll status doctor completion services help version --help --version" -- "$cur") )
    \\        return 0
    \\    fi
    \\
    \\    cmd="${COMP_WORDS[1]}"
    \\
    \\    case "$cmd" in
    \\        agent)
    \\            COMPREPLY=( $(compgen -W "--socket --frontend --tty" -- "$cur") )
    \\            ;;
    \\        run)
    \\            if _file_snitch_has_word "allow" "${COMP_WORDS[@]:2}" || _file_snitch_has_word "deny" "${COMP_WORDS[@]:2}" || _file_snitch_has_word "prompt" "${COMP_WORDS[@]:2}"; then
    \\                COMPREPLY=( $(compgen -W "--policy" -- "$cur") )
    \\            else
    \\                COMPREPLY=( $(compgen -W "allow deny prompt --policy" -- "$cur") )
    \\            fi
    \\            ;;
    \\        enroll|unenroll)
    \\            if [[ "$cur" == -* ]]; then
    \\                COMPREPLY=( $(compgen -W "--policy" -- "$cur") )
    \\            else
    \\                COMPREPLY=( $(compgen -f -- "$cur") )
    \\            fi
    \\            ;;
    \\        status)
    \\            COMPREPLY=( $(compgen -W "--policy" -- "$cur") )
    \\            ;;
    \\        doctor)
    \\            COMPREPLY=( $(compgen -W "--policy --export-debug-dossier" -- "$cur") )
    \\            ;;
    \\        completion)
    \\            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
    \\            ;;
    \\        services)
    \\            if [[ ${COMP_CWORD} -eq 2 ]]; then
    \\                COMPREPLY=( $(compgen -W "render install uninstall" -- "$cur") )
    \\                return 0
    \\            fi
    \\            case "${COMP_WORDS[2]}" in
    \\                render)
    \\                    COMPREPLY=( $(compgen -W "--platform --bin --pass-bin --output-dir" -- "$cur") )
    \\                    ;;
    \\                install)
    \\                    COMPREPLY=( $(compgen -W "--platform --bin --pass-bin" -- "$cur") )
    \\                    ;;
    \\                uninstall)
    \\                    COMPREPLY=( $(compgen -W "--platform" -- "$cur") )
    \\                    ;;
    \\            esac
    \\            ;;
    \\    esac
    \\}
    \\
    \\complete -F _file_snitch file-snitch
    \\
;

const zsh_script =
    \\#compdef file-snitch
    \\
    \\local -a commands
    \\commands=(agent run enroll unenroll status doctor completion services help version --help --version)
    \\
    \\if (( CURRENT == 2 )); then
    \\    compadd -- $commands
    \\    return
    \\fi
    \\
    \\case "${words[2]}" in
    \\    agent)
    \\        case "${words[CURRENT-1]}" in
    \\            --socket|--tty)
    \\                _files
    \\                return
    \\                ;;
    \\            --frontend)
    \\                compadd -- terminal-pinentry macos-ui linux-ui
    \\                return
    \\                ;;
    \\        esac
    \\        compadd -- --socket --frontend --tty
    \\        ;;
    \\    run)
    \\        case "${words[CURRENT-1]}" in
    \\            --policy)
    \\                _files
    \\                return
    \\                ;;
    \\        esac
    \\        if (( CURRENT == 3 )); then
    \\            compadd -- allow deny prompt --policy
    \\            return
    \\        fi
    \\        compadd -- --policy
    \\        ;;
    \\    enroll|unenroll)
    \\        case "${words[CURRENT-1]}" in
    \\            --policy)
    \\                _files
    \\                return
    \\                ;;
    \\        esac
    \\        if (( CURRENT == 3 )); then
    \\            _files
    \\            return
    \\        fi
    \\        compadd -- --policy
    \\        ;;
    \\    status)
    \\        case "${words[CURRENT-1]}" in
    \\            --policy)
    \\                _files
    \\                return
    \\                ;;
    \\        esac
    \\        compadd -- --policy
    \\        ;;
    \\    doctor)
    \\        case "${words[CURRENT-1]}" in
    \\            --policy|--export-debug-dossier)
    \\                _files
    \\                return
    \\                ;;
    \\        esac
    \\        compadd -- --policy --export-debug-dossier
    \\        ;;
    \\    completion)
    \\        if (( CURRENT == 3 )); then
    \\            compadd -- bash zsh fish
    \\        fi
    \\        ;;
    \\    services)
    \\        case "${words[CURRENT-1]}" in
    \\            --bin|--pass-bin|--output-dir)
    \\                _files
    \\                return
    \\                ;;
    \\            --platform)
    \\                compadd -- macos linux
    \\                return
    \\                ;;
    \\        esac
    \\        if (( CURRENT == 3 )); then
    \\            compadd -- render install uninstall
    \\            return
    \\        fi
    \\        case "${words[3]}" in
    \\            render)
    \\                compadd -- --platform --bin --pass-bin --output-dir
    \\                ;;
    \\            install)
    \\                compadd -- --platform --bin --pass-bin
    \\                ;;
    \\            uninstall)
    \\                compadd -- --platform
    \\                ;;
    \\        esac
    \\        ;;
    \\esac
    \\
;

const fish_script =
    \\function __fish_file_snitch_needs_run_outcome
    \\    set -l tokens (commandline -opc)
    \\    if test (count $tokens) -lt 3
    \\        return 0
    \\    end
    \\    for token in $tokens[3..-1]
    \\        switch $token
    \\            case allow deny prompt
    \\                return 1
    \\        end
    \\    end
    \\    return 0
    \\end
    \\
    \\complete -c file-snitch -n "__fish_use_subcommand" -l help
    \\complete -c file-snitch -n "__fish_use_subcommand" -l version -s V
    \\complete -c file-snitch -n "__fish_use_subcommand" -f -a "agent run enroll unenroll status doctor completion services help version"
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from agent" -l socket -r -F
    \\complete -c file-snitch -n "__fish_seen_subcommand_from agent" -l frontend -r -f -a "terminal-pinentry macos-ui linux-ui"
    \\complete -c file-snitch -n "__fish_seen_subcommand_from agent" -l tty -r -F
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from run" -l policy -r -F
    \\complete -c file-snitch -n "__fish_seen_subcommand_from run; and __fish_file_snitch_needs_run_outcome" -f -a "allow deny prompt"
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from enroll unenroll" -l policy -r -F
    \\complete -c file-snitch -n "__fish_seen_subcommand_from enroll unenroll" -F
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from status" -l policy -r -F
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from doctor" -l policy -r -F
    \\complete -c file-snitch -n "__fish_seen_subcommand_from doctor" -l export-debug-dossier -r -F
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from completion" -f -a "bash zsh fish"
    \\
    \\complete -c file-snitch -n "__fish_seen_subcommand_from services; and not __fish_seen_subcommand_from render install uninstall" -f -a "render install uninstall"
    \\complete -c file-snitch -n "__fish_seen_subcommand_from services" -l platform -r -f -a "macos linux"
    \\complete -c file-snitch -n "__fish_seen_subcommand_from services; and __fish_seen_subcommand_from render install" -l bin -r -F
    \\complete -c file-snitch -n "__fish_seen_subcommand_from services; and __fish_seen_subcommand_from render install" -l pass-bin -r -F
    \\complete -c file-snitch -n "__fish_seen_subcommand_from services; and __fish_seen_subcommand_from render" -l output-dir -r -F
    \\
;

test "parse shell accepts supported shells" {
    try std.testing.expectEqual(Shell.bash, parseShell("bash").?);
    try std.testing.expectEqual(Shell.zsh, parseShell("zsh").?);
    try std.testing.expectEqual(Shell.fish, parseShell("fish").?);
    try std.testing.expect(parseShell("powershell") == null);
}

fn expectContainsAll(haystack: []const u8, needles: []const []const u8) !void {
    for (needles) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
    }
}

test "scripts include current command surface" {
    const shared_subcommands = [_][]const u8{
        "agent",
        "run",
        "enroll",
        "unenroll",
        "status",
        "doctor",
        "completion",
        "services",
        "help",
        "version",
    };
    const service_subcommands = [_][]const u8{
        "render",
        "install",
        "uninstall",
    };
    const service_flags = [_][]const u8{
        "--platform",
        "--bin",
        "--pass-bin",
        "--output-dir",
    };
    const frontend_choices = [_][]const u8{
        "terminal-pinentry",
        "macos-ui",
        "linux-ui",
    };
    const run_outcomes = [_][]const u8{
        "allow",
        "deny",
        "prompt",
    };
    const completion_shells = [_][]const u8{
        "bash",
        "zsh",
        "fish",
    };

    const bash_agent_flags = [_][]const u8{ "--socket", "--frontend", "--tty" };
    const bash_doctor_flags = [_][]const u8{ "--policy", "--export-debug-dossier" };
    try expectContainsAll(scriptFor(.bash), &shared_subcommands);
    try expectContainsAll(scriptFor(.bash), &bash_agent_flags);
    try expectContainsAll(scriptFor(.bash), &frontend_choices);
    try expectContainsAll(scriptFor(.bash), &run_outcomes);
    try expectContainsAll(scriptFor(.bash), &bash_doctor_flags);
    try expectContainsAll(scriptFor(.bash), &completion_shells);
    try expectContainsAll(scriptFor(.bash), &service_subcommands);
    try expectContainsAll(scriptFor(.bash), &service_flags);

    const zsh_agent_flags = [_][]const u8{ "--socket", "--frontend", "--tty" };
    const zsh_doctor_flags = [_][]const u8{ "--policy", "--export-debug-dossier" };
    try expectContainsAll(scriptFor(.zsh), &shared_subcommands);
    try expectContainsAll(scriptFor(.zsh), &zsh_agent_flags);
    try expectContainsAll(scriptFor(.zsh), &frontend_choices);
    try expectContainsAll(scriptFor(.zsh), &run_outcomes);
    try expectContainsAll(scriptFor(.zsh), &zsh_doctor_flags);
    try expectContainsAll(scriptFor(.zsh), &completion_shells);
    try expectContainsAll(scriptFor(.zsh), &service_subcommands);
    try expectContainsAll(scriptFor(.zsh), &service_flags);

    const fish_agent_flags = [_][]const u8{ "-l socket", "-l frontend", "-l tty" };
    const fish_doctor_flags = [_][]const u8{ "-l policy", "-l export-debug-dossier" };
    const fish_service_flags = [_][]const u8{ "-l platform", "-l bin", "-l pass-bin", "-l output-dir" };
    try expectContainsAll(scriptFor(.fish), &shared_subcommands);
    try expectContainsAll(scriptFor(.fish), &fish_agent_flags);
    try expectContainsAll(scriptFor(.fish), &frontend_choices);
    try expectContainsAll(scriptFor(.fish), &run_outcomes);
    try expectContainsAll(scriptFor(.fish), &fish_doctor_flags);
    try expectContainsAll(scriptFor(.fish), &completion_shells);
    try expectContainsAll(scriptFor(.fish), &service_subcommands);
    try expectContainsAll(scriptFor(.fish), &fish_service_flags);
}

test "scripts include expected entry points" {
    try std.testing.expect(std.mem.indexOf(u8, scriptFor(.bash), "complete -F _file_snitch file-snitch") != null);
    try std.testing.expect(std.mem.indexOf(u8, scriptFor(.zsh), "#compdef file-snitch") != null);
    try std.testing.expect(std.mem.indexOf(u8, scriptFor(.fish), "complete -c file-snitch") != null);
}
