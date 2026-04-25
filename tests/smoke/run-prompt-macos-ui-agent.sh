#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp_root="$(mktemp -d "/tmp/file-snitch-macos-ui-agent.XXXXXX")"
agent_pid=""

cleanup() {
  if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
    kill -INT "$agent_pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      if ! kill -0 "$agent_pid" 2>/dev/null; then
        wait "$agent_pid" 2>/dev/null || true
        agent_pid=""
        break
      fi
      sleep 0.1
    done
    if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
      kill -TERM "$agent_pid" 2>/dev/null || true
      sleep 0.2
    fi
    if [[ -n "$agent_pid" ]] && kill -0 "$agent_pid" 2>/dev/null; then
      kill -KILL "$agent_pid" 2>/dev/null || true
    fi
    if [[ -n "$agent_pid" ]]; then
      wait "$agent_pid" 2>/dev/null || true
    fi
  fi
  rm -rf "$tmp_root"
}
trap cleanup EXIT

fake_bin_dir="$tmp_root/bin"
runtime_dir="$tmp_root/run"
home_dir="$tmp_root/home"
queue_path="$tmp_root/osascript.queue"
socket_path="$runtime_dir/file-snitch/agent.sock"
agent_log="$tmp_root/agent.log"

mkdir -p "$fake_bin_dir" "$runtime_dir" "$home_dir"
cat >"$fake_bin_dir/osascript" <<EOF
#!/usr/bin/env bash
set -euo pipefail

queue_path="$queue_path"
response="\$(head -n 1 "\$queue_path" || true)"
if [[ -s "\$queue_path" ]]; then
  tail -n +2 "\$queue_path" >"\$queue_path.next" || true
  mv "\$queue_path.next" "\$queue_path"
fi

case "\$response" in
  allow|deny|timeout|always-allow|always-deny)
    printf '%s\n' "\$response"
    ;;
  hang)
    sleep 30
    ;;
  "")
    printf 'allow\n'
    ;;
  *)
    exit 99
    ;;
esac
EOF
chmod +x "$fake_bin_dir/osascript"

printf '%s\n' allow deny timeout hang >"$queue_path"

PATH="$fake_bin_dir:$PATH" \
  HOME="$home_dir" \
  XDG_RUNTIME_DIR="$runtime_dir" \
  FILE_SNITCH_OSASCRIPT_BIN="$fake_bin_dir/osascript" \
  FILE_SNITCH_PROMPT_TIMEOUT_MS=2000 \
  "$repo_root/zig-out/bin/file-snitch" agent --frontend macos-ui \
  >"$agent_log" 2>&1 &
agent_pid="$!"

for _ in $(seq 1 100); do
  if [[ -S "$socket_path" ]]; then
    break
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    cat "$agent_log" >&2
    echo "agent exited before socket became ready" >&2
    exit 1
  fi
  sleep 0.1
done

[[ -S "$socket_path" ]] || {
  cat "$agent_log" >&2
  echo "agent did not create its socket" >&2
  exit 1
}

python3 -u - "$socket_path" <<'PY'
import json
import socket
import sys

socket_path = sys.argv[1]

def read_frame(sock):
    length = bytearray()
    while True:
        byte = sock.recv(1)
        if not byte:
            raise RuntimeError("unexpected EOF while reading frame length")
        if byte == b":":
            break
        length.extend(byte)
    payload_len = int(length.decode("ascii"))
    payload = bytearray()
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            raise RuntimeError("unexpected EOF while reading frame payload")
        payload.extend(chunk)
    trailing = sock.recv(1)
    if trailing != b"\n":
        raise RuntimeError("invalid frame terminator")
    return json.loads(payload.decode("utf-8"))

def write_frame(sock, payload):
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sock.sendall(str(len(encoded)).encode("ascii") + b":" + encoded + b"\n")

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.settimeout(5)
    sock.connect(socket_path)
    hello = read_frame(sock)
    assert hello["protocol"] == "file-snitch-agent"
    assert hello["version"] == "1.0"
    assert hello["type"] == "hello"

    write_frame(sock, {
        "protocol": "file-snitch-agent",
        "version": "1.0",
        "type": "welcome",
        "request_id": hello["request_id"],
        "role": "requester",
        "requester_name": "file-snitch-smoke",
        "requester_version": "0",
        "capabilities": ["decide", "query"],
    })

    expected = [
        ("allow", "once"),
        ("deny", "once"),
        ("timeout", "none"),
        ("timeout", "none"),
    ]
    for index, (outcome, remember_kind) in enumerate(expected, start=1):
        request_id = f"macos-ui-agent-{index}"
        write_frame(sock, {
            "protocol": "file-snitch-agent",
            "version": "1.0",
            "type": "decide",
            "request_id": request_id,
            "subject": {
                "uid": 501,
                "pid": 42,
                "executable_path": "/bin/cat",
            },
            "request": {
                "enrolled_path": "/Users/test/.kube/config",
                "approval_class": "read_like",
                "operation": "open",
                "mode": "read",
            },
            "policy_context": {
                "default_timeout": "2026-04-10T12:00:00Z",
                "can_remember": True,
            },
            "details": {
                "display_path": "open O_RDONLY /Users/test/.kube/config",
            },
        })
        decision = read_frame(sock)
        assert decision["type"] == "decision", decision
        assert decision["request_id"] == request_id, decision
        assert decision["outcome"] == outcome, decision
        assert decision["remember"]["kind"] == remember_kind, decision

print("macos-ui fake osascript agent smoke passed")
PY
