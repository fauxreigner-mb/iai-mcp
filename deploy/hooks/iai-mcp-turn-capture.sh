#!/usr/bin/env bash
# IAI-MCP UserPromptSubmit hook — per-turn ambient capture.
#
# Pure file IO: appends one JSONL event line per new transcript turn to
# ~/.iai-mcp/.deferred-captures/{session_id}.live.jsonl. Inline system
# python3 (stdlib only) so cold-start stays under the per-turn latency
# budget; the equivalent `iai-mcp capture-turn-deferred` CLI exists for
# manual / debugging use. Format invariants are kept in sync with
# src/iai_mcp/capture.py::write_deferred_event.
#
# Fail-safe: any error exits 0. Hard 5s wall-clock timeout.

set -u
input=$(cat 2>/dev/null || true)

# Portable python lookup — /usr/bin/python3 may be absent on some Linux distros
_PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo /usr/bin/python3)"

extract() {
  local key=$1
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$input" | jq -r ".${key} // empty" 2>/dev/null
  else
    printf '%s' "$input" | "${_PY}" -c "
import json, sys
try:
    d = json.load(sys.stdin)
    print(d.get('${key}', '') or '')
except Exception:
    print('')
" 2>/dev/null
  fi
}

session_id=$(extract "session_id")
transcript_path=$(extract "transcript_path")

mkdir -p "$HOME/.iai-mcp/logs" 2>/dev/null || true
log="$HOME/.iai-mcp/logs/turn-capture-$(date -u +%Y-%m-%d).log"
ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [[ -z "$session_id" || -z "$transcript_path" ]]; then
  echo "$ts skipped: missing session_id or transcript_path" >> "$log" 2>/dev/null
  exit 0
fi

PY_SCRIPT='
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_TURNS = 200

session_id = sys.argv[1]
transcript_path = Path(sys.argv[2]).expanduser()
if not transcript_path.exists():
    sys.exit(0)

home = Path(os.environ.get("HOME", str(Path.home())))
deferred_dir = home / ".iai-mcp" / ".deferred-captures"
state_dir = home / ".iai-mcp" / ".capture-state"
deferred_dir.mkdir(parents=True, exist_ok=True)
state_dir.mkdir(parents=True, exist_ok=True)
live = deferred_dir / f"{session_id}.live.jsonl"
offset = state_dir / f"{session_id}.offset"

prev = 0
if offset.exists():
    try:
        prev = int(offset.read_text().strip() or "0")
    except ValueError:
        prev = 0

with transcript_path.open() as fh:
    lines = fh.readlines()
total = len(lines)
if prev > total:
    prev = 0

cwd = os.getcwd()
emitted = 0
consumed = 0

def parse_line(raw):
    try:
        obj = json.loads(raw)
    except Exception:
        return None
    msg = obj.get("message") if isinstance(obj.get("message"), dict) else obj
    role = obj.get("type") or msg.get("role", "")
    if role not in {"user", "assistant"}:
        return None
    content = msg.get("content", "")
    if isinstance(content, list):
        parts = [
            b.get("text", "")
            for b in content
            if isinstance(b, dict) and b.get("type") == "text"
        ]
        text = "\n".join(parts).strip()
    else:
        text = str(content).strip()
    if not text:
        return None
    return role, text

if total > prev:
    need_header = (not live.exists()) or live.stat().st_size == 0
    with live.open("a") as out:
        if need_header:
            header = {
                "version": 1,
                "deferred_at": datetime.now(timezone.utc).isoformat(),
                "session_id": session_id,
                "cwd": cwd,
            }
            out.write(json.dumps(header, ensure_ascii=False) + "\n")
        for raw in lines[prev:]:
            if emitted >= MAX_TURNS:
                break
            consumed += 1
            parsed = parse_line(raw)
            if parsed is None:
                continue
            role, text = parsed
            event = {
                "text": text,
                "cue": f"session {session_id} turn",
                "tier": "episodic",
                "role": role,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
            out.write(json.dumps(event, ensure_ascii=False) + "\n")
            emitted += 1

new_offset = prev + consumed
tmp = state_dir / f"{session_id}.offset.tmp"
tmp.write_text(str(new_offset))
os.replace(tmp, offset)
'

if command -v timeout >/dev/null 2>&1; then
  timeout 5 "${_PY}" -c "$PY_SCRIPT" "$session_id" "$transcript_path" 2>/dev/null
elif command -v gtimeout >/dev/null 2>&1; then
  gtimeout 5 "${_PY}" -c "$PY_SCRIPT" "$session_id" "$transcript_path" 2>/dev/null
else
  "${_PY}" -c "$PY_SCRIPT" "$session_id" "$transcript_path" 2>/dev/null
fi
rc=$?

echo "$ts session=$session_id rc=$rc" >> "$log" 2>/dev/null
exit 0
