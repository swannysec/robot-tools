#!/usr/bin/env bash
# Tests for anti-laziness-guard.sh (command hook / Layer 1)
# Run: bash workflow-toolkit/hooks/test-anti-laziness-guard.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD="$SCRIPT_DIR/anti-laziness-guard.sh"
TMP="$(mktemp -d)"
PASS=0
FAIL=0

cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); echo "PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $1"; }

# mtime helper (BSD first, then GNU)
set_mtime() {  # <file> <epoch>
  touch -t "$(date -r "$2" +%Y%m%d%H%M.%S 2>/dev/null || date -d "@$2" +%Y%m%d%H%M.%S 2>/dev/null)" "$1" 2>/dev/null || true
}

# Build a Stop-hook input JSON. Args: <message> [transcript_path]
make_input() {
  local msg="$1"; local tp="${2:-}"
  jq -n --arg m "$msg" --arg tp "$tp" \
    '{last_assistant_message: $m, stop_hook_active: false} + (if $tp != "" then {transcript_path: $tp} else {} end)'
}

# Create a session transcript + a subagent transcript in the sibling subagents dir.
# Args: <session-name> <state: running|completed> <age-secs>
setup_subagent() {
  local name="$1" state="$2" age="${3:-0}"
  local session_dir="$TMP/$name"
  mkdir -p "$session_dir/subagents"
  local main="$session_dir.jsonl"
  echo '{"type":"user","message":{"content":"go"}}' > "$main"
  local sub="$session_dir/subagents/agent-abc123.jsonl"
  echo '{"type":"user","message":{"content":"task"}}' > "$sub"
  if [ "$state" = "completed" ]; then
    echo '{"type":"assistant","message":{"stop_reason":"end_turn","content":[{"type":"text","text":"done"}]}}' >> "$sub"
  else
    # running: last line is a non-terminal assistant turn (no stop_reason)
    echo '{"type":"assistant","message":{"stop_reason":null,"content":[{"type":"text","text":"working"}]}}' >> "$sub"
  fi
  if [ "$age" -gt 0 ]; then
    set_mtime "$sub" "$(( $(date +%s) - age ))"
  fi
  printf '%s' "$main"
}

run_guard() { printf '%s' "$1" | bash "$GUARD" 2>/dev/null; }

LAZY='In the interest of time, I will stop here.'

# 1: background-work gate — lazy phrase but a fresh running subagent → ALLOW
test_gate_allows_when_subagent_running() {
  local tp; tp=$(setup_subagent "s1" running 0)
  local out; out=$(run_guard "$(make_input "$LAZY" "$tp")")
  if [ "$out" = "{}" ]; then
    pass "1: waiting on running subagent → stop allowed despite lazy phrase"
  else
    fail "1: expected allow ({}) while subagent running; got: $out"
  fi
}

# 2: no background work — lazy phrase + completed subagent → BLOCK
test_blocks_when_subagent_completed() {
  local tp; tp=$(setup_subagent "s2" completed 0)
  local out; out=$(run_guard "$(make_input "$LAZY" "$tp")")
  if printf '%s' "$out" | jq -e '.decision=="block"' >/dev/null 2>&1; then
    pass "2: completed subagent → lazy phrase still blocks"
  else
    fail "2: expected block when no work in flight; got: $out"
  fi
}

# 3: stale running subagent (dead, >180s) → does NOT suppress → BLOCK
test_stale_running_subagent_does_not_suppress() {
  local tp; tp=$(setup_subagent "s3" running 600)
  local out; out=$(run_guard "$(make_input "$LAZY" "$tp")")
  if printf '%s' "$out" | jq -e '.decision=="block"' >/dev/null 2>&1; then
    pass "3: stale (dead) subagent does not suppress the guard"
  else
    fail "3: expected block for stale subagent; got: $out"
  fi
}

# 4: greedy-regex false positive — output-style prose must NOT block
test_greedy_regex_false_positive() {
  local msg="I follow the output style: skip the analysis essay when the request is unambiguous, and do not pre-analyze the step before acting."
  local out; out=$(run_guard "$(make_input "$msg")")
  if [ "$out" = "{}" ]; then
    pass "4: 'skip the analysis essay ... the step' no longer false-positives"
  else
    fail "4: expected allow for output-style prose; got: $out"
  fi
}

# 5: genuine Tier-1 skip still blocks
test_genuine_skip_still_blocks() {
  local out; out=$(run_guard "$(make_input "I will skip the remaining tests to finish.")")
  if printf '%s' "$out" | jq -e '.decision=="block"' >/dev/null 2>&1; then
    pass "5: genuine 'skip the remaining tests' still blocks"
  else
    fail "5: expected block for genuine skip; got: $out"
  fi
}

# 6: stop_hook_active → allow
test_stop_hook_active() {
  local inp; inp=$(jq -n --arg m "$LAZY" '{last_assistant_message: $m, stop_hook_active: true}')
  local out; out=$(run_guard "$inp")
  if [ "$out" = "{}" ]; then
    pass "6: stop_hook_active respected"
  else
    fail "6: expected allow on stop_hook_active; got: $out"
  fi
}

echo "=== Anti-Laziness Guard: command hook tests ==="
echo ""
test_gate_allows_when_subagent_running
test_blocks_when_subagent_completed
test_stale_running_subagent_does_not_suppress
test_greedy_regex_false_positive
test_genuine_skip_still_blocks
test_stop_hook_active
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
