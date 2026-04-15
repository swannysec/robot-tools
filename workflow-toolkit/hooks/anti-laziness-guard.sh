#!/bin/bash
# Anti-Laziness Guard — Stop hook for Claude Code
# Detects work-skipping rationalizations in the agent's final message
# and blocks the stop if laziness patterns are found.
#
# Tiers 1-2: BLOCK (>75% confidence these indicate actual laziness)
# See skills/anti-laziness-guard/references/phrase-taxonomy.md for full taxonomy.
#
# Input: Stop hook JSON on stdin (last_assistant_message, stop_hook_active, etc.)
# Output: JSON on stdout — {"decision":"block","reason":"..."} or {} (allow)
# Exit: Always 0 (control via JSON, not exit codes)
#
# Security: Uses printf instead of echo to prevent \c escape sequence bypass.
# Fails closed if jq is missing or input is malformed.

set -uo pipefail

# Fail closed if jq is not available
if ! command -v jq >/dev/null 2>&1; then
  printf '%s\n' '{"decision":"block","reason":"ANTI-LAZINESS GUARD: jq not found. Cannot evaluate stop request safely. Install jq to proceed."}'
  exit 0
fi

# Read input; fail closed on missing/empty stdin
INPUT=$(cat) || INPUT=""
if [ -z "$INPUT" ]; then
  printf '%s\n' '{"decision":"block","reason":"ANTI-LAZINESS GUARD: No input received. Blocking stop as a precaution."}'
  exit 0
fi

# Prevent infinite loops: if we already blocked once, let the agent stop
STOP_HOOK_ACTIVE=$(printf '%s' "$INPUT" | jq -r '.stop_hook_active // false' 2>/dev/null) || STOP_HOOK_ACTIVE="false"
if [ "$STOP_HOOK_ACTIVE" = "true" ]; then
  printf '%s\n' '{}'
  exit 0
fi

# Extract the agent's final message; fail closed on parse error
MESSAGE=$(printf '%s' "$INPUT" | jq -r '.last_assistant_message // ""' 2>/dev/null) || {
  printf '%s\n' '{"decision":"block","reason":"ANTI-LAZINESS GUARD: Failed to parse input JSON. Blocking stop as a precaution."}'
  exit 0
}
if [ -z "$MESSAGE" ]; then
  printf '%s\n' '{}'
  exit 0
fi

# Strip fenced code blocks so quoted examples don't trigger detection
PROSE=$(printf '%s\n' "$MESSAGE" | sed '/^```/,/^```/d')
# Fallback: if stripping removed everything (unclosed fence), scan full message
if [ -z "$PROSE" ]; then
  PROSE="$MESSAGE"
fi

# --- Tier 1: Very High Confidence (>90%) ---
# These phrases are almost never legitimate at stop time.
TIER1_PATTERNS=(
  'skip the remaining'
  'skip the[[:space:]].*review'
  'skip the[[:space:]].*test'
  'skip the[[:space:]].*stage'
  'skip the[[:space:]].*phase'
  'skip the[[:space:]].*step'
  'skip external research'
  'in the interest of time'
  'for brevity'
  'considerable time'
  'would take too long'
  'takes? significant'
  'context constraints'
  'running low on context'
  'context limit'
  'conserve tokens'
  'session is getting long'
  'accelerate through the remaining'
  'consolidate the remaining'
)

for pattern in "${TIER1_PATTERNS[@]}"; do
  if printf '%s\n' "$PROSE" | grep -iqE "$pattern"; then
    MATCHED=$(printf '%s\n' "$MESSAGE" | grep -ioE "$pattern" | head -1)
    jq -n --arg matched "$MATCHED" '{
      decision: "block",
      reason: ("ANTI-LAZINESS GUARD [Tier 1]: Detected work-skipping rationalization: \"\($matched)\". We trust you to be thorough — if this phrase reflects a genuine constraint, explain it to the user and let them decide. If you cited context constraints, verify with /context before claiming limits.")
    }'
    exit 0
  fi
done

# --- Tier 2: High Confidence (75-90%) ---
# Strong signals with slightly more legitimate-use surface area.
TIER2_SIMPLE=(
  'not worth the complexity'
  'not worth the effort'
  'do that later'
  "doesn't need a formal"
  'for the sake of efficiency'
  'to save time'
)

for pattern in "${TIER2_SIMPLE[@]}"; do
  if printf '%s\n' "$PROSE" | grep -iqE "$pattern"; then
    MATCHED=$(printf '%s\n' "$MESSAGE" | grep -ioE "$pattern" | head -1)
    jq -n --arg matched "$MATCHED" '{
      decision: "block",
      reason: ("ANTI-LAZINESS GUARD [Tier 2]: Detected work-skipping rationalization: \"\($matched)\". We trust you to be thorough — if you believe the scope should change, explain your reasoning to the user and let them decide.")
    }'
    exit 0
  fi
done

# "overkill" — only when discussing process/skills/steps, not technical descriptions
if printf '%s\n' "$PROSE" | grep -iqE 'overkill' && printf '%s\n' "$PROSE" | grep -iqE 'skill|process|step|stage|review|check'; then
  jq -n '{
    decision: "block",
    reason: "ANTI-LAZINESS GUARD [Tier 2]: Detected process-bypassing rationalization (\"overkill\"). The assigned process exists for a reason. We trust you to be thorough — if you believe it is excessive for this case, explain why to the user."
  }'
  exit 0
fi

# "this is straightforward" — only when used to bypass a mandatory process
if printf '%s\n' "$PROSE" | grep -iqE 'this is straightforward' && printf '%s\n' "$PROSE" | grep -iqE 'skip|don.t need|no need|unnecessary'; then
  jq -n '{
    decision: "block",
    reason: "ANTI-LAZINESS GUARD [Tier 2]: Detected process-bypassing rationalization (\"straightforward\" used to justify skipping steps). We trust you to be thorough — the assigned process exists regardless of perceived simplicity. Explain to the user if you believe an exception is warranted."
  }'
  exit 0
fi

# "for now" — only when deferring assigned work (scoped by nearby laziness context)
if printf '%s\n' "$PROSE" | grep -iqE 'for now' && printf '%s\n' "$PROSE" | grep -iqE 'skip|remaining|stage|review|step|defer|later|move on'; then
  jq -n '{
    decision: "block",
    reason: "ANTI-LAZINESS GUARD [Tier 2]: Detected work deferral (\"for now\" in context of skipping/deferring assigned work). We trust you to be thorough — if deferral is genuinely appropriate, explain your reasoning to the user."
  }'
  exit 0
fi

# No matches — allow stop
printf '%s\n' '{}'
exit 0
