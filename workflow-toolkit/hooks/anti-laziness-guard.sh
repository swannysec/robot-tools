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
  if printf '%s\n' "$MESSAGE" | grep -iqE "$pattern"; then
    MATCHED=$(printf '%s\n' "$MESSAGE" | grep -ioE "$pattern" | head -1)
    jq -n --arg matched "$MATCHED" '{
      decision: "block",
      reason: ("ANTI-LAZINESS GUARD [Tier 1]: Detected work-skipping rationalization: \"\($matched)\". You are not permitted to skip assigned work. If you believe remaining work is genuinely unnecessary, ask the user — do not decide unilaterally. If you cited context constraints, verify with /context before claiming limits.")
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
  if printf '%s\n' "$MESSAGE" | grep -iqE "$pattern"; then
    MATCHED=$(printf '%s\n' "$MESSAGE" | grep -ioE "$pattern" | head -1)
    jq -n --arg matched "$MATCHED" '{
      decision: "block",
      reason: ("ANTI-LAZINESS GUARD [Tier 2]: Detected work-skipping rationalization: \"\($matched)\". You are not permitted to skip assigned work or decide that assigned tasks are not worth doing. Ask the user if you believe the scope should change.")
    }'
    exit 0
  fi
done

# "overkill" — only when discussing process/skills/steps, not technical descriptions
if printf '%s\n' "$MESSAGE" | grep -iqE 'overkill' && printf '%s\n' "$MESSAGE" | grep -iqE 'skill|process|step|stage|review|check'; then
  jq -n '{
    decision: "block",
    reason: "ANTI-LAZINESS GUARD [Tier 2]: Detected process-bypassing rationalization (\"overkill\"). Follow the assigned process. If you believe it is excessive, ask the user."
  }'
  exit 0
fi

# "this is straightforward" — only when used to bypass a mandatory process
if printf '%s\n' "$MESSAGE" | grep -iqE 'this is straightforward' && printf '%s\n' "$MESSAGE" | grep -iqE 'skip|don.t need|no need|unnecessary'; then
  jq -n '{
    decision: "block",
    reason: "ANTI-LAZINESS GUARD [Tier 2]: Detected process-bypassing rationalization (\"straightforward\" used to justify skipping steps). Follow the assigned process regardless of perceived simplicity."
  }'
  exit 0
fi

# "for now" — only when deferring assigned work (scoped by nearby laziness context)
if printf '%s\n' "$MESSAGE" | grep -iqE 'for now' && printf '%s\n' "$MESSAGE" | grep -iqE 'skip|remaining|stage|review|step|defer|later|move on'; then
  jq -n '{
    decision: "block",
    reason: "ANTI-LAZINESS GUARD [Tier 2]: Detected work deferral (\"for now\" in context of skipping/deferring assigned work). Complete assigned work before stopping."
  }'
  exit 0
fi

# No matches — allow stop
printf '%s\n' '{}'
exit 0
