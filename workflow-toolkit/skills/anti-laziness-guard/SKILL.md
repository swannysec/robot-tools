---
name: anti-laziness-guard
description: |
  Three-layer Stop hook that detects and blocks work-skipping rationalizations
  by Claude Code agents. Prevents agents from unilaterally deciding to skip
  assigned work, bypass mandatory processes, or cite unverified context
  constraints as justification for shortcuts.

  Layer 1: Deterministic regex detection of known laziness phrases (Tiers 1-2)
  Layer 2: Haiku-evaluated intent detection for premature victory and silent omission (Tier 4)
  Layer 3: Optional agent-based deep verification against task lists and plan files

  This is a passive hook — it activates automatically when the plugin is enabled.
  No slash command needed. The hook fires on every Stop event and only blocks
  when laziness patterns are detected.
triggers:
  - "anti-laziness"
  - "laziness guard"
  - "stop hook"
  - "work skipping"
  - "skip detection"
  - "agent laziness"
  - "premature stop"
---

# Anti-Laziness Guard

Stop hook that detects and blocks work-skipping rationalizations at stop time. Fires automatically on every Stop event when the workflow-toolkit plugin is enabled.

## How It Works

Three hooks run **in parallel** every time the agent tries to stop. Any one blocking prevents the stop.

### Layer 1: Command Hook (always runs, <1s)

Deterministic regex matching against the agent's `last_assistant_message`. Detects Tier 1-2 laziness phrases with >75% confidence.

**Blocks on phrases like:**
- "skip the remaining review stages"
- "in the interest of time"
- "context constraints" / "running low on context"
- "accelerate through the remaining"
- "consolidate the remaining"
- "not worth the complexity"
- "to save time" / "for brevity"

See `references/phrase-taxonomy.md` for the complete taxonomy with sources.

### Layer 2: Prompt Hook (always runs, ~2-3s)

Haiku evaluates the agent's final message for intent-level patterns that regex cannot catch:

1. **Premature victory** — declaring success while work remains incomplete
2. **Offering instead of doing** — "Let me know if you'd like me to..." for assigned work
3. **Silent omission** — summarizing completed work without mentioning skipped items
4. **Rationalized shortcuts** — framing incomplete work as "a good start" or "sufficient"

### Layer 3: Agent Hook (conditional, 10-30s)

Evidence-based deep verification that reads task lists and plan files. **Only activates when the flag file exists:**

```bash
touch .claude/anti-laziness-deep-check
```

When active, a subagent with Read/Grep/Glob access:
1. Checks `~/.claude/tasks/` and `.claude/tasks/` for incomplete tasks
2. Reads plan files in `.claude/plans/` and cross-references against the agent's claims
3. Searches the transcript for TodoWrite entries with pending/in_progress status
4. Blocks if it finds incomplete work that the agent didn't acknowledge

Remove the flag file to deactivate: `rm .claude/anti-laziness-deep-check`

## Infinite Loop Prevention

The command hook checks `stop_hook_active` — if the agent was already blocked by a stop hook and is trying to stop again, it is allowed through. This prevents the hook from blocking indefinitely.

## Configuration

**Enable/disable the entire hook:** Enable or disable the workflow-toolkit plugin in Claude Code settings.

**Enable deep verification (Layer 3):**
```bash
# Before a critical session
touch .claude/anti-laziness-deep-check

# After the session
rm .claude/anti-laziness-deep-check
```

**Disable just the command hook:** Not possible without modifying `hooks.json`. If you experience false positives, please report them so we can refine the phrase taxonomy.

## Tier Summary

| Tier | Confidence | Action | Detection Method |
|------|-----------|--------|-----------------|
| 1 | >90% | BLOCK | Regex (command hook) |
| 2 | 75-90% | BLOCK | Regex with context scoping (command hook) |
| 3 | 50-75% | Documented only | Not enforced — see `references/phrase-taxonomy.md` |
| 4 | Varies | BLOCK | Haiku evaluation (prompt hook) + optional agent verification |

## Background

This hook was designed based on research across 10+ verified GitHub issues (anthropics/claude-code #26691, #21604, #23368, #16506, #1632, #24129, #6159, #8738, #20270, #1113), the Columbia DAPLab "Vibe Coding Needs Policy Enforcement" research, the Cognition/Anthropic "context anxiety" discovery, and analysis of real session logs showing agents using euphemistic language ("accelerate," "consolidate," "streamline") to disguise work-skipping as productivity optimization.
