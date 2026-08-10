---
name: anti-laziness-guard
description: |
  Three-layer Stop hook that detects and blocks work-skipping rationalizations
  by Claude Code agents. Prevents agents from unilaterally deciding to skip
  assigned work, bypass mandatory processes, or cite unverified context
  constraints as justification for shortcuts.

  Layer 1: Deterministic regex detection of known laziness phrases (Tiers 1-2)
  Layer 2: Haiku-evaluated internal contradiction detection (Tier 4)
  Layer 3: Context-aware agent verification — auto-activates when plans/tasks exist (Tier 5)

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

Haiku evaluates the agent's final message for a single criterion: **internal contradiction** — the message claims completion but contains contradicting evidence of incompleteness in the same message.

Biased toward allowing: when in doubt, the evaluator allows the stop. False positives (blocking a legitimate stop) cause more damage than false negatives (missing a lazy stop).

### Layer 3: Agent Hook (conditional, 10-30s)

Context-aware deep verification that reads task lists, plan files, and the session transcript. **Auto-activates when structured work exists:**

- Plan files in `.claude/plans/*.md` or `~/.claude/plans/*.md`
- Task files in `.claude/tasks/**/*.json` or `~/.claude/tasks/**/*.json`
- Manual flag file: `.claude/anti-laziness-deep-check`

When active, a subagent with Read/Grep/Glob access:
1. Checks `~/.claude/tasks/` and `.claude/tasks/` for incomplete tasks
2. Reads plan files in `.claude/plans/` and cross-references against the agent's claims
3. Searches the transcript for TodoWrite entries with pending/in_progress status
4. Checks for **offering instead of doing** — agent offers to do assigned work instead of completing it (with carve-outs for completed-then-offering, backlog items, credential questions, and CLAUDE.md-directed confirmations)
5. Checks for **silent omission** — agent summarizes completed work without mentioning assigned items it didn't do

**Context budget:** The subagent reads selectively — only user messages from the transcript (not assistant messages, tool results, or progress events). This keeps evaluation within Haiku's 200k token context window even for long sessions.

## Infinite Loop Prevention

The command hook checks `stop_hook_active` — if the agent was already blocked by a stop hook and is trying to stop again, it is allowed through. This prevents the hook from blocking indefinitely.

## Background-Work Gate

All three layers allow the stop when the orchestrator is waiting on a still-running subagent it launched. Claude Code re-invokes the agent when background work completes, so blocking a "waiting" stop is both wrong — the awaited work is not the main agent's to do yet — and the direct cause of wasteful in-turn `sleep`/`wait` polling loops (the agent waits *inside* the turn because the guard won't let it end).

- **Layer 1 (command):** checks the sibling `subagents/` directory derived from `transcript_path` for an `agent-*.jsonl` written in the last 3 minutes whose last line is not a completed assistant turn.
- **Layer 3 (agent):** runs the same structural check before resolving the in-scope file set.
- **Layer 2 (prompt):** allows when the final message indicates the agent is awaiting delegated results (it only receives the message text, so it relies on that signal).

Detection covers **subagents** (the common fan-out case). A backgrounded `bash` shell that signals completion out-of-band is not directly detected by Layer 1's structural check; Layer 2's prose signal is the backstop there.

**Guidance for agents:** if you have fanned work out to subagents or launched a background job that will signal its own completion, **stop and let the harness re-invoke you** — do not run a `sleep`/`wait` loop to keep the turn alive. Reserve intentional in-turn waiting for work that genuinely cannot be resumed after a stop. Light administrative steps (pure transcription, reading context for the next step, fetching an unrelated piece of data) remain fine while you wait.

## Configuration

**Enable/disable the entire hook:** Enable or disable the workflow-toolkit plugin in Claude Code settings.

**Layer 3 auto-activation:** Layer 3 activates automatically when plan or task files exist. No configuration needed for structured work sessions.

**Manual activation (for sessions without plans/tasks):**
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
| 4 | Varies | BLOCK | Haiku evaluation — internal contradiction only (prompt hook) |
| 5 | Varies | BLOCK | Context-aware agent verification — offering, omission, task/plan checks (agent hook) |

**Coverage model:** Layers 1+2 are intentionally conservative — near-zero false positives, may miss subtle patterns like pure rationalization without internal contradiction. Layer 3 auto-activates during structured work sessions (plan or task files present) and provides deeper, context-aware coverage including patterns that require transcript access.

## Background

This hook was designed based on research across 10+ verified GitHub issues (anthropics/claude-code #26691, #21604, #23368, #16506, #1632, #24129, #6159, #8738, #20270, #1113), the Columbia DAPLab "Vibe Coding Needs Policy Enforcement" research, the Cognition/Anthropic "context anxiety" discovery, and analysis of real session logs showing agents using euphemistic language ("accelerate," "consolidate," "streamline") to disguise work-skipping as productivity optimization.
