# Anti-Laziness Guard — Phrase Taxonomy

Complete taxonomy of laziness rationalization phrases with confidence levels, sources, and enforcement status.

## Tier 1: Very High Confidence (>90%) — BLOCK

These phrases are almost never legitimate when an agent uses them at stop time to justify not doing assigned work.

| Pattern | Example | Source |
|---------|---------|--------|
| `skip the remaining` | "I'll skip the remaining review stages" | User's original example |
| `skip the.*review` | "skip the security review" | Issue #26691, #16506 |
| `skip the.*test` | "Let's skip the failing tests" | Issue #23368 |
| `skip the.*stage` | "skip the remaining stages" | Issue #6159 |
| `skip the.*phase` | "skip Phase 4-6" | Issue #6159 |
| `skip the.*step` | "skip this step" | Issue #26691 |
| `skip external research` | "skip external research and go straight to recommendations" | User session logs |
| `in the interest of time` | "in the interest of time, I'll summarize" | Community-documented, widely reported |
| `for brevity` | "for brevity, I'll omit the details" | Issue #4695, community reports |
| `considerable time` | "since they would take considerable time" | User's original example |
| `would take too long` | "the full review would take too long" | Community reports |
| `takes? significant` | "takes significant effort" | Variant of above |
| `context constraints` | "Given context constraints, I'll skip external research" | User session logs (verified) |
| `running low on context` | "running low on context window" | Context anxiety research (Cognition/Inkeep) |
| `context limit` | "approaching the context limit" | Context anxiety research |
| `conserve tokens` | "to conserve tokens" | Context anxiety research |
| `session is getting long` | "This review session is getting long" | User session logs (verified) |
| `accelerate through the remaining` | "let me accelerate through the remaining stages" | User session logs (verified) |
| `consolidate the remaining` | "I'll consolidate the remaining stages" | User session logs (verified) |

## Tier 2: High Confidence (75-90%) — BLOCK

Strong signals with slightly more legitimate-use surface area. Still blocked because at stop time, the laziness interpretation is overwhelmingly more likely.

| Pattern | Example | Source | Scoping |
|---------|---------|--------|---------|
| `not worth the complexity` | "not worth the complexity" | Issue #20270 | Simple match |
| `not worth the effort` | "not worth the effort for this case" | Variant of above | Simple match |
| `do that later` | "we can do that later" | Issue #20270 | Simple match |
| `doesn't need a formal` | "doesn't need a formal skill" | Issue #26691 | Simple match |
| `for the sake of efficiency` | "for the sake of efficiency" | Euphemistic acceleration | Simple match |
| `to save time` | "to save time, I'll combine these" | Community reports | Simple match |
| `overkill` | "The skill is overkill for this" | Issue #26691 | Scoped: must co-occur with skill/process/step/stage/review/check |
| `this is straightforward` | "this is straightforward, no need for full review" | Issue #16506 | Scoped: must co-occur with skip/don't need/no need/unnecessary |
| `for now` | "Let's skip the failing tests for now" | Issue #23368 | Scoped: must co-occur with skip/remaining/stage/review/step/defer/later/move on |

## Tier 3: Medium Confidence (50-75%) — DOCUMENTED ONLY (not enforced)

These phrases have real dual-use. They appear in both lazy and legitimate contexts. Documented here for potential future enforcement if false-positive rate proves acceptable.

| Pattern | Why Medium | Common False Positive |
|---------|-----------|----------------------|
| `already covered` | Could be genuine — prior work sometimes does cover it | Legitimate cross-referencing between review stages |
| `already addressed` | Same as above | Same |
| `already handled` | Same as above | Same |
| `pre-existing` | Could be a real observation about existing bugs | Legitimately noting existing issues unrelated to current work |
| `out of scope` | Could be genuine scope boundary | Legitimately noting scope limits defined by the user |
| `move on to` | Could be legitimate transition | Normal workflow progression between assigned tasks |
| `proceed to` | Same as above | Same |
| `streamline` | Context-dependent — 48 hits in user's logs, most legitimate | Normal efficiency language in technical descriptions |
| `efficiently` | Very common legitimate word | Normal description of approach or implementation |
| `good enough` / `sufficient` | Could be genuine quality assessment | Legitimate engineering judgment about coverage or completeness |
| `follow-up` | Could be genuine suggestion for future work | Legitimately suggesting non-assigned enhancements |

## Tier 4: Internal Contradiction Detection — PROMPT HOOK

These require Haiku evaluation because no keyword pattern can reliably detect self-contradicting completion claims. Layer 2 evaluates a single criterion: does the message claim completion while containing contradicting evidence of incompleteness?

| Pattern | Detection Method | Example |
|---------|-----------------|---------|
| Premature victory | Prompt hook | "Everything is working now!" (but lists 3 remaining items) — Issue #8738 |
| Positive framing of incomplete work | Prompt hook | "This is a good start" (contradicts completion claim) — DoltHub blog |

**Note:** Pure rationalization without internal contradiction (e.g., "The key changes are [partial list]" with no completion claim) is no longer caught at this tier. This is an accepted tradeoff — see ADR-006 addendum.

## Tier 5: Context-Dependent Detection — AGENT HOOK

These patterns require conversation context (transcript access) to distinguish laziness from legitimate behavior. Detected by the Layer 3 agent hook, which auto-activates when plan or task files exist.

| Pattern | Detection Method | Example |
|---------|-----------------|---------|
| Silent omission | Agent hook (transcript comparison) | Summarizing 5 of 10 assigned items without mentioning the other 5 — Issue #1632 |
| Offering instead of doing | Agent hook (transcript comparison) | "Let me know if you'd like me to create the other files" when creation was assigned — Issue #1113 |
| Unchecked tasks in task list | Agent hook (task file check) | Tasks with "pending"/"in_progress" status when agent claims done |
| Plan steps not addressed | Agent hook (plan file check) | Numbered plan steps not cross-referenced in completion summary |

## Sources

### Verified GitHub Issues (anthropics/claude-code)
- **#26691** — Claude skips mandatory skill task list checkpoints; "I was optimizing for speed over process"
- **#21604** — Claude ignores CLAUDE.md with helpfulness judgment calls; "this is only 7 lines, I'll skip the sprint doc"
- **#23368** — Feature request for AssistantResponse hook; "Let's skip the failing tests for now"
- **#16506** — Claude ignores explicit instructions; "I prioritized speed over process"
- **#1632** — Claude stops with unfinished TODOs; premature victory declarations
- **#24129** — Claude skips hard tasks, does easy ones; "I was lazy and chased speed"
- **#6159** — Agent stops mid-task, fails to complete its own plan
- **#8738** — Premature victory declaring without actually fixing issues
- **#20270** — "not worth the complexity" for 4-line changes
- **#1113** — Offering partial work instead of completing

### Verified Session Logs
- "accelerate through the remaining stages" — claudebox session
- "consolidate the remaining stages" — claudebox session
- "Given context constraints, I'll skip external research" — robot-tools session
- "Given context constraints, I'll batch the parallel agents and keep synthesis tight" — robot-tools session

### Academic/Industry Research
- Columbia DAPLab — "Vibe Coding Needs Policy Enforcement" (Jan 2026)
- Cognition/Inkeep — "Context Anxiety: How AI Agents Panic About Their Perceived Context Windows"
- Trail of Bits — claude-code-config stop hook patterns
- Taskmaster (blader/taskmaster) — done token pattern and honesty check prompts
