---
name: session-retrospective
description: |
  Iterative reflection, research, and improvement skill for extracting actionable learnings from any Claude Code session.
  Use after longer sessions to capture process improvements, project improvements, or both.
  Produces agent-ready context documents for future implementation.
triggers:
  - "session retrospective"
  - "what did we learn"
  - "session review"
  - "extract learnings"
  - "improve process"
  - "after action review"
  - "reflect"
  - "reflection"
  - "reflect on"
  - "retro"
  - "retrospective"
  - "session summary"
  - "lessons learned"
---

# Session Retrospective

A structured methodology for extracting actionable improvements from any Claude Code session. Based on After Action Review principles combined with AI-specific metacognitive learning patterns.

## When to Use This Skill

- After any session longer than 30 minutes
- When significant friction was encountered
- After completing a complex multi-step task
- When a new pattern or approach was discovered
- Periodically (weekly/monthly) for continuous improvement

## Core Principles

1. **Ground Truth**: Those who experienced the session directly are best able to understand its significance
2. **Forward Focus**: Think about what happened in context of what will happen next time
3. **Iteration**: Keep retrospectives short and actionable—blur the line between learning and doing
4. **Lesson Learned ≠ Lesson Observed**: If there's no change, there's been no learning

---

## Phase 0: Scope Selection

Before beginning, clarify what type of improvements to focus on.

**Present to user:**
```
What would you like to improve from this session?

1. PROCESS   - How we work together (applicable to all future sessions)
2. PROJECT   - The specific project/skill/codebase we worked on
3. BOTH      - Extract both process and project improvements

Select [1-3]:
```

Store selection for Phase 5 filtering.

---

## Phase 1: Session Review (Ground Truth)

**Objective:** Capture what actually happened while memories are fresh.

### 1.1 Successes
Ask the user (or infer from conversation if user prefers):
```
What went WELL in this session?
- Tasks completed successfully
- Efficient approaches discovered
- Good collaboration moments
- Problems solved elegantly

(List 3-5 items, or say "infer from conversation")
```

### 1.2 Friction Points
```
What caused FRICTION in this session?
- Repeated attempts needed
- Confusion or miscommunication
- Slow or tedious operations
- Permission prompts or interruptions
- Context limits hit
- Errors encountered

(List 3-5 items, or say "infer from conversation")
```

### 1.3 Surprises
```
What was UNEXPECTED (good or bad)?
- Behaviors that differed from expectations
- Discoveries made along the way
- Assumptions that proved wrong

(List 1-3 items, or say "infer from conversation")
```

---

## Phase 2: Evidence Gathering

**Objective:** Collect concrete evidence to support observations.

### 2.1 Conversation Analysis
Review the session for:
- Tool calls that failed or required multiple attempts
- User messages expressing frustration or confusion
- Repeated patterns (good or bad)
- Time-consuming operations
- Successful approaches worth capturing

### 2.2 Artifact Review
Check for relevant outputs:
- Error messages and stack traces
- Tool output that was verbose or truncated
- Files created or modified
- Commands that were blocked or required confirmation

### 2.3 Categorize Findings
Organize evidence into:

| Category | Evidence Type | Example |
|----------|--------------|---------|
| **Efficiency** | Time sinks, redundant operations | "Ran same search 3 times" |
| **Quality** | Errors, incomplete results | "Missing validation caused bug" |
| **UX** | Friction, confusion, interruptions | "12 permission prompts" |
| **Knowledge** | Missing info, wrong assumptions | "Didn't know API existed" |
| **Architecture** | Structural issues, design problems | "Sequential when parallel possible" |

---

## Phase 3: External Research

**Objective:** Gather best practices and prior art to inform recommendations.

### 3.1 Identify Research Topics
Based on friction points and categories, identify 2-4 research topics:
- If efficiency issues → search for optimization patterns
- If quality issues → search for testing/validation approaches
- If UX issues → search for permission/confirmation patterns
- If knowledge gaps → search for documentation/learning resources
- If architecture issues → search for design patterns

### 3.2 Execute Research
Use the ai-dev-research skill or direct web searches:
```
Research: [topic] best practices 2025
Focus on: production patterns, lessons learned, authoritative sources
```

### 3.3 Synthesize Findings
For each research topic, capture:
- Key insight with citation
- How it applies to observed friction
- Concrete recommendation derived from research

---

## Phase 4: Cross-Cutting Analysis

**Objective:** Find overlaps, dependencies, and unified improvements.

### 4.1 Map Relationships
For each potential improvement, ask:
- Does this overlap with another improvement?
- Does this depend on another improvement?
- Does this enable other improvements?
- Is this the same idea at a different level (process vs. project)?

### 4.2 Cluster Related Items
Group improvements that:
- Address the same root cause
- Must be implemented together
- Form a coherent "system" (e.g., parallel execution + artifact storage + detailed prompts)

### 4.3 Identify Dependencies
Create dependency graph:
```
A ──depends on──> B
C ──enables──> D
E ──same as──> F (different levels)
```

---

## Phase 5: Prioritization

**Objective:** Rank improvements by combined impact.

### 5.1 Scoring Criteria

| Criterion | Weight | Description |
|-----------|--------|-------------|
| **Impact** | 40% | How much improvement if implemented? |
| **Frequency** | 25% | How often will this help? |
| **Effort** | 20% | How hard to implement? (inverse) |
| **Dependencies** | 15% | Does this enable other improvements? |

### 5.2 Scope Filtering
Based on Phase 0 selection:
- **PROCESS**: Include only user-level improvements (applicable to any project)
- **PROJECT**: Include only project-specific improvements
- **BOTH**: Include all, but tag each with scope

### 5.3 Produce Ranked List
Create unified top N list (typically 5-10 items):

| Rank | Improvement | Scope | Impact | Effort | Dependencies |
|------|-------------|-------|--------|--------|--------------|
| 1 | ... | ... | ... | ... | ... |

---

## Phase 6: Actionable Output

**Objective:** Produce implementation-ready recommendations.

### 6.1 Document Structure
Create a document with:

```markdown
# Session Retrospective: [Date] - [Topic/Project]

## How to Use This Document
[Instructions for future agent sessions]

## Executive Summary
[2-3 sentence overview]

## Context
- Session date: [date]
- Duration: [approximate]
- Primary task: [what was being done]
- Scope: [PROCESS/PROJECT/BOTH]

## Key Findings
### Successes
- [item with evidence]

### Friction Points
- [item with evidence]

## Research Insights
[Key findings from Phase 3 with citations]

## Unified Recommendations (Ranked)
[Table from Phase 5]

## Implementation Menu
[Selectable items with effort estimates and dependencies]

## Implementation Specifications
[For each menu item: files to modify, steps, acceptance criteria]
```

### 6.2 Implementation Specifications
For each recommendation, include:
- **Files to modify/create**
- **Implementation steps** (numbered, specific)
- **Acceptance criteria** (checkboxes)
- **Dependencies** (which other items must come first)

### 6.3 Save Location
Ask user:
```
Where should I save the retrospective document?

1. ~/Documents/retrospectives/[date]-[topic].md
2. [Project]/.claude/retrospectives/[date].md
3. Custom path
4. Display only (don't save)

Select [1-4]:
```

---

## Phase 7: Verification

**Objective:** Ensure the retrospective will lead to actual change.

### 7.1 Actionability Check
For each recommendation, verify:
- [ ] Specific enough to implement without re-research?
- [ ] Clear acceptance criteria?
- [ ] Dependencies identified?
- [ ] Effort estimated?

### 7.2 User Confirmation
```
I've identified [N] improvements ranked by impact.

Top 3:
1. [name] - [scope] - [effort]
2. [name] - [scope] - [effort]
3. [name] - [scope] - [effort]

Would you like to:
1. Review full document
2. Save and implement top item now
3. Save for later implementation
4. Revise (specify what to change)

Select [1-4]:
```

### 7.3 Backlog Management

After implementation decisions, handle deferred items:

**For each item NOT implemented:**
1. Add to `improvement_backlog.md` with:
   - Unique ID (P-XXX for PROCESS, J-XXX for PROJECT)
   - Source link to this retrospective
   - Problem, proposed solution, acceptance criteria
   - Priority and effort from scoring

**Backlog location:** `~/Library/CloudStorage/GoogleDrive-sabreace33@gmail.com/My Drive/Obsidian/my-notes/ai_plans/`

**Template for backlog entry:**
```markdown
#### [P/J]-XXX: [Improvement Name]

**Added:** [date]
**Source:** [[retrospective-filename#Item N]]
**Priority:** [High/Medium/Low]
**Effort:** [Low/Medium/High]
**Dependencies:** [list or None]

**Problem:** [What friction or issue was encountered]

**Proposed Solution:** [What should be done]

**Acceptance Criteria:**
- [ ] [criterion 1]
- [ ] [criterion 2]
```

### 7.4 Update Improvement Log

After implementing improvements:
1. Add entry to `improvement_log.md` with full details
2. Update retrospective document to mark items as completed
3. Move any completed backlog items to the archive section

---

## Anti-Patterns to Avoid

| Anti-Pattern | Why It's Bad | Better Approach |
|--------------|--------------|-----------------|
| **Vague recommendations** | "Improve error handling" → no action | "Add try/catch to X function with specific error types" |
| **No evidence** | Opinions without support | Cite specific moments from session |
| **No research** | Reinventing known solutions | Check existing best practices first |
| **No prioritization** | Everything seems important | Force-rank by impact × frequency |
| **No implementation spec** | Future self won't know what to do | Include files, steps, acceptance criteria |
| **No follow-through** | "Lesson observed, not learned" | Offer to implement top item immediately |

---

## Example Invocations

```
# After a skill development session
"Let's do a session retrospective focused on the process"

# After a debugging session
"What did we learn from this debugging session? Extract project improvements."

# Periodic review
"Run a retrospective on our last few sessions - what patterns should we change?"

# Immediate action
"Retrospective with immediate implementation of top improvement"
```

---

## Integration with Other Skills

This skill works well with:
- **ai-dev-research**: For Phase 3 external research
- **research-verification**: Apply verification checklist during research
- **parallel-first-design-guide**: If architecture issues identified
- **skill-creator**: If creating new skills based on learnings

## Related Documents

Maintain these companion documents:

**Location:** `~/Library/CloudStorage/GoogleDrive-sabreace33@gmail.com/My Drive/Obsidian/my-notes/ai_plans/`

| Document | Purpose |
|----------|---------|
| `improvement_log.md` | Running log of completed improvements with full context |
| `improvement_backlog.md` | Queue of deferred improvements awaiting implementation |

**Workflow:**
1. Retrospective identifies improvements
2. Implemented items → `improvement_log.md`
3. Deferred items → `improvement_backlog.md`
4. Future sessions check backlog for relevant items

---

## Metadata

**Version:** 1.1.0
**Created:** 2025-01-18
**Updated:** 2025-01-20

**Changelog:**
- 1.1.0 (2025-01-20): Added backlog management (7.3), improvement log integration (7.4), related documents section, additional triggers
- 1.0.0 (2025-01-18): Initial release

**Based on:**
- After Action Review methodology (US Army, 1980s)
- Metacognitive learning framework (arXiv:2506.05109)
- HealthFlow self-evolving agent patterns (arXiv:2508.02621)
- Zimmerman's self-regulation model (planning, execution, reflection)

**Sources:**
- [BetterEvaluation: After Action Review](https://www.betterevaluation.org/methods-approaches/methods/after-action-review)
- [Beam AI: Self-Learning Agents](https://beam.ai/agentic-insights/self-learning-ai-agents-transforming-automation-with-continuous-improvement)
- [Monday.com: After Action Reports 2025](https://monday.com/blog/project-management/after-action-report/)
- [Anthropic: Multi-Agent Research System](https://www.anthropic.com/engineering/multi-agent-research-system)
