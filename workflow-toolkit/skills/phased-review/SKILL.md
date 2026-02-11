---
name: phased-review
description: |
  Multi-stage implementation review with parallel sub-agents, severity-based autonomous fixes,
  and gated test verification. Runs code quality, architecture, simplicity, documentation,
  and security reviews in sequence with test gates between each fix stage. Security review
  is blocked until all other fixes are complete.
  Use after completing a feature, implementation phase, or release candidate.
  Supports scope modes: full, code-only, security, simplicity, docs.
triggers:
  - "phased review"
  - "run review"
  - "review and validate"
  - "validate implementation"
  - "pre-release review"
  - "review implementation"
  - "full review"
  - "code review"
  - "security review"
  - "simplicity review"
  - "docs review"
---

# Phased Review

Multi-stage implementation review pipeline with parallel sub-agent reviews, severity-based fix autonomy, and gated test verification.

## Architecture

```
Stage 0  — Baseline Verification + Test Coverage Snapshot
Stage 1  — Parallel Code + Architecture Review (2 sub-agents)
Stage 2  — Synthesize Code/Architecture Findings
Stage 3  — Fix Code/Architecture Findings + Re-run Tests
Stage 4  — Simplicity Review (1 sub-agent)
Stage 5  — Fix Simplicity Findings + Re-run Tests
Stage 6  — Documentation Review (1 sub-agent)
Stage 7  — Fix Documentation Findings + Re-run Tests
Stage 8  — Parallel Security Review (3 sub-agents) ← BLOCKED until 3, 5, 7 pass
Stage 9  — Synthesize Security Findings
Stage 10 — Fix Security Findings + Re-run Tests
Stage 11 — Final Verification + Completion Validation
```

### Design Principles

1. **Tests gate every fix stage.** Tests run at Stage 0, then re-run after Stages 3, 5, 7, 10, and 11. No stage proceeds if tests fail.
2. **Security is always last.** Stage 8 is blocked until Stages 3, 5, and 7 complete with passing tests.
3. **Parallel within stages, sequential between stages.** Stage 1 dispatches its two sub-agents in parallel; Stage 8 dispatches its three sub-agents in parallel. Stage 8 itself is strictly blocked until Stages 3, 5, and 7 complete with passing tests.
4. **Autonomous fixes with escalation.** Fix stages apply Critical, High, and Medium findings. Escalate to user only if a fix would change design intent or core functionality.
5. **Language agnostic.** Baseline detection probes for test runners across ecosystems.
6. **No git operations.** No branches, commits, or PRs. The calling agent or user handles git workflow.
7. **Centralized review log.** All findings written to a single file for traceability.

---

## Step 1: Scope Mode Selection

Parse the user's request to determine scope mode. If ambiguous, ask.

| Mode | Stages Run | Use Case |
|------|-----------|----------|
| `full` | 0, 1-11 | Complete pre-release validation |
| `code-only` | 0, 1-3, 11 | Code quality pass — security explicitly out of scope |
| `security` | 0, 8-10, 11 | Security-focused review only |
| `simplicity` | 0, 4-5, 11 | YAGNI / over-engineering check |
| `docs` | 0, 6-7, 11 | Documentation completeness review |

**Default:** `full`

Store the selected mode — it determines which stages run and what the completion checklist validates.

If mode is `code-only`, inform the user: "Note: code-only mode does not include security review. Run with `security` or `full` mode for security coverage."

---

## Step 2: Review Log Setup

Create a review log file in `.claude/memory/reviews/`. This directory is gitignored (under `.claude/memory/`) so review logs are never committed to the repo.

Create the directory if it doesn't exist: `mkdir -p .claude/memory/reviews`

**Filename:** `phased-review-YYYY-MM-DD.md` (use current date)

If a log with today's date already exists, append a counter: `phased-review-YYYY-MM-DD-2.md`

Write the log header:
```markdown
# Phased Review Log

- **Date:** [YYYY-MM-DD]
- **Mode:** [selected mode]
- **Stages:** [list of stage numbers for this mode]
- **Project:** [project name / working directory]
```

---

## Step 3: Execute Stages

Run only the stages included in the selected mode, in order. Each stage writes results to the review log.

### Stage 0 — Baseline Verification

**Always runs in every mode.**

Follow the detection and execution probes in **references/baseline-detection.md** to:

1. **Detect and run the test command.** Record total, passing, failing, skipped, and exit code.
2. **Detect and run linting/typechecking** (if available). Record pass/fail per tool. Skip tools that aren't present.
3. **Detect and run coverage measurement** (if available). Record percentage. If no coverage tool found, note "not measured."
4. Check CLAUDE.md or project config for custom test/lint commands — prefer those if specified.

Write to review log:
```markdown
## Stage 0 — Baseline
- Tests: [X] passing, [Y] failing, [Z] skipped (exit code [N])
- Lint: [tool]: [PASS/FAIL] (or SKIPPED if not available)
- Typecheck: [tool]: [PASS/FAIL] (or SKIPPED if not available)
- Coverage: [X%] (tool: [name]) or "not measured"
- Test command: `[detected command]`
- Status: **[PASS/FAIL]**
```

**GATE:** If tests fail (exit code != 0), **STOP**. Report failures and tell the user they must fix baseline failures before review can begin. Do not proceed to any further stage.

---

### Stage 1 — Parallel Code + Architecture Review

**Modes:** `full`, `code-only`

Launch two sub-agents **in parallel** using the Task tool. Use the prompts from **references/sub-agent-prompts.md**.

**Sub-Agent A — Code Review:**
```
subagent_type: "workflow-toolkit:code-reviewer"
```

**Sub-Agent B — Architecture Review:**
```
subagent_type: "compound-engineering:review:architecture-strategist"
```

Both agents must output findings categorized as **Critical / High / Medium / Low** with:
- Finding ID (C1, C2... for code; A1, A2... for architecture)
- File path and line reference
- Description
- Recommended fix

Write raw outputs to review log under `## Stage 1 — Raw Findings (Code)` and `## Stage 1 — Raw Findings (Architecture)`.

---

### Stage 2 — Synthesize Code/Architecture Findings

**Modes:** `full`, `code-only`

1. Read both sub-agent outputs from Stage 1
2. Deduplicate findings referencing the same code location or issue
3. Assign consolidated IDs: CA-001, CA-002, etc.
4. Group by severity: Critical > High > Medium > Low

Write to review log:
```markdown
## Stage 2 — Code/Architecture Findings (Consolidated)
### Critical
- CA-001: [description] — [file:line]
### High
- CA-002: [description] — [file:line]
### Medium
- CA-003: [description] — [file:line]
### Low (informational — do not fix)
- CA-004: [description] — [file:line]

**Totals:** [X] Critical, [Y] High, [Z] Medium, [W] Low
```

---

### Stage 3 — Fix Code/Architecture Findings + Re-run Tests

**Modes:** `full`, `code-only`

1. Fix all **Critical** findings
2. Fix all **High** findings
3. Fix all **Medium** findings
4. **Escalate to user** any fix that would change design intent or core functionality — do not apply autonomously
5. Re-run the test command detected in Stage 0
6. If tests fail after fixes, debug and resolve before proceeding

Write to review log:
```markdown
## Stage 3 — Code/Architecture Fixes
- **Fixed:** [list of CA-IDs with one-line fix descriptions]
- **Escalated:** [list of CA-IDs with reason for escalation]
- **Deferred:** [Low findings — not fixed, informational only]
- Tests after fix: [X] passing, [Y] failing
- Status: **[PASS/FAIL]**
```

**GATE:** Tests must pass before proceeding.

---

### Stage 4 — Simplicity Review

**Modes:** `full`, `simplicity`

Launch one sub-agent using the prompt from **references/sub-agent-prompts.md**.

```
subagent_type: "compound-engineering:review:code-simplicity-reviewer"
```

The agent categorizes findings as:
- **Should Apply** — clear simplification, no functional loss
- **Consider** — judgment call, context-dependent
- **Skip** — informational only

Write to review log under `## Stage 4 — Simplicity Findings`.

---

### Stage 5 — Fix Simplicity Findings + Re-run Tests

**Modes:** `full`, `simplicity`

1. Apply all **Should Apply** findings autonomously
2. For **Consider** findings, apply only if clearly beneficial; otherwise note as deferred
3. Re-run tests

Write to review log:
```markdown
## Stage 5 — Simplicity Fixes
- **Applied:** [list with descriptions]
- **Deferred:** [list with reasons]
- Tests after fix: [X] passing, [Y] failing
- Status: **[PASS/FAIL]**
```

**GATE:** Tests must pass before proceeding.

---

### Stage 6 — Documentation Review

**Modes:** `full`, `docs`

Launch one sub-agent using the prompt from **references/sub-agent-prompts.md**.

```
subagent_type: "workflow-toolkit:ops-docs-generator"
```

Output: list of missing or outdated documentation with specific recommendations and draft content where possible.

Write to review log under `## Stage 6 — Documentation Findings`.

---

### Stage 7 — Fix Documentation Findings + Re-run Tests

**Modes:** `full`, `docs`

1. Apply documentation fixes (update README, add missing docs, fix outdated content)
2. Re-run tests to ensure no accidental code modifications
3. If tests fail, something was accidentally changed — investigate and fix

Write to review log:
```markdown
## Stage 7 — Documentation Fixes
- **Updated:** [list of files modified]
- **Created:** [list of new files, if any]
- Tests after fix: [X] passing, [Y] failing
- Status: **[PASS/FAIL]**
```

**GATE:** Tests must pass before proceeding.

---

### Stage 8 — Parallel Security Review (3 Personas)

**Modes:** `full`, `security`

**BLOCKING CONDITION:** In `full` mode, this stage MUST NOT begin until Stages 3, 5, and 7 are ALL complete with passing tests. Verify all three gates passed before proceeding. In `security` mode (which skips 1-7), proceed directly after Stage 0 passes.

Launch three sub-agents **in parallel** using the Task tool. Use the prompts from **references/sub-agent-prompts.md**.

**Sub-Agent E — Offensive Security (Red Team):**
```
subagent_type: "compound-engineering:review:security-sentinel"
```
Thinks like an attacker. Finds exploitation paths, proves attack vectors with concrete PoC inputs, identifies the highest-impact vulnerabilities. IDs: OT1, OT2, etc.

**Sub-Agent F — Defensive Security (Technical/Code):**
```
subagent_type: "security-scanning:security-auditor"
```
Defense-in-depth mindset. Secure coding patterns, input validation at every layer, encryption implementation, security headers, DevSecOps integration. IDs: DF1, DF2, etc.

**Sub-Agent G — Security Architecture / Auditor:**
```
subagent_type: "security-scanning:threat-modeling-expert"
```
STRIDE analysis, attack tree construction, data flow diagrams, trust boundary mapping, risk scoring, and residual risk documentation. IDs: SA1, SA2, etc.

All three agents output findings as **Critical / High / Medium / Low** with finding IDs, file references, descriptions, and recommended fixes.

Write raw outputs to review log under:
- `## Stage 8 — Raw Findings (Offensive)`
- `## Stage 8 — Raw Findings (Defensive/Technical)`
- `## Stage 8 — Raw Findings (Security Architecture)`

---

### Stage 9 — Synthesize Security Findings

**Modes:** `full`, `security`

1. Read all three sub-agent outputs from Stage 8 (offensive, defensive, architecture)
2. Deduplicate — findings from different personas that identify the same underlying issue get merged (note which personas flagged it)
3. Assign consolidated IDs: SEC-001, SEC-002, etc.
4. Classify each finding:
   - **Actionable** — can and should be fixed in this review cycle
   - **Informational** — noted for awareness or future work
   - **Deferred** — requires design changes beyond this review's scope

Write to review log:
```markdown
## Stage 9 — Security Findings (Consolidated)
### Critical
- SEC-001 (actionable): [description] — [file:line]
### High
- SEC-002 (actionable): [description] — [file:line]
- SEC-003 (informational): [description — reason for deferral]
### Medium
- SEC-004 (deferred): [description — requires design change]
### Low (informational — do not fix)
- SEC-005: [description]

**Totals:** [X] Critical, [Y] High, [Z] Medium, [W] Low
**Actionable:** [N], **Informational:** [N], **Deferred:** [N]
```

---

### Stage 10 — Fix Security Findings + Re-run Tests

**Modes:** `full`, `security`

1. Fix all **actionable** Critical, High, and Medium security findings
2. Add security-specific tests where applicable (input validation, injection tests, boundary checks)
3. **Escalate to user** if a fix would change design intent
4. Re-run tests including any newly added security tests

Write to review log:
```markdown
## Stage 10 — Security Fixes
- **Fixed:** [list of SEC-IDs with descriptions]
- **New tests added:** [count and brief descriptions]
- **Informational/Deferred:** [list with justifications]
- Tests after fix: [X] passing, [Y] failing
- Status: **[PASS/FAIL]**
```

**GATE:** Tests must pass.

---

### Stage 11 — Final Verification + Completion Validation

**Always runs in every mode.**

#### 11.1 — Re-run Full Test Suite
Execute the test command from Stage 0. Record final counts.

#### 11.2 — Re-run Coverage (if measured at baseline)
Execute the coverage command from Stage 0. Record final percentage.

#### 11.3 — Re-run Lint/Typecheck (if available at baseline)
Execute lint/typecheck commands from Stage 0. Record final status.

#### 11.4 — Completion Validation Checklist

For the selected scope mode, verify every required stage was executed and recorded in the review log. Read the review log file and check:

**`full` mode — ALL required:**
- [ ] Stage 0: Baseline recorded with test counts and coverage
- [ ] Stage 1: Two sub-agent reviews launched (code + architecture)
- [ ] Stage 2: Consolidated findings written with severity counts
- [ ] Stage 3: Fixes applied, tests re-run and passing
- [ ] Stage 4: Simplicity review completed
- [ ] Stage 5: Simplicity fixes applied, tests re-run and passing
- [ ] Stage 6: Documentation review completed
- [ ] Stage 7: Documentation fixes applied, tests re-run and passing
- [ ] Stage 8: Three security sub-agents launched (offensive, defensive, architecture)
- [ ] Stage 9: Security findings consolidated with severity counts
- [ ] Stage 10: Security fixes applied, tests re-run and passing
- [ ] Stage 11: Final verification passing

**`code-only` mode:** Stages 0, 1, 2, 3, 11
**`security` mode:** Stages 0, 8, 9, 10, 11
**`simplicity` mode:** Stages 0, 4, 5, 11
**`docs` mode:** Stages 0, 6, 7, 11

#### 11.5 — Success Criteria

ALL must be true for the review to **PASS**:

1. All tests passing (0 failures)
2. No unfixed Critical findings across any stage
3. No unfixed High findings (unless explicitly escalated to and accepted by the user)
4. All Medium findings either fixed or documented as deferred with justification
5. Lint/typecheck passing (if they passed at baseline)
6. Coverage not decreased from baseline (if measured at baseline)
7. Every stage required by the selected mode has an entry in the review log

#### 11.6 — Write Final Summary

Write to review log:
```markdown
## Stage 11 — Final Verification

### Test Results
- Baseline: [X] passing, [Y] failing → Final: [X] passing, [Y] failing
- New tests added during review: [N]

### Coverage
- Baseline: [X%] → Final: [Y%] (delta: [+/-Z%])

### Lint / Typecheck
- Baseline: [status] → Final: [status]

### Findings Summary
| Stage | Critical | High | Medium | Low | Fixed | Escalated | Deferred |
|-------|----------|------|--------|-----|-------|-----------|----------|
| Code/Arch (1-3) | ... | ... | ... | ... | ... | ... | ... |
| Simplicity (4-5) | - | - | - | - | ... | ... | ... |
| Documentation (6-7) | - | - | - | - | ... | ... | ... |
| Security (8-10) | ... | ... | ... | ... | ... | ... | ... |
| **Total** | ... | ... | ... | ... | ... | ... | ... |

### Completion Validation
- Mode: [mode]
- Stages required: [list]
- Stages completed: [list]
- Missing stages: [none / list]

### Final Status: **[PASS / FAIL]**
[If FAIL, list specific criteria not met]
```

#### 11.7 — Present Summary to User

**You MUST display the full Stage 11 summary directly in the conversation.** Do not just write to the review log — the user needs to see the results without opening the file. Present:

1. The complete findings summary table (all stages, all severities, fix/escalate/defer counts)
2. Test results comparison (baseline → final)
3. Coverage delta (if measured)
4. Completion validation status (all stages checked off or missing stages listed)
5. **Final PASS/FAIL status** with specific unmet criteria if FAIL
6. The review log file path for full details: `.claude/memory/reviews/phased-review-[date].md`

If the review **PASSED**, confirm clearly. If it **FAILED**, list every unmet criterion and what the user needs to address.
