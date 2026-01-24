# Secret Scanning Alert Investigator

## Purpose

Investigate GitHub secret scanning alerts to trace provenance, gather context, assess risk, and produce a structured report for security professionals. This skill handles one or more alerts in a single investigation using only open-source tools.

## Trigger Phrases

- "investigate secret scanning alert"
- "analyze leaked secret"
- "trace secret provenance"
- "secret scanning report"
- "investigate secret scanning alerts" (batch)

---

## Critical Requirements

### Evidence-Based Analysis Only

**DO NOT make assumptions or guesses.** All reported information must be:

- Validated with actual API responses, git history, or file contents
- Cited with specific commit SHAs, timestamps, or API endpoints
- Clearly distinguished from estimates or possibilities

When providing estimates or possibilities (e.g., in risk assessment):
- Explicitly label them as "ESTIMATE" or "POSSIBLE"
- Explain the logic and evidence used to arrive at them
- State what evidence would be needed to confirm

### Modification Safeguards

**Any action that modifies state requires explicit safeguards:**

1. **Warn the user** about the specific action and its consequences
2. **Request explicit confirmation** with "CONFIRM" before proceeding
3. **Never assume** the user wants to resolve, close, or modify anything

Actions requiring double-confirmation:
- Resolving or closing alerts
- Adding comments to alerts
- Any GitHub API PATCH/POST/DELETE operations
- Creating issues, PRs, or gists
- Running active verification against third-party services
- Executing history cleanup commands
- Installing tools on the user's system

Permitted without confirmation:
- GET/read operations
- Creating/deleting local temporary clones in `/tmp`
- Writing reports to user-specified local paths
- Passive analysis of already-retrieved data

---

## Parallel Execution Architecture

This skill uses parallel sub-agents to accelerate investigation:

```
Phase 0: Tool Check (sequential)
    |
Phase 0.5: Permission Pre-Approval (sequential - user interaction)
    |
Phase 1: Mode Selection (sequential - user interaction)
    |
+-----------------------------------------------------------+
|                    PARALLEL BLOCK A                        |
|  Agent A1: Alert Acquisition    -> Full alert + locations  |
|  Agent A2: Repository Clone     -> Clone + file history    |
|  Agent A3: Commit/PR Context    -> Author, PR, issues      |
+-----------------------------------------------------------+
    | (wait for all)
+-----------------------------------------------------------+
|                    PARALLEL BLOCK B                        |
|  Agent B1: TruffleHog Scan      -> Detection + verify      |
|  Agent B2: Gitleaks Scan        -> Cross-validate + SARIF  |
|  Agent B3: Entropy Analysis     -> Shannon entropy         |
|  Agent B4: Service Analysis     -> GitHub App / token      |
+-----------------------------------------------------------+
    | (wait for all)
Phase 6.2: Active Verification (requires confirmation)
    |
Phase 7: Risk Assessment (synthesis)
    |
Phase 8: Report & Actions (user interaction)
```

### Sub-Agent Invocation

Use the Task tool to launch parallel agents:
```
# Launch Parallel Block A (all three in single message)
<Task tool call 1: subagent_type="Explore", prompt="...", run_in_background=true>
<Task tool call 2: subagent_type="Explore", prompt="...", run_in_background=true>
<Task tool call 3: subagent_type="Explore", prompt="...", run_in_background=true>
```

**READ: `references/sub-agents/block-a.md`** for Agent A1-A3 prompts.
**READ: `references/sub-agents/block-b.md`** for Agent B1-B4 prompts and coordinator.

### Artifact Storage Pattern

All agents write findings to `/tmp/secret-scan-{alert_number}/`:
```
alert.json       (Agent A1)
provenance.json  (Agent A2)
context.json     (Agent A3)
trufflehog.json  (Agent B1)
gitleaks.json    (Agent B2)
entropy.json     (Agent B3)
service.json     (Agent B4)
```

The coordinator reads all artifacts ONCE during synthesis phase.

---

## Phase Overview

### Phase 0: Environment Setup
Verify required tools (gh, git) and offer to install optional tools (trufflehog, gitleaks, ggshield).

**READ: `references/phases/phase-0-setup.md`** for tool check details and installation commands.

### Phase 0.5: Permission Pre-Approval
Present all read-only commands upfront for batch approval to minimize interruptions.

**READ: `references/phases/phase-0.5-permissions.md`** for permission request format.

### Phase 1: Initial Triage and Mode Selection
Fetch basic alert details and require user to select PASSIVE or ACTIVE mode.

**READ: `references/phases/phase-1-triage.md`** for mode selection prompts.

### Phases 2-6: Investigation
Deep investigation including alert acquisition, multi-tool scanning, provenance tracing, and secret-specific analysis.

**READ: `references/phases/phases-2-6-investigation.md`** for detailed procedures.

### Phase 7: Risk Assessment
Evaluate risk factors and produce overall rating (CRITICAL/HIGH/MEDIUM/LOW).

**READ: `references/phases/phase-7-risk.md`** for risk criteria and assessment format.

---

## Phase 8: Report Generation and Actions

### 8.1 Generate Report
After investigation completes, generate comprehensive report.

**READ: `references/report-template.md`** for the full report structure.

### 8.2 Output Options Menu

```
===============================================================
                    INVESTIGATION COMPLETE
===============================================================

Investigation Mode: {ACTIVE/PASSIVE}
Alerts Analyzed: {count}
Risk Rating: {CRITICAL/HIGH/MEDIUM/LOW}

OUTPUT OPTIONS:
1. Display report here
2. Save report to local file
3. Display and save

ADDITIONAL ACTIONS AVAILABLE:
4. Resolve alert(s) on GitHub
5. Generate SARIF output for security dashboard
6. Generate history cleanup commands
7. Generate prevention recommendations (pre-commit hooks, CI/CD)
8. Check for public leaks (requires ggshield)
9. Create GitHub issue with findings
10. Export timeline as CSV
11. Generate permanent permissions (settings.json)

Which options would you like? (comma-separated, e.g., "1,4,6"):
```

### Action Reference Files

Each action has detailed implementation guidance:

| Option | Action | Reference |
|--------|--------|-----------|
| 4 | Resolve Alert | `references/actions/resolve-alert.md` |
| 5 | SARIF Output | `references/actions/sarif-output.md` |
| 6 | History Cleanup | `references/actions/history-cleanup.md` |
| 7 | Prevention | `references/actions/prevention.md` |
| 8 | Public Leak Check | Uses ggshield (inline) |
| 9 | GitHub Issue | `references/actions/github-issue.md` |
| 10 | Timeline CSV | `references/actions/timeline-csv.md` |
| 11 | Permissions | `references/actions/permissions.md` |

**READ: `references/actions/rotation-guides.md`** for credential rotation instructions.

---

## Batch Processing

When multiple alerts are provided:

1. Run Phase 0 (tool check) once
2. Ask for mode selection once (applies to all unless user specifies otherwise)
3. Process each alert through Phases 2-7
4. Generate combined report with:
   - Shared executive summary noting patterns
   - Individual alert sections
   - Combined timeline showing relationships
   - Aggregate risk assessment
5. For Phase 8 actions, offer batch operations with explicit per-alert confirmation

---

## Error Handling

| Error | Handling |
|-------|----------|
| Alert not found | Report error, continue with other alerts if batch |
| Insufficient permissions | Document limitation, use available data, note in report |
| Clone fails | Fall back to API-based history, note limitation |
| Tool not available | Skip that analysis, note in report what was missed |
| Rate limiting | Wait and retry with backoff, or document incomplete analysis |
| Active verification refused | Fall back to passive analysis for that secret |

---

## Tool Requirements Summary

| Tool | Required | Purpose | License | Install |
|------|----------|---------|---------|---------|
| `gh` | **Yes** | GitHub API access | MIT | `brew install gh` |
| `git` | **Yes** | History analysis | GPL-2.0 | Pre-installed |
| `trufflehog` | No | Verification, analysis | Apache-2.0 | `brew install trufflehog` |
| `gitleaks` | No | Cross-validation, SARIF | MIT | `brew install gitleaks` |
| `ggshield` | No | Public leak check | MIT | `pip install ggshield` |
| `python3` | No | Entropy calculation | PSF | Pre-installed |

All optional tools are **free and open-source**.

---

## Example Invocations

```
# Single alert by URL
"Investigate https://github.com/org/repo/security/secret-scanning/19"

# Single alert by components
"Investigate secret scanning alert #19 in org/repo"

# Multiple alerts
"Investigate secret scanning alerts #19, #20, #21 in org/repo"

# All open alerts in repo
"Investigate all open secret scanning alerts in org/repo"

# Organization-wide
"Investigate all critical secret scanning alerts in the org organization"
```
