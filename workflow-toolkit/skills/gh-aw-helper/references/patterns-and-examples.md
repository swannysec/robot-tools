# GitHub Agentic Workflows: Patterns and Examples

Comprehensive reference for the 14 operational patterns in GitHub Agentic Workflows (gh-aw). Each pattern includes purpose, triggers, key configuration, and complete workflow examples.

## Table of Contents

1. [ChatOps](#1-chatops) — Interactive slash commands
2. [DailyOps](#2-dailyops) — Scheduled incremental improvements
3. [DataOps](#3-dataops) — Deterministic data + AI analysis
4. [DispatchOps](#4-dispatchops) — Manual triggers with inputs
5. [IssueOps](#5-issueops) — Auto-triage and responses
6. [LabelOps](#6-labelops) — Label-triggered workflows
7. [Monitoring](#7-monitoring) — GitHub Projects tracking
8. [MultiRepoOps](#8-multirepoops) — Cross-repository coordination
9. [Orchestration](#9-orchestration) — Orchestrator/worker pattern
10. [ProjectOps](#10-projectops) — AI-powered project boards
11. [SideRepoOps](#11-siderepoops) — Isolated side-repo automation
12. [SpecOps](#12-specops) — Specification maintenance
13. [TaskOps](#13-taskops) — Three-phase scaffolded improvements
14. [TrialOps](#14-trialops) — Test in isolated trial repos
15. [Quick Pattern Selection Guide](#quick-pattern-selection-guide)

---

## 1. ChatOps

**What it does:** Enables interactive automation via slash commands (e.g., `/review`, `/deploy`) in issue or PR comments.

**When to use:**
- User-initiated actions requiring immediate feedback
- Operations that need human approval or input
- Interactive code review, deployment, or investigation tasks

**Key frontmatter:**
```yaml
trigger:
  slash_command:
    name: review
    events: [pull_request_comment]
roles:
  - write  # Access control: who can invoke
```

**Security:** Always treat user content as untrusted. Use allow-lists for label names and validate inputs.

### Example: Code Review Assistant

```yaml
---
name: code-review-assistant
description: AI code review triggered by /review command
trigger:
  slash_command:
    name: review
    events: [pull_request_comment]
roles:
  - write
safe-outputs:
  - add-comment
  - add-labels:
      allowed:
        - needs-changes
        - approved
        - security-concern
---

You are a code review assistant. When a user comments `/review` on a PR:

1. Fetch the PR diff using GitHub API
2. Analyze for:
   - Code quality issues
   - Security vulnerabilities
   - Best practice violations
   - Performance concerns
3. Post a review comment with findings
4. Apply appropriate labels based on severity

Be constructive and specific. Reference line numbers when possible.

If critical security issues found, apply `security-concern` label and tag @security-team.
```

---

## 2. DailyOps

**What it does:** Scheduled incremental daily improvements that compound over time. Small, safe changes executed automatically.

**When to use:**
- Technical debt reduction (import organization, dead code removal)
- Continuous improvement (test coverage, documentation)
- Monitoring and reporting tasks

**Key frontmatter:**
```yaml
trigger:
  schedule: daily on weekdays
  workflow_dispatch:  # Allow manual runs
cache-memory: true  # Persist state across runs
```

**Pattern:** Three-phase approach
1. **Research** — Analyze codebase, identify opportunities
2. **Config** — Load/update configuration and state
3. **Execute** — Make small, safe changes

### Example: Daily Test Coverage Improver

```yaml
---
name: daily-coverage-improver
description: Incrementally adds tests to low-coverage modules
trigger:
  schedule: daily on weekdays at 10am
  workflow_dispatch:
cache-memory: true
safe-outputs:
  - create-pull-request
tools:
  bash: [read]
  edit: [read, write]
---

You are a test coverage improvement agent. Each weekday, find one low-coverage module and add tests.

## Phase 1: Research

1. Run coverage analysis: `pytest --cov=src --cov-report=json`
2. Parse coverage report to identify modules below 70% coverage
3. Review existing tests to understand patterns
4. Check cache-memory for previously improved modules

## Phase 2: Config

Load state from memory:
- `improved_modules`: List of modules already enhanced
- `current_target`: Module being worked on (if incomplete)

If no current target, select next module with lowest coverage (excluding already improved).

## Phase 3: Execute

1. Analyze the target module's code
2. Write 3-5 new test cases covering untested code paths
3. Run tests to verify they pass
4. Create PR with title: `test: improve coverage for {module_name}`
5. Update cache-memory with completed module

**Constraints:**
- Max 1 PR per day
- Each PR should improve coverage by 10-20%
- Tests must follow existing patterns
- All new tests must pass before creating PR
```

---

## 3. DataOps

**What it does:** Combines deterministic data extraction (in `steps:`) with agentic AI analysis (in body).

**When to use:**
- Reports requiring pre-computed statistics
- Dashboards fed by structured data
- Weekly/monthly summaries with AI insights

**Key pattern:**
- `steps:` — Shell commands to fetch/transform data (gh api, jq, curl)
- Files in `/tmp/gh-aw/agent/` automatically uploaded as artifacts
- AI body reads prepared data and generates insights

### Example: Weekly PR Summary

```yaml
---
name: weekly-pr-summary
description: Weekly PR activity report with AI insights
trigger:
  schedule: weekly on monday at 9am
  workflow_dispatch:
safe-outputs:
  - create-issue
steps:
  - name: Fetch PR data
    run: |
      # Get PRs merged in last 7 days
      gh api graphql -f query='
        query($owner: String!, $repo: String!) {
          repository(owner: $owner, name: $repo) {
            pullRequests(last: 100, states: MERGED) {
              nodes {
                number
                title
                author { login }
                mergedAt
                additions
                deletions
                changedFiles
                labels(first: 10) { nodes { name } }
              }
            }
          }
        }' -f owner="${GITHUB_REPOSITORY_OWNER}" -f repo="${GITHUB_REPOSITORY#*/}" \
        | jq '.data.repository.pullRequests.nodes[] | select(.mergedAt > (now - 7*86400 | strftime("%Y-%m-%dT%H:%M:%SZ")))' \
        > /tmp/gh-aw/agent/prs.json

      # Compute statistics
      jq -s '{
        total: length,
        total_additions: map(.additions) | add,
        total_deletions: map(.deletions) | add,
        total_files: map(.changedFiles) | add,
        authors: map(.author.login) | unique,
        by_label: group_by(.labels[].name) | map({label: .[0].labels[0].name, count: length})
      }' /tmp/gh-aw/agent/prs.json > /tmp/gh-aw/agent/stats.json
---

You are a weekly PR summary analyst. Data has been pre-computed in `/tmp/gh-aw/agent/`.

## Task

Read `prs.json` and `stats.json`, then:

1. Generate a summary report including:
   - Total PRs merged
   - Top contributors
   - Lines changed (additions/deletions)
   - Distribution by label/category
2. Identify trends:
   - Are PRs getting larger?
   - Which areas saw most activity?
   - Any unusual patterns?
3. Provide 2-3 actionable insights

Create an issue titled "Weekly PR Summary — [Week of YYYY-MM-DD]" with your analysis.

Use markdown tables and charts where helpful.
```

---

## 4. DispatchOps

**What it does:** Manual workflow triggers with custom inputs via `workflow_dispatch`.

**When to use:**
- On-demand research or investigation
- One-off tasks with user-specified parameters
- Interactive tooling requiring flexible inputs

**Key frontmatter:**
```yaml
trigger:
  workflow_dispatch:
    inputs:
      topic:
        description: Research topic
        required: true
        type: string
      depth:
        description: Analysis depth
        required: false
        type: choice
        options: [shallow, medium, deep]
        default: medium
```

**Running:**
- CLI: `gh aw run my-workflow --raw-field topic="AI safety" --raw-field depth="deep"`
- GitHub UI: Actions tab → workflow → "Run workflow"

### Example: On-Demand Research Assistant

```yaml
---
name: research-assistant
description: On-demand research with custom topic and depth
trigger:
  workflow_dispatch:
    inputs:
      topic:
        description: Research topic or question
        required: true
        type: string
      depth:
        description: Analysis depth
        required: false
        type: choice
        options: [shallow, medium, deep]
        default: medium
      output_format:
        description: Output format
        required: false
        type: choice
        options: [issue, discussion, gist]
        default: issue
safe-outputs:
  - create-issue
  - create-discussion
tools:
  web-search: true
---

You are a research assistant. User requested research on: **${{ github.event.inputs.topic }}**

Analysis depth: **${{ github.event.inputs.depth }}**

## Task

Conduct research based on depth level:

**Shallow:**
- 3-5 key sources
- 1-2 paragraph summary
- 3-5 bullet points

**Medium:**
- 10-15 sources
- Multi-section analysis
- Key findings, trends, and open questions
- 5-10 references

**Deep:**
- 20+ sources
- Comprehensive analysis with subsections
- Historical context, current state, future directions
- Comparative analysis
- 15+ references with annotations

## Output

Format: **${{ github.event.inputs.output_format }}**

- If `issue`: Create issue with title "Research: [topic]"
- If `discussion`: Create discussion in "Research" category
- If `gist`: Output raw markdown (user will copy to gist)

Include:
- Executive summary (3-5 sentences)
- Main findings (organized by theme)
- References (with links)
- Suggested next steps
```

---

## 5. IssueOps

**What it does:** Automatic triage, categorization, and responses when issues are created or updated.

**When to use:**
- Auto-labeling and routing
- Bug report validation
- Template compliance checking
- Auto-responses to common questions

**Key frontmatter:**
```yaml
trigger:
  issues:
    types: [opened]
safe-outputs:
  - add-labels:
      allowed: [bug, feature, documentation, invalid]
  - add-comment
```

**Security:** Use allow-lists for labels. Never trust issue body content directly in shell commands.

### Example: Bug Report Triage

```yaml
---
name: bug-triage
description: Auto-triage and categorize new bug reports
trigger:
  issues:
    types: [opened]
safe-outputs:
  - add-labels:
      allowed:
        - bug
        - feature-request
        - documentation
        - question
        - needs-reproduction
        - needs-info
        - duplicate
        - invalid
  - add-comment
tools:
  github:
    toolsets: [default]
---

You are a bug triage assistant. A new issue was just opened: **#${{ github.event.issue.number }}**

## Task

1. **Analyze the issue:**
   - Read title and body
   - Check if it follows the bug report template
   - Determine issue type (bug, feature, question, etc.)

2. **Categorize:**
   - `bug` — Clear bug with reproduction steps
   - `feature-request` — New functionality request
   - `documentation` — Docs improvement or question
   - `question` — Usage question
   - `needs-reproduction` — Bug report without clear repro
   - `needs-info` — Missing critical information
   - `duplicate` — Likely duplicate of existing issue
   - `invalid` — Spam, template not followed, off-topic

3. **Respond:**
   - For valid bugs: Thank user, confirm receipt, apply `bug` label
   - For incomplete reports: Apply `needs-info`, ask for missing details (OS, version, logs, etc.)
   - For duplicates: Apply `duplicate`, link to original issue, close
   - For questions: Apply `question`, provide brief guidance or point to docs

4. **Route:**
   - Security issues → apply `security` and tag @security-team
   - Performance issues → apply `performance`
   - Check similar past issues for patterns

Be welcoming and helpful. If unsure, err on side of requesting more info rather than closing.
```

---

## 6. LabelOps

**What it does:** Workflows triggered when specific labels are added to issues/PRs, with label filtering.

**When to use:**
- Escalation workflows (e.g., `critical` label triggers immediate action)
- Status-driven automation (e.g., `ready-for-review` triggers checks)
- Label-based routing

**Key frontmatter:**
```yaml
trigger:
  issues:
    types: [labeled]
    names: [critical, security, bug]
```

**Pattern:** Labels serve as both triggers and state markers.

### Example: Critical Issue Handler

```yaml
---
name: critical-issue-handler
description: Immediate response to critical issues
trigger:
  issues:
    types: [labeled]
    names: [critical]
safe-outputs:
  - add-comment
  - add-labels:
      allowed:
        - incident-declared
        - needs-immediate-action
        - escalated
  - update-project:
      project: https://github.com/orgs/myorg/projects/5
tools:
  github:
    toolsets: [default, projects]
---

You are a critical issue handler. Issue **#${{ github.event.issue.number }}** was just labeled `critical`.

## Immediate Actions

1. **Assess severity:**
   - Read issue description
   - Check if this is truly critical (production down, data loss, security breach)
   - If not critical, suggest downgrading label

2. **If truly critical:**
   - Apply `incident-declared` label
   - Add comment: "@team This has been escalated as a critical incident. [Incident Commander rotation here]"
   - Update GitHub Project board:
     - Move to "Critical / In Progress" column
     - Set priority to "Urgent"
     - Add to current sprint

3. **Initial investigation:**
   - Check recent deployments (last 24h)
   - Search for related issues
   - Check monitoring/logs references in issue
   - Identify likely component/team

4. **Create incident response checklist:**
   ```markdown
   - [ ] Incident commander assigned
   - [ ] Impact assessment completed
   - [ ] Root cause identified
   - [ ] Fix implemented
   - [ ] Monitoring confirmed
   - [ ] Post-mortem scheduled
   ```

5. **Tag relevant teams:**
   - Infrastructure issues → @infra-team
   - Security issues → @security-team
   - API issues → @api-team

Response time target: < 5 minutes for acknowledgment.
```

---

## 7. Monitoring

**What it does:** Tracks workflow outputs and status in GitHub Projects for visibility and reporting.

**When to use:**
- Tracking triage decisions
- Monitoring workflow success/failure rates
- Building dashboards of AI agent activity

**Key frontmatter:**
```yaml
safe-outputs:
  - update-project:
      project: https://github.com/orgs/myorg/projects/5
  - create-project-status-update
group-reports: true  # Group runs in project updates
```

**Requires:** `GH_AW_PROJECT_GITHUB_TOKEN` environment variable with `project` scope.

### Example: Issue Triage with Tracking

```yaml
---
name: issue-triage-tracker
description: Triage issues and track decisions in Projects
trigger:
  issues:
    types: [opened]
safe-outputs:
  - add-labels:
      allowed: [triaged, needs-info, duplicate, wontfix]
  - add-comment
  - update-project:
      project: https://github.com/orgs/myorg/projects/3
  - create-project-status-update
group-reports: true
tools:
  github:
    toolsets: [default, projects]
---

You are an issue triage agent with project tracking.

## Task

1. **Triage issue #${{ github.event.issue.number }}:**
   - Categorize: bug, feature, docs, question
   - Assess completeness and validity
   - Apply appropriate label

2. **Update project board:**
   - Add issue to "Triage Board" project
   - Set status based on outcome:
     - Valid → "Ready for Review"
     - Needs info → "Blocked"
     - Duplicate/invalid → "Closed"
   - Set priority field: Low, Medium, High, Critical
   - Set "Triage Date" field to today

3. **Track decision:**
   Create project status update summarizing:
   - Issue number and title
   - Triage decision
   - Applied labels
   - Next action required

4. **Comment on issue:**
   - For valid issues: Welcome and confirm triage
   - For incomplete: Request specific information
   - For duplicates: Link to original

This workflow runs every time an issue opens. Project updates are grouped hourly for cleaner reporting.
```

---

## 8. MultiRepoOps

**What it does:** Cross-repository coordination and automation.

**When to use:**
- Monorepo-style issue tracking across multiple repos
- Syncing labels, milestones, or workflows
- Creating issues in target repo from source events

**Key configuration:**
```yaml
safe-outputs:
  - create-issue:
      target-repo: myorg/target-repo
github-token: ${{ secrets.CROSS_REPO_PAT }}
tools:
  github:
    mode: remote
```

**Security:** Requires Personal Access Token (PAT) with access to target repositories.

### Example: Cross-Repo Issue Tracker

```yaml
---
name: cross-repo-issue-tracker
description: Create tracking issues in central repo when features start
trigger:
  issues:
    types: [labeled]
    names: [feature-started]
safe-outputs:
  - create-issue:
      target-repo: myorg/central-tracking
github-token: ${{ secrets.CROSS_REPO_PAT }}
tools:
  github:
    mode: remote
---

You are a cross-repository tracking agent. Issue **#${{ github.event.issue.number }}** in **${{ github.repository }}** was labeled `feature-started`.

## Task

Create a tracking issue in the central tracking repository (`myorg/central-tracking`):

**Title:** `[Track] Feature: [original issue title]`

**Body:**
```markdown
## Source
- Repository: ${{ github.repository }}
- Issue: #${{ github.event.issue.number }}
- Link: ${{ github.event.issue.html_url }}

## Summary
[Extract and summarize the feature description from original issue]

## Status
- Stage: Development Started
- Assigned to: @[extract assignee if present]

## Related Work
[Check for related issues in other repositories]

## Checklist
- [ ] Feature implementation complete
- [ ] Tests added
- [ ] Documentation updated
- [ ] Deployed to staging
- [ ] Deployed to production

---
*Auto-generated by cross-repo-tracker*
```

**Labels:** `tracking`, `[source-repo-name]`, `in-progress`

After creating tracking issue:
1. Comment on original issue with link to tracking issue
2. Add `tracked-in-central` label to original issue
```

---

## 9. Orchestration

**What it does:** Orchestrator/worker pattern where one workflow dispatches work to specialized worker workflows.

**When to use:**
- Complex tasks requiring specialized agents
- Parallel execution of independent subtasks
- Fan-out processing patterns

**Key configuration:**
```yaml
safe-outputs:
  - dispatch-workflow:
      workflows:
        - triage-worker
        - security-analyzer
        - test-generator
```

**Pattern:** Orchestrator decides strategy, dispatches to workers with context, optionally collects results.

### Example: Issue Analysis Orchestrator

```yaml
---
name: issue-orchestrator
description: Orchestrates parallel analysis of new issues
trigger:
  issues:
    types: [opened]
safe-outputs:
  - dispatch-workflow:
      workflows:
        - issue-triage-worker
        - security-scan-worker
        - similar-issue-finder
  - add-comment
---

You are an issue orchestration agent. New issue **#${{ github.event.issue.number }}** requires analysis.

## Task

Analyze the issue and dispatch to appropriate worker workflows:

1. **Issue Triage Worker** (always run):
   - Dispatch: `issue-triage-worker`
   - Inputs:
     - `issue_number`: ${{ github.event.issue.number }}
     - `priority`: [determine: low, medium, high, critical]
   - Purpose: Categorize and label

2. **Security Scanner** (if security-related keywords detected):
   - Keywords: "security", "vulnerability", "CVE", "XSS", "SQL injection", "auth"
   - Dispatch: `security-scan-worker`
   - Inputs:
     - `issue_number`: ${{ github.event.issue.number }}
     - `scan_type`: [determine: code, dependency, config]
   - Purpose: Deep security analysis

3. **Similar Issue Finder** (always run):
   - Dispatch: `similar-issue-finder`
   - Inputs:
     - `issue_number`: ${{ github.event.issue.number }}
     - `search_closed`: true
   - Purpose: Find duplicates and related discussions

## Orchestration

Assign tracker ID: `ORCH-${{ github.run_id }}`

After dispatching all workers:
- Comment on issue: "Analysis in progress. Tracker: ORCH-${{ github.run_id }}"
- Workers will comment with their findings when complete
- Each worker has 5-minute timeout

**Note:** Workers run independently. This orchestrator does not wait for results.
```

---

## 10. ProjectOps

**What it does:** AI-powered management of GitHub Projects boards with full read/write capabilities.

**When to use:**
- Smart issue routing to project boards
- Automated sprint planning
- Project status updates based on issue/PR activity

**Key configuration:**
```yaml
tools:
  github:
    toolsets: [default, projects]
safe-outputs:
  - update-project:
      project: https://github.com/orgs/myorg/projects/7
```

**Requires:** `GH_AW_PROJECT_GITHUB_TOKEN` with `project` scope.

### Example: Smart Issue Router to Projects

```yaml
---
name: smart-project-router
description: AI-powered routing of issues to appropriate project boards
trigger:
  issues:
    types: [opened, labeled]
safe-outputs:
  - update-project:
      project: https://github.com/orgs/myorg/projects/7
  - add-comment
tools:
  github:
    toolsets: [default, projects]
github-token: ${{ secrets.GH_AW_PROJECT_GITHUB_TOKEN }}
---

You are a smart project routing agent. Route issue **#${{ github.event.issue.number }}** to the appropriate project board and column.

## Project Structure

**Project:** Engineering Roadmap (https://github.com/orgs/myorg/projects/7)

**Columns:**
- Backlog — Unprioritized items
- Next Quarter — Planned for upcoming quarter
- Current Sprint — Active work
- In Progress — Currently being worked on
- In Review — PRs open, awaiting review
- Done — Completed

**Fields:**
- Priority: None, Low, Medium, High, Critical
- Team: Frontend, Backend, Infrastructure, Security, Mobile
- Size: XS, S, M, L, XL
- Sprint: [current sprint number]

## Routing Logic

1. **Determine team** (based on labels and content):
   - `frontend`, `ui`, `react` → Frontend
   - `api`, `database`, `backend` → Backend
   - `infra`, `deployment`, `docker` → Infrastructure
   - `security`, `auth`, `vulnerability` → Security
   - `ios`, `android`, `mobile` → Mobile

2. **Determine priority:**
   - Has `critical` label → Critical
   - Has `bug` + `production` → High
   - Has `feature` → Medium
   - Default → Low

3. **Determine size** (estimate based on description):
   - Simple fix, typo, config change → XS
   - Small feature, isolated bug → S
   - Feature with tests, multi-file change → M
   - Cross-cutting feature, refactor → L
   - Major feature, architectural change → XL

4. **Determine column:**
   - `critical` or `bug` + `high` priority → Current Sprint
   - Recently labeled `ready` → Next Quarter
   - Default → Backlog

5. **Add to project:**
   - Set Status field to determined column
   - Set Priority, Team, Size fields
   - If Current Sprint → assign to current sprint number

6. **Comment on issue:**
   ```markdown
   Routed to **Engineering Roadmap** project:
   - Team: [team]
   - Priority: [priority]
   - Size: [size]
   - Status: [column]
   ```

Make routing decisions transparent. If uncertain, default to Backlog and tag appropriate team.
```

---

## 11. SideRepoOps

**What it does:** Run workflows from a separate "side" repository that targets the main codebase, isolating AI noise from the primary repo.

**When to use:**
- Experimenting with workflows without polluting main repo history
- Organizations requiring clean main repo activity logs
- Development/testing of workflow automation

**Key configuration:**
```yaml
safe-outputs:
  - create-issue:
      target-repo: myorg/main-repo
  - create-pull-request:
      target-repo: myorg/main-repo
github-token: ${{ secrets.CROSS_REPO_PAT }}
tools:
  github:
    mode: remote
```

**Pattern:** Side repo contains workflows, main repo receives outputs (issues, PRs, comments).

### Example: Side Repo Automation

```yaml
---
name: side-repo-daily-improvements
description: Daily improvements dispatched from side repo
trigger:
  workflow_dispatch:
    inputs:
      target_area:
        description: Area to improve
        type: choice
        options: [tests, docs, types, performance]
        required: true
safe-outputs:
  - create-pull-request:
      target-repo: myorg/main-repo
github-token: ${{ secrets.CROSS_REPO_PAT }}
tools:
  github:
    mode: remote
  bash: [read]
  edit: [read, write]
---

You are a daily improvement agent running from the side repository (`myorg/automation-side-repo`).

Target: **myorg/main-repo**
Area: **${{ github.event.inputs.target_area }}**

## Task

1. **Clone target repository:**
   ```bash
   git clone https://github.com/myorg/main-repo.git /tmp/main-repo
   cd /tmp/main-repo
   ```

2. **Analyze and improve based on target area:**

   **Tests:**
   - Find modules with coverage < 70%
   - Add 5-10 new test cases
   - Ensure all tests pass

   **Docs:**
   - Find functions missing docstrings
   - Add comprehensive docstrings
   - Update README if needed

   **Types:**
   - Find functions with `Any` types
   - Add specific type hints
   - Verify with mypy

   **Performance:**
   - Run profiler on main paths
   - Identify and fix bottlenecks
   - Add benchmarks

3. **Create PR in main repo:**
   - Branch: `auto/improve-${{ github.event.inputs.target_area }}-${{ github.run_id }}`
   - Title: `chore: improve ${{ github.event.inputs.target_area }}`
   - Body:
     ```markdown
     ## Changes
     [Detailed list of improvements]

     ## Verification
     [How changes were verified]

     ## Impact
     [Expected impact]

     ---
     Auto-generated from automation-side-repo
     Run ID: ${{ github.run_id }}
     ```

All PR activity occurs in main repo. Workflow history stays in side repo.
```

---

## 12. SpecOps

**What it does:** W3C-style specification document maintenance with RFC 2119 keywords.

**When to use:**
- Maintaining technical specifications
- API documentation that requires precision
- Standards documents with normative requirements

**Key configuration:**
```yaml
tools:
  edit: [read, write]
  bash: [read]
safe-outputs:
  - create-pull-request
```

**Keywords:** MUST, SHALL, SHOULD, MAY, MUST NOT (RFC 2119)

### Example: Spec Update Workflow

```yaml
---
name: spec-updater
description: Update technical specification based on RFCs
trigger:
  issues:
    types: [labeled]
    names: [spec-change-approved]
safe-outputs:
  - create-pull-request
tools:
  edit: [read, write]
  bash: [read]
---

You are a specification maintenance agent. Issue **#${{ github.event.issue.number }}** contains an approved spec change.

## Task

1. **Parse the RFC** (issue body):
   - Extract proposed changes
   - Identify affected sections
   - Note normative vs. informative changes

2. **Update specification** (`docs/spec.md`):
   - Use RFC 2119 keywords correctly:
     - MUST / SHALL — absolute requirement
     - SHOULD — recommended, exceptions possible
     - MAY — truly optional
     - MUST NOT — absolute prohibition
   - Maintain spec section numbering
   - Update table of contents if needed

3. **Update changelog** (`docs/CHANGELOG.md`):
   ```markdown
   ### [Version X.Y.Z] - YYYY-MM-DD
   #### Changed
   - [Section N.M] Updated [description] (#issue-number)
   ```

4. **Create PR:**
   - Title: `spec: [brief description] (#${{ github.event.issue.number }})`
   - Reference RFC issue in body
   - Tag @spec-reviewers

Ensure all changes are backward compatible unless explicitly marked as breaking.
```

---

## 13. TaskOps

**What it does:** Three-phase scaffolded improvement process: Research → Plan → Assign.

**When to use:**
- Large-scale codebase improvements
- Systematic technical debt reduction
- Projects requiring human review between phases

**Key configuration:**
```yaml
cache-memory: true  # Track phase state
trigger:
  schedule: weekly on monday at 9am
  slash_command: { name: plan }  # Manual phase transition
```

**Phases:**
1. **Research** — AI agent analyzes, creates discussion with findings
2. **Plan** — Developer reviews, invokes `/plan` to create actionable issues
3. **Assign** — Issues assigned to Copilot or human developers

### Example: Static Analysis Report (Research Phase)

```yaml
---
name: taskops-static-analysis
description: Weekly static analysis with phased improvements
trigger:
  schedule: weekly on monday at 9am
  workflow_dispatch:
cache-memory: true
safe-outputs:
  - create-discussion
tools:
  bash: [read]
---

You are a TaskOps research agent (Phase 1/3). Conduct static analysis and create research discussion.

## Phase 1: Research

1. **Run analysis tools:**
   ```bash
   # Type coverage
   mypy --show-error-codes --strict src/ 2>&1 | tee /tmp/mypy.txt

   # Code quality
   pylint src/ --output-format=json > /tmp/pylint.json

   # Security
   bandit -r src/ -f json -o /tmp/bandit.json

   # Complexity
   radon cc src/ -a -j > /tmp/radon.json
   ```

2. **Analyze results:**
   - Count issues by severity
   - Identify patterns (common anti-patterns, repeated issues)
   - Group by area (module, type of issue)
   - Prioritize by impact

3. **Create research discussion:**
   - Category: "Engineering"
   - Title: "Static Analysis Report — [Week of YYYY-MM-DD]"
   - Body:
     ```markdown
     ## Executive Summary
     - Total issues: [count]
     - High priority: [count]
     - Medium priority: [count]
     - Low priority: [count]

     ## Findings by Category

     ### Type Safety (mypy)
     [Summary of type issues]
     Top 3 modules with issues: ...

     ### Code Quality (pylint)
     [Summary of quality issues]
     Most common: ...

     ### Security (bandit)
     [Summary of security findings]
     Critical items: ...

     ### Complexity (radon)
     [Summary of complex functions]
     Top 5 by cyclomatic complexity: ...

     ## Recommended Actions

     1. [High-priority action 1]
     2. [High-priority action 2]
     3. [Medium-priority action 3]

     ## Next Steps

     Review this analysis. To create actionable issues, comment `/plan` and specify which findings to address.
     ```

4. **Update cache-memory:**
   ```json
   {
     "phase": "research_complete",
     "discussion_id": "[ID]",
     "report_date": "[YYYY-MM-DD]",
     "total_issues": [count]
   }
   ```

**Phase 2 (Developer-triggered):** User reviews discussion, comments `/plan focus=type-safety count=5` to create issues.

**Phase 3 (Developer-triggered):** User assigns created issues to Copilot or team members.
```

---

## 14. TrialOps

**What it does:** Test workflows in isolated trial repositories before deploying to production.

**When to use:**
- Developing new workflows
- Testing workflow changes
- Verifying consistency across runs
- Previewing workflow behavior

**CLI Commands:**
```bash
# Basic trial (creates temporary trial repo)
gh aw trial ./my-workflow.md

# Specify existing repo
gh aw trial ./workflow.md --repo myorg/test-repo

# Logical repo (simulated, no actual repo created)
gh aw trial ./workflow.md --logical-repo

# Clone repo for testing
gh aw trial ./workflow.md --clone-repo myorg/source-repo

# Test consistency with multiple runs
gh aw trial ./workflow.md --repeat 3

# Dry-run (preview without execution)
gh aw trial ./workflow.md --dry-run
```

**Modes:**

| Mode | Description | Use Case |
|------|-------------|----------|
| Default | Creates temp trial repo | Quick testing without affecting real repos |
| `--repo` | Uses existing repo | Testing in controlled environment |
| `--logical-repo` | Simulated (no real repo) | Validating workflow logic without side effects |
| `--clone-repo` | Clones source repo | Testing against real data |
| `--repeat N` | Runs N times | Checking consistency and flakiness |
| `--dry-run` | Preview only | Understanding workflow before running |

**No workflow file needed** — this is a CLI testing pattern, not a workflow trigger.

### Example Session

```bash
# Create new workflow
cat > issue-labeler.md <<'EOF'
---
name: issue-labeler
description: Auto-label issues
trigger:
  issues:
    types: [opened]
safe-outputs:
  - add-labels:
      allowed: [bug, feature, docs]
---
You are an issue labeler. Label issue based on content.
EOF

# Test in trial repo
gh aw trial ./issue-labeler.md

# Output:
# ✓ Created trial repo: gh-aw-trial-abc123
# ✓ Installed workflow
# ✓ Created test issue #1
# ✓ Workflow run completed
# Labels applied: [bug]

# Test consistency (run 3 times)
gh aw trial ./issue-labeler.md --repeat 3

# Output shows if labels vary across runs

# Preview without execution
gh aw trial ./issue-labeler.md --dry-run

# Output shows what would happen

# Clean up
gh repo delete gh-aw-trial-abc123 --yes
```

---

## Quick Pattern Selection Guide

| Need | Pattern | Trigger | When to Use |
|------|---------|---------|-------------|
| On-demand user interaction | **ChatOps** | `slash_command: /command` | Interactive operations requiring approval or input |
| Scheduled daily improvements | **DailyOps** | `schedule: daily on weekdays` | Incremental technical debt reduction |
| Data fetch + AI analysis | **DataOps** | `steps:` + body | Reports with pre-computed statistics |
| Manual one-off tasks | **DispatchOps** | `workflow_dispatch` | On-demand research, custom investigations |
| Auto-respond to new issues | **IssueOps** | `issues: [opened]` | Triage, categorization, validation |
| React to label changes | **LabelOps** | `issues: [labeled]` | Escalation, status-driven workflows |
| Track work in Projects | **Monitoring** / **ProjectOps** | `update-project` | Visibility, reporting, dashboards |
| Cross-repo coordination | **MultiRepoOps** | `target-repo:` | Monorepo-style tracking, syncing |
| Fan-out to workers | **Orchestration** | `dispatch-workflow` | Complex tasks needing specialized agents |
| Isolated experimentation | **SideRepoOps** | `mode: remote` | Clean main repo, workflow development |
| Multi-phase improvements | **TaskOps** | 3-phase (research → plan → assign) | Large-scale systematic improvements |
| Test before production | **TrialOps** | `gh aw trial` | Workflow development, validation |
| W3C-style spec maintenance | **SpecOps** | `edit:` tools | Technical specifications, standards docs |

---

## Combining Patterns

Patterns can be combined for sophisticated workflows:

- **ChatOps + MultiRepoOps:** `/deploy` command that creates issues in multiple repos
- **DailyOps + Monitoring:** Daily improvements tracked in project board
- **IssueOps + Orchestration:** Triage orchestrator fans out to specialized analyzers
- **LabelOps + ProjectOps:** Label change triggers project board updates
- **DataOps + DispatchOps:** Scheduled reports + on-demand deep dives
- **TaskOps + SideRepoOps:** Multi-phase improvements from side repo to keep main clean

---

## Security Best Practices Across Patterns

1. **Input validation:**
   - Always use allow-lists for labels
   - Treat issue/comment content as untrusted
   - Validate workflow_dispatch inputs

2. **Access control:**
   - Use `roles:` field in ChatOps triggers
   - Restrict sensitive workflows to org members
   - Use minimal-scope PATs for cross-repo operations

3. **Safe outputs:**
   - Explicitly list allowed safe-outputs
   - Use `allowed:` lists for labels
   - Verify target-repo access before cross-repo operations

4. **Secrets:**
   - Never log secrets or tokens
   - Use environment variables for sensitive data
   - Rotate PATs regularly

5. **Audit:**
   - Enable `group-reports:` for tracking
   - Log all agent decisions
   - Review workflow runs regularly

---

## Additional Resources

- **Official Docs:** [GitHub Agentic Workflows Documentation](https://docs.github.com/agentic-workflows)
- **Trigger Reference:** See `gh-aw/references/triggers-comprehensive.md`
- **Safe Outputs Reference:** See `gh-aw/references/safe-outputs.md`
- **Tools Reference:** See `gh-aw/references/tools.md`

---

*Last updated: 2026-02-19*
