# GitHub Agentic Workflows — Triggers and Scheduling Reference

## Table of Contents

1. [Trigger Types](#trigger-types)
   - [Standard GitHub Events](#standard-github-events)
   - [Slash Command Triggers](#slash-command-triggers)
   - [Context Text](#context-text)
2. [Fuzzy Scheduling (Recommended)](#fuzzy-scheduling-recommended)
   - [Daily Schedules](#daily-schedules)
   - [Hourly Schedules](#hourly-schedules)
   - [Weekly Schedules](#weekly-schedules)
   - [Interval Schedules](#interval-schedules)
   - [UTC Offset Support](#utc-offset-support)
   - [Time Formats](#time-formats)
   - [Multiple Schedules](#multiple-schedules)
3. [Fixed Cron Schedules](#fixed-cron-schedules)
4. [Shorthand Triggers](#shorthand-triggers)
5. [Scattering Algorithm](#scattering-algorithm)
6. [Trigger Modifiers](#trigger-modifiers)
7. [Combining Triggers](#combining-triggers)

---

## Trigger Types

### Standard GitHub Events

| Event | Supported Types | Special Features |
|-------|----------------|------------------|
| `issues` | opened, edited, labeled, unlabeled, deleted, transferred, pinned, unpinned, closed, reopened, assigned, unassigned, milestoned, demilestoned | `names:` label filtering, `lock-for-agent:` |
| `pull_request` | opened, synchronize, reopened, closed, ready_for_review, converted_to_draft, labeled, unlabeled | `forks:` filtering (true/false) |
| `issue_comment` | created, edited, deleted | Includes PR comments |
| `discussion` | created, edited, deleted, closed, reopened, labeled, unlabeled, category_changed | |
| `discussion_comment` | created, edited, deleted | |
| `pull_request_review` | submitted, edited, dismissed | |
| `push` | | Branch filtering available |
| `workflow_run` | completed, requested | Chain workflows |
| `release` | published, created, edited, deleted, prereleased, released | |
| `workflow_dispatch` | | Manual trigger with inputs |

**Example with label filtering:**
```yaml
on:
  issues:
    types: [labeled, unlabeled]
    names: [bug, enhancement]
```

**Example with fork filtering:**
```yaml
on:
  pull_request:
    types: [opened, synchronize]
    forks: false  # Ignore PRs from forks
```

**Example with lock-for-agent:**
```yaml
on:
  issues:
    types: [opened]
    lock-for-agent: true  # Lock issue for this agent's exclusive handling
```

**workflow_dispatch inputs:**
```yaml
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deployment environment'
        required: true
        type: environment
      debug:
        description: 'Enable debug logging'
        required: false
        type: boolean
        default: false
      version:
        description: 'Version to deploy'
        required: true
        type: string
      strategy:
        description: 'Deployment strategy'
        required: true
        type: choice
        options:
          - rolling
          - blue-green
          - canary
```

### Slash Command Triggers

Slash commands allow users to trigger workflows by posting comments starting with a command word.

**Basic syntax:**
```yaml
on:
  slash_command: "my-bot"
```

**Shorthand:**
```yaml
on: /my-bot
```

**Object syntax with options:**
```yaml
on:
  slash_command:
    name: "my-bot"
    events: [issues, issue_comment]
    reaction: rocket
```

**Multiple commands:**
```yaml
on:
  slash_command:
    name: ["cmd.add", "cmd.remove"]
    events: "*"
```

**Event filtering:**

| Event Value | Description |
|------------|-------------|
| `issues` | Comments on issues only |
| `issue_comment` | All issue/PR comments |
| `pull_request_comment` | PR comments only |
| `pull_request_review_comment` | PR review comments |
| `discussion` | Discussion posts |
| `discussion_comment` | Discussion comments |
| `"*"` | All supported events |

**Requirements and constraints:**
- Command must be the **first word** in the comment
- Cannot combine with `issues`, `issue_comment`, or `pull_request` event types (except label-only triggers)
- Command is case-sensitive by default

**Automatic features:**
- 👀 Eyes reaction on command detection (default)
- Automatic edit to add run link after activation
- Custom reaction via `reaction:` field

**Available output:**
```yaml
steps:
  - name: Check command
    run: |
      echo "Command: ${{ needs.activation.outputs.slash_command }}"
```

### Context Text

**Output:** `needs.activation.outputs.text`

Provides sanitized, agent-safe text from issue/PR titles, bodies, or comments.

**Use this instead of:**
- ❌ `github.event.issue.title`
- ❌ `github.event.issue.body`
- ❌ `github.event.comment.body`

**Sanitization applied:**

| Protection | Details |
|-----------|---------|
| @mention neutralization | Converts `@username` → `@ username` |
| Bot trigger protection | Strips slash commands to prevent recursive triggers |
| XML/HTML conversion | Escapes `<`, `>`, `&` to prevent injection |
| URI filtering | Neutralizes dangerous URIs |
| Content limits | Max 0.5MB, 65k lines |
| ANSI stripping | Removes terminal escape codes |

**Example usage:**
```yaml
steps:
  - name: Process issue content
    run: |
      echo "Safe text: ${{ needs.activation.outputs.text }}"
```

---

## Fuzzy Scheduling (Recommended)

Fuzzy schedules use natural language syntax and automatically scatter execution times to avoid thundering herd problems.

### Daily Schedules

```yaml
# Scattered randomly across 24 hours
schedule: daily

# Monday-Friday only
schedule: daily on weekdays

# Scattered within ±1 hour window around 14:00 UTC
schedule: daily around 14:00

# Monday-Friday, 8:00-10:00 UTC window
schedule: daily around 9am on weekdays

# Business hours (9am-5pm UTC)
schedule: daily between 9:00 and 17:00

# Business hours on weekdays
schedule: daily between 9:00 and 17:00 on weekdays

# Night window crossing midnight
schedule: daily between 22:00 and 02:00
```

### Hourly Schedules

```yaml
# Scattered minute each hour
schedule: hourly

# Weekdays only
schedule: hourly on weekdays

# Every N hours (valid: 1h, 2h, 3h, 4h, 6h, 8h, 12h)
schedule: every 2h
schedule: every 6h on weekdays
```

### Weekly Schedules

```yaml
# Scattered day/time
schedule: weekly

# Specific day
schedule: weekly on monday
schedule: weekly on friday around 5pm

# Every 14 days
schedule: bi-weekly

# Every 21 days
schedule: tri-weekly
```

### Interval Schedules

```yaml
# Fixed minute schedules (minimum 5 minutes)
schedule: every 5 minutes
schedule: every 15 minutes
schedule: every 30 minutes

# Fixed day schedules (midnight UTC)
schedule: every 2 days
schedule: every 7 days

# Fixed week schedules (Sunday midnight UTC)
schedule: every 1w
schedule: every 2w

# Fixed month schedules (1st of month, midnight UTC)
schedule: every 1mo
schedule: every 2mo
```

### UTC Offset Support

All fuzzy schedules support UTC offset specification.

**Supported range:** UTC-12:00 to UTC+14:00

```yaml
# Japan Standard Time (UTC+9)
schedule: daily around 14:00 utc+9

# Eastern Standard Time (UTC-5)
schedule: daily around 9am utc-5
schedule: daily between 9am utc-5 and 5pm utc-5

# India Standard Time (UTC+5:30)
schedule: weekly on monday around 08:00 utc+05:30

# Australia Eastern Time (UTC+10)
schedule: hourly utc+10
```

### Time Formats

| Format | Example | Result |
|--------|---------|--------|
| 24-hour | `14:00`, `09:30`, `23:59` | Direct time |
| 12-hour | `2pm`, `9am`, `3:30pm` | Converted to 24h |
| Keyword | `midnight` | `00:00` |
| Keyword | `noon` | `12:00` |

**Special cases:**
- `12am` → `00:00` (midnight)
- `12pm` → `12:00` (noon)

### Multiple Schedules

Run on multiple different schedules:

```yaml
schedule:
  - cron: daily
  - cron: weekly on monday
  - cron: "0 0 15 * *"  # Plus fixed cron
```

---

## Fixed Cron Schedules

Standard 5-field cron expressions for precise scheduling.

**Format:** `minute hour day month weekday`

```yaml
schedule:
  - cron: "0 2 * * *"          # Daily at 2:00 AM UTC
  - cron: "30 6 * * 1"         # Monday at 6:30 AM UTC
  - cron: "0 */2 * * *"        # Every 2 hours
  - cron: "0 0 1 * *"          # First day of month
  - cron: "0 0 * * 0"          # Every Sunday
  - cron: "*/15 * * * *"       # Every 15 minutes
  - cron: "0 9 * * 1-5"        # Weekdays at 9 AM UTC
```

**Fields:**

| Position | Field | Values |
|----------|-------|--------|
| 1 | Minute | 0-59 |
| 2 | Hour | 0-23 |
| 3 | Day of month | 1-31 |
| 4 | Month | 1-12 |
| 5 | Day of week | 0-6 (Sunday=0) |

**Special characters:**
- `*` — Any value
- `*/N` — Every N units
- `N-M` — Range from N to M
- `N,M` — Specific values N and M

---

## Shorthand Triggers

Convenient one-liners that expand to multiple trigger types.

```yaml
# Daily schedule + manual trigger
on: daily

# Slash command + manual trigger
on: /my-bot

# Issue labeled trigger
on: issue labeled bug
on: issue labeled [bug, enhancement]
```

**Expansion:**

| Shorthand | Expands To |
|-----------|-----------|
| `on: daily` | `schedule: daily` + `workflow_dispatch` |
| `on: /cmd` | `slash_command: cmd` + `workflow_dispatch` |
| `on: issue labeled X` | `issues: { types: [labeled], names: [X] }` |

---

## Scattering Algorithm

Fuzzy schedules use deterministic scattering to distribute load.

**Algorithm:** FNV-1a 32-bit hash
**Input:** `repository_slug + "/" + workflow_file_path`
**Result:** Deterministic — same workflow always gets same scattered time

**Benefits:**
- Prevents thundering herd on GitHub Actions
- Distributes load across time windows
- Predictable — same workflow, same time
- No coordination needed between repositories

**Example:**
- Repo: `owner/repo`
- Workflow: `.github/workflows/daily-check.yml`
- Hash input: `owner/repo/.github/workflows/daily-check.yml`
- Result: Consistently scattered to (e.g.) `03:47 UTC` for `daily` schedule

---

## Trigger Modifiers

Modifiers apply to ALL trigger types (events, schedules, slash commands).

### stop-after

Automatically disable workflow after specified time or duration.

```yaml
on:
  issues:
    types: [opened]
    stop-after: "+7d"  # Disable after 7 days from now

  schedule:
    - cron: hourly
      stop-after: "2025-06-01"  # Disable on June 1, 2025
```

**Duration format:** `+<value><unit>`
- Units: `h` (hours), `d` (days), `mo` (months)
- Combined: `+1d12h30m`
- Min unit: hours
- Max: `12mo` / `365d` / `8760h`

**Date format:**
- ISO: `2025-06-01`
- Natural: `June 1 2025`, `1 June 2025`

### skip-if-match

Skip workflow if GitHub search query finds matches.

```yaml
on:
  schedule:
    - cron: daily
      skip-if-match: "is:issue is:open label:bot-processed"
```

**Default threshold:** 1 match (skip if ≥1 found)

**Specify threshold:**
```yaml
skip-if-match:
  query: "is:issue is:open label:bug"
  count: 5  # Skip if ≥5 matches
```

### skip-if-no-match

Skip workflow if GitHub search query finds NO matches.

```yaml
on:
  schedule:
    - cron: hourly
      skip-if-no-match: "is:issue is:open label:needs-triage"
```

**Use case:** Only run if there's work to do.

### manual-approval

Require manual approval before workflow runs.

```yaml
on:
  issues:
    types: [labeled]
    names: [deploy]
    manual-approval: production
```

**Requirements:**
- Environment name must exist in repository settings
- Protection rules configured on environment
- Approvers defined in protection rules

### reaction

Custom emoji reaction on slash command or event.

```yaml
on:
  slash_command:
    name: "deploy"
    reaction: rocket
```

**Valid reactions:**
- `+1`, `-1`
- `laugh`, `confused`, `heart`, `hooray`, `rocket`, `eyes`
- `none` (disable default eyes reaction)

### roles

Restrict trigger to users with specific repository roles.

```yaml
on:
  slash_command:
    name: "deploy"
    roles: [admin, maintainer]
```

**Valid roles:**
- `admin` — Repository admins
- `maintainer` — Repository maintainers (org repos)
- `write` — Users with write access
- `all` — Any user (use with caution)

**Default:** `[admin, maintainer, write]`

### bots

Allow specific bots to trigger workflow.

```yaml
on:
  issues:
    types: [opened]
    bots: ["dependabot[bot]", "renovate[bot]"]
```

**Use case:** Process automated bot-created issues/PRs.

**Note:** Must use exact bot username format (e.g., `dependabot[bot]`).

### skip-roles

Exempt specific roles from triggering.

```yaml
on:
  issues:
    types: [opened]
    skip-roles: [read]
```

**Use case:** Ignore issues from external contributors.

### skip-bots

Exempt specific bots from triggering.

```yaml
on:
  issue_comment:
    types: [created]
    skip-bots: ["github-actions[bot]"]
```

**Use case:** Prevent recursive triggers from your own bot.

---

## Combining Triggers

Multiple trigger types can coexist in one workflow.

**Compatible combinations:**

```yaml
on:
  slash_command: my-bot
  workflow_dispatch:
  schedule: weekly on monday
  issues:
    types: [labeled, unlabeled]  # Label-only OK with slash_command
```

**Incompatible combinations:**

❌ Cannot combine `slash_command` with:
- `issues` (except label-only types)
- `issue_comment` (except label-only)
- `pull_request` (except label-only)

**Rationale:** Prevents ambiguous activation context.

**Label-only exception:**

```yaml
on:
  slash_command: my-bot
  issues:
    types: [labeled, unlabeled]  # OK — no content processing conflict
    names: [needs-bot]
```

**Full example:**

```yaml
name: Multi-trigger workflow

on:
  # Manual trigger
  workflow_dispatch:
    inputs:
      severity:
        type: choice
        options: [low, medium, high]

  # Scheduled trigger
  schedule:
    - cron: daily around 9am on weekdays
      skip-if-no-match: "is:issue is:open label:needs-review"

  # Event trigger
  issues:
    types: [opened, labeled]
    names: [bug, urgent]
    roles: [admin, maintainer, write]

  # Slash command
  slash_command:
    name: "triage"
    events: [issues, issue_comment]
    reaction: eyes

jobs:
  activation:
    # Provided by gh-aw

  process:
    needs: activation
    runs-on: ubuntu-latest
    steps:
      - name: Get context
        run: |
          echo "Text: ${{ needs.activation.outputs.text }}"
          echo "Command: ${{ needs.activation.outputs.slash_command }}"
          echo "Trigger: ${{ github.event_name }}"
```

---

**Reference version:** 2026-02-19
**gh-aw compatibility:** All documented features supported in latest release