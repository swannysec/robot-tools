---
name: gh-aw-helper
description: |
  GitHub Agentic Workflows (gh-aw) — write AI-powered automation workflows in
  natural-language markdown that compile to secure GitHub Actions. Supports
  Copilot, Claude, and Codex engines with safe-output guardrails, MCP tool
  integration, and sandboxed execution.

  Use this skill when users need to:
  (1) Install or set up gh-aw in a repository
  (2) Create, edit, or compile agentic workflow markdown files
  (3) Configure triggers, schedules, safe outputs, tools, or MCP servers
  (4) Switch AI engines (Copilot, Claude, Codex) or configure engine options
  (5) Troubleshoot workflow failures, compilation errors, or permission issues
  (6) Understand gh-aw patterns (ChatOps, DailyOps, IssueOps, etc.)
  (7) Configure security: permissions, network rules, sandbox, threat detection
  (8) Use advanced features: memory, imports, orchestration, cross-repo ops
triggers:
  - "gh-aw"
  - "gh aw"
  - "agentic workflow"
  - "agentic workflows"
  - "github agentic"
  - "create agentic workflow"
  - "compile workflow"
  - "safe outputs"
  - "safe inputs"
  - "workflow markdown"
  - "gh aw compile"
  - "gh aw run"
  - "gh aw init"
  - "slash command trigger"
  - "fuzzy schedule"
  - "workflow frontmatter"
  - "copilot engine"
  - "workflow lock file"
---

# GitHub Agentic Workflows (gh-aw)

Write agentic workflows in natural-language markdown, compile them to secure
GitHub Actions YAML, and run them with AI engines (Copilot, Claude, Codex).

> **Docs**: https://github.github.com/gh-aw/
> **Repo**: https://github.com/github/gh-aw

---

## Help — Topic Navigator

When the user asks for help with gh-aw or a specific topic, use this table to
find the right reference file. Read the reference **only when needed**.

| Topic | Reference File | Covers |
|-------|---------------|--------|
| Frontmatter fields | `references/frontmatter-reference.md` | All YAML fields, types, defaults, examples |
| Triggers & scheduling | `references/triggers-and-scheduling.md` | Event triggers, slash commands, fuzzy/cron schedules, modifiers |
| Safe inputs & outputs | `references/safe-io-reference.md` | Custom MCP tools, 20+ output types, cross-repo, footers |
| Security & network | `references/security-and-network.md` | Permissions, sandbox, auth, lockdown, network, threat detection, rate limits |
| Tools & MCP servers | `references/tools-and-mcp.md` | GitHub toolsets, bash, playwright, serena, custom MCP, MCP gateway |
| Patterns & examples | `references/patterns-and-examples.md` | 14 operational patterns (ChatOps, DailyOps, IssueOps, etc.) with full examples |
| Troubleshooting | `references/troubleshooting.md` | Error reference, common issues, FAQ, debugging |

When responding to a help request, list these topics and ask which area the
user needs guidance on. Then load only the relevant reference file.

---

## Quick Start (10 minutes)

### 1. Install the CLI Extension

```bash
gh extension install github/gh-aw
# Or standalone (works in Codespaces / restricted networks):
curl -sL https://raw.githubusercontent.com/github/gh-aw/main/install-gh-aw.sh | bash
```

Verify: `gh aw version`

### 2. Add a Sample Workflow

```bash
gh aw add-wizard githubnext/agentics/daily-repo-status
```

The wizard checks prerequisites, selects an engine, sets up the required
secret, adds the workflow + lock file, and optionally triggers a run.

### 3. Customize

1. Edit `.github/workflows/daily-repo-status.md` (markdown body — no recompile needed)
2. If you changed **frontmatter**, recompile: `gh aw compile`
3. Commit both `.md` and `.lock.yml`, push

---

## Core Workflow

### Creating a Workflow

Three methods, in order of ease:

**Method A — Wizard** (recommended for existing workflows):
```bash
gh aw add-wizard githubnext/agentics/<workflow-name>
```

**Method B — AI-assisted** (recommended for new workflows):
Prompt a coding agent with:
```text
Create a workflow for GitHub Agentic Workflows using
https://raw.githubusercontent.com/github/gh-aw/main/create.md

The purpose of the workflow is: <describe your goal>
```

**Method C — Manual**:
1. Create `.github/workflows/<name>.md` with frontmatter + markdown body
2. Compile: `gh aw compile`
3. Commit both `.md` and `.lock.yml`

### Workflow File Structure

```
.github/workflows/
├── my-workflow.md          # Source (frontmatter + markdown)
└── my-workflow.lock.yml    # Compiled GitHub Actions YAML (generated)
```

Minimal example:
```markdown
---
on:
  issues:
    types: [opened]
permissions:
  contents: read
safe-outputs:
  add-comment:
tools:
  github:
    toolsets: [issues]
---

# Issue Responder

Read issue #${{ github.event.issue.number }}.
Add a helpful comment with relevant resources.
```

### What Requires Recompilation

| Change to... | Recompile? |
|---------------|-----------|
| Markdown body (AI instructions, templates, logic) | No |
| Frontmatter (triggers, tools, permissions, network, safe-outputs) | **Yes** — `gh aw compile` |

### Compiling

```bash
gh aw compile                    # All workflows
gh aw compile my-workflow        # Single workflow
gh aw compile --watch            # Watch mode
gh aw compile --verbose          # Debug output
gh aw compile --strict           # Enhanced security validation
gh aw compile --purge            # Remove orphaned .lock.yml files
gh aw compile --dependabot       # Generate dependency manifests
```

### Running

```bash
gh aw run <workflow-name>        # Trigger via CLI
gh aw status                     # Check all workflow states
gh aw list                       # List all workflows
```

Also runnable from GitHub Actions UI (Actions tab > select workflow > Run).

### Debugging

```bash
gh aw logs <workflow-name>       # View recent logs
gh aw audit <run-id>             # Detailed run analysis
gh aw mcp inspect <workflow>     # Check MCP server/tool config
```

Enable Actions debug: set repo secret `ACTIONS_STEP_DEBUG = true`.

Use Copilot Chat: `/agent agentic-workflows debug <description>`

---

## Workflow Authoring Essentials

### Frontmatter (YAML between `---`)

Key fields (see `references/frontmatter-reference.md` for the complete spec):

```yaml
---
on: daily on weekdays                    # Trigger (fuzzy schedule)
engine: copilot                          # AI engine (copilot|claude|codex)
permissions:
  contents: read                         # Minimal permissions
tools:
  github:
    toolsets: [default]                  # MCP tool groups
safe-outputs:
  create-issue:                          # Pre-approved write operations
    title-prefix: "[bot] "
    max: 3
    expires: 7
network:
  allowed: [defaults, python]            # Domain allowlist
imports:
  - shared/reporting.md                  # Reusable components
---
```

### Markdown Body

Write clear, action-oriented natural language instructions:
- Structured headings for multi-step processes
- Specific criteria and examples for consistent AI decisions
- Use `${{ needs.activation.outputs.text }}` for sanitized user input
- Use `${{ github.event.issue.number }}`, `${{ github.actor }}`, etc.
- Do NOT use `${{ secrets.* }}` or `${{ env.* }}` in the markdown body

### Templating

**Conditional sections:**
```markdown
{{#if github.event.issue.number}}
Analyze issue #${{ github.event.issue.number }}.
{{/if}}
```

**Runtime imports** (load files at execution time):
```markdown
{{#runtime-import coding-standards.md}}
{{#runtime-import? optional-file.md}}
{{#runtime-import https://example.com/checklist.md}}
```
File paths restricted to `.github/` folder. No recursion.

---

## Engine Configuration

### Switching Engines

```yaml
engine: copilot    # Default — uses COPILOT_GITHUB_TOKEN
engine: claude     # Uses ANTHROPIC_API_KEY
engine: codex      # Uses OPENAI_API_KEY
```

### Extended Engine Config

```yaml
engine:
  id: copilot
  model: claude-sonnet-4          # Override model
  agent: my-custom-agent          # .github/agents/my-custom-agent.agent.md
  args: ["--add-dir", "/workspace"]
  env:
    DEBUG_MODE: "true"
  concurrency:
    group: "gh-aw-copilot-${{ github.workflow }}"
```

### Setting Up Secrets

```bash
gh aw secrets set COPILOT_GITHUB_TOKEN    # For Copilot
gh aw secrets set ANTHROPIC_API_KEY       # For Claude
gh aw secrets set OPENAI_API_KEY          # For Codex
gh aw secrets bootstrap                   # Auto-detect and prompt
```

---

## Validation & Quality

### Compile-Time Validation

Strict mode (`strict: true` or `--strict`) enforces:
- No direct write permissions (use safe-outputs instead)
- Explicit network configuration required
- No wildcard `*` in allowed domains
- Ecosystem identifiers preferred over individual domains
- GitHub Actions pinned to commit SHAs

### Validate Without Compiling

```bash
gh aw compile <workflow> --validate
```

### Apply Automated Fixes

```bash
gh aw fix --write                # Apply all codemods
gh aw fix <workflow> --write     # Fix specific workflow
```

Codemods: `sandbox-false-to-agent-false`, `network-firewall-migration`,
`safe-inputs-mode-removal`, `schedule-at-to-around-migration`, and more.

### Upgrade Workflows

```bash
gh aw upgrade                    # Update agents, apply codemods, recompile
gh aw upgrade -v                 # Verbose
gh aw upgrade --no-fix           # Skip codemods
```

---

## Repository Initialization

```bash
gh aw init                       # Interactive setup
gh aw init --no-mcp              # Skip MCP server integration
gh aw init --push                # Auto-commit and push
gh aw init --completions         # Install shell completions
```

Creates: `.gitattributes`, `.github/aw/` prompt files,
`.github/agents/agentic-workflows.agent.md`, Copilot instructions.

---

## Common Patterns (Quick Reference)

See `references/patterns-and-examples.md` for full details on all 14 patterns.

| Pattern | Trigger | Use Case |
|---------|---------|----------|
| **ChatOps** | `/command` in comments | On-demand code review, deploy, analysis |
| **DailyOps** | `daily on weekdays` | Incremental improvements, tech debt |
| **IssueOps** | `issues: [opened]` | Auto-triage, labeling, routing |
| **DataOps** | `steps:` + markdown | Deterministic data fetch + AI analysis |
| **DispatchOps** | `workflow_dispatch` | Manual research, one-off tasks |
| **LabelOps** | `issues: [labeled]` | Priority-based automation |
| **TaskOps** | 3-phase | Research → Plan → Assign to Copilot |
| **MultiRepoOps** | Cross-repo PAT | Sync features, centralize tracking |
| **Orchestration** | `dispatch-workflow` | Fan-out work to worker workflows |
| **MemoryOps** | `cache-memory` / `repo-memory` | Stateful workflows across runs |

---

## Advanced Features (Quick Reference)

### Memory

```yaml
tools:
  cache-memory: true              # 7-day retention, /tmp/gh-aw/cache-memory/
  repo-memory:                    # Unlimited retention via Git branches
    branch-name: memory/my-data
```

### Imports (Reusable Components)

```yaml
imports:
  - shared/reporting.md                          # Local
  - githubnext/agentics/shared/tools.md@v1.0.0   # Remote (pinned)
```

### Cross-Repository Operations

```yaml
safe-outputs:
  github-token: ${{ secrets.CROSS_REPO_PAT }}
  create-issue:
    target-repo: "org/other-repo"
tools:
  github:
    mode: remote
```

### Orchestrator / Worker Pattern

```yaml
safe-outputs:
  dispatch-workflow:
    workflows: [worker-a, worker-b]
    max: 10
```

### Ephemerals (Auto-Expiring Resources)

```yaml
safe-outputs:
  create-issue:
    expires: 7                     # Auto-close after 7 days
    close-older-issues: true       # Replace previous reports
on:
  schedule: daily
  stop-after: "+30d"               # Auto-disable workflow after 30 days
```

---

## CLI Quick Reference

```bash
# Setup
gh extension install github/gh-aw
gh aw init
gh aw secrets bootstrap

# Workflow management
gh aw add-wizard <source>         # Interactive add
gh aw add <source>                # Non-interactive add
gh aw compile [workflow]          # Compile to .lock.yml
gh aw run <workflow>              # Trigger run
gh aw list                        # List workflows
gh aw status                      # Check states

# Debugging
gh aw logs [workflow]             # View logs
gh aw audit <run-id>              # Detailed analysis
gh aw mcp inspect <workflow>      # Check MCP config

# Maintenance
gh aw upgrade                     # Update + recompile
gh aw fix --write                 # Apply codemods
gh aw compile --purge             # Clean orphaned locks
gh aw secrets set <name>          # Set secret
gh aw trial <workflow>            # Test in isolation
```
