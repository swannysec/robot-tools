# Workflow Toolkit

Development workflow automation, review orchestration, and productivity tools for enhanced development workflows.

## Features

### Commands

| Command | Description |
|---------|-------------|
| `/dep-check` | Check dependency health and security before adding to project |
| `/git-branch-cleanup` | Clean up merged and stale git branches |
| `/git-safe-commit` | Safe commit workflow with build/test validation |
| `/post-impl-review` | Post-implementation review for completed features |
| `/verify` | Run full verification suite (typecheck, lint, test, coverage, audit) before PR or release |

### Deprecated (Reference Only)

| Command | Description |
|---------|-------------|
| `/bootstrap-project` | ⚠️ Deprecated. Bootstrap a new project with Claude Code best practices. Retained for reference patterns only. |

### Skills

| Skill | Description |
|-------|-------------|
| `open-sourceror` | Prepare Claude Code skills, agents, or collections for open-source sharing. Supports standalone repo creation or marketplace integration into existing plugin repos (e.g., robot-tools). |
| `session-retrospective` | Iterative reflection skill for extracting actionable learnings from Claude Code sessions. Produces agent-ready context documents for future implementation. |

### Agents

| Agent | Description |
|-------|-------------|
| `code-reviewer` | Staff-level Rust code review specialist. Focuses on security, reliability, accessibility, and planning implementations. |
| `idempotency-tester` | Verifies operations are idempotent by running them twice and comparing results. Use for sync operations, data migrations, or API calls. |
| `ops-docs-generator` | Generates operational documentation (troubleshooting, performance, deployment) by analyzing actual codebase patterns. |
| `review-orchestrator` | Coordinates multi-phase code reviews by delegating to specialized agents and managing branch/PR workflows. |

## Installation

### Via Marketplace

```bash
/plugin marketplace add https://github.com/swannysec/robot-tools
/plugin install workflow-toolkit@robot-tools
```

### Manual Installation

```bash
git clone https://github.com/swannysec/robot-tools.git
cd robot-tools
cc --plugin-dir ./workflow-toolkit
```

## Usage

### Commands

Commands are invoked with the `/` prefix:

```
/dep-check lodash                   # Check if lodash is safe to add
/git-branch-cleanup                 # Clean up merged branches
/git-safe-commit "feat: add login"  # Safe commit with validation
/post-impl-review                   # Review completed implementation
/verify                             # Run full verification suite
```

### Skills

Skills activate automatically via trigger phrases:

**open-sourceror**:
- `"prepare for open source"`, `"open source this skill"`
- `"upload skill to github"`, `"share this agent"`
- `"add to marketplace"`, `"add to robot-tools"`
- `"create repo for skill"`, `"package for sharing"`

**session-retrospective**:
- `"session retrospective"`, `"retro"`
- `"what did we learn"`, `"lessons learned"`

### Agents

Agents are invoked by Claude Code when their specialized capabilities match the task:

- `code-reviewer`: Activated for code review tasks, especially Rust projects
- `idempotency-tester`: Use when testing sync operations or migrations
- `ops-docs-generator`: Use when creating operational documentation
- `review-orchestrator`: Use for comprehensive multi-phase reviews

### Example Commands

```
"Prepare this skill for open source sharing"
"Add this skill to robot-tools research-toolkit"
"Run a session retrospective on what we learned"
"Review this Rust code for security issues"
"Test if this sync operation is idempotent"
"Generate ops documentation for the deployment process"
"Orchestrate a comprehensive review of this PR"
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- [GitHub CLI](https://cli.github.com/) (for open-sourceror skill)

## License

[MIT License with Commercial Restriction](../LICENSE)
