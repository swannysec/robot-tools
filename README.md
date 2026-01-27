# Robot Tools

A comprehensive collection of Claude Code plugins for research, security, code analysis, and workflow automation.

## Plugins

### Research Toolkit
AI/ML research and verification tools for software development.

**Skills:**
- `ai-dev-research` - Expert technical research on AI topics
- `ai-twitter-radar` - Discover AI trends and news from Twitter/X using Bird CLI
- `research-verification` - Pre-flight verification checklist for research tasks

[View Documentation](./research-toolkit/README.md)

### Security Toolkit
Security investigation and analysis tools.

**Skills:**
- `secret-scanning-investigator` - Investigate GitHub secret scanning alerts with evidence-based analysis

[View Documentation](./security-toolkit/README.md)

### Code Analysis Toolkit
Codebase flow analysis, dependency visualization, and health scoring.

**Skills:**
- `impact-flow` - Dependency graphs, blast radius analysis, health scoring, and dead code detection

[View Documentation](./code-analysis-toolkit/README.md)

### Workflow Toolkit
Development workflow automation and productivity tools.

**Commands:**
- `/dep-check` - Check dependency health and security
- `/git-branch-cleanup` - Clean up merged/stale branches
- `/git-safe-commit` - Safe commit with validation
- `/post-impl-review` - Post-implementation review
- `/verify` - Full verification suite (typecheck, lint, test, audit)

**Skills:**
- `open-sourceror` - Prepare skills/agents for open-source sharing or marketplace integration
- `session-retrospective` - Extract learnings from Claude Code sessions

**Agents:**
- `code-reviewer` - Staff-level Rust code review specialist
- `idempotency-tester` - Verify operation idempotency
- `ops-docs-generator` - Generate operational documentation
- `review-orchestrator` - Coordinate multi-phase code reviews

[View Documentation](./workflow-toolkit/README.md)

## Installation

### Install All Plugins

```bash
/plugin marketplace add https://github.com/swannysec/robot-tools
/plugin install research-toolkit@robot-tools
/plugin install security-toolkit@robot-tools
/plugin install code-analysis-toolkit@robot-tools
/plugin install workflow-toolkit@robot-tools
```

### Install Individual Plugin

```bash
/plugin marketplace add https://github.com/swannysec/robot-tools
/plugin install <plugin-name>@robot-tools
```

### Manual Installation

```bash
git clone https://github.com/swannysec/robot-tools.git
cd robot-tools
cc --plugin-dir ./<plugin-name>
```

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
- Additional requirements vary by plugin (see individual plugin documentation)

## Structure

```
robot-tools/
├── marketplace.json               # Marketplace manifest
├── research-toolkit/              # AI/ML research tools
│   ├── plugin.json
│   └── skills/
├── security-toolkit/              # Security investigation tools
│   ├── plugin.json
│   └── skills/
├── code-analysis-toolkit/         # Code analysis tools
│   ├── plugin.json
│   └── skills/
└── workflow-toolkit/              # Workflow automation tools
    ├── plugin.json
    ├── commands/
    ├── skills/
    └── agents/
```

## License

[MIT License with Commercial Restriction](LICENSE)

## Author

**swannysec**
- GitHub: [@swannysec](https://github.com/swannysec)
