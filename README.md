# Robot Tools

A comprehensive collection of Claude Code plugins for research, security, code analysis, and workflow automation. Selected self-contained skills also support local Codex in the ChatGPT/Codex desktop app; ChatGPT on the web is outside this support scope.

## Plugins

### Research Toolkit
AI/ML research and verification tools for software development.

**Skills:**
- `ai-dev-research` - Expert technical research on AI topics
- `ai-twitter-radar` - Discover AI trends and news from Twitter/X using Bird CLI
- `research-verification` - Pre-flight verification checklist for research tasks
- `kcap` - Capture and distill URLs with portable Claude Code and Codex desktop runtimes
- `starduster` - Catalog GitHub starred repos into a structured Obsidian vault

[View Documentation](./research-toolkit/README.md)

### Security Toolkit
Security investigation and analysis tools.

**Skills:**
- `secret-scanning-investigator` - Investigate GitHub secret scanning alerts with evidence-based analysis
- `security-vuln-analyzer` - Multi-agent vulnerability analysis with adversarial verification, ICD 203 analytic standards, CWE-specific procedures, confirmation bias mitigation, deterministic validation, primitive class enumeration, `--verify-fix` mode (mandatory bypass construction before issue closure), and `--develop-fix` mode (Rust-first v1 — authors a human-gated candidate patch: validated regression tests + minimum fix on a branch, then mandatory `--verify-fix` handoff)
- `gha-hardening` - GitHub Actions security hardening — permissions, secrets, OIDC, attack patterns, supply chain, detection tools, runner security, incident response
- `vanta` - Vanta compliance operations — posture analysis, audit readiness, vulnerability management, personnel compliance, flexible reporting, and direct API operations
- `vercel-forensics` - Preservation-first forensic evidence collection and analysis for Vercel incidents — read-only collection across Vercel + GitHub, redaction, SHA-256 manifest + software WORM freeze, 8-section findings report, and rotation-worklist CSV handoff to subinium/metapod

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
- `phased-review` - Multi-stage implementation review with parallel sub-agents, test gates, and scope modes
- `safe-skill-install` - Supply chain security scanning for skill installations via Cisco skill-scanner
- `session-retrospective` - Extract learnings from Claude Code sessions
- `plugin-qa` - Validate plugins and standalone Portable Skill Profile v1 packages; guided release prep with version bumping
- `gh-aw-helper` - GitHub Agentic Workflows guide — setup, authoring, triggers, safe I/O, security, MCP tools, patterns, troubleshooting
- `anti-laziness-guard` - Three-layer Stop hook detecting and blocking work-skipping rationalizations (regex + Haiku intent detection + optional deep verification)
- `docker-sandbox` - Docker Sandboxes (sbx CLI) — run AI coding agents in isolated microVMs with credential proxying, network policies, custom templates, and 1Password integration

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

### Portable skill installation

Skills marked with `agents/openai.yaml` conform to [Portable Skill Profile v1](./workflow-toolkit/skills/plugin-qa/references/portable-skill-profile.md). Copy the complete canonical skill directory unchanged into a host's skill directory:

- Claude Code project: `.claude/skills/<skill-name>`
- Codex desktop user: `$CODEX_HOME/skills/<skill-name>` (normally `~/.codex/skills/<skill-name>`)

An optional distributor may use another host-recognized shared skill root, such as
`.agents/skills`, when it verifies that destination against the active desktop build.

`research-toolkit/skills/kcap` and `research-toolkit/skills/starduster` are portable
skills. Both work without hplumb; hplumb may distribute either complete package but is
never a runtime dependency.

Run the noninteractive proof-of-concept acceptance suite with:

```bash
uv run --with pyyaml tests/run_dual_runtime_acceptance.py --all --live --hplumb-verify
```

The runner uses temporary skill roots, projects, configuration, state, and output
directories. A requested live or hplumb check that cannot run is reported as
`INCOMPLETE` and returns nonzero; it is never treated as a passing release gate.

## Requirements

- Claude Code CLI for plugin use, or local Codex in the ChatGPT/Codex desktop app for portable skills
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
├── workflow-toolkit/              # Workflow automation tools
│   ├── plugin.json
│   ├── commands/
│   ├── skills/
│   ├── agents/
│   └── hooks/
└── tests/                         # Cross-host portable-skill acceptance
```

## License

[MIT License with Commercial Restriction](LICENSE)

## Author

**swannysec**
- GitHub: [@swannysec](https://github.com/swannysec)
