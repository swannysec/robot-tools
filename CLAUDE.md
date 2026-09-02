# Robot Tools — Project Conventions

## Project Overview

Plugin monorepo for Claude Code with four toolkits:

| Toolkit | Purpose |
|---------|---------|
| `research-toolkit` | AI/ML research and verification tools |
| `security-toolkit` | Security investigation and analysis |
| `code-analysis-toolkit` | Dependency visualization, flow analysis, health scoring |
| `workflow-toolkit` | Development workflow automation and productivity |

## Repository Structure

```
robot-tools/
├── CLAUDE.md                                  # This file — project conventions
├── README.md                                  # Root README with all plugins listed
├── LICENSE
├── .gitignore
├── .claude-plugin/
│   └── marketplace.json                       # Marketplace manifest (plugin registry)
├── .claude/
│   └── memory/                                # Session memory (gitignored)
│       └── decisions/                         # ADRs (ADR-001 through ADR-004)
├── research-toolkit/
│   ├── .claude-plugin/plugin.json             # Plugin manifest (version source of truth)
│   ├── README.md
│   └── skills/
│       ├── ai-dev-research/SKILL.md
│       ├── ai-twitter-radar/SKILL.md
│       ├── kcap/SKILL.md
│       └── research-verification/SKILL.md
├── security-toolkit/
│   ├── .claude-plugin/plugin.json
│   ├── README.md
│   └── skills/
│       ├── secret-scanning-investigator/SKILL.md
│       └── security-vuln-analyzer/SKILL.md
├── code-analysis-toolkit/
│   ├── .claude-plugin/plugin.json
│   ├── README.md
│   └── skills/
│       └── impact-flow/SKILL.md
├── workflow-toolkit/
│   ├── .claude-plugin/plugin.json
│   ├── README.md
│   ├── commands/*.md                          # Slash commands (auto-discovered)
│   ├── skills/*/SKILL.md                      # Skills (auto-discovered)
│   │   └── references/                        # Optional reference docs per skill
│   └── agents/*.md                            # Sub-agents (auto-discovered)
└── tests/                                     # Portable cross-host acceptance
```

**Auto-discovery:** Claude Code discovers components automatically from:
- Skills: `skills/*/SKILL.md`
- Agents: `agents/*.md`
- Commands: `commands/*.md`

No registration in `plugin.json` is needed for discovery. However, READMEs, root README, and keywords must be updated manually (see checklist below).

## Adding New Content

When adding a skill, agent, or command to any toolkit:

### Skill Checklist

1. Create `<toolkit>/skills/<skill-name>/SKILL.md`
2. Add YAML frontmatter with required fields:
   - `name` — must match the directory name exactly
   - `description` — multi-line (`|`) summary of what the skill does
3. Choose one profile:
   - Claude-only: add a `triggers` array (strongly recommended).
   - Portable Claude Code + Codex desktop: add `agents/openai.yaml`, omit `triggers`, link `references/runtime-claude.md` and `references/runtime-codex.md`, and follow [Portable Skill Profile v1](workflow-toolkit/skills/plugin-qa/references/portable-skill-profile.md).
4. Optionally add `<toolkit>/skills/<skill-name>/references/*.md` for supplementary docs
5. Add row to the **Skills table** in `<toolkit>/README.md`
6. Add bullet to the toolkit's **Skills** list in root `README.md`
7. Add skill name to `keywords` array in `<toolkit>/.claude-plugin/plugin.json`
8. Add trigger phrases to the **Skills trigger section** in `<toolkit>/README.md`
9. Run `plugin-qa` to validate consistency. For a portable package, also run `uv run --with pyyaml workflow-toolkit/skills/plugin-qa/scripts/validate-portable-skill.py <skill-dir>` and the cross-host acceptance suite.

### Agent Checklist

1. Create `<toolkit>/agents/<agent-name>.md`
2. Add YAML frontmatter with required fields: `name`, `description`, `tools`
3. Add row to the **Agents table** in `<toolkit>/README.md`
4. Add bullet to the toolkit's **Agents** list in root `README.md`
5. Add agent name to `keywords` array in `<toolkit>/.claude-plugin/plugin.json`

### Command Checklist

1. Create `<toolkit>/commands/<command-name>.md`
2. Add YAML frontmatter with required fields: `name`, `description`
3. Add row to the **Commands table** in `<toolkit>/README.md`
4. Add entry to the toolkit's **Commands** list in root `README.md`

## Shell Scripting

- Target **bash 3.2** (macOS default) — no bash 4+ features
- BSD userland, not GNU — no `timeout`, no GNU tar flags, no `$EPOCHSECONDS`
- Use `gtimeout` (from coreutils) or the portable timeout watchdog pattern (ADR-004)
- Use `date +%s` instead of `$EPOCHSECONDS`
- POSIX-compliant constructs preferred for cross-platform scripts
- See ADR-002 for full macOS portability rules

## Debugging Protocol

- Before each fix attempt, state the hypothesis and supporting evidence.
- When a fix remains safe and in scope, make as many as five distinct, evidence-based attempts before stopping. Do not stop solely because two attempts failed.
- After five unsuccessful attempts at the same issue, stop and re-plan the approach before making another change.

## Versioning Protocol

Each toolkit's version lives in one place only:

| File | JSON Path | Role |
|------|-----------|------|
| `<toolkit>/.claude-plugin/plugin.json` | `version` | **Source of truth** per toolkit |

The marketplace manifest (`.claude-plugin/marketplace.json`) does **not** contain version
fields. Per Claude Code docs, versions belong only in each plugin's `plugin.json`. The
marketplace lists plugins by name and source path; Claude Code reads version info directly
from each plugin's manifest.

**Semver rules:**
- `feat:` commit → bump **minor** (e.g., 0.4.0 → 0.5.0)
- `fix:` commit → bump **patch** (e.g., 0.4.0 → 0.4.1)

**Git tags:** `vX.Y.Z` — repo-level release tags, incremented on each release regardless of which plugin changed.

Use the `plugin-qa` skill in release-prep mode to automate version bumping and validation.

## ADRs

Architectural Decision Records live in `.claude/memory/decisions/`:

| ADR | Topic |
|-----|-------|
| ADR-001 | Wrapper + agent architecture for security-sensitive skills |
| ADR-002 | macOS/BSD portability — no GNU-isms |
| ADR-003 | fd3 fail-report pattern for wrapper scripts |
| ADR-004 | Portable bash timeout watchdog pattern |

**New ADR format:** `ADR-NNN-<slug>.md` with sections: Context, Decision, Consequences.

## Git Workflow

- **Conventional commits:** `feat:`, `fix:`, `docs:`, `chore:` — scope = toolkit name (e.g., `feat(workflow-toolkit): ...`)
- **Branching:** Feature branches → PR → merge to main
- **Never push directly to main**
- PR titles follow the same conventional commit format

## Gitignored vs Tracked

**Gitignored** (not in repo):
- `.claude/memory/` — session memory and ADRs
- `.claude/*.local.md` — local plugin settings
- `.claude/settings.local.json`
- `node_modules/`, `venv/`, `__pycache__/`
- `.DS_Store`, IDE files, logs, test fixtures/output

**Tracked** (in repo):
- All `plugin.json` and `marketplace.json` manifests
- All `SKILL.md`, agent, and command files
- `CLAUDE.md`, `README.md`, `LICENSE`, `.gitignore`
