# README Templates

Use these templates based on component type. Replace `{{placeholders}}` with actual values.

## Single Skill (Directory-based)

```markdown
# {{SKILL_NAME}}

{{DESCRIPTION}}

## Features

{{FEATURE_LIST}}

## Installation

### Option 1: Clone to Claude Skills Directory

\`\`\`bash
git clone https://github.com/{{OWNER}}/{{REPO}}.git ~/.claude/skills/{{SKILL_NAME}}
\`\`\`

### Option 2: Symlink from Custom Location

\`\`\`bash
git clone https://github.com/{{OWNER}}/{{REPO}}.git ~/my-skills/{{SKILL_NAME}}
ln -s ~/my-skills/{{SKILL_NAME}} ~/.claude/skills/{{SKILL_NAME}}
\`\`\`

## Usage

Once installed, the skill activates automatically when you use trigger phrases:

{{TRIGGER_LIST}}

### Example Commands

\`\`\`
{{EXAMPLE_COMMANDS}}
\`\`\`

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI
{{ADDITIONAL_REQUIREMENTS}}

## Structure

\`\`\`
{{DIRECTORY_TREE}}
\`\`\`

## License

[MIT License with Commercial Product Restriction](LICENSE)
```

## Single Agent

```markdown
# {{AGENT_NAME}}

{{DESCRIPTION}}

## Capabilities

{{CAPABILITIES_LIST}}

## Installation

\`\`\`bash
git clone https://github.com/{{OWNER}}/{{REPO}}.git ~/my-agents/{{REPO}}
ln -s ~/my-agents/{{REPO}}/{{AGENT_FILE}} ~/.claude/agents/
\`\`\`

## Usage

The agent is invoked automatically when tasks match its specialization:

{{TRIGGER_CONTEXTS}}

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI

## License

[MIT License with Commercial Product Restriction](LICENSE)
```

## Mixed Collection (Skills + Agents)

```markdown
# {{COLLECTION_NAME}}

{{COLLECTION_DESCRIPTION}}

## Contents

### Skills

| Skill | Description |
|-------|-------------|
{{SKILLS_TABLE}}

### Agents

| Agent | Description |
|-------|-------------|
{{AGENTS_TABLE}}

## Installation

### Install All Components

\`\`\`bash
# Clone the repo
git clone https://github.com/{{OWNER}}/{{REPO}}.git ~/{{REPO}}

# Symlink skills
{{SKILL_SYMLINKS}}

# Symlink agents
{{AGENT_SYMLINKS}}
\`\`\`

### Install Individual Components

\`\`\`bash
# Clone the repo
git clone https://github.com/{{OWNER}}/{{REPO}}.git ~/{{REPO}}

# Symlink only what you need
{{EXAMPLE_INDIVIDUAL_SYMLINKS}}
\`\`\`

## Usage

### Skills

Skills activate automatically via trigger phrases:

{{SKILL_TRIGGERS}}

### Agents

Agents are invoked by Claude Code when their specialized capabilities match the task.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI

## Structure

\`\`\`
{{DIRECTORY_TREE}}
\`\`\`

## License

[MIT License with Commercial Product Restriction](LICENSE)
```

## Placeholder Reference

| Placeholder | Source |
|-------------|--------|
| `{{SKILL_NAME}}` | Skill directory name or frontmatter `name` |
| `{{DESCRIPTION}}` | Extract from frontmatter `description` (first sentence or paragraph) |
| `{{FEATURE_LIST}}` | Derive from skill capabilities/modes |
| `{{OWNER}}` | GitHub username (ask user or detect from `gh api user`) |
| `{{REPO}}` | Repository name |
| `{{TRIGGER_LIST}}` | Extract from frontmatter `description` triggers or skill body |
| `{{EXAMPLE_COMMANDS}}` | Generate 3-4 realistic usage examples |
| `{{DIRECTORY_TREE}}` | Generate via `find` or `tree` command |
| `{{YEAR}}` | Current year |
| `{{AUTHOR}}` | Ask user or detect from git config |
