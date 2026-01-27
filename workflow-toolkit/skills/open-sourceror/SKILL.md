---
name: open-sourceror
description: |
  Prepare Claude Code skills, agents, or collections for open-source sharing on GitHub.
  Supports two modes: (1) Standalone repo creation, or (2) Marketplace integration into existing plugin repos.

  Use when:
  - "prepare for open source", "open source this skill"
  - "upload skill to github", "share this agent"
  - "add to marketplace", "add to robot-tools"
  - "create repo for skill", "package for sharing"
  - User has a skill directory, agent file, or collection to share
---

# Open Sourceror

Prepare AI-related components (skills, agents, collections) for open-source sharing.

## Mode Selection

Ask user which mode to use:

| Mode | Use Case |
|------|----------|
| **Standalone** | Create new private repo for the component |
| **Marketplace** | Add to existing multi-plugin repo (e.g., robot-tools) |

Default to **Marketplace** if user mentions an existing repo name or "add to".

---

## Mode 1: Standalone Repository

Create a new private repository for the component.

### 1. Gather Information

Ask user for:
- **Source path**: Local path to skill directory, agent file, or collection
- **Repo name**: GitHub repository name (default: component name)
- **Description**: One-line repo description
- **Author name**: For LICENSE copyright (default: detect from `git config user.name`)

Detect automatically:
- **GitHub username**: `gh api user --jq '.login'`
- **Current year**: For LICENSE copyright
- **Component type**: Skill (has SKILL.md), Agent (.md with agent frontmatter), or Mixed

### 2. Detect Component Type

```
If source has SKILL.md → Single Skill
If source is .md file with "tools:" in frontmatter → Single Agent
If source has skills/ or agents/ subdirs → Mixed Collection
If source has multiple .md files with frontmatter → Mixed Collection
```

### 3. Create Repository

```bash
gh repo create {{REPO_NAME}} --private --description "{{DESCRIPTION}}"
```

### 4. Upload Files

```bash
cd /tmp && rm -rf {{REPO_NAME}}-upload
mkdir {{REPO_NAME}}-upload && cd {{REPO_NAME}}-upload
cp -r {{SOURCE_PATH}}/* .
git init -b main
git remote add origin https://github.com/{{OWNER}}/{{REPO_NAME}}.git
git add -A
git commit -m "feat: Initial upload of {{COMPONENT_NAME}}"
git push -u origin main
```

### 5. Generate README

Select template from `references/readme-templates.md` based on component type.

### 6. Add LICENSE

Copy `assets/LICENSE` template, replacing:
- `{{YEAR}}` → Current year
- `{{AUTHOR}}` → User-provided or detected author name

### 7. Push Documentation

```bash
cd /tmp && rm -rf {{REPO_NAME}}-docs
git clone https://github.com/{{OWNER}}/{{REPO_NAME}}.git {{REPO_NAME}}-docs
cd {{REPO_NAME}}-docs
# Write README.md and LICENSE
git add -A
git commit -m "docs: Add README and LICENSE"
git push
```

### 8. Report

```
✅ Repository created: https://github.com/{{OWNER}}/{{REPO_NAME}}

| Property | Value |
|----------|-------|
| Visibility | Private |
| Files | {{FILE_COUNT}} |
| README | ✓ |
| LICENSE | MIT with Commercial Restriction |

**Next step**: Make public when ready:
gh repo edit {{OWNER}}/{{REPO_NAME}} --visibility public
```

---

## Mode 2: Marketplace Integration

Add component to an existing multi-plugin repository.

### 1. Gather Information

Ask user for:
- **Source path**: Local path to skill directory or agent file
- **Plugin repo**: GitHub repo URL or name (e.g., `swannysec/robot-tools`)
- **Target toolkit**: Which toolkit to add to (e.g., `research-toolkit`, `workflow-toolkit`)

If user has a default configured in `~/.config/open-sourceror/config.json`, use that:
```json
{
  "default_plugin_repo": "swannysec/robot-tools",
  "default_toolkit": null
}
```

Detect automatically:
- **Component type**: Skill or Agent
- **Component name**: From directory name or frontmatter

### 2. Validate Plugin Repo Structure

```bash
# Clone to temp
cd /tmp && rm -rf {{REPO_NAME}}-marketplace
gh repo clone {{PLUGIN_REPO}} {{REPO_NAME}}-marketplace
cd {{REPO_NAME}}-marketplace
```

Verify structure:
```bash
# Must have marketplace.json
test -f .claude-plugin/marketplace.json

# Must have target toolkit
test -d {{TARGET_TOOLKIT}}
test -f {{TARGET_TOOLKIT}}/.claude-plugin/plugin.json
```

### 3. Determine Target Directory

```
If Skill (has SKILL.md) → {{TARGET_TOOLKIT}}/skills/{{COMPONENT_NAME}}/
If Agent (.md file) → {{TARGET_TOOLKIT}}/agents/{{COMPONENT_NAME}}.md
```

### 4. Copy Component

```bash
# For skill
cp -r {{SOURCE_PATH}} {{TARGET_TOOLKIT}}/skills/

# For agent
cp {{SOURCE_PATH}} {{TARGET_TOOLKIT}}/agents/
```

### 5. Update Toolkit README

Read `{{TARGET_TOOLKIT}}/README.md` and add entry to appropriate table:

**For Skills** - add to Skills table:
```markdown
| `{{SKILL_NAME}}` | {{DESCRIPTION}} |
```

**For Agents** - add to Agents table:
```markdown
| `{{AGENT_NAME}}` | {{DESCRIPTION}} |
```

Also add:
- Trigger phrases to Usage section
- Example command to Examples section
- Any new requirements to Requirements section

### 6. Create Branch and Commit

```bash
git checkout -b feat/{{COMPONENT_NAME}}
git add {{TARGET_TOOLKIT}}/
git commit -m "feat({{TARGET_TOOLKIT}}): add {{COMPONENT_NAME}} {{TYPE}}"
git push -u origin feat/{{COMPONENT_NAME}}
```

### 7. Create Pull Request

```bash
gh pr create \
  --title "feat({{TARGET_TOOLKIT}}): add {{COMPONENT_NAME}} {{TYPE}}" \
  --body "## Summary

Add \`{{COMPONENT_NAME}}\` {{TYPE}} to {{TARGET_TOOLKIT}}.

{{DESCRIPTION}}

## Files Added

\`\`\`
{{FILE_LIST}}
\`\`\`

## Test plan

- [ ] Verify {{TYPE}} triggers on relevant phrases
- [ ] Test {{TYPE}} functionality"
```

### 8. Clean Up and Report

```bash
rm -rf /tmp/{{REPO_NAME}}-marketplace
```

Report:
```
✅ Pull request created: {{PR_URL}}

| Property | Value |
|----------|-------|
| Repository | {{PLUGIN_REPO}} |
| Toolkit | {{TARGET_TOOLKIT}} |
| Component | {{COMPONENT_NAME}} |
| Type | {{TYPE}} |
| Branch | feat/{{COMPONENT_NAME}} |

**Next step**: Review and merge the PR.
```

---

## Toolkit Selection Guide

If user doesn't specify toolkit, suggest based on component purpose:

| Component Purpose | Suggested Toolkit |
|-------------------|-------------------|
| Research, discovery, information gathering | `research-toolkit` |
| Security analysis, vulnerability scanning | `security-toolkit` |
| Code analysis, metrics, visualization | `code-analysis-toolkit` |
| Workflow automation, productivity, sharing | `workflow-toolkit` |

---

## Notes

- Always create branches for marketplace mode—never push directly to main
- Use conventional commit format: `feat(toolkit): add component-name type`
- Standalone repos are created as **private**—user controls visibility
- Verify target toolkit exists before proceeding
- Extract description from frontmatter for README updates
