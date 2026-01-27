---
name: open-sourceror
description: |
  Prepare Claude Code skills, agents, or mixed collections for open-source sharing on GitHub.
  Creates private repo, uploads files, generates README with install instructions, and adds MIT License with Commercial Restrictions.
  Does NOT change repo visibility—user handles that when ready.

  Use when:
  - "prepare for open source", "open source this skill"
  - "upload skill to github", "share this agent"
  - "create repo for skill", "package for sharing"
  - User has a skill directory, agent file, or collection to share
---

# Open Sourceror

Prepare AI-related components (skills, agents, collections) for open-source sharing.

## Workflow

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
# Create temp directory
cd /tmp && rm -rf {{REPO_NAME}}-upload
mkdir {{REPO_NAME}}-upload && cd {{REPO_NAME}}-upload

# Copy source files
cp -r {{SOURCE_PATH}}/* .

# Initialize and push
git init -b main
git remote add origin https://github.com/{{OWNER}}/{{REPO_NAME}}.git
git add -A
git commit -m "feat: Initial upload of {{COMPONENT_NAME}}"
git push -u origin main
```

### 5. Generate README

Select template from `references/readme-templates.md` based on component type.

Extract from source files:
- **Name/description**: From SKILL.md or agent frontmatter
- **Features**: From skill modes, agent capabilities
- **Triggers**: From frontmatter description or skill body
- **Directory structure**: Generate with `find` command

### 6. Add LICENSE

Copy `assets/LICENSE` template, replacing:
- `{{YEAR}}` → Current year
- `{{AUTHOR}}` → User-provided or detected author name

### 7. Push Documentation

```bash
# Clone, add docs, push
cd /tmp && rm -rf {{REPO_NAME}}-docs
git clone https://github.com/{{OWNER}}/{{REPO_NAME}}.git {{REPO_NAME}}-docs
cd {{REPO_NAME}}-docs
# Write README.md and LICENSE
git add -A
git commit -m "docs: Add README and LICENSE"
git push
```

### 8. Clean Up and Report

```bash
rm -rf /tmp/{{REPO_NAME}}-upload /tmp/{{REPO_NAME}}-docs
```

Report to user:
```
✅ Repository created: https://github.com/{{OWNER}}/{{REPO_NAME}}

| Property | Value |
|----------|-------|
| Visibility | Private |
| Default branch | main |
| Files | {{FILE_COUNT}} |
| README | ✓ |
| LICENSE | MIT with Commercial Restriction |

**Next step**: Change visibility to public when ready via GitHub settings or:
gh repo edit {{OWNER}}/{{REPO_NAME}} --visibility public
```

## Notes

- Always create repos as **private**—user controls when to make public
- Use HTTPS for git operations (works with gh auth)
- Use `git init -b main` to avoid master→main rename
- Verify push success before cleanup
