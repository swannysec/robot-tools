---
description: Bootstrap a new project with Claude Code best practices - sets up context management, skills directory, and initial documentation
arguments:
  - name: name
    description: Project name
    required: true
  - name: type
    description: "Project type: 'web', 'api', 'library', or 'fullstack' (default: web)"
    required: false
---

# Bootstrap Project: $ARGUMENTS.name

Type: $ARGUMENTS.type (default: web)

## 1. Create Project Structure

### Claude Code Directory
```bash
mkdir -p .claude/skills
mkdir -p .claude/commands
```

### Context Files (add to .gitignore)
```bash
# Create placeholder context files
touch .claude-session.md
mkdir -p .claude-memories
```

### Update .gitignore
Add these entries:
```
# Claude Code context (local only)
.claude-session.md
.claude-memories/
*-handoff.md
.debug-journal.md
```

## 2. Create CLAUDE.md

Create project-specific instructions:

```markdown
# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

# $ARGUMENTS.name - Claude Code Instructions

## Project Overview
[DESCRIPTION - to be filled in]

## Development Environment

**Setup:**
1. [Setup steps - customize for project]

## Critical Tools

### Context Management (Optional)

**If ConPort is available**, use for project context:
- `mcp__conport__log_decision` - Log architectural decisions
- `mcp__conport__log_progress` - Track task status
- `mcp__conport__update_active_context` - Maintain current focus

**If ConPort is not available**, use local files:
- `.claude-session.md` - Session state and handoffs
- `.claude-memories/*.md` - Learnings and patterns

### Serena (If Available)

Use Serena for semantic code navigation:
- `get_symbols_overview` - Explore file structure
- `find_symbol` - Locate code elements
- `replace_symbol_body` - Edit functions/methods

## Project-Specific Skills

Add custom skills to `.claude/skills/` as needed.

## Workflows

### Session Start
1. Check `.claude-session.md` for previous state
2. Review git status and recent commits
3. Identify current priorities

### Session End
1. Update `.claude-session.md` with current state
2. Commit or stash changes
3. Note next steps

### Before Commits
1. Run build: `npm run build`
2. Run tests: `npm test`
3. Review staged changes

## Key Features
[LIST - to be filled in]

## Success Criteria
[LIST - to be filled in]

## Forbidden Actions
- DO NOT commit without running tests
- DO NOT skip context updates at session end
- DO NOT [project-specific rules]
```

## 3. Create Initial Context

### .claude-session.md Template
```markdown
# Claude Code Session Context

## Project: $ARGUMENTS.name
Created: [TIMESTAMP]

## Current Focus
[Initial setup]

## Recent Decisions
| Decision | Rationale | Date |
|----------|-----------|------|
| Project bootstrapped | Starting new project | [DATE] |

## Progress
| Task | Status | Notes |
|------|--------|-------|
| Initial setup | DONE | Project bootstrapped |

## Known Issues
- None yet

## Next Session
- [Define initial tasks]
```

## 4. Project Type Configuration

### Web Project
Add to CLAUDE.md:
```markdown
## Development Commands
- `npm run dev` - Start dev server
- `npm run build` - Production build
- `npm test` - Run tests
- `npm run lint` - Check code style

## Tech Stack
- [Framework: React/Vue/Svelte/etc.]
- [Build tool: Vite/Webpack/etc.]
- [Styling: CSS/Tailwind/etc.]
```

### API Project
Add to CLAUDE.md:
```markdown
## Development Commands
- `npm run dev` - Start dev server with hot reload
- `npm run build` - Compile TypeScript
- `npm test` - Run tests
- `npm start` - Production server

## Tech Stack
- [Framework: Express/Fastify/Hono/etc.]
- [Database: PostgreSQL/MongoDB/etc.]
- [ORM: Prisma/Drizzle/etc.]
```

### Library Project
Add to CLAUDE.md:
```markdown
## Development Commands
- `npm run build` - Build library
- `npm test` - Run tests
- `npm run lint` - Check code style
- `npm pack` - Create package tarball

## Publishing
- Update version in package.json
- Run tests and build
- `npm publish`
```

### Fullstack Project
Combine Web and API sections as appropriate.

## 5. Initialize ConPort (If Available)

**If ConPort is present:**
```
mcp__conport__update_product_context(
  workspace_id,
  content={
    "name": "$ARGUMENTS.name",
    "type": "$ARGUMENTS.type",
    "goals": ["To be defined"],
    "created": "[timestamp]"
  }
)

mcp__conport__log_progress(
  workspace_id,
  status="DONE",
  description="Project bootstrapped with Claude Code best practices"
)
```

## 6. Summary

After bootstrap, the project has:
- [ ] `.claude/` directory for skills and commands
- [ ] `.claude-session.md` for session context
- [ ] `.claude-memories/` for persistent learnings
- [ ] `CLAUDE.md` with project instructions
- [ ] `.gitignore` updated for context files
- [ ] Initial context recorded (ConPort or local files)

## Next Steps
1. Fill in CLAUDE.md project overview and details
2. Define initial tasks and priorities
3. Add project-specific skills to `.claude/skills/`
4. Begin development
