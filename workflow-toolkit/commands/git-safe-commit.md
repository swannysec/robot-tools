---
description: Safe commit workflow - runs build, tests, and checks before allowing commit
arguments:
  - name: message
    description: Commit message (format "type: description")
    required: true
---

# Safe Commit Workflow

Validate and commit changes with message: "$ARGUMENTS.message"

## Pre-Commit Validation

### 1. Check Commit Message Format
Verify message follows conventional format:
- `feat:` - New feature
- `fix:` - Bug fix
- `refactor:` - Code refactoring
- `docs:` - Documentation only
- `test:` - Adding/updating tests
- `chore:` - Maintenance tasks
- `style:` - Formatting, no code change
- `perf:` - Performance improvement

Message: "$ARGUMENTS.message"
- [ ] Has valid type prefix
- [ ] Description is meaningful (not just "updates" or "changes")

### 2. Build Check
```bash
npm run build
```
- [ ] Build completes without errors
- [ ] No new warnings (or warnings are acceptable)

If build fails, STOP and fix issues before proceeding.

### 3. Test Check
```bash
npm test
```
- [ ] All tests pass
- [ ] No skipped tests that should run

If tests fail, STOP and fix issues before proceeding.

### 4. Lint Check (if available)
```bash
npm run lint 2>/dev/null || echo "No lint script configured"
```
- [ ] No linting errors (or no lint configured)

### 5. Code Quality Scan
Check staged files for common issues:

```bash
git diff --cached --name-only
```

For each staged file, check for:
- [ ] No `console.log` statements (unless intentional logging)
- [ ] No `debugger` statements
- [ ] No commented-out code blocks without explanation
- [ ] No hardcoded secrets or API keys
- [ ] No TODO/FIXME without ticket reference

### 6. Review Staged Changes
```bash
git diff --cached --stat
git diff --cached
```

- [ ] Changes match commit message description
- [ ] No unintended files included
- [ ] No large binary files accidentally staged

## Context Updates

### 7. Update Progress Tracking

**If ConPort is present:**
```
mcp__conport__update_progress(workspace_id, progress_id, status="DONE")
mcp__conport__log_decision(...) # If any decisions were made
```

**If ConPort is not available:**
- Update `.claude-session.md` with completed work
- Note any decisions made in this work

## Execute Commit

### 8. Commit
If all checks pass:
```bash
git add -A
git status
git commit -m "$ARGUMENTS.message"
```

### 9. Post-Commit
```bash
git log -1 --oneline
```

Confirm commit was created successfully.

## Failure Handling

If any check fails:
1. Report which check failed
2. Provide specific error/issue found
3. Suggest fix approach
4. Do NOT proceed with commit

## Optional: Push
After successful commit, optionally:
```bash
git push
```

Only if user confirms or requests push.
