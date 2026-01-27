---
description: Orchestrate a comprehensive post-implementation review with multiple phases (architecture, code, tests, security, docs)
arguments:
  - name: scope
    description: "Review scope: 'full' (all phases), 'quick' (code + tests only), or specific phase (architecture, code, tests, security, docs)"
    required: false
---

# Post-Implementation Review

Orchestrate a structured review after completing a feature or project implementation.

**Scope:** $ARGUMENTS.scope (default: full)

## Overview

This review follows a sequential phase approach where each phase builds on the previous. Each phase creates a separate branch and PR for audit trail.

**Critical Rule:** NEVER merge PRs without explicit user approval.

## Phase Definitions

| Phase | Focus | Agent/Tool | Branch |
|-------|-------|------------|--------|
| R0 | Baseline | /verify | - |
| R1 | Architecture | comprehensive-review:architect-review | review/architecture |
| R2 | Code Quality | comprehensive-review:code-reviewer | review/code-quality |
| R3 | Test Coverage | pr-review-toolkit:pr-test-analyzer | review/test-coverage |
| R4 | Security | comprehensive-review:security-auditor | review/security |
| R5 | Documentation | ops-docs-generator | review/documentation |
| R6 | Final | /verify | - |

## Execution

### Determine Phases to Run

Based on scope argument:
- `full` → R0, R1, R2, R3, R4, R5, R6
- `quick` → R0, R2, R3, R6
- `architecture` → R0, R1, R6
- `code` → R0, R2, R6
- `tests` → R0, R3, R6
- `security` → R0, R4, R6
- `docs` → R0, R5, R6

### R0: Baseline Verification

Run /verify command to establish baseline. All checks must pass before proceeding.

```
/verify
```

**Gate:** If baseline fails, STOP. Fix issues before review.

### R1: Architecture Review (if in scope)

1. Create branch:
```bash
git checkout main && git pull origin main
git checkout -b review/architecture
```

2. Launch architecture review agent:
```
Use Task tool with subagent_type="comprehensive-review:architect-review"
Prompt: "Review the architecture of this codebase. Focus on:
- Separation of concerns
- Module boundaries and dependencies
- Error propagation strategy
- Configuration management
- Extensibility

Identify any significant architectural issues or improvements needed."
```

3. **PAUSE POINT:** Present findings to user. If significant changes recommended:
   - List proposed changes
   - Ask: "Proceed with architectural changes? (yes/no/modify)"
   - Only continue with explicit approval

4. If changes made, commit and create PR:
```bash
git add -A && git commit -m "refactor: architecture improvements from review"
git push -u origin review/architecture
gh pr create --title "Review: Architecture Improvements" --body "[findings summary]"
```

5. **STOP.** Wait for user to merge or skip.

### R2: Code Quality Review (if in scope)

1. Create branch from latest main:
```bash
git checkout main && git pull origin main
git checkout -b review/code-quality
```

2. Launch code review agent:
```
Use Task tool with subagent_type="comprehensive-review:code-reviewer"
Prompt: "Review all source code for:
- Logic errors and bugs
- Code quality and maintainability
- Performance issues
- Error handling completeness
- DRY violations
- Dead code

Focus on high-confidence issues. Provide fixes for Critical/High issues."
```

3. Apply fixes for Critical/High issues.

4. Commit and create PR:
```bash
git add -A && git commit -m "fix: code quality improvements from review"
git push -u origin review/code-quality
gh pr create --title "Review: Code Quality Fixes" --body "[findings summary]"
```

5. **STOP.** Wait for user to merge or skip.

### R3: Test Coverage Review (if in scope)

1. Create branch from latest main:
```bash
git checkout main && git pull origin main
git checkout -b review/test-coverage
```

2. Run coverage analysis:
```bash
npm run test:coverage 2>/dev/null || cargo tarpaulin 2>/dev/null || pytest --cov 2>/dev/null
```

3. Launch test analysis agent:
```
Use Task tool with subagent_type="pr-review-toolkit:pr-test-analyzer"
Prompt: "Analyze test coverage for this codebase:
- Identify untested code paths
- Find missing edge case tests
- Check error path coverage
- Identify integration test gaps

Recommend specific tests to add for critical gaps."
```

4. Add recommended tests.

5. Verify coverage improved:
```bash
npm run test:coverage
```

6. Commit and create PR:
```bash
git add -A && git commit -m "test: improve coverage from review"
git push -u origin review/test-coverage
gh pr create --title "Review: Test Coverage Improvements" --body "[coverage before/after]"
```

7. **STOP.** Wait for user to merge or skip.

### R4: Security Review (if in scope)

1. Create branch from latest main:
```bash
git checkout main && git pull origin main
git checkout -b review/security
```

2. Run security audit:
```bash
npm audit 2>/dev/null || cargo audit 2>/dev/null || pip-audit 2>/dev/null
```

3. Launch security review agent:
```
Use Task tool with subagent_type="comprehensive-review:security-auditor"
Prompt: "Perform security review of this codebase:
- Authentication/authorization
- Input validation
- Injection vulnerabilities (SQL, command, XSS)
- Information disclosure
- Dependency vulnerabilities
- Secrets management

Prioritize findings by severity. Provide fixes for Critical/High issues."
```

4. Fix Critical/High security issues.

5. Update dependencies if vulnerabilities found:
```bash
npm audit fix 2>/dev/null || cargo update 2>/dev/null
```

6. Verify clean audit:
```bash
npm audit
```

7. Commit and create PR:
```bash
git add -A && git commit -m "security: fixes from security review"
git push -u origin review/security
gh pr create --title "Review: Security Fixes" --body "[findings summary]"
```

8. **STOP.** Wait for user to merge or skip.

### R5: Documentation Review (if in scope)

1. Create branch from latest main:
```bash
git checkout main && git pull origin main
git checkout -b review/documentation
```

2. Launch docs generator agent:
```
Use Task tool with subagent_type="ops-docs-generator"
Prompt: "Review and generate operational documentation:
- Analyze codebase for error patterns, API limits, configuration
- Create/update troubleshooting guide
- Create/update performance guide
- Enhance deployment docs with monitoring and rollback sections
- Verify .env.example is complete

Generate docs based on actual code, not templates."
```

3. Review generated docs for accuracy.

4. Commit and create PR:
```bash
git add -A && git commit -m "docs: operational documentation from review"
git push -u origin review/documentation
gh pr create --title "Review: Documentation Updates" --body "[docs added/updated]"
```

5. **STOP.** Wait for user to merge or skip.

### R6: Final Verification

After all PRs merged:

```bash
git checkout main && git pull origin main
```

Run /verify command:
```
/verify
```

**Success Criteria:**
- [ ] TypeScript/compilation passes
- [ ] Linting passes
- [ ] All tests pass
- [ ] Coverage thresholds met
- [ ] Security audit clean (0 vulnerabilities)

## Progress Tracking

Use TodoWrite to track phases:
```
- [ ] R0: Baseline verification
- [ ] R1: Architecture review (if applicable)
- [ ] R2: Code quality review (if applicable)
- [ ] R3: Test coverage review (if applicable)
- [ ] R4: Security review (if applicable)
- [ ] R5: Documentation review (if applicable)
- [ ] R6: Final verification
```

Update ConPort at completion:
```
mcp__conport__log_decision: "Post-implementation review completed"
mcp__conport__update_active_context: review_status = "complete"
```

## Summary Report

After R6, produce summary:

```markdown
## Post-Implementation Review Summary

| Phase | Status | PR | Key Findings |
|-------|--------|-----|--------------|
| R0 Baseline | ✓ | - | [baseline status] |
| R1 Architecture | ✓/⊘ | #X | [findings] |
| R2 Code Quality | ✓/⊘ | #X | [findings] |
| R3 Test Coverage | ✓/⊘ | #X | [before → after] |
| R4 Security | ✓/⊘ | #X | [vulnerabilities fixed] |
| R5 Documentation | ✓/⊘ | #X | [docs added] |
| R6 Final | ✓ | - | [final status] |

**Final State:**
- Tests: [count] passing
- Coverage: [percentage]
- Vulnerabilities: [count]
- Review PRs: [list]
```

## Critical Rules

1. **NEVER merge PRs** - only user can merge
2. **PAUSE at decision points** - especially architecture changes
3. **Each phase from fresh main** - pull after each merge
4. **Separate branches per phase** - audit trail
5. **Skip gracefully** - if user says skip a phase, proceed to next
