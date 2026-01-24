---
name: research-verification
description: |
  Pre-flight verification checklist for research tasks. Use DURING research when gathering information about external systems, APIs, registries, or configurations.
  Prevents assumptions from becoming errors. Apply before finalizing plans or documentation.
triggers:
  - "verify research"
  - "check assumptions"
  - "validate findings"
  - "research checklist"
  - "trust but verify"
---

# Research Verification Checklist

A systematic approach to verifying assumptions made during research. Prevents costly errors from unverified information.

## When to Use

- **During** research tasks (not just after)
- Before finalizing deployment plans
- When documenting external system configurations
- When inferring patterns from incomplete documentation

## Core Principle

> **Trust but verify**: Every assumption is a potential failure point. Verification takes minutes; debugging takes hours.

---

## The Checklist

### 1. Existence Verification

Before referencing external resources, verify they exist:

| Resource Type | Verification Method |
|---------------|---------------------|
| Container registry | `curl -s -o /dev/null -w "%{http_code}" https://ghcr.io/v2/org/repo/tags/list` |
| npm package | `npm view <package> version` |
| GitHub repo | `gh repo view owner/repo` or WebFetch the URL |
| API endpoint | `curl -I https://api.example.com/health` |
| Documentation page | WebFetch with existence check |

**Pattern:**
```
Before: "The image is available at ghcr.io/org/repo"
After:  "Verified: ghcr.io/org/repo exists (or: not published, build from source)"
```

### 2. Schema Verification

When documenting configuration:

| Confidence Level | Criteria | Action |
|------------------|----------|--------|
| ✅ **High** | Found in official docs with examples | Document directly |
| ⚠️ **Medium** | Inferred from source code or patterns | Mark as "verify during implementation" |
| ❌ **Low** | Guessed based on similar systems | Mark as "unverified - may not work" |

**Pattern:**
```markdown
> [!warning] Confidence: Medium
> This configuration option was inferred from [source]. Verify before use.
```

### 3. Version Verification

External systems change. Verify currency:

- [ ] Documentation date checked (reject if >12 months old without verification)
- [ ] Release/changelog reviewed for breaking changes
- [ ] API version specified explicitly
- [ ] Dependency versions pinned

### 4. Environment Assumptions

Never assume environment details:

| Assumption | Verification |
|------------|--------------|
| Network names | Ask user or check existing configs |
| Domain names | Ask user explicitly |
| File paths | Ask user for conventions |
| Auth methods | Ask user for preferences |

**Pattern:**
```
Wrong: "Add to the traefik network"
Right: "What is your Traefik network name?" → "Add to the `proxy` network"
```

### 5. Integration Verification

When connecting systems:

- [ ] Both systems' APIs documented?
- [ ] Authentication method confirmed?
- [ ] Data format compatibility checked?
- [ ] Error handling documented?

---

## Quick Reference

### Before Documenting External Resources

```
□ Does it exist? (fetch/curl)
□ What version? (pin it)
□ Official docs? (link them)
□ Confidence level? (mark it)
```

### Before Finalizing Plans

```
□ Environment details confirmed with user?
□ Inferred configs marked with confidence?
□ Validation steps included?
□ Fallback options documented?
```

---

## Anti-Patterns

| Anti-Pattern | Problem | Better Approach |
|--------------|---------|-----------------|
| "The registry has the image" | May not exist | Verify with HTTP request |
| "Use the default network" | User may have custom setup | Ask for network name |
| "This config option does X" | May be inferred incorrectly | Mark confidence level |
| "Just run this command" | May fail silently | Add validation step |

---

## Integration

Use alongside:
- **ai-dev-research**: Apply checklist during research phase
- **session-retrospective**: Identify verification gaps in retrospectives

---

## Version

**Version:** 1.0.0
**Created:** 2025-01-20
**Origin:** Session retrospective finding - registry assumption failure
