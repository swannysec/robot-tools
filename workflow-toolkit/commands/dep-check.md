---
description: Check dependency health before adding to project - verifies npm/CDN versions, bundle size, maintenance status, and known issues
arguments:
  - name: package
    description: npm package name to evaluate (e.g., "pdfjs-dist", "react")
    required: true
---

# Dependency Health Check for $ARGUMENTS.package

Evaluate this package before adding it to the project.

## Required Checks

### 1. Version Information
Use Context7 to get current documentation:
```
mcp__mcp-server-context7__resolve-library-id("$ARGUMENTS.package")
mcp__mcp-server-context7__get-library-docs(id, topic="installation")
```

Check npm for latest version:
```bash
npm view $ARGUMENTS.package version
npm view $ARGUMENTS.package time --json | tail -5
```

### 2. CDN Availability (if CDN usage planned)
Verify the npm version exists on popular CDNs:
- cdnjs: https://cdnjs.com/libraries/$ARGUMENTS.package
- unpkg: https://unpkg.com/$ARGUMENTS.package/
- jsDelivr: https://www.jsdelivr.com/package/npm/$ARGUMENTS.package

**Common issue**: npm versions often release faster than CDNs update. If using CDN, verify your exact version is available.

### 3. Bundle Size Impact
```bash
# Check package size
npm view $ARGUMENTS.package dist.unpackedSize

# For detailed analysis, use bundlephobia
# https://bundlephobia.com/package/$ARGUMENTS.package
```

Report:
- Minified size
- Gzipped size
- Tree-shakeable?
- Side effects?

### 4. Maintenance Status
```bash
npm view $ARGUMENTS.package repository.url
npm view $ARGUMENTS.package time.modified
```

Check:
- Last publish date (warn if > 1 year)
- Open issues count on GitHub
- Recent commit activity
- Maintainer responsiveness

### 5. Peer Dependencies
```bash
npm view $ARGUMENTS.package peerDependencies
```

Verify compatibility with project's existing dependencies.

### 6. Known Compatibility Issues

Use Context7 to check for bundler-specific issues:
```
mcp__mcp-server-context7__get-library-docs(id, topic="vite")
mcp__mcp-server-context7__get-library-docs(id, topic="webpack")
mcp__mcp-server-context7__get-library-docs(id, topic="bundler")
```

Common issues to check:
- ES module vs CommonJS compatibility
- Worker loading requirements
- Asset handling (fonts, wasm, etc.)
- SSR compatibility if applicable

### 7. Security
```bash
npm audit $ARGUMENTS.package
```

Check for known vulnerabilities.

## Output Report

Provide a summary:

```markdown
## Dependency Report: $ARGUMENTS.package

| Check | Status | Notes |
|-------|--------|-------|
| Latest Version | [version] | |
| CDN Available | Yes/No/Partial | [which CDNs] |
| Bundle Size | [size] | |
| Last Updated | [date] | |
| Maintenance | Active/Stale/Abandoned | |
| Peer Deps | [list or none] | |
| Known Issues | [count] | |
| Security | Clean/Warnings | |

### Recommendation
[RECOMMENDED / CAUTION / NOT RECOMMENDED]

### Notes
- [Any special configuration needed]
- [Bundler-specific setup]
- [Known gotchas]
```

## Decision Logging

**If ConPort is present:**
```
mcp__conport__log_decision(
  workspace_id,
  summary="Add/reject $ARGUMENTS.package dependency",
  rationale="[Based on health check findings]",
  tags=["dependencies", "$ARGUMENTS.package"]
)
```

**If ConPort is not available:**
Add to `.claude-session.md` or project decision log.
