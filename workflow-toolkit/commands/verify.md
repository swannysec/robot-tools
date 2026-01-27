---
description: Run full verification suite (typecheck, lint, test, coverage, audit) before PR or release
arguments: []
---

# Verification Suite

Run all verification checks to confirm the project is ready for PR or release.

## Detect Project Type

First, identify what kind of project this is:

```bash
ls package.json Cargo.toml pyproject.toml go.mod 2>/dev/null
```

## Run Checks (Parallel Where Possible)

### For Node.js/TypeScript Projects

Run these checks. Report results as they complete:

#### 1. TypeScript Compilation
```bash
npm run typecheck 2>/dev/null || npx tsc --noEmit 2>/dev/null || echo "SKIP: No TypeScript configured"
```
**Success:** No output or clean compilation message.

#### 2. Linting
```bash
npm run lint 2>/dev/null || echo "SKIP: No lint script configured"
```
**Success:** No errors (warnings may be acceptable if documented).

#### 3. Tests
```bash
npm run test:run 2>/dev/null || npm test -- --run 2>/dev/null || npm test 2>/dev/null || echo "SKIP: No test script configured"
```
**Success:** All tests pass.

#### 4. Coverage (if available)
```bash
npm run test:coverage 2>/dev/null || echo "SKIP: No coverage script configured"
```
**Success:** Coverage thresholds met (check project's vitest.config.ts or jest.config.js for thresholds).

#### 5. Security Audit
```bash
npm audit 2>/dev/null || echo "SKIP: npm audit not available"
```
**Success:** `found 0 vulnerabilities`

### For Rust Projects

#### 1. Compilation
```bash
cargo check 2>/dev/null || echo "SKIP: Not a Cargo project"
```

#### 2. Linting
```bash
cargo clippy -- -D warnings 2>/dev/null || echo "SKIP: Clippy not available"
```

#### 3. Tests
```bash
cargo test 2>/dev/null || echo "SKIP: No tests"
```

#### 4. Security Audit
```bash
cargo audit 2>/dev/null || echo "SKIP: cargo-audit not installed"
```

### For Python Projects

#### 1. Type Checking
```bash
mypy . 2>/dev/null || pyright 2>/dev/null || echo "SKIP: No type checker configured"
```

#### 2. Linting
```bash
ruff check . 2>/dev/null || flake8 2>/dev/null || echo "SKIP: No linter configured"
```

#### 3. Tests
```bash
pytest 2>/dev/null || python -m unittest discover 2>/dev/null || echo "SKIP: No tests"
```

#### 4. Security Audit
```bash
pip-audit 2>/dev/null || safety check 2>/dev/null || echo "SKIP: No security audit tool"
```

### For Go Projects

#### 1. Build Check
```bash
go build ./... 2>/dev/null || echo "SKIP: Not a Go project"
```

#### 2. Linting
```bash
golangci-lint run 2>/dev/null || go vet ./... 2>/dev/null || echo "SKIP: No linter"
```

#### 3. Tests
```bash
go test ./... 2>/dev/null || echo "SKIP: No tests"
```

#### 4. Security
```bash
govulncheck ./... 2>/dev/null || echo "SKIP: govulncheck not installed"
```

## Report Summary

After all checks complete, produce a summary table:

| Check | Status | Notes |
|-------|--------|-------|
| Compilation/Types | ✓ PASS / ✗ FAIL / ⊘ SKIP | [details] |
| Linting | ✓ PASS / ✗ FAIL / ⊘ SKIP | [details] |
| Tests | ✓ PASS / ✗ FAIL / ⊘ SKIP | [count] passing |
| Coverage | ✓ PASS / ✗ FAIL / ⊘ SKIP | [percentage] |
| Security Audit | ✓ PASS / ✗ FAIL / ⊘ SKIP | [vulnerability count] |

## Final Verdict

- **✓ READY**: All checks pass (or skip gracefully) - safe to create PR
- **✗ NOT READY**: One or more checks failed - fix issues before proceeding

If NOT READY, list specific failures and suggest fixes.

## Notes

- Warnings are generally acceptable if they're known/documented
- SKIP results don't block - they indicate the check isn't configured
- For coverage failures, check if new code is untested
- For security audit failures, evaluate if vulnerabilities are exploitable in your context
