# Action: Generate Prevention Recommendations (8.6)

## Pre-Commit Hook Configuration

```yaml
# .pre-commit-config.yaml
repos:
  # TruffleHog - comprehensive secret detection with verification
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.63.0
    hooks:
      - id: trufflehog
        entry: trufflehog git file://. --since-commit HEAD --fail

  # Gitleaks - fast regex-based detection
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks

# Install: pip install pre-commit && pre-commit install
```

## CI/CD Integration

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning
on: [push, pull_request]

jobs:
  trufflehog:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: TruffleHog Scan
        uses: trufflesecurity/trufflehog@main
        with:
          extra_args: --only-verified

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Gitleaks Scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## GitGuardian Integration (Optional)

```yaml
# .github/workflows/gitguardian.yml
name: GitGuardian Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: GitGuardian scan
        uses: GitGuardian/ggshield-action@v1.25.0
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
```

## Additional Recommendations

### For Teams
1. **Enable GitHub Advanced Security** - Native secret scanning with push protection
2. **Require PR reviews** - Second pair of eyes catches accidental commits
3. **Use environment variables** - Never hardcode secrets in source files
4. **Implement secret rotation** - Regular rotation limits exposure windows

### For Developers
1. **Use .gitignore** - Exclude config files with secrets
2. **Use git-secrets** - AWS-specific pre-commit hook
3. **Check before commit** - `git diff --staged` before committing
4. **Use secret managers** - HashiCorp Vault, AWS Secrets Manager, etc.
