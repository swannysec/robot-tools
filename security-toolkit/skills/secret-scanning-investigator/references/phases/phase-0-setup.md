# Phase 0: Environment Setup and Tool Check

## Required Tools

Before beginning investigation, verify the following tools are available:

```bash
# Check for required tools
command -v gh >/dev/null 2>&1 && echo "✓ gh CLI" || echo "✗ gh CLI (REQUIRED)"
command -v git >/dev/null 2>&1 && echo "✓ git" || echo "✗ git (REQUIRED)"
command -v trufflehog >/dev/null 2>&1 && echo "✓ trufflehog" || echo "✗ trufflehog (optional - enables verification)"
command -v gitleaks >/dev/null 2>&1 && echo "✓ gitleaks" || echo "✗ gitleaks (optional - enables cross-validation)"
command -v ggshield >/dev/null 2>&1 && echo "✓ ggshield" || echo "✗ ggshield (optional - enables leak checking)"
```

## Tool Installation Offer

If optional tools are missing, offer to install them:

```
The following optional tools are not installed:
- trufflehog: Enables credential verification and permission analysis
- gitleaks: Enables cross-tool validation and SARIF output
- ggshield: Enables public leak checking (requires free GitGuardian account)

Would you like me to install any of these tools?

1. Install trufflehog (recommended - adds verification)
2. Install gitleaks (recommended - adds cross-validation)
3. Install ggshield (optional - adds public leak checking)
4. Install all available tools
5. Skip - proceed with available tools only

Note: Installation requires your confirmation for each tool.
```

## Installation Commands (Open-Source Only)

**All tools below are free and open-source.**

```bash
# TruffleHog (Apache 2.0 License)
# macOS
brew install trufflehog
# Linux/other - direct binary
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Gitleaks (MIT License)
# macOS
brew install gitleaks
# Linux/other - direct binary
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_$(uname -s)_$(uname -m).tar.gz | tar -xz -C /usr/local/bin gitleaks

# ggshield (MIT License) - requires free GitGuardian account for API key
pip install ggshield
# After install: ggshield auth login
```

## Installation Confirmation

**Before executing any installation:**
```
⚠️  INSTALLATION CONFIRMATION

I will run the following command to install {tool}:
{command}

This will:
- Download the tool from {source}
- Install to {location}
- Require {permissions}

Type 'CONFIRM' to proceed or 'skip' to continue without this tool:
```
