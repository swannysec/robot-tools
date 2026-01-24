# Phase 0.5: Permission Pre-Approval (Session Setup)

To minimize interactive confirmations during investigation, present all read-only commands upfront for batch approval.

## 0.5.1 Permission Request

After tool check, present the following to the user:

```
═══════════════════════════════════════════════════════════════════
                    SESSION PERMISSION SETUP
═══════════════════════════════════════════════════════════════════

This investigation will execute the following READ-ONLY commands.
Approving them now will allow the investigation to proceed with
minimal interruptions.

┌─────────────────────────────────────────────────────────────────┐
│  GITHUB API COMMANDS (read-only)                                │
├─────────────────────────────────────────────────────────────────┤
│  gh api repos/{owner}/{repo}/secret-scanning/alerts/{n}         │
│  gh api repos/{owner}/{repo}/secret-scanning/alerts/{n}/locations│
│  gh api repos/{owner}/{repo}/git/commits/{sha}                  │
│  gh api repos/{owner}/{repo}/commits/{sha}/pulls                │
│  gh api repos/{owner}/{repo}/contents/{path}                    │
│  gh api repos/{owner}/{repo}/issues/{n}                         │
│  gh api /apps/{slug}                                            │
│  gh api /users/{login}                                          │
│  gh search code "{pattern}"                                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  GIT COMMANDS (local temp clone only)                           │
├─────────────────────────────────────────────────────────────────┤
│  git clone ... /tmp/{repo}-investigation                        │
│  git log, git show, git fetch (in /tmp only)                    │
│  rm -rf /tmp/{repo}-investigation (cleanup)                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  SECURITY SCANNING TOOLS (if installed)                         │
├─────────────────────────────────────────────────────────────────┤
│  trufflehog git file:///tmp/... --no-verification               │
│  trufflehog filesystem /tmp/...                                 │
│  gitleaks detect --source /tmp/...                              │
│  python3 (entropy calculation)                                  │
└─────────────────────────────────────────────────────────────────┘

These commands:
✓ Only READ data - no modifications to GitHub or your system
✓ Clone to /tmp only - automatically cleaned up
✓ Do not send credentials to external services (passive mode)

WRITE/MODIFY actions (resolving alerts, creating issues, active
verification) will ALWAYS require separate confirmation.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Options:
1. APPROVE ALL - Approve all read-only commands (recommended)
2. SELECTIVE   - I'll approve each command individually
3. REVIEW      - Show me each command before running

Select [1/2/3]:
```

## 0.5.2 Settings Recommendation

If the user frequently runs this skill, suggest adding permanent permissions:

```
TIP: To avoid this prompt in future sessions, add these to your
~/.claude/settings.json under "permissions.allow":

  "Bash(gh api:*)",
  "Bash(gh search:*)",
  "Bash(git clone:*)",
  "Bash(git log:*)",
  "Bash(git show:*)",
  "Bash(git fetch:*)",
  "Bash(trufflehog:*)",
  "Bash(gitleaks:*)",
  "Bash(python3:*)",
  "Bash(rm -rf /tmp/*-investigation)"

Would you like me to show you the full settings.json snippet? [y/n]
```

## 0.5.3 Permission Modes

Based on user selection, set the session mode:

| Selection | Behavior |
|-----------|----------|
| **APPROVE ALL** | Proceed with all read commands without further prompts |
| **SELECTIVE** | User approves/denies each command as normal |
| **REVIEW** | Show command before execution, auto-approve after display |
