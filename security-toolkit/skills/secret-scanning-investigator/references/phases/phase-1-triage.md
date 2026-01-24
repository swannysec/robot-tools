# Phase 1: Initial Triage and Mode Selection

## 1.1 Basic Alert Acquisition

Fetch minimal alert details for initial triage:

```bash
gh api repos/{owner}/{repo}/secret-scanning/alerts/{alert_number} \
  --jq '{number, secret_type, state, validity, created_at, html_url}'
```

## 1.2 Mode Selection (REQUIRED)

After basic triage, **explicitly ask the user** to select an investigation mode:

```
═══════════════════════════════════════════════════════════════════
                    INVESTIGATION MODE SELECTION
═══════════════════════════════════════════════════════════════════

Alert #{number}: {secret_type} in {repo}
Status: {state} | Validity: {validity}

Before proceeding, please select an investigation mode:

┌─────────────────────────────────────────────────────────────────┐
│  PASSIVE MODE (Default - No External Probing)                   │
├─────────────────────────────────────────────────────────────────┤
│  • Analyzes secret structure and metadata only                  │
│  • Uses git history and commit context                          │
│  • Does NOT probe external services                             │
│  • No risk of exposing third-party data                         │
│                                                                 │
│  USE WHEN: The secret may belong to a third party, or you       │
│  do not have authorization to actively test credentials.        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│  ACTIVE MODE (Requires Confirmation)                            │
├─────────────────────────────────────────────────────────────────┤
│  • Actively probes the secret against service APIs              │
│  • Enumerates permissions and accessible resources              │
│  • Verifies credential validity in real-time                    │
│  • May generate logs/alerts at the target service               │
│                                                                 │
│  USE WHEN: The secret belongs to you or your organization       │
│  and you have authorization to test it.                         │
└─────────────────────────────────────────────────────────────────┘

Please select: [active/passive]
```

**Do not proceed until the user explicitly selects a mode.**

## 1.3 Active Mode Confirmation (REQUIRED if active selected)

If the user selects active mode, require explicit confirmation:

```
⚠️  WARNING: ACTIVE MODE CONFIRMATION REQUIRED

You have selected ACTIVE investigation mode.

This mode will:
• Send the leaked credential to external service APIs
• Attempt to authenticate using the credential
• Enumerate permissions and accessible resources
• Potentially generate logs, alerts, or notifications at the target service
• May expose that you possess this credential to the service provider

IMPORTANT: Only proceed if:
✓ The credential belongs to you or your organization
✓ You have authorization to test this credential
✓ You understand that this may trigger security alerts
✓ You accept responsibility for any consequences of active probing

Type 'CONFIRM ACTIVE' to proceed with active mode, or 'passive' to switch to passive mode:
```

**Do not proceed with active mode until the user types exactly 'CONFIRM ACTIVE'.**
