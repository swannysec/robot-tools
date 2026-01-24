# Action: Resolve Alert (8.3)

**Requires explicit confirmation before execution.**

## Confirmation Prompt

```
⚠️  DESTRUCTIVE ACTION: RESOLVE ALERT

You are about to resolve {count} secret scanning alert(s):
- Alert #{number}: {secret_type} in {file_path}

Available resolution types:
┌────────────────┬─────────────────────────────────────────────┐
│ Resolution     │ Use When                                    │
├────────────────┼─────────────────────────────────────────────┤
│ revoked        │ Secret has been rotated or revoked          │
│ false_positive │ Not actually a secret or not sensitive      │
│ wont_fix       │ Accepted risk, no action planned            │
│ used_in_tests  │ Intentionally used in test fixtures         │
└────────────────┴─────────────────────────────────────────────┘

Select resolution type (or 'cancel'):
```

## After Selection

```
Resolution: {type}
Comment (max 280 chars): {auto-generated summary}

This action:
- Changes alert state to 'resolved'
- Is visible in repository security tab
- Is logged with your username

Type 'CONFIRM' to proceed or 'cancel' to abort:
```

## Execution

```bash
gh api repos/{owner}/{repo}/secret-scanning/alerts/{number} \
  --method PATCH \
  -f state='resolved' \
  -f resolution='{type}' \
  -f resolution_comment='{comment}'
```

## Auto-Generated Comment Templates

| Resolution | Comment Template |
|------------|------------------|
| revoked | "Credential rotated on {date}. Investigation confirmed no unauthorized access." |
| false_positive | "Determined to be {reason}: {evidence}. Not a sensitive credential." |
| wont_fix | "Accepted risk per security review. Mitigation: {mitigation}." |
| used_in_tests | "Intentional test fixture in {test_path}. Not a production credential." |
