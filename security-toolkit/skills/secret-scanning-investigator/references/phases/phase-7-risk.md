# Phase 7: Risk Assessment

## 7.1 Risk Factor Evaluation

| Factor | ACTIVE MODE Source | PASSIVE MODE Source |
|--------|-------------------|---------------------|
| Validity | Direct API verification | GitHub validity field + format analysis |
| Permissions | TruffleHog Analyze | Inferred from secret type |
| Exposure | Code location + history | Code location + history |
| Timeline | Git history | Git history |
| Blast Radius | Permission enumeration | Secret type documentation |

## 7.2 Risk Rating Criteria

| Rating | Criteria |
|--------|----------|
| **CRITICAL** | CONFIRMED active secret with elevated privileges in current code |
| **HIGH** | CONFIRMED active secret, OR high-privilege secret with unknown validity |
| **MEDIUM** | Secret with limited scope, OR ESTIMATED revoked with high privileges |
| **LOW** | CONFIRMED revoked/invalid, OR low-privilege secret in history only |

## 7.3 Validity Assessment Format

```markdown
### Validity Assessment

**STATUS:** {CONFIRMED ACTIVE / CONFIRMED INACTIVE / UNKNOWN}
**CONFIDENCE:** {High / Medium / Low}
**METHOD:** {How validity was determined}

Evidence:
- {Evidence point 1 with source}
- {Evidence point 2 with source}

{If ESTIMATE or UNKNOWN:}
REASONING: {Logic used to arrive at assessment}
TO CONFIRM: {What additional evidence would be needed}
```

## 7.4 Exposure Timeline

```markdown
### Exposure Timeline

| Metric | Value | Source |
|--------|-------|--------|
| First Committed | {date} | git log |
| Days Exposed | {N} days | Calculated |
| In Current Code | Yes/No | HEAD check |
| Public Since | {date or N/A} | Repo visibility history |
```

## 7.5 Blast Radius Assessment

For each secret type, assess potential impact:

### High-Privilege Secrets (CRITICAL/HIGH)
- GitHub tokens with `repo`, `admin`, or `delete` scopes
- AWS keys with IAM/admin permissions
- Database connection strings with write access
- Private keys for code signing or deployment

### Medium-Privilege Secrets (MEDIUM)
- GitHub tokens with read-only scopes
- AWS keys with limited service access
- API keys for non-production services
- OAuth tokens with limited scopes

### Low-Privilege Secrets (LOW)
- Test/development credentials
- Expired or explicitly revoked secrets
- Keys for deprecated services
- Tokens that never had elevated access

## 7.6 Combining Factors

Use this matrix to determine overall risk:

| Validity | In Current Code | Privilege Level | Rating |
|----------|-----------------|-----------------|--------|
| ACTIVE | Yes | High | **CRITICAL** |
| ACTIVE | Yes | Medium | **HIGH** |
| ACTIVE | No (history) | High | **HIGH** |
| ACTIVE | No (history) | Medium | **MEDIUM** |
| UNKNOWN | Yes | High | **HIGH** |
| UNKNOWN | Yes | Medium | **MEDIUM** |
| UNKNOWN | No (history) | Any | **MEDIUM** |
| INACTIVE | Any | High | **MEDIUM** |
| INACTIVE | Any | Medium/Low | **LOW** |
