# Report Template

Use this template to generate the final investigation report.

---

```markdown
# Secret Scanning Investigation Report

**Alert ID(s):** {links}
**Repository:** {owner}/{repo}
**Investigation Date:** {date}
**Investigation Mode:** {ACTIVE/PASSIVE}
**Alerts Investigated:** {count}

---

## Executive Summary

{3-4 sentences: What was found, risk level, key evidence, recommended action}

**Overall Risk Rating:** {CRITICAL/HIGH/MEDIUM/LOW}
**Validity Status:** {CONFIRMED ACTIVE/CONFIRMED INACTIVE/UNKNOWN}
**Investigation Mode:** {ACTIVE/PASSIVE}

---

## 1. Secret Details

### 1.1 Alert Information

| Field | Value | Source |
|-------|-------|--------|
| Alert Number | #{number} | GitHub API |
| Secret Type | {type} | GitHub API |
| Display Name | {display_name} | GitHub API |
| State | {open/resolved} | GitHub API |
| GitHub Validity | {active/inactive/unknown} | GitHub API |
| Created | {date} | GitHub API |
| Base64 Encoded | {yes/no} | GitHub API |

### 1.2 Location

| Field | Value |
|-------|-------|
| File Path | `{path}` |
| Lines | {start}-{end} |
| Commit SHA | `{sha}` |
| In Current Code | {Yes/No} |
| In Git History | Yes |

### 1.3 Secret Structure (Redacted)

```
{redacted structure showing format without full secret}
```

### 1.4 Cross-Tool Validation

| Tool | Detected | Verified | Notes |
|------|----------|----------|-------|
| GitHub Native | Yes | {validity} | Alert #{number} |
| TruffleHog | {Yes/No/N/A} | {Yes/No/N/A} | {notes} |
| Gitleaks | {Yes/No/N/A} | N/A | {notes} |
| Entropy Analysis | {value} | N/A | {high/medium/low} |

---

## 2. Provenance

### 2.1 Introducing Commit

| Field | Value |
|-------|-------|
| SHA | `{sha}` |
| Date | {date} |
| Author | {name} <{email}> |
| Message | {verbatim message} |

### 2.2 File History

| Date | Commit | Author | Action |
|------|--------|--------|--------|
| {date} | `{sha}` | {author} | {description} |

### 2.3 How Secret Was Introduced

{Evidence-based description of the mechanism - e.g., "Template file with placeholder was replaced with populated config during crate restructuring"}

---

## 3. Commit and PR Context

### 3.1 Associated Pull Request

| Field | Value |
|-------|-------|
| PR Number | #{number} or "None found" |
| Title | {title} |
| Author | {author} |
| Description | {verbatim or "Empty"} |
| Merged | {date} |

### 3.2 Linked Issues

{List or "None found"}

### 3.3 Security Discussion

{Quote any security-related comments or "No security discussion found in PR/commits"}

### 3.4 Intent Assessment

**CONFIRMED:** {What the commit message/PR explicitly states}
**NOT CONFIRMED:** Whether the secret inclusion was intentional (no explicit mention found)

---

## 4. Secret Analysis

### 4.1 Secret Type Details

| Attribute | Value |
|-----------|-------|
| Type | {secret_type} |
| Format | {format description} |
| Typical Use | {what this secret type is used for} |
| Associated Service | {service name or "Unknown"} |

### 4.2 Validity Verification

**Mode:** {ACTIVE/PASSIVE}
**Status:** {CONFIRMED ACTIVE/CONFIRMED INACTIVE/UNKNOWN}
**Method:** {How determined - e.g., "Direct API call" or "Format analysis + GitHub validity field"}

| Check | Result | Source |
|-------|--------|--------|
| GitHub Validity | {active/inactive/unknown} | GitHub API |
| {Additional checks based on mode} | {result} | {source} |

{If ACTIVE mode with TruffleHog Analyze:}
### 4.3 Permission Analysis

| Resource | Permission | Details |
|----------|------------|---------|
| {resource} | {read/write/admin} | {details} |

{If GitHub App:}
### 4.4 GitHub App Comparison

| Attribute | Leaked Value | Current Value | Match |
|-----------|--------------|---------------|-------|
| App ID | {leaked} | {current} | {Yes/No} |
| Client ID | {leaked} | {current} | {Yes/No} |
| Created | N/A | {date} | N/A |

**Assessment:** {e.g., "Credentials do not match current app - original app likely deleted and replaced"}

---

## 5. Timeline

| Date | Event | Source |
|------|-------|--------|
| {date} | {event} | {commit SHA, API response, etc.} |

**Exposure Window:** {N} days
**Calculation:** From {introduction_date} to {remediation_date or "present"}

---

## 6. Risk Assessment

### 6.1 Confirmed Findings

| Factor | Finding | Evidence |
|--------|---------|----------|
| Validity | {status} | {source} |
| Exposure | {current code / history only} | {source} |
| Permissions | {scope} | {source} |
| Timeline | {N days} | {calculation} |

### 6.2 Estimates and Possibilities

| Assessment | Confidence | Reasoning |
|------------|------------|-----------|
| {assessment} | {High/Medium/Low} | {evidence-based logic} |

### 6.3 Overall Risk Rating

**Rating:** {CRITICAL/HIGH/MEDIUM/LOW}

**Justification:**
{Evidence-based explanation referencing specific findings}

### 6.4 Residual Risks

{Any remaining concerns even after remediation}

---

## 7. Recommendations

### 7.1 Immediate Actions

| Priority | Action | Rationale | Status |
|----------|--------|-----------|--------|
| P1 | {action} | {why} | {pending/done} |

### 7.2 Remediation Steps

1. **Revoke/Rotate Credential**
   {Service-specific instructions}

2. **Verify Revocation**
   {How to confirm the credential no longer works}

3. **History Cleanup (if warranted)**
   {Reference to cleanup commands or "Not recommended - credential revoked"}

4. **Update Systems**
   {Identify systems that need new credentials}

### 7.3 Prevention Measures

{Pre-commit hooks, CI/CD integration, training recommendations}

---

## Appendices

### A. Key Commits

| SHA | Date | Author | Message |
|-----|------|--------|---------|
| `{sha}` | {date} | {author} | {message} |

### B. API Queries Used

```bash
{List of gh api and other commands used}
```

### C. Tool Versions

| Tool | Version | Used For |
|------|---------|----------|
| gh | {version} | GitHub API queries |
| trufflehog | {version or N/A} | Verification |
| gitleaks | {version or N/A} | Cross-validation |

### D. Evidence Artifacts

{Any additional raw data supporting findings}

---

**Report Generated:** {timestamp}
**Investigation Mode:** {ACTIVE/PASSIVE}
```
