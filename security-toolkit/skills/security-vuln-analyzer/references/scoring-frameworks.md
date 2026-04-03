# Scoring Frameworks Reference

Combined severity scoring, prioritization formulas, business impact data, and security metrics for vulnerability assessment.

## EPSS + KEV + CVSS Combined Scoring

Do not use CVSS alone. Use three complementary signals:

### CVSS (Common Vulnerability Scoring System)
- Technical severity score (0.0-10.0)
- Measures: attack vector, complexity, privileges required, user interaction, scope, impact (confidentiality/integrity/availability)
- Limitation: does not predict real-world exploitation likelihood

### Scope Metric — Security Authority Test

CVSS 3.1 defines Scope as whether the vulnerability impacts resources beyond the security authority governing the vulnerable component. A security authority is a mechanism (application sandbox, OS user account, container runtime, hypervisor) that defines and enforces access control.

**To determine Scope, answer three questions:**
1. What security authority governs the **vulnerable component**?
2. What security authority governs the **impacted component(s)**?
3. Are these the **SAME** authority? If yes → **S:U**. If no → **S:C**.

| Example | Vulnerable Component | Impacted Component | Same Authority? | Scope |
|---------|--------------------|--------------------|----------------|-------|
| Zed Editor command injection | Zed text processing (OS user) | User's SSH keys, shell (OS user) | Yes | S:U |
| VS Code extension sandbox escape | Extension host sandbox | Host filesystem (OS user) | No | S:C |
| Container escape from dev tool | Container runtime | Host OS | No | S:C |
| Privilege escalation via helper daemon | Unprivileged user process | Root-owned service | No | S:C |

**Do NOT use application category (e.g., "developer tool") as a Scope heuristic.** Scope depends on security authority boundaries, not on what kind of software is being scored.

**Mandatory: document the Scope decision** in the consensus table with the security authorities identified for both components.

### Environmental Severity Note (Mandatory When Applicable)

When the base score uses S:U but the target environment provides access to high-value assets beyond the application's own data, add an **ENVIRONMENTAL SEVERITY NOTE** to the consensus table:

> "Base score uses S:U (single security authority: [authority]). However, the exploited context has access to [specific assets: SSH keys, cloud provider credentials, CI/CD signing keys, package registry tokens, etc.]. Real-world impact may exceed the base score. Organizations should apply CVSS Environmental metrics (Modified Scope, Confidentiality Requirement: High) or treat as [adjusted severity] for prioritization."

This preserves spec-compliant base scores comparable to NVD while explicitly documenting the real blast radius for human reviewers.

### EPSS (Exploit Prediction Scoring System)
- Probability (0.0-1.0) that a CVE will be exploited in the wild within the next 30 days
- Source: [first.org/epss](https://www.first.org/epss/)
- API: `https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN`
- Thresholds: >0.5 = high likelihood, >0.9 = near-certain exploitation
- Key insight: Many high-CVSS vulnerabilities have low EPSS scores (hard to exploit in practice)

### KEV (Known Exploited Vulnerabilities)
- Binary signal: is this CVE in CISA's Known Exploited Vulnerabilities catalog?
- Source: [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- If listed: confirmed active exploitation — escalate to Critical/immediate regardless of CVSS
- CISA mandates federal agencies patch KEV entries within specified timelines

### Combined Decision Matrix

| CVSS | EPSS | KEV | Priority | Response Timeline |
|------|------|-----|----------|-------------------|
| 9.0+ | Any | Yes | Critical | Immediate (hours) |
| 9.0+ | >0.5 | No | Critical | Immediate (24-72h) |
| 9.0+ | <0.5 | No | High | 7 days |
| 7.0-8.9 | >0.5 | Yes | Critical | Immediate |
| 7.0-8.9 | >0.5 | No | High | 7 days |
| 7.0-8.9 | <0.5 | No | Medium-High | 14 days |
| 4.0-6.9 | Any | Yes | High | 7 days |
| 4.0-6.9 | >0.5 | No | Medium | 30 days |
| 4.0-6.9 | <0.5 | No | Medium | 30 days |
| <4.0 | Any | No | Low | 90 days |

## Vulnerability Prioritization Formula

```
Priority Score = (CVSS * 0.4) + (exploitability * 2.0) + (fix_available * 1.0)
```

| Variable | Values |
|----------|--------|
| CVSS | Base score 0.0-10.0 |
| exploitability | 0 = no known exploit, 1 = PoC exists, 2 = active exploitation (KEV) |
| fix_available | 0 = no fix available, 1 = patch/update available |

Score range: 0.0-9.0. Higher = more urgent.

Example: CVSS 7.5 with active exploitation and fix available = (7.5 * 0.4) + (2 * 2.0) + (1 * 1.0) = 3.0 + 4.0 + 1.0 = **8.0** (Critical priority)

## Business Impact Data

| Metric | Value | Source |
|--------|-------|--------|
| Average data breach cost | $4.88M | IBM Cost of a Data Breach Report 2024 |
| Healthcare breach cost | $9.77M | IBM 2024 |
| Financial services breach cost | $6.08M | IBM 2024 |
| Average time to identify breach | 194 days | IBM 2024 |
| Average time to contain breach | 64 days | IBM 2024 |

### Compliance-to-Revenue Mapping

| Compliance | Business Impact |
|------------|----------------|
| SOC 2 Type II | Enables $100K+ enterprise SaaS deals |
| FedRAMP | Enables $1M+ US government contracts |
| PCI-DSS | Required for payment card processing |
| HIPAA | Required for healthcare data handling |
| GDPR | Required for EU personal data processing (fines up to 4% of annual revenue) |

## Security Metrics

Track these to measure security posture over time:

| Metric | Definition | Target |
|--------|-----------|--------|
| Vulnerability Density | Issues per 1,000 lines of code | < 1.0 |
| Mean Time to Remediate (MTTR) | Average days from discovery to fix | Critical: <1 day, High: <7 days |
| Compliance Score | % of applicable controls implemented | > 90% |
| Security Debt | Count of unfixed known issues | Trending downward |
| Scan Coverage | % of codebase covered by security scanning | > 95% |
