---
name: security-vuln-analyzer
description: Multi-agent security vulnerability analysis and remediation skill. Orchestrates parallel security agents to analyze vulnerability reports, validate findings, assess risk, and provide comprehensive fix recommendations. Use when receiving vulnerability reports, security disclosures, bug bounty submissions, or when needing to assess and remediate security issues. Triggers on keywords like "vulnerability report", "security issue", "CVE", "clickjacking", "XSS", "CSRF", "injection", "security disclosure", or requests to analyze/fix security problems.
---

# Security Vulnerability Analyzer

Orchestrate multiple specialized security agents in parallel to provide comprehensive vulnerability analysis, validation, threat modeling, and fix recommendations.

## Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. VALIDATE: Confirm vulnerability exists                      │
│     - Fetch target URL/endpoint headers                         │
│     - Check for missing security controls                       │
│     - Document current security posture                         │
├─────────────────────────────────────────────────────────────────┤
│  2. ANALYZE: Launch 4 agents IN PARALLEL                        │
│     ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────┐│
│     │Security      │ │Threat        │ │Backend       │ │Compr- ││
│     │Auditor       │ │Modeling      │ │Security      │ │ehensive││
│     │              │ │Expert        │ │Coder         │ │Review ││
│     └──────────────┘ └──────────────┘ └──────────────┘ └───────┘│
├─────────────────────────────────────────────────────────────────┤
│  3. SYNTHESIZE: Combine agent findings                          │
│     - Consensus assessment                                      │
│     - Consolidated fix recommendations                          │
│     - Risk summary matrix                                       │
└─────────────────────────────────────────────────────────────────┘
```

## Step 1: Validate the Vulnerability

Before launching agents, confirm the vulnerability exists:

```bash
# For web vulnerabilities, check HTTP headers
curl -sI <TARGET_URL> | head -50

# Look for missing security headers:
# - X-Frame-Options (clickjacking)
# - Content-Security-Policy (XSS, clickjacking)
# - X-Content-Type-Options (MIME sniffing)
# - Strict-Transport-Security (HTTPS enforcement)
```

Document findings:
- **Missing headers/controls**: List what's absent
- **Present security measures**: Note existing protections
- **Technology stack**: Identify framework, hosting (helps with fix)

## Step 2: Launch Parallel Security Agents

Launch ALL FOUR agents in a SINGLE message with parallel Task tool calls:

### Agent 1: Security Auditor
```
subagent_type: security-scanning:security-auditor
prompt: |
  Analyze this vulnerability and provide security audit assessment:

  **Target:** [URL/System]
  **Vulnerability:** [Type and description]
  **Current Security Posture:** [Headers/controls present and missing]

  Provide:
  1. CVSS score estimate with breakdown
  2. Attack scenarios specific to this context
  3. Compliance implications (OWASP, SOC2, PCI-DSS, GDPR)
  4. Prioritized remediation steps
  5. Additional security concerns identified
```

### Agent 2: Threat Modeling Expert
```
subagent_type: security-scanning:threat-modeling-expert
prompt: |
  Create threat model for this vulnerability:

  **Target:** [URL/System]
  **Vulnerability:** [Type and description]
  **Context:** [Technology stack, authentication flow, etc.]

  Provide:
  1. STRIDE analysis for this vulnerability
  2. Attack tree showing potential attack paths
  3. Threat actor analysis (who might exploit this)
  4. Impact assessment (users and business)
  5. Risk rating with justification
```

### Agent 3: Backend Security Coder
```
subagent_type: backend-api-security:backend-security-coder
prompt: |
  Review proposed fix and provide implementation guidance:

  **Target:** [URL/System]
  **Vulnerability:** [Type]
  **Technology Stack:** [Framework, hosting]
  **Proposed Fix:** [Initial fix recommendation]

  Provide:
  1. Code review of proposed fix - improvements needed?
  2. Framework-specific implementation (Next.js, Rails, Django, etc.)
  3. Additional security headers/controls to add
  4. Testing strategy to verify the fix
  5. Edge cases and gotchas for this stack
```

### Agent 4: Comprehensive Security Reviewer
```
subagent_type: comprehensive-review:security-auditor
prompt: |
  Provide comprehensive security review:

  **Vulnerability Report:** [Summary]
  **Target:** [URL/System]
  **Current Posture:** [What's present vs missing]

  Address:
  1. Is this report legitimate or false positive?
  2. Real-world exploitability given modern protections
  3. Urgency assessment - emergency vs regular release cycle
  4. Additional vulnerabilities suggested by findings
  5. Complete security header recommendations
  6. Related attack vectors to investigate
```

## Step 3: Synthesize Agent Findings

After all agents return, create consolidated summary:

### Consensus Assessment Table
| Aspect | Agent Consensus |
|--------|-----------------|
| Vulnerability Valid? | [Yes/No + confidence] |
| CVSS Score | [Score + range from agents] |
| Urgency | [Timeline recommendation] |
| Fix Complexity | [Low/Medium/High] |

### Key Findings by Agent
Summarize unique insights from each agent:
- **Security Auditor**: Compliance, CVSS breakdown
- **Threat Modeling**: Attack paths, threat actors
- **Backend Security**: Implementation specifics, gotchas
- **Comprehensive Review**: Legitimacy, related vulnerabilities

### Consolidated Fix Recommendation
Merge agent recommendations into single implementation:
```
[Framework-specific code example]
```

### Risk Summary Box
```
┌─────────────────────────────────────────────────────────────┐
│  [VULNERABILITY NAME] - [Target]                            │
├─────────────────────────────────────────────────────────────┤
│  Severity:        [Rating] (CVSS [Score])                   │
│  Exploitability:  [Low/Medium/High] ([reason])              │
│  Fix Effort:      [Minimal/Moderate/Significant]            │
│  Timeline:        [Recommended fix window]                  │
│  Compliance:      [Affected standards]                      │
└─────────────────────────────────────────────────────────────┘
```

## Common Vulnerability Patterns

### Web Application Vulnerabilities
| Vulnerability | Key Headers/Controls | Primary Agent Focus |
|--------------|---------------------|---------------------|
| Clickjacking | X-Frame-Options, CSP frame-ancestors | All agents |
| XSS | CSP script-src, X-Content-Type-Options | Security Auditor |
| CSRF | SameSite cookies, CSRF tokens | Backend Security |
| Open Redirect | Input validation, allowlists | Threat Modeling |
| SQL Injection | Parameterized queries, WAF | Backend Security |

### Verification Commands
```bash
# Check all security headers
curl -sI [URL] | grep -iE "(x-frame|content-security|x-content-type|strict-transport|referrer-policy|permissions-policy)"

# Test iframe embedding (clickjacking)
echo '<iframe src="[URL]"></iframe>' > test.html && open test.html

# Check SSL/TLS configuration
curl -sI [URL] | grep -i strict-transport
```

## Output Quality Checklist

Before delivering final report, verify:
- [ ] Vulnerability validated with actual evidence
- [ ] All 4 agents launched in parallel (single message)
- [ ] CVSS score provided with breakdown
- [ ] Framework-specific fix code included
- [ ] Testing/verification steps provided
- [ ] Urgency/timeline recommendation clear
- [ ] Compliance implications noted
