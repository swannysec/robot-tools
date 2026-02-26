---
name: security-vuln-analyzer
description: Multi-agent security vulnerability analysis and remediation skill. Orchestrates parallel security agents to analyze vulnerability reports, validate findings, assess risk, and provide comprehensive fix recommendations. Use when receiving vulnerability reports, security disclosures, bug bounty submissions, or when needing to assess and remediate security issues. Triggers on keywords like "vulnerability report", "security issue", "CVE", "clickjacking", "XSS", "CSRF", "injection", "security disclosure", or requests to analyze/fix security problems.
---

# Security Vulnerability Analyzer

Orchestrate multiple specialized security agents in parallel to provide comprehensive vulnerability analysis, validation, threat modeling, and fix recommendations.

## Evidence-Only Policy

**No assumptions. No guessing. Every conclusion must be grounded in evidence.**

This policy applies to the orchestrating agent, all 5 sub-agents, and the synthesis step:

1. **All claims must cite evidence.** Every finding must reference specific source code (file path + line number), HTTP response data, configuration values, or official documentation. Generic statements like "this is typically vulnerable" without pointing to the actual code or config are not acceptable.
2. **If you cannot verify it, say so.** When source code or documentation is unavailable for a claim, explicitly state "NOT VERIFIED — [reason]" rather than presenting the claim as fact.
3. **No speculative severity ratings.** CVSS scores and risk ratings must be justified by observed evidence (actual headers, actual code paths, actual configurations), not by what "could" theoretically exist.
4. **Cite sources in findings.** Use the format: `[source: path/to/file.py:42]` for code, `[source: HTTP response header]` for runtime evidence, `[source: docs.example.com/page]` for documentation references.

**Include the following preamble in every sub-agent prompt:**

> EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason. Findings without citations will be discarded during synthesis.

## Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. VALIDATE: Confirm vulnerability exists                      │
│     - Fetch target URL/endpoint headers                         │
│     - Check for missing security controls                       │
│     - Document current security posture                         │
├─────────────────────────────────────────────────────────────────┤
│  2. ANALYZE: Launch 5 agents IN PARALLEL                        │
│     ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐    │
│     │Security   │ │Threat     │ │Backend    │ │Compre-    │    │
│     │Sentinel   │ │Modeling   │ │Security   │ │hensive    │    │
│     │           │ │Expert     │ │Coder      │ │Review     │    │
│     └───────────┘ └───────────┘ └───────────┘ └───────────┘    │
│     ┌───────────┐                                               │
│     │Codex 5.3  │                                               │
│     │(OpenAI)   │                                               │
│     └───────────┘                                               │
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

Launch ALL FIVE agents in a SINGLE message with parallel tool calls:

### Agent 1: Security Sentinel
```
subagent_type: compound-engineering:review:security-sentinel
prompt: |
  EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason. Findings without citations will be discarded during synthesis.

  METHODOLOGY:

  Severity scoring — use three signals, not CVSS alone:
  - CVSS: Technical severity. Justify each metric with observed evidence.
  - EPSS: Exploit Prediction Scoring System — probability (0.0-1.0) that this CVE will be exploited in the wild within 30 days. Check first.org/epss API if a CVE ID is available. EPSS > 0.5 = high exploitation likelihood.
  - KEV: CISA Known Exploited Vulnerabilities catalog. Check cisa.gov/known-exploited-vulnerabilities-catalog. If listed, escalate urgency to Critical/immediate regardless of CVSS.
  A CVSS 7.0 with EPSS 0.95 + KEV listing is more urgent than CVSS 9.0 with EPSS 0.001.

  Severity → response timeline: Critical (9.0-10.0) = immediate, High (7.0-8.9) = 7 days, Medium (4.0-6.9) = 30 days, Low (0.1-3.9) = 90 days.

  Scan using 4-bucket classification — ensure each is covered:
  1. Dependencies: known CVEs in third-party packages
  2. Code: injection, auth bypass, data exposure in application code
  3. Containers: image vulnerabilities, misconfigurations (if containerized)
  4. Secrets: hardcoded credentials, API keys, private keys in code or config

  Auth audit checklist:
  - JWT: verify signing algorithm is not "none" or HS256 with weak key; check exp, aud, iss claims are validated; check token storage (memory preferred over localStorage)
  - Cookies: HttpOnly, Secure, SameSite=Strict or Lax; proper domain scoping
  - Password hashing: must use bcrypt, Argon2, or scrypt — flag MD5, SHA-1, SHA-256 without salt

  Misconfiguration scan categories: Cloud Storage (public buckets, unencrypted), Network (0.0.0.0/0 on sensitive ports, missing VPC flow logs), Identity (IAM wildcards, missing MFA), Database (public access, default ports, missing encryption at rest), App Config (debug mode in prod, default credentials), API (keys in config, wildcard CORS, missing rate limiting), Web Server (directory listing, server tokens, missing security headers, weak TLS).

  For Rust targets specifically:
  - Run cargo audit for RustSec advisory database
  - Run cargo clippy -- -W clippy::unwrap_used to flag panic-prone code in server paths
  - Run cargo deny check for license and advisory policy violations
  - Run cargo-geiger to measure unsafe code surface area

  OWASP Top 10:2025 — use the 2025 version (not 2021): A03 is now "Supply Chain Failures", A10 is "Exceptional Conditions". Assess compliance against all 10 categories.

  REFERENCE FILES — fetch and read these for detailed methodology before starting analysis:
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/scoring-frameworks.md
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/rust-security.md
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/remediation-patterns.md

  Perform a structured security audit of this vulnerability:

  **Target:** [URL/System]
  **Vulnerability:** [Type and description]
  **Current Security Posture:** [Headers/controls present and missing]

  Provide:
  1. CVSS + EPSS + KEV scoring with breakdown (justified by observed evidence)
  2. Attack scenarios specific to this context
  3. OWASP Top 10:2025 compliance assessment
  4. Input validation and injection risk analysis (4-bucket scan results)
  5. Authentication/authorization audit findings (JWT/cookie/hashing checklist)
  6. Sensitive data exposure check
  7. Prioritized remediation roadmap with severity ratings and response timelines

  OUTPUT FORMAT — structure your response using these sections:

  ## Findings
  For each finding:
  - **ID**: SENTINEL-[N]
  - **Title**: One-line summary
  - **Severity**: Critical / High / Medium / Low
  - **CVSS Estimate**: [score] (with justification)
  - **EPSS/KEV**: [EPSS probability if available] / [In KEV: Yes/No/Unknown]
  - **Evidence**: [source: file:line / header / doc URL]
  - **Description**: What was found and why it matters
  - **Recommendation**: Specific remediation action

  ## Risk Assessment
  - Overall severity with justification
  - Exploitability: Low/Medium/High with reasoning
  - Business impact summary

  ## Remediation Recommendations
  - Prioritized list of fixes (highest severity first)
  - For each: effort estimate (Minimal/Moderate/Significant) and verification steps
```

### Agent 2: Threat Modeling Expert
```
subagent_type: security-scanning:threat-modeling-expert
prompt: |
  EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason. Findings without citations will be discarded during synthesis.

  METHODOLOGY:

  STRIDE-per-interaction analysis: For each data flow in the system, identify the source and target element types (external entity, process, data store), then apply only the STRIDE categories relevant to that interaction:
  - External entity → Process: Spoofing, Tampering, Repudiation, Denial of Service
  - Process → Data store: Tampering, Information Disclosure, Denial of Service
  - Process → Process: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
  - Data store → Process: Tampering, Information Disclosure
  Do NOT apply all 6 STRIDE categories to every component — use the interaction-specific mapping above.

  Attack trees: Build attack trees with quantifiable attributes on each node:
  - Difficulty: Low/Medium/High (attacker skill required)
  - Cost: Low/Medium/High (resources needed)
  - Detection risk: Low/Medium/High (likelihood of detection during attack)
  - Time: Hours/Days/Weeks (estimated attack duration)
  Identify three paths through each tree: the easiest path (lowest difficulty), the cheapest path (lowest cost), and the stealthiest path (lowest detection risk). These inform prioritization.

  Defense-in-depth layers — ensure threat coverage spans:
  1. Application layer (input validation, auth, session management)
  2. Infrastructure layer (network segmentation, firewalls, encryption in transit)
  3. CI/CD layer (supply chain integrity, secrets management, deployment controls)
  Flag any layer with no identified controls as a gap.

  Risk calibration with empirical frequency data:
  - SQL injection: ~35% of findings in typical security scans
  - Exposed secrets: ~28%
  - Vulnerable dependencies: ~25%
  - Missing authentication: ~18%
  - XSS: ~15%
  Use these to weight likelihood in risk calculations.

  For each identified threat, map to a specific mitigation control and note applicable compliance references (e.g., "PCI-DSS 6.5.1", "NIST SP 800-53 AC-3", "OWASP ASVS 5.2.1").

  REFERENCE FILES — fetch and read these for detailed methodology before starting analysis:
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/threat-modeling-methodology.md
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/compliance-frameworks.md

  Create threat model for this vulnerability:

  **Target:** [URL/System]
  **Vulnerability:** [Type and description]
  **Context:** [Technology stack, authentication flow, etc.]

  Provide:
  1. STRIDE-per-interaction analysis (using the interaction-specific mapping above)
  2. Attack tree with quantified attributes (difficulty, cost, detection risk, time) and three priority paths (easiest, cheapest, stealthiest)
  3. Threat actor analysis (who might exploit this, calibrated by empirical frequency data)
  4. Impact assessment (users and business)
  5. Defense-in-depth coverage assessment (application, infrastructure, CI/CD layers — flag gaps)
  6. Risk rating with justification
  7. Recommended mitigations mapped to each identified threat with compliance references

  OUTPUT FORMAT — structure your response using these sections:

  ## Findings
  For each finding:
  - **ID**: THREAT-[N]
  - **Title**: One-line summary
  - **Severity**: Critical / High / Medium / Low
  - **CVSS Estimate**: [score] (with justification)
  - **Evidence**: [source: file:line / header / doc URL]
  - **Description**: What was found and why it matters
  - **Recommendation**: Specific remediation action

  ## Risk Assessment
  - Overall severity with justification
  - Exploitability: Low/Medium/High with reasoning
  - Business impact summary

  ## Remediation Recommendations
  - Prioritized list of fixes (highest severity first)
  - For each: effort estimate (Minimal/Moderate/Significant) and verification steps
```

### Agent 3: Backend Security Coder
```
subagent_type: backend-api-security:backend-security-coder
prompt: |
  EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason. Findings without citations will be discarded during synthesis.

  METHODOLOGY:

  Test-first remediation workflow:
  1. Run existing test suite to establish baseline (what already passes/fails)
  2. Read any failing security-related tests to understand the exact vulnerability: what inputs should be blocked, what behavior is expected
  3. Classify the vulnerability by CWE number (e.g., CWE-78 for command injection)
  4. Implement the minimum fix that makes security tests pass
  5. Verify: re-run tests, confirm the vulnerability is resolved, confirm no regressions

  For Rust targets:
  - Dependencies: run cargo audit against the RustSec advisory database. Fix by updating affected crates or applying patches.
  - Unsafe code: every unsafe block MUST have a // SAFETY: comment explaining why the invariants hold. Prefer rewriting in safe Rust. Use #[deny(unsafe_code)] at crate level where possible. Run cargo-geiger to measure unsafe surface area.
  - Secrets: never hardcode — use std::env::var() or a secrets manager. Flag any string literal matching key/token/password patterns.
  - Input validation: use newtype pattern (e.g., struct ValidatedEmail(String)) to enforce validation at construction. Use serde with #[serde(try_from = "...")] for deserialized input boundaries.
  - Auth flows: use type-state pattern to make invalid states unrepresentable (e.g., UnauthenticatedUser → AuthenticatedUser state machine enforced by the type system).
  - Web frameworks (Axum/Tower): implement security controls as middleware layers — auth extraction, rate limiting, CORS, security headers. Use tower::ServiceBuilder to compose layers.

  CWE mapping for Rust:
  - CWE-78 (OS Command Injection): std::process::Command with unsanitized user input
  - CWE-22 (Path Traversal): std::path::Path/PathBuf with user-controlled segments without canonicalization
  - CWE-94 (Code Injection): unsafe blocks executing arbitrary logic, FFI boundaries
  - CWE-190 (Integer Overflow): arithmetic in release builds (Rust wraps by default in release)
  - CWE-416 (Use After Free): raw pointer dereference in unsafe after the owned value is dropped

  Security headers — implement all of these (adapt to framework middleware):
  - Content-Security-Policy: start with report-only (Content-Security-Policy-Report-Only), then enforce after tuning
  - Strict-Transport-Security: max-age=31536000; includeSubDomains
  - X-Frame-Options: DENY (or SAMEORIGIN if iframing is needed)
  - X-Content-Type-Options: nosniff
  - Referrer-Policy: strict-origin-when-cross-origin
  - SameSite cookies: Strict or Lax

  Common Rust security mistakes to flag:
  - unwrap() or expect() in server request handlers (panics = DoS)
  - Missing validation on serde deserialization boundaries (attacker-controlled JSON/YAML)
  - Raw SQL via format!() instead of parameterized queries (sqlx::query! or diesel)
  - Unchecked integer arithmetic in release builds

  REFERENCE FILES — fetch and read these for detailed methodology before starting analysis:
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/rust-security.md
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/remediation-patterns.md

  Assess the backend security surface for this vulnerability and provide implementation-grade fixes:

  **Target:** [URL/System]
  **Vulnerability:** [Type and description]
  **Technology Stack:** [Framework, hosting]
  **Current Security Posture:** [Headers/controls present and missing]

  Provide:
  1. Backend attack surface analysis (input validation gaps, auth/authz weaknesses, database exposure) — classify each by CWE
  2. Framework-specific remediation code (Rust/Axum/Tower preferred; also Next.js, Rails, Django as applicable)
  3. Security headers and cookie configuration to add
  4. CSRF/SSRF prevention measures if applicable
  5. Testing strategy to verify each fix (how to confirm the vulnerability is resolved and no regressions introduced)
  6. Edge cases and deployment gotchas for this stack

  OUTPUT FORMAT — structure your response using these sections:

  ## Findings
  For each finding:
  - **ID**: BACKEND-[N]
  - **Title**: One-line summary
  - **Severity**: Critical / High / Medium / Low
  - **CVSS Estimate**: [score] (with justification)
  - **Evidence**: [source: file:line / header / doc URL]
  - **Description**: What was found and why it matters
  - **Recommendation**: Specific remediation action

  ## Risk Assessment
  - Overall severity with justification
  - Exploitability: Low/Medium/High with reasoning
  - Business impact summary

  ## Remediation Recommendations
  - Prioritized list of fixes (highest severity first)
  - For each: effort estimate (Minimal/Moderate/Significant) and verification steps
```

### Agent 4: Comprehensive Security Reviewer
```
subagent_type: comprehensive-review:security-auditor
prompt: |
  EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason. Findings without citations will be discarded during synthesis.

  METHODOLOGY:

  Vulnerability prioritization — use this formula to rank findings:
  Priority Score = (CVSS * 0.4) + (exploitability * 2.0) + (fix_available * 1.0)
  Where: CVSS = base score (0-10), exploitability = 0 (no known exploit) / 1 (PoC exists) / 2 (active exploitation), fix_available = 0 (no fix) / 1 (fix available). Higher score = more urgent.

  Business impact context:
  - Average data breach cost: $4.88M (IBM 2024 Cost of a Data Breach Report)
  - SOC 2 compliance enables $100K+ enterprise deals
  - FedRAMP compliance enables $1M+ government contracts
  Use these to frame urgency in business terms, not just technical severity.

  For Rust dependency supply chain analysis:
  1. cargo audit — check against RustSec advisory database
  2. Triage findings by CVSS severity
  3. cargo update for compatible version bumps; manual Cargo.toml edits for breaking changes
  4. cargo test — verify no regressions
  5. Re-run cargo audit to confirm resolution
  Also available: cargo deny (license + advisory policy), cargo-vet (supply chain vetting), cargo-crev (code review trust network), cargo outdated (version freshness)

  Compliance references — cite specific section numbers, not just framework names:
  - PCI-DSS: e.g., "Requirement 6.5.1 (injection flaws)"
  - HIPAA: e.g., "§164.312(a)(1) (access control)"
  - GDPR: e.g., "Article 32 (security of processing)"
  - SOC 2: reference Trust Service Criteria CC1-CC9
  - NIST CSF: e.g., "PR.DS-1 (data at rest protection)"
  - OWASP ASVS: e.g., "V5.2.1 (output encoding)"

  Security metrics to include in assessment:
  - Vulnerability Density: issues per 1000 lines of code
  - Mean Time to Remediate: average fix time by severity
  - Compliance Score: % compliance across applicable frameworks
  - Security Debt: count of accumulated unfixed issues

  Incident response awareness — if the vulnerability is actively exploited or high-risk:
  Recommend the response sequence: Detect → Contain (isolate affected systems) → Investigate (determine scope and access) → Remediate (apply fixes) → Recover (restore from clean state) → Learn (post-mortem, update controls)

  REFERENCE FILES — fetch and read these for detailed methodology before starting analysis:
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/compliance-frameworks.md
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/scoring-frameworks.md
  - https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/rust-security.md

  Provide comprehensive security review:

  **Vulnerability Report:** [Summary]
  **Target:** [URL/System]
  **Current Posture:** [What's present vs missing]

  Address:
  1. Is this report legitimate or false positive?
  2. Real-world exploitability given modern protections
  3. CVSS score estimate with breakdown + Priority Score using the formula above
  4. Urgency assessment with business impact context (breach cost, compliance implications)
  5. Supply chain and dependency dimension (if applicable — cargo audit findings, compromised packages, transitive risks)
  6. Compliance impact with specific section references (PCI-DSS, SOC 2, GDPR, etc.)
  7. Additional vulnerabilities suggested by findings
  8. Complete security header recommendations
  9. Related attack vectors to investigate

  OUTPUT FORMAT — structure your response using these sections:

  ## Findings
  For each finding:
  - **ID**: REVIEW-[N]
  - **Title**: One-line summary
  - **Severity**: Critical / High / Medium / Low
  - **CVSS Estimate**: [score] (with justification)
  - **Priority Score**: [score using formula]
  - **Evidence**: [source: file:line / header / doc URL]
  - **Description**: What was found and why it matters
  - **Recommendation**: Specific remediation action

  ## Risk Assessment
  - Overall severity with justification
  - Exploitability: Low/Medium/High with reasoning
  - Business impact summary

  ## Remediation Recommendations
  - Prioritized list of fixes (highest severity first)
  - For each: effort estimate (Minimal/Moderate/Significant) and verification steps
```

### Agent 5: Codex 5.3 (OpenAI)

Run via the `/codex` skill. Use `gpt-5.3-codex`, reasoning effort `high`, sandbox `read-only`:

```bash
echo "EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it NOT VERIFIED with the reason. Findings without citations will be discarded during synthesis.

Analyze this vulnerability and provide an independent security assessment:

**Target:** [URL/System]
**Vulnerability:** [Type and description]
**Current Security Posture:** [Headers/controls present and missing]
**Technology Stack:** [Framework, hosting]

Provide:
1. Independent severity assessment with CVSS estimate
2. Attack scenarios and real-world exploitability
3. Framework-specific fix recommendations with code
4. Testing/verification strategy (how to confirm the vulnerability exists AND how to confirm a fix resolves it)
5. Additional security concerns or related vulnerabilities
6. Compliance implications (OWASP, SOC2, PCI-DSS)

OUTPUT FORMAT — structure your response using these sections:

## Findings
For each finding:
- ID: CODEX-[N]
- Title: One-line summary
- Severity: Critical / High / Medium / Low
- CVSS Estimate: [score] (with justification)
- Evidence: [source: file:line / header / doc URL]
- Description: What was found and why it matters
- Recommendation: Specific remediation action

## Risk Assessment
- Overall severity with justification
- Exploitability: Low/Medium/High with reasoning
- Business impact summary

## Remediation Recommendations
- Prioritized list of fixes (highest severity first)
- For each: effort estimate (Minimal/Moderate/Significant) and verification steps" | codex exec --skip-git-repo-check -m gpt-5.3-codex --config model_reasoning_effort="high" --sandbox read-only 2>/dev/null
```

## Step 3: Synthesize Agent Findings

After all agents return, create consolidated summary. **Apply the Evidence-Only Policy during synthesis**: discard any agent finding that lacks a specific citation (file path, header, documentation URL). If agents disagree, note the disagreement and the evidence each side cites — do not resolve conflicts by guessing.

Collate findings by their standardized IDs (SENTINEL-N, THREAT-N, BACKEND-N, REVIEW-N, CODEX-N). Cross-reference matching findings across agents to build consensus.

**Orchestrator reference files** — fetch these for synthesis methodology:
- https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/scoring-frameworks.md
- https://raw.githubusercontent.com/swannysec/robot-tools/main/security-toolkit/skills/security-vuln-analyzer/references/compliance-frameworks.md

### Consensus Assessment Table
| Aspect | Agent Consensus |
|--------|-----------------|
| Vulnerability Valid? | [Yes/No + confidence across agents] |
| CVSS Score | [Score + range from agents — Sentinel, Reviewer, Codex] |
| EPSS Score | [Probability from Sentinel, if CVE available] |
| KEV Listed? | [Yes/No from Sentinel check] |
| Priority Score | [Formula result from Reviewer: (CVSS*0.4)+(exploitability*2.0)+(fix_available*1.0)] |
| Urgency | [Timeline recommendation — use severity→timeline mapping] |
| Fix Complexity | [Low/Medium/High — from Backend Coder effort estimates] |
| Supply Chain | [Clean / Affected — from Reviewer cargo audit findings] |

### Key Findings by Agent
Summarize unique insights from each agent using their finding IDs:
- **Security Sentinel (SENTINEL-N)**: OWASP 2025 compliance, EPSS+KEV+CVSS scoring, 4-bucket scan results, auth audit
- **Threat Modeling (THREAT-N)**: STRIDE-per-interaction analysis, attack trees with quantified paths (easiest/cheapest/stealthiest), defense-in-depth coverage gaps, threat-to-control mapping
- **Backend Security (BACKEND-N)**: CWE-classified findings, Rust-specific remediation (cargo/unsafe/type-state), test-first verification, framework middleware code
- **Comprehensive Review (REVIEW-N)**: Legitimacy assessment, supply chain (cargo audit), prioritization formula scores, compliance section references, business impact
- **Codex 5.3 (CODEX-N)**: Independent cross-model assessment, fix recommendations, verification strategy

### Attack Tree Summary
Merge Agent 2's attack trees into a consolidated view:
```
Easiest path:  [Node chain with difficulty ratings]
Cheapest path: [Node chain with cost ratings]
Stealthiest:   [Node chain with detection risk ratings]
```
Note which paths are blocked by recommended mitigations and which remain open.

### Consolidated Fix Recommendation
Merge agent recommendations into single implementation. Prioritize by Priority Score (highest first):
```
[Framework-specific code example — Rust/Axum preferred]
```

### Compliance Impact Matrix
| Finding ID | PCI-DSS | SOC 2 | HIPAA | GDPR | NIST CSF | OWASP ASVS |
|-----------|---------|-------|-------|------|----------|------------|
| [ID] | [Section ref or N/A] | [CC ref or N/A] | [Section ref or N/A] | [Article ref or N/A] | [Function ref or N/A] | [Chapter ref or N/A] |

### Rust Toolchain Verification
If the target is a Rust codebase, include these post-fix verification commands:
```bash
cargo audit              # Verify no remaining RustSec advisories
cargo deny check         # Verify license and advisory policy compliance
cargo clippy -- -W clippy::unwrap_used -W clippy::indexing_slicing  # Lint for security patterns
cargo-geiger             # Measure unsafe code surface area
cargo test               # Verify no regressions
```

### Risk Summary Box
```
┌─────────────────────────────────────────────────────────────┐
│  [VULNERABILITY NAME] - [Target]                            │
├─────────────────────────────────────────────────────────────┤
│  Severity:        [Rating] (CVSS [Score])                   │
│  EPSS:            [Probability] ([Low/Medium/High])         │
│  KEV:             [Listed / Not Listed]                     │
│  Priority Score:  [Score from formula]                      │
│  Exploitability:  [Low/Medium/High] ([reason])              │
│  Fix Effort:      [Minimal/Moderate/Significant]            │
│  Timeline:        [Recommended fix window]                  │
│  Supply Chain:    [Clean / Affected]                        │
│  Compliance:      [Affected standards with section refs]    │
└─────────────────────────────────────────────────────────────┘
```

## Common Vulnerability Patterns

### Web Application Vulnerabilities
| Vulnerability | Key Headers/Controls | Primary Agent Focus |
|--------------|---------------------|---------------------|
| Clickjacking | X-Frame-Options, CSP frame-ancestors | All agents |
| XSS | CSP script-src, X-Content-Type-Options | Security Sentinel |
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
- [ ] All 5 agents launched in parallel (single message)
- [ ] All agents used standardized output format (SENTINEL/THREAT/BACKEND/REVIEW/CODEX prefixed IDs)
- [ ] CVSS score provided with breakdown (from 3+ agents)
- [ ] EPSS/KEV scoring considered (not CVSS alone)
- [ ] Priority Score calculated using formula
- [ ] Attack trees include quantified path analysis (easiest/cheapest/stealthiest)
- [ ] Framework-specific fix code included (Rust/Axum preferred)
- [ ] Testing/verification steps provided (both vulnerability reproduction and fix confirmation)
- [ ] Urgency/timeline recommendation uses severity→timeline mapping
- [ ] Compliance impact matrix with specific section numbers (not just framework names)
- [ ] Rust-specific toolchain verification included (if applicable)
- [ ] Supply chain dimension assessed (cargo audit / dependency analysis)
- [ ] Every finding cites specific evidence (file:line, header, or doc URL)
- [ ] Unverified claims marked "NOT VERIFIED" with reason
- [ ] Agent disagreements noted with evidence from each side
