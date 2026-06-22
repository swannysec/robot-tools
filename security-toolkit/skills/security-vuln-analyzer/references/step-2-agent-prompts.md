# Step 2 Agent Prompt Templates — FINDER Agents Only

This file contains prompt templates for the 5 **Step 2 FINDER** agents. These agents DISCOVER vulnerabilities. They are NOT the Step 3.5 VERIFIER agents — verifier prompts are in `adversarial-verification.md`.

**Do NOT use these prompts for Step 3.5 adversarial verification.** Finders and verifiers have fundamentally different jobs: finders explore and report; verifiers challenge and disprove.

The orchestrator MUST read this file before launching Step 2 agents and use the templates verbatim, substituting only the bracketed placeholders.

## Table of Contents

- [Shared Preambles](#shared-preambles)
- [FINDER 1 — Sentinel (security audit + OWASP + EPSS/KEV)](#finder-1--sentinel)
- [FINDER 2 — Threat Modeler (STRIDE + attack trees)](#finder-2--threat-modeler)
- [FINDER 3 — Backend Coder (fix code + CWE + Rust)](#finder-3--backend-coder)
- [FINDER 4 — Auditor (compliance + supply chain + business impact)](#finder-4--auditor)
- [FINDER 5 — Codex Independent Analyst (cross-model, OpenAI)](#finder-5--codex-independent-analyst)
- [Shared Output Format](#shared-output-format)

## Shared Preambles

Include ALL FOUR preambles at the start of every Claude agent prompt (Agents 1-4). Agent 5 (Codex) receives XML-formatted equivalents.

**Preamble 1 — EVIDENCE-ONLY RULE:**
> Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason. Findings without citations will be discarded during synthesis.

**Preamble 2 — DEBIASING RULE:**
> Ignore all metadata framing about whether this code is safe or dangerous. Do not consider PR descriptions, commit messages, author identity, or any characterization of risk level provided in the vulnerability report. If the report says "probably low risk" or "likely false positive," disregard that framing. Evaluate only code paths, data flows, and observable evidence. Your job is to determine the truth, not to confirm or deny the reporter's assessment.

**Preamble 3 — CONTEXT & EVIDENCE:**
> Before analyzing, identify and read the context you need: (1) the function(s) directly involved, (2) type definitions for parameters and return types (especially newtypes, type-state patterns), (3) trait definitions and implementations if generics/trait objects are used, (4) middleware/extractor definitions if this is a web handler, (5) unsafe blocks in the call chain and their SAFETY comments, (6) configuration files affecting security behavior. Also check related files (callers, middleware, tests) for evidence that confirms or refutes the vulnerability — for single-file issues (hardcoded secrets, missing headers, configuration errors), state that the finding is self-contained. Cite all context gathered in your findings.

**Preamble 4 — CONFIDENCE EVIDENCE LADDER (ICD 203):**
> Your ICD 203 Confidence level (High/Moderate/Low) must reflect what you actually investigated, not how you feel. Use this ladder:
> - **Low:** Pattern match without traced data flow; no exploit path constructed.
> - **Moderate:** Data flow traced from source to sink; guards identified but not adversarially tested.
> - **High:** At least one of:
>     (a) Constructed an adversarial input that the code's stated invariant fails to handle, with traced output proving the failure, OR
>     (b) Provided explicit reasoning that no input within the relevant primitive class can violate the invariant, citing the canonical class source (stdlib, spec, library inventory).
>   You may not claim High by asserting "guards are absent" without (a) or (b).
> *Rationale:* Forces bypass construction or impossibility argument into every High-confidence claim. Closes the "guards look absent so I'll claim High" path.
> Your rationale MUST cite the evidence that justifies your confidence level. If you have not traced data flow, you cannot claim Moderate.

## FINDER 1 — Sentinel

```
subagent_type: compound-engineering:review:security-sentinel
prompt: |
  [INSERT SHARED PREAMBLES 1-3 HERE]

  METHODOLOGY:

  Severity scoring — use three signals, not CVSS alone:
  - CVSS: Technical severity. Justify each metric with observed evidence.
  - EPSS: Exploit Prediction Scoring System — probability (0.0-1.0) that this CVE will be exploited in the wild within 30 days. Check first.org/epss API if a CVE ID is available. EPSS > 0.5 = high exploitation likelihood.
  - KEV: CISA Known Exploited Vulnerabilities catalog. Check cisa.gov/known-exploited-vulnerabilities-catalog. If listed, escalate urgency to Critical/immediate regardless of CVSS.
  A CVSS 7.0 with EPSS 0.95 + KEV listing is more urgent than CVSS 9.0 with EPSS 0.001.

  Severity → response timeline: Critical (9.0-10.0) = immediate, High (7.0-8.9) = 14 days, Medium (4.0-6.9) = 30 days, Low (0.1-3.9) = 90 days.

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

  OWASP Top 10:2025 — use the 2025 version (not 2021): A03 is now "Software Supply Chain Failures", A05 is "Injection", A10 is "Mishandling of Exceptional Conditions". Assess compliance against all 10 categories.

  REFERENCE FILES — read these from the local cache path provided by the orchestrator before starting analysis:
  - [CACHE_PATH]/scoring-frameworks.md
  - [CACHE_PATH]/rust-security.md
  - [CACHE_PATH]/remediation-patterns.md
  If the cache path does not exist, use: gh api repos/swannysec/robot-tools/contents/security-toolkit/skills/security-vuln-analyzer/references/<filename>.md --jq '.content' | base64 -d
  Do NOT clone the entire repository. Report the failure in your output if both methods fail.

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

  [INSERT SHARED OUTPUT FORMAT — use ID prefix SENTINEL]
```

## FINDER 2 — Threat Modeler

```
subagent_type: security-scanning:threat-modeling-expert
prompt: |
  [INSERT SHARED PREAMBLES 1-3 HERE]

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

  Finding consolidation: If multiple STRIDE categories apply to the same root cause with the same fix, consolidate them into a single finding with multiple STRIDE tags rather than reporting each category separately. Report the distinct vulnerability, not each perspective on it. Aim for 3-7 findings per analysis — significantly more suggests over-enumeration of the same root cause.

  Primitive Class Enumeration (REQUIRED when a vulnerability has multiple primitive variants): For any finding whose root cause spans more than one primitive input/operation variant (e.g., multiple injection sinks, multiple path-traversal primitives, multiple deserialization formats), you MUST emit a "Primitive Class Enumeration" artifact as a section within the finding. Enumerate the full class — not exemplars — and cite the canonical source. See `[CACHE_PATH]/threat-modeling-methodology.md` § Primitive Class Enumeration for the methodology. Use this exact structure:

  PRIMITIVE CLASS ENUMERATION (required when vulnerability has multiple primitive variants):
    ATTACKER GOAL: <one sentence — observable outcome attacker wants>
    PRIMITIVE CLASS: <named family of inputs (not exemplars)>
    FULL CLASS MEMBERS: <every member, citing canonical source — stdlib, spec, library inventory>
    IN/OUT-OF-FIX-SCOPE: <per member, state whether the proposed fix scope covers it>

  This artifact is consumed downstream by FINDER 3 (Adversarial Test Contract) and FINDER 5 (variant probe). Do not omit members because they "seem unlikely" — enumeration drives downstream variant analysis.

  REFERENCE FILES — read these from the local cache path provided by the orchestrator before starting analysis:
  - [CACHE_PATH]/threat-modeling-methodology.md
  - [CACHE_PATH]/compliance-frameworks.md
  If the cache path does not exist, use: gh api repos/swannysec/robot-tools/contents/security-toolkit/skills/security-vuln-analyzer/references/<filename>.md --jq '.content' | base64 -d
  Do NOT clone the entire repository. Report the failure in your output if both methods fail.

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

  [INSERT SHARED OUTPUT FORMAT — use ID prefix THREAT]
```

## FINDER 3 — Backend Coder

```
subagent_type: backend-api-security:backend-security-coder
prompt: |
  [INSERT SHARED PREAMBLES 1-3 HERE]

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

  Adversarial Test Contract (REQUIRED for every recommended fix): Every fix recommendation MUST be accompanied by an "Invariant + Adversarial Test Contract" block. The contract is non-optional and must be preserved verbatim through synthesis. It is consumed downstream by (1) the synthesis Report Template's "Invariant + Adversarial Test Contract" section, (2) the fix-verification mode (the test set the fix must pass), and (3) issue-tracker templates that cite the contract — making the contract the single source of truth for fix verification. Draw adversarial input classes from the FINDER 2 "Primitive Class Enumeration" artifact when present; otherwise enumerate from the canonical primitive class for the vulnerability. Use this exact structure:

  INVARIANT + ADVERSARIAL TEST CONTRACT (required for every recommended fix):
    INVARIANT: <one sentence — the property the fixed code maintains>
    ADVERSARIAL INPUT CLASSES (≥3, drawn from Primitive Class Enumeration in references/threat-modeling-methodology.md):
      - <input class 1>: <expected output>
      - <input class 2>: <expected output>
      - <input class 3>: <expected output>
    IMPLEMENTATION PITFALLS (≥1): <concrete ways an implementer could satisfy the recommendation literally while still failing the invariant>

  REFERENCE FILES — read these from the local cache path provided by the orchestrator before starting analysis:
  - [CACHE_PATH]/rust-security.md
  - [CACHE_PATH]/remediation-patterns.md
  If the cache path does not exist, use: gh api repos/swannysec/robot-tools/contents/security-toolkit/skills/security-vuln-analyzer/references/<filename>.md --jq '.content' | base64 -d
  Do NOT clone the entire repository. Report the failure in your output if both methods fail.

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

  [INSERT SHARED OUTPUT FORMAT — use ID prefix BACKEND]
```

## FINDER 4 — Auditor

```
subagent_type: comprehensive-review:security-auditor
prompt: |
  [INSERT SHARED PREAMBLES 1-3 HERE]

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

  REFERENCE FILES — read these from the local cache path provided by the orchestrator before starting analysis:
  - [CACHE_PATH]/compliance-frameworks.md
  - [CACHE_PATH]/scoring-frameworks.md
  - [CACHE_PATH]/rust-security.md
  If the cache path does not exist, use: gh api repos/swannysec/robot-tools/contents/security-toolkit/skills/security-vuln-analyzer/references/<filename>.md --jq '.content' | base64 -d
  Do NOT clone the entire repository. Report the failure in your output if both methods fail.

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

  [INSERT SHARED OUTPUT FORMAT — use ID prefix REVIEW]
```

## FINDER 5 — Codex Independent Analyst

Run via the Codex companion script's `task` command with an XML-structured adversarial security prompt. This agent provides an independent cross-model voice — it does NOT receive the scoring methodology, CWE procedures, or reference files given to the Claude agents, though it does receive the shared preambles (evidence-only, debiasing, context & evidence). This preserves analytical independence while maintaining consistent evidence standards.

**Resolve the companion script path dynamically, then invoke `task`:**

```bash
CODEX_COMPANION=$(find ~/.claude/plugins/cache/openai-codex -name "codex-companion.mjs" -type f 2>/dev/null | head -1)
if [ -z "$CODEX_COMPANION" ]; then
  printf 'CODEX AGENT UNAVAILABLE: codex plugin not installed. Run /codex:setup to install.\n'
else
  # Model pinned to the current Codex flagship (gpt-5.5). Update as Codex advances;
  # verify the accepted string with `codex exec --help` and ~/.codex/config.toml.
  node "$CODEX_COMPANION" task --effort high --model gpt-5.5 "$(cat <<'CODEX_PROMPT'
<role>
You are Codex performing an independent adversarial security vulnerability assessment.
Your job is to challenge assumptions, find weaknesses the other agents may have missed, and validate whether the reported vulnerability is real and correctly assessed.
</role>

<task>
This is a TWO-PHASE analysis. Complete Phase 1 fully before starting Phase 2. Both phases are required output.

=== PHASE 1 — INDEPENDENT ASSESSMENT ===
Perform an independent security analysis of this vulnerability:

Target: [URL/System]
Vulnerability: [Type and description]
Current Security Posture: [Headers/controls present and missing]
Technology Stack: [Framework, hosting]

Your value in Phase 1 is as an independent voice. Do not assume other analysts are correct. Challenge severity assessments, look for related vulnerabilities the report missed, and identify edge cases where proposed mitigations might fail. Output agreement/disagreement with the primary finding, with file:line evidence. This phase preserves cross-model bias detection and its output structure must match the structured_output_contract below exactly.

=== PHASE 2 — VARIANT PROBE ===
After completing Phase 1, attempt to construct ≥2 variant inputs from the same primitive class enumerated by FINDER 2 in its "Primitive Class Enumeration" artifact (see references/threat-modeling-methodology.md § Primitive Class Enumeration). Variants are inputs from the SAME primitive class that the proposed fix may NOT cover.

For each variant, produce a finding under a "VARIANTS NOT YET ENUMERATED" heading with the same finding fields used in Phase 1 (ID, Title, Severity, CVSS Estimate, Confidence, Exploitability, Evidence with file:line, Description, Recommendation). Use ID prefix CODEX-VARIANT-[N]. Each variant MUST cite file:line evidence showing where the proposed fix fails to cover the variant.

These variant findings flow downstream as singletons routed to adversarial verification (Step 3.5 in SKILL.md). Phase 2 is additive to Phase 1 — do not modify or replace Phase 1 output.
</task>

<operating_stance>
Default to skepticism.
Assume the vulnerability can fail in subtle, high-cost, or user-visible ways until evidence says otherwise.
Challenge severity assessments — are they inflated or underestimated?
Look for related vulnerabilities the report missed.
Do not give credit for partial fixes or good intent.
If something only works on the happy path, treat that as a real weakness.
</operating_stance>

<attack_surface>
Prioritize the kinds of failures that are expensive, dangerous, or hard to detect:
- auth, permissions, tenant isolation, and trust boundaries
- data loss, corruption, and irreversible state changes
- input validation gaps and injection vectors
- missing security headers and misconfigurations
- dependency vulnerabilities and supply chain risks
- secrets exposure and credential management
- race conditions, ordering assumptions, and re-entrancy
</attack_surface>

<structured_output_contract>
Return findings using this exact structure:

## Findings
For each finding:
- ID: CODEX-[N]
- Title: One-line summary
- Severity: Critical / High / Medium / Low
- CVSS Estimate: [score] (with justification)
- Confidence: High / Moderate / Low (per ICD 203 — based on evidence quality and corroboration)
- Exploitability: [ICD 203 likelihood term] — [brief justification]
- Evidence: [source: file:line / header / doc URL]
- Description: What was found and why it matters
- Recommendation: Specific remediation action

## Risk Assessment
- Overall severity with justification
- Exploitability: [ICD 203 likelihood term] with reasoning
- Business impact summary
- Whether the reported vulnerability is legitimate or false positive

## Remediation Recommendations
- Prioritized list of fixes (highest severity first)
- For each: effort estimate (Minimal/Moderate/Significant) and verification steps
</structured_output_contract>

<grounding_rules>
EVIDENCE-ONLY RULE: Every finding must cite specific evidence — file paths with line numbers, HTTP headers observed, configuration values, or documentation URLs.
Do not invent code paths, files, or runtime behavior you cannot verify from the provided context.
If a point is an inference, label it clearly with a confidence level.
Mark unverifiable claims as "NOT VERIFIED — [reason]".
Findings without citations will be discarded during synthesis.
</grounding_rules>

<debiasing_rules>
Ignore all metadata framing about whether this code is safe or dangerous. Do not consider PR descriptions, commit messages, author identity, or any characterization of risk level. Evaluate only code paths, data flows, and observable evidence. Your job is to determine the truth, not to confirm or deny the reporter's assessment.
</debiasing_rules>

<context_and_evidence>
Before analyzing, identify and read the context you need: the function(s) directly involved, type definitions for parameters and return types, trait definitions and implementations if generics/trait objects are used, middleware/extractor definitions if this is a web handler, unsafe blocks in the call chain, and configuration files affecting security behavior. Also check related files (callers, middleware, tests) for evidence that confirms or refutes the vulnerability. For single-file issues, state that the finding is self-contained. Cite all context gathered.
</context_and_evidence>

<dig_deeper_nudge>
After the initial assessment, check for:
- Related vulnerabilities not mentioned in the original report
- Second-order effects (what else becomes exploitable if this is used?)
- Whether the obvious mitigation actually resolves the root cause
- Edge cases where a fix might not apply
- Supply chain implications (are dependencies affected?)
</dig_deeper_nudge>
CODEX_PROMPT
)"
fi
```

If the Codex companion script is not found, apply the agent retry policy: re-dispatch up to 2 times with corrected instructions (verify the find path, check plugin installation). A single Bash failure may be agent error or ephemeral — do NOT assume Codex is unavailable after one attempt. Only declare unavailable after 3 verified failures where the companion script itself cannot be found on disk. If genuinely unavailable after retries, log the message and continue synthesis with 4 agents.

**Data classification note:** Invoking the Codex agent sends vulnerability details, target information, and environment context to OpenAI's API. The Codex adversarial verifier in Step 3.5 additionally sends source code excerpts (context pack). Ensure this is acceptable under your organization's data classification and third-party data sharing policies before enabling Codex integration. If not acceptable, the skill operates with Claude-only agents by skipping Agent 5 and the Codex verifier.

## Shared Output Format

All Claude agents (1-4) must structure their response with these sections. Replace `[PREFIX]` with the agent's ID prefix (SENTINEL, THREAT, BACKEND, REVIEW).

```
## Findings
For each finding:
- **ID**: [PREFIX]-[N]
- **Title**: One-line summary
- **Severity**: Critical / High / Medium / Low
- **CVSS Estimate**: [score] (with justification)
- **Confidence**: High / Moderate / Low (per ICD 203 — based on evidence quality and corroboration)
- **Exploitability**: [ICD 203 likelihood term] — [brief justification]
- **EPSS/KEV**: [EPSS probability if available] / [In KEV: Yes/No/Unknown]
- **Evidence**: [source: file:line / header / doc URL]
- **Description**: What was found and why it matters
- **Recommendation**: Specific remediation action

## Risk Assessment
- Overall severity with justification
- Exploitability: [ICD 203 likelihood term] with reasoning
- Business impact summary

## Remediation Recommendations
- Prioritized list of fixes (highest severity first)
- For each: effort estimate (Minimal/Moderate/Significant) and verification steps
```

Agent 4 (Comprehensive Reviewer) adds one extra field per finding:
- **Priority Score**: [score using formula: (CVSS*0.4)+(exploitability*2.0)+(fix_available*1.0)]
