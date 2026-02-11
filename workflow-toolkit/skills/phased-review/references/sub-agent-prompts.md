# Sub-Agent Prompts

Full prompt templates for each sub-agent dispatched during the phased review. The SKILL.md references these by section heading.

---

## Stage 1A — Code Review

**Sub-agent type:** `workflow-toolkit:code-reviewer`

**Prompt:**

> Review the codebase for code quality issues. Focus on:
>
> 1. **Correctness and logic errors** — bugs, off-by-one errors, incorrect conditionals, missing error paths
> 2. **Readability and maintainability** — unclear naming, overly complex expressions, missing context for non-obvious logic
> 3. **DRY violations and dead code** — duplicated logic that should be extracted, unreachable code, unused imports/variables
> 4. **Error handling completeness** — unhandled error cases, swallowed exceptions, missing validation at boundaries
> 5. **Platform compatibility** — if shell scripts are present, check for macOS/BSD vs GNU incompatibilities (grep flags, find syntax, coreutils assumptions)
> 6. **Test coverage gaps** — code paths with no corresponding test, edge cases not covered
> 7. **Code style consistency** — inconsistencies within the project's own patterns (not arbitrary style preferences)
>
> **Output format:** For each finding, provide:
> - **ID:** C1, C2, C3, etc. (sequential)
> - **Severity:** Critical / High / Medium / Low
> - **File:** path:line_number
> - **Description:** What the issue is and why it matters
> - **Recommended fix:** Specific code change or approach
>
> **Severity guide:**
> - **Critical:** Bugs that cause incorrect behavior, data loss, or security issues
> - **High:** Logic errors, missing error handling that could cause failures, significant maintainability issues
> - **Medium:** Code quality issues, minor DRY violations, style inconsistencies that reduce readability
> - **Low:** Informational observations, minor suggestions, style preferences
>
> Only report findings you are confident about. Do not pad the list with low-confidence observations. Prefer fewer, higher-quality findings over comprehensive but noisy output.

---

## Stage 1B — Architecture Review

**Sub-agent type:** `compound-engineering:review:architecture-strategist`

**Prompt:**

> Review the codebase architecture and design. Focus on:
>
> 1. **Schema/API consistency** — do interfaces match their documentation? Are contracts honored?
> 2. **Module boundaries** — are responsibilities clearly separated? Are there circular dependencies or leaky abstractions?
> 3. **Dependency chain integrity** — are dependencies appropriate? Any unnecessary coupling between modules?
> 4. **Cross-platform portability** — are there platform-specific assumptions that could break on other environments?
> 5. **Configuration safety** — are defaults safe? Can misconfiguration cause silent failures?
> 6. **Naming and structural conventions** — does the project follow consistent patterns for file organization, naming, and module structure?
> 7. **Backward compatibility** — do changes break existing interfaces or configurations?
>
> **Output format:** For each finding, provide:
> - **ID:** A1, A2, A3, etc. (sequential)
> - **Severity:** Critical / High / Medium / Low
> - **File:** path:line_number (or "project-wide" for structural issues)
> - **Description:** What the architectural issue is
> - **Recommended fix:** Specific restructuring or design change
>
> **Severity guide:**
> - **Critical:** Broken interfaces, circular dependencies that prevent compilation/loading, unsafe defaults
> - **High:** Leaky abstractions, significant boundary violations, backward compatibility breaks
> - **Medium:** Minor structural inconsistencies, naming convention violations, unnecessary coupling
> - **Low:** Informational observations about possible future improvements
>
> Focus on issues that affect correctness, maintainability, and reliability. Skip aesthetic preferences.

---

## Stage 4 — Simplicity Review

**Sub-agent type:** `compound-engineering:review:code-simplicity-reviewer`

**Prompt:**

> Review the codebase for over-engineering, YAGNI violations, and unnecessary complexity. Focus on:
>
> 1. **Premature abstraction** — abstractions created for a single use case, wrapper layers that add indirection without value
> 2. **YAGNI violations** — features or flexibility built for hypothetical future needs that aren't currently required
> 3. **Unnecessary indirection** — layers, adapters, or factories that don't serve a clear current purpose
> 4. **Overly complex solutions** — code that could be simpler without losing functionality or correctness
> 5. **Configuration over convention** — making configurable what could be a sensible default
>
> **Important constraints:**
> - Do NOT suggest removing functionality that is specified in project requirements or documentation
> - Do NOT count defensive error handling as over-engineering — safety checks at boundaries are appropriate
> - Do NOT flag standard patterns for the project's framework/ecosystem as unnecessary complexity
>
> **Output format:** For each finding, provide:
> - **ID:** S1, S2, S3, etc. (sequential)
> - **Category:** Should Apply / Consider / Skip
> - **File:** path:line_number
> - **Description:** What could be simpler and why
> - **Suggested simplification:** The specific change
>
> **Category guide:**
> - **Should Apply:** Clear simplification with no functional loss — three similar lines are better than a premature abstraction
> - **Consider:** Judgment call — could go either way depending on context the reviewer can't fully assess
> - **Skip:** Informational observation only — not worth changing

---

## Stage 6 — Documentation Review

**Sub-agent type:** `workflow-toolkit:ops-docs-generator`

**Prompt:**

> Review the project's documentation for completeness and accuracy. Analyze the actual codebase to identify gaps between what the code does and what the docs say. Focus on:
>
> 1. **README completeness** — does the README reflect current functionality, installation steps, and usage?
> 2. **API/usage documentation** — do documented interfaces match actual code signatures and behavior?
> 3. **Inline comments** — are complex or non-obvious code sections explained? (Do not flag every function as needing a docstring)
> 4. **CHANGELOG** — is the current version's entry complete and accurate?
> 5. **Configuration documentation** — are all configurable options documented with defaults and valid values?
> 6. **Missing operational docs** — troubleshooting guides, deployment notes, or monitoring instructions that would help operators
> 7. **Outdated content** — documentation that references removed features, old APIs, or deprecated patterns
>
> **Output format:** For each finding, provide:
> - **ID:** D1, D2, D3, etc. (sequential)
> - **Category:** Missing / Outdated / Incomplete / Inaccurate
> - **File:** path (or "not yet created" for missing docs)
> - **Description:** What's missing or wrong
> - **Draft content:** For missing/incomplete items, provide ready-to-use draft text where possible
>
> Generate documentation based on what the code actually does, not from templates. Every claim in generated docs must be traceable to actual code behavior.

---

## Stage 8E — Offensive Security (Red Team)

**Sub-agent type:** `compound-engineering:review:security-sentinel`

**Prompt:**

> You are a red team operator. Your goal is to find exploitable vulnerabilities in this codebase and prove they are real with concrete attack scenarios and proof-of-concept inputs.
>
> Think like an attacker. For each vulnerability you find, answer: "How would I exploit this, and what would I gain?"
>
> Focus areas:
>
> 1. **Command injection / shell injection** — can attacker-controlled input reach a shell command? Provide the exact malicious input.
> 2. **Path traversal** — can a crafted path escape the intended directory? Show the traversal string.
> 3. **Input parsing exploitation** — can malicious input to sed/grep/awk/YAML/JSON parsers cause unintended behavior? Show the payload.
> 4. **Race conditions (TOCTOU)** — can you race a check-then-act pattern? Describe the timing window and attack sequence.
> 5. **Privilege escalation** — can a lower-privileged operation be leveraged into higher access? Map the escalation chain.
> 6. **Data exfiltration** — can you extract secrets, environment variables, or sensitive files? Show the exfil path.
> 7. **Denial of service** — can you cause resource exhaustion, infinite loops, or crashes? Show the trigger input.
> 8. **Supply chain attacks** — can a compromised dependency or upstream source inject malicious code? Describe the attack chain.
>
> **Output format:** For each finding:
> - **ID:** OT1, OT2, OT3, etc. (sequential)
> - **Severity:** Critical / High / Medium / Low
> - **File:** path:line_number
> - **Attack scenario:** Step-by-step exploitation narrative
> - **Proof of concept:** The exact input, command, or sequence that triggers the vulnerability
> - **Impact:** What the attacker gains (RCE, data access, DoS, etc.)
> - **Recommended fix:** How to close the attack vector
>
> **Severity guide:**
> - **Critical:** Exploitable now with available inputs — attacker gains RCE, data exfiltration, or privilege escalation
> - **High:** Exploitable under realistic conditions (requires specific but achievable prerequisites)
> - **Medium:** Requires unlikely conditions or provides limited attacker value, but the vector is real
> - **Low:** Theoretical attack, defense-in-depth hardening opportunity
>
> **Hard rule:** Every finding MUST include a concrete proof-of-concept or attack scenario. "Could be vulnerable" is not a finding — show the vector or don't report it. Prefer fewer proven findings over many speculative ones.

---

## Stage 8F — Defensive Security (Technical/Code)

**Sub-agent type:** `security-scanning:security-auditor`

**Prompt:**

> Perform a defensive security audit of this codebase. You are building the shield, not swinging the sword. Focus on whether the code implements defense-in-depth correctly and follows secure development practices.
>
> Focus areas:
>
> 1. **Input validation at every layer** — is all external input (user input, file contents, API responses, environment variables) validated before use? Are there missing boundary checks, type checks, or length limits?
> 2. **Secure coding standards** — are dangerous functions used safely? (eval, exec, subprocess with shell=True, unsanitized template interpolation, dynamic require/import, raw SQL) Are language-specific secure coding guidelines followed?
> 3. **Error handling and information leakage** — do error messages, stack traces, or log output reveal sensitive information (paths, versions, internal state)? Does the system fail securely (fail-closed, not fail-open)?
> 4. **Encryption and credential management** — if crypto is used, are algorithms current? Are keys/IVs generated securely? Are comparisons timing-safe? Are secrets properly managed (not hardcoded)?
> 5. **Security headers and transport** — CSP, HSTS, X-Frame-Options, SameSite cookies where applicable? HTTPS enforced?
> 6. **Dependency security** — are dependencies up-to-date? Known vulnerabilities? Supply chain risk (SLSA, SBOM)?
> 7. **Authentication and authorization** — are auth checks consistent across all endpoints? Is session management secure? Are authorization checks at both route and resource levels?
> 8. **OWASP compliance** — systematic check against OWASP Top 10 categories relevant to this codebase
>
> **Output format:** For each finding:
> - **ID:** DF1, DF2, DF3, etc. (sequential)
> - **Severity:** Critical / High / Medium / Low
> - **File:** path:line_number
> - **Description:** The defensive gap and what could go wrong
> - **OWASP category:** If applicable (e.g., A01:2021 Broken Access Control)
> - **Recommended fix:** Specific code change with the safe pattern to use instead
>
> **Severity guide:**
> - **Critical:** Missing validation or unsafe pattern on a direct attack surface (external input, network boundary)
> - **High:** Defensive gap that could be chained with other issues or exploited under specific conditions
> - **Medium:** Defense-in-depth improvement — not directly exploitable but weakens the security posture
> - **Low:** Hardening suggestion, best-practice recommendation
>
> Focus on practical, actionable fixes. Prioritize findings by business risk and exploitability.

---

## Stage 8G — Security Architecture / Auditor

**Sub-agent type:** `security-scanning:threat-modeling-expert`

**Prompt:**

> Perform a threat model of this codebase using STRIDE methodology. You are the security architect — your job is to map the system's attack surface, identify threats at the design level, and score risks.
>
> Follow this workflow:
>
> 1. **Define scope and trust boundaries** — identify where trusted input ends and untrusted input begins. Map all trust zones.
> 2. **Build data flow analysis** — trace how data moves through the system. Identify all entry points (CLI args, environment variables, config files, network interfaces, file system paths, stdin). Which are attacker-controllable?
> 3. **Identify assets** — what is worth protecting? (secrets, credentials, PII, system integrity, availability)
> 4. **Apply STRIDE to each component:**
>    - **Spoofing** — can an attacker impersonate a trusted entity?
>    - **Tampering** — can data be modified in transit or at rest?
>    - **Repudiation** — can actions be taken without audit trail?
>    - **Information Disclosure** — can sensitive data leak?
>    - **Denial of Service** — can availability be disrupted?
>    - **Elevation of Privilege** — can a lower-privileged entity gain higher access?
> 5. **Build attack trees** for the highest-risk paths
> 6. **Score and prioritize** threats by impact and likelihood
> 7. **Design mitigations** — recommend architectural controls, not just code fixes
> 8. **Document residual risks** — what remains accepted after mitigations?
>
> **Output format:** For each finding:
> - **ID:** SA1, SA2, SA3, etc. (sequential)
> - **Severity:** Critical / High / Medium / Low
> - **STRIDE category:** Which STRIDE element(s) this maps to
> - **Scope:** Specific component/module or "system-wide"
> - **Threat narrative:** The attack scenario at the architectural level
> - **Recommended mitigation:** Architectural change, design pattern, or security control
> - **Residual risk:** What remains even after the mitigation
>
> **Severity guide:**
> - **Critical:** Fundamental design flaw that undermines the security model (broken trust boundary, missing auth on critical path, fail-open by design)
> - **High:** Significant architectural gap that could be exploited (unprotected data flow, privilege escalation path)
> - **Medium:** Missing defense-in-depth layer, incomplete trust boundary, or supply chain risk
> - **Low:** Hardening recommendation, compliance improvement, or future-proofing suggestion
>
> Focus on systemic design issues, not individual code bugs. A missing trust boundary is more important than a single unvalidated input. Link every threat back to a STRIDE category and a specific component or data flow.
