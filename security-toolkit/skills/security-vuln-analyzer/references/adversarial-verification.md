# Adversarial Verification Reference — VERIFIER Agents Only

Four-gate review checklist, framework security defaults, common LLM verification shortcuts to reject, environment protection categories, and **prompt templates** for Step 3.5 adversarial VERIFIER agents.

**These are VERIFIER agents, NOT FINDER agents.** Finders discover vulnerabilities (Step 2, in `step-2-agent-prompts.md`). Verifiers CHALLENGE findings — their job is to disprove, not confirm. Do not use finder prompts for verifiers or vice versa.

## Table of Contents

- [Four-Gate Review Checklist](#four-gate-review-checklist)
- [Framework Security Defaults](#framework-security-defaults)
- [Common LLM Verification Shortcuts to Reject](#common-llm-verification-shortcuts-to-reject)
- [Environment Protection Categories](#environment-protection-categories)
- [VERIFIER Prompt Templates](#verifier-prompt-templates)

## Four-Gate Review Checklist

Each finding must be challenged through 4 gates. A finding is CONFIRMED only if it passes all applicable gates. If any gate fails, the finding is REFUTED with the failed gate cited.

### Reachability Gate

Is the vulnerable code actually reachable from attacker-controlled input?

| Requirement | Details |
|-------------|---------|
| Trace call chain | Map the full path from external entry point to the vulnerable code |
| Verify no sanitization | Confirm input is not sanitized, validated, or transformed before reaching the sink |
| Check dispatch paths | For Rust: verify trait dispatch or generics mean the vulnerable path is actually invoked at runtime |
| **FAIL criteria** | No path from attacker input to vulnerable code, or input is fully sanitized before reaching it |

### Real Impact Gate

If exploited, what is the actual (not theoretical) damage?

| Requirement | Details |
|-------------|---------|
| Classify impact type | Distinguish RCE, privilege escalation, data disclosure, DoS — each has different real-world impact |
| Assess data sensitivity | Consider the classification and sensitivity of data that could be exposed |
| Evaluate blast radius | Consider blast radius and recovery difficulty |
| **FAIL criteria** | Impact is purely theoretical, or the exploitable state has no meaningful consequence |

### Mitigation Check Gate

Are there existing controls that neutralize this vulnerability?

| Requirement | Details |
|-------------|---------|
| Check framework defaults | See Framework Security Defaults table below |
| Check middleware protections | Review middleware/extractor protections in the request pipeline |
| Check type system constraints | Rust newtypes, type-state patterns, sealed traits |
| Check input validation | Verify validation at trust boundaries |
| **FAIL criteria** | Existing controls already prevent exploitation |

### Environment Check Gate

Do deployment-level protections reduce exploitability?

| Requirement | Details |
|-------------|---------|
| WAF/CDN rules | Check for request filtering at the edge |
| CSP policy | Verify Content-Security-Policy blocks the attack vector |
| Network segmentation | Determine if the endpoint is internet-facing |
| Auth requirements | Check authentication requirements on the affected path |
| Container isolation | Check runtime restrictions and sandboxing |
| **FAIL criteria** | Deployment protections prevent exploitation even if code is vulnerable |

## Framework Security Defaults

Verifiers must check these before claiming a vulnerability is exploitable.

| Framework | Built-in Protections |
|-----------|---------------------|
| **Rust/Axum** | Type-safe extractors reject malformed input, Tower middleware composition for auth/CORS/rate-limiting, ownership system prevents use-after-free in safe code, no null pointers |
| **Rust/Actix** | Guards system for route protection, middleware pipeline, actor model for concurrency isolation, payload size limits |
| **Next.js (14+)** | Automatic HTML escaping in JSX, CSRF tokens in Server Actions, CSP nonce support, API route isolation, built-in image optimization prevents SSRF via domains allowlist |
| **Rails** | CSRF protection on by default (`protect_from_forgery`), parameterized queries via ActiveRecord, Content-Security-Policy middleware, strong parameters |
| **Django** | CSRF middleware enabled by default, ORM prevents SQL injection, template auto-escaping, clickjacking protection (X-Frame-Options middleware), password hashing with PBKDF2 |

## Common LLM Verification Shortcuts to Reject

Adversarial verifiers must NOT accept these reasoning patterns. If a finding's evidence relies on any of these, challenge it.

| Shortcut | Why It Fails | What to Do Instead |
|----------|-------------|-------------------|
| "This pattern looks dangerous" | Pattern does not equal exploitability. Context determines risk. | Trace the actual data flow from input to sink. |
| "Similar code was vulnerable elsewhere" | Different codebase, different context, different mitigations. | Verify THIS code has the same conditions. |
| "No sanitization visible in this file" | Sanitization may be in middleware, callers, or framework defaults. | Check non-target files and framework protections. |
| "This CWE is typically Critical" | Severity depends on context, not CWE classification. | Assess based on observed evidence only. |
| "The function name suggests insecurity" | Naming does not equal behavior. `unsafe_parse()` may have safe invariants. | Read the implementation, check SAFETY comments. |
| "Multiple agents agree" | Consensus from shared training data is not independent confirmation. | Check if agents cited independent evidence or echoed each other. |
| "CVSS base score is X for this type" | Base score ignores environmental and temporal factors. | Use CVSS with environmental metrics, add EPSS/KEV context, and express likelihood using ICD 203 estimative language. |

## Common False-Dismissal Patterns

When REFUTING a finding, do NOT accept these rationalizations without further investigation. Each has a known bypass:

| Dismissal | Why It's Unreliable | What to Check Instead |
|-----------|--------------------|-----------------------|
| "The WAF will catch it" | WAFs are bypassable via encoding, parameter pollution, protocol-level tricks | Test the application logic directly — WAFs are defense-in-depth, not the security boundary |
| "We use parameterized queries" | ORM misuse, stored procedures with dynamic SQL, and second-order injection bypass parameterization | Check for string concatenation in ANY query path, not just the flagged one |
| "The framework handles XSS" | Template engines have raw output modes, JS contexts bypass HTML encoding, DOM XSS is client-side | Verify auto-escaping is active for THIS specific template/context |
| "File uploads are safe because we check the extension" | Null bytes, double extensions, parser discrepancies bypass extension checks | Check the full validation chain: extension + content-type + magic bytes + filename sanitization |
| "We validate on the frontend" | Client-side validation is UX, not security — any HTTP client bypasses it | Check for server-side validation of the same input |
| "It's internal, auth doesn't matter" | Internal apps get compromised via SSRF, lateral movement, and supply chain attacks | Verify network segmentation and authentication requirements |
| "Low severity, not worth flagging" | Low-severity findings chain into critical attack paths | Check for chaining potential (see Vulnerability Chain Patterns below) |

## Vulnerability Chain Patterns

When evaluating the Real Impact Gate, consider whether a finding that appears low-severity individually could chain with other weaknesses into a critical attack path:

| Chain Pattern | Example |
|--------------|---------|
| Information disclosure → credential extraction → system compromise | Config file read exposes DB password → full database access |
| SSRF → internal service access → data exfiltration | SSRF to metadata endpoint → cloud credentials → S3 bucket access |
| Auth weakness → privilege escalation → admin functionality | Weak session management → admin panel access → data modification |
| File upload → code execution → lateral movement | Image upload with PHP payload → RCE → internal network pivot |
| XSS → session hijacking → account takeover | Stored XSS → steal admin cookie → full account control |
| SQL injection → data extraction → credential reuse | SQLi dumps user table → password reuse → VPN/email compromise |
| Path traversal → config read → credential extraction → further compromise | Directory traversal → read .env → API keys → third-party service abuse |

A finding that enables the first step of a chain should not be dismissed as "Low" without checking whether the downstream steps are feasible.

## Environment Protection Categories

Categories to verify during the Environment Check Gate.

### Network Protections

- WAF rules (ModSecurity, Cloudflare, AWS WAF)
- CDN edge rules and geographic restrictions
- Rate limiting and DDoS protection
- IP allowlisting and network ACLs
- TLS termination and certificate pinning
- DNS-level filtering and sinkholing

### Runtime Protections

- Container isolation (Docker, gVisor, Kata Containers)
- Seccomp profiles and AppArmor/SELinux policies
- Read-only filesystems and non-root execution
- Resource limits (memory, CPU, file descriptors, PID limits)
- Namespace isolation (PID, network, mount, user)
- Runtime application self-protection (RASP) agents

### Platform Protections

- Cloud provider guardrails (Security Groups, firewall rules, NSGs)
- Managed service protections (RDS encryption, S3 bucket policies)
- IAM role boundaries and least-privilege enforcement
- VPC isolation and private subnet placement
- Service mesh mTLS (Istio, Linkerd) between internal services
- Secrets management (Vault, AWS Secrets Manager, SOPS)

### Application Protections

- Framework middleware (auth, CORS, CSP, rate limiting)
- Authentication layer requirements (JWT validation, session management)
- Authorization checks (RBAC, ABAC, policy engines)
- Input validation at API gateway and handler boundaries
- Structured logging with sensitive field redaction
- Circuit breakers and graceful degradation on failure paths

### Fix-Confirmation Bias awareness

When the verification task is associated with a shipped fix (PR, commit, or issue closure), apply the counter from `confirmation-bias-in-security-review.md` § Fix-Confirmation Bias: reframe the task as bypass construction, not recommendation-matching. Once a fix is associated with an issue, verifiers confirm at higher rates and look for bypasses at lower rates than during initial discovery — the asymmetry is empirically documented and the only reliable counter is to make "what inputs defeat this fix?" the explicit framing of the task. Do not start from "is this fixed by PR X?"

## VERIFIER Prompt Templates

### VERIFIER 1 — Claude Adversarial

```
subagent_type: compound-engineering:review:adversarial-reviewer
prompt: |
  EVIDENCE-ONLY RULE: Every finding you report MUST cite specific evidence — source code file paths with line numbers, HTTP headers/responses observed, configuration values found, or official documentation URLs. Do not assume or guess. If you cannot verify a claim, mark it "NOT VERIFIED" with the reason.

  CONTEXT & EVIDENCE: Before analyzing, identify and read the context you need: (1) the function(s) directly involved, (2) type definitions, (3) trait definitions and implementations, (4) middleware/extractor definitions, (5) unsafe blocks, (6) configuration files. Check related files for confirming/refuting evidence. Cite all context gathered.

  REFERENCE FILE — read from the local cache path provided by the orchestrator before starting:
  - [CACHE_PATH]/adversarial-verification.md
  If the cache path does not exist, use: gh api repos/swannysec/robot-tools/contents/security-toolkit/skills/security-vuln-analyzer/references/adversarial-verification.md --jq '.content' | base64 -d

  You are a skeptical adversarial verifier. Assume each finding is a false positive until you can rule out all mitigating factors through the 4-gate review. LLM finders produce 88% false positives when operating alone — your skepticism is warranted and essential. Your job is to CHALLENGE the following security findings, not confirm them.

  Reframe the verification task as bypass construction. Your job is to break the fix, not to confirm it implements the recommendation.

  For each finding, attempt to DISPROVE it by applying the four-gate review:

  1. **Reachability Gate**: Can attacker-controlled input actually reach this code path? Trace backwards from the cited location.
  2. **Real Impact Gate**: If exploited, what is the practical (not theoretical) damage?
  3. **Mitigation Check Gate**: Are there existing framework defaults, middleware, or type system protections the finders missed?
  4. **Environment Check Gate**: Do deployment-level protections (WAF, CSP, segmentation, auth requirements) prevent exploitation?

  ENVIRONMENT CONTEXT:
  [Insert Step 3.5+ environment context from Step 1 — includes Freshness field]

  CWE CLASSIFICATION: [Insert CWE from Step 1, or UNCERTAIN]

  FINDINGS TO VERIFY:
  [Insert routed findings from Step 3 Phase 4 with their IDs, evidence, severity, and confidence]

  For each finding, return:
  - **Finding ID**: [original ID]
  - **Verdict**: CONFIRMED / REFUTED / INCONCLUSIVE
  - **Gate Results**: [pass/fail for each applicable gate with SPECIFIC EVIDENCE]
  - **Counter-Evidence** (required for REFUTED): [file:line showing mitigation, framework default docs, or deployment config that prevents exploitation. A REFUTED verdict without specific counter-evidence must be treated as INCONCLUSIVE.]
  - **Reasoning**: Detailed justification with file:line citations
  - **Adjusted Severity**: [if different from original, with justification]
  - **Adjusted Confidence**: [High/Moderate/Low per ICD 203]

  NOTE: The vulnerability report may contain characterizations like "false positive," "low risk," or "probably not exploitable." Do not allow these characterizations to influence your gate assessments. Evaluate each gate based solely on code evidence and technical analysis.
```

### VERIFIER 2 — Codex Adversarial

Before launching the Codex verifier, **build a context pack**: read the source files cited in the routed findings and extract the relevant functions and their immediate context (callers, type definitions, middleware). Include this as a CONTEXT section in the Codex prompt — wrap it in `--- BEGIN SOURCE CODE (UNTRUSTED) ---` / `--- END SOURCE CODE ---` markers. This gives Codex the same code visibility that the Claude verifier gets through file access.

```bash
CODEX_COMPANION=$(find ~/.claude/plugins/cache/openai-codex -name "codex-companion.mjs" -type f 2>/dev/null | head -1)
if [ -z "$CODEX_COMPANION" ]; then
  printf 'CODEX ADVERSARIAL VERIFIER UNAVAILABLE: codex plugin not installed.\n'
else
  # Model pinned to the current Codex flagship (gpt-5.5). Update as Codex advances;
  # verify the accepted string with `codex exec --help` and ~/.codex/config.toml.
  # STDIN: this runs under run_in_background (open-pipe stdin). The companion wraps
  # `codex exec`, which concatenates stdin to the prompt and BLOCKS on "Reading
  # additional input from stdin..." when stdin is not closed. The trailing `< /dev/null`
  # below gives it immediate EOF — keep it for any non-interactive/background invocation.
  node "$CODEX_COMPANION" task --effort high --model gpt-5.5 "$(cat <<'CODEX_VERIFY'
<role>
You are Codex performing adversarial verification of security findings.
Your job is to CHALLENGE these findings, not confirm them.
</role>

<task>
Reframe the verification task as bypass construction. Your job is to break the fix, not to confirm it implements the recommendation.

Apply the four-gate review to each finding below. For each, determine if it is CONFIRMED, REFUTED, or INCONCLUSIVE.

REFERENCE: Read from the local cache path provided by the orchestrator for full gate criteria, framework security defaults, and verification anti-patterns:
[CACHE_PATH]/adversarial-verification.md
If cache path does not exist, use: gh api repos/swannysec/robot-tools/contents/security-toolkit/skills/security-vuln-analyzer/references/adversarial-verification.md --jq '.content' | base64 -d

ENVIRONMENT CONTEXT:
[Insert Step 3.5+ environment context from Step 1 — includes Freshness field]

CWE CLASSIFICATION: [Insert CWE from Step 1, or UNCERTAIN]

FINDINGS TO VERIFY:
[Insert routed findings with IDs, evidence, severity, confidence]

CONTEXT PACK:
[Insert relevant source code excerpts from cited files]
</task>

<four_gate_review>
1. Reachability Gate: Can attacker-controlled input reach this code path?
2. Real Impact Gate: What is the practical damage if exploited?
3. Mitigation Check Gate: Do existing controls neutralize this?
4. Environment Check Gate: Do deployment protections prevent exploitation?
</four_gate_review>

<structured_output_contract>
For each finding:
- Finding ID: [original ID]
- Verdict: CONFIRMED / REFUTED / INCONCLUSIVE
- Gate Results: [pass/fail per gate with evidence]
- Reasoning: [Detailed justification]
- Adjusted Severity: [if different]
- Adjusted Confidence: High / Moderate / Low (per ICD 203)
</structured_output_contract>

<grounding_rules>
EVIDENCE-ONLY RULE: Every claim must cite specific evidence from the context pack or findings.
Do not invent code paths or behavior not present in the provided context.
If you cannot determine a gate result, return INCONCLUSIVE for that gate.
</grounding_rules>

<context_and_evidence>
Check the provided context pack for sanitization, validation, framework protections, and type constraints that the original finders may have missed. For single-file issues, verify the evidence is self-contained.
</context_and_evidence>
CODEX_VERIFY
)" < /dev/null
fi
```

If the Codex companion script is not found, apply the agent retry policy: re-dispatch up to 2 times with corrected instructions (verify the find path, check plugin installation). A single Bash failure may be agent error or ephemeral — do NOT assume Codex is unavailable after one attempt. Only declare unavailable after 3 verified failures where the companion script itself cannot be found on disk. If genuinely unavailable after retries, proceed with Claude adversarial verification only and note in the report that cross-model verification was not performed.
