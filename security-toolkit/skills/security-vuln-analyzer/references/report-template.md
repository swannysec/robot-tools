# Step 3.8 Report Template and Output Quality Checklist

Report assembly templates and pre-delivery verification checklist. The orchestrator MUST read this file during Step 3.8 and use the templates to structure the final report.

## Table of Contents

- [Report Assembly Rules](#report-assembly-rules)
- [Consensus Assessment Table](#consensus-assessment-table)
- [Key Findings by Agent](#key-findings-by-agent)
- [Attack Tree Summary](#attack-tree-summary)
- [Consolidated Fix Recommendation](#consolidated-fix-recommendation)
- [Compliance Impact Matrix](#compliance-impact-matrix)
- [Rust Toolchain Verification](#rust-toolchain-verification)
- [Disputed Findings](#disputed-findings)
- [Risk Summary Box](#risk-summary-box)
- [Common Vulnerability Patterns](#common-vulnerability-patterns)
- [Output Quality Checklist](#output-quality-checklist)

## Report Assembly Rules

Only findings that survived Steps 3.5-3.7 appear in the final output.

**If all findings were REFUTED or discarded:** Produce a False Positive Report that includes: (1) the original vulnerability claim, (2) the evidence that refuted each finding (citing gate failures and tool output), (3) a summary of what was checked, and (4) a HUMAN REVIEW REQUIRED note — false-negative risk still exists even when all findings are refuted.

**INTERNAL USE ONLY** — This report contains detailed attack paths, infrastructure information, and security tool inventory. Redact sensitive details before sharing outside the security team. If findings reference hardcoded secrets, API keys, or credentials, redact the actual values in the report — cite the file:line location but do not quote secret values verbatim.

## Consensus Assessment Table

| Aspect | Assessment |
|--------|-----------|
| Vulnerability Valid? | [Yes/No + confidence across agents] |
| CVSS Score | [Best-justified score from agents] |
| EPSS Score | [Probability from Sentinel, if CVE available] |
| KEV Listed? | [Yes/No from Sentinel check] |
| Priority Score | [Formula: (CVSS*0.4)+(exploitability*2.0)+(fix_available*1.0)] |
| Confidence | [High/Moderate/Low per ICD 203 — post-verification assessment] |
| Exploitability | [ICD 203 likelihood term — post-verification assessment] |
| Urgency | [Timeline: Critical=immediate, High=14d, Medium=30d, Low=90d] |
| Fix Complexity | [Low/Medium/High — from Backend Coder] |
| Supply Chain | [Clean / Affected — from Auditor cargo audit] |
| Adversarial Verdict | [CONFIRMED/REFUTED per finding — from Step 3.5] |
| Validation Status | [TOOL-CONFIRMED/OBSERVATION-MATCHED/NOT-VALIDATED — from Step 3.7] |

## Key Findings by Agent

Summarize unique insights from each agent using contributing IDs per deduplicated finding:
- **FINDER 1 — Sentinel (SENTINEL-N)**: OWASP 2025 compliance, EPSS+KEV+CVSS scoring, 4-bucket scan, auth audit
- **FINDER 2 — Threat Modeler (THREAT-N)**: STRIDE-per-interaction, attack trees (easiest/cheapest/stealthiest), defense-in-depth gaps
- **FINDER 3 — Backend Coder (BACKEND-N)**: CWE-classified, Rust-specific remediation, test-first verification, middleware code
- **FINDER 4 — Auditor (REVIEW-N)**: Legitimacy, supply chain, prioritization scores, compliance references, business impact
- **FINDER 5 — Codex Independent (CODEX-N)**: Independent cross-model challenge, severity rating challenges, related vulnerability discovery

## Attack Tree Summary

Merge FINDER 2's attack trees into a consolidated view:
```
Easiest path:  [Node chain with difficulty ratings]
Cheapest path: [Node chain with cost ratings]
Stealthiest:   [Node chain with detection risk ratings]
```
Note which paths are blocked by verified mitigations and which remain open.

## Consolidated Fix Recommendation

Merge agent recommendations into single implementation. Prioritize by severity + exploitability:
```
[Framework-specific code example — Rust/Axum preferred]
```

## Compliance Impact Matrix

| Finding ID | PCI-DSS | SOC 2 | HIPAA | GDPR | NIST CSF | OWASP ASVS |
|-----------|---------|-------|-------|------|----------|------------|
| [ID] | [Section ref or N/A] | [CC ref or N/A] | [Section ref or N/A] | [Article ref or N/A] | [Function ref or N/A] | [Chapter ref or N/A] |

## Rust Toolchain Verification

If the target is a Rust codebase, include these post-fix verification commands:
```bash
cargo audit              # Verify no remaining RustSec advisories
cargo deny check         # Verify license and advisory policy compliance
cargo clippy -- -W clippy::unwrap_used -W clippy::indexing_slicing  # Lint for security patterns
cargo-geiger             # Measure unsafe code surface area
cargo test               # Verify no regressions
```

## Disputed Findings

If any findings were marked DISPUTED in Steps 3.6 or 3.7 (deterministic validation could not resolve):
- List each disputed finding with its original ID, evidence from all agents, both verifiers' verdicts, and the validation agent's assessment
- Include all evidence from all sides — the human reviewer needs the full picture
- Do NOT silently drop disputed findings

## Risk Summary Box

```
┌─────────────────────────────────────────────────────────────┐
│  [VULNERABILITY NAME] - [Target]                            │
├─────────────────────────────────────────────────────────────┤
│  Severity:        [Rating] (CVSS [Score])                   │
│  Confidence:      [High/Moderate/Low per ICD 203]           │
│  Exploitability:  [ICD 203 likelihood term] ([reason])      │
│  EPSS:            [Probability] ([Low/Medium/High])         │
│  KEV:             [Listed / Not Listed]                     │
│  Priority Score:  [Score from formula]                      │
│  Fix Effort:      [Minimal/Moderate/Significant]            │
│  Timeline:        [Recommended fix window]                  │
│  Supply Chain:    [Clean / Affected]                        │
│  Verification:    [TOOL-CONFIRMED / NOT-VALIDATED]          │
│  Compliance:      [Affected standards with section refs]    │
├─────────────────────────────────────────────────────────────┤
│  ⚠ HUMAN REVIEW REQUIRED                                   │
│  Multi-agent analysis reduces but does not eliminate false   │
│  negatives. AI security analysis can suppress a significant │
│  fraction of real vulnerabilities. Non-determinism means    │
│  re-running may surface additional findings. This report    │
│  is a triage aid, not a definitive security assessment.     │
└─────────────────────────────────────────────────────────────┘
```

## Appendix: Environment Context Blocks

Include both versions of the environment context block used during this analysis so reviewers can verify the Freshness field was correctly excluded from Step 2 agents:

**Step 2 version (sent to FINDER agents — no Freshness field):**
```
[Paste the actual Step 2 environment context block used]
```

**Step 3.5+ version (sent to VERIFIER agents — includes Freshness field):**
```
[Paste the actual Step 3.5+ environment context block used]
```

## Common Vulnerability Patterns

### Web Application Vulnerabilities
| Vulnerability | Key Headers/Controls | Primary Agent Focus |
|--------------|---------------------|---------------------|
| Clickjacking | X-Frame-Options, CSP frame-ancestors | All agents |
| XSS | CSP script-src, X-Content-Type-Options | FINDER 1 — Sentinel |
| CSRF | SameSite cookies, CSRF tokens | FINDER 3 — Backend Coder |
| Open Redirect | Input validation, allowlists | FINDER 2 — Threat Modeler |
| SQL Injection | Parameterized queries, WAF | FINDER 3 — Backend Coder |

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

**Step 1 — Validation:**
- [ ] Code freshness check performed with deterministic tools
- [ ] Vulnerability validated with actual evidence
- [ ] CWE classified or marked UNCERTAIN
- [ ] Environment context captured (runtime, network, framework, auth, deployment stage)
- [ ] Pre-dispatch preparation completed (target resolved to local path with fresh pull, reference cache verified)

**Step 2 — Analysis:**
- [ ] Prompts loaded from `references/step-2-agent-prompts.md` (not from memory)
- [ ] FINDERs 1-4 launched in a single message with parallel Agent tool calls
- [ ] FINDER 5 (Codex) launched immediately after — not after Claude agents returned
- [ ] DEBIASING preamble included in all Step 2 agent prompts (NOT in verifier prompts)
- [ ] CONTEXT & EVIDENCE preamble included in all agent prompts
- [ ] CWE-specific verification procedures injected (if CWE was classified)
- [ ] Step 2 environment context block used (WITHOUT Freshness field)
- [ ] All agents used standardized output format (SENTINEL/THREAT/BACKEND/REVIEW/CODEX prefixed IDs)
- [ ] ICD 203 Confidence (High/Moderate/Low) in all agent output
- [ ] ICD 203 Exploitability (7-point likelihood scale) in all agent output
- [ ] CVSS score provided with breakdown (from 3+ agents)
- [ ] EPSS/KEV scoring considered (from Sentinel — not CVSS alone)
- [ ] Orchestrator waited for ALL 5 agents to return before starting Step 3
- [ ] Failed agents re-dispatched up to 2 times before moving on

**Step 3 — Synthesis:**
- [ ] Synthesis methodology reference files read (scoring-frameworks, compliance-frameworks, synthesis-methodology)
- [ ] Findings deduplicated by vulnerability (not by agent)
- [ ] Instantiation rule applied (specific instances merged into parent clusters)
- [ ] Evidence quality rated per ICD 203 (High/Moderate/Low Confidence)
- [ ] Low Confidence findings discarded with explanation
- [ ] Conflicts resolved by evidence quality (not vote counting)
- [ ] Critical/High + DISPUTED + singletons + Moderate Confidence routed to verification
- [ ] Phase 4.5 auto-resolution applied (amplifier, singleton-informational, hedge-word rules)
- [ ] Auto-resolved findings logged with triggering rule and finder quotes

**Steps 3.5-3.7 — Verification:**
- [ ] Verifier prompts loaded from `references/adversarial-verification.md`
- [ ] Both adversarial verifiers launched in parallel (Claude + Codex)
- [ ] Step 3.5+ environment context block used (WITH Freshness field)
- [ ] Codex verifier received context pack (orchestrator-packed source code)
- [ ] Adversarial verdicts recorded with 4-gate results per finding
- [ ] Orchestrator waited for BOTH verifiers to return before starting Step 3.6
- [ ] Resolution table applied correctly (agree->accept, disagree->deterministic check)
- [ ] Deterministic validation used `model: sonnet` per `references/deterministic-validation.md`
- [ ] Orchestrator waited for validator to return before starting Step 3.8
- [ ] Verifier disagreements resolved by deterministic ground truth (not another LLM)

**Step 3.8 — Report:**
- [ ] Report template loaded from `references/report-template.md`
- [ ] Consensus table includes ICD 203 Confidence + Exploitability + Validation Status
- [ ] Attack trees include quantified path analysis (easiest/cheapest/stealthiest)
- [ ] Framework-specific fix code included (Rust/Axum preferred)
- [ ] Compliance impact matrix with specific section numbers
- [ ] Rust-specific toolchain verification included (if applicable)
- [ ] Supply chain dimension assessed (cargo audit / dependency analysis)
- [ ] DISPUTED findings listed with full evidence trail for human review
- [ ] HUMAN REVIEW REQUIRED warning present in Risk Summary Box
- [ ] Every finding cites specific evidence (file:line, header, or doc URL)
- [ ] Unverified claims marked "NOT VERIFIED" with reason
- [ ] Any agent failures clearly flagged in report summary with attempt counts

**Step 4 — Fix Validation (if applicable):**
- [ ] If fixes applied: /codex:adversarial-review run against working tree
