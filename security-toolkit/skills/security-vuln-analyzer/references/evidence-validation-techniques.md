---
name: evidence-validation-techniques
description: Six techniques for validating AI-generated security findings, ranked by research-demonstrated effectiveness
---

# Evidence-Based Validation Techniques

Six techniques for validating AI-generated security findings, ranked by research-demonstrated effectiveness.

## 1. Requiring Specific File:Line Evidence

GitHub Security Lab's Taskflow Agent mandates strict evidence: analysts must "include the line number where the untrusted code is invoked, as well as the untrusted code or package manager that is invoked." Missing or inconsistent information results in report rejection.

Critical finding from "Sifting the Noise": **51.2% of successful false positive identifications relied on evidence from non-target files** — agents accessed helper classes and configuration files to verify or refute vulnerability claims. This means restricting analysis to a single file misses over half of the evidence needed for accurate triage.

## 2. Exploit PoC Generation as Verification

**CVE-Genie** (multi-agent framework for CVE reproduction):
- Reproduced **428/841 CVEs (50.8%)** at average cost of **$2.77 per CVE**
- Ablation study: removing critic agents increased false positives by **47%**
- Standalone LLM approaches achieved **zero** reproductions — modular orchestration is essential
- Web vulnerabilities (XSS, CSRF, SQLi) most reproducible; memory safety and concurrency least

**CVE-Bench** (ICML 2025):
- LLM agents achieve only **13% exploitation success rate** on critical-severity CVEs with tool access
- Without tools: **2.5%** success rate
- PoC-based verification is valuable but cannot be the sole validation gate

Trail of Bits' fp-check adds **negative PoCs**: show what normal operation looks like vs. what the exploit requires. This clarifies the gap between theoretical and practical exploitability.

## 3. Static Analysis Tool Corroboration

The highest-ROI technique when SAST tools are available:

| System | Approach | Result |
|--------|----------|--------|
| **IRIS** (ICLR 2025) | LLM infers taint specs → CodeQL verifies via whole-repo analysis | **103.7% detection improvement** (55 vs 27 vulns), FDR reduced 5.21pp |
| **SAST-Genius** | Semgrep candidates + fine-tuned Llama 3 8B evaluation | **91% FP reduction** (225→20), ~11x fewer FP |
| **Semgrep AI** | Rule-based engine + AI reasoning, bidirectional | **96% researcher agreement**, 60% triage workload reduction |
| **ZeroFalse** | CWE-specialized prompts on SAST output | Best F1=0.912 (OWASP), 0.955 (OpenVuln) |

Key insight: **CWE-specialized prompting consistently outperforms generic prompts** when triaging SAST output. Providing the CWE-specific rubric (sources, sinks, sanitizers for that exact vulnerability class) dramatically improves precision.

## 4. DAST-Style Runtime Validation

CVE-Genie uses CTF-style verification: successful exploits trigger hidden flags. Pipeline: pre-setup environment validation → exploit execution → post-execution success confirmation. Provides binary ground truth but limited to vulnerabilities with reproducible environments.

In 1.6% of cases ("Sifting the Noise"), agents attempted to compile minimal code snippets to validate suspicious logic — a lightweight form of runtime validation even without a full DAST setup.

## 5. Two-Pass Validation (Find → Verify)

**The most consistently effective pattern across all literature:**

| System | First Pass | Second Pass | FP Reduction |
|--------|-----------|-------------|-------------|
| **Sifting the Noise** | Initial detection (98.3% FPR) | SWE-agent with Claude verifies | **92.1%** (→6.3% FPR) |
| **IRIS** | LLM infers specs | CodeQL performs taint analysis | 5.21pp FDR improvement |
| **SAST-Genius** | Semgrep flags | LLM evaluates context | **91%** (11x fewer FP) |
| **CVE-Genie** | Developer agent generates | Critic agent challenges | Removing critics: **+47% FP** |

The pattern: use one mechanism for broad detection (high recall, high FP), then a different mechanism for verification (high precision). The two mechanisms should be different approaches — not the same model running twice.

## Ground Truth Comparison

ZeroFalse (2025) tested 10 LLMs against OWASP Java Benchmark (known ground truth). Best results: GPT-5 achieved F1=0.955, recall=0.914, precision=1.0 on real-world data.

**Critical caveat:** Models that performed well on OWASP sometimes collapsed on real-world datasets. Gemini 2.5 Pro went from F1=0.910 on OWASP to **F1=0.372 on OpenVuln**. Benchmark performance does not reliably transfer.

## 6. Adversarial Bypass Construction

A specialization of Two-Pass Validation aimed at fix-verification rather than initial detection. Distinct from PoC reproduction (which validates the original bug exists) and PoC generation (which validates exploitability).

PATTERN: After a fix ships, construct adversarial inputs the fix is supposed to handle. Trace each input through the fixed code and verify the output. Bypasses surface as inputs the fix accepts that should be rejected (or rejects that should be accepted).
TRIGGER: Any fix-verification task. Mandatory before issue closure.
COUNTER (used as): The find/verify pattern from Two-Pass Validation, with the verifier reframed as a bypass constructor rather than a PR description matcher. The verifier's task is "what inputs defeat this fix?" — not "does the fix implement the recommendation?"

Methodological grounding: This is the find/verify pattern with *different* mechanisms (Two-Pass Validation, section 5 above). The 91-92% FP reduction observed in Sifting the Noise and SAST-Genius generalizes only when the verifier mechanism is genuinely different from the finder. Same model running twice does not deliver the FP-reduction observed in literature; CVE-Genie ablation showed +47% FP when the critic agent was removed.

For workflow integration, see `fix-verification-mode.md`. For why this is needed (failure pattern reference), see `premature-fix-confirmation.md`.
