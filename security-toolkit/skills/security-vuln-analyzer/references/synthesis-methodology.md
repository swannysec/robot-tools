# Synthesis Methodology Reference

ICD 203 terminology, deduplication rules, evidence quality rubric, conflict resolution, escalation protocol, and report assembly checklist for multi-agent vulnerability analysis synthesis.

## ICD 203 Analytic Standards Terminology

### Confidence Levels (Evidence Quality)

Per ICD 203, confidence reflects the quality of evidence and analytic reasoning — NOT the analyst's personal certainty.

| Level | Definition | Criteria in This Skill |
|-------|-----------|----------------------|
| **High Confidence** | Assessment based on high-quality information and sound reasoning | File:line citations verified by reading code, data flow traced source-to-sink, corroborated by 2+ agents or confirmed by deterministic tool (semgrep, cargo audit) |
| **Moderate Confidence** | Information credibly sourced and plausible but not sufficient for higher confidence | File:line cited but data flow inferred (not fully traced), OR single-agent finding without corroboration, OR evidence depends on configuration not directly observed |
| **Low Confidence** | Information questionable, fragmented, or poorly corroborated | Generic CWE citation without specific code path, pattern-matched without context analysis, or evidence could not be verified. Discard during synthesis. |

### Exploitability (Likelihood Scale)

Per ICD 203 words of estimative probability. Use to assess likelihood of exploitation.

| Term | Probability | Application |
|------|------------|-------------|
| **Almost no chance** | 1-5% | Theoretical only; requires conditions that effectively never occur |
| **Very unlikely** | 5-20% | No public PoC; requires significant prerequisites |
| **Unlikely** | 20-45% | PoC exists but unreliable, requires auth, or targets uncommon configs |
| **Roughly even chance** | 45-55% | Reliable exploit exists but significant mitigations commonly deployed |
| **Likely** | 55-80% | Reliable public exploit; commonly deployed vulnerable software |
| **Very likely** | 80-95% | Known exploitation in wild (KEV-listed); weaponized in toolkits |
| **Almost certain** | 95-99% | Trivially exploitable; mass exploitation observed |

### Severity and Response Timeline

| Severity | CVSS Range | Response Timeline |
|----------|-----------|-------------------|
| Critical | 9.0-10.0 | Immediate |
| High | 7.0-8.9 | 14 days |
| Medium | 4.0-6.9 | 30 days |
| Low | 0.1-3.9 | 90 days |

## Deduplication Rules

Cluster findings by vulnerability, not by agent:

- **Same vulnerability**: findings referencing the same file + line range (within 5 lines), same CWE, or same attack vector
- **Merge rule**: when agents report the same vulnerability under different IDs, merge into a single finding. Keep the richest evidence set. Record all contributing agent IDs (e.g., "SENTINEL-2, BACKEND-1, CODEX-3").
- **Distinguish**: same root cause (merge) vs. related but distinct vulnerabilities (keep separate). Two SQL injection findings at different endpoints are distinct. Two descriptions of the same injection at the same endpoint are duplicates.

## Evidence Quality Rubric

Rate each deduplicated finding using the ICD 203 Confidence scale above:

1. Check citation specificity: file:line present? Data flow described?
2. Check corroboration: how many agents independently found this? Did they cite independent evidence?
3. Check reasoning completeness: is the chain from input to vulnerability to impact fully articulated?

**Actions by confidence level:**

- **High Confidence**: Proceed to report. Still routed to adversarial verification if Critical/High severity.
- **Moderate Confidence**: Flag for adversarial verification regardless of severity.
- **Low Confidence**: Discard with explanation. Note in report as "discarded — insufficient evidence."

## Conflict Resolution Decision Tree

When agents disagree on severity or validity:

1. Compare evidence quality (confidence level) of each side
2. Higher-confidence evidence wins — High Confidence evidence overrides Moderate Confidence
3. If confidence is equal: the position with more specific code-level evidence wins
4. If still tied: flag as DISPUTED, route to adversarial verification
5. NEVER resolve conflicts by averaging severity scores
6. NEVER dismiss a finding solely because it's a singleton (only one agent reported it)

## Escalation Protocol

Route to adversarial verification (Step 3.5):

- All Critical and High severity findings (regardless of consensus)
- All DISPUTED findings from conflict resolution
- Singleton findings (reported by only 1 agent — may be highest-value cross-model finding)
- All Moderate Confidence findings

Route to deterministic validation (Step 3.7):

- All surviving CONFIRMED findings from Step 3.6 (tool-based spot check)
- All findings where adversarial verifiers disagreed (deterministic tiebreaker)
- All findings where both verifiers returned INCONCLUSIVE

## Resolution, Anti-Patterns, and Report Assembly

The authoritative resolution table (Step 3.6), synthesis anti-patterns, and report assembly procedures are defined in the SKILL.md Steps 3.6 and 3.8. This reference file provides the methodology inputs (deduplication, evidence quality, conflict resolution, escalation); the SKILL.md provides the execution procedures and output templates.
