# Scoring Frameworks

Scoring records independent observations. It must not turn model agreement, a formula, or a missing signal into proof that a vulnerability exists.

## Required fields

For each security candidate or finding, record these fields separately with citations, counterevidence, assumptions, and uncertainty:

| Field | Meaning |
|---|---|
| Validity | Whether the cited code or configuration has the asserted security-relevant property. |
| Reachability | Whether the stated attacker/input can reach the condition in the pinned deployment and trust-boundary context. |
| Impact | The demonstrated security consequence of the reachable condition. |
| Mitigation/fix state | Whether primary or compensating controls prevent the consequence for the declared primitive class and variants. |
| Confidence | Evidence quality and remaining uncertainty; never a vote count or aggregate of model confidence. |
| Priority | A human triage decision based on demonstrated consequence, exposure, exploit signals, remediation state, and organizational context. |

These fields are not interchangeable. A high-priority issue can remain `NOT VERIFIED`; a valid implementation defect can lack reachability or security impact; a fix can satisfy one primitive class while leaving another disputed.

## CVSS v4.0

Use **CVSS v4.0** as the primary technical severity framework when the finding has enough evidence for a vector. Record the complete vector, score, calculator/version, score type (Base, Threat, Environmental, or Supplemental where used), inputs, and the security authorities/trust boundaries that justify the inputs.

CVSS describes technical severity; it neither establishes validity/reachability/impact nor predicts exploitation. Do not silently substitute CVSS v3.1. If a consumer requires v3.1, render it only as an explicitly labeled compatibility score alongside CVSS v4.0, with its own vector and rationale.

When evidence is insufficient to score a metric, record `CVSS v4.0: NOT SCORED` with the missing evidence. Do not infer a score from product category, repository name, or severity labels.

## Exploitation signals

EPSS and CISA KEV are contextual triage signals, not evidence that a local claim is valid.

- Record an EPSS value only for an applicable CVE. Include CVE, probability, percentile when available, retrieval timestamp in UTC, and the EPSS model/data version or API response version supplied at retrieval.
- Record KEV membership with the catalog retrieval timestamp and catalog/version identifier when available.
- `NO CVE`, `NOT RETRIEVED`, and `NOT APPLICABLE` are distinct states. A missing EPSS or KEV signal must not lower severity or disposition.

## Priority rationale

Priority is a transparent human triage field, not a weighted formula. State the evidence for exposure, attacker preconditions, demonstrated impact, active-exploitation signals, remediation availability, compensating controls, and required response timing. Separate external policy deadlines from the technical assessment.

## Disposition boundary

The only discovery dispositions are:

1. `vulnerability finding`
2. `primary-control weakness`
3. `hardening or secure-code note`
4. `reliability or maintainability signal`

Disposition follows the evidence and four gates in [discovery-contract.md](discovery-contract.md) and [cross-model-verification.md](cross-model-verification.md), not a severity threshold. Stable IDs, status, provenance, and dispute packets follow [orchestrator-contract.md](orchestrator-contract.md).
