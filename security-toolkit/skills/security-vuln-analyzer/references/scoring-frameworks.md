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

## Structured scoring records

Each candidate has a required `scoring` object with three strict records. Each role emits its own records, even when it has not assessed a signal; Role 3 owns security and scoring guidance. Preserve each record separately. External information must come from frozen approved intake or permitted retrieval; these fields do not authorize an additional fetch.

| Record | Required fields |
|---|---|
| `cvss_v4` | `status` (`SCORED`, `NOT SCORED`, `NOT APPLICABLE`), `vector`, `score`, `score_type`, `calculator_version`, `inputs`, `rationale`, `evidence` |
| `epss` | `status` (`RETRIEVED`, `NO CVE`, `NOT RETRIEVED`, `NOT APPLICABLE`), `cve`, `probability`, `percentile`, `retrieved_at_utc`, `version`, `rationale`, `evidence` |
| `kev` | `status` (`RETRIEVED`, `NO CVE`, `NOT RETRIEVED`, `NOT APPLICABLE`), `cve`, `membership` (`LISTED`, `NOT LISTED`, `UNKNOWN`), `retrieved_at_utc`, `version`, `rationale`, `evidence` |

`score`, `probability`, and `percentile` are numbers or null; unknown numbers are null, never fabricated zeroes. Unavailable string metadata is `""` and unavailable arrays are `[]`. `inputs` is an array of strings and `evidence` is an array of structured citations. Explain unknown or unavailable information with a nonblank `rationale`; do not represent unknown KEV membership as `NOT LISTED`.

The role must explain the security authorities and trust boundaries supporting a CVSS score, supply an applicable CVE for a retrieved signal, and explain when a returned version is unavailable. These are author obligations: the controller does not assess whether a rationale is adequate or a CVE applies.

After schema validation, the controller performs only literal presence, syntax, citation, and range checks. A `SCORED` CVSS record requires a `CVSS:4.0` vector, finite score from 0 through 10, nonblank score type, calculator version and rationale, nonempty inputs, and evidence. Other CVSS states require a null score. A `RETRIEVED` EPSS or KEV record requires a syntactically valid CVE, UTC retrieval timestamp, nonblank rationale, and evidence. EPSS probability must be finite from 0 through 1; percentile may be null or finite from 0 through 1. For other EPSS states, probability and percentile are null and timestamp and version are empty strings. For other KEV states, membership is `UNKNOWN` and timestamp and version are empty strings. `NO CVE` requires an empty CVE string. When a retrieved record has an empty version, require a nonblank rationale without judging its explanation. Missing or malformed mandatory fields or violations are `MALFORMED`, with one identical-packet retry, then `INCOMPLETE` if unrepaired. Do not use conditional schema keywords; the controller applies these post-schema checks without calculating values or inferring missing values from prose.

## CVSS v4.0

For literal vector syntax checks, use the required metrics, value abbreviations, and order
in [FIRST's CVSS v4.0 vector specification, Table 23](https://www.first.org/cvss/v4.0/specification-document#Vector-String).
Reject missing Base metrics, unknown metrics or values, duplicate metrics, and incorrect
ordering. Syntax validation does not calculate the score or decide whether a metric choice
or its security rationale is justified.

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
