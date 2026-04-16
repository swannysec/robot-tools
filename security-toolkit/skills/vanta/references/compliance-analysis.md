# Compliance Analysis Methods

Scoring methodology, gap identification, audit readiness checklist, and
cross-framework overlap analysis for Vanta compliance workflows.

---

## Table of Contents

1. [Posture Scoring Methodology](#posture-scoring-methodology)
2. [Gap Identification Patterns](#gap-identification-patterns)
3. [Audit Readiness Checklist](#audit-readiness-checklist)
4. [Cross-Framework Overlap Analysis](#cross-framework-overlap-analysis)
5. [Posture Trend Analysis](#posture-trend-analysis)

---

## Posture Scoring Methodology

Compute four component scores, then combine into an overall posture score.
Present per framework and as a cross-framework aggregate.

### Component Scores

**Framework Completeness** (weight: 40%)

```
(passing tests / total active tests) x 100
```

Retrieve via `tests` MCP tool (use `frameworkFilter`) or `GET /v1/tests`
(use `frameworkFilter` query param). Count tests with status `OK` as passing. Exclude `DEACTIVATED` and
`NOT_APPLICABLE` tests from the denominator — only active tests count.

**Control Coverage** (weight: 30%)

```
(controls with >= 1 passing test / total controls) x 100
```

Retrieve controls via `controls` MCP tool (use `frameworkMatchesAny`) or
`GET /v1/controls` (use `frameworkMatchesAny` query param). For each control,
use `list_control_tests` MCP tool to retrieve its tests and check whether at
least one has status `OK`. A control with all failing or no tests is uncovered.

**Evidence Freshness** (weight: 20%)

```
(documents current and not expired / total required documents) x 100
```

Retrieve via `documents` MCP tool or `GET /v1/documents`. A document is
"current" if its last review date plus cadence interval has not elapsed.
Treat documents past cadence expiry as stale.

**Personnel Compliance** (weight: 10%)

```
(tasks completed / total assigned tasks) x 100
```

Retrieve via `people` MCP tool or `GET /v1/people` with
`taskFilter=INCOMPLETE`. Sum completed and incomplete tasks across all
in-scope personnel (training, policy acceptance, custom tasks).

### Overall Posture Score

```
overall = (framework_completeness x 0.40)
        + (control_coverage x 0.30)
        + (evidence_freshness x 0.20)
        + (personnel_compliance x 0.10)
```

### Presentation

- Compute per-framework scores first, then aggregate across all frameworks.
- For aggregate scores, use the mean of per-framework scores weighted by
  number of controls in each framework.
- Display each component score alongside the overall score so the user sees
  which dimension drags the posture down.
- Use thresholds: >= 90% green, 70-89% yellow, < 70% red.

**Methodology note:** These scores measure configuration status, not audit
outcome. Vanta uses its own internal scoring which is not publicly documented.
A 100% posture score does not guarantee an audit pass — auditors evaluate
effectiveness and evidence quality beyond binary test results.

---

## Gap Identification Patterns

Investigate gaps in priority order. Each pattern specifies what to look for,
which tool to use, and how to prioritize findings.

### Pattern 1: Controls with Zero Passing Tests

**Priority:** Critical — these represent complete compliance gaps.

- Retrieve all controls for the target framework via `controls` MCP tool
  (use `frameworkMatchesAny`).
- For each control, retrieve associated tests via `list_control_tests` MCP tool.
- Flag any control where zero tests have status `OK`.
- Prioritize by cross-framework coverage count (see [Cross-Framework Overlap
  Analysis](#cross-framework-overlap-analysis)) — a gap in a control that
  satisfies 4 frameworks is more urgent than one covering 1.

### Pattern 2: Tests in NEEDS_ATTENTION or INVALID Status

**Priority:** High — require investigation, may indicate integration issues.

- Retrieve tests via `tests` MCP tool filtered by `statusFilter=NEEDS_ATTENTION`
  or `statusFilter=INVALID`.
- Group by `integrationFilter` to detect systemic issues. If multiple tests from
  the same integration share this status, investigate the integration
  connection (via `integrations` MCP tool) before individual tests.

### Pattern 3: Tests in IN_PROGRESS Status

**Priority:** Medium — tests currently being evaluated.

- Retrieve tests via `tests` MCP tool filtered by `statusFilter=IN_PROGRESS`.
- IN_PROGRESS means Vanta is still evaluating the test (recently connected
  integration, pending data collection).
- Do not count IN_PROGRESS tests as compliance failures. Report separately as
  pending evaluation. Check integration status via `integrations` MCP tool.

### Pattern 4: Documents with Expired Cadence

**Priority:** Medium — evidence that needs renewal.

- Retrieve all documents via `documents` MCP tool.
- Compare each document's last review date plus cadence interval against
  the current date.
- Flag documents past their cadence expiry date.
- Prioritize by number of controls or frameworks the document supports.

### Pattern 5: Policies Not Yet Approved or Accepted

**Priority:** Medium — governance gaps.

- Retrieve policies via `policies` MCP tool. Flag unapproved policies.
- For approved policies, check acceptance via `people` with
  `taskFilter=INCOMPLETE`. Prioritize policies under active audit frameworks.

### Pattern 6: Controls Owned by Departed Employees

**Priority:** Medium — orphaned ownership.

- Retrieve controls via `controls` MCP tool, extract owner IDs.
- Cross-reference against `people` filtered by `employmentStatus=INACTIVE`
  or `employmentStatus=FORMER`. Flag controls with inactive owners.
- Remediate via `POST /v1/controls/{id}/set-owner` (requires confirmation).

### Pattern 7: Framework Requirements Without Mapped Controls

**Priority:** Low-Medium — missing coverage.

- Retrieve controls per framework. Compare against expected requirements.
- Vanta may not expose a canonical requirements list — use the framework's
  test categories as a proxy to identify sparse coverage areas.

---

## Audit Readiness Checklist

Framework-agnostic checklist for audit preparation. Each item is a pass/fail
gate. Walk through every item before declaring audit readiness.

Each item below lists: how to verify, what passing looks like, and common
blockers with remediation approaches.

**1. All in-scope controls have >= 1 passing test**
- Verify: `controls` MCP tool filtered by `frameworkMatchesAny`, then
  `list_control_tests` for each control.
- Pass: every control has at least one test with status `OK`.
- Blocker: controls with zero passing tests. Prioritize by cross-framework
  overlap. Use `getAgentRemediationPrompt` (plugin) for fix guidance.

**2. All required documents uploaded and current**
- Verify: `documents` MCP tool. Check last review date + cadence vs. today.
- Pass: no documents past cadence expiry; all required uploads present.
- Blocker: missing or expired documents. Notify owners; identify dependent
  controls to assess impact.

**3. All policies approved and accepted**
- Verify: `policies` MCP tool for approval status; `people` for acceptance.
- Pass: every policy approved and accepted by all assigned employees.
- Blocker: unapproved policies or unaccepted ones. Escalate to policy owners.

**4. No CRITICAL/HIGH vulnerabilities past SLA deadline**
- Verify: `vulnerabilities` MCP tool filtered by severity and SLA deadline.
- Pass: zero CRITICAL/HIGH vulnerabilities with elapsed SLA deadlines.
- Blocker: past-due vulnerabilities. Acknowledged SLA misses reduce audit
  risk but still require remediation.

**5. All personnel completed security awareness training**
- Verify: `people` MCP tool with `taskFilter=INCOMPLETE`, filter for training.
- Pass: no active employees have incomplete training tasks.
- Blocker: overdue training, especially for privileged roles. Send reminders.

**6. Risk register reviewed within last 90 days**
- Verify: `risk_scenarios` MCP tool. Check for review timestamp < 90 days old.
- Pass: risk register has a recent review date.
- Blocker: stale register. Schedule review; prioritize risks linked to
  in-scope controls.

**7. Vendor security reviews current for in-scope vendors**
- Verify: `vendors` MCP tool. Check last security review date < 12 months.
- Pass: all in-scope vendors have a current security review.
- Blocker: stale or missing reviews. Prioritize vendors with access to
  sensitive data or production systems.

**8. Access reviews completed for the audit period**
- Verify: `tests` MCP tool filtered for access-review-related tests.
- Pass: access review tests pass for all in-scope integrations.
- Blocker: failing tests or incomplete review cycles. Run access reviews for
  flagged integrations.

**9. Change management logs available for the audit period**
- Verify: `tests` MCP tool filtered for change-management tests.
- Pass: tests pass; logs accessible via connected integration (GitHub, Jira).
- Blocker: failing tests or disconnected integrations. Reconnect and verify
  coverage for the full audit period.

**10. Incident response plan exists and has been tested**
- Verify: `documents` MCP tool for IR plan; `policies` for IR policy.
- Pass: IR plan exists, is current, policy is approved, and a tabletop
  exercise or drill occurred within 12 months.
- Blocker: missing plan, expired document, or untested plan. Schedule a
  tabletop exercise and upload results as evidence.

---

## Cross-Framework Overlap Analysis

Identify controls that satisfy multiple frameworks to prioritize remediation
for maximum audit coverage impact.

### Step 1: Enumerate Frameworks

Retrieve all frameworks via `frameworks` MCP tool or `GET /v1/frameworks`.
Record each framework's ID and name.

### Step 2: Collect Control-to-Framework Mapping

For each framework, retrieve controls via `controls` MCP tool filtered by
`frameworkMatchesAny`. Build a mapping of `controlId -> [frameworkIds]`.

### Step 3: Rank by Coverage Count

Sort controls by the number of frameworks they support (descending). Controls
appearing in more frameworks have higher remediation ROI.

### Step 4: Prioritize Failing High-Overlap Controls

Cross-reference the ranked list with test results. A failing control that
covers 4 frameworks has higher remediation priority than one covering 1.
Compute a priority score:

```
priority = framework_count x severity_multiplier
```

Where `severity_multiplier`:
- All tests failing = 3
- Some tests failing = 2
- Tests in NEEDS_ATTENTION/INVALID/IN_PROGRESS = 1

### Step 5: Present as a Matrix

Build a Controls x Frameworks matrix:

```
                  SOC 2   ISO 27001   HIPAA   PCI DSS
Control A           P         P         P        P
Control B           F         F         -        -
Control C           P         -         P        F
```

- `P` = all tests passing
- `F` = one or more tests failing
- `-` = control not mapped to this framework

This matrix shows which controls have the widest blast radius when failing
and which remediations unlock compliance across the most frameworks.

---

## Posture Trend Analysis

Compare current posture against previous assessments when historical data is
available.

**Availability note:** Vanta's API does not provide historical test results
natively. Trend analysis requires the user to have stored previous assessment
results (e.g., from a prior run of the Compliance Posture Analysis workflow).
If no historical data exists, skip this section and note that the current
assessment establishes the baseline.

### Comparison Method

1. Load the previous posture snapshot (user-provided or from a prior report).
2. Compute current scores using the methodology above.
3. Calculate deltas: `delta = current_score - previous_score`.
4. Flag improving areas (positive delta) and degrading areas (negative delta).
5. Highlight components that crossed a threshold boundary (e.g., green to
   yellow, or red to green).

### Presentation

- Show current vs. previous scores side-by-side with delta and direction.
- Call out the largest positive and negative changes.
- If a component degraded, cross-reference with gap identification patterns
  to surface the specific new gaps that caused the decline.
