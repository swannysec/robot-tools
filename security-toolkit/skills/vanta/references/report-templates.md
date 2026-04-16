# Report Templates

Fill placeholders (`{curly_braces}`) with live data from MCP tools or REST API.

---

## Table of Contents

- [Executive Compliance Summary](#executive-compliance-summary)
- [Audit Readiness Report](#audit-readiness-report)
- [Vulnerability SLA Report](#vulnerability-sla-report)
- [Personnel Compliance Report](#personnel-compliance-report)
- [Custom Report Guidance](#custom-report-guidance)

---

## Executive Compliance Summary

```markdown
# Compliance Posture Summary — {report_date}

## Overall Posture Score: {posture_score}%

Weighted across {framework_count} active frameworks.
## Framework Status

| Framework | Completeness | Control Coverage | Status |
|-----------|-------------:|----------------:|--------|
| {framework_name} | {completeness_pct}% | {coverage_pct}% | {status} |

Status values: **On Track** (>= 90%), **At Risk** (70–89%), **Critical** (< 70%).
## Top 5 Risks to Compliance

| # | Failing Control | Frameworks Affected | Current Pass Rate |
|---|----------------|--------------------:|------------------:|
| {rank} | {control_name} | {affected_count} | {pass_rate}% |

Ordered by cross-framework impact (controls affecting more frameworks rank higher).
## Remediation Priorities

1. **{priority_title}** — {priority_description}
## 30-Day Trend

{trend_note}
```

Omit "30-Day Trend" if no historical data is available. `posture_score` =
weighted average of framework completeness (weight by control count).

---

## Audit Readiness Report

```markdown
# Audit Readiness Report — {framework_name}

**Audit window:** {audit_start_date} to {audit_end_date}
**Generated:** {report_date}
**Readiness score:** {readiness_score}% ({items_passing} / {items_total} passing)

## Checklist Results

| Item | Status | Details |
|------|--------|---------|
| {checklist_item} | {PASS/FAIL/N-A} | {details} |

## Blockers

### Failing Tests

| Test | Control | Integration | Last Result |
|------|---------|-------------|-------------|
| {test_name} | {control_name} | {integration_name} | {last_result_date} |

### Missing Evidence

| Document | Control | Required By | Last Uploaded |
|----------|---------|-------------|---------------|
| {document_name} | {control_name} | {required_by_date} | {last_uploaded_date} |

### Policy Issues

| Policy | Issue | Affected People |
|--------|-------|----------------:|
| {policy_title} | {expired/not_accepted} | {affected_count} |

### Personnel Gaps

| Person | Issue | Due Date |
|--------|-------|----------|
| {person_name} | {overdue_training/missing_task} | {due_date} |

### Unmitigated Risks

| Risk Scenario | Severity | Linked Controls |
|---------------|----------|----------------:|
| {risk_name} | {severity} | {linked_control_count} |

## Remediation Sequence (dependency-aware, highest impact first)

1. **{step_title}** — {step_description}
   Owner: {owner_name} | Effort: {low/medium/high}
```

Compute `readiness_score` as (passing items / total) * 100. Omit blocker
subsections with zero entries. Set owner to "Unassigned" when unknown.

---

## Vulnerability SLA Report

```markdown
# Vulnerability SLA Report — {report_date}

## Summary by Severity

| Severity | Total Open | Within SLA | Approaching | Missed SLA |
|----------|----------:|-----------:|------------:|-----------:|
| Critical | {count} | {count} | {count} | {count} |
| High     | {count} | {count} | {count} | {count} |
| Medium   | {count} | {count} | {count} | {count} |
| Low      | {count} | {count} | {count} | {count} |

## Approaching SLA Deadlines

| Window | Count |
|--------|------:|
| Within 7 days | {count} |
| 7–14 days | {count} |
| 14–30 days | {count} |

## Missed SLAs

| Vulnerability ID | Severity | Days Overdue | Acknowledged |
|------------------|----------|-------------:|--------------|
| {vuln_id} | {severity} | {days_overdue} | {yes/no} |

## By Integration

| Integration | Critical | High | Medium | Low | Total |
|-------------|--------:|-----:|-------:|----:|------:|
| {integration_name} | {count} | {count} | {count} | {count} | {total} |

## Remediation Recommendations (by severity * days overdue, descending)

1. **{vuln_id}** ({severity}, {days_overdue}d overdue) — {recommendation}
```

Bucket each vulnerability into exactly one column: Within SLA, Approaching, or
Missed. Use severity-specific SLA windows configured in Vanta.

---

## Personnel Compliance Report

```markdown
# Personnel Compliance Report — {report_date}

## Summary

| Metric | Count |
|--------|------:|
| Total personnel in scope | {total_people} |
| Fully compliant | {compliant_count} |
| Non-compliant | {non_compliant_count} |

## Overdue Training

| Person | Training | Due Date | Days Overdue |
|--------|----------|----------|-------------:|
| {person_name} | {training_type} | {due_date} | {days_overdue} |

## Unsigned Policies

| Person | Policy | Sent Date |
|--------|--------|-----------|
| {person_name} | {policy_title} | {sent_date} |

## Outstanding Security Tasks

| Person | Task | Assigned Date |
|--------|------|---------------|
| {person_name} | {task_type} | {assigned_date} |

## Deactivated Personnel in Scope — Remove or Reactivate

| Person | Deactivated Date | Recommended Action |
|--------|------------------|--------------------|
| {person_name} | {deactivated_date} | {remove_from_scope/reactivate/investigate} |

## By Group

| Group | Total | Compliant | Non-Compliant |
|-------|------:|----------:|--------------:|
| {group_name} | {total} | {compliant} | {non_compliant} |
```

Omit "By Group" if groups are not configured. Omit any section with zero
entries. "Fully compliant" = all training complete, all policies signed, all
security tasks done.

---

## Custom Report Guidance

### Combining Data from Multiple Endpoints

Cross-cut reports pull from multiple resources. Common combinations:

| Report Goal | Endpoints / Tools to Combine |
|-------------|------------------------------|
| Control health with test details | `controls` + `tests` (join on control ID) |
| Framework gap with evidence status | `frameworks` + `controls` + `documents` |
| Vulnerability impact by integration | `vulnerabilities` + `integrations` |
| Personnel risk to audit readiness | `people` + `frameworks` + `policies` |

Retrieve the primary resource first, then fetch related resources by ID. The
Vanta API does not support cross-resource queries.

### Aggregation Patterns

- **Count by status:** Group results by status field, count per group.
- **Group by integration:** Partition by `integrationId`, then aggregate.
- **Bucket by date range:** Assign to time buckets (7d/14d/30d/90d), count per bucket.

### Pagination-Aware Data Collection

Paginate through **all pages** before computing aggregates — partial-page
aggregations produce incorrect totals. Set `pageSize=100`. Track rate limits
per `references/api-patterns.md`.

### Formatting Guidance

- **Markdown tables** for tabular data; **bullet lists** for qualitative findings.
- **Bold** for status labels (PASS, FAIL, On Track, Critical).
- Right-align numeric columns. Include report date and scope at the top.

### MCP Tools vs. REST API

| Scenario | Preferred Method |
|----------|-----------------|
| Simple list with basic filters | MCP tools (faster, no auth management) |
| Filters not exposed by MCP tools | REST API with query parameters |
| Multi-parameter filtering | REST API |
| Write operations | REST API only |
| Large paginated result sets | Either — both support cursor pagination |

Start with MCP tools when available. Fall back to REST API when MCP does not
expose the needed filter or for write operations.
