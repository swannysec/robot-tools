---
name: vanta
description: |
  Vanta compliance platform operations — posture analysis, audit readiness,
  vulnerability management, personnel compliance, and flexible reporting.
  Complements the official vanta-mcp-plugin with analysis workflows,
  direct API access for write operations, and reporting capabilities
  not available in the Vanta UI.

  50% compliance analysis/reporting, 30% API operations, 20% workflow orchestration.

  Use this skill when users need to:
  (1) Assess compliance posture across frameworks (gap analysis, control coverage,
      cross-framework overlap)
  (2) Prepare for audits (readiness checklist, missing evidence, policy expiry,
      personnel compliance)
  (3) Track and triage vulnerabilities with SLA awareness (approaching deadlines,
      missed SLAs, severity breakdown)
  (4) Monitor personnel compliance (overdue training, policy acceptance,
      deactivated personnel in scope)
  (5) Generate compliance reports and executive summaries (posture, readiness,
      vulnerability SLA, personnel, custom)
  (6) Perform bulk low-risk operations (set control owners, acknowledge SLA
      misses, reactivate test entities, update person metadata)
  (7) Understand risk and vendor impact on audit readiness (unmitigated risks,
      stale vendor reviews, risk-control linkage)
  (8) Query Vanta data that is hard to surface in the Vanta UI (cross-framework
      control overlap, integration resource inventory, historical test status)
triggers:
  - "vanta"
  - "vanta compliance"
  - "vanta audit"
  - "compliance posture"
  - "audit readiness"
  - "vanta tests"
  - "vanta controls"
  - "vanta vulnerabilities"
  - "vanta frameworks"
  - "vanta personnel"
  - "vanta people"
  - "compliance gap"
  - "compliance report"
  - "vanta api"
  - "vanta mcp"
  - "failing tests vanta"
  - "vulnerability sla"
  - "control owner"
  - "vanta risk"
  - "vanta vendor audit"
  - "evidence collection"
  - "policy expiry"
  - "access review vanta"
---

# Vanta Compliance Operations

Compliance posture analysis, audit readiness, and operational workflows for the
Vanta platform. Complements the official vanta-mcp-plugin.

---

## Help — Topic Navigator

Use this table to find the right reference file. Load references **only when
needed** for the user's specific question.

| Topic | Reference File | Covers |
|-------|---------------|--------|
| Vanta REST API endpoints | `references/api-manage-vanta.md` | All Manage Vanta endpoints by resource: people, controls, tests, frameworks, policies, documents, vulnerabilities, vendors, risk scenarios, integrations, trust center |
| Compliance analysis methods | `references/compliance-analysis.md` | Posture scoring methodology, gap identification patterns, audit readiness checklist, cross-framework overlap analysis |
| Report templates | `references/report-templates.md` | Executive summary, audit readiness report, vulnerability SLA report, personnel compliance report, custom report guidance |
| Auth, pagination, rate limits | `references/api-patterns.md` | OAuth client credentials flow, cursor pagination, rate limits and backoff, error handling, request headers, batch strategies |
| MCP tools reference | `references/mcp-tools-reference.md` | All MCP tools from Vanta hosted server and plugin, tool parameters, usage examples, REST API fallback mapping |

---

## Prerequisites

- A **Vanta account** with **Admin role** (the MCP server requires Admin access;
  non-admin access is not yet available)
- **Claude Code** CLI installed
- For Path A: the **vanta-mcp-plugin** (handles MCP reads)
- For Path B: a **Vanta API application** with client credentials (handles writes
  and standalone API access)
- For write operations, both Path A and Path B are needed

> **Note:** Vanta's remote MCP server is currently in beta.

## Quick Start — Auth Setup

### Path A: Install vanta-mcp-plugin (recommended for reads)

**Option 1 — Install the plugin (recommended):**
```
/plugin marketplace add VantaInc/vanta-mcp-plugin
/plugin install vanta
/reload-plugins
```
Then authenticate by running `/mcp` and selecting `vanta-*` for your region
(US/EU/AUS). A browser window opens — click **Allow** to complete OAuth.

This adds MCP tools plus the `/vanta:fix-test` and `/vanta:list-tests` commands.

**Option 2 — Manual MCP configuration (without plugin commands):**
Add to your MCP settings (`.mcp.json` or Claude Code MCP config):
```json
{
  "vanta-us": {
    "type": "http",
    "url": "https://mcp.vanta.com/mcp"
  }
}
```
Use `vanta-eu` with `mcp.eu.vanta.com/mcp` for EU, or `vanta-aus` with
`mcp.aus.vanta.com/mcp` for AUS. Then run `/mcp` to authenticate via OAuth.

This gives MCP tools but not the plugin's slash commands.

**Verify:** Check if the `tests` MCP tool is available. If it responds, MCP is
configured.

MCP tools are **read-only**. For write operations, also configure Path B.

### Path B: Client credentials (for writes or standalone use)

1. In Vanta, go to **Settings → API → Create Application**.
2. Select application type: **Manage Vanta**.
3. Grant scopes: `vanta-api.all:read` and `vanta-api.all:write`.
   For document uploads, also grant `vanta-api.documents:upload`.
4. Save `client_id` and `client_secret` to a JSON file:
   ```json
   {"client_id": "...", "client_secret": "..."}
   ```
5. Set the environment variable: `VANTA_CREDENTIALS_FILE=/path/to/credentials.json`
6. Token exchange: `POST https://api.vanta.com/oauth/token` with JSON body
   (`Content-Type: application/json`).
   Read `references/api-patterns.md` for the full OAuth flow and all available scopes.

**IMPORTANT — token isolation:** Vanta enforces a single active token per API
application. If the MCP plugin holds a token from the same application, requesting
a new token for writes will revoke it. Use a **separate Vanta API application**
for client-credentials writes.

### Detection logic

```
IF MCP tool `tests` is available → use MCP for reads
IF VANTA_CREDENTIALS_FILE is set → use REST API for writes + fallback reads
IF neither → guide user through setup (Path A or B above)
```

---

## Workflows

### 1. Compliance Posture Analysis

Assess overall compliance health across all frameworks.

1. List all frameworks. For each, retrieve controls and tests.
2. Aggregate pass/fail/deactivated test counts per framework.
3. Identify controls with failing tests — prioritize by cross-framework coverage
   (a failing control that appears in 3 frameworks is higher priority than one in 1).
4. Compute cross-framework overlap: which controls satisfy multiple frameworks.
5. Output posture summary with framework-by-framework breakdown.

Read `references/compliance-analysis.md` before running this workflow. This is
mandatory — it contains the scoring methodology and gap identification patterns.

### 2. Audit Readiness Assessment

Determine readiness for a specific framework audit within a target window.

1. Select target framework and audit window (date range).
2. Retrieve all controls, tests, documents, and policies for the framework.
3. Check readiness criteria:
   - % controls with at least one passing test
   - % required documents uploaded and current (not expired)
   - % policies approved and accepted by employees
   - No CRITICAL/HIGH vulnerabilities past SLA deadline
   - All personnel have completed required security training
   - Risk register reviewed within last 90 days
   - Vendor security reviews current for in-scope vendors
4. Identify blockers: failing tests, missing evidence, overdue renewals.
5. Prioritize blockers by audit impact (blocking vs. advisory).
6. Output readiness report with remediation sequence.

Read `references/compliance-analysis.md` for the audit readiness checklist.
Read `references/report-templates.md` for the report format.

### 3. Vulnerability Management

Track, triage, and report on vulnerability SLA compliance.

1. List vulnerabilities. Filter by severity, SLA deadline, integration, or status.
2. Bucket by SLA timeline: approaching (7d, 14d, 30d) and missed.
3. Group by integration or asset type for remediation planning.
4. For missed SLAs: batch-acknowledge with user confirmation (low-risk write).
5. Output vulnerability triage report with SLA timeline.

Read `references/report-templates.md` for the vulnerability SLA report template.

### 4. Personnel Compliance

Monitor training, policy acceptance, and personnel scope.

1. List people. Filter by employment status, group, or task completion.
2. Identify overdue items: incomplete training, unsigned policies, outstanding tasks.
3. Flag deactivated personnel still appearing in compliance scope.
4. For metadata corrections: update person records with user confirmation.
5. Output personnel compliance report.

Read `references/report-templates.md` for the personnel compliance report template.

### 5. Flexible Reporting

Generate custom reports from any combination of Vanta data.

1. User describes what they want to know.
2. Select appropriate endpoints or MCP tools based on the question.
3. Apply filters, cursor pagination, and aggregation as needed.
4. Format results into a structured report.

Read `references/report-templates.md` for report templates and custom report
guidance. Read `references/api-manage-vanta.md` for available endpoints and
filter parameters.

### 6. Risk & Vendor Impact on Audit Readiness

Assess how risk scenarios and vendor relationships affect audit posture.

1. List risk scenarios. Identify unmitigated high-severity risks.
2. Check risk-control linkage: are high-severity risks covered by passing controls?
3. List vendors in framework scope. Flag stale security reviews (last review > 1 year).
4. Assess vendor risk attributes and their impact on controls.
5. Output risk/vendor impact summary scoped to the target framework.

**Note:** Full risk management (create, score, approve, treat) and full vendor
management (create, assess, findings) are future enhancements. This workflow
covers read-only analysis of existing risk and vendor data.

---

## Write Operations Reference

All write operations require **explicit user confirmation** before execution.
Present the operation details, ask for confirmation, then execute.

| Operation | Method & Endpoint | Key Parameters |
|-----------|-------------------|----------------|
| Set control owner | `POST /v1/controls/{id}/set-owner` | `userId` (person ID) |
| Acknowledge vulnerability SLA miss | `POST /v1/vulnerability-remediations/acknowledge-sla-miss` | `updates[]` with `id` + `slaViolationComment` (batch 1-50) |
| Reactivate test entity | `POST /v1/tests/{testId}/entities/{entityId}/reactivate` | — (returns 202) |
| Update person metadata | `PATCH /v1/people/{personId}` | Fields to update |
| Update integration resources | `PATCH /v1/integrations/{id}/resource-kinds/{kind}/resources` | `updates[]` with `id`, `ownerId`, `inScope` (bulk 1-50) |

Respect rate limits for batch operations — read `references/api-patterns.md` for
rate limit values and exponential backoff strategy.

---

## Data Model Quick Reference

Key Vanta entities and their relationships:

```
Framework
  └── Controls
        ├── Tests → Test Entities
        └── Documents

People
  ├── Groups → Task Sets → Tasks
  └── Task types: Background Check, Accept Policies, Device Monitoring,
      Security & Privacy Training, Access Removal, Custom Tasks

Vulnerabilities
  └── Vulnerable Assets → Integrations

Vendors
  └── Security Reviews → Documents

Risk Scenarios ←→ Controls (linkage)
  └── Status: Draft → Needs Review → Pending Approval → Approved
  └── Treatment: Accept, Transfer, Mitigate, Avoid

Integrations → Resource Kinds → Resources
```

Use this to navigate the data model when constructing queries. For full endpoint
details, read `references/api-manage-vanta.md`.

---

## Future Enhancements

These capabilities are not implemented in v1 but the architecture supports them:

- **Full vendor risk management** — create vendors, assessments, findings, custom fields
- **Full risk management** — create, score, approve, cancel risk scenarios with treatment plans
- **Linear integration** — create Linear issues from failing tests or overdue vulnerabilities
- **Document upload workflows** — evidence management with approval workflows
- **Auditor API workflows** — separate application type with audit-specific scopes and queries
- **Questionnaire assistance** — leverage QAuto patterns for vendor questionnaires
- **Webhook delta sync** — use `changedSinceDate` parameter for incremental data polling
- **Trust Center management** — settings, access requests, content, subprocessor lists

---

## Runtime Reinforcement

These rules are critical — follow them throughout every workflow:

1. **MCP first, API fallback.** Always use MCP tools for reads when available.
   Fall back to REST API only when MCP tools are unavailable or for write operations.
2. **All writes require confirmation.** Never execute a write operation without
   presenting the details and receiving explicit user confirmation.
3. **Respect rate limits.** Management: 50/min. Auth: 5/min. Integrations: 20/min.
   On 429 response, apply exponential backoff (1s, 2s, 4s, ...).
4. **Single active token.** Never request a new token while one is in-flight.
   Use a separate API application for client-credentials writes if MCP plugin is active.
5. **Distinguish "no data" from "API error."** An empty result set means no
   matching records. A non-200 response means the query failed — report the error,
   do not report "none found."
