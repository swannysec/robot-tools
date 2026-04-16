# Vanta MCP Tools Reference

Quick reference for all MCP tools available through the Vanta hosted server and
the vanta-mcp-plugin, with REST API fallback mapping.

---

## Table of Contents

1. [Hosted Server Tools](#hosted-server-tools) — 14 enabled tools from `mcp.vanta.com`
2. [Plugin-Exclusive Tools](#plugin-exclusive-tools) — Tools added by vanta-mcp-plugin
3. [REST API Fallback Mapping](#rest-api-fallback-mapping) — Endpoint equivalents when MCP is unavailable
4. [Regional Endpoints](#regional-endpoints)

---

## Hosted Server Tools

The vanta-mcp-plugin connects to Vanta's hosted remote MCP server. The source
repo (`VantaInc/vanta-mcp-server`) defines 45 tools across 17 modules, but only
**14 are enabled** by default via a whitelist in `config.ts`. The hosted server
may enable additional tools over time.

### tests

List or get compliance tests with optional filters.

- **Parameters:** `testId` (optional — get single test), `statusFilter`, `frameworkFilter`, `integrationFilter`, `pageSize`, `pageCursor`
- **Returns:** Test name, status, description, remediation info
- **Status values:** `OK`, `NEEDS_ATTENTION`, `DEACTIVATED`, `IN_PROGRESS`, `INVALID`, `NOT_APPLICABLE`

### list_test_entities

List entities evaluated by a specific test.

- **Parameters:** `testId` (required), `pageSize`, `pageCursor`
- **Returns:** Entity ID, status, resource info
- **Entity statuses:** `FAILING`, `DEACTIVATED`

### controls

List or get controls with optional framework filter.

- **Parameters:** `controlId` (optional), `frameworkMatchesAny` (optional, array of strings), `pageSize`, `pageCursor`
- **Returns:** Control name, description, status, owner

### list_control_tests

List tests linked to a specific control.

- **Parameters:** `controlId` (required), `pageSize`, `pageCursor`

### list_control_documents

List documents linked to a specific control.

- **Parameters:** `controlId` (required), `pageSize`, `pageCursor`

### people

List or get personnel with task filters.

- **Parameters:** `personId` (optional), `taskStatusMatchesAny` (optional, array), `pageSize`, `pageCursor`
- **Returns:** Person details, group membership, task status

### frameworks

List or get compliance frameworks.

- **Parameters:** `frameworkId` (optional), `pageSize`, `pageCursor`
- **Returns:** Framework name, ID, description

### list_framework_controls

List controls mapped to a specific framework.

- **Parameters:** `frameworkId` (required), `pageSize`, `pageCursor`

### vulnerabilities

List or get vulnerabilities with filters.

- **Parameters:** `vulnerabilityId` (optional), `externalVulnerabilityId` (optional), `severity` (optional), `integrationId` (optional), `slaDeadlineAfter` (optional), `slaDeadlineBefore` (optional), `pageSize`, `pageCursor`
- **Returns:** Vulnerability details, severity, SLA status

### documents

List or get compliance documents with filters.

- **Parameters:** `documentId` (optional), `frameworkMatchesAny` (optional, array), `statusMatchesAny` (optional, array), `pageSize`, `pageCursor`
- **Returns:** Document metadata, status, cadence

### document_resources

List resources linked to a document (controls, links, or uploads).

- **Parameters:** `documentId` (required), `resourceType` (required, enum: `controls`/`links`/`uploads`), `pageSize`, `pageCursor`

### integrations

List or get connected integrations.

- **Parameters:** `integrationId` (optional), `pageSize`, `pageCursor`
- **Returns:** Integration name, type, connection status

### integration_resources

Explore integration resource hierarchy.

- **Parameters:** `integrationId` (required), `operation` (required, enum: `list_kinds`/`get_kind_details`/`list_resources`/`get_resource`), `resourceKind` (optional), `resourceId` (optional), `pageSize`, `pageCursor`

### risks

List or get risk register entries.

- **Parameters:** `riskId` (optional), `pageSize`, `pageCursor`
- **Returns:** Risk scenario description, severity, linked controls

### Tools NOT Enabled on Hosted Server

These tools exist in the source code but are **not enabled** by default. They may
become available as Vanta updates the hosted server:

`policies`, `vendors`, `vendor_compliance`, `get_vendor_security_review`,
`list_vendor_security_review_documents`, `groups`, `list_group_people`,
`monitored_computers`, `list_discovered_vendors`, `list_discovered_vendor_accounts`,
`list_vulnerability_remediations`, `vulnerable_assets`, `list_vendor_risk_attributes`,
`download_document_file`, `list_library_controls`, and 16 trust center tools.

For these resources, use the REST API directly (see `api-manage-vanta.md`).

---

## Plugin-Exclusive Tools

The vanta-mcp-plugin (`VantaInc/vanta-mcp-plugin`) adds these capabilities on
top of the hosted server tools.

### getAgentRemediationPrompt

Return a structured remediation prompt for a specific failing test entity. This
is the plugin's primary value-add — it provides rich, actionable context for
fixing compliance failures.

- **Parameters:** `testId`, `entityId` (both required)
- **Returns:** `{ systemPrompt, userMessage, entityContext }`
- **Use for:** Test remediation workflows
- **Note:** This tool is served by the remote MCP server, not defined in the
  open-source repo. Parameter and response schema are inferred from plugin usage.
- **No REST equivalent.**

### Plugin Commands (not MCP tools)

- **`/vanta:fix-test`** — Accepts test ID or Vanta test URL. Calls `getAgentRemediationPrompt`, then follows the returned prompt.
- **`/vanta:list-tests`** — Fetches failing tests via `tests` tool with status `NEEDS_ATTENTION`, categorizes into priority tiers.

---

## REST API Fallback Mapping

When MCP tools are unavailable, use these REST API endpoints. Base URL:
`https://api.vanta.com`. Read `api-patterns.md` for auth, pagination, and rate limits.

**MCP tool names use `snake_case`; REST endpoints use `kebab-case`.**

| MCP Tool | REST Endpoint | Notes |
|----------|---------------|-------|
| `tests` | `GET /v1/tests` | Filters as query params |
| `list_test_entities` | `GET /v1/tests/{testId}/entities` | |
| `controls` | `GET /v1/controls` | Use `frameworkMatchesAny` query param |
| `list_control_tests` | `GET /v1/controls/{controlId}/tests` | |
| `list_control_documents` | `GET /v1/controls/{controlId}/documents` | |
| `people` | `GET /v1/people` | |
| `frameworks` | `GET /v1/frameworks` | |
| `list_framework_controls` | `GET /v1/frameworks/{frameworkId}/controls` | |
| `vulnerabilities` | `GET /v1/vulnerabilities` | 11 filter parameters |
| `documents` | `GET /v1/documents` | |
| `document_resources` | `GET /v1/documents/{documentId}/{resourceType}` | |
| `integrations` | `GET /v1/integrations` | |
| `integration_resources` | `GET /v1/integrations/{id}/resource-kinds/...` | Nested hierarchy |
| `risks` | `GET /v1/risk-scenarios` | |
| `getAgentRemediationPrompt` | **No REST equivalent** | Plugin-exclusive |

### When to Use REST Over MCP

- MCP tools are unavailable or the plugin is not installed
- Write operations (MCP tools are read-only)
- Resources with no enabled MCP tool (policies, vendors, groups, trust center)
- Queries needing parameters not exposed by the MCP tool interface

---

## Regional Endpoints

The hosted MCP server has three regional endpoints:

| Region | URL |
|--------|-----|
| US | `https://mcp.vanta.com/mcp` |
| EU | `https://mcp.eu.vanta.com/mcp` |
| AUS | `https://mcp.aus.vanta.com/mcp` |

The vanta-mcp-plugin configures all three; users select their region during setup.
