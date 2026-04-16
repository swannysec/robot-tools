# Manage Vanta API — Endpoint Reference

All REST endpoints under `https://api.vanta.com/v1/` organized by resource.
Auth: Bearer token (see `api-patterns.md`). All list endpoints support cursor
pagination (`pageSize`, `pageCursor`).

---

## Table of Contents

- [People](#people)
- [Controls](#controls)
- [Tests](#tests)
- [Frameworks](#frameworks)
- [Policies](#policies)
- [Documents](#documents)
- [Vulnerabilities](#vulnerabilities)
- [Vulnerable Assets](#vulnerable-assets)
- [Vendors](#vendors)
- [Risk Scenarios](#risk-scenarios)
- [Integrations](#integrations)
- [Trust Center](#trust-center)
- [Supplementary Endpoints](#supplementary-endpoints)

---

## People

### List People

```
GET /v1/people
```

**Filters:**

| Parameter | Values / Type | Description |
|-----------|---------------|-------------|
| `employmentStatus` | `UPCOMING`, `CURRENT`, `ON_LEAVE`, `INACTIVE`, `FORMER` | Filter by employment state |
| `groupIdsMatchesAny` | string[] | Filter by group membership (array of group IDs) |
| `tasksSummaryStatusMatchesAny` | string[] | Filter by task summary status |
| `taskTypeMatchesAny` | string[] | Filter by task type (requires `taskStatusMatchesAny`) |
| `taskStatusMatchesAny` | string[] | Filter by task status (requires `taskTypeMatchesAny`) |
| `emailAndNameFilter` | string | Partial match on email or display name |

**Response fields:** `id`, `email`, `displayName`, `employmentStatus`, `isActive`.

### Update Person (WRITE — requires user confirmation)

```
PATCH /v1/people/{personId}
```

Update person metadata. Body contains fields to modify.

### List Groups

```
GET /v1/groups
```

Returns group names and IDs for use as `groupIdsMatchesAny` filter above.

### List Group Members

```
GET /v1/groups/{groupId}/people
```

Returns people belonging to a specific group.

---

## Controls

### List Controls

```
GET /v1/controls
```

**Filters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `frameworkMatchesAny` | string[] | Controls mapped to specific frameworks (array of framework IDs) |

**Response fields:** `name`, `description`, `controlCategory`, `ownerId`, `status`.

### List Controls Library

```
GET /v1/controls/controls-library
```

Returns Vanta's built-in control library for use with add-from-library.

### List Control Tests

```
GET /v1/controls/{controlId}/tests
```

Returns tests linked to a specific control.

### List Control Documents

```
GET /v1/controls/{controlId}/documents
```

Returns documents linked to a specific control.

### Create Custom Control (WRITE — requires user confirmation)

```
POST /v1/controls
```

**Body:** `externalId` (required), `name` (required), `description` (required),
`effectiveDate` (required), `domain` (required, enum).

### Add Control from Library (WRITE — requires user confirmation)

```
POST /v1/controls/add-from-library
```

**Body:** `controlId` (required). Add a control from Vanta's built-in library.

### Set Control Owner (WRITE — requires user confirmation)

```
POST /v1/controls/{controlId}/set-owner
```

**Body:** `userId` (required).

---

## Tests

### List Tests

```
GET /v1/tests
```

**Filters:**

| Parameter | Values / Type | Description |
|-----------|---------------|-------------|
| `statusFilter` | `OK`, `NEEDS_ATTENTION`, `DEACTIVATED`, `IN_PROGRESS`, `INVALID`, `NOT_APPLICABLE` | Test outcome status |
| `frameworkFilter` | string | Tests mapped to a framework |
| `integrationFilter` | string | Tests tied to an integration |
| `controlFilter` | string | Tests linked to a control |
| `categoryFilter` | string (17 defined values) | Category grouping |
| `ownerFilter` | string | Assigned owner |
| `isInRollout` | boolean | Currently in rollout |

**Response fields:** `name`, `description`, `status`, `remediation`,
`outcomeControlIds`, `integrationId`.

**Status values:** `OK` = passing, `NEEDS_ATTENTION` = failing/needs action,
`DEACTIVATED` = disabled, `IN_PROGRESS` = evaluating, `INVALID` = cannot evaluate,
`NOT_APPLICABLE` = not relevant to this environment.

### List Test Entities

```
GET /v1/tests/{testId}/entities
```

**Filters:** `entityStatus` (`FAILING`, `DEACTIVATED`).

Returns individual entities evaluated by the test: `entityId`, `status`,
`resourceInfo`.

### Reactivate Test Entity (WRITE — requires user confirmation)

```
POST /v1/tests/{testId}/entities/{entityId}/reactivate
```

Re-enable a previously deactivated test entity. Returns 202 Accepted.

---

## Frameworks

### List Frameworks

```
GET /v1/frameworks
```

No filters besides pagination. Returns all compliance frameworks configured.

**Response fields:** `name`, `id`, `description`.

**Common frameworks:** SOC 2, ISO 27001, HIPAA, PCI DSS, GDPR, NIST CSF 2.0,
NIST 800-53, NIST 800-171, CMMC 2.0, FedRAMP, FedRAMP 20x, HITRUST, SOX ITGC,
DORA, NIS 2, EU AI Act, ISO 42001, NIST AI RMF, CIS v8.1, Custom Frameworks.

Use the returned `id` as the `frameworkFilter` on Tests or `frameworkMatchesAny`
on Controls and Documents.

---

## Policies

### List Policies

```
GET /v1/policies
```

**Response fields:** `title`, `status`, `version`, `approvedDate`, `cadence`.

### Get Policy

```
GET /v1/policies/{policyId}
```

Returns full policy details by ID.

---

## Documents

### List Documents

```
GET /v1/documents
```

**Filters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `frameworkMatchesAny` | string[] | Documents linked to specific frameworks |
| `statusMatchesAny` | string[] | Filter by document status |

**Response fields:** `name`, `documentType`, `status`, `uploadedDate`, `cadence`.

### Get Document

```
GET /v1/documents/{documentId}
```

Returns full document details by ID.

### Create Document (WRITE — requires user confirmation)

```
POST /v1/documents
```

**Body:** `title` (required), `description` (required), `timeSensitivity` (required),
`cadence` (required), `reminderWindow` (required), `isSensitive` (required).

### Upload Evidence (WRITE — requires user confirmation)

```
POST /v1/documents/{documentId}/uploads
```

**Content-Type:** `multipart/form-data` (not JSON). Attach file in form body.

### Delete Document (WRITE — requires user confirmation)

```
DELETE /v1/documents/{documentId}
```

Returns 204 No Content. **Destructive** — cannot be undone.

---

## Vulnerabilities

### List Vulnerabilities

```
GET /v1/vulnerabilities
```

**Filters:**

| Parameter | Values / Type | Description |
|-----------|---------------|-------------|
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` | Severity level |
| `integrationId` | string | Source integration |
| `isDeactivated` | boolean | Filter active vs. deactivated |
| `slaDeadlineBeforeDate` | ISO 8601 date | SLA deadline before this date |
| `slaDeadlineAfterDate` | ISO 8601 date | SLA deadline after this date |
| `externalVulnerabilityId` | string | External ID (e.g., CVE identifier) |
| `isFixAvailable` | boolean | Patch/fix exists |
| `vulnerableAssetId` | string | Filter by specific asset |
| `includeVulnerabilitiesWithoutSlas` | boolean | Include vulns without SLA deadlines |
| `q` | string | Search query |
| `packageIdentifier` | string | Filter by package |

**Response fields:** `title`, `severity`, `status`, `remediateByDate` (SLA deadline),
`externalVulnerabilityId`, `integrationId`.

**Note:** SLA changes only affect newly detected vulnerabilities. Historical items
keep their original SLA deadlines.

### Acknowledge SLA Miss (WRITE — requires user confirmation)

```
POST /v1/vulnerability-remediations/acknowledge-sla-miss
```

**Body:** `updates` (required, array of 1-50 objects). Each object:
- `id` (required) — vulnerability ID
- `slaViolationComment` (required) — reason for acknowledgment

---

## Vulnerable Assets

### List Vulnerable Assets

```
GET /v1/vulnerable-assets
```

**Filters:** `q`, `integrationId`, `assetType`, `assetExternalAccountId`.

Returns assets affected by vulnerabilities.

### Get Vulnerable Asset

```
GET /v1/vulnerable-assets/{vulnerableAssetId}
```

Returns details for a specific vulnerable asset.

---

## Vendors

### List Vendors

```
GET /v1/vendors
```

**Filters:** `name`, `statusMatchesAny` (array).

**Response fields:** `name`, `riskLevel`, `securityReviewStatus`,
`lastReviewDate`, `category`.

### Create Vendor (WRITE — requires user confirmation)

```
POST /v1/vendors
```

Extensive body parameters for vendor details.

### Update Vendor (WRITE — requires user confirmation)

```
PATCH /v1/vendors/{vendorId}
```

### Add Vendor Finding (WRITE — requires user confirmation)

```
POST /v1/vendors/{vendorId}/findings
```

**Body:** `content` (required), `riskStatus` (required), optional `remediation`,
`securityReviewId`, `documentId`.

---

## Risk Scenarios

### List Risk Scenarios

```
GET /v1/risk-scenarios
```

**Response fields:** `name`, `severity`, `status`, `linkedControlIds`.

Risk scoring uses a 5x5 matrix (Likelihood x Impact) producing Inherent Risk
and Residual Risk scores. Treatment options: Accept, Transfer, Mitigate, Avoid.
Status workflow: Draft → Needs Review → Pending Approval → Approved.

### Create Risk Scenario (WRITE — requires user confirmation)

```
POST /v1/risk-scenarios
```

**Body:** `description` (required), plus many optional fields.

### Submit for Approval (WRITE — requires user confirmation)

```
POST /v1/risk-scenarios/{riskScenarioId}/submit-for-approval
```

**Body:** `comment` (optional).

### Cancel Approval Request (WRITE — requires user confirmation)

```
POST /v1/risk-scenarios/{riskScenarioId}/cancel-approval-request
```

---

## Integrations

### List Integrations

```
GET /v1/integrations
```

**Response fields:** `name`, `type`, `status`, `resourceKinds`.

### Get Integration

```
GET /v1/integrations/{integrationId}
```

Returns full integration details by ID.

### List Resource Kinds

```
GET /v1/integrations/{integrationId}/resource-kinds
```

Returns the types of resources monitored by this integration.

### List Resources

```
GET /v1/integrations/{integrationId}/resource-kinds/{resourceKind}/resources
```

Returns individual resources of a specific kind within an integration.

### Update Resources (WRITE — bulk, requires user confirmation)

```
PATCH /v1/integrations/{integrationId}/resource-kinds/{resourceKind}/resources
```

**Body:** `updates` (required, array of 1-50 objects). Each object:
- `id` (required) — resource ID
- `ownerId` (optional)
- `description` (optional)
- `inScope` (optional, boolean)

Bulk endpoint — sends multiple resource updates in one request.
See `api-patterns.md` for batch strategy.

---

## Trust Center

All trust center endpoints are scoped by `slugId` (the trust center's URL slug).

### Get Trust Center Settings

```
GET /v1/trust-centers/{slugId}
```

Returns trust center configuration.

### Update Trust Center Settings (WRITE — requires user confirmation)

```
PATCH /v1/trust-centers/{slugId}
```

### List Controls

```
GET /v1/trust-centers/{slugId}/controls
```

Returns trust center controls with their categories.

### Create Control Category (WRITE — requires user confirmation)

```
POST /v1/trust-centers/{slugId}/control-categories
```

### List Subprocessors

```
GET /v1/trust-centers/{slugId}/subprocessors
```

Returns subprocessor list published on the trust center.

### Get Activity Log

```
GET /v1/trust-centers/{slugId}/activity
```

Returns trust center activity/audit log.

### Additional Trust Center Endpoints

- `GET /v1/trust-centers/{slugId}/viewers/{viewerId}` — Viewer details
- `GET /v1/trust-centers/{slugId}/faqs/{faqId}` — FAQ entry
- `GET /v1/trust-centers/{slugId}/access-request` — Access request details

---

## Supplementary Endpoints

Lightweight read-only endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /v1/monitored-computers` | Devices tracked by Vanta agent installations |
| `GET /v1/discovered-vendors` | Auto-discovered vendors from integrations. Filters: `scope` (NEEDS_REVIEW, IGNORED, REJECTED) |
| `GET /v1/vendor-risk-attributes` | Vendor risk attribute definitions |
| `GET /v1/groups/{groupId}/people` | Members of a specific group |
