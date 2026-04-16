# API Patterns Reference

Auth, pagination, rate limits, error handling, and batch strategies for the
Vanta REST API.

---

## Table of Contents

- [OAuth Client Credentials Flow](#oauth-client-credentials-flow)
- [Cursor Pagination](#cursor-pagination)
- [Rate Limits](#rate-limits)
- [Error Handling](#error-handling)
- [Request Headers](#request-headers)
- [API Application Types](#api-application-types)
- [Batch Strategies](#batch-strategies)

---

## OAuth Client Credentials Flow

### Token Request

```
POST https://api.vanta.com/oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "scope": "vanta-api.all:read vanta-api.all:write"
}
```

Use `application/json` with a JSON body. Scopes are space-separated.

### Token Response

```json
{
  "access_token": "vat_...",
  "token_type": "Bearer",
  "expires_in": 3599
}
```

Token is valid for ~1 hour (3599 seconds).

### Refresh Strategy

- Track token acquisition time.
- Request a new token when remaining lifetime falls below 60 seconds.
- Do NOT wait for a 401 to refresh — proactively rotate before expiry.

### Token Isolation Warning

Vanta enforces a **single active token per API application**. Requesting a new
token immediately revokes the previous one.

- If the vanta-mcp-plugin holds a token from the same application, requesting
  a client-credentials token will revoke the plugin's token.
- The plugin will begin returning 401 errors until it re-authenticates.

**Recommendation:** Create a separate Vanta API application for
client-credentials writes. Keep the MCP plugin on its own application.

---

## Cursor Pagination

### Query Parameters

| Parameter | Type | Range | Default | Description |
|-----------|------|-------|---------|-------------|
| `pageSize` | integer | 1–100 | 10 | Results per page |
| `pageCursor` | string | — | — | Cursor from previous response |

### Response Shape

```json
{
  "results": {
    "data": [ ... ],
    "pageInfo": {
      "endCursor": "eyJpZCI6Ii...",
      "hasNextPage": true
    }
  }
}
```

### Pagination Loop

```
SET pageCursor = null
LOOP:
  REQUEST with pageSize=100, pageCursor=pageCursor
  PROCESS results.data
  IF results.pageInfo.hasNextPage == false → BREAK
  SET pageCursor = results.pageInfo.endCursor
```

---

## Rate Limits

### Limits by Endpoint Category

| Category | Limit | Applies To |
|----------|-------|------------|
| Management API | 50 requests/minute | All `/v1/` endpoints (people, controls, tests, etc.) |
| OAuth token | 5 requests/minute | `POST /oauth/token` |
| Integration endpoints | 20 requests/minute | `/v1/integrations/` resource endpoints |

### Exponential Backoff

On `429 Too Many Requests`:

1. Read the `Retry-After` header if present — use that value as the wait time.
2. If absent, apply exponential backoff: 1s, 2s, 4s, 8s, 16s (cap at 30s).
3. After 5 consecutive 429 responses, stop and report the rate limit issue.

Track requests per category independently — management API calls do not
consume integration endpoint quota.

---

## Error Handling

### Status Code Reference

| Code | Meaning | Action |
|------|---------|--------|
| 400 | Bad Request — malformed query parameters or body | Fix request and retry |
| 401 | Unauthorized — token expired or invalid | Refresh token, retry once |
| 403 | Forbidden — missing required scope | Check API application scope configuration |
| 404 | Not Found — resource does not exist | Verify resource ID; report to user |
| 422 | Unprocessable Entity — business logic rejection | Report rejection reason to user |
| 429 | Too Many Requests — rate limited | Apply backoff strategy (see above) |
| 500+ | Server error | Wait 5s, retry once; report if persistent |

### Token Refresh on 401

```
ON 401 response:
  IF already retried with fresh token → report auth failure, STOP
  ELSE → request new token → retry original request once
```

Do NOT loop on 401. A second 401 after a fresh token indicates a configuration
problem (wrong scopes, revoked application, or token isolation conflict).

### Distinguishing Empty Results from Errors

- HTTP 200 with `results.data: []` → no matching records exist.
- HTTP 4xx/5xx → the query failed. Report the error code and message body.

Never report "none found" when the API returned an error.

---

## Request Headers

| Context | Authorization | Content-Type | Accept |
|---------|---------------|--------------|--------|
| API calls | `Bearer {access_token}` | `application/json` | `application/json` |
| Token request | *(omit)* | `application/json` | `application/json` |

Do NOT send an `Authorization` header on the token request — credentials are
in the JSON body.

---

## API Application Types

Vanta offers three API application types. This skill uses **Manage Vanta**.

| Type | Purpose | Scopes |
|------|---------|--------|
| **Manage Vanta** | Full compliance data access + writes | `vanta-api.all:read`, `vanta-api.all:write`, `vanta-api.documents:upload`, `vanta-api.vendors:read`, `vanta-api.vendors:write` |
| **Build Integrations** | Sync data from external systems into Vanta | Separate integration-specific scopes |
| **Conduct an Audit** | Auditor access to audit-specific endpoints | Separate auditor-specific scopes |

---

## Batch Strategies

### Vulnerability SLA Acknowledge

- Endpoint accepts an `updates` array of 1-50 objects per request.
- Each object requires `id` (vulnerability ID) and `slaViolationComment` (string).
- Partition larger sets into batches of 50.
- Pause between batches if approaching the 50/min management limit.

### Integration Resource Updates

- Bulk PATCH endpoint accepts an `updates` array of 1-50 items.
- Each item requires `id` (resource ID), optional `ownerId`, `description`, `inScope`.
- Partition larger sets into batches of 50.

### Pagination Collection (Bulk Reads)

- Set `pageSize=100` to minimize page count.
- Each page consumes one request against the rate limit.
- For large collections (1000+ records), pause every 40 requests to stay
  under the 50/min ceiling.

### Rate-Limit-Aware Batching Pattern

```
SET requestCount = 0
SET windowStart = now()
FOR EACH operation:
  IF requestCount >= 45 AND elapsed(windowStart) < 60s:
    WAIT until 60s have elapsed since windowStart
    SET requestCount = 0
    SET windowStart = now()
  EXECUTE request
  INCREMENT requestCount
```

Use a threshold of 45 (not 50) to leave margin for retries and token refreshes.
