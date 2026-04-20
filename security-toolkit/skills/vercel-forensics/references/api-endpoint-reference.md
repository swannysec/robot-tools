# API Endpoint Reference — Vercel + GitHub (Read-Only)

Endpoint catalogue for the `vercel-forensics` collection phase. Every path here must appear in the `ALLOWED_PATHS` map in `_common.py`. Enforcement mechanics (URL validation, verb gating, redirect handling) live in `allowlist-enforcement.md`.

## Contents

- [Auth](#auth)
- [Vercel team-level endpoints](#vercel-team-level-endpoints)
- [Vercel project-level endpoints](#vercel-project-level-endpoints)
- [Vercel deployment endpoints](#vercel-deployment-endpoints)
- [Vercel security / firewall endpoints](#vercel-security--firewall-endpoints)
- [Vercel rate limits](#vercel-rate-limits)
- [GitHub REST endpoints](#github-rest-endpoints)
- [GitHub GraphQL](#github-graphql)
- [GitHub REST audit log](#github-rest-audit-log)
- [ALLOWED_PATHS map](#allowed_paths-map)
- [404-prone paths](#404-prone-paths)

## Auth

- **Prefer `vercel api`** over raw `curl` — the CLI wraps team-scope, pagination, and session auth.
- **Never pass `--token <value>` on the command line** — the value lands in shell history and appears in `ps(1)` output. Scripts refuse this form.
- **CI pattern**: `VERCEL_TOKEN` environment variable, loaded by `_common.py::get_token()` via the priority chain `--token-file` → env → `getpass` prompt.
- **Fresh token hygiene**: mint a new Developer-role team-scoped token specifically for the forensic pull; revoke it after freeze. Never use a token that is itself under investigation — it contaminates the activity log.
- **GitHub**: fine-grained PAT with `read:audit_log`, repo `Administration: read`, `Metadata: read` (auto). Loaded via `gh auth token` or `GH_TOKEN` env.

## Vercel team-level endpoints

Known-working GETs. All team-scoped endpoints require `?teamId=:tid` unless noted.

| Endpoint | Purpose | Rate limit | Notes |
|---|---|---|---|
| `GET /v2/teams/:tid` | Team record — plan, SAML, SCIM, created_at | Generic | Primary tier signal (`saml.connection`) |
| `GET /v2/teams/:tid/members` | Roster — role, email, confirmed, joinedFrom | Generic | Paginate via `?since` |
| `GET /v1/teams/:tid/audit-log` | Enterprise audit log | 5 req/min (export) | 404 on Pro/Hobby |
| `GET /v3/events?teamId=:tid` | Activity log (non-Enterprise substitute) | 60 req/min/user | Hangs under Vercel-side load — see `activity-paginate.sh` |
| `GET /v5/user/tokens` | Caller's personal tokens | 120 req/min per owner | **No team-wide enumeration** |
| `GET /v1/log-drains?teamId=:tid` | List drains | Generic | Empty array ⇒ 24h runtime-log ceiling |
| `GET /v1/access-groups?teamId=:tid` | Access groups (Enterprise) | Generic | Empty on Pro |
| `GET /v1/integrations/configurations?teamId=:tid&view=account` | Marketplace integration list | Generic | |
| `GET /v1/integrations/configurations/:cid?teamId=:tid` | Per-integration detail (scopes + permissions) | Generic | Follow-up call for each list entry |
| `GET /v5/domains?teamId=:tid` | Custom domains | Generic | Paginate with `?limit=100` |
| `GET /v4/aliases?teamId=:tid` | Deployment→domain aliases | Generic | Large response — paginate |
| `GET /v4/certs?teamId=:tid` | TLS certificates | Generic | LE auto-renewed |
| `GET /v1/webhooks?teamId=:tid` | Team webhooks | Generic | |
| `GET /v1/edge-config?teamId=:tid` | Edge Config stores | Generic | Items retrievable via `/v1/edge-config/:id/items` (treat as secret-bearing) |

## Vercel project-level endpoints

| Endpoint | Purpose | Rate limit |
|---|---|---|
| `GET /v9/projects?teamId=:tid` | List projects | Generic |
| `GET /v9/projects/:pid?teamId=:tid` | Full project record (probe for undocumented `trustedIps`) | Generic |
| `GET /v9/projects/:pid/env?teamId=:tid` | Env var metadata (names only) | Generic |
| `GET /v9/projects/:pid/domains?teamId=:tid` | Domains bound to project | Generic |
| `GET /v9/projects/:pid/deployment-retention-policy` | Retention policy (404 ⇒ plan default) | Generic |
| `GET /v9/projects/:pid/access-groups` | Project access groups (Enterprise) | Generic |
| `GET /v1/projects/:pid/logs?teamId=:tid` | Recent runtime logs (~24h on Pro) | Generic |

## Vercel deployment endpoints

| Endpoint | Purpose | Rate limit |
|---|---|---|
| `GET /v6/deployments?projectId=:pid&teamId=:tid` | All deployments for a project | 500 req/min (Pro), 2000 req/min (Enterprise) |
| `GET /v13/deployments/:uid?teamId=:tid` | Full deployment record | 500/2000 req/min |
| `GET /v3/deployments/:uid/events?teamId=:tid&builds=1` | Build-event stream (build log) | Generic |
| `GET /v6/deployments/:uid/files?teamId=:tid` | Source-file listing | Generic |
| `GET /v7/deployments/:uid/files/:fileId?teamId=:tid` | Specific source-file contents | Generic |

## Vercel security / firewall endpoints

Known-working paths. Docs list some close-but-wrong variants — see [404-prone paths](#404-prone-paths).

| Endpoint | Purpose | Rate limit |
|---|---|---|
| `GET /v1/security/firewall/config/active?projectId=:pid&teamId=:tid` | Active firewall config (404 ⇒ not configured) | Generic |
| `GET /v1/security/firewall/bypass?projectId=:pid&teamId=:tid` | Bypass rules | Generic |
| `GET /v1/security/firewall/attack-status?projectId=:pid&teamId=:tid` | Attack-mode anomaly status | 20 req/min |

## Vercel rate limits

Official per `vercel.com/docs/limits`. Emit `_common.py::rate_limit_sleep(response)` on 429 response.

| Surface | Limit |
|---|---|
| `/v3/events` (activity log) | 60 req/min/user |
| Audit Log export (`/v1/teams/:tid/audit-log`) | 5 req/min (Enterprise only) |
| Deployments retrieval (`/v6/deployments`, `/v13/deployments/:uid`) | 500 req/min (Pro), 2000 req/min (Enterprise) |
| Token retrieval (`/v5/user/tokens`) | 120 req/min per owner |
| Attack Status (`/v1/security/firewall/attack-status`) | 20 req/min |

**429 response headers** — respect all four:

- `x-ratelimit-limit` — window cap
- `x-ratelimit-remaining` — remaining in window
- `x-ratelimit-reset` — Unix epoch seconds when window resets
- `retry-after` — seconds to sleep before retrying (prefer this when present)

## GitHub REST endpoints

Read-only GETs. `gh api` handles pagination when `--paginate` is passed for cursor-style endpoints.

| Endpoint | Purpose | Notes |
|---|---|---|
| `GET /users/:username` | Owner-type probe (`User` vs `Organization`) | Determines whether audit log is reachable |
| `GET /orgs/:org/audit-log` | Org audit log | 14-day chunks; see [GitHub REST audit log](#github-rest-audit-log) |
| `GET /enterprises/:ent/audit-log` | Enterprise audit log | Enterprise slug supplied by operator — no discovery |
| `GET /orgs/:org/installations` | Installed GitHub Apps | |
| `GET /repos/:o/:r` | Per-repo metadata (`archived`, `pushed_at`, `visibility`) | |
| `GET /repos/:o/:r/hooks` | Per-repo webhooks | Discord/Zulip secrets embedded in URLs |
| `GET /repos/:o/:r/keys` | Deploy keys | Static SSH |
| `GET /repos/:o/:r/branches/:branch/protection` | Branch protection | Review-gate posture |
| `GET /repos/:o/:r/actions/secrets` | Actions secret names (values never returned) | |
| `GET /repos/:o/:r/dependabot/alerts` | Open Dependabot alerts | |

## GitHub GraphQL

- `gh api graphql` **does not auto-paginate** — cursor handling is hand-rolled (`defaultBranchRef { branchProtectionRule }`, `deployKeys(first: 25)`, `isArchived`/`pushedAt`/`visibility`).
- **Cost model**: 5,000 points/hr budget. Shallow pagination (`first: 25` for repos) keeps per-query cost ~30 points.
- **`webhooks` field is unconfirmed in the schema** — stay on REST (`GET /repos/:o/:r/hooks`) for webhook data.
- One query per repo; failure in one does not block the others.

## GitHub REST audit log

- **Rate limit**: 1,750 requests/hr per user+IP pair.
- **Retention**: 180 days.
- **Chunking**: 14-day windows stay below the observed ~18-day dense-activity wall.
- **Pagination**: `per_page=100`; prefer the `Link: rel=next` cursor over date-range chunking (cursor is more stable under event bursts).
- **Recovery**: on 403 from rate-limit exhaustion, `github-audit-log.sh` attempts JSON-decode recovery via `JSONDecoder.raw_decode` against partial bodies and resumes from the last-seen cursor.
- **Auth scope**: fine-grained PAT with `read:audit_log`.

## ALLOWED_PATHS map

The canonical read-only endpoint map is defined in `_common.py::ALLOWED_PATHS`. Every endpoint listed in this reference must appear in that map; new endpoints require simultaneous updates to both files. Each map entry is a path pattern plus a per-path query allowlist; `validate_url(url)` parses the URL, matches path + params, and rejects non-GET verbs. Query params whose name matches `decrypt` or `reveal` (case-insensitive) are rejected unconditionally.

See `allowlist-enforcement.md` for validation-mechanics detail: URL parsing order, param allowlist semantics, redirect (`Location` header) re-validation, ingress projection field whitelists per resource type, and the atomic-write pattern that follows validation.

## 404-prone paths

Documented but broken or deprecated — do not add to the allowlist.

| Wrong path | Reason | Correct path |
|---|---|---|
| `GET /v3/secrets?teamId=:tid` | Deprecated | No replacement — legacy-secrets inventory unavailable |
| `GET /v1/teams/:tid/audit-log` on Pro/Hobby | Enterprise-only endpoint | Use `/v3/events` as the non-Enterprise substitute |
| `GET /v1/security/attack-status` | Missing `firewall/` segment | `GET /v1/security/firewall/attack-status?projectId=:pid` |
| `GET /v1/security/firewall/config` without `active` segment | `active` is a path segment, not a query param | `GET /v1/security/firewall/config/active?projectId=:pid` |
| `GET /v1/security/firewall/config/active?configVersion=active` | Same misconception as above | Drop the query param; path-segment form is canonical |
