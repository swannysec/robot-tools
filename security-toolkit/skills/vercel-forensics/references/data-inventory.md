# Data Inventory — Vercel Forensic Collection Surface

What is collectable during a Vercel forensic pull, organized by scope, with retention windows, tier gating, and known gaps. Every endpoint listed here must also appear in `api-endpoint-reference.md` and the `ALLOWED_PATHS` map in `_common.py`.

## Contents

- [Team-scope artifacts](#team-scope-artifacts)
- [Project-scope artifacts](#project-scope-artifacts)
- [External adjacent artifacts (GitHub)](#external-adjacent-artifacts-github)
- [Vercel tier detection](#vercel-tier-detection)
- [GitHub owner type detection](#github-owner-type-detection)
- [Known gaps and limitations](#known-gaps-and-limitations)

## Team-scope artifacts

| Artifact | Source endpoint | Retention | Gotchas |
|---|---|---|---|
| Team record (plan, SAML, SCIM, created_at) | `GET /v2/teams/:tid` | Current | `saml.connection` presence is the primary tier signal |
| Members (role, email, confirmed, joinedFrom) | `GET /v2/teams/:tid/members` | Current | `joinedFrom.ssoConnectedAt` indicates SAML-mediated join; `membership.confirmed` is per-user, not per-team |
| Activity log (team-wide events) | `GET /v3/events?teamId=:tid` (via `vercel activity --all --format json`) | ~90 days on Pro; configurable on Enterprise | Not a structured audit log on Pro — this is the only substitute; endpoint has been observed to hang under Vercel-side load (see `activity-paginate.sh` graceful-degradation path) |
| Audit log (structured events) | `GET /v1/teams/:tid/audit-log` | **Enterprise only** | 404 on Pro/Hobby — use as tier-detection fallback |
| Access tokens | `GET /v5/user/tokens` | Current | **Self-scope only.** No team-wide token enumeration endpoint exists. Each member must self-report |
| Access groups | `GET /v1/access-groups?teamId=:tid` | Current | Enterprise only; empty array on Pro |
| Log drains | `GET /v1/log-drains?teamId=:tid` | Current | Empty list implies runtime-log forensics is limited to ~24h — emit a MEDIUM hygiene finding if incident window exceeds that |
| Marketplace integrations | `GET /v1/integrations/configurations?teamId=:tid&view=account` | Current | List-only; per-integration scopes require follow-up `GET /v1/integrations/configurations/:cid` |
| Custom domains | `GET /v5/domains?teamId=:tid` (paginate) | Current | Includes `createdAt`, `boughtAt`, `serviceType` |
| Deployment→domain aliases | `GET /v4/aliases?teamId=:tid` (paginate) | Current | What is serving each domain right now |
| TLS certificates | `GET /v4/certs?teamId=:tid` (paginate) | Current | Auto-renewed Let's Encrypt; 90-day lifetime |
| Webhooks | `GET /v1/webhooks?teamId=:tid` | Current | Discord/Zulip URL-embedded secrets often appear here |
| Edge Config stores | `GET /v1/edge-config?teamId=:tid` | Current | Item values retrievable via follow-up `GET /v1/edge-config/:id/items` — treat as secret-bearing |

## Project-scope artifacts

| Artifact | Source endpoint | Retention | Gotchas |
|---|---|---|---|
| Project record (~40 fields) | `GET /v9/projects/:pid?teamId=:tid` | Current | Probe live response for undocumented `trustedIps` (Terraform provider reads it; not in the documented schema). Captures `ssoProtection`, `passwordProtection`, `gitForkProtection`, `link` (Git repo binding) |
| Env var metadata | `GET /v9/projects/:pid/env?teamId=:tid` | Current | **Values never returned.** Names + `target` + `type` (`encrypted`/`sensitive`/`plain`) + `createdBy`/`updatedBy` only |
| Deployments | `GET /v6/deployments?projectId=:pid&teamId=:tid` (paginate) | Full history (years) | Immutable; generous rate limit |
| Runtime logs | `GET /v1/projects/:pid/logs?teamId=:tid` (or `vercel logs --json`) | ~24h on Pro without a log drain | Primary forensic-visibility gap; see hygiene finding in `triage.py` |
| Build events per deploy | `GET /v3/deployments/:uid/events?teamId=:tid&builds=1` | Per-deployment | Source tarball retrievable via `/v6/deployments/:uid/files` + `/v7/deployments/:uid/files/:fileId` |
| Firewall config (active) | `GET /v1/security/firewall/config/active?projectId=:pid` | Current | 404 if firewall not configured; path segment is `active`, not a query param |
| Firewall bypass rules | `GET /v1/security/firewall/bypass?projectId=:pid` | Current | |
| Firewall attack anomaly status | `GET /v1/security/firewall/attack-status?projectId=:pid` | Recent | Rate-limited 20 req/min |
| Project domains | `GET /v9/projects/:pid/domains` | Current | Includes `gitBranch` binding for branch-aliased domains |
| Deployment retention policy | `GET /v9/projects/:pid/deployment-retention-policy` | Current | 404 means plan default in effect |
| Access groups on project | `GET /v9/projects/:pid/access-groups` | Current | Enterprise; 404 on Pro |

## External adjacent artifacts (GitHub)

Not on Vercel but inside the trust boundary — GitHub auto-deploy is the primary code path into Vercel.

| Artifact | Source | Why forensic |
|---|---|---|
| Org audit log | `GET /orgs/:org/audit-log` | 180-day retention; 1,750 req/hr rate limit per user+IP; 14-day chunks to stay below the 18-day dense-activity wall; primary source for OAuth app installs, token use, repo permission changes |
| Installed apps | `GET /orgs/:org/installations` | Who has GitHub App access to auto-deploy |
| Per-repo webhooks | `GET /repos/:o/:r/hooks` | Embedded-secrets issue (Discord/Zulip webhook URLs, Slack URLs in `config.url`) |
| Per-repo deploy keys | `GET /repos/:o/:r/keys` | Static SSH keys bound to the repo — long-lived pivot surface |
| Per-repo metadata | `GET /repos/:o/:r` | `archived` + `pushed_at` + `visibility`; archived repos still auto-deploying is a governance gap |
| Per-repo branch protection | `GET /repos/:o/:r/branches/:branch/protection` | Whether auto-deploy has review gates |
| Actions secrets (names only) | `GET /repos/:o/:r/actions/secrets` | Parallel secret store to Vercel env vars; values NEVER returned |
| Dependabot alerts | `GET /repos/:o/:r/dependabot/alerts` | Open alerts on deployed dependencies |

## Vercel tier detection

Executed in `preflight.sh`. Emit the detected tier to `COLLECTOR.json` and let downstream scripts skip Enterprise-only endpoints on non-Enterprise tiers.

1. **Primary signal** — `GET /v2/teams/:tid` → presence of a `saml.connection` object → **Enterprise** or Pro+SAML add-on. Extract `saml.enforcement`, `saml.idpType`, `saml.scim`, `saml.roleMapping` for the forensic record. IdP metadata URL / ACS URL / signing cert are dashboard-only — flag as a forensic gap.
2. **Secondary signal** — `resourceConfig.concurrentBuilds` threshold on the team response. Enterprise tiers typically exceed the Pro default; treat as corroborating, not authoritative.
3. **Tertiary signal** — `platform: true` on the team response → **Enterprise Platform** (dedicated single-tenant).
4. **Fallback probe** — `GET /v1/teams/:tid/audit-log` → 404 → **Pro or Hobby** (no structured audit log). 200 → Enterprise.
5. **Caveat** — trial and pending-upgrade states are undocumented. `membership.confirmed` is per-user, not per-team; do not confuse it with team-level state.

## GitHub owner type detection

Executed in `preflight.sh` before selecting an audit-log endpoint.

- `GET /users/:username` → `type: User` → **no REST audit log available** (skip Phase 4 audit-log pull; record as limitation in the forensic report).
- `GET /users/:username` → `type: Organization` → use `GET /orgs/:org/audit-log`.
- **Enterprise probe** — if the customer is on GitHub Enterprise, probe `GET /enterprises/:ent/audit-log`. The enterprise slug is **separate** from the org slug and must be supplied in advance by the operator — there is no discovery endpoint.

## Known gaps and limitations

Document these in the forensic report as limitations, not blockers.

- **Env var values are never returned by the API.** Only names, targets, type (`encrypted`/`sensitive`/`plain`), and `createdBy`/`updatedBy` metadata via `GET /v9/projects/:pid/env`. Dashboard or `vercel env pull` are the only retrieval paths — both create a secondary exfil target and are explicitly banned by the Preservation Contract.
- **`VERCEL_AUTOMATION_BYPASS_SECRET` is not exposed via the env-var listing.** It is a Vercel-managed system variable; forensically unrecoverable via API. If rotation is needed, the user must regenerate via the Vercel dashboard.
- **`trustedIps` is not in the documented `/v9/projects/:pid` schema.** The Terraform provider reads it, suggesting it is an undocumented live field. Scripts must probe the live response and record `trustedIps` if present.
- **Runtime logs are ~24h on Pro without a log drain.** If the incident window extends beyond 24h and no drain is configured, `triage.py` emits a MEDIUM hygiene finding ("runtime logs expired — forensics-blind beyond 24h window").
- **No team-wide token enumeration endpoint.** `GET /v5/user/tokens` returns only the calling session's tokens. Offboarding workflow must force each member to self-revoke.
- **`vercel activity` has been observed to hang under Vercel-side load.** `activity-paginate.sh` implements a 60s per-page HTTP timeout + 5-minute idle-progress watchdog; on timeout it records `partial` in `scan-errors.txt` and continues with whatever was collected.
- **Legacy `/v3/secrets` is deprecated.** 404 on all current tiers — no legacy-secrets inventory is available.
- **SAML IdP metadata URL / ACS URL / signing cert are dashboard-only.** The `/v2/teams/:tid` `saml` object surfaces connection state and role mapping but not the raw IdP configuration. Flag as forensic gap.
- **GitHub REST audit log saturates at ~18–19 days of dense activity.** 14-day chunks with `per_page=100` + `Link: rel=next` cursor keeps the walk below the wall.
