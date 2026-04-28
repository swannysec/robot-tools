# Report Template — `vercel-forensics`

Canonical output format for findings + the handoff bundle produced by the skill. Every finding MUST match the Per-finding Format. Every case MUST produce the 8-section audit report.

Pattern attribution: the 8-section audit layout, severity tiers, and env-var class taxonomy are adapted from `codyhxyz/metapod-harden`. The rotation-worklist CSV consumed downstream is the `garyhtou/Vercel-Env-Var-Exposure-Triager` schema.

## Table of contents

1. [Per-finding format](#1-per-finding-format)
2. [8-section audit report structure](#2-8-section-audit-report-structure-metapod-attributed)
3. [Handoff bundle layout](#3-handoff-bundle-layout)
4. [Severity discipline guardrails](#4-severity-discipline-guardrails)
5. [Action field discipline](#5-action-field-discipline)

---

## 1. Per-finding format

Every finding in `02-TECHNICAL-FINDINGS.md` uses this exact markdown structure. No prose preamble, no decorative headers between findings other than the H3.

```
### <short-id> — <one-line description> (<severity>)

**Where:** <evidence file path + line number OR event ID>
**What:** <observed event, stated as fact, no interpretation>
**Why it matters:** <threat-model implication; link to threat-model-context.md section if relevant>
**Action:** <imperative recommendation the USER executes downstream — never an action the skill takes>
```

Rules:

- `short-id` format: `VF-<NN>` (e.g., `VF-01`, `VF-02`), zero-padded, assigned in order of discovery within each severity band.
- `severity` is one of `LOW` / `MEDIUM` / `HIGH` per the `analysis-methodology.md` rubric. Reserve `HIGH` for plausible exploitation combined with active signal (e.g., unknown actor deploy inside incident window with abnormal source diversity). Unusual-but-benign activity is `LOW` or `MEDIUM`.
- `Where` must cite a concrete artifact: `raw/vercel-activity/page-03.json:L1274` OR an event ID such as `evt_9x4k2m`. Never "the activity log" unqualified.
- `What` describes only what happened. Save interpretation for `Why it matters`.
- `Why it matters` ties back to the threat model — which pivot path, which env-var class, which control gap.
- `Action` is imperative and scoped to the user. Examples: "Rotate STRIPE_SECRET_KEY via Stripe dashboard; update Vercel env; force redeploy", "Revoke integration token for <integration-slug>", "Add log drain to <provider> before next investigation". Never: "The skill rotates the key".

### Worked example

```
### VF-03 — Non-sensitive production env var readable post-incident (MEDIUM)

**Where:** raw/vercel/projects/acme-web/env-metadata.json:L42 (envId: env_7h2k)
**What:** Env var STRIPE_WEBHOOK_SECRET present on production target with type=plain (not `sensitive`). Last updated 2026-03-11; not rotated since Vercel disclosure on 2026-04-19.
**Why it matters:** Per the 3-tier env-var threat model (threat-model-context.md §3), `plain` values are decryptable by any holder of a team-scoped Vercel token. Incident window overlaps OAuth-token compromise; must be treated as potentially read.
**Action:** Rotate STRIPE_WEBHOOK_SECRET in Stripe dashboard (Developers → Webhooks → Roll); update Vercel env via `subinium/vercel-incident-toolkit` Flow C or `metapod-harden` `/rotate-vercel-env STRIPE_WEBHOOK_SECRET`; force redeploy; confirm Stripe event stream resumed.
```

---

## 2. 8-section audit report structure (metapod, attributed)

Canonical layout for `01-AUDIT-REPORT.md`. Section order is fixed; section headings are H2. Each section begins with a one-sentence TL;DR, then the required table or content, then a pointer to the evidence file.

If `scan-errors.txt` exists in the case dir, prepend a bolded banner at the very top of the report: **PARTIAL COLLECTION — see `scan-errors.txt`. Findings below may be incomplete.**

### Section 1 — TL;DR

A single table summarizing surface, finding count, top priority. One row per audit surface.

```
| Surface               | Finding                                                              |
|-----------------------|----------------------------------------------------------------------|
| Env vars              | 47 non-sensitive env vars across 8 projects — 12 P0, 18 P1, 17 P2    |
| Deployments           | 412 deploys in 14d window; 3 from anomalous source (vercel-cli-older)|
| Account tokens        | 6 team tokens active; 2 inactive > 90d — revoke                      |
| Integrations          | 4 active; 1 (Sentry) has full team read scope                        |
| Webhooks / log drains | 0 log drains configured — runtime logs unrecoverable beyond 24h      |
| Local CLI hygiene     | `~/Library/.../vercel/auth.json` present — rotate token post-audit   |
```

### Section 2 — Env-var inventory

Per-project table. One row per env var (key + target combination). Values are NEVER emitted.

```
| key                      | envs       | type       | class                | rotate-priority |
|--------------------------|------------|------------|----------------------|-----------------|
| STRIPE_SECRET_KEY        | prod       | sensitive  | Provider API key     | P0              |
| DATABASE_URL             | prod, prev | plain      | DB credential        | P0              |
| NEXT_PUBLIC_ANALYTICS_ID | all        | plain      | Public               | —               |
```

Class taxonomy (from `metapod-harden`, see `analysis-methodology.md`):
`DB credential` / `OAuth secret` / `Provider API key` / `Webhook signing` / `Vercel-managed` / `Public` / `Other`.

Priority tiers:
- **P0** — External-vendor credentials with production blast radius (DB credentials, payment API keys, OAuth secrets backing customer sessions).
- **P1** — Non-production-critical but internet-callable (webhook signing, internal service tokens, monitoring API keys).
- **P2** — Vercel-managed or low-blast-radius (build-only secrets, feature flags marked sensitive).

### Section 3 — Secrets summary

P0/P1/P2 counts grouped across all projects, with a pointer to the rotation-worklist CSV.

```
| tier | count | CSV rows                                   |
|------|-------|--------------------------------------------|
| P0   | 12    | see 05-ROTATION-WORKLIST.csv (priority=P0) |
| P1   | 18    | (priority=P1)                              |
| P2   | 17    | (priority=P2)                              |
```

### Section 4 — Deployment audit

Total deployments in the incident window, unique creator UIDs, unique sources (`vercel-cli`, `github`, `git-cli`, `api`), anomaly flags.

```
| metric             | value  | anomaly?                                           |
|--------------------|--------|----------------------------------------------------|
| deployments        | 412    | —                                                  |
| unique creators    | 5      | 1 creator deployed outside 90d baseline (anomaly)  |
| unique sources     | 3      | —                                                  |
| non-default branch | 7      | 2 from fork PRs — verify allowForkPullRequests     |
```

Pointer: `analysis/per-actor-profile.md` for per-actor detail.

### Section 5 — Account-surface audit

One table covering every account-level surface collected. Status column uses `ok` / `review` / `action-required`.

```
| surface           | count | status            |
|-------------------|-------|-------------------|
| team tokens       | 6     | action-required   |
| integrations      | 4     | review            |
| webhooks          | 2     | ok                |
| log drains        | 0     | action-required   |
| domains           | 11    | ok                |
| aliases           | 14    | ok                |
| access groups     | 3     | review            |
| edge config       | 2     | ok                |
```

### Section 6 — Local CLI hygiene

Single-paragraph note on whether `~/Library/Application Support/com.vercel.cli/auth.json` was present on the investigation host. If present, recommend `vercel logout && vercel login` after the case dir is frozen and evidence is handed off. The investigation token itself is written into that file and must be considered exposed post-pull.

### Section 7 — Prioritized rotation list

The skill does NOT rotate. This section is a pointer, not an action list.

For each P0 entry, recommend downstream execution:
- `subinium/vercel-incident-toolkit` → Flow C (guided rotation)
- `codyhxyz/metapod-harden` → `/rotate-vercel-env <KEY>`

The structured input for both tools is `05-ROTATION-WORKLIST.csv` (garyhtou schema, 23 columns). Hand it to the operator alongside the audit report.

#### 23-column schema (authoritative: `scripts/rotation-worklist.py::COLUMNS`)

| # | Column | Source | Notes |
|---|---|---|---|
| 1 | `team_name` | Vercel team object | human-readable |
| 2 | `team_slug` | Vercel team object | stable identifier |
| 3 | `project_name` | `/v9/projects/:pid` | may contain unicode; `_safe_cell` bidi-scrubs |
| 4 | `project_id` | `/v9/projects/:pid` | `^prj_[A-Za-z0-9]+$` validated in preflight |
| 5 | `env_id` | `/v9/projects/:pid/env` | env-var record id |
| 6 | `configuration_id` | integration link (when present) | pointer to `/v1/integrations/configurations/:cid` |
| 7 | `key` | `/v9/projects/:pid/env[].key` | env-var name — attacker-controlled; formula-injection neutralized |
| 8 | `type` | `env[].type` | `encrypted` \| `plain` \| `system` \| `sensitive` |
| 9 | `targets` | `env[].target` joined by `\|` | `production` / `preview` / `development` |
| 10 | `git_branch` | `env[].gitBranch` | optional, preview scope |
| 11 | `class` | derived via `classify_key()` | DB-cred \| OAuth-secret \| Provider-API-key \| Webhook-signing \| Vercel-managed \| Public \| Other |
| 12 | `provider` | derived via `infer_provider()` | STRIPE \| OPENAI \| ANTHROPIC \| AWS \| GCP \| SUPABASE \| etc. (or blank) |
| 13 | `rotate_priority` | derived via `rotate_priority()` | P0 \| P1 \| P2 |
| 14 | `recommendation` | derived via `recommendation()` | free-text operator guidance |
| 15 | `primary_owner_name` | `env[].lastUpdatedByDisplayName` | display name |
| 16 | `primary_owner_email` | members lookup on `lastUpdatedBy` uid | |
| 17 | `backup_owner_name` | `actors.json` most-frequent-90d deployer | bot-filtered |
| 18 | `backup_owner_email` | members lookup on backup owner | |
| 19 | `backup_deploy_count_90d` | `actors.json` | `0` when unresolved |
| 20 | `last_updated_at` | `env[].updatedAt` ISO-8601 | |
| 21 | `last_updated_days_ago` | now − `updatedAt` / 86400 | integer days |
| 22 | `created_at` | `env[].createdAt` ISO-8601 | |
| 23 | `vercel_url` | `https://vercel.com/:team/:project/settings/environment-variables` | dashboard shortcut |

**Header row**: first line is the `CONFIDENTIAL` comment (leading `#`), then a blank, then the 23-column header, then data rows. Rows are sorted by `provider`/`team_slug`/`project_name`/`key`.

**Guarantees:**
- Never emits env-var **values** — the API contract (L4, §SKILL.md) ensures plain GETs do not return them, and `_common.py::ALLOWED_PATHS` rejects `?decrypt=` / `?reveal=` that could be used to fetch them.
- Formula-injection neutralized: cells beginning with `= + - @ \t \r` get a single-quote prefix.
- Bidi/zero-width control code points stripped from `project_name` and `key`.
- Cells containing `\t` / `\n` are RFC-4180-quoted by Python's `csv` module; intended consumer is a spreadsheet or an RFC-4180 parser (not naive `awk`/`cut`).

### Section 8 — Caveats + unknowns

Explicit disclosure of forensic gaps. Required content:

- Pro-tier audit-log unavailability if applicable (detected in preflight; only Enterprise has `/v1/teams/:tid/audit-log`).
- `trustedIps` schema gap — undocumented field on `/v9/projects/:pid`; shape inferred, not contract-guaranteed.
- `VERCEL_AUTOMATION_BYPASS_SECRET` is not retrievable via the API.
- Runtime logs retention — 24h on Pro, unavailable beyond window if no log drain.
- IdP metadata URL / ACS URL / SAML cert are dashboard-only; excluded from this collection.
- Contents of `scan-errors.txt` if present — summarize which phase aborted and what is missing.

---

## 3. Handoff bundle layout

What ends up in the frozen case directory after `freeze.sh` runs, and what the operator hands to downstream parties:

```
~/.vercel-forensics/case-<id>/
├── 00-EXECUTIVE-SUMMARY.md             (1 page — non-technical stakeholders)
├── 01-AUDIT-REPORT.md                  (the 8 sections above)
├── 02-TECHNICAL-FINDINGS.md            (findings grouped by severity; Where/What/Why/Action)
├── 03-TIMELINE.md                      (narrative + pointer to analysis/timeline.tsv)
├── 04-EVIDENCE-INDEX.md                (map: finding-id → evidence file + line/event ID)
├── 05-ROTATION-WORKLIST.csv            (garyhtou schema; consumable by subinium/metapod)
├── MANIFEST.sha256                     (SHA-256 per file in case dir)
├── COLLECTOR.json                      (whoami + hostname + tool_version + case_id + ISO timestamps + timezone)
├── CHAIN_OF_CUSTODY.md                 (chronological ledger of collection events)
├── DRY-RUN-PLAN.md                     (only present if --dry-run was used)
├── scan-errors.txt                     (only present on partial-failure)
└── raw/                                (per-phase raw evidence; frozen a-w)
    ├── vercel/
    ├── github/
    └── analysis/
```

All files inside the frozen case dir are `a-w` (software WORM) after `freeze.sh`. The skill refuses to re-run against a frozen case dir. If additional collection is needed, open a new case.

Downstream handoff MUST include the full bundle. Do not hand off `05-ROTATION-WORKLIST.csv` in isolation — the audit report, findings, and manifest provide the provenance the CSV relies on.

---

## 4. Severity discipline guardrails

Explicit rules for the report writer. These override any instinct to dramatize findings.

- **Do NOT over-call severity because something is unusual.** Unusual-but-benign is `LOW`. `HIGH` requires both plausible exploitation AND active signal (new actor deploying inside the window, anomalous source, failed auth burst). See `analysis-methodology.md` for the full rubric.
- **Do NOT attribute to a named threat group based on brand claims alone.** Telegram/forum/Twitter self-claims are not corroborating evidence. Default to "unknown actor".
- **Use `preliminary` for any attribution.** Example: "Preliminary: activity pattern consistent with access-token abuse, not credential stuffing." Never drop the `preliminary` prefix without two independent corroborating signals.
- **Cite evidence by file path + line number OR event ID — never by recollection.** If you cannot cite, omit the claim. Evidence-only is Runtime Reinforcement Rule 1.
- **Flag partial collection at the top of TL;DR.** If `scan-errors.txt` exists, the banner goes above Section 1. Do not bury partial-collection status inside Section 8.
- **`HIGH` when collection aborted mid-incident-window with active events present.** If the activity paginator tripped the 5-minute idle watchdog while new events were still arriving, that is itself a `HIGH` finding (evidence gap overlapping live signal).
- **Runtime log unavailability is MEDIUM when incident window > 24h AND no log drain configured.** This is the forensics-blind hygiene finding emitted by `triage.py`.

---

## 5. Action field discipline

The `Action` field in any finding is a recommendation for the USER. The skill does NOT take actions. This is absolute and non-negotiable (Runtime Reinforcement Rule 3).

Write actions in imperative form aimed at the operator:

- YES: "Rotate `STRIPE_SECRET_KEY` via Stripe dashboard; update Vercel env with `metapod-harden` `/rotate-vercel-env`; force redeploy."
- YES: "Revoke the Sentry integration at vercel.com/<team>/integrations; re-grant with project scope only."
- YES: "Add a log drain (Datadog, Axiom, or BetterStack) before the next investigation so runtime logs are available beyond the 24h Pro retention."

Never write actions as skill behavior:

- NO: "The skill will rotate `STRIPE_SECRET_KEY`."
- NO: "Automatically revoke the integration."
- NO: "The skill forces redeploy after rotation."

If a user asks the skill to perform rotation mid-workflow, refuse and point at `subinium/vercel-incident-toolkit` Flow C or `codyhxyz/metapod-harden` `/rotate-vercel-env <KEY>`. Hand them the rotation-worklist CSV as structured input.
