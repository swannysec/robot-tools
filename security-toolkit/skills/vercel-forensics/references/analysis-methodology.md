# Analysis Methodology

How to interpret evidence collected into a frozen `vercel-forensics` case directory. Covers the four sequential analysis phases executed by the skill scripts, the severity rubric, the env-var class taxonomy + P0/P1/P2 rotate-priority rules (metapod pattern, attributed), the lingering-threats checklist beyond env-var rotation (subinium pattern, attributed), and the attribution-caution rules.

This file is the "how to analyze" companion to `threat-model-context.md` ("what the threat is"). It does not restate the runtime rules in `SKILL.md §13 Runtime Reinforcement` — those govern runtime behavior; this governs analytical interpretation.

## Table of contents

1. [Analysis phases](#1-analysis-phases)
2. [Severity rubric](#2-severity-rubric)
3. [Env-var class taxonomy and rotate-priority (metapod)](#3-env-var-class-taxonomy-and-rotate-priority-metapod)
4. [Lingering-threats checklist (subinium)](#4-lingering-threats-checklist-subinium)
5. [Attribution caution](#5-attribution-caution)

---

## 1. Analysis phases

Four scripts run in strict sequence against a frozen case directory. Output lands under `<case>/analysis/`. No script mutates raw evidence; freeze-set `a-w` permissions remain intact.

### 1a. Triage (`triage.py`)

Input: `<case>/vercel/activity.jsonl`, `<case>/github/audit-log.jsonl`, `<case>/vercel/team/*`, `<case>/vercel/projects/*/env-metadata.json`.

Emits `<case>/analysis/triage.md` with:

- **Event-type counters** — top 20 Vercel activity types + top 20 GitHub audit actions (sorted by count).
- **Security-relevant slices**:
  - `env-variable-read.*cli` (exfil channel — `vercel env pull` is the loudest signal).
  - `deployment-creation-blocked` (who tried, what SHA).
  - Team-member and project-member churn within the incident window.
  - GitHub `protected_branch.policy_override`, `hook.*`, `integration_installation.create`, `personal_access_token.*`, `repo.create_actions_secret`.
- **Per-project sensitive-vs-non-sensitive counts** — how many env vars on each project are `sensitive` (value non-readable post-create) vs `encrypted`/`plain` (value readable).
- **Class taxonomy** (see §3) — every env var is bucketed into DB-cred / OAuth-secret / Provider-API-key / Webhook-signing / Vercel-managed / Public / Other based on key-name regex.
- **P0/P1/P2 rotate-priority** per env var (see §3).
- **Account-surface audit table** — team members with their role, last-login, 2FA state, SAML linkage; tokens with scope and last-used date.
- **Local CLI hygiene note** — presence of `~/.vercel/auth.json`, age, last-used. Flag MEDIUM if present.
- **Runtime-log availability finding** — if no log drain is configured AND the incident window exceeds 24h, emit MEDIUM finding: *"runtime logs expired — forensics-blind beyond 24h window."*

### 1b. Timeline fusion (`timeline-fuse.py`)

Merge Vercel + GitHub event streams into a single chronological view. Output: `<case>/analysis/timeline.tsv` with columns `iso_ts \t source \t event \t actor \t project`.

Correlation window: **15 minutes**. Pairs of Vercel + GitHub events within 15 minutes of each other by the same actor (email match where possible) get a `correlated=1` column flag for quick scanning.

Look for cross-source correlation clusters: GitHub push → Vercel deploy → `env-variable-read:cli:env:pull` inside one window is a high-signal exfil pattern.

### 1c. Per-actor profile (`per-actor-profile.py`)

For each actor appearing in timeline events:

- **Primary owner resolution** — take `lastUpdatedBy` from env metadata and project metadata.
- **Backup owner resolution** — most-frequent deployer over the last 90 days, bots filtered (`*-bot@*`, `vercel@*`, known CI identities).
- **Per-actor baselines** — typical event mix + weekday/hour distribution over 90d.
- **Anomaly flags**:
  - Actions during the incident window that sit outside the actor's 90d baseline.
  - Non-corporate email domain (raises the personal-device-compromise branch).
  - Deployment anomalies: unique `creator.uid` values and source diversity (git-hosts, CLI, API) above baseline.

Output: `<case>/analysis/per-actor.md` + `<case>/analysis/actors.json`.

### 1d. IOC scan (`build-log-scan.py`)

Per-deployment build-log regex scan for supply-chain tampering indicators:

- Unexpected outbound hostnames during install/build (hosts histogram).
- `curl`/`wget` + piped interpreter (`| sh`, `| bash`, `| python`).
- `npm install` / `pip install` / `cargo install` of unpinned packages during build steps.
- Postinstall-script execution footprint.
- Suspicious base64-decode-and-execute fragments.

Output: `<case>/analysis/build-log-scan.md` with per-deployment findings and a cross-deployment hosts histogram.

Full regex list lives in `references/collection-patterns.md`. Scan runs against redacted logs only.

---

## 2. Severity rubric

Operational three-tier rubric. Decide on concrete evidence, not vibe.

### HIGH — plausible exploitation + active signal

Reserve for findings where both conditions hold: (a) the exploitation path is plausible given the current threat model, and (b) there is an active signal in the evidence that the path was taken.

Concrete example:

> A non-sensitive Stripe key (`STRIPE_SECRET_KEY`) exists on a production project AND `triage.md` shows `env-variable-read:cli:env:pull` on that project inside the incident window AND Stripe's own activity log shows that key in use from an unfamiliar IP during the incident window.

All three conditions together are HIGH. Any two is MEDIUM.

### MEDIUM — plausible exposure OR unusual actor pattern OR hygiene gap on a critical control

Examples:

- Non-sensitive DB password on production, no active-use signal (rotate anyway — exposure is plausible).
- Anomalous team-member action during incident window (outside baseline, no active-use signal).
- Disabled git fork protection on a repo that deploys to production.
- Log drain not configured AND incident window > 24h (runtime logs expired — evidence gap).
- GitHub webhook created inside the incident window by an unfamiliar actor.

### LOW — hygiene findings with no active signal

Examples:

- Stale team members (90d+ no activity) still provisioned.
- Old unused PATs still provisioned.
- Missing deploy protection on non-production environments.
- `~/.vercel/auth.json` present locally with read-permission bits looser than `0600`.
- Non-sensitive env var that is by design public (e.g., `NEXT_PUBLIC_*`) — noted but no rotation.

### Rule

Do not inflate severity. "Unusual" alone is not HIGH. "Hygiene gap" alone is not HIGH. If the current threat model does not support plausible exploitation, severity stops at MEDIUM.

Findings above MEDIUM must cite a specific `analysis/*.md` line or raw evidence file path + event ID.

---

## 3. Env-var class taxonomy and rotate-priority (metapod)

*Attribution: taxonomy and P0/P1/P2 tiers borrowed from `codyhxyz/metapod-harden`.*

### Class taxonomy (by key-name regex)

| Class | Example key names | Post-leak assumption |
|---|---|---|
| DB-cred | `*_URL`, `*DATABASE*`, `*DB_*`, `POSTGRES_*`, `MYSQL_*`, `REDIS_*`, `MONGO*` | High-value if contains password |
| OAuth-secret | `*_CLIENT_SECRET`, `OAUTH_*SECRET`, `SSO_*SECRET` | Must rotate IdP-side |
| Provider-API-key | `STRIPE_*`, `OPENAI_*`, `ANTHROPIC_*`, `AWS_*`, `GCP_*`, `SENDGRID_*`, `TWILIO_*`, `RESEND_*`, `SLACK_*`, `GITHUB_TOKEN`, `VERCEL_*TOKEN` | Rotate at the provider; blast radius varies by scope |
| Webhook-signing | `*WEBHOOK*SECRET`, `*SIGNING_SECRET`, `STRIPE_WEBHOOK_SECRET`, `CLERK_WEBHOOK_SECRET` | Rotate at the issuer; rewrite verifier |
| Vercel-managed | `VERCEL_*` (non-token), `NEXT_RUNTIME`, platform-set vars | Platform rotates; no customer action |
| Public-by-design | `NEXT_PUBLIC_*`, `PUBLIC_*`, `NX_PUBLIC_*` | No rotation — already public by intent |
| Other | Everything not matched above | Manual classification required |

### Rotate-priority tiers

| Tier | Rule | Rationale |
|---|---|---|
| **P0** | Non-public secrets currently stored as `plain` or `encrypted` | Value was readable pre-breach assumption; must rotate |
| **P1** | Test-tier prefixed values (`sk_test_*`, `pk_test_*`, staging DB URLs) | Rotate for hygiene; lower blast radius |
| **P2** | Public-by-design values + Vercel-managed | No rotation needed; documented for completeness |
| **(already sensitive)** | Values flagged `sensitive` at creation time | Survived intact under current threat model — no rotation required unless threat model changes |

`rotation-worklist.py` emits rows sorted by `provider`, `team`, `project`, `key`, with the P-tier as a column. The skill itself never rotates — operator hands the CSV to `subinium/vercel-incident-toolkit` Flow C or `codyhxyz/metapod-harden` `/rotate-vercel-env`.

---

## 4. Lingering-threats checklist (subinium)

*Attribution: checklist pattern borrowed from `subinium/vercel-incident-toolkit`.*

Rotating env vars is necessary but not sufficient. After rotation the following must be separately verified — each represents an attacker foothold that survives env-var rotation alone.

| # | Check | Why it matters |
|---|---|---|
| 1 | Backdoored builds / deployments — list every production deploy since the earliest suspected compromise; diff HEAD vs deployed SHA; force clean redeploy if any diverges | Attacker-modified build survives env-var rotation |
| 2 | `vercel.json` rootkits — audit `rewrites`, `redirects`, `headers`, and `functions[*].regions` for unexpected additions | Routing-level tamper silently redirects traffic or weakens headers |
| 3 | Unauthorized team members or tokens — Team → Members + Tokens; cross-reference against known-good roster | New member/token seeded during breach survives rotation |
| 4 | Deploy-hook URL exfil — Project → Settings → Git → Deploy Hooks; rotate any hook URL that existed during the window | Deploy hooks can trigger arbitrary builds from an attacker-held URL |
| 5 | NPM supply-chain injection — if any in-window deploy published a package, treat every published version as tainted until provenance is verified | Published package with tainted build affects downstream users |
| 6 | Serverless warm-instance env — force scale-down via full redeploy after rotation; warm Lambdas can hold old env in memory | Rotated value without redeploy does not evict warm instances |
| 7 | Preview deployments pinned to old env — audit open preview URLs; delete or redeploy | Previews remain callable with pre-rotation creds |
| 8 | Data in logs / analytics — review Log Drain destinations for exfiltrated values | Secrets accidentally logged persist in the drain sink |

Emit a `analysis/lingering-checklist.md` stub during `triage.py` and require the operator to confirm each item manually. The skill marks the checklist as *unverified* until an operator signs off in the findings report.

---

## 5. Attribution caution

Default `unknown actor` in every finding until corroborating infrastructure exists.

**Do NOT attribute based on:**

- Brand appearances in BreachForums listings (forums are multiply compromised, listings are opportunistic).
- Self-claims on Telegram, Tox, or forum DMs (affiliate impersonation is documented for major brands).
- Press coverage that repeats a claimed group name without independent corroboration.

**Positive attribution requires at least one of:**

- Tox ID match against prior-incident known-good IDs.
- Domain-registrar pattern continuity (e.g., NICENIC vs Tucows clusters).
- Contact-email continuity (e.g., `shinycorp@tutanota.com`, `shinygroup@onionmail.com`).
- Data-hosting venue continuity (e.g., Limewire samples).
- BTC address format + payment-deadline pattern continuity.

**Label all skill-produced attribution `preliminary`.** Final attribution is a separate workstream conducted by threat-intelligence analysts with access to non-public correlation data. The skill emits signals; it does not name groups.

When the findings report cites a possible actor, the phrasing is:

> *Preliminary: the listing brand appears consistent with [GROUP], but no infrastructure correlation is available. Treat as unverified.*

Never:

> *This incident is attributed to [GROUP].*

See `references/threat-model-context.md §3` for the expanded Phase-3 pivot-path list that bears on attribution questions.
