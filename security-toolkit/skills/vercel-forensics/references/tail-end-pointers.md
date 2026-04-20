# Tail-End Pointers — post-skill investigator guidance

Where to look AFTER `vercel-forensics` completes collection + analysis and the case dir is frozen. This file is NOT collection logic — the skill has already finished by the time the operator reads it. The skill still has NOT taken any action and will not; these are pointers for the operator to execute manually or via other tooling.

Pattern attribution: the canary-env-var pattern is adapted from `subinium/vercel-incident-toolkit` lingering-threats checklist.

## Table of contents

1. [Google Workspace OAuth audit-log hunt](#1-google-workspace-oauth-audit-log-hunt)
2. [Vendor-side audit logs](#2-vendor-side-audit-logs)
3. [MCP token inventory pointer](#3-mcp-token-inventory-pointer)
4. [Canary env var pattern (subinium, attributed)](#4-canary-env-var-pattern-subinium-attributed)
5. [2026 adjacent-SaaS pointers](#5-2026-adjacent-saas-pointers)
6. [Post-forensics local CLI hygiene](#6-post-forensics-local-cli-hygiene)
7. [When to escalate to dedicated DFIR tooling](#7-when-to-escalate-to-dedicated-dfir-tooling)

---

## 1. Google Workspace OAuth audit-log hunt

For customers whose identity provider is Google Workspace. The 2026-04-19 Vercel incident originated through a compromised third-party Workspace OAuth application. If the customer under investigation uses Workspace SSO for any surface (Vercel, GitHub, Linear, Notion, Slack, Figma), the Workspace admin audit log is the upstream source of truth for OAuth-grant + revoke events.

**Current endpoint (verified April 2026):**
`https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token`

**Required scope:** `https://www.googleapis.com/auth/admin.reports.audit.readonly`

**Required role:** Workspace Super Admin OR a role granting "Reports" read (custom role path: Admin console → Account → Admin roles → privileges → "Reports").

**Filter by `eventName`:**
- `authorize` — app granted access
- `revoke` — user or admin revoked access
- `activity` — app used granted scopes (noisier; query last)

**Hunt procedure:**

1. Pull the last 180 days of `authorize` events across all users (Workspace retains 6 months by default).
2. Extract unique `client_id` values from `parameters[].value` where `parameters[].name = 'client_id'`.
3. Cross-reference against:
   - Any IOC app-ID published by Vercel in the incident notification.
   - Any app-ID inferred from the incident write-up or the vendor's own disclosure.
   - Apps granted scopes covering Gmail, Drive, or Admin SDK (lateral-movement surface).
4. For each hit, list all users who granted it and the exact grant timestamp.
5. If the incident window is known, also query `activity` events for that `client_id` during the window — this reveals whether the compromised app actually exercised its scopes.

Export as JSON; hand to the audit report as a supplementary evidence file. Do NOT attempt this hunt inside the `vercel-forensics` case dir (frozen); produce a separate workspace-audit bundle.

---

## 2. Vendor-side audit logs

For every P0/P1 vendor key listed in `05-ROTATION-WORKLIST.csv`, pull the vendor's own audit log for the incident window. The Vercel activity log shows WHEN the key-material was potentially read; the vendor's log shows whether it was USED.

Minimum checklist:

- **Stripe** — `https://dashboard.stripe.com/logs` + Events API (`GET /v1/events`). Filter by IP + API-key fingerprint. Stripe retains 30 days of logs by default; longer with workspace upgrade.
- **Supabase** — Project logs (Database + Auth + Storage + Edge Functions). Query for unusual service-role-key activity. Supabase Pro retains 7 days; Team 14 days.
- **Neon** — Branch + role audit. Check for new branches created outside the window's normal cadence.
- **PlanetScale** — Audit log (Organization → Settings → Audit log). Connection-string regeneration events are most relevant.
- **OpenAI** — Organization settings → Audit log. Filter by API-key ID. Retention is 30 days for Teams, 180 days for Enterprise.
- **Anthropic** — Console → Settings → Audit (Enterprise only). Request logs via the API with usage metrics.
- **GitHub (adjacent org)** — Organization audit log at `/organizations/:org/audit-log`; filter by `actor_ip` + `hashed_token`. Check for non-investigation actions taken by tokens enumerated in the Vercel side of the investigation.
- **Cloudflare (if used upstream)** — Audit logs at `dash.cloudflare.com/<account>/audit-log`. Filter by API-token ID.
- **SendGrid / Resend / Postmark** — Email-send logs. A leaked API key is often exercised by sending a test email before bulk abuse.

For each vendor, record: window queried, events returned, anomalies, evidence file path. Hand off as a supplement to the `vercel-forensics` bundle, NOT inside the frozen case dir.

---

## 3. MCP token inventory pointer (2026-critical)

As of 2026, MCP (Model Context Protocol) servers are a first-class token-bearing surface. Any `.claude/`, `.cursor/`, `.codex/` directory may contain PATs, OAuth tokens, and service account keys for the AI tooling stack — and those tokens frequently have write access to the same platforms under investigation (Vercel, GitHub, Linear).

**v1 scope — operator should list contents (PATHS only, not values) of:**

- `~/Library/Application Support/Claude/` — Claude Desktop MCP config
- `~/.cursor/mcp.json` — Cursor MCP server config
- `~/.codex/` — Codex CLI config + cached tokens
- Project-level `.claude/settings*.json` (including `.claude/settings.local.json`)
- Project-level `.mcp.json` (repo-root MCP servers)

Record file paths, mtimes, and file modes. Do NOT open and read contents — treat MCP token stores as sensitive-by-default. If values are needed, the operator mints a fresh short-lived PAT for any server with plaintext tokens, revokes the old one, and rotates.

**Automated MCP collection is deferred to v2** (`mcp-inventory.sh` — stat metadata, never contents).

---

## 4. Canary env var pattern (subinium, attributed)

After rotation is complete, deploy a canary env var whose only purpose is to trigger an alert when it is accessed. If the attacker retains ANY read capability (e.g., unrotated lingering secret, new pivot path, compromised CI runner), a canary fires before the next real credential exfil.

**Pattern:**

1. Add `CANARY_2026_APR_<random-id>=<random-token>` to the Vercel project env at target=production, type=plain (intentionally not `sensitive` — we WANT it readable).
2. Wire into application code to log-on-read:
   ```js
   // e.g. server/boot.ts
   if (process.env.CANARY_2026_APR_XYZ) {
     fetch(process.env.CANARY_ALERT_WEBHOOK, {
       method: 'POST',
       body: JSON.stringify({
         event: 'canary-read',
         host: process.env.HOSTNAME,
         when: new Date().toISOString(),
       }),
     });
   }
   ```
3. Add a weekly audit cron that queries Vercel's activity log for any CLI/API read of the canary project's env metadata. The canary itself is meant to be read — the SIGNAL is any access outside of expected build-time reads.
4. Rotate the canary quarterly (re-generate `<random-id>` + `<random-token>`) to avoid becoming an ignored fixture.

The canary is cheap, non-sensitive, and provides high-fidelity signal: there is no legitimate reason for the canary to be exfiltrated.

---

## 5. 2026 adjacent-SaaS pointers

Env-var exposure on Vercel has near-neighbors. If the customer uses any of these, check them with the same rigor:

- **Cloudflare Workers / Fastly Compute / Netlify Edge** — same env-var exposure class as Vercel if used adjacent. Pull their respective env listings and compare against the Vercel rotation worklist; duplicated secrets across platforms need rotation on both.
- **Stripe / Supabase / Neon dashboards** — "last auth from IP" on connection strings. Unusual IP or ASN on a DB connection string that was in the Vercel env = red flag.
- **Browser-extension token-stealer audit** — Chrome / Arc / Brave extensions with `cookies` permission scoped to `*.vercel.com` or `*.github.com`. 2026 supply-chain pattern: extension auto-updates to a malicious version, scrapes session cookies. List installed extensions + permissions on the investigation machine (`chrome://extensions`, Arc's Extensions pane).
- **Shadow SaaS via SCIM/SSO** — any Workspace-federated app that held a compromised OAuth token is a pivot path: Notion, Slack, Figma, PagerDuty, Linear, Airtable, Retool. List every app federated through the customer's Workspace SSO; prioritize apps with write access to source-of-truth data.
- **iCloud Keychain / 1Password / LastPass / Bitwarden shared-vault audit** — after OAuth scope review, do a credential-manager pivot. Any shared-vault entry whose "last accessed" falls inside the incident window deserves a look.

For each adjacent surface that turns up anomalies, open a new investigation scope. Do NOT bolt findings onto the frozen `vercel-forensics` case dir.

---

## 6. Post-forensics local CLI hygiene

After the skill completes and the evidence is frozen:

1. **Rotate the investigation Vercel token.** The token used for the pull was written to `~/Library/Application Support/com.vercel.cli/auth.json` during any interactive use, and is referenced by hash throughout Vercel's own activity log. Revoke it at vercel.com/account/tokens.
2. **Re-login with a fresh token:** `vercel logout && vercel login`.
3. **Revoke the investigation GitHub PAT** at github.com/settings/tokens. Do NOT reuse it.
4. **Confirm case dir remains locked:** `ls -la ~/.vercel-forensics/case-*/` — all entries should show `a-w` permissions. If any file is writable, something changed the frozen dir post-`freeze.sh` and chain of custody is broken.
5. **Store the case dir on the investigation machine only.** If it must move, copy with `rsync -a` (preserve mode), re-verify hashes against `MANIFEST.sha256` at destination, document the transfer in `CHAIN_OF_CUSTODY.md`.
6. **Clear shell history entries containing the investigation token if the operator pasted the token into a terminal.** `history -d <N>` or `history -c` as appropriate.

---

## 7. When to escalate to dedicated DFIR tooling

This skill produces engineering-triage evidence. The `freeze.sh` SHA-256 manifest + `chmod -R a-w` software WORM is sufficient for internal rotation decisions and vendor conversations. It is NOT sufficient for court-admissible exhibits.

**Escalate to dedicated DFIR tooling when:**

- Litigation is contemplated or underway.
- Regulatory reporting (SEC 8-K material cyber incident, GDPR Art. 33) requires a defensible chain-of-custody.
- Law enforcement is engaged.
- The incident spans hosts beyond the Vercel + GitHub surface (endpoints, mail servers, AD, on-prem).
- Admissibility under Federal Rules of Evidence 902(13)-(14), eIDAS qualified timestamps, or equivalent is required.

**Options:**

- **Velociraptor** — free, open-source endpoint DFIR framework. Query language (VQL) + artifact catalogue + server mode for fleet collection.
- **KAPE (Kroll Artifact Parser and Extractor)** — Windows-focused targeted collection + parsing. Free for non-commercial use.
- **Magnet AXIOM** — commercial, full-suite DFIR platform with court-admissibility workflows built in.
- **GRR Rapid Response** — Google's open-source fleet forensics tool.

**Or wait for v2 of this skill.** Deferred additions include GPG-signed manifests, dual-location manifest copies, RFC 3161 Trusted Timestamping Authority integration, and a `verify-scene.sh` companion. Those lift the evidentiary bar to court-admissible without switching tools. Resume trigger: demand signal from a real case with admissibility requirements.
