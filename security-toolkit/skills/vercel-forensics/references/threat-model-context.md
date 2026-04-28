# Threat Model Context

The threat landscape the `vercel-forensics` skill is built to investigate. Anchored on the 2026-04-19 Vercel incident (third-party AI tool's Google Workspace OAuth app compromised → pivot into Vercel's internal Linear + GitHub → customer env-var metadata exposed), generalized into a reusable 5-phase attack chain with STRIDE overlay, six plausible Phase-3 pivot sub-paths, and the three-tier env-var threat model that drives rotate-vs-harden decisions.

This file is the "what the threat is" companion to `analysis-methodology.md` ("how to analyze"). It is descriptive context, not runtime rules — the Preservation Contract and Runtime Reinforcement in `SKILL.md` are the operational authorities.

## Table of contents

1. [5-phase attack chain (2026-04-19 template)](#1-5-phase-attack-chain-2026-04-19-template)
2. [STRIDE overlay per known phase](#2-stride-overlay-per-known-phase)
3. [Six plausible Phase-3 pivot sub-paths](#3-six-plausible-phase-3-pivot-sub-paths)
4. [Three-tier env-var threat model (subinium)](#4-three-tier-env-var-threat-model-subinium)
5. [Customer-side vs vendor-side defenses](#5-customer-side-vs-vendor-side-defenses)
6. [2026 adjacent threat classes](#6-2026-adjacent-threat-classes)

---

## 1. 5-phase attack chain (2026-04-19 template)

| Phase | Status | What happened |
|---|---|---|
| 1 | KNOWN | Compromise a third-party AI tool's Google Workspace OAuth application. Upstream mechanism (phishing, credential leak, vendor breach, insider access) was not disclosed. |
| 2 | KNOWN | Malicious OAuth app holds valid Workspace tokens. Scope set determines blast radius; specific scopes were not disclosed. |
| 3 | KNOWN + INFERENTIAL | Pivot from Workspace foothold to Vercel internal Linear + GitHub. Specific TTPs were not disclosed; six plausible sub-paths enumerated in §3. |
| 4 | KNOWN | Internal access at Vercel. Parallel outcomes: (4a) customer env-var names enumerated, non-sensitive values possibly read; (4b) internal Linear read; (4c) internal GitHub source read; (4d) possible employee-records exfil (580-record sample corroborated by independent reporting). |
| 5 | KNOWN | Monetization via BreachForums listing + Telegram ransom ask. Brand attribution disputed. |

Customer-side relevance: Phase 4a is the step that touches customers directly. Phases 1-3 are outside customer control but determine whether future blast radius extends beyond env-var names. If Vercel later discloses SSO tokens or federated credentials were involved, Phase 3 becomes a re-assessment trigger.

Phase 4d is currently unverified attacker claims beyond the 580-record corroboration, not confirmed exposure.

---

## 2. STRIDE overlay per known phase

STRIDE legend: **S** Spoofing · **T** Tampering · **R** Repudiation · **I** Information Disclosure · **D** Denial of Service · **E** Elevation of Privilege.

| Phase | Primary | Secondary | Rationale |
|---|---|---|---|
| 1 — Compromise AI tool's OAuth client | **S** | E | Attacker ends up acting *as* the legitimate OAuth app — a textbook spoofing outcome at the relying party. |
| 2 — Malicious app holds Workspace tokens | **E** | I, S | Token issuance to a spoofed client is an elevation event from the relying party's perspective; broad scopes enable information disclosure. |
| 3 — Pivot to Linear + GitHub | **E** | S, I | Workspace foothold becomes session/token access to adjacent SaaS. |
| 4a — Env-var names read | **I** | — | Pure read on a confidentiality asset. No integrity/availability impact reported. |
| 4b — Internal Linear read | **I** | R | Confidentiality of roadmap/ops content; secondary repudiation because reads occur as legitimate employee identities, defeating accountability. |
| 4c — Internal GitHub repos read | **I** | T, E | If CI secrets, deploy keys, or PATs were reachable, tampering and privilege-escalation branches open immediately. |
| 4d — Employee records claim | **I** | R | Partially corroborated (580-record sample). Broader claims unverified. |
| 5 — Monetization | **R** | I | Attacker-side outcome; not a technical STRIDE event against Vercel. Included for completeness. |

---

## 3. Six plausible Phase-3 pivot sub-paths

Vercel has not published TTPs for the Workspace-to-Linear/GitHub pivot. The sub-paths below are consistent with the published bulletin (third-party AI tool's Workspace OAuth app compromised) plus the attacker's claim of "access to multiple employee accounts with access to several internal deployments."

| # | Sub-path | STRIDE | Plausibility | Notes |
|---|---|---|---|---|
| 3a | **OAuth token trove in Drive/Gmail** — malicious app with `drive.readonly` or `gmail.readonly` harvests `.env` files, PAT emails, password-reset flows, and Linear/GitHub session cookies sitting in mailbox attachments | I → E | High | Single technique explains "hundreds of users across many orgs." |
| 3b | **Google SSO session cookie / refresh token theft** — federated identity (Linear/GitHub SSO via Workspace) exploited by cookie or token-reachable scopes | S → E | Medium-high | Explains the specific Linear + GitHub pairing. |
| 3c | **Admin-API scope abuse** — app holds `admin.directory.*` or delegated-admin scope; enumerates or creates service accounts and pivots into Google-linked SaaS | E | Low-medium | Requires unusually permissive grant; blast radius would exceed what was reported. |
| 3d | **OAuth grant chain** — victim had previously authorized the same malicious app with Linear and GitHub OAuth scopes directly ("install our AI in Linear/GitHub" single-flow) | S, E | Medium | Explains Linear + GitHub being reached without Google-side scope abuse. |
| 3e | **Secondary phishing using the Workspace foothold** — attacker sends Gmail-authentic phishing from trusted internal threads, harvesting Linear/GitHub credentials | S | Medium | Slower; less consistent with the attacker's implied timeline but plausible. |
| 3f | **Stored secrets in Drive docs / Notes** — runbooks, onboarding docs, or ticket attachments containing Linear API keys or GitHub PATs | I → E | Medium-high | Matches common enterprise reality that secrets leak into collaboration docs. |

For blast-radius questions across orgs that used the same AI tool, 3a / 3d / 3f are the branches that most change the answer — they imply cross-org harvesting of identical OAuth grants.

---

## 4. Three-tier env-var threat model (subinium)

*Attribution: the three-tier model is borrowed from `subinium/vercel-incident-toolkit` and is the single most load-bearing concept in the skill's rotation decisions.*

The assumption that "sensitive means safe" is wrong in a way that costs incidents. The accurate model is where the decryption key sits, not whether the value is labeled sensitive.

| Type | Decryption-key location | Post-breach assumption |
|---|---|---|
| **`plain`** | Nowhere — stored as plaintext | **Assume leaked** in any breach reaching the env-var store |
| **`encrypted`** | Vercel internal KMS, decrypted server-side for dashboard and runtime | **Assume leaked** in any breach reaching internal systems (2026-04-19 case) |
| **`sensitive`** | Restricted path; non-readable after creation, not returned by dashboard or API | **Probably survived** unless the breach reached the build / runtime sandbox — `sensitive` is not magical; build-time access still exposes |

### Rules that follow from the table

1. **Rotation beats hardening** for any value that may have been leaked. Promoting `encrypted` → `sensitive` after a breach does nothing for a value an attacker has already read.
2. **`sensitive` is not invulnerability.** If the attacker reached the build or runtime sandbox, the value was decrypted there and may have been exfiltrated — promotion does not retroactively protect it.
3. **Type changes are destructive** — upgrading `plain` or `encrypted` to `sensitive` is delete-plus-create, not in-place edit. Plan downtime or use overlapping keys during cutover.
4. **Rotate first, reclassify second.** The rotation cycle itself is the protection; the reclassification reduces the blast radius of the *next* incident.
5. **Vercel-managed values** (e.g., `VERCEL_URL`) are not customer secrets and have no decryption key relevant to this model — exclude from rotation worklists.

### Applied to the 2026-04-19 incident

Non-sensitive env values reachable via Vercel internal systems are in-scope for rotation under Vercel's own guidance. Values stored as `sensitive` are *probably* unaffected under the current threat model; the skill still surfaces them as low-priority review items and surfaces the caveat that Phase 4 scope could yet widen.

---

## 5. Customer-side vs vendor-side defenses

What a Vercel customer can control vs what is Vercel-side only. The skill's findings and rotation worklist address the customer side; it surfaces Vercel-side items as context, never as action items.

### Customer-controllable

- **Scope minimization** on third-party OAuth integrations — request narrowest Google/Microsoft scopes; deny broad Drive / Gmail scopes unless justified.
- **Workspace OAuth app allowlisting** — admin-approved list for the org's Google Workspace; mandatory review for `drive.readonly`, `gmail.readonly`, `admin.directory.*`.
- **`sensitive` by default** — mark every high-risk env var `sensitive` at creation time; prefer runtime-fetched secrets via Vault / Doppler / 1Password for the highest tier rather than Vercel env vars at all.
- **Phishing-resistant MFA (WebAuthn/passkey)** on every federated SaaS (GitHub, Linear, etc.) — breaks 3b entirely and 3d partially.
- **Log Drains configured to a retained sink** — forensics-enabling regardless of which SaaS is the next victim.
- **Branch protection + required signed commits** on customer repos — blunts worst-case 4c abuse if attacker reaches *customer* GitHub.
- **Workspace OAuth audit log alerting** on new third-party app grants — detection, not prevention.

### Vendor-side only (Vercel must do these)

- Ship customer env vars with `sensitive: true` by default (product change at Vercel).
- Internal phishing-resistant MFA on Vercel employee accounts accessing Linear / GitHub.
- Internal workload-identity federation instead of long-lived PATs stored in Linear or docs.
- Vercel-side Workspace OAuth app allowlist for Vercel employees.
- Short-lifetime access tokens with refresh-token revocation policy Vercel-side.

The skill never prescribes Vercel-side changes — those are documented as context but excluded from findings reports, which cover only customer-actionable items.

---

## 6. 2026 adjacent threat classes

Sibling trees worth modeling and tracking alongside the current incident. None are part of the 2026-04-19 chain directly, but each is a 2026-native pivot surface that a post-incident hardening cycle should cover.

| Class | Mechanism | Why it matters now |
|---|---|---|
| **OAuth device-code phishing** | Device-code flow decouples auth from originating session; attacker initiates a code and socials the user into entering it | Bypasses most MFA. Microsoft Security logged 10-15 campaigns per 24h starting March 2026. A hardening cycle focused only on "malicious OAuth app registration" misses this variant. |
| **MCP server / AI-agent credential theft** | MCP servers and agent frameworks routinely hold Linear / GitHub / Slack / cloud tokens; a compromised MCP server or prompt-injected agent is a 2026-native Phase-3 pivot | Inventory which MCP servers hold which tokens, where tokens live on disk, whether any MCP server auto-updates from npm / a registry. |
| **npm / PyPI postinstall supply-chain injection** | Malicious package with token-exfil postinstall ships via dep update; build log shows outbound to attacker host | Adjacent to 4c. Covered by `build-log-scan.py` IOC regex; still a standing watch item. |
| **AI coding-agent prompt injection to exfil env vars** | Agent with env-var read scope in CI is induced to echo values to stdout via a crafted file in a PR | 2026-specific. Mitigation: agent-scoped token boundaries + env-var read gating at the agent harness. |
| **Supply-chain OAuth scope creep** | Third-party SaaS adds new scopes on update; Google re-consent dialog clicked-through by default | Quarterly Workspace OAuth audit catches this. Not a zero-day, a drift problem. |

Each of these is a *sibling tree*, not an extension of the current one. Model them separately when resources allow. The `vercel-forensics` skill surfaces signals that are consistent with any of them (anomalous outbound hosts in build logs, unexpected MCP-token-path changes if `mcp-inventory.sh` ships in v2) but does not attribute findings to them without separate corroboration.
