# Incident Reference

Real-world supply chain attacks, CVEs, CISA alerts, and GitHub Security Lab
advisories related to GitHub Actions.

---

## Table of Contents

- [tj-actions/changed-files (CVE-2025-30066)](#tj-actionschanged-files-cve-2025-30066)
- [reviewdog/action-setup (CVE-2025-30154)](#reviewdogaction-setup-cve-2025-30154)
- [Full Attack Chain Timeline](#full-attack-chain-timeline)
- [CISA Recommendations](#cisa-recommendations)
- [OpenSSF Post-Incident Guidance](#openssf-post-incident-guidance)
- [GitHub Security Lab Advisories](#github-security-lab-advisories)
- [OWASP Top 10 CI/CD Risks](#owasp-top-10-cicd-risks)
- [Other Notable Incidents](#other-notable-incidents)

---

## tj-actions/changed-files (CVE-2025-30066)

**CVE:** CVE-2025-30066
**CVSS:** 8.6 (High) — `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N`
**EPSS:** 86.6th percentile
**CWE:** CWE-506 (Embedded Malicious Code)
**Affected:** All tags v1 through v45.0.7 (during March 12–15, 2025 window)
**Fixed:** v46.0.1

### What Happened

Attackers retroactively modified multiple version tags to point to a malicious
commit. The payload:

1. Downloaded `memdump.py` from a GitHub Gist
2. Scanned Runner Worker **process memory** for secrets
3. Base64-encoded secrets and printed them to workflow logs
4. Public repos had logs publicly accessible

### Impact

- 23,000+ repositories used the action
- 218 repositories had secrets actively exposed
- Stolen: API keys, GitHub PATs, npm tokens, private RSA keys, cloud credentials
- Public repositories at highest risk (logs publicly readable)

### Malicious Artifacts

- Malicious commit SHA: `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- Tags redirected: `v1.0.0`, `v35.7.7-sec`, `v44.5.1`

### Detection

StepSecurity Harden-Runner flagged an unauthorized outbound network request
to `gist.githubusercontent.com`.

### Remediation

1. Review workflow runs from March 14–15, 2025
2. Decode suspicious base64 output: `echo 'xxx' | base64 -d | base64 -d`
3. Rotate ALL secrets that were in runner environment during that window
4. Update to v46.0.1 or later
5. Pin to commit SHA going forward

---

## reviewdog/action-setup (CVE-2025-30154)

**CVE:** CVE-2025-30154
**Affected:** `v1` tag during the attack window

The `v1` tag was redirected to a malicious commit from fork user `iLrmKCu86tjwp8`.
This was the **root enabler** for the tj-actions compromise.

---

## Full Attack Chain Timeline

This was a **multi-hop supply chain attack** spanning 4+ months:

| Date | Event |
|------|-------|
| Nov 2024 | Attacker exploits vulnerable `pull_request_target` workflow in `spotbugs/spotbugs`, steals maintainer PAT |
| Dec 6, 2024 | Uses stolen SpotBugs PAT to add dummy user to `spotbugs/spotbugs` |
| Shortly after | Malicious workflow extracts second PAT belonging to `reviewdog` maintainer |
| Mar 11, 2025 | Uses reviewdog PAT to override `reviewdog/action-setup` `v1` tag → malicious commit |
| Mar 14, 2025 | `tj-actions/changed-files` CI runs, depends on `tj-actions/eslint-changed-files` → depends on `reviewdog/action-setup` → malicious code executes → steals tj-actions token |
| Mar 14, 2025 | Attacker overrides tj-actions tags → memory-dumping payload targeting Coinbase's `agentkit` |
| Mar 14–15 | Active exploitation window; 218 repos have secrets exposed |
| Mar 15, 2025 | Compromise detected; GHSA-mrrh-fwg8-r2c3 published |
| Mar 18, 2025 | CISA issues alert |
| Mar 20, 2025 | Maintainers apply mitigations |

### Attack Graph

```
Vulnerable pull_request_target (spotbugs)
  → SpotBugs maintainer PAT stolen
    → reviewdog/action-setup v1 tag poisoned (CVE-2025-30154)
      → tj-actions/changed-files CI runs malicious action
        → tj-actions GitHub token stolen
          → tj-actions tags poisoned (CVE-2025-30066)
            → 23,000+ downstream repos affected
```

**Primary target:** Coinbase's `coinbase/agentkit`. Coinbase's additional
defenses prevented successful exploitation.

### Key Lessons

- **Mutable tags are the root enabler** — SHA pinning would have prevented the cascade
- **Transitive dependencies are opaque** — tj-actions didn't directly use reviewdog
- **Shared maintainer credentials multiply blast radius** — one PAT traversed multiple repos
- **Automated invitation processes are attack surface** — attacker exploited auto-join mechanism

---

## CISA Recommendations

From CISA Alert (March 18, 2025):

1. Identify if your workflows used `tj-actions/changed-files` between March 12–15
2. **Rotate all potentially exposed secrets immediately**
3. Audit workflow logs for unexpected base64-encoded blobs
4. Update or remove references to the compromised action
5. **Pin actions to full commit SHAs** — not mutable tags
6. Review and reduce GITHUB_TOKEN permissions in all workflows

CVE-2025-30066 was added to the **CISA Known Exploited Vulnerabilities (KEV)** catalog.

---

## OpenSSF Post-Incident Guidance

From OpenSSF (June 2025): "Maintainers' Guide: Securing CI/CD Pipelines
After the tj-actions and reviewdog Supply Chain Attacks"

### Core Message

**Assume any third-party component or credential in your CI pipeline can be
a potential target.** The tj-actions/reviewdog attacks serve as a blueprint
for attackers.

### Recommendations

1. Pin all actions to full commit SHAs — the only immutable release reference
2. Restrict allowed actions via organization policy
3. Audit and prune unused third-party actions regularly
4. Enforce MFA on all contributors with commit/release privileges
5. Use short-lived credentials (OIDC) instead of long-lived secrets
6. Apply least-privilege GITHUB_TOKEN permissions
7. Monitor for anomalous outbound network traffic from runners
8. Consider runtime egress filtering (Harden-Runner)
9. Adopt defense-in-depth — no single control is sufficient

---

## GitHub Security Lab Advisories

### Common Vulnerability Pattern

The dominant type across SecLab advisories is **GitHub Actions expression /
command injection** — untrusted context values interpolated into `run:` steps.

### Selected Advisories

| Advisory | Project | Vulnerability |
|----------|---------|---------------|
| GHSL-2021-001 | Saagie | Command injection + secret exfiltration |
| GHSL-2023-107 | Jellyfin | `github.head_ref` injection in `pull_request_target` |
| GHSL-2023-108 | Stash | `github.event.comment.body` injection |
| GHSL-2023-181 | pytorch/pytorch | `workflow_run` injection via `head_branch` |
| GHSL-2024-145 | Discord.js | Expression injection → repository takeover + secret theft |
| GHSL-2025-090 | Harvester | Code injection in privileged context |
| GHSL-2025-101 | homeassistant-tapo-control | Code injection (CVE-2025-55192) |
| GHSL-2025-111 | nrwl/nx | Privilege escalation via GitHub Actions |

### SecLab Publications

Key articles for understanding attack evolution:

1. **Part 1 — Preventing pwn requests:** `pull_request_target` attack patterns
2. **Part 2 — Untrusted input:** Expression injection deep dive
3. **Part 4 — New patterns:** `workflow_run` trigger manipulation, cache poisoning, artifact poisoning

### Artifact Privilege Escalation (Google Security Research)

**GHSA-cj34-9v6h-grxm** (June 2024): Path traversal in artifact download
action allowed escape from extraction directory → overwrite runner files →
code execution in privileged `workflow_run` context. Undermines the
"workflow splitting" mitigation pattern.

---

## OWASP Top 10 CI/CD Risks

GitHub Actions-relevant risks from the OWASP CI/CD Security project:

| Risk | Description | GitHub Actions Relevance |
|------|-------------|------------------------|
| CICD-SEC-1 | Insufficient Flow Control | No required reviews/approvals before privileged actions |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) | Attacker-controlled code runs in CI with secret access |
| CICD-SEC-6 | Insufficient Credential Hygiene | Long-lived secrets, over-scoped tokens, env var exfiltration |
| CICD-SEC-7 | Insecure System Configuration | Permissive GITHUB_TOKEN, misconfigured runners |

### Referenced Real-World Incidents

- **SolarWinds:** Build system compromise → 18,000 customers affected
- **Codecov:** Modified upload script → env var (secret) exfiltration from thousands of CI pipelines
- **PHP:** Malicious backdoor via compromised commit
- **Dependency Confusion:** Namespace collisions in package registries

---

## Other Notable Incidents

### Discoveries by Security Researchers

| Researcher | Finding | Impact |
|-----------|---------|--------|
| Orca Security | `pull_request_target` RCE in Microsoft Symphony | Reverse shell → code push to origin |
| Orca Security | Typosquatting in Actions marketplace (14 orgs) | 198 workflow files affected by `actons/checkout` |
| Synacktiv | Repo jacking in Azure, Firebase, Alibaba workflows | Actions referencing deleted orgs |
| Legit Security | `workflow_run` privilege escalation across major repos | Thousands of repos vulnerable |
| Google Security Research | Artifact path traversal (GHSA-cj34-9v6h-grxm) | Undermines workflow splitting pattern |
| Praetorian | TensorFlow supply chain via self-hosted runner | Runner persistence → infrastructure access |
| Cycode (Raven) | Cross-workflow vulns in FreeCodeCamp, Microsoft Fluent UI, Storybook | Multi-step chains invisible to static scanners |
