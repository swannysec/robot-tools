---
name: gha-hardening
description: |
  GitHub Actions security hardening, configuration best practices, and
  vulnerability detection. Covers workflow syntax, trigger security,
  permission management, secrets handling, OIDC federation, supply chain
  protection, self-hosted runner hardening, attack pattern recognition,
  and security scanning tool rules.

  60% security/hardening content, 40% implementation/configuration guidance.

  Use this skill when users need to:
  (1) Harden GitHub Actions workflows against injection, supply chain, or
      privilege escalation attacks
  (2) Configure workflow permissions, secrets, OIDC, or environment
      protection rules securely
  (3) Understand dangerous workflow patterns (pull_request_target + checkout,
      workflow_run artifact poisoning, script injection via ${{ }})
  (4) Choose or configure security scanning tools (zizmor, scorecard,
      actionlint, poutine, harden-runner, Raven)
  (5) Respond to supply chain incidents (tj-actions, reviewdog, compromised
      action tags)
  (6) Audit workflows for OWASP CI/CD risks, CIS benchmark compliance, or
      OpenSSF Scorecard checks
  (7) Write or review workflow YAML (triggers, matrix, reusable workflows,
      composite actions, caching, artifacts, environments)
  (8) Secure self-hosted runners (ephemeral patterns, network egress,
      persistence detection, runner groups)
triggers:
  - "github actions security"
  - "github actions hardening"
  - "gha security"
  - "gha hardening"
  - "workflow security"
  - "actions security"
  - "actions hardening"
  - "github actions best practices"
  - "secure github actions"
  - "harden workflows"
  - "pull_request_target"
  - "workflow_run security"
  - "script injection actions"
  - "template injection actions"
  - "action pinning"
  - "sha pinning actions"
  - "supply chain actions"
  - "tj-actions"
  - "zizmor"
  - "scorecard checks"
  - "actionlint security"
  - "poutine scanner"
  - "harden-runner"
  - "GITHUB_TOKEN permissions"
  - "oidc github actions"
  - "self-hosted runner security"
  - "github actions audit"
---

# GitHub Actions Hardening

Security hardening and configuration best practices for GitHub Actions.

---

## Help — Topic Navigator

Use this table to find the right reference file. Load references **only when
needed** for the user's specific question.

| Topic | Reference File | Covers |
|-------|---------------|--------|
| Workflow syntax & config | `references/workflow-configuration.md` | Triggers, matrix, environments, reusable workflows, composite actions, caching, artifacts, runners |
| Security hardening | `references/security-hardening.md` | Permissions, secrets, OIDC, GITHUB_TOKEN, push protection, governance policies |
| Attack patterns | `references/attack-patterns.md` | Injection, pwn requests, workflow_run escalation, GITHUB_ENV, artifact poisoning, repo jacking |
| Supply chain security | `references/supply-chain-security.md` | SHA pinning, tj-actions incident, typosquatting, Dependabot, compromised action detection |
| Runner security | `references/runner-security.md` | Self-hosted threats, ephemeral patterns, ARC, persistence techniques, runner groups |
| Detection tools | `references/detection-tools.md` | Zizmor 30+ rules, Scorecard 18 checks, Poutine, Actionlint, Harden-Runner, Snyk scanner, Raven |
| Incident reference | `references/incident-reference.md` | CVE database, tj-actions timeline, SecLab advisories, CISA alerts, real-world exploits |

---

## Top 10 Security Rules

These are the highest-priority hardening measures. Apply them to every
GitHub Actions workflow.

### 1. Never interpolate untrusted input into `run:` blocks

Route all `github.event.*`, `github.head_ref`, and user-supplied values
through `env:` variables — never use `${{ }}` directly in `run:` steps.

```yaml
# DANGEROUS
- run: echo "${{ github.event.pull_request.title }}"

# SAFE
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "$PR_TITLE"
```

Dangerous fields include anything ending in: `body`, `title`, `ref`, `name`,
`message`, `email`, `label`, `page_name`.

### 2. Pin all third-party actions to full commit SHAs

Tags are mutable — the tj-actions/changed-files attack (CVE-2025-30066)
compromised 23,000+ repos by redirecting version tags.

```yaml
# VULNERABLE — tag can be silently redirected
- uses: actions/checkout@v4

# SECURE — immutable SHA with version comment
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

Use Dependabot (`package-ecosystem: github-actions`) to keep SHA pins current.

### 3. Set explicit minimal `permissions:`

Always declare `permissions:` at the workflow level. When present, all
unspecified scopes default to `none`.

```yaml
permissions:
  contents: read

jobs:
  deploy:
    permissions:
      contents: read
      id-token: write    # only when OIDC is needed
```

Repos created before Feb 2, 2023 may still default to read/write — audit them.

### 4. Use OIDC instead of long-lived cloud secrets

OIDC tokens are ephemeral — no secret to rotate, leak, or exfiltrate.

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: aws-actions/configure-aws-credentials@<SHA>
    with:
      role-to-assume: arn:aws:iam::123456789:role/GitHubRole
      aws-region: us-east-1
```

Scope trust policies using `sub` (with `environment`) + `aud` claims.

### 5. Never use self-hosted runners on public repositories

Any user can open a PR and trigger code execution on internal infrastructure.
Use ephemeral (JIT) runners, restrict egress, and isolate by runner group.

### 6. Never combine `pull_request_target` with code checkout

`pull_request_target` runs with secrets and write access — checking out
the PR head gives attacker code full privileged execution.

```yaml
# DANGEROUS — RCE with secrets
on: pull_request_target
steps:
  - uses: actions/checkout@<SHA>
    with:
      ref: ${{ github.event.pull_request.head.ref }}  # attacker code

# SAFE — no checkout, just label
on: pull_request_target
permissions:
  pull-requests: write
  contents: none
steps:
  - uses: actions/labeler@<SHA>
```

### 7. Treat all `workflow_run` artifacts as untrusted

Artifacts from fork PRs cross a trust boundary. Never execute artifact
content — extract to `/tmp`, validate as structured data only.

### 8. Scope environment secrets with required reviewers

Use named environments (dev/staging/prod) with required reviewer approval
for deployment credentials. This provides a human gate between merge and
deploy.

### 9. Evaluate third-party actions before adoption

Check for: verified creator badge, source audit, unpinnable dynamic deps,
maintenance status. Enforce org-level allowed actions policy.

### 10. Use `::add-mask::` for dynamic secrets

For runtime-generated tokens not stored as GitHub Secrets:

```yaml
- run: |
    TOKEN=$(generate-token)
    echo "::add-mask::$TOKEN"
    echo "TOKEN=$TOKEN" >> "$GITHUB_OUTPUT"
```

Call `add-mask` **before** any step that could log the value.

---

## Dangerous Patterns — Quick Reference

### Script Injection via `${{ }}`

**Trigger:** Any `run:` step interpolating attacker-controlled context.

**Fix:** Use `env:` mapping. See Rule 1 above.

### Pwn Request (`pull_request_target` + checkout)

**Trigger:** `pull_request_target` trigger + `actions/checkout` with
`ref:` pointing to PR head.

**Fix:** Use `pull_request` (read-only for forks) for code execution.
Use `pull_request_target` only for label/comment ops without checkout.

### workflow_run Privilege Escalation

**Trigger:** Privileged `workflow_run` downloads and executes artifacts
from an unprivileged `pull_request` workflow.

**Fix:** Extract artifacts to isolated paths. Only read structured data
(PR numbers, coverage scores). Never execute artifact content.

### GITHUB_ENV / GITHUB_PATH Injection

**Trigger:** Attacker-controlled content written to `$GITHUB_ENV` or
`$GITHUB_PATH` (e.g., from artifacts or untrusted input).

**Fix:** Never write untrusted data to environment files. Validate all
input before appending to `$GITHUB_ENV`.

### Repo Jacking

**Trigger:** `uses:` references an org/user that no longer exists.
Attacker registers the namespace and publishes a malicious action.

**Fix:** SHA-pin all actions. Audit for references to renamed/deleted orgs.

### Typosquatting

**Trigger:** Misspelled action owner (e.g., `actons/checkout` instead of
`actions/checkout`).

**Fix:** Maintain an org-level allowlist of permitted actions. Double-check
owner names. SHA pinning catches mismatches.

### Impostor Commits

**Trigger:** SHA-pinned action references a commit from a fork network,
not the actual repository.

**Fix:** Verify SHAs correspond to tagged releases. Use zizmor's
`impostor-commit` audit rule.

### Cache Poisoning

**Trigger:** Fork PR injects malicious content into GitHub Actions cache.
Privileged downstream workflow restores the poisoned cache.

**Fix:** Scope caches carefully. Do not restore caches in release
workflows from branches that accept fork PRs.

---

## Workflow Security Checklist

Use this before merging any workflow change:

- [ ] `permissions:` declared explicitly (workflow or job level)
- [ ] All third-party actions pinned to full commit SHA
- [ ] No `${{ }}` interpolation of untrusted input in `run:` steps
- [ ] No `pull_request_target` + checkout of PR head
- [ ] `workflow_run` artifacts treated as untrusted data
- [ ] Self-hosted runners not exposed to public repos
- [ ] OIDC used instead of long-lived cloud credentials where possible
- [ ] Environment secrets gated by required reviewers for production
- [ ] `persist-credentials: false` on `actions/checkout` in sensitive workflows
- [ ] Dependabot configured for `github-actions` ecosystem

---

## Security Scanner Quick Comparison

| Tool | Type | Primary Strength |
|------|------|-----------------|
| **zizmor** | Static | Broadest rule set (30+ rules): injection, impostor commits, cache poisoning, permissions |
| **Scorecard** | Static | Project-level security posture (18 checks): Dangerous-Workflow, Token-Permissions, Pinned-Dependencies |
| **Poutine** | Static | Cross-platform CI/CD (GitHub, GitLab, Azure); "Living Off The Pipeline" detection |
| **Actionlint** | Static | Workflow YAML validation + untrusted input detection |
| **Harden-Runner** | Runtime | Network egress monitoring, file integrity, anomaly detection (caught tj-actions attack) |
| **Raven** | Graph | Multi-step cross-workflow vulnerability detection via Neo4j |
| **Snyk Scanner** | Static | Regex-based rule engine; includes LD_PRELOAD PoC generator |

For complete rule references, load `references/detection-tools.md`.
