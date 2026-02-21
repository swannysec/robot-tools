# Detection Tools Reference

Security scanning tool rules, checks, and detection coverage for GitHub
Actions workflows. Focus: what each tool detects and why it matters.

---

## Table of Contents

- [Zizmor Audit Rules](#zizmor-audit-rules)
- [OpenSSF Scorecard Checks](#openssf-scorecard-checks)
- [Poutine Detection Rules](#poutine-detection-rules)
- [Actionlint Security Checks](#actionlint-security-checks)
- [StepSecurity Harden-Runner](#stepsecurity-harden-runner)
- [Snyk GitHub Actions Scanner](#snyk-github-actions-scanner)
- [Cycode Raven](#cycode-raven)
- [Detection Coverage Matrix](#detection-coverage-matrix)

---

## Zizmor Audit Rules

Static analysis for GitHub Actions workflows and composite actions.
Docs: https://docs.zizmor.sh/audits/

### Complete Rule Reference

| Rule | Severity | What It Detects | Why It's Dangerous |
|------|----------|-----------------|-------------------|
| `artipacked` | Medium | `actions/checkout` without `persist-credentials: false` | Git credentials stored on disk may be exposed in artifacts |
| `bot-conditions` | High | `github.actor` checks to gate privileged actions for bots | `github.actor` reflects last actor, not original creator — spoofable |
| `cache-poisoning` | High | Release workflows restoring cache from branches accepting fork PRs | Attacker-poisoned cache content enters release builds |
| `dangerous-triggers` | High | `pull_request_target` and `workflow_run` triggers | Run in target repo context while triggerable by forks |
| `excessive-permissions` | High | Over-scoped `permissions:` or missing `permissions: {}` | Compromised code inherits broad GITHUB_TOKEN scopes |
| `github-env` | High | Dangerous writes to `GITHUB_ENV` / `GITHUB_PATH` in fork-triggered workflows | `LD_PRELOAD` via env or `PATH` shadowing achieves code execution |
| `hardcoded-container-credentials` | High | Docker credentials hardcoded in workflow YAML | Credentials exposed in logs, history, and forks |
| `impostor-commit` | High | SHA-pinned `uses:` pointing to fork network commits | Backdoored action appears legitimately hash-pinned |
| `insecure-commands` | High | `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` | Re-enables deprecated injection-vulnerable workflow commands |
| `known-vulnerable-actions` | High | Actions with CVEs in GitHub Advisories database | Direct vulnerability exposure |
| `overprovisioned-secrets` | High | `toJson(secrets)` exposing entire secrets context | All secrets loaded into runner environment |
| `secrets-inherit` | Medium | `secrets: inherit` in reusable workflow calls | Passes all caller secrets, violating least privilege |
| `secrets-outside-env` | Medium | Secrets used in jobs without a named environment | No deployment protection rules applied |
| `template-injection` | High | `${{ }}` in `run:` or code-execution contexts with attacker-controllable values | Template expansion before shell interpretation = code injection |
| `unpinned-uses` | Medium | `uses:` not pinned by SHA (tag or branch pinned) | Upstream tag force-push delivers malicious code |
| `unpinned-images` | Medium | Container images without SHA256 pin | Mutable image tags can be overwritten at registry |
| `unredacted-secrets` | Medium | Secrets accessed via `fromJSON(secrets.X).field` | Extracted field not redacted in logs |
| `unsound-condition` | High | `if: |` with fenced `${{ }}` — trailing newline bypasses gate | Security `if:` conditions always evaluate to true |
| `unsound-contains` | Medium | `contains()` with string (not array) first argument | Substring match bypasses branch protection guards |
| `use-trusted-publishing` | Medium | Packaging workflows using long-lived tokens instead of OIDC | Persistent credential risk vs ephemeral Trusted Publishing |
| `ref-confusion` | Medium | Symbolic refs where branch/tag ambiguity exists | Attacker publishes conflicting ref taking precedence |
| `ref-version-mismatch` | Low | SHA comment doesn't match pinned commit | Dependabot silently ignores mismatched comments |
| `forbidden-uses` | Config | Allowlist/denylist enforcement on `uses:` (opt-in) | Organizational policy enforcement |
| `dependabot-cooldown` | Low | Missing `cooldown` in Dependabot config | Pulling just-released deps before they're vetted |
| `dependabot-execution` | High | `insecure-external-code-execution: allow` in Dependabot | Compromised package can steal credentials during resolution |
| `obfuscation` | Medium | Obfuscated `uses:` paths or expressions | Hides malicious actions from review |
| `stale-action-refs` | Low | SHA not pointing to a Git tag | Pinned to unreleased commit |
| `superfluous-actions` | Low | Actions duplicating pre-installed runner functionality | Unnecessary attack surface |
| `anonymous-definition` | Pedantic | Missing `name:` field | Reduced Actions UI visibility |
| `self-hosted-runner` | Pedantic | Self-hosted runner usage | Risk indicator for public repos |
| `undocumented-permissions` | Pedantic | Missing comments on `permissions:` blocks | Risk of over-scoping over time |
| `concurrency-limits` | Low | Missing concurrency settings | Resource exhaustion and race conditions |
| `archived-uses` | Low | `uses:` referencing archived repos | Unpatched vulnerabilities accumulate |
| `misfeature` | Low | `pip-install` on setup-python, CMD shell, non-standard shells | Security analysis limitations |

Auto-fix available for: `template-injection`, `unpinned-uses`, `artipacked`,
`excessive-permissions`, `unsound-condition`.

---

## OpenSSF Scorecard Checks

Project-level security posture. 0–10 scores per check.
Docs: https://scorecard.dev/

| Check | Risk | What It Evaluates |
|-------|------|-------------------|
| `Binary-Artifacts` | High | No generated binaries checked into source |
| `Branch-Protection` | High | Force-push prevention, reviewer requirements, status checks |
| `CI-Tests` | Low | CI runs before PR merge |
| `CII-Best-Practices` | Low | OpenSSF Best Practices badge level |
| `Code-Review` | High | Recent PRs reviewed before merge (human only) |
| `Contributors` | Low | Contributors from 3+ organizations |
| `Dangerous-Workflow` | **Critical** | No `pull_request_target` checkout, no script injection |
| `Dependency-Update-Tool` | High | Dependabot or Renovate configured |
| `Fuzzing` | Medium | OSS-Fuzz, ClusterFuzzLite, or native fuzz functions |
| `License` | Low | License file present with SPDX identifier |
| `Maintained` | High | 1+ commit/week in past 90 days |
| `Pinned-Dependencies` | Medium | Dockerfiles, shell scripts, `uses:` pinned by hash |
| `SAST` | Medium | CodeQL or SonarCloud in recent merged PRs |
| `Security-Policy` | Medium | `SECURITY.md` with contact info and disclosure process |
| `Signed-Releases` | High | Signature files in last 5 releases; SLSA provenance = 10/10 |
| `Token-Permissions` | High | Workflow-level read-only + job-level write grants |
| `Vulnerabilities` | High | No open OSV-tracked vulnerabilities |
| `Webhooks` | **Critical** | All webhooks have authentication secrets |

### Dangerous-Workflow Check (Critical)

Flags two patterns:
1. **Untrusted code checkout:** `pull_request_target` or `workflow_run` + PR head checkout
2. **Script injection:** `${{ }}` with attacker-controllable context in `run:` blocks

---

## Poutine Detection Rules

Cross-platform CI/CD scanner (GitHub, GitLab, Azure DevOps, Tekton).
Rules written in Rego (OPA).

| Rule | Severity | What It Detects |
|------|----------|-----------------|
| `injection` | Warning | `${{ }}` in `run:` or `actions/github-script` with attacker input |
| `untrusted_checkout_exec` | Error | `pull_request_target` checkout + "Living Off The Pipeline" tool execution |
| `unverified_script_exec` | Note | `curl URL \| bash` patterns without integrity verification |
| `default_permissions_on_risky_events` | Warning | `pull_request_target`/`issue_comment` without explicit `permissions:` |
| `pr_runs_on_self_hosted` | Warning | `pull_request` on self-hosted runners in public repos |
| `unpinnable_action` | Note | Composite actions with unpinnable transitive dependencies |
| `confused_deputy_auto_merge` | Error | `github.actor` as sole auth check for auto-merge |
| `debug_enabled` | Note | `ACTIONS_RUNNER_DEBUG: true` in workflow YAML |
| `if_always_true` | Error | `if:` conditions that always evaluate to true |
| `job_all_secrets` | Warning | `toJSON(secrets)` or dynamic `secrets[key]` access |
| `known_vulnerability_in_build_component` | Warning | Actions with CVEs in OSV database |
| `known_vulnerability_in_build_platform` | Warning | Vulnerable CI/CD platform versions |
| `github_action_from_unverified_creator_used` | Note | Actions from non-verified Marketplace creators |

### "Living Off The Pipeline" Detection

Poutine uniquely detects when `pull_request_target` checks out fork code and
then runs common dev tools (`npm`, `cargo`, `make`, linters) that execute
package manager hooks — achieving RCE through build tooling.

---

## Actionlint Security Checks

Workflow YAML validator with security-relevant checks.
Docs: https://rhysd.github.io/actionlint/

### Untrusted Inputs (`untrusted-inputs`)

Maintains a hardcoded list of attacker-controllable context variables. Flags
when any appear in `run:` or `actions/github-script` via `${{ }}`:

```
github.event.pull_request.title / .body
github.event.issue.title / .body
github.event.comment.body
github.event.review.body / review_comment.body
github.event.head_commit.author.name / .message
github.event.pages.*.page_name
github.event.*.body (via object filter)
```

### Other Security Checks

| Check | What It Detects |
|-------|-----------------|
| `credentials` | Literal passwords in `container.credentials.password` |
| `permissions` | Invalid scopes, unknown scope names, invalid access levels |
| `deprecated-commands` | `::set-env` and `::add-path` usage |
| `if-cond-constant` | Constant `if:` conditions (potential bypassed gates) |

---

## StepSecurity Harden-Runner

Runtime security monitoring using eBPF. The **only runtime tool** in this set.

### What It Monitors

| Category | Details |
|----------|---------|
| **Network egress** | All outbound connections correlated per step/job/workflow |
| **File integrity** | Every file write with process correlation (Enterprise) |
| **Process execution** | Process names, arguments, process tree (Enterprise) |
| **GitHub API calls** | Outbound HTTPS to GitHub APIs per job (Enterprise) |
| **Source code tampering** | Unauthorized modifications during CI/CD |

### Egress Modes

- `audit` — monitor and log, do not block
- `block` — enforce domain allowlist; block all other traffic

### Real-World Detections

| Incident | How It Was Detected |
|----------|-------------------|
| tj-actions/changed-files (CVE-2025-30066) | Anomalous egress to `gist.githubusercontent.com` |
| Google Flank supply chain attack | Unexpected outbound domain connection |
| NX build system compromise | Malicious payload network calls |
| Microsoft Azure Karpenter Provider | Anomalous outbound calls in real time |

---

## Snyk GitHub Actions Scanner

Regex-based Node.js rule engine from Snyk Labs (research tool).

| Rule | What It Detects |
|------|-----------------|
| `CMD_EXEC` | `${{ }}` in `run:` with attacker-controlled values |
| `CODE_INJECT` | `${{ }}` in `actions/github-script` script input |
| `PWN_REQUEST` | `pull_request_target` + PR branch checkout |
| `UNSAFE_INPUT_ASSIGN` | Attacker input passed by value via `with:` |
| `WORKFLOW_RUN` | `workflow_run` + checkout of triggering branch |
| `REPOJACKABLE` | `uses:` references to renamed/deleted orgs |
| `UNPINNED_ACTION` | `uses:` pinned to branch or tag (not SHA) |

Includes `ldpreload-poc` command for PoC exploit generation.

---

## Cycode Raven

Graph-based vulnerability detection using Neo4j.

### How It Works

1. Downloads GitHub Actions workflows from target repos
2. Indexes into Neo4j graph database
3. Uses Cypher queries to detect multi-step vulnerability patterns

### What It Uniquely Detects

- **Cross-workflow privilege escalation** (workflow A → workflow B)
- **Artifact poisoning chains** (discovered in Microsoft Fluent UI)
- **Branch injection** (discovered in Storybook)
- **Multi-hop taint flows** that simpler tools cannot model

### Notable Discoveries

Found vulnerabilities in: FreeCodeCamp (most-starred GitHub repo),
Storybook, Microsoft Fluent UI (300M+ users).

---

## Detection Coverage Matrix

| Issue | Zizmor | Scorecard | Poutine | Actionlint | Harden-Runner | Snyk | Raven |
|-------|:------:|:---------:|:-------:|:----------:|:-------------:|:----:|:-----:|
| Script injection | `template-injection` | `Dangerous-Workflow` | `injection` | `untrusted-inputs` | Runtime | `CMD_EXEC` | Graph |
| `pull_request_target` | `dangerous-triggers` | `Dangerous-Workflow` | `untrusted_checkout_exec` | — | Runtime | `PWN_REQUEST` | Graph |
| `workflow_run` abuse | `dangerous-triggers` | `Dangerous-Workflow` | — | — | Runtime | `WORKFLOW_RUN` | Graph |
| Unpinned actions | `unpinned-uses` | `Pinned-Dependencies` | `unpinnable_action` | — | — | `UNPINNED_ACTION` | — |
| Excessive permissions | `excessive-permissions` | `Token-Permissions` | `default_permissions_on_risky_events` | `permissions` | — | — | — |
| Credential persistence | `artipacked` | — | — | `credentials` | Runtime | — | — |
| Impostor commits | `impostor-commit` | — | — | — | — | — | — |
| Cache poisoning | `cache-poisoning` | — | — | — | Runtime | — | — |
| GITHUB_ENV injection | `github-env` | — | — | — | Runtime | — | — |
| Insecure commands | `insecure-commands` | — | — | `deprecated-commands` | — | — | — |
| Self-hosted risk | `self-hosted-runner` | — | `pr_runs_on_self_hosted` | — | Runtime | — | — |
| Network exfiltration | — | — | — | — | **Primary** | — | — |
| Repo jacking | — | — | — | — | — | `REPOJACKABLE` | — |
| Confused deputy | `bot-conditions` | — | `confused_deputy_auto_merge` | — | — | — | — |
| Cross-workflow chains | — | — | — | — | — | — | **Primary** |
| Known CVEs | `known-vulnerable-actions` | `Vulnerabilities` | `known_vulnerability_in_build_component` | — | — | — | — |
| Secrets overprovisioning | `secrets-inherit`, `overprovisioned-secrets` | — | `job_all_secrets` | — | — | — | — |
| Always-true conditions | `unsound-condition` | — | `if_always_true` | `if-cond-constant` | — | — | — |
| Trusted publishing | `use-trusted-publishing` | — | — | — | — | — | — |
| Signed releases | — | `Signed-Releases` | — | — | — | — | — |
| Branch protection | — | `Branch-Protection` | — | — | — | — | — |

### Key Observations

1. **Template injection** is detected by every tool — it's the most common vulnerability
2. **Harden-Runner is the only runtime tool** — uniquely detects exfiltration and live attacks
3. **Zizmor has the broadest rule set** (30+) including unique rules: `impostor-commit`, `cache-poisoning`, `unsound-condition`
4. **Raven detects multi-step chains** via graph analysis that simpler tools miss
5. **Poutine uniquely models "Living Off The Pipeline"** — build tool execution as RCE vector
6. **Scorecard `Dangerous-Workflow` is Critical risk** — covers the two most exploited patterns
