# Security Hardening Reference

Official GitHub security guidance, permission management, secrets handling,
OIDC federation, and governance policies.

---

## Table of Contents

- [GITHUB_TOKEN Permissions](#github_token-permissions)
- [Secrets Management](#secrets-management)
- [OIDC Federation](#oidc-federation)
- [Push Protection and Secret Scanning](#push-protection-and-secret-scanning)
- [Governance Policies](#governance-policies)
- [Hardening Checklist by Role](#hardening-checklist-by-role)

---

## GITHUB_TOKEN Permissions

### Lifecycle

- Fresh token **created per job** before job starts
- Expires when job finishes or after **24 hours** (whichever is sooner)
- GitHub manages creation, rotation, and revocation automatically
- Accessible via `${{ secrets.GITHUB_TOKEN }}` or `${{ github.token }}`
- Actions can access `github.token` implicitly even without explicit pass-through

### Permission Scopes

| Scope | Typical Use |
|-------|-------------|
| `actions` | Manage workflow runs and artifacts |
| `attestations` | Attestation management |
| `checks` | Create/update check runs and suites |
| `contents` | Read/write repo contents, commits, branches, tags, releases |
| `deployments` | Create and update deployments |
| `discussions` | Read/write GitHub Discussions |
| `id-token` | Request OIDC JWT (write = can request) |
| `issues` | Read/write issues and comments |
| `packages` | Read/write GitHub Packages |
| `pages` | Read/write GitHub Pages configuration |
| `pull-requests` | Read/write PRs, reviews, comments |
| `repository-projects` | Read/write repository-level Projects |
| `security-events` | Read/write code scanning alerts and SARIF uploads |
| `statuses` | Read/write commit statuses |

Each scope accepts `read`, `write`, or `none`. `write` implies `read`.

### Default Permission Modes

| Mode | Behavior | Applies To |
|------|----------|------------|
| **Permissive** (legacy) | Most scopes read/write by default | Repos created before Feb 2, 2023 |
| **Restricted** (current default) | `contents: read`, `packages: read`, all others `none` | New orgs and repos |

Enterprise settings cascade → org settings → repo settings. More restrictive
parent settings cannot be overridden by children.

### Fork PR Behavior

| Trigger | GITHUB_TOKEN Permissions |
|---------|--------------------------|
| Push / PR from same repo | As configured per workflow/job |
| PR from fork | **Read-only for all scopes** |
| Fork PR + admin opt-in | Write tokens can be sent (not recommended) |

### Best Practices

```yaml
# Workflow-level baseline (all unspecified scopes → none)
permissions:
  contents: read

jobs:
  deploy:
    permissions:
      contents: read
      id-token: write    # OIDC
      deployments: write
```

- Always declare `permissions:` explicitly — do not rely on org defaults
- Grant write at job level, not workflow level
- Avoid `write-all`
- Use `actions-permissions/monitor` to discover actual permissions needed

---

## Secrets Management

### Secret Types

| Type | Scope | Use Case |
|------|-------|----------|
| Repository secret | Single repo, all workflows | Project-specific credentials |
| Organization secret | Multiple repos (admin-scoped allowlist) | Shared credentials across teams |
| Environment secret | Single named environment | Deployment credentials with approval gates |

### Encryption

Secrets use **Libsodium sealed boxes** — encrypted client-side before
transmission. GitHub Actions can only read a secret if explicitly referenced.

### Automatic Masking

GitHub automatically redacts all secret values in workflow logs. For dynamic
values, use `::add-mask::`:

```yaml
- run: |
    TOKEN=$(generate-token)
    echo "::add-mask::$TOKEN"
    echo "TOKEN=$TOKEN" >> "$GITHUB_OUTPUT"
```

Call `add-mask` **before** any step that could log the value.

### Fork Access

- Secrets are **not passed to runners** for fork PR workflows (except GITHUB_TOKEN which is read-only)
- The "Send secrets to workflows from pull requests" setting can override this — strongly discouraged
- Environment secrets require reviewer approval before accessible

### Secrets in Reusable Workflows

- Not automatically passed — must be declared as `secrets:` inputs
- `secrets: inherit` passes all caller secrets (use judiciously)
- For dynamic secrets between workflows: double-base64 encode, pass as input, decode + mask in called workflow

### Token Comparison

| Token | Lifetime | Scope | Recommended For |
|-------|----------|-------|-----------------|
| `GITHUB_TOKEN` | Job duration (max 24h) | Repo-scoped, auto-provisioned | All GitHub API ops within workflow |
| PAT (classic) | User-defined (indefinite) | User account-wide | Legacy; avoid |
| PAT (fine-grained) | User-defined, expiring | Resource + permission scoped | Where GitHub App unavailable |
| GitHub App token | 1 hour | Installation-scoped, granular | Cross-repo/org automation |
| OIDC token | Minutes | Cloud-provider scoped | Cloud deployments |

---

## OIDC Federation

### How It Works

1. Workflow requests JWT from GitHub's OIDC provider (requires `id-token: write`)
2. GitHub issues signed JWT with workflow metadata claims
3. Job presents JWT to cloud provider STS
4. Cloud validates JWT signature against GitHub's JWKS endpoint
5. If trust policy matches claims, cloud issues short-lived credential
6. No long-lived secrets stored in GitHub

### JWT Claims (Complete)

| Claim | Description | Example |
|-------|-------------|---------|
| `iss` | Issuer | `https://token.actions.githubusercontent.com` |
| `aud` | Audience | `sts.amazonaws.com` (or custom) |
| `sub` | Subject (customizable) | `repo:org/repo:environment:prod` |
| `repository` | Full repo name | `octo-org/octo-repo` |
| `repository_id` | Numeric repo ID | `123456` |
| `repository_owner` | Org or user | `octo-org` |
| `repository_owner_id` | Numeric owner ID | `654321` |
| `repository_visibility` | `public`, `private`, `internal` | `private` |
| `actor` | Triggering user | `octocat` |
| `actor_id` | Numeric actor ID | `111111` |
| `workflow` | Workflow name | `CI` |
| `run_id` | Workflow run ID | `1234567890` |
| `run_number` | Run counter | `42` |
| `run_attempt` | Attempt number | `1` |
| `event_name` | Triggering event | `push` |
| `ref` | Git ref | `refs/heads/main` |
| `ref_type` | `branch` or `tag` | `branch` |
| `head_ref` | PR head branch | `feature/my-pr` |
| `base_ref` | PR base branch | `main` |
| `sha` | Commit SHA | `abc123...` |
| `environment` | Deployment environment | `prod` |
| `job_workflow_ref` | Reusable workflow path | `org/repo/.github/workflows/deploy.yml@abc123` |

### Default Subject Claim Formats

```
repo:<owner>/<repo>:environment:<name>
repo:<owner>/<repo>:ref:refs/heads/<branch>
repo:<owner>/<repo>:ref:refs/tags/<tag>
repo:<owner>/<repo>:pull_request
```

Customizable via REST API: `PATCH /repos/{owner}/{repo}/actions/oidc/customization/sub`

### Cloud Provider Configuration

**AWS:**
```yaml
- uses: aws-actions/configure-aws-credentials@<SHA>
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActionsRole
    aws-region: us-east-1
```

IAM trust policy:
```json
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:org/repo:environment:prod"
    },
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

**Azure:** `azure/login` action with `client-id`, `tenant-id`, `subscription-id`. Federated credential on Azure AD app registration.

**GCP:** `google-github-actions/auth` with Workload Identity Federation.

### Trust Policy Security

- Overly broad `sub` claims are dangerous — `repo:org/repo:*` allows any branch including fork PRs
- Always include `environment` in `sub` for production cloud roles
- Use `job_workflow_ref` to restrict to specific reusable workflows
- Validate both `sub` and `aud` for defense in depth

---

## Push Protection and Secret Scanning

### How Push Protection Works

- Scans commits **at push time** — blocks push if recognized secret pattern found
- ~150 service provider integrations (partner patterns)
- Low false-positive rate for push protection patterns
- Available free on public repos; private repos need GitHub Secret Protection license

### Custom Patterns

Organizations can define regex patterns for org-specific secrets not covered by
default patterns. Custom patterns can be enforced by push protection at
enterprise, org, or repository level.

### Bypass and Audit

- Bypass events logged in audit log
- Email alert to org owners, security managers, repo admins
- **Delegated bypass:** approval workflow — designated reviewer must approve
- All bypass reasons captured for compliance

---

## Governance Policies

### Allowed Actions Policy (Enterprise > Org > Repo)

| Mode | Description |
|------|-------------|
| Allow all | No restriction |
| Same enterprise/org only | Only actions from repos within enterprise/org |
| Verified creators + specific list | GitHub-owned + verified badge + explicit allowlist |
| Specific allowlist only | Glob patterns: `actions/cache@*`, `aws-actions/*@v4` |

Enterprise settings override org, which override repo. Children cannot be
more permissive than parents.

### Runner Group Policies

- Scope runner groups to specific repositories (not all repos)
- Restrict groups to specific workflows within allowed repositories
- Repository-level self-hosted runners can be disabled at org level

### Organization Secrets and Variables

- Org secrets shareable with access policies: all repos, private only, or selected list
- Secrets never exposed to fork PRs by default

### Required Workflows (Enterprise Cloud)

Organizations can configure required workflows that run on all repos in the org
regardless of repo-level workflow configuration. Cannot be bypassed by repo owners.

### Additional Controls

- IP allow lists on self-hosted runners for outbound access restriction
- Audit log streaming to SIEM (workflow changes, secret access, permission changes)
- Rulesets for scalable branch/tag protection across repos via custom properties
- Alert on `.github/workflows/` modifications from non-CODEOWNERS

---

## Hardening Checklist by Role

### Repository Maintainer

- [ ] Set `permissions:` explicitly in all workflows
- [ ] Pin all third-party actions to SHA
- [ ] Configure Dependabot for `github-actions` ecosystem
- [ ] Enable push protection and secret scanning
- [ ] Use environment protection for production deployments
- [ ] Audit for `pull_request_target` + checkout patterns
- [ ] Set `persist-credentials: false` on `actions/checkout`

### Organization Admin

- [ ] Set GITHUB_TOKEN default to restricted (read-only)
- [ ] Configure allowed actions policy (verified creators + allowlist)
- [ ] Restrict self-hosted runners to private repos only
- [ ] Enable required reviewer approval for fork PR workflows
- [ ] Stream audit logs to SIEM
- [ ] Enforce MFA for all org members
- [ ] Scope org secrets to minimum repos needed

### Enterprise Admin

- [ ] Enforce restricted GITHUB_TOKEN default at enterprise level
- [ ] Set allowed actions policy at enterprise level
- [ ] Configure required workflows for critical compliance checks
- [ ] Enable SSO (SAML) for centralized identity
- [ ] Restrict runner groups by org and repository
- [ ] Implement delegated bypass for push protection
