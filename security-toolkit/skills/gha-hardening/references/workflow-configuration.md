# Workflow Configuration Reference

Comprehensive reference for GitHub Actions workflow syntax, triggers, job
configuration, and advanced features.

---

## Table of Contents

- [Workflow Structure](#workflow-structure)
- [Trigger Types](#trigger-types)
- [Job Configuration](#job-configuration)
- [Step Configuration](#step-configuration)
- [Matrix Strategies](#matrix-strategies)
- [Reusable Workflows](#reusable-workflows)
- [Composite Actions](#composite-actions)
- [Environments and Deployments](#environments-and-deployments)
- [Dependency Caching](#dependency-caching)
- [Workflow Artifacts](#workflow-artifacts)
- [Concurrency Control](#concurrency-control)
- [Service Containers](#service-containers)

---

## Workflow Structure

Workflow files live in `.github/workflows/` (`.yml` or `.yaml` extension).

### Top-Level Keys

| Key | Purpose |
|-----|---------|
| `name` | Display name in Actions tab |
| `run-name` | Per-run name; supports `${{ inputs.* }}` and `${{ github.actor }}` |
| `on` | Event triggers |
| `permissions` | `GITHUB_TOKEN` permission scopes for all jobs |
| `env` | Variables available to all steps in all jobs |
| `defaults` | Default `run` settings (`shell`, `working-directory`) |
| `concurrency` | Prevent simultaneous runs; optionally cancel in-progress |
| `jobs` | Map of job definitions |

```yaml
run-name: Deploy to ${{ inputs.deploy_target }} by @${{ github.actor }}

env:
  SERVER: production

defaults:
  run:
    shell: bash
    working-directory: ./scripts

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

---

## Trigger Types

### Webhook Events (Selected)

| Event | Key Activity Types |
|-------|--------------------|
| `push` | `branches`, `tags`, `paths` filters |
| `pull_request` | `opened`, `closed`, `synchronize`, `labeled` |
| `pull_request_target` | Same as PR but runs in base branch context (security-sensitive) |
| `issues` | `opened`, `edited`, `closed`, `labeled` |
| `issue_comment` | `created`, `edited`, `deleted` |
| `release` | `published`, `created`, `edited`, `prereleased` |
| `workflow_run` | `completed`, `requested`, `in_progress` (security-sensitive) |
| `repository_dispatch` | Custom event from REST API |
| `merge_group` | `checks_requested` |

### Manual and Scheduled

- `workflow_dispatch` — manual trigger with typed `inputs` (boolean, choice, number, environment, string)
- `schedule` — cron syntax: `- cron: '0 5 * * 1'`
- `workflow_call` — reusable workflow trigger

### Branch/Path Filtering

Pattern characters: `*` (not `/`), `**` (any), `?`, `+`, `[]`, `!` (negate).

```yaml
on:
  push:
    branches: [main, 'releases/**']
    paths: ['src/**', '!src/**/*.test.ts']
  pull_request:
    branches: [main]
    types: [opened, synchronize]
```

Prefer explicit `types:` for webhook events rather than triggering on all activity.

---

## Job Configuration

### Job-Level Keys

| Key | Purpose |
|-----|---------|
| `name` | Display name |
| `permissions` | Override workflow-level GITHUB_TOKEN permissions |
| `needs` | Declare job dependencies (sequential ordering) |
| `if` | Conditional execution expression |
| `runs-on` | Runner label(s), group, or array of labels |
| `environment` | Named deployment environment |
| `concurrency` | Job-level concurrency group |
| `outputs` | Map of outputs exposed to downstream jobs |
| `timeout-minutes` | Max job runtime (default: 360, max: 360) |
| `strategy` | Matrix strategy configuration |
| `continue-on-error` | Allow workflow to pass even if this job fails |
| `container` | Run all steps in a Docker container |
| `services` | Sidecar containers (databases, caches) |
| `uses` | Call a reusable workflow |

### Job Outputs

```yaml
jobs:
  job1:
    outputs:
      result: ${{ steps.step1.outputs.value }}
    steps:
      - id: step1
        run: echo "value=hello" >> $GITHUB_OUTPUT

  job2:
    needs: job1
    steps:
      - run: echo ${{ needs.job1.outputs.result }}
```

---

## Step Configuration

| Key | Purpose |
|-----|---------|
| `id` | Unique identifier for referencing in contexts |
| `if` | Conditional — supports `failure()`, `success()`, `always()`, `cancelled()` |
| `uses` | Action reference: `owner/repo@ref`, `./local-path`, `docker://image:tag` |
| `run` | Shell command(s) — max 21,000 characters |
| `shell` | `bash`, `sh`, `cmd`, `pwsh`, `powershell`, `python`, or custom (`perl {0}`) |
| `with` | Input parameters for an action |
| `env` | Step-scoped environment variables |
| `timeout-minutes` | Max step runtime (max: 360) |

### Shell Behavior

- `bash`: fail-fast via `set -eo pipefail`
- `sh`: fail-fast via `set -e`
- `pwsh`/`powershell`: `$ErrorActionPreference = 'stop'` + LASTEXITCODE check
- Custom: `shell: perl {0}` — `{0}` replaced with temp script path

---

## Matrix Strategies

```yaml
strategy:
  fail-fast: false       # don't cancel all on first failure
  max-parallel: 3        # limit concurrent jobs
  matrix:
    os: [ubuntu-22.04, ubuntu-24.04]
    version: [10, 12, 14]
    include:             # add extra combinations
      - version: 15
        os: ubuntu-latest
        experimental: true
    exclude:             # remove specific combinations
      - os: ubuntu-22.04
        version: 10
runs-on: ${{ matrix.os }}
continue-on-error: ${{ matrix.experimental || false }}
```

- Max 256 jobs per workflow run
- `include` is processed after `exclude`; can re-add excluded combos
- Matrix variables available via `matrix` context

---

## Reusable Workflows

### Defining

Must be in `.github/workflows/` with `on: workflow_call:`.

```yaml
on:
  workflow_call:
    inputs:
      config-path:
        required: true
        type: string        # boolean | number | string
    secrets:
      token:
        required: true
    outputs:
      result:
        value: ${{ jobs.build.outputs.result }}
```

### Calling

```yaml
jobs:
  call-workflow:
    uses: octo-org/repo/.github/workflows/deploy.yml@main
    permissions:
      contents: read
    with:
      config-path: .github/config.yml
    secrets:
      token: ${{ secrets.GITHUB_TOKEN }}

  # Or pass all secrets:
  call-with-inherit:
    uses: ./.github/workflows/internal.yml
    secrets: inherit
```

### Rules and Limits

- Called via `jobs.<id>.uses` (job level, not step level)
- Input types: `boolean`, `number`, `string`
- Nesting: max 10 levels (GitHub.com), 4 levels (GHES)
- Permissions can only be maintained or reduced in the chain — never elevated
- `secrets: inherit` passes all caller secrets (security: use judiciously)

---

## Composite Actions

Defined in `action.yml` with `runs.using: "composite"`.

```yaml
name: "My Composite Action"
description: "Does X, Y, Z"

inputs:
  some-input:
    required: true

outputs:
  result:
    value: ${{ steps.step-id.outputs.result }}

runs:
  using: "composite"
  steps:
    - id: step-id
      shell: bash                    # REQUIRED per step
      run: echo "result=hello" >> $GITHUB_OUTPUT

    - uses: actions/checkout@v4     # can use other actions
```

Key rules:
- Every `run:` step **must** declare `shell:` explicitly — no inherited defaults
- Secrets must be passed as inputs (not directly accessible)
- `defaults:` is not supported within composite action `runs`

---

## Environments and Deployments

### Protection Rules

```yaml
jobs:
  deploy:
    environment:
      name: production
      url: https://example.com
    runs-on: ubuntu-latest
```

**Required reviewers:** Up to 6 users/teams per environment. Only 1 needs to approve.
Optional: prevent self-reviews (initiator cannot approve own deployment).

**Wait timer:** 1–43,200 minutes (30 days max). Does not count toward billable time.

**Deployment branches:** No restriction | Protected branches only | Selected patterns.
Pattern matching uses Ruby `File.fnmatch` syntax. Wildcards don't match `/`.

**Custom protection rules:** Powered by GitHub Apps. Up to 30 days for webhook response.
Partner integrations: Datadog, Honeycomb, New Relic, Sentry, ServiceNow.

### Environment Secrets

- Accessible only to jobs referencing that environment
- Unavailable until reviewer approves (if required)
- On self-hosted runners: treat at same security level as repo/org secrets (no isolation)

---

## Dependency Caching

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-node-
```

### Cache Resolution Order

1. Exact match on `key` in current branch
2. Prefix match via `restore-keys` in current branch
3. Same sequence against the default branch

### Scope and Isolation

- Caches are per-repository, per-key, per-branch
- PRs can restore from: current branch, default branch, base branch
- PR merge ref caches (`refs/pull/.../merge`) only restorable by re-runs of same PR
- **Security note:** Forks can read base branch caches (intentional by design)

### Limits

- **10 GB** total per repository
- Entries expire after **7 days** of no access (LRU eviction)
- No per-entry size limit; repo quota is the constraint

---

## Workflow Artifacts

```yaml
# Upload
- uses: actions/upload-artifact@v4
  with:
    name: build-output
    path: dist/
    retention-days: 7

# Download (in dependent job)
- uses: actions/download-artifact@v4
  with:
    name: build-output
    path: ./dist
```

### v4 Behavior

- Artifacts are **immutable** once uploaded (zip archive)
- Cannot upload to same name twice — use distinct names per job
- Merge multiple artifacts: `actions/upload-artifact/merge@v4`

### Limits

- Per artifact: **5 GB**
- Per job: **500 artifacts**
- Retention: 1–90 days (default 90, configurable at org level)

### Security Note

Treat all inter-workflow artifacts as untrusted. Never execute content from
artifacts downloaded in `workflow_run` workflows — see attack-patterns.md.

---

## Concurrency Control

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Use `cancel-in-progress: true` on PR workflows to avoid wasted runner time.
Group by workflow + ref to isolate PR runs from each other.

---

## Service Containers

```yaml
jobs:
  test:
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
        ports:
          - 5432/tcp
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
    steps:
      - run: echo "DB at 127.0.0.1:${{ job.services.postgres.ports['5432'] }}"
```

Services run as sidecar containers alongside the job. Use health checks to
ensure readiness before tests run.
