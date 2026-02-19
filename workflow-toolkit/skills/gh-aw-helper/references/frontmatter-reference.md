# GitHub Agentic Workflows: Complete Frontmatter Reference

Comprehensive specification for all frontmatter fields in `.github/agentic/*.yml` workflow files.

## Table of Contents

- [Core Fields](#core-fields)
  - [on](#on)
  - [permissions](#permissions)
  - [engine](#engine)
  - [description](#description)
  - [strict](#strict)
- [Trigger Modifiers](#trigger-modifiers)
  - [stop-after](#stop-after)
  - [skip-if-match / skip-if-no-match](#skip-if-match--skip-if-no-match)
  - [manual-approval](#manual-approval)
  - [reaction](#reaction)
  - [roles](#roles)
  - [bots](#bots)
  - [skip-roles / skip-bots](#skip-roles--skip-bots)
- [Tools Configuration](#tools-configuration)
  - [tools](#tools)
  - [mcp-servers](#mcp-servers)
- [Safe I/O](#safe-io)
  - [safe-outputs](#safe-outputs)
  - [safe-inputs](#safe-inputs)
- [Network & Security](#network--security)
  - [network](#network)
  - [sandbox](#sandbox)
  - [threat-detection](#threat-detection)
  - [lockdown](#lockdown)
  - [rate-limit](#rate-limit)
- [Execution Control](#execution-control)
  - [timeout-minutes](#timeout-minutes)
  - [concurrency](#concurrency)
  - [if](#if)
  - [runs-on](#runs-on)
  - [run-name](#run-name)
  - [env](#env)
  - [cache](#cache)
  - [container / services](#container--services)
  - [runtimes](#runtimes)
- [Structure & Composition](#structure--composition)
  - [imports](#imports)
  - [steps](#steps)
  - [post-steps](#post-steps)
  - [jobs](#jobs)
  - [secrets](#secrets)
  - [labels](#labels)
  - [metadata](#metadata)
  - [tracker-id](#tracker-id)
  - [source](#source)
  - [features](#features)
  - [plugins](#plugins)
  - [environment](#environment)
  - [secret-masking](#secret-masking)

---

## Core Fields

### on

**Type:** Object or String (shorthand)
**Default:** Required field
**Description:** Defines when the workflow triggers. Supports GitHub events, slash commands, schedules, and custom shorthands.

#### Event Types

| Event | Description | Label Filtering | Fork Support |
|-------|-------------|-----------------|--------------|
| `issues` | Issue opened, labeled, closed, etc. | Yes | Yes |
| `pull_request` | PR opened, synchronized, labeled, etc. | Yes | Yes |
| `push` | Code pushed to branches/tags | No | Yes |
| `schedule` | Cron-based triggers | No | N/A |
| `workflow_dispatch` | Manual trigger | No | N/A |
| `slash_command` | Custom `/command` in comments | No | Yes |
| `discussion` | Discussions created, labeled, etc. | Yes | No |
| `issue_comment` | Comments on issues/PRs | No | Yes |
| `pull_request_review` | PR review submitted | No | Yes |
| `pull_request_review_comment` | PR review comment | No | Yes |
| `repository_dispatch` | External webhook | No | N/A |
| `workflow_call` | Reusable workflow call | No | N/A |

#### Shorthand Formats

```yaml
# Cron schedule
on: daily
on: hourly
on: weekly
on: "0 9 * * 1-5"  # Custom cron

# Slash command
on: /my-bot

# Issue trigger with label filter
on: issue labeled bug

# Simple event
on: push
```

#### Extended Format

```yaml
on:
  issues:
    types: [opened, labeled]
    labels:
      include: [bug, enhancement]
      exclude: [wontfix]
    lock-for-agent: true  # Prevents concurrent access

  pull_request:
    types: [opened, synchronize]
    labels:
      include: [needs-review]
    forks: allowed  # allow, disallow, only

  schedule:
    - cron: "0 9 * * *"

  slash_command:
    command: /analyze
    aliases: [/check, /scan]

  workflow_dispatch:
    inputs:
      environment:
        description: "Target environment"
        required: true
        default: "staging"
```

---

### permissions

**Type:** Object or String
**Default:** `read-all` (safe default)
**Description:** Defines GitHub token permissions for the workflow. Follows least-privilege principle.

#### Permission Scopes

| Scope | Read Access | Write Access |
|-------|-------------|--------------|
| `contents` | Read repo files | Push commits, create tags |
| `issues` | Read issues | Create, edit, close issues |
| `pull-requests` | Read PRs | Create, edit, merge PRs |
| `discussions` | Read discussions | Create, edit discussions |
| `actions` | Read workflow runs | Cancel/rerun workflows |
| `checks` | Read check runs | Create check runs |
| `statuses` | Read commit statuses | Create commit statuses |
| `deployments` | Read deployments | Create deployments |
| `packages` | Read packages | Publish packages |
| `pages` | Read Pages | Deploy Pages |
| `security-events` | Read security alerts | Create security alerts |
| `id-token` | N/A | Request OIDC token |

#### Shorthand Options

```yaml
# All read permissions
permissions: read-all

# All write permissions (use cautiously)
permissions: write-all

# No permissions
permissions: {}
```

#### Granular Permissions

```yaml
permissions:
  contents: read
  issues: write
  pull-requests: write
  discussions: read
  checks: write
  id-token: write  # For OIDC auth
```

---

### engine

**Type:** String or Object
**Default:** `copilot`
**Description:** Specifies the AI engine to use for executing the workflow.

#### Simple Format

```yaml
engine: copilot   # GitHub Copilot (default)
engine: claude    # Anthropic Claude
engine: codex     # OpenAI Codex
```

#### Extended Format

```yaml
engine:
  name: claude
  model: claude-opus-4-6  # Specific model version
  command: /path/to/custom-engine  # Custom engine binary
  args: ["--verbose", "--mode=strict"]
  agent: custom-agent-name  # For multi-agent workflows
  env:
    ENGINE_API_KEY: ${{ secrets.CLAUDE_KEY }}
  concurrency:
    max-parallel: 3
    cancel-in-progress: true
```

---

### description

**Type:** String
**Default:** Empty
**Description:** Human-readable explanation of what the workflow does. Shown in UI and logs.

```yaml
description: |
  Analyzes security vulnerabilities in pull requests and creates
  a detailed report as a comment. Blocks merge if critical issues found.
```

---

### strict

**Type:** Boolean
**Default:** `false`
**Description:** Enforces strict validation of workflow syntax, tool usage, and safety constraints. Fails workflow on any policy violation.

```yaml
strict: true

# When enabled, enforces:
# - All tools must be explicitly enabled in `tools:`
# - All outputs must be declared in `safe-outputs:`
# - Network requests require explicit allowlist in `network:`
# - No dynamic code execution outside sandboxes
```

---

## Trigger Modifiers

### stop-after

**Type:** String
**Default:** Never expires
**Description:** Auto-disables the workflow after a deadline. Useful for temporary bots or trial periods.

#### Formats

| Format | Example | Meaning |
|--------|---------|---------|
| Relative | `+25h` | 25 hours from now |
| Relative | `+7d` | 7 days from now |
| Absolute | `2025-06-01` | June 1, 2025 at 00:00 UTC |
| Absolute | `2025-12-31T23:59:59Z` | ISO 8601 timestamp |

```yaml
stop-after: +30d  # Disable after 30 days
stop-after: 2026-03-01  # Disable on March 1, 2026
```

---

### skip-if-match / skip-if-no-match

**Type:** String (GitHub search query)
**Default:** No skipping
**Description:** Conditionally skip workflow execution based on GitHub search results.

```yaml
# Skip if issue already has a linked PR
skip-if-match: "linked:pr"

# Skip if no security label exists
skip-if-no-match: "label:security"

# Complex search query
skip-if-match: "is:open label:duplicate OR label:wontfix"
```

---

### manual-approval

**Type:** String (environment name)
**Default:** No approval required
**Description:** Requires manual approval via GitHub Environments before workflow executes.

```yaml
manual-approval: production  # Requires approval from "production" environment

# Configure environment protection rules in repo settings:
# Settings → Environments → production → Required reviewers
```

---

### reaction

**Type:** String (emoji)
**Default:** No reaction required
**Description:** Requires a specific emoji reaction on the triggering item to activate workflow.

```yaml
reaction: "👍"  # Workflow runs when someone reacts with thumbs-up
reaction: "rocket"  # GitHub emoji shortcode also supported
```

---

### roles

**Type:** Array of Strings
**Default:** `[all]`
**Description:** Restricts workflow to users with specific repository roles.

```yaml
roles: [admin, maintainer]  # Only admins and maintainers can trigger
roles: [write]              # Contributors with write access
roles: [all]                # Anyone (default)

# Available roles: admin, maintain, write, read, all
```

---

### bots

**Type:** String
**Default:** `allow`
**Description:** Controls whether bots can trigger the workflow.

```yaml
bots: allow     # Bots can trigger (default)
bots: disallow  # No bots allowed
bots: only      # Only bots can trigger
```

---

### skip-roles / skip-bots

**Type:** Array of Strings or Boolean
**Default:** Empty (no exemptions)
**Description:** Exempts specific roles or bots from triggering the workflow.

```yaml
skip-roles: [admin]  # Admins won't trigger this workflow
skip-bots: true      # All bots are exempted
skip-bots: [dependabot, renovate]  # Specific bots exempted
```

---

## Tools Configuration

### tools

**Type:** Object
**Default:** Safe defaults per tool
**Description:** Enables and configures tools available to the AI agent.

#### GitHub Tool

```yaml
tools:
  github:
    toolsets: [issues, pull-requests, discussions]  # Scope access
    mode: standard  # standard, read-only, lockdown
    read-only: false
    lockdown: false  # Disables all write operations
    github-token: ${{ secrets.CUSTOM_TOKEN }}
    app:  # GitHub App auth
      id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
```

#### Edit Tool

```yaml
tools:
  edit: true  # Enable file editing

  edit:
    paths: ["src/**/*.py", "docs/*.md"]  # Restrict to paths
    exclude: ["src/generated/**"]
    max-file-size: 1MB
```

#### Bash Tool

```yaml
tools:
  bash: true  # Allow all commands

  bash:
    commands: [git, npm, pytest]  # Allowlist specific commands
    wildcards: ["npm run *", "pytest tests/*"]
    timeout: 300  # Seconds
```

#### Web Tools

```yaml
tools:
  web-fetch: true
  web-search:
    provider: google  # google, bing, duckduckgo
    max-results: 10
```

#### Playwright Browser

```yaml
tools:
  playwright:
    allowed_domains: ["docs.example.com", "api.example.com"]
    version: "1.40.0"
    headless: true
```

#### Cache/Memory

```yaml
tools:
  cache-memory: true  # Enable workflow memory cache
  repo-memory: true   # Enable repo-level memory
```

#### Agentic Workflows

```yaml
tools:
  agentic-workflows:
    allowed: [other-workflow.yml]  # Can invoke other workflows
```

#### Serena (Code Analysis)

```yaml
tools:
  serena:
    enabled: true
    max-file-size: 5MB
```

---

### mcp-servers

**Type:** Object
**Default:** Empty (no MCP servers)
**Description:** Configures Model Context Protocol (MCP) servers for extended tool access.

```yaml
mcp-servers:
  # Command-based server
  sqlite:
    command: "uvx"
    args: ["mcp-server-sqlite", "--db-path", "/tmp/data.db"]
    env:
      DATABASE_URL: ${{ secrets.DB_URL }}

  # Container-based server
  postgres:
    container: "ghcr.io/org/mcp-postgres:latest"
    env:
      POSTGRES_PASSWORD: ${{ secrets.PG_PASS }}

  # Remote URL
  api-server:
    url: "https://mcp.example.com"
    headers:
      Authorization: "Bearer ${{ secrets.API_KEY }}"

  # Registry reference
  github:
    registry: "@modelcontextprotocol/server-github"
    version: "0.2.0"
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  # Network and permissions
  external-api:
    url: "https://api.external.com/mcp"
    allowed: true  # Explicitly allow network access
    network: [api.external.com, cdn.external.com]
```

---

## Safe I/O

### safe-outputs

**Type:** Object
**Default:** All outputs disabled
**Description:** Declares which outputs the agent can create. Each output type has configurable limits and formatting options.

#### Output Types

| Type | Default Max | Description |
|------|-------------|-------------|
| `create-issue` | 1 | Create new issues |
| `add-comment` | 1 | Add comments to issues/PRs |
| `create-pull-request` | 1 | Create new pull requests |
| `update-issue` | 1 | Edit existing issues |
| `close-issue` | 1 | Close issues |
| `add-label` | 5 | Add labels |
| `remove-label` | 5 | Remove labels |
| `create-discussion` | 1 | Create discussions |
| `add-reaction` | 3 | Add emoji reactions |
| `request-review` | 3 | Request PR reviews |
| `create-check-run` | 1 | Create check runs |
| `update-check-run` | 1 | Update check runs |
| `create-deployment` | 1 | Create deployments |
| `write-file` | 10 | Write files to repo |

#### Basic Configuration

```yaml
safe-outputs:
  create-issue:
    max: 2  # Allow up to 2 issues per run

  add-comment:
    max: 3
    footer: |
      ---
      *Generated by AI workflow*
```

#### Advanced Configuration

```yaml
safe-outputs:
  create-issue:
    max: 1
    title-prefix: "[Bot] "
    labels: [automated, needs-triage]
    expires: +7d  # Auto-close after 7 days
    close-older-issues: true  # Close previous bot-created issues

  create-pull-request:
    max: 1
    title-prefix: "fix: "
    labels: [automated]
    target-repo: owner/other-repo  # Cross-repo PRs
    staged: true  # Use staged files only
    github-token: ${{ secrets.PR_TOKEN }}
    app:
      id: ${{ secrets.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}

  add-comment:
    max: 5
    footer: |
      ---
      <details>
      <summary>Debug Info</summary>
      Workflow: ${{ github.workflow }}
      Run: ${{ github.run_id }}
      </details>
```

---

### safe-inputs

**Type:** Object
**Default:** Empty (no custom inputs)
**Description:** Defines custom tools available to the agent via declarative scripts.

```yaml
safe-inputs:
  analyze-deps:
    description: "Analyzes Python dependencies for security issues"
    inputs:
      file:
        description: "Path to requirements.txt"
        required: true
      severity:
        description: "Minimum severity level"
        default: "medium"
    script: |
      pip-audit -r "${{ inputs.file }}" --severity "${{ inputs.severity }}"
    timeout: 120
    env:
      PIP_INDEX_URL: ${{ secrets.PIP_MIRROR }}

  run-linter:
    description: "Runs ESLint on specified files"
    inputs:
      paths:
        description: "Comma-separated file paths"
        required: true
    run: npx eslint ${{ inputs.paths }} --format json

  check-types:
    description: "Runs mypy type checker"
    py: |
      import subprocess
      import sys
      result = subprocess.run(
          ["mypy", sys.argv[1]],
          capture_output=True,
          text=True
      )
      print(result.stdout)
      sys.exit(result.returncode)

  build-go:
    description: "Compiles Go package"
    go: |
      package main
      import "os/exec"
      func main() {
          cmd := exec.Command("go", "build", "./...")
          cmd.Run()
      }
```

---

## Network & Security

### network

**Type:** Object
**Default:** Restrictive defaults
**Description:** Controls network access for the agent and tools.

```yaml
network:
  allowed:
    # Default categories
    - github  # github.com, api.github.com, raw.githubusercontent.com
    - npm     # npmjs.com, registry.npmjs.org
    - pypi    # pypi.org, files.pythonhosted.org
    - docker  # docker.io, ghcr.io, gcr.io

    # Ecosystem identifiers
    - cargo   # crates.io
    - maven   # maven.org, repo.maven.apache.org
    - nuget   # nuget.org

    # Custom domains
    - "api.example.com"
    - "*.cdn.example.com"  # Wildcard subdomain

    # IP ranges (CIDR notation)
    - "10.0.0.0/8"

  blocked:
    - "internal.example.com"
    - "192.168.0.0/16"

  firewall:
    mode: strict  # strict, permissive
    log-blocked: true
```

---

### sandbox

**Type:** String or Object
**Default:** `awf` (Agentic Workflows sandbox)
**Description:** Specifies sandbox environment for code execution.

```yaml
# Built-in sandboxes
sandbox: awf   # Default gh-aw sandbox
sandbox: srt   # Secure Runtime (stricter)
sandbox: false # No sandboxing (use cautiously)

# MCP Gateway configuration
sandbox:
  type: mcp-gateway
  endpoint: "https://gateway.example.com"
  auth:
    token: ${{ secrets.GATEWAY_TOKEN }}
```

---

### threat-detection

**Type:** Object
**Default:** Disabled
**Description:** Enables AI-based threat detection for agent actions.

```yaml
threat-detection:
  enabled: true
  prompt: |
    Analyze the following action for:
    - Data exfiltration attempts
    - Privilege escalation
    - Malicious code injection
  engine: claude  # Use specific engine for analysis
  steps: [pre-execution, pre-output]  # When to check
```

---

### lockdown

**Type:** Boolean
**Default:** `false`
**Description:** Disables all write operations when enabled. Read-only mode for debugging or auditing.

```yaml
lockdown: true

# When enabled:
# - No file writes
# - No issue/PR creation
# - No comments
# - No label changes
# - Network requests still allowed (read-only)
```

---

### rate-limit

**Type:** Object
**Default:** No rate limiting
**Description:** Enforces rate limits on workflow executions.

```yaml
rate-limit:
  max: 10         # Max 10 runs
  window: 3600    # Per hour (seconds)
  events: [issues, pull_request]  # Apply to specific events
  ignored-roles: [admin]  # Admins exempt from limits
```

---

## Execution Control

### timeout-minutes

**Type:** Integer
**Default:** `20`
**Description:** Maximum runtime for the workflow in minutes. Workflow is cancelled if exceeded.

```yaml
timeout-minutes: 60  # 1 hour
timeout-minutes: 5   # 5 minutes for quick checks
```

---

### concurrency

**Type:** Object
**Default:** Per-engine defaults
**Description:** Controls concurrent execution of workflows.

```yaml
concurrency:
  group: issue-${{ github.event.issue.number }}
  cancel-in-progress: true  # Cancel older runs in same group

# Per-engine defaults:
# - copilot: cancel-in-progress: true
# - claude: cancel-in-progress: false (preserves context)
# - codex: cancel-in-progress: true
```

---

### if

**Type:** String (expression)
**Default:** Always runs
**Description:** Conditional execution using GitHub Actions expression syntax.

```yaml
if: github.event.issue.state == 'open'
if: contains(github.event.issue.labels.*.name, 'bug')
if: github.actor != 'dependabot[bot]'
if: |
  github.event_name == 'pull_request' &&
  github.event.pull_request.draft == false
```

---

### runs-on

**Type:** String or Array
**Default:** `ubuntu-latest`
**Description:** Specifies runner environment.

```yaml
runs-on: ubuntu-latest
runs-on: macos-latest
runs-on: windows-latest
runs-on: [self-hosted, linux, x64]
```

---

### run-name

**Type:** String (template)
**Default:** Workflow filename
**Description:** Custom name for workflow run shown in UI.

```yaml
run-name: "Analyze PR #${{ github.event.pull_request.number }}"
run-name: "Security scan: ${{ github.event.issue.title }}"
```

---

### env

**Type:** Object
**Default:** Empty
**Description:** Environment variables with 13 scopes and precedence rules.

#### Scope Precedence (highest to lowest)

1. `safe-inputs.*.env` — Per-input tool environment
2. `engine.env` — Engine-specific environment
3. `steps.*.env` — Per-step environment
4. `jobs.*.steps.*.env` — Job step environment
5. `jobs.*.env` — Job-level environment
6. `container.env` — Container environment
7. `services.*.env` — Service environment
8. `mcp-servers.*.env` — MCP server environment
9. `runtimes.*.env` — Runtime environment
10. `imports.*.env` — Imported environment
11. Top-level `env:` — Workflow-level environment
12. Repository secrets
13. GitHub default environment

```yaml
env:
  NODE_ENV: production
  API_KEY: ${{ secrets.API_KEY }}
  DEBUG: "false"

engine:
  env:
    CLAUDE_CONTEXT_SIZE: "200k"

steps:
  - name: Build
    env:
      BUILD_TYPE: release
```

---

### cache

**Type:** Object
**Default:** No caching
**Description:** Caches dependencies or build artifacts.

```yaml
cache:
  key: npm-${{ hashFiles('package-lock.json') }}
  path:
    - node_modules
    - .npm
  restore-keys: |
    npm-
    npm-${{ runner.os }}-
```

---

### container / services

**Type:** Object
**Default:** No containers
**Description:** Runs workflow in a container or with service containers.

```yaml
container:
  image: node:18
  env:
    NODE_ENV: test
  volumes:
    - /tmp:/tmp
  options: --cpus 2

services:
  postgres:
    image: postgres:15
    env:
      POSTGRES_PASSWORD: testpass
    ports:
      - 5432:5432
    options: >-
      --health-cmd pg_isready
      --health-interval 10s
```

---

### runtimes

**Type:** Object
**Default:** Auto-detected from project
**Description:** Configures language runtimes available to agent.

```yaml
runtimes:
  node:
    version: "20"      # Default: 20
    package-manager: npm  # npm, yarn, pnpm

  python:
    version: "3.11"    # Default: 3.11
    package-manager: pip  # pip, poetry, pipenv

  go:
    version: "1.21"    # Default: 1.21

  uv:
    enabled: true      # Fast Python package installer

  bun:
    version: "1.0"

  deno:
    version: "1.40"

  ruby:
    version: "3.2"
    package-manager: bundler

  java:
    version: "17"      # Default: 17
    distribution: temurin  # temurin, zulu, adopt

  dotnet:
    version: "8.0"

  elixir:
    version: "1.15"

  haskell:
    version: "9.4"
```

---

## Structure & Composition

### imports

**Type:** Array of Objects or Strings
**Default:** Empty
**Description:** Imports configuration from other workflow files or repositories.

```yaml
imports:
  # Local file
  - .github/agentic/shared/common-tools.yml

  # Remote repository (owner/repo/path@ref)
  - org/workflows/shared/security.yml@main
  - org/workflows/shared/nodejs.yml@v1.2.3

  # Agent files (special syntax)
  - agent://security-reviewer

  # Merge strategies
  - path: shared/base.yml
    merge: deep  # deep (default), shallow, override

  - path: shared/overrides.yml
    merge: override  # Completely replaces existing config

  - path: shared/tools.yml
    merge: shallow  # Only top-level keys

  # Conditional imports
  - path: prod-config.yml
    if: github.ref == 'refs/heads/main'
```

---

### steps

**Type:** Array of Objects
**Default:** Empty
**Description:** Pre-execution steps run before agent starts. Can prepare data for agent.

```yaml
steps:
  - name: Checkout code
    uses: actions/checkout@v4

  - name: Install dependencies
    run: npm ci

  - name: Run tests
    run: npm test

  - name: Prepare analysis data
    run: |
      npm run analyze > /tmp/gh-aw/agent/analysis.json
      echo "Data saved for agent"
    env:
      NODE_ENV: production

# Agent can access files in /tmp/gh-aw/agent/
```

---

### post-steps

**Type:** Array of Objects
**Default:** Empty
**Description:** Post-execution steps run after agent completes.

```yaml
post-steps:
  - name: Cleanup
    run: rm -rf /tmp/analysis
    if: always()

  - name: Notify Slack
    if: success()
    run: |
      curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
        -d '{"text": "Workflow completed successfully"}'

  - name: Archive logs
    if: failure()
    uses: actions/upload-artifact@v4
    with:
      name: failure-logs
      path: /tmp/logs/
```

---

### jobs

**Type:** Object
**Default:** Single implicit job
**Description:** Defines custom jobs that run before the agentic execution job.

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  # Implicit agentic job runs after all custom jobs
  # and has access to their outputs
```

---

### secrets

**Type:** Array of Strings
**Default:** Empty
**Description:** Declares secrets required by the workflow. Provides clear documentation.

```yaml
secrets:
  - ANTHROPIC_API_KEY
  - SLACK_WEBHOOK_URL
  - DATABASE_PASSWORD

# Secrets referenced as: ${{ secrets.ANTHROPIC_API_KEY }}
```

---

### labels

**Type:** Array of Strings
**Default:** Empty
**Description:** Categorizes workflows for filtering and organization.

```yaml
labels: [security, automated, high-priority]
```

---

### metadata

**Type:** Object
**Default:** Empty
**Description:** Custom key-value pairs for workflow metadata.

```yaml
metadata:
  team: platform
  owner: "@security-team"
  category: vulnerability-scanning
  cost-center: "1234"
  priority: high
```

---

### tracker-id

**Type:** String
**Default:** Auto-generated
**Description:** Unique identifier for assets created by this workflow. Used for tracking and cleanup.

```yaml
tracker-id: bot-security-scan-v2

# Assets created will be tagged:
# <!-- gh-aw-tracker: bot-security-scan-v2 -->
```

---

### source

**Type:** String
**Default:** Workflow file path
**Description:** Reference to the origin of the workflow, useful for composed workflows.

```yaml
source: "org/workflows/shared/security.yml@v1"
```

---

### features

**Type:** Object
**Default:** All features disabled
**Description:** Experimental feature flags.

```yaml
features:
  action-mode: true  # Enable GitHub Actions compatibility mode
```

---

### plugins

**Type:** Array of Strings
**Default:** Empty
**Description:** Experimental plugin support for extending workflow capabilities.

```yaml
plugins:
  - "@gh-aw/plugin-slack"
  - "@gh-aw/plugin-jira"
```

---

### environment

**Type:** String
**Default:** No environment
**Description:** GitHub Environment for deployment protection rules and secrets.

```yaml
environment: production

# Requires:
# 1. Environment created in repo settings
# 2. Protection rules configured (required reviewers, wait timer)
# 3. Environment-specific secrets configured
```

---

### secret-masking

**Type:** Array of Objects
**Default:** Auto-masking of declared secrets
**Description:** Custom patterns to mask in logs beyond default secret masking.

```yaml
secret-masking:
  - pattern: "api_key=([a-zA-Z0-9]+)"
    replacement: "api_key=***"

  - pattern: "password:\\s*([^\\s]+)"
    replacement: "password: ***"

  - pattern: "Bearer\\s+([a-zA-Z0-9._-]+)"
    replacement: "Bearer ***"
```

---

## Reference Sources

- GitHub Agentic Workflows Documentation
- GitHub Actions Reference: https://docs.github.com/en/actions/reference
- MCP Specification: https://spec.modelcontextprotocol.io
- GitHub API: https://docs.github.com/en/rest

Last updated: 2026-02-19
