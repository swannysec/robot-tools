# Security and Network Reference — GitHub Agentic Workflows

## Table of Contents

1. [Permissions System](#permissions-system)
2. [Authentication & Secrets](#authentication--secrets)
3. [Sandbox Execution](#sandbox-execution)
4. [Network Configuration](#network-configuration)
5. [Lockdown Mode](#lockdown-mode)
6. [Threat Detection](#threat-detection)
7. [Rate Limiting](#rate-limiting)
8. [Compilation-Time Security](#compilation-time-security)
9. [Secret Redaction](#secret-redaction)

---

## Permissions System

**Default behavior:** Read-only access. Write operations only through safe outputs.

### Permission Scopes

| Scope | Description |
|-------|-------------|
| `contents` | Repository files and commits |
| `issues` | Issue read/write |
| `pull-requests` | PR read/write |
| `discussions` | Discussion read/write |
| `actions` | Workflow dispatch and logs |
| `checks` | Check runs and suites |
| `deployments` | Deployment status |
| `packages` | Package read/write |
| `pages` | GitHub Pages |
| `statuses` | Commit statuses |
| `id-token` | OIDC token generation |
| `metadata` | Repository metadata (always read) |
| `models` | GitHub Models API |
| `attestations` | Artifact attestations |
| `security-events` | Security alerts |

### Shorthands

```yaml
permissions: read-all          # all read
permissions: write-all         # all write (blocked by default)
permissions: {}                # no permissions
```

### Write Permission Restrictions

- **Blocked by default** (except `id-token: write` for OIDC)
- **Strict mode**: Refuses all write permissions unconditionally
- Write operations must use safe outputs (e.g., `create-comment`, `dispatch-workflow`)

---

## Authentication & Secrets

### Required Secrets by Engine

| Secret | Purpose | When Required |
|--------|---------|---------------|
| `COPILOT_GITHUB_TOKEN` | Copilot CLI auth | Copilot engine |
| `ANTHROPIC_API_KEY` | Claude API auth | Claude engine |
| `OPENAI_API_KEY` | Codex API auth | Codex engine |
| `GH_AW_GITHUB_TOKEN` | Enhanced security, cross-repo, remote tools | Lockdown mode, cross-repo |
| `GH_AW_PROJECT_GITHUB_TOKEN` | GitHub Projects v2 operations | Project operations |
| `GH_AW_AGENT_TOKEN` | Copilot coding agent assignment | `assign-to-agent` safe output |
| `GH_AW_GITHUB_MCP_SERVER_TOKEN` | MCP server special permissions | MCP server auth |

### Token Types

#### User-Owned Projects
- **Classic PAT** with `project` scope

#### Org-Owned Projects
- **Classic PAT**: `project` + `read:org` + `repo`
- **Fine-grained PAT**: Project-specific scopes

#### Agent Assignment Token
**Fine-grained PAT** with:
- Actions: Write
- Contents: Write
- Issues: Write
- Pull requests: Write

### GitHub App Authentication

```yaml
tools:
  github:
    app:
      app-id: ${{ vars.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
      owner: "my-org"
      repositories: ["repo1", "repo2"]  # or ["*"] for all

safe-outputs:
  app:
    app-id: ${{ vars.APP_ID }}
    private-key: ${{ secrets.APP_PRIVATE_KEY }}
    owner: "my-org"
    repositories: ["*"]
```

### Token Precedence (GitHub Tools)

**Order of token selection:**

1. GitHub App (`app.private-key`)
2. `github-token` parameter
3. `GH_AW_GITHUB_MCP_SERVER_TOKEN`
4. `GH_AW_GITHUB_TOKEN`
5. `GITHUB_TOKEN` (default)

---

## Sandbox Execution

### Agent Workflow Firewall (AWF) — Default

**Network isolation:**
- Egress via domain allowlist
- iptables → Squid proxy filtering

**Filesystem:**
- User paths: Read/Write
- System paths: Read-Only
- Docker socket: Hidden

**Binaries:**
- All host binaries available

**Custom mounts:**
- Format: `source:destination:mode`
- Modes: `ro` (read-only), `rw` (read-write)

### Sandbox Configuration

```yaml
# Default AWF sandbox
sandbox: awf

# Sandbox Runtime (stricter)
sandbox: srt

# Disable sandbox (not allowed in strict mode)
sandbox: false

# Advanced configuration
sandbox:
  agent:
    id: awf
    mounts:
      - "/host/data:/container/data:ro"
      - "/host/logs:/container/logs:rw"
    env:
      DEBUG: "true"
      LOG_LEVEL: "info"

  # Custom MCP gateway
  mcp:
    container: "ghcr.io/org/mcp-gateway:latest"
    port: 8080
    api-key: ${{ secrets.MCP_API_KEY }}
```

---

## Network Configuration

### Allowed Domains

```yaml
# Basic infrastructure only
network: defaults

# No network access
network: {}

# Explicit configuration
network:
  allowed:
    - defaults                           # certificates, JSON schema, Ubuntu
    - python                             # PyPI, conda, pythonhosted.org
    - node                               # npm, yarn, pnpm
    - go                                 # proxy.golang.org
    - containers                         # Docker Hub, GHCR, Quay, GCR
    - java                               # Maven, Gradle
    - dotnet                             # NuGet
    - ruby                               # RubyGems
    - rust                               # crates.io
    - github                             # githubusercontent.com
    - terraform                          # HashiCorp registry
    - playwright                         # browser downloads
    - linux-distros                      # Debian, Ubuntu, Alpine
    - "api.example.com"                  # custom domain
    - "*.example.com"                    # wildcard
  blocked:
    - "tracker.example.com"              # blocked takes precedence over allowed
```

### Ecosystem Identifiers

| Identifier | Domains Allowed |
|------------|----------------|
| `defaults` | Certificates, schemas, Ubuntu repos |
| `python` | pypi.org, anaconda.org, pythonhosted.org |
| `node` | npmjs.com, yarnpkg.com, pnpm.io |
| `go` | proxy.golang.org, sum.golang.org |
| `containers` | Docker Hub, ghcr.io, quay.io, gcr.io |
| `java` | Maven Central, Gradle repos |
| `dotnet` | nuget.org, dotnetfoundation.org |
| `ruby` | rubygems.org, bundler.io |
| `rust` | crates.io, static.crates.io |
| `github` | githubusercontent.com, github.com |
| `terraform` | registry.terraform.io |
| `playwright` | playwright.azureedge.net |
| `linux-distros` | Debian, Ubuntu, Alpine mirrors |

### Strict Mode Network Rules

- **Requires explicit network configuration** (no implicit defaults)
- **Refuses wildcard** `*` in allowed domains
- **Recommends ecosystem identifiers** over individual domains
- **Requires network config** for custom MCP containers

### Protocol-Specific Filtering (Copilot with AWF)

```yaml
network:
  allowed:
    - "https://secure.api.example.com"   # HTTPS-only
    - "http://legacy.example.com"        # HTTP-only
    - "example.org"                      # both HTTP and HTTPS
```

### AWF Firewall Features

```yaml
network:
  firewall:
    log-level: info                      # debug, info, warn, error
    ssl-bump: true                       # HTTPS deep packet inspection
    allow-urls:
      - "https://github.com/githubnext/*"
      - "https://api.github.com/repos/*/issues"
```

**Features:**
- URL pattern matching with wildcards
- SSL/TLS inspection (when `ssl-bump: true`)
- Granular logging for debugging

### Content Sanitization

**Behavior:**
- URLs from non-allowed domains replaced with `(redacted)` in agent context
- Prevents leaking sensitive URLs in logs/artifacts

---

## Lockdown Mode

**Purpose:** Filter public repo content to show only items from users with push access.

```yaml
tools:
  github:
    lockdown: true    # force enable
    lockdown: false   # explicitly disable
```

### Automatic Activation

- **Public repos** with `GH_AW_GITHUB_TOKEN` set
- **Private/internal repos**: No effect (already restricted)

### Required Token Permissions

`GH_AW_GITHUB_TOKEN` must have:
- Contents: Read
- Issues: Read
- Pull requests: Read

### When to Disable Lockdown

| Use Case | Reason |
|----------|--------|
| Issue triage | Need to see all public issues |
| Spam detection | Analyze all submissions |
| Public dashboards | Report on all activity |
| Command workflows | Verify permissions per-command |

---

## Threat Detection

### Configuration

```yaml
# Default (enabled when safe-outputs exist)
threat-detection: true

# Advanced configuration
threat-detection:
  enabled: true
  prompt: "Focus on SQL injection and XSS patterns"
  engine: copilot               # or full engine config
  steps:
    - name: Custom Check
      run: |
        echo "Running additional security checks"
        grep -r "dangerous_pattern" /tmp/gh-aw || true
```

### Detection Types

| Threat | Description |
|--------|-------------|
| `prompt_injection` | Malicious prompt manipulation |
| `secret_leak` | Credentials or API keys in output |
| `malicious_patch` | Code changes with security risks |

### Output Format

```json
{
  "prompt_injection": false,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": []
}
```

**When threats detected:**
```json
{
  "prompt_injection": true,
  "secret_leak": false,
  "malicious_patch": false,
  "reasons": ["Detected prompt override attempt in user input"]
}
```

### Execution Order

1. Download artifacts from agent execution
2. AI-based analysis (prompt, secrets, patches)
3. Custom validation steps
4. Upload detection log as artifact

---

## Rate Limiting

### Defense-in-Depth Layers

| Layer | Mechanism |
|-------|-----------|
| 1. Bot non-triggering | `github-actions[bot]` doesn't trigger workflow events |
| 2. Concurrency groups | Per-workflow, per-engine limits |
| 3. Timeouts | `job.timeout-minutes`, `workflow.stop-after` |
| 4. Safe output limits | `assign-to-agent: 1`, `dispatch-workflow: 1` per run |
| 5. Built-in delays | Agent assignments: 10s, dispatches: 5s |
| 6. Manual review gates | GitHub Environments with approvers |

### Per-User Rate Limiting

```yaml
rate-limit:
  max: 5                              # 1-10 runs per window
  window: 60                          # minutes (default 60, max 180)
  events:
    - workflow_dispatch
    - issue_comment
  ignored-roles:
    - admin
    - maintain                        # default: [admin, maintain, write]
```

**Behavior:**
- Tracks runs per `actor` (GitHub username)
- Blocks new runs if limit exceeded
- Configurable per workflow

**Role exemptions:**
- `admin`: Repository administrators
- `maintain`: Maintain role
- `write`: Write access (default included)

---

## Compilation-Time Security

### Validation Layers

| Check | Purpose |
|-------|---------|
| Schema validation | YAML structure correctness |
| Expression safety | Only allowlisted expressions, no secrets |
| Action pinning | Tags → SHAs with version comments |
| Security scanners | actionlint, zizmor, poutine |
| Strict mode enforcement | Fails on any security violation |

### Expression Safety

**Allowed expressions:**
```yaml
# Safe: predefined contexts
if: ${{ github.event_name == 'pull_request' }}
run: echo "${{ inputs.safe-string }}"

# Blocked: secret exposure
run: echo "${{ secrets.API_KEY }}"  # compilation error
```

**Allowlisted contexts:**
- `github.*`
- `inputs.*`
- `vars.*`
- `env.*`
- `job.*`
- `runner.*`

### Action Pinning

**Before compilation:**
```yaml
uses: actions/checkout@v4
```

**After compilation:**
```yaml
uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

**Benefits:**
- Immutable action versions
- Supply chain security
- Version audit trail

### Security Scanner Integration

```bash
# actionlint: workflow syntax and security
actionlint .github/workflows/compiled.yml

# zizmor: security-specific checks
zizmor .github/workflows/compiled.yml

# poutine: supply chain analysis
poutine analyze-actions .github/workflows/
```

---

## Secret Redaction

### Automatic Redaction

**Scope:** All files in `/tmp/gh-aw` before artifact upload

**Execution:** Unconditional (`if: always()`)

**Visibility:** First 3 characters + asterisks

```
API_KEY=abc***************
GITHUB_TOKEN=ghp_***************
```

### Custom Masking

```yaml
secret-masking:
  patterns:
    - "password=.*"
    - "token=[A-Za-z0-9_-]+"
  files:
    - "/tmp/gh-aw/logs/*.log"
    - "/tmp/gh-aw/output/*.json"
```

**Features:**
- Regex pattern matching
- File path filtering
- Pre-upload execution
- No performance impact on agent execution

### Built-In Secret Patterns

- GitHub tokens (`ghp_`, `gho_`, `ghs_`)
- Generic API keys (`api_key=`, `apikey=`)
- AWS credentials
- JWT tokens
- SSH private keys

---

## Security Best Practices

### Token Management

1. Use **fine-grained PATs** over classic when possible
2. Set **minimum required scopes**
3. Rotate tokens regularly
4. Store in **repository secrets**, not hardcoded
5. Use **GitHub Apps** for cross-repo access

### Network Isolation

1. Start with `network: defaults`
2. Add ecosystems as needed (`python`, `node`, etc.)
3. Use **explicit domains** for third-party APIs
4. Enable **lockdown mode** for public repos
5. Monitor firewall logs in AWF

### Safe Output Design

1. Validate all user input before safe outputs
2. Use **threat detection** for high-risk operations
3. Limit safe output executions (e.g., `assign-to-agent: 1`)
4. Add **manual review gates** for sensitive workflows

### Strict Mode Adoption

Enable strict mode to enforce:
- No write permissions
- Explicit network config
- Mandatory threat detection
- Action pinning required

```yaml
strict: true
```

**When to use strict mode:**
- Public repositories
- Sensitive data access
- Production deployments
- Compliance requirements