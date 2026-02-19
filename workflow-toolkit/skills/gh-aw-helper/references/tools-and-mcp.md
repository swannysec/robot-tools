# GitHub Agentic Workflows — Tools and MCP Configuration

Reference documentation for configuring tools and MCP servers in gh-aw workflows.

## Table of Contents

- [GitHub Tools](#github-tools)
  - [Toolsets](#toolsets)
  - [Operating Modes](#operating-modes)
  - [Read-Only Mode](#read-only-mode)
  - [GitHub App Authentication](#github-app-authentication)
  - [Token Precedence](#token-precedence)
  - [Lockdown Mode](#lockdown-mode)
- [Edit Tool](#edit-tool)
- [Bash Tool](#bash-tool)
- [Web Tools](#web-tools)
- [Playwright Tool](#playwright-tool)
- [Built-in MCP Tools](#built-in-mcp-tools)
  - [Agentic Workflows](#agentic-workflows-self-introspection)
  - [Cache Memory](#cache-memory-7-day-retention)
  - [Repo Memory](#repo-memory-unlimited-retention)
  - [Serena](#serena-semantic-code-analysis)
- [Custom MCP Servers](#custom-mcp-servers)
  - [Stdio (Command-based)](#stdio-command-based)
  - [Container (Docker-based)](#container-docker-based)
  - [HTTP (Remote Service)](#http-remote-service)
  - [Registry (Informational)](#registry-informational)
- [MCP Gateway](#mcp-gateway)
- [gh-aw as MCP Server](#gh-aw-as-mcp-server)
- [Debugging MCP](#debugging-mcp)
- [Shared MCP Configurations](#shared-mcp-configurations)
- [Adding MCP Servers via CLI](#adding-mcp-servers-via-cli)

---

## GitHub Tools

### Toolsets

All available GitHub toolsets with their included tools:

| Toolset | Tools | Notes |
|---------|-------|-------|
| `context` | get_teams, get_team_members | Team context retrieval |
| `repos` | get_repository, get_file_contents, list_commits | Repository operations |
| `issues` | list_issues, create_issue, update_issue | Issue management |
| `pull_requests` | list_pull_requests, create_pull_request | PR operations |
| `users` | User profile access | **NOT in default**, requires PAT |
| `actions` | Workflow runs and artifacts | CI/CD integration |
| `code_security` | Security alerts | Vulnerability scanning |
| `discussions` | GitHub Discussions | Community forums |
| `labels` | Label management | Issue/PR organization |
| `notifications` | Notification access | Alert management |
| `orgs` | Organization operations | Org-level management |
| `projects` | GitHub Projects | Project boards |
| `gists` | Gist operations | Code snippets |
| `search` | Search API | Code/issue search |
| `dependabot` | Dependabot alerts | Dependency updates |
| `experiments` | Experimental features | Preview features |
| `secret_protection` | Secret scanning | Leaked secret detection |
| `security_advisories` | Security advisories | CVE management |
| `stargazers` | Repository stars | Star tracking |
| `default` | Expands to: context, repos, issues, pull_requests | **Recommended starting point** |
| `all` | Everything | Full API access |

**Basic configuration:**

```yaml
tools:
  github:
    toolsets: [default]
```

**Custom toolset selection:**

```yaml
tools:
  github:
    toolsets: [repos, issues, pull_requests, actions, code_security]
```

### Operating Modes

| Mode | Requirements | Performance | Security | Use Case |
|------|-------------|-------------|----------|----------|
| `remote` | `GH_AW_GITHUB_TOKEN` | Faster | Token-based | Production, quick tasks |
| `local` | `tools: docker:` | Slower | Docker isolation | Security-sensitive |

**Remote mode (recommended):**

```yaml
tools:
  github:
    mode: remote
    toolsets: [default]
```

**Local mode (Docker isolation):**

```yaml
tools:
  docker:
  github:
    mode: local
    toolsets: [default]
```

### Read-Only Mode

Prevents all write operations (create, update, delete):

```yaml
tools:
  github:
    read-only: true
    toolsets: [repos, issues, pull_requests]
```

### GitHub App Authentication

Use GitHub App instead of personal access token:

```yaml
tools:
  github:
    app:
      app-id: ${{ vars.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
      owner: "my-org"
      repositories: ["repo1", "repo2"]
```

**Benefits:**
- Fine-grained permissions per repository
- Organization-level authentication
- Audit trail with app identity

### Token Precedence

Token resolution order (first match wins):

1. **GitHub App** (app.app-id + app.private-key)
2. **github-token** (explicit config)
3. **GH_AW_GITHUB_MCP_SERVER_TOKEN** (environment)
4. **GH_AW_GITHUB_TOKEN** (environment)
5. **GITHUB_TOKEN** (GitHub Actions default)

```yaml
tools:
  github:
    github-token: ${{ secrets.CUSTOM_TOKEN }}  # Overrides all env vars
```

### Lockdown Mode

Restricts tool invocations to users with push access to the repository.

**Auto-enabled when:**
- Using custom token (not `GITHUB_TOKEN`)
- Operating on public repositories

**Manual configuration:**

```yaml
tools:
  github:
    lockdown: true     # Force enable
    lockdown: false    # Disable (safe for triage workflows)
```

**Security implications:**
- `lockdown: true` — Only push-access users can invoke tools
- `lockdown: false` — Any authenticated user can invoke (appropriate for public triage)

---

## Edit Tool

Enables file editing within the workspace:

```yaml
tools:
  edit:
```

**Capabilities:**
- Create, read, update, delete files
- Search and replace
- Multi-file operations

**Workspace location:** `/tmp/gh-aw/workspace/<workflow-id>/`

---

## Bash Tool

Executes shell commands with configurable allowlist.

### Configuration Options

| Config | Behavior |
|--------|----------|
| `bash:` (no value) | Default safe commands only |
| `bash: []` | Disable all commands |
| `bash: ["cmd1", "cmd2"]` | Specific commands only |
| `bash: [":*"]` | All commands (unrestricted) |

### Default Safe Commands

```yaml
tools:
  bash:  # Enables these by default:
```

- File operations: `echo`, `cat`, `head`, `tail`
- Directory: `ls`, `pwd`
- Text processing: `grep`, `wc`, `sort`, `uniq`
- Utilities: `date`

### Command Families (Wildcards)

```yaml
tools:
  bash: ["git:*", "npm:*", "docker:*"]  # Command family wildcards
```

**Examples:**
- `git:*` — All git subcommands (git status, git commit, git push)
- `npm:*` — All npm commands
- `:*` — All commands (unrestricted, use with caution)

### Explicit Command List

```yaml
tools:
  bash: ["echo", "ls", "git status", "git log", "npm install"]
```

---

## Web Tools

### Web Fetch

Retrieve web content:

```yaml
tools:
  web-fetch:
```

**Use cases:** Scraping documentation, fetching API responses, downloading resources

### Web Search

Search engine integration:

```yaml
tools:
  web-search:
```

**Requirements:** May require MCP server configuration depending on search engine

---

## Playwright Tool

Browser automation for web testing and scraping.

```yaml
tools:
  playwright:
    allowed_domains: ["defaults", "github", "*.custom.com"]
    version: "1.56.1"
```

### Configuration Options

| Option | Values | Default |
|--------|--------|---------|
| `allowed_domains` | Array of domains | `["defaults"]` |
| `version` | Specific version or `"latest"` | `"latest"` |

**Domain allowlist:**
- `"defaults"` — localhost, 127.0.0.1
- `"github"` — github.com
- `"*.example.com"` — Wildcard subdomains

**Network configuration:**
```yaml
tools:
  playwright:
    allowed_domains: ["defaults", "github", "api.example.com"]
    version: "1.56.1"
network:
  allowed: ["api.example.com"]  # Required for custom domains
```

**Security:** Docker security flags auto-configured in gh-aw 0.41.0+

---

## Built-in MCP Tools

### Agentic Workflows (Self-Introspection)

Provides workflow status, log analysis, and debugging tools.

```yaml
permissions:
  actions: read
tools:
  agentic-workflows:
```

**Capabilities:**
- Query workflow run status
- Analyze logs
- Debug workflow failures
- Inspect configuration

### Cache Memory (7-Day Retention)

Temporary storage with automatic expiration.

**Simple configuration:**

```yaml
tools:
  cache-memory: true
```

**Advanced configuration:**

```yaml
tools:
  cache-memory:
    key: custom-key                          # Namespace key
    retention-days: 30                       # 7-30 days
    allowed-extensions: [".json", ".txt"]    # File type restrictions
```

**Multiple cache configurations:**

```yaml
tools:
  cache-memory:
    - id: default
      retention-days: 7
    - id: analysis-results
      key: analysis
      retention-days: 14
      allowed-extensions: [".json"]
```

**Storage location:** `/tmp/gh-aw/cache-memory/`

**Use cases:** Temporary analysis results, intermediate build artifacts, session state

### Repo Memory (Unlimited Retention)

Persistent storage backed by Git branches.

**Simple configuration:**

```yaml
tools:
  repo-memory: true
```

**Advanced configuration:**

```yaml
tools:
  repo-memory:
    branch-name: memory/my-data              # Branch for storage
    branch-prefix: tracking                   # Prefix for auto-generated branches
    file-glob: ["memory/my-data/*.json"]     # File pattern filter
    max-file-size: 1048576                   # 1MB limit per file
    max-file-count: 50                       # Max files
    target-repo: "owner/repo"                # Different repo (optional)
    create-orphan: true                      # Orphan branch (no history)
    allowed-extensions: [".json", ".md"]     # File type restrictions
```

**Storage location:** `/tmp/gh-aw/repo-memory-default/`

**Permissions:** Automatically adds `contents: write` to workflow permissions

**Use cases:** Long-term state, experiment results, learned knowledge, configuration history

### Serena (Semantic Code Analysis)

Language server protocol (LSP) integration for symbol-level navigation and editing.

**Short syntax (recommended):**

```yaml
tools:
  serena: ["go", "typescript", "python"]
```

**Long syntax (version pinning):**

```yaml
tools:
  serena:
    version: latest
    languages:
      go:
        version: "1.21"
        go-mod-file: "go.mod"
        gopls-version: "v0.14.2"
      typescript:
        tsconfig: "tsconfig.json"
      python:
        python-version: "3.11"
```

**Supported languages:** 30+ including Go, TypeScript, Python, Rust, Java, C++, C#, Ruby, PHP, Swift, Kotlin

**Capabilities:**
- Symbol search and navigation
- Go to definition
- Find references
- Rename symbol
- Code completion
- Semantic editing

**Performance optimization:**
```yaml
tools:
  cache-memory: true    # Cache LSP indexes
  serena: ["typescript"]
```

---

## Custom MCP Servers

### Stdio (Command-Based)

Execute local commands to spawn MCP servers.

```yaml
mcp-servers:
  tavily:
    command: npx
    args: ["-y", "@tavily/mcp-server"]
    env:
      TAVILY_API_KEY: "${{ secrets.TAVILY_API_KEY }}"
    allowed: ["search", "search_news"]
```

**Configuration options:**

| Field | Required | Description |
|-------|----------|-------------|
| `command` | Yes | Executable command |
| `args` | No | Command arguments |
| `env` | No | Environment variables |
| `allowed` | No | Tool allowlist (default: all) |

**Common patterns:**

```yaml
mcp-servers:
  # Node.js package
  server-name:
    command: npx
    args: ["-y", "@org/package"]

  # Python package
  python-server:
    command: uvx
    args: ["package-name"]

  # Local binary
  custom:
    command: /usr/local/bin/custom-server
    args: ["--config", "config.json"]
```

### Container (Docker-Based)

Run MCP servers in isolated containers.

```yaml
mcp-servers:
  ast-grep:
    container: "mcp/ast-grep:latest"
    allowed: ["*"]

  custom:
    container: "mcp/custom:v1.0"
    args: ["-v", "/host/data:/app/data"]           # Volume mounts BEFORE image
    entrypointArgs: ["serve", "--port", "8080"]    # App args AFTER image
    env:
      API_KEY: "${{ secrets.KEY }}"
    allowed: ["tool1", "tool2"]
```

**Configuration options:**

| Field | Required | Description |
|-------|----------|-------------|
| `container` | Yes | Docker image |
| `args` | No | Docker run arguments (volumes, ports) |
| `entrypointArgs` | No | Container command arguments |
| `env` | No | Environment variables |
| `allowed` | No | Tool allowlist |

**Argument order:**
```bash
docker run [args] [container] [entrypointArgs]
docker run -v /host:/container mcp/custom:v1.0 serve --port 8080
```

### HTTP (Remote Service)

Connect to remote MCP servers over HTTP.

```yaml
mcp-servers:
  slack:
    url: "https://api.slack.com/mcp"
    headers:
      Authorization: "Bearer ${{ secrets.SLACK_TOKEN }}"
    env:
      SLACK_BOT_TOKEN: "${{ secrets.SLACK_TOKEN }}"
    network:
      allowed: ["api.slack.com"]
    allowed: ["send_message", "get_channel_history"]
```

**Configuration options:**

| Field | Required | Description |
|-------|----------|-------------|
| `url` | Yes | MCP server endpoint |
| `headers` | No | HTTP headers |
| `env` | No | Environment variables |
| `network.allowed` | No | Domain allowlist for network access |
| `allowed` | No | Tool allowlist |

**Network security:**
```yaml
mcp-servers:
  api-server:
    url: "https://api.example.com/mcp"
    network:
      allowed: ["api.example.com", "cdn.example.com"]  # Must whitelist all domains
```

### Registry (Informational)

Reference MCP servers from registries with additional metadata.

```yaml
mcp-servers:
  markitdown:
    registry: "https://api.mcp.github.com/v0/servers/microsoft/markitdown"
    command: "npx"
    args: ["-y", "@microsoft/markitdown"]
```

**Purpose:** Combines registry metadata with execution configuration for discovery and documentation.

---

## MCP Gateway

Transparent proxy routing MCP server calls through unified HTTP gateway.

### Architecture

- **Protocol translation:** Stdio ↔ HTTP JSON-RPC
- **Server isolation:** Containerized MCP servers
- **Authentication:** Token-based security
- **Health monitoring:** Liveness and readiness checks

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/mcp/{server-name}` | POST | JSON-RPC request forwarding |
| `/health` | GET | Health and readiness status |
| `/close` | POST | Graceful shutdown |

### Configuration

```yaml
sandbox:
  mcp:
    container: "ghcr.io/org/mcp-gateway"
    port: 8080
    api-key: "${{ secrets.MCP_GATEWAY_KEY }}"
    domain: "localhost"
```

**Benefits:**
- Single HTTP endpoint for multiple MCP servers
- Centralized authentication and logging
- Resource pooling and connection management

---

## gh-aw as MCP Server

Expose gh-aw CLI tools to AI agents via MCP protocol.

### Configuration

```yaml
permissions:
  actions: read
tools:
  agentic-workflows:
```

### Direct Usage

```bash
# Stdio mode (pipe-based communication)
gh aw mcp-server

# HTTP mode (server on specified port)
gh aw mcp-server --port 8080

# With permission validation
gh aw mcp-server --validate-actor
```

### Available Tools

| Tool | Purpose |
|------|---------|
| `status` | Query workflow run status |
| `compile` | Validate workflow configuration |
| `logs` | Retrieve workflow logs |
| `audit` | Audit trail and history |
| `mcp-inspect` | Inspect MCP server configuration |
| `add` | Add new workflow components |
| `update` | Update workflow configuration |
| `fix` | Auto-fix common issues |

---

## Debugging MCP

### Inspect MCP Configuration

```bash
# Inspect all MCP servers in workflow
gh aw mcp inspect <workflow>

# Inspect specific server
gh aw mcp inspect <workflow> --server github

# List available tools
gh aw mcp list-tools github <workflow>
```

### Validate Configuration

```bash
# Validate workflow configuration
gh aw compile <workflow> --validate

# Strict validation (fail on warnings)
gh aw compile <workflow> --validate --strict
```

### Common Issues

| Issue | Symptom | Solution |
|-------|---------|----------|
| Missing token | Authentication failure | Check token precedence, verify secrets |
| Tool not found | Tool invocation fails | Verify `allowed` list, check server status |
| Network blocked | HTTP timeout | Add domain to `network.allowed` |
| Container startup | Server unreachable | Check Docker daemon, verify image |

---

## Shared MCP Configurations

Pre-built configurations in `.github/workflows/shared/mcp/`:

| Server | Purpose | Import Path |
|--------|---------|-------------|
| `jupyter` | Jupyter notebook execution | `shared/mcp/jupyter.md` |
| `drain3` | Log parsing and pattern extraction | `shared/mcp/drain3.md` |
| `ast-grep` | AST-based code search | `shared/mcp/ast-grep.md` |
| `azure` | Azure cloud integration | `shared/mcp/azure.md` |
| `brave` | Brave search engine | `shared/mcp/brave.md` |
| `context7` | Documentation context | `shared/mcp/context7.md` |
| `datadog` | Datadog monitoring | `shared/mcp/datadog.md` |
| `deepwiki` | Wikipedia integration | `shared/mcp/deepwiki.md` |
| `fabric-rti` | RTI processing | `shared/mcp/fabric-rti.md` |
| `markitdown` | Markdown conversion | `shared/mcp/markitdown.md` |
| `microsoft-docs` | Microsoft docs | `shared/mcp/microsoft-docs.md` |
| `notion` | Notion workspace | `shared/mcp/notion.md` |
| `sentry` | Error tracking | `shared/mcp/sentry.md` |
| `serena` | Code analysis | `shared/mcp/serena.md` |
| `server-memory` | Persistent memory | `shared/mcp/server-memory.md` |
| `slack` | Slack integration | `shared/mcp/slack.md` |
| `tavily` | AI search | `shared/mcp/tavily.md` |
| `arxiv` | Academic papers | `shared/mcp/arxiv.md` |

### Import Syntax

```yaml
imports:
  - shared/mcp/tavily.md
  - shared/mcp/slack.md
```

**Override imported configuration:**

```yaml
imports:
  - shared/mcp/tavily.md

mcp-servers:
  tavily:
    env:
      TAVILY_API_KEY: "${{ secrets.CUSTOM_TAVILY_KEY }}"  # Override
```

---

## Adding MCP Servers via CLI

### From Package Name

```bash
# Add from npm package
gh aw mcp add <workflow> makenotion/notion-mcp-server

# With custom tool ID
gh aw mcp add <workflow> server --tool-id my-notion

# From custom registry
gh aw mcp add <workflow> server --registry https://custom.registry.com/v1
```

### Interactive Configuration

```bash
# CLI prompts for configuration options
gh aw mcp add <workflow> custom-server
# Prompts:
# - Server type (stdio/container/http)
# - Command/image/url
# - Environment variables
# - Tool allowlist
```

### Manual Configuration

After adding via CLI, edit workflow file to customize:

```yaml
mcp-servers:
  notion:
    command: npx
    args: ["-y", "@makenotion/notion-mcp-server"]
    env:
      NOTION_API_KEY: "${{ secrets.NOTION_KEY }}"
    allowed: ["search", "create_page", "update_page"]
```

---

## Quick Reference

### Minimal Workflow Configuration

```yaml
permissions:
  contents: read
  issues: write
  pull-requests: write

tools:
  github:
    toolsets: [default]
  edit:
  bash:

mcp-servers:
  tavily:
    command: npx
    args: ["-y", "@tavily/mcp-server"]
    env:
      TAVILY_API_KEY: "${{ secrets.TAVILY_API_KEY }}"
```

### Full-Featured Configuration

```yaml
permissions:
  contents: write
  issues: write
  pull-requests: write
  actions: read

tools:
  docker:
  github:
    mode: remote
    toolsets: [default, actions, code_security]
    lockdown: true
  edit:
  bash: ["git:*", "npm:*"]
  web-fetch:
  playwright:
    allowed_domains: ["defaults", "github"]
  cache-memory:
    retention-days: 14
  repo-memory:
    branch-prefix: workflow-state
  serena: ["typescript", "go", "python"]
  agentic-workflows:

mcp-servers:
  tavily:
    command: npx
    args: ["-y", "@tavily/mcp-server"]
    env:
      TAVILY_API_KEY: "${{ secrets.TAVILY_API_KEY }}"

  ast-grep:
    container: "mcp/ast-grep:latest"

  slack:
    url: "https://api.slack.com/mcp"
    headers:
      Authorization: "Bearer ${{ secrets.SLACK_TOKEN }}"
    network:
      allowed: ["api.slack.com"]

network:
  allowed: ["api.slack.com", "api.tavily.com"]
```
