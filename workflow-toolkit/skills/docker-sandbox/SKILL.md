---
name: docker-sandbox
description: |
  Docker Sandboxes (sbx CLI) — run AI coding agents in isolated microVM
  environments with credential proxying, network policy enforcement, and
  custom templates. Covers Claude Code, Codex, Copilot, and Gemini agents.
  Compatible with Rancher Desktop (Docker Desktop not required).

  Use this skill when users need to:
  (1) Install, configure, or authenticate with the sbx CLI
  (2) Create, run, stop, or remove sandboxed agent sessions
  (3) Configure credentials, secrets, or API keys for sandboxed agents
  (4) Understand the security model (microVM, proxy, network policies)
  (5) Build custom sandbox templates or customize environments
  (6) Troubleshoot sandbox issues (clock drift, port forwarding, connectivity)
  (7) Use branch mode, multi-workspace, or reconnection workflows
  (8) Set up specific agents (Claude Code, Codex, Copilot, Gemini) in sandboxes
  (9) Use 1Password CLI (op) for zero-disk-footprint secret injection
triggers:
  - "docker sandbox"
  - "docker sandboxes"
  - "sbx"
  - "sbx cli"
  - "sbx run"
  - "sbx create"
  - "sandbox agent"
  - "sandbox microvm"
  - "sandbox template"
  - "sbx login"
  - "sbx secret"
  - "sbx policy"
  - "sbx branch"
  - "sandbox credential"
  - "sandbox security"
  - "sandbox isolation"
  - "custom sandbox template"
  - "sbx save"
  - "sandbox port forwarding"
  - "sandbox troubleshooting"
  - "rancher desktop sandbox"
  - "sandbox clock drift"
  - "1password sandbox"
  - "op cli sandbox"
---

# Docker Sandboxes (sbx CLI)

Run AI coding agents in isolated microVM environments with their own Docker
daemon, filesystem, and network stack.

> **Docs**: https://docs.docker.com/ai/sandboxes/
> **Install**: `brew install docker/tap/sbx` (macOS)

---

## Help — Topic Navigator

Use this table to find the right reference file. **Read the reference only when
needed** for the user's specific question.

| Topic | Reference | Consult when... |
|-------|-----------|-----------------|
| CLI commands & flags | [references/cli-reference.md](references/cli-reference.md) | User needs exact flag syntax, all options for a subcommand, or uncommon commands |
| Security & isolation | [references/security-deep-dive.md](references/security-deep-dive.md) | User asks about isolation layers, network policies, residual risks, or threat model |
| Credentials & secrets | [references/credential-management.md](references/credential-management.md) | User needs to set up API keys, troubleshoot auth, use 1Password `op` CLI, or configure custom env vars |
| Custom environments | [references/custom-environments.md](references/custom-environments.md) | User wants to build templates, customize images, or use `sbx save` |
| Agent-specific setup | [references/agent-setup.md](references/agent-setup.md) | User needs per-agent auth details, config quirks, or agent comparison |
| Troubleshooting | [references/troubleshooting.md](references/troubleshooting.md) | User hits errors, clock drift, port issues, connectivity problems, or needs diagnostics |

---

## Quick Start

### 1. Install

```bash
brew install docker/tap/sbx   # macOS (Docker Desktop NOT required)
```

Windows: `winget install -h Docker.sbx`
Linux (Ubuntu 22.04+): requires KVM — see official docs.

### 2. Authenticate

```bash
sbx login
```

You will be prompted to select a default network policy:

| Policy | Behavior |
|--------|----------|
| **Open** | All outbound traffic allowed |
| **Balanced** | Deny-by-default + common dev sites allowed (recommended) |
| **Locked Down** | All traffic blocked unless explicitly allowed |

### 3. Store agent credentials

```bash
sbx secret set -g anthropic           # prompts for Anthropic API key
sbx secret set -g openai              # prompts for OpenAI API key
sbx secret set -g github -t "$(gh auth token)"  # GitHub token
sbx secret set -g google              # prompts for Google API key
```

Secrets are stored in the host OS keychain. The proxy injects auth headers into
outbound API requests — **raw credential values never enter the sandbox**.

### 4. Run your first sandbox

```bash
cd ~/my-project
sbx run claude                         # creates + attaches in one step
```

First run downloads the sandbox image (slow); subsequent runs are cached.
Verify: `sbx ls`

---

## Essential Workflows

### Run, stop, reconnect

```bash
sbx run claude ~/project               # create + attach
sbx run claude --name my-sandbox       # explicit naming
sbx stop my-sandbox                    # pause (state preserved)
sbx run my-sandbox                     # reconnect to existing
sbx rm my-sandbox                      # permanent delete
```

### Branch mode (isolated git)

```bash
sbx run claude --branch my-feature     # creates git worktree under .sbx/
sbx run claude --branch auto           # auto-generated branch name
```

Worktrees live under `.sbx/` — add to `.gitignore`. Uncommitted changes in your
main tree are NOT visible in worktrees. `sbx rm` deletes all worktrees for that
sandbox.

### Multi-workspace mounting

```bash
sbx run claude ~/project-a ~/shared-libs:ro ~/docs:ro
```

First path is primary workspace. Additional paths mount at their host absolute
paths. Append `:ro` for read-only.

### Execute commands inside a sandbox

```bash
sbx exec -it my-sandbox bash           # interactive shell
sbx exec -d my-sandbox npm start       # background command
```

### Port forwarding (post-hoc only)

```bash
sbx ports my-sandbox --publish 8080:3000   # host:8080 → sandbox:3000
sbx ports my-sandbox                        # list all mappings
sbx ports my-sandbox --unpublish 8080:3000  # remove mapping
```

Services inside the sandbox must bind to `0.0.0.0` (not `127.0.0.1`). Port
mappings are lost on sandbox stop.

### List and manage

```bash
sbx ls                                 # table with agent, status, ports, workspace
sbx ls --json                          # JSON output
sbx                                    # interactive TUI dashboard
```

**For full flag details on every subcommand, read
[references/cli-reference.md](references/cli-reference.md).** This is mandatory
when the user needs exact syntax or uncommon options.

---

## Security Model Overview

Docker Sandboxes isolate agents in microVMs with **4 security layers**:

| Layer | Isolation |
|-------|-----------|
| **Hypervisor** | Separate Linux kernel per sandbox; processes invisible to host |
| **Network proxy** | All HTTP/HTTPS through host proxy; no raw TCP/UDP/ICMP; DNS via proxy |
| **Docker Engine** | Isolated daemon per sandbox; no access to host Docker |
| **Credentials** | Proxy injects auth headers; raw keys never enter VM |

**Key principle:** The hypervisor boundary is the security control, not in-VM
privilege separation. Agents have sudo inside the sandbox by design.

### Critical gotchas

- **Workspace is the primary residual risk** — agents can modify git hooks, CI
  configs, IDE tasks, and build scripts within the mounted workspace
- **Git hooks are invisible to `git diff`** — check `.git/hooks/` manually
  after each session
- **Branch mode is NOT a security boundary** — documented as convenience only
- **Deny always beats allow** in network policies, regardless of specificity
- **`~/.claude` is NOT mounted** — only project-level config is available

**For the full isolation architecture, policy syntax, residual risks, and
security checklist, read
[references/security-deep-dive.md](references/security-deep-dive.md).** This is
mandatory when the user asks about threat model or policy configuration.

---

## Credential Quick Reference

| Provider | Secret Name | Env Var(s) | Auth Method |
|----------|------------|------------|-------------|
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | API key or OAuth |
| OpenAI | `openai` | `OPENAI_API_KEY` | API key (required) |
| GitHub | `github` | `GH_TOKEN`, `GITHUB_TOKEN` | Token |
| Google | `google` | `GEMINI_API_KEY`, `GOOGLE_API_KEY` | API key or interactive sign-in |
| AWS | `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Key pair |

**Scoping:** `sbx secret set -g <provider>` (global, all sandboxes) vs
`sbx secret set <sandbox> <provider>` (per-sandbox).

### Key gotchas

- Global secrets only take effect at sandbox **creation** — recreate sandbox
  after changing a global secret
- `sbx reset` destroys **all** secrets (use `--preserve-secrets` to keep them)
- For arbitrary env vars not covered by `sbx secret`, write to
  `/etc/sandbox-persistent.sh` inside the sandbox

### 1Password CLI (`op`) quick pattern

Keep secrets off disk entirely using `op read` command substitution:

```bash
sbx secret set -g anthropic -t "$(op read -n op://Vault/Anthropic/api-key)"
sbx secret set -g openai -t "$(op read -n op://Vault/OpenAI/api-key)"
sbx secret set -g github -t "$(op read -n op://Vault/GitHub/token)"
```

**For full auth flows, OAuth vs API key details, custom env vars, and complete
1Password `op` CLI integration patterns, read
[references/credential-management.md](references/credential-management.md).**
This is mandatory when the user needs to troubleshoot auth or set up `op`
workflows.

---

## Policy Quick Reference

Three policy templates available at `sbx login` or via `sbx policy set-default`:

| Template | Value | Behavior |
|----------|-------|----------|
| Open | `allow-all` | All outbound allowed |
| Balanced | `balanced` | Deny-default + common dev sites |
| Locked Down | `deny-all` | All blocked; must explicitly allow |

### Common operations

```bash
sbx policy ls                                   # list active rules
sbx policy allow network registry.npmjs.org     # allow a host
sbx policy allow network "*.pypi.org,files.pythonhosted.org"  # wildcards
sbx policy deny network evil.example.com        # deny a host
sbx policy log                                  # view allowed/blocked requests
sbx policy reset                                # wipe all rules, re-prompt
```

**Wildcard rules:** `example.com` does NOT match subdomains; `*.example.com`
does NOT match the root domain. Specify both if needed.

**Deny always wins** — if a domain matches both allow and deny rules, deny
takes precedence regardless of specificity.

---

## Custom Environments Quick Reference

```bash
sbx run shell ~/project                         # bare shell, no agent
sbx run claude --template docker.io/org/img:v1  # custom template
sbx save my-sandbox myimage:v1.0                # snapshot current state
```

Templates use custom Dockerfiles extending base images like
`docker/sandbox-templates:claude-code`. Default images include a Docker daemon
inside the sandbox (`-docker` suffix variants).

**For Dockerfile patterns, base image variants, memory config, and the full
build+push+run workflow, read
[references/custom-environments.md](references/custom-environments.md).** This
is mandatory when the user wants to create custom templates.

---

## Agent Setup Quick Reference

| Agent | Command | Credential | Notes |
|-------|---------|------------|-------|
| Claude Code | `sbx run claude` | `anthropic` or OAuth | Runs with `--dangerously-skip-permissions` |
| Codex | `sbx run codex` | `openai` (required) | No OAuth fallback |
| Copilot | `sbx run copilot` | `github` | Pipe `gh auth token` |
| Gemini | `sbx run gemini` | `google` or interactive | Sign-in is sandbox-scoped |

All agents: user-level config (`~/.claude`, `~/.codex`, etc.) is NOT mounted.
Only project-level config in the workspace is available.

**For per-agent auth details, configuration quirks, and comparison, read
[references/agent-setup.md](references/agent-setup.md).** This is mandatory when
the user needs agent-specific guidance.

---

## CLI Quick Reference

| Command | Purpose | Key Flags |
|---------|---------|-----------|
| `sbx run` | Create + attach | `--branch`, `-m`, `--name`, `-t` |
| `sbx create` | Create (background) | `--branch`, `-m`, `--name`, `-t`, `-q` |
| `sbx exec` | Run command inside | `-it`, `-d`, `-e`, `-u`, `-w` |
| `sbx ls` | List sandboxes | `--json`, `-q` |
| `sbx stop` | Pause (state preserved) | — |
| `sbx rm` | Permanent delete | `--all`, `-f` |
| `sbx reset` | Nuclear reset | `--preserve-secrets`, `-f` |
| `sbx save` | Snapshot as template | `-o` (tar output) |
| `sbx ports` | Port forwarding | `--publish`, `--unpublish`, `--json` |
| `sbx policy` | Network policy mgmt | `allow`, `deny`, `log`, `ls`, `reset`, `rm` |
| `sbx secret` | Credential mgmt | `set`, `ls`, `rm`, `-g`, `-t` |
| `sbx login` | Authenticate | — |

**For complete flag reference, usage examples, and behavioral notes for every
subcommand, read [references/cli-reference.md](references/cli-reference.md).**

---

## Project Documentation

When helping a user set up Docker Sandboxes for a project, **document the
configuration in the project itself**. Create or update a project-level doc
(e.g., `docs/sandbox-setup.md` or a section in the project's `CONTRIBUTING.md`)
covering:

1. **Which agent and template** the project uses (`sbx run claude`, custom
   template, memory/docker-size overrides)
2. **Credential management** — full usage instructions for setting up secrets:
   - List every provider the project needs (e.g., `anthropic`, `github`) and
     whether each should be global (`-g`) or per-sandbox scoped
   - **With 1Password (`op`)**: provide exact `op://` reference paths and the
     corresponding `sbx secret set` commands:
     ```
     sbx secret set -g anthropic -t "$(op read -n 'op://Vault/Anthropic/credential')"
     sbx secret set my-sandbox github -t "$(op read -n 'op://Vault/GitHub/narrow-token')"
     ```
   - **Without 1Password**: provide the interactive commands and note which
     tokens/keys are needed (without including actual values):
     ```
     sbx secret set -g anthropic       # paste your Anthropic API key when prompted
     sbx secret set -g github -t "$(gh auth token)"
     ```
   - Document any per-sandbox overrides (e.g., a narrower-scoped GitHub token
     for a specific project) and the change workflow: stop → set → restart
   - Note the creation-time gotcha: global secrets require sandbox recreation,
     not just restart
   - If the project warrants it, include a bulk setup script
     (`sbx-secrets-setup.sh`) that contributors can run in one command
3. **Network policy** — any hosts that must be explicitly allowed beyond the
   default policy (e.g., private registries, internal APIs)
4. **Port forwarding** — any services the sandbox exposes and their expected
   mappings
5. **Branch mode convention** — whether the project uses `--branch` and what
   `.gitignore` entries are needed (`.sbx/`)
6. **Post-session checklist** — remind contributors to check `.git/hooks/`,
   `git diff`, and CI config changes after each sandbox session

This documentation ensures any team member (or future Claude instance) can
reproduce the sandbox environment without tribal knowledge.

---

## Rancher Desktop Compatibility

Docker Desktop is **not** required. The `sbx` CLI works standalone — install via
`brew install docker/tap/sbx`. The `docker sandbox` subcommand (Docker Desktop
only) is a separate, more limited interface not covered by this skill.

If using Rancher Desktop, the `sbx` CLI operates independently of your container
runtime. The sandbox's internal Docker daemon is isolated and does not interact
with your host Docker/containerd.
