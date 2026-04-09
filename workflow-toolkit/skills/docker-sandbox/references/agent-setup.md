# Agent Setup

## Table of Contents

- [Claude Code](#claude-code)
- [Codex (OpenAI)](#codex-openai)
- [Copilot (GitHub)](#copilot-github)
- [Gemini (Google)](#gemini-google)
- [Shell (No Agent)](#shell-no-agent)
- [Agent Comparison](#agent-comparison)
- [Common Cross-Agent Notes](#common-cross-agent-notes)
- [Agents Not Covered](#agents-not-covered)

## Claude Code

### Launch

```bash
sbx run claude ~/project
```

### Authentication

- **API key**: `sbx secret set -g anthropic` (or use `-t` to pass the value directly)
- **OAuth**: If no API key secret is set, Claude Code will attempt an OAuth flow via browser-based auth
- **Recommended**: API key via `sbx secret set` for headless and automated use

### Behavior Inside Sandbox

- Runs with `--dangerously-skip-permissions` by default -- full autonomous mode
- Has sudo/root access inside the sandbox (by design -- the microVM is the security boundary)
- `~/.claude` is NOT mounted -- only project-level config (`.claude/` in workspace) is available
- Can install packages, modify files, and run arbitrary commands within the sandbox
- CLAUDE.md and project-level settings from the workspace ARE available

### Configuration

- Project-level `.claude/` directory and `CLAUDE.md` in the workspace are available inside the sandbox
- User-level config (`~/.claude/settings.json`, `~/.claude/CLAUDE.md`) is NOT available
- To use user-level settings inside a sandbox, either:
  - Add them to the project-level config (`.claude/` directory or `CLAUDE.md` in the workspace)
  - Build a custom template that includes them

## Codex (OpenAI)

### Launch

```bash
sbx run codex ~/project
```

### Authentication

- **API key ONLY** -- `sbx secret set -g openai` is required before creating the sandbox
- No OAuth fallback -- the sandbox will fail to authenticate without an API key
- Must set the secret BEFORE creating the sandbox (global secrets are baked in at creation time)

### Behavior Inside Sandbox

- Runs in autonomous mode within the sandbox
- Has sudo/root access
- `~/.codex` is NOT mounted

### Configuration

- Project-level config only
- Codex configuration files present in the workspace directory are available

## Copilot (GitHub)

### Launch

```bash
sbx run copilot ~/project
```

### Authentication

- **GitHub token**: `sbx secret set -g github -t "$(gh auth token)"`
- Pipes the token from the GitHub CLI (`gh`)
- Must have appropriate GitHub permissions for the repos being accessed

### Behavior Inside Sandbox

- Runs with GitHub authentication
- Has sudo/root access

### Configuration

- Project-level config only
- `~/.config/github-copilot` is NOT mounted

## Gemini (Google)

### Launch

```bash
sbx run gemini ~/project
```

### Authentication

- **API key**: `sbx secret set -g google`
- **Interactive sign-in**: If no API key is set, Gemini will prompt for Google sign-in inside the sandbox
- Interactive sign-in is sandbox-scoped -- must redo for each new sandbox
- **Recommended**: API key for automation and reproducibility

### Behavior Inside Sandbox

- Has sudo/root access
- Can access Google APIs via the authenticated credential

### Configuration

- Project-level config only

## Shell (No Agent)

### Launch

```bash
sbx run shell ~/project
```

### Purpose

- No agent pre-installed -- bare Linux environment
- Use for manual exploration, custom toolchains, or agents not directly supported by `sbx`
- Same isolation model (microVM, network policy, credential proxying) as agent sandboxes
- Install any agent manually inside the sandbox if needed

### Example Use Cases

- Testing shell scripts in an isolated environment
- Running a custom agent binary or script
- Debugging network policy or credential configuration without agent interference
- Experimenting with tools before committing to an agent-specific sandbox

## Agent Comparison

| Feature | Claude Code | Codex | Copilot | Gemini |
|---------|------------|-------|---------|--------|
| Auth method | API key or OAuth | API key only | GitHub token | API key or sign-in |
| OAuth fallback | Yes | No | N/A | Interactive sign-in |
| Secret name | `anthropic` | `openai` | `github` | `google` |
| Auto mode | `--dangerously-skip-permissions` | Autonomous | Standard | Standard |
| User config mounted | No | No | No | No |
| Project config | Yes (`.claude/`, `CLAUDE.md`) | Yes | Yes | Yes |

### Reading the Table

- **Auth method**: How the agent authenticates with its provider API.
- **OAuth fallback**: Whether the agent can fall back to an interactive OAuth/sign-in flow if no API key is set.
- **Secret name**: The name used with `sbx secret set -g <name>` for this agent's provider.
- **Auto mode**: How the agent operates autonomously inside the sandbox.
- **User config mounted**: Whether user-level config directories from the host are available. Always "No" for all agents.
- **Project config**: Whether project-level config from the mounted workspace is available. Always "Yes" for all agents.

## Common Cross-Agent Notes

### Root Access is by Design

ALL agents have sudo/root access inside the sandbox. This is intentional, not a security issue. The microVM itself is the security boundary -- the agent can do anything it wants inside the VM without affecting the host.

### User Config is Never Mounted

User-level config directories (`~/.claude`, `~/.codex`, `~/.config/github-copilot`, etc.) are NEVER mounted into sandboxes. Only project-level config from the mounted workspace is available.

If you need user-level settings inside a sandbox:
- Copy the relevant settings into the project's config directory
- Build a custom sandbox template that includes them
- Manually copy them in after sandbox creation via `sbx exec`

### Global Secrets and Sandbox Creation Timing

Global secrets are injected into the sandbox at creation time only. If you add or change a global secret after a sandbox already exists:
1. The existing sandbox will NOT pick up the change
2. You must destroy and recreate the sandbox
3. Simply stopping and starting the sandbox is NOT sufficient

### Network Policy Applies Equally

Network policy (allowed/blocked endpoints) is enforced at the sandbox level and applies identically to all agents. An agent cannot bypass network restrictions regardless of its provider.

### Workspace Mounting

The project directory passed to `sbx run` is mounted into the sandbox as the working directory. Changes made by the agent to files in this directory are reflected on the host. This is bidirectional -- changes on the host also appear inside the sandbox.

### Stopping vs Destroying

- **`sbx stop`**: Pauses the sandbox. State is preserved. Restart with `sbx start`.
- **`sbx rm`**: Destroys the sandbox. All state inside the VM is lost.
- Credentials persist in the host keychain regardless of sandbox lifecycle (unless `sbx reset` is used without `--preserve-secrets`).

## Agents Not Covered

Docker Agent, Kiro, and OpenCode are supported by Docker Sandboxes but are not covered in detail here. See the official Docker documentation at https://docs.docker.com/ai/sandboxes/ for setup guidance on these agents.
