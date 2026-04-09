# sbx CLI Reference

## Table of Contents

- [sbx run](#sbx-run)
- [sbx create](#sbx-create)
- [sbx exec](#sbx-exec)
- [sbx ls](#sbx-ls)
- [sbx stop](#sbx-stop)
- [sbx rm](#sbx-rm)
- [sbx reset](#sbx-reset)
- [sbx save](#sbx-save)
- [sbx ports](#sbx-ports)
- [sbx policy](#sbx-policy)
- [sbx secret](#sbx-secret)
- [sbx login](#sbx-login)
- [sbx (TUI Dashboard)](#sbx-tui-dashboard)

## sbx run

Create and attach to a sandbox. If the named sandbox already exists, reconnects to it.

```text
sbx run [OPTIONS] <AGENT|SANDBOX_NAME> [WORKSPACE...]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--branch <NAME\|auto>` | Create a git worktree for the sandbox. `auto` generates a branch name. | None |
| `-m <SIZE>` | Memory limit in binary units (e.g., `1024m`, `8g`). | 50% of host memory, max 32 GiB |
| `--name <NAME>` | Explicit sandbox name. If omitted, a name is generated. | `<agent>-<workdir>` |
| `-t <IMAGE>` / `--template <IMAGE>` | Custom template image. Must be a fully qualified registry path. | Agent-specific default image |

### Agents

Available agent values: `claude`, `codex`, `copilot`, `gemini`, `shell`.

Other agents exist (`docker-agent`, `kiro`, `opencode`) but are not covered by
this skill — see official docs.

### Workspace Arguments

- The first path is the primary workspace, mounted read-write inside the sandbox.
- Additional paths are mounted at their host absolute path.
- Append `:ro` to any path to mount it read-only.

### Reconnecting

Pass an existing sandbox name instead of an agent to reconnect:

```bash
sbx run my-sandbox
```

### Examples

```bash
# Start a Claude sandbox with the current directory as workspace
sbx run claude ~/projects/myapp

# Start with 8 GiB memory and a custom name
sbx run claude -m 8g --name my-feature ~/projects/myapp

# Create a worktree branch automatically
sbx run claude --branch auto ~/projects/myapp

# Mount multiple workspaces, second one read-only
sbx run claude ~/projects/myapp ~/shared/configs:ro

# Use a custom template image
sbx run claude -t docker.io/myorg/custom-sandbox:latest ~/projects/myapp
```

## sbx create

Create a sandbox without attaching to it. Useful for background or batch creation.

```text
sbx create [OPTIONS] <AGENT> [WORKSPACE...]
```

### Flags

All flags from `sbx run` apply, plus:

| Flag | Description | Default |
|------|-------------|---------|
| `-q` / `--quiet` | Output only the sandbox name (no progress output). | Off |

### Examples

```bash
# Create a sandbox in the background
sbx create claude ~/projects/myapp

# Create quietly, capture name in a variable
SANDBOX=$(sbx create -q claude ~/projects/myapp)
```

## sbx exec

Run a command inside a running sandbox.

```text
sbx exec [OPTIONS] <SANDBOX> <COMMAND...>
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-it` | Interactive TTY mode. Required for shells and interactive programs. | Off |
| `-d` | Run command in detached/background mode. | Off |
| `-e KEY=VALUE` | Set an environment variable for the command. Repeatable. | None |
| `-u <USER>` | Run command as the specified user. | Default sandbox user |
| `-w <DIR>` | Set working directory inside the sandbox. | Sandbox default |

### Examples

```bash
# Run a one-off command
sbx exec my-sandbox ls -la /workspace

# Open an interactive shell
sbx exec -it my-sandbox bash

# Run a build in the background
sbx exec -d my-sandbox make build

# Set env vars and working directory
sbx exec -e NODE_ENV=production -w /workspace/app my-sandbox npm start
```

## sbx ls

List sandboxes.

```text
sbx ls [OPTIONS]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--json` | Output in JSON format. | Off |
| `-q` / `--quiet` | Output sandbox IDs only. | Off |

### Output Columns

`NAME`, `AGENT`, `STATUS`, `PORTS`, `WORKSPACE`

### Examples

```bash
# List all sandboxes
sbx ls

# Get JSON output for scripting
sbx ls --json

# Get just sandbox names
sbx ls -q
```

## sbx stop

Stop a running sandbox. State is preserved; the sandbox can be restarted later.

```text
sbx stop <SANDBOX...>
```

- Accepts one or more sandbox names.
- Stopped sandboxes retain their filesystem state.
- Restart a stopped sandbox with `sbx run <name>`.
- Port mappings are lost on stop and must be re-added after restart.

### Examples

```bash
# Stop a single sandbox
sbx stop my-sandbox

# Stop multiple sandboxes
sbx stop sandbox-1 sandbox-2
```

## sbx rm

Remove a sandbox permanently. This is irreversible.

```text
sbx rm [OPTIONS] <SANDBOX...>
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--all` | Remove all sandboxes. | Off |
| `-f` / `--force` | Skip confirmation prompt. | Off |

- Also deletes git worktrees created by `--branch`.
- A sandbox must be stopped before removal, or use `-f` to force.

### Examples

```bash
# Remove a sandbox (prompts for confirmation)
sbx rm my-sandbox

# Force remove without confirmation
sbx rm -f my-sandbox

# Remove all sandboxes
sbx rm --all
```

## sbx reset

Nuclear reset. Destroys all sandboxes, images, and secrets.

```text
sbx reset [OPTIONS]
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--preserve-secrets` | Keep keychain entries intact. Only removes sandboxes and images. | Off |
| `-f` / `--force` | Skip confirmation prompt. | Off |

- Without `--preserve-secrets`, ALL stored secrets are deleted.
- This removes every sandbox, cached image, and (by default) every secret.

### Examples

```bash
# Full nuclear reset (prompts for confirmation)
sbx reset

# Reset but keep credentials
sbx reset --preserve-secrets

# Force reset without prompts
sbx reset -f --preserve-secrets
```

## sbx save

Snapshot a sandbox as a reusable template image.

```text
sbx save [OPTIONS] <SANDBOX> <IMAGE:TAG>
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o <FILE>` / `--output <FILE>` | Save as a tar file instead of loading into host Docker. | Load into host Docker |

- By default, the image is loaded into the host's Docker daemon (requires Docker to be running).
- Use `--output` to save as a tar file instead (works without host Docker).
- Captures the full sandbox state, including all installed packages and modifications.

### Examples

```bash
# Save sandbox as an image loaded into host Docker
sbx save my-sandbox myimage:v1.0

# Save as a local tar file (no host Docker required)
sbx save -o ./my-template.tar my-sandbox myimage:v1.0
```

## sbx ports

Manage port forwarding for a sandbox. Port forwarding is post-hoc only — it can only be configured after the sandbox exists.

```text
sbx ports [OPTIONS] <SANDBOX>
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--publish <SPEC>` | Add a port mapping. Repeatable. | None |
| `--unpublish <SPEC>` | Remove a port mapping. Repeatable. | None |
| `--json` | Output in JSON format. | Off |

Port spec format: `[[HOST_IP:]HOST_PORT:]SANDBOX_PORT[/PROTOCOL]`
- If `HOST_PORT` is omitted, an ephemeral port is allocated automatically.
- `HOST_IP` defaults to `127.0.0.1`.
- `PROTOCOL` defaults to `tcp`. Supported: `tcp`, `tcp4`, `tcp6`, `udp`, `udp4`, `udp6`.

### Key Behaviors

- Services inside the sandbox must bind to `0.0.0.0`, not `127.0.0.1`, to be reachable.
- Port mappings are ephemeral. They are lost when the sandbox is stopped and must be re-added after restart.

### Examples

```bash
# View current port mappings
sbx ports my-sandbox

# Forward host port 8080 to sandbox port 3000
sbx ports --publish 8080:3000 my-sandbox

# Remove a port mapping
sbx ports --unpublish 8080:3000 my-sandbox

# JSON output for scripting
sbx ports --json my-sandbox
```

## sbx policy

Manage network policies controlling sandbox outbound traffic.

### Subcommands

#### sbx policy ls

List active network policy rules.

```bash
sbx policy ls
```

#### sbx policy allow network

Allow outbound traffic to specified hosts.

```bash
sbx policy allow network <HOSTS>
```

- `HOSTS` is a comma-separated list.
- Supports wildcard subdomains: `*.example.com`.

#### sbx policy deny network

Deny outbound traffic to specified hosts.

```bash
sbx policy deny network <HOSTS>
```

#### sbx policy rm

Remove a specific policy rule by ID.

```bash
sbx policy rm <RULE_ID>
```

#### sbx policy log

View a log of allowed and blocked network requests.

```bash
sbx policy log
```

#### sbx policy reset

Wipe all policy rules. Re-prompts for a default policy template.

```bash
sbx policy reset
```

#### sbx policy set-default

Set the default network policy template.

```bash
sbx policy set-default <TEMPLATE>
```

Available templates: `allow-all`, `balanced`, `deny-all`.

### Key Behaviors

- Deny rules always take precedence over allow rules.
- `example.com` does NOT match `*.example.com` -- you must specify both if you need the root domain and all subdomains.
- Wildcard `*.example.com` matches `sub.example.com` but NOT the bare `example.com`.

### Examples

```bash
# Allow PyPI and npm registries
sbx policy allow network "pypi.org,*.pypi.org,registry.npmjs.org"

# Block a specific host
sbx policy deny network "evil.example.com"

# Check what's being blocked
sbx policy log

# Switch to allow-all policy
sbx policy set-default allow-all
```

## sbx secret

Manage credentials injected into sandboxes.

### Subcommands

#### sbx secret set

Set a secret for a specific sandbox or globally.

```bash
sbx secret set [OPTIONS] [SANDBOX] <PROVIDER>
```

Prompts for the secret value interactively unless `-t` is used.

#### sbx secret ls

List all stored secrets.

```bash
sbx secret ls
```

#### sbx secret rm

Remove a stored secret.

```bash
sbx secret rm <PROVIDER>
```

### Flags (for `secret set`)

| Flag | Description | Default |
|------|-------------|---------|
| `-g` / `--global` | Apply the secret to all sandboxes. | Off (per-sandbox) |
| `-t <TOKEN>` / `--token <TOKEN>` | Pass the secret value directly instead of prompting. Useful for piping. Note: visible in shell history. | Interactive prompt |
| `-f` / `--force` | Overwrite an existing secret when `--token` is used. | Off |
| `--oauth` | Start OAuth flow and store OAuth tokens. Currently only supported for `openai` with global scope. | Off |

Secrets can also be set via stdin piping (avoids shell history exposure):

```bash
echo "$ANTHROPIC_API_KEY" | sbx secret set -g anthropic
```

### Providers

`anthropic`, `aws`, `cursor`, `github`, `google`, `groq`, `mistral`, `nebius`,
`openai`, `xai`

This skill covers `anthropic`, `aws`, `github`, `google`, and `openai`. For
other providers, refer to the official docs.

### Key Behaviors

- Global secrets (`-g`) are only injected at sandbox creation time. If you add or change a global secret, you must recreate the sandbox for it to take effect.
- Per-sandbox secrets override global secrets for the same provider.

### Examples

```bash
# Set an Anthropic key globally (prompts for value)
sbx secret set -g anthropic

# Set a GitHub token for a specific sandbox via pipe
echo "ghp_xxxx" | sbx secret set -t "$(cat -)" my-sandbox github

# List stored secrets
sbx secret ls

# Remove a secret
sbx secret rm openai
```

## sbx login

Authenticate with Docker and configure initial network policy.

```text
sbx login
```

- Prompts for default network policy selection on first login.
- Required before pulling or pushing custom template images.

## sbx (TUI Dashboard)

Running `sbx` with no subcommand opens an interactive terminal UI for managing sandboxes.

```bash
sbx
```

The TUI provides a visual overview of all sandboxes with their status, agent, ports, and workspace. Use it for quick interactive management without memorizing subcommands.
