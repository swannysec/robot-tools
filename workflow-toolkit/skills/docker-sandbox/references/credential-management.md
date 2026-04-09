# Credential Management

## Table of Contents

- [How Credential Proxying Works](#how-credential-proxying-works)
- [Provider Reference](#provider-reference)
- [Setting Secrets](#setting-secrets)
- [Scoping: Global vs Per-Sandbox](#scoping-global-vs-per-sandbox)
- [OAuth vs API Key Flows](#oauth-vs-api-key-flows)
- [Custom Environment Variables](#custom-environment-variables)
- [1Password CLI Integration](#1password-cli-integration)
- [Critical Gotchas](#critical-gotchas)

## How Credential Proxying Works

Secrets are stored in the host OS keychain via `sbx secret set`. They never enter the sandbox VM directly. Instead, a host-side proxy intercepts outbound API requests from the sandbox and injects the appropriate auth headers (e.g., `Authorization: Bearer ...`) into requests before they reach the provider.

The agent running inside the sandbox never sees the actual API key value. It makes standard HTTP requests to provider APIs, and the proxy transparently authenticates them on the way out.

Flow:

1. You store a secret on the host via `sbx secret set`
2. The secret is saved in the host OS keychain
3. When the agent makes an API call, the host-side proxy intercepts it
4. The proxy injects the stored credential into the request headers
5. The authenticated request reaches the provider API
6. Raw credential values never enter the sandbox VM

## Provider Reference

| Provider | Secret Name | Env Var(s) Injected | Auth Method |
|----------|------------|---------------------|-------------|
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` | API key or OAuth |
| OpenAI | `openai` | `OPENAI_API_KEY` | API key (required, no OAuth fallback) |
| GitHub | `github` | `GH_TOKEN`, `GITHUB_TOKEN` | Token (pipe from `gh auth token`) |
| Google | `google` | `GEMINI_API_KEY`, `GOOGLE_API_KEY` | API key or interactive sign-in |
| AWS | `aws` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Key pair |

Additional providers (`cursor`, `groq`, `mistral`, `nebius`, `xai`) are
supported by `sbx secret set` but not covered in this skill. See official docs.

## Setting Secrets

```bash
# Global secrets (apply to ALL future sandboxes)
sbx secret set -g anthropic           # prompts for value interactively
sbx secret set -g openai              # prompts for value
sbx secret set -g github -t "$(gh auth token)"  # pass token directly

# Per-sandbox secrets (override globals for one sandbox)
sbx secret set my-sandbox anthropic   # prompts for value
sbx secret set my-sandbox github -t "$(gh auth token)"

# List stored secrets
sbx secret ls

# Remove a secret
sbx secret rm anthropic
```

The `-t` flag passes the secret value directly, bypassing the interactive prompt. This is useful for scripting and for piping values from other tools.

## Scoping: Global vs Per-Sandbox

- **`-g` / `--global`**: Secret applies to all sandboxes created after it is set.
- **Without `-g`**: Secret applies only to the named sandbox.
- Per-sandbox secrets override global secrets for the same provider.

**Critical gotcha: Global secrets only take effect at sandbox creation time.** If you change a global secret, you must recreate the sandbox for it to take effect. Simply stopping and restarting the sandbox is NOT enough. The secret values are baked into the sandbox's proxy configuration when the sandbox is first created.

### Changing a Secret on an Existing Sandbox

To change a per-sandbox secret (e.g., swapping a broad GitHub token for a
narrower project-scoped one):

```bash
sbx stop my-sandbox                                    # stop the sandbox
sbx secret set my-sandbox github -t "$(op read -n 'op://Dev/GitHub/narrow-token')"
sbx run my-sandbox                                     # restart — picks up new secret
```

To change a global secret, you must **recreate** (not just restart):

```bash
sbx secret set -g github -t "$(op read -n 'op://Dev/GitHub/new-token')"
sbx rm my-sandbox                                      # delete existing
sbx run claude --name my-sandbox ~/project             # recreate with new global
```

**When to use per-sandbox vs re-set global:**
- **Per-sandbox override**: One project needs a different token (narrower scope, different account). Other sandboxes keep the global.
- **Re-set global**: The old token was rotated/revoked. All sandboxes need the new value. Re-run your setup script, then recreate sandboxes.

## OAuth vs API Key Flows

### Anthropic

Supports both OAuth and API key. If no API key secret is set, Claude Code will attempt an OAuth flow that launches a browser-based auth. For headless or automated use, set the API key via `sbx secret set -g anthropic`.

### OpenAI

API key ONLY. There is no OAuth fallback. You must run `sbx secret set -g openai` before creating a Codex sandbox. Without this, the sandbox will fail to authenticate.

### GitHub

Token-based. Best practice is to pipe from the GitHub CLI:

```bash
sbx secret set -g github -t "$(gh auth token)"
```

This ensures the token stays in sync with your `gh` authentication state.

### Google / Gemini

Supports API key OR interactive sign-in. Interactive sign-in is sandbox-scoped and must be redone for each new sandbox. For automation, use the API key method via `sbx secret set -g google`.

### AWS

Key pair authentication. Both the access key ID and secret access key must be provided.

## Custom Environment Variables

For env vars not covered by `sbx secret` (e.g., custom API endpoints, feature flags, internal service tokens):

```bash
# Write to persistent env file inside sandbox
sbx exec -it my-sandbox bash -c 'echo "export MY_VAR=value" >> /etc/sandbox-persistent.sh'

# Verify
sbx exec -it my-sandbox bash -c 'source /etc/sandbox-persistent.sh && echo $MY_VAR'
```

Key details:

- `/etc/sandbox-persistent.sh` survives sandbox stop/restart cycles
- Variables set here are available to all processes in the sandbox
- This is the only mechanism for custom env vars -- `sbx secret` only covers the built-in providers listed in the provider reference table
- For sensitive custom values, combine with the 1Password `op read` pattern described below to avoid writing plaintext values in shell history

## 1Password CLI Integration

Use the 1Password CLI (`op`) to keep secrets entirely off disk. No plaintext API keys in shell history, dotfiles, or environment variables on the host.

### Prerequisites

- 1Password CLI installed (`brew install 1password-cli` on macOS)
- 1Password desktop app connected to CLI, OR `op signin` completed
- Secrets stored in a 1Password vault with known item/field paths

### Core Pattern: `op read` for Command Substitution

Use `op read -n` (no-newline) with `op://` secret references to inject secrets directly into `sbx secret set`:

```bash
# Set Anthropic API key from 1Password
sbx secret set -g anthropic -t "$(op read -n 'op://Vault/Anthropic API Key/credential')"

# Set OpenAI API key from 1Password
sbx secret set -g openai -t "$(op read -n 'op://Vault/OpenAI API Key/credential')"

# Set GitHub token from 1Password
sbx secret set -g github -t "$(op read -n 'op://Vault/GitHub Token/token')"

# Set Google/Gemini API key from 1Password
sbx secret set -g google -t "$(op read -n 'op://Vault/Google API Key/credential')"

# Set AWS credentials from 1Password
sbx secret set -g aws -t "$(op read -n 'op://Vault/AWS/access-key-id'):$(op read -n 'op://Vault/AWS/secret-access-key')"
```

### How `op://` References Work

- Format: `op://<vault>/<item>/<field>`
- `<vault>`: Name or ID of your 1Password vault
- `<item>`: Name or ID of the item containing the secret
- `<field>`: Field name within the item (e.g., `credential`, `password`, `token`, or a custom field)
- The `-n` flag on `op read` suppresses the trailing newline, which is important for clean token injection
- The secret is resolved at command execution time, piped directly to `sbx secret set`, and stored in the OS keychain. It never touches disk in plaintext.

### Shell Script Pattern for Bulk Setup

For repeated setup (e.g., after `sbx reset --preserve-secrets` or on a new machine), create a script:

```bash
#!/bin/bash
# sbx-secrets-setup.sh — load all secrets from 1Password into sbx
# Run: bash sbx-secrets-setup.sh

set -euo pipefail

echo "Loading secrets from 1Password into sbx..."

sbx secret set -g anthropic -t "$(op read -n 'op://Dev/Anthropic/credential')"
echo "  Anthropic set"

sbx secret set -g openai -t "$(op read -n 'op://Dev/OpenAI/credential')"
echo "  OpenAI set"

sbx secret set -g github -t "$(op read -n 'op://Dev/GitHub/token')"
echo "  GitHub set"

sbx secret set -g google -t "$(op read -n 'op://Dev/Google/credential')"
echo "  Google set"

echo "All secrets loaded. Recreate sandboxes to pick up changes."
```

Adjust the `op://` paths to match your vault and item names.

### `op run` for Environment Injection (Alternative)

If you need to run `sbx` commands in an environment where specific env vars are populated from 1Password:

```bash
# op run injects env vars for the duration of the command
op run --env-file=sbx.env -- sbx create claude ~/project
```

Where `sbx.env` contains:

```text
ANTHROPIC_API_KEY=op://Dev/Anthropic/credential
```

This pattern is less common with `sbx` because `sbx secret set` is the preferred way to manage credentials. Use `op run` only when you need env vars that `sbx secret` does not cover.

### Security Benefits of `op` + `sbx`

1. **No plaintext on disk** -- secrets are never written to dotfiles, shell history, or env files on the host
2. **Double proxying** -- 1Password resolves the secret, `sbx secret set` stores it in the OS keychain, and the sbx proxy injects it into sandbox requests. The actual key value exists only transiently in memory.
3. **Vault-level access control** -- 1Password vaults can restrict which team members can read which secrets
4. **Rotation** -- when you rotate a key in 1Password, re-run the `sbx secret set` command. No files to update.
5. **Auditability** -- 1Password logs secret access events

## Critical Gotchas

- **`sbx reset` destroys ALL secrets** unless `--preserve-secrets` is used. Always pass `--preserve-secrets` if you want to keep credential configuration intact.
- **User-level agent config is NOT mounted** -- `~/.claude`, `~/.codex`, and other user-level agent config directories are not available inside sandboxes. Only project-level config in the workspace is accessible.
- **Auth failure debugging checklist**: If an agent reports authentication failures, verify:
  1. Secret exists: run `sbx secret ls` and confirm the provider appears
  2. Network policy: confirm the target API endpoint is allowed by the sandbox network policy
  3. Creation timing: if using a global secret, confirm the sandbox was created AFTER the secret was set (recreate if needed)
- **Shell history exposure**: When using `-t` with a literal value (not `op read` or `gh auth token`), the secret may appear in shell history. Use `op read` or another command-substitution approach to avoid this.
