# sbx Troubleshooting Guide

## Table of Contents

- [Common Issues](#common-issues)
- [Network Connectivity Deep Dive](#network-connectivity-deep-dive)
- [Credential Troubleshooting](#credential-troubleshooting)
- [Lifecycle Troubleshooting](#lifecycle-troubleshooting)
- [Diagnostic Commands](#diagnostic-commands)
- [FAQ](#faq)

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Clock drift after host sleep | Sandbox VM clock falls out of sync when host sleeps/hibernates. | `sbx stop <name>` then `sbx run <name>` to restart with fresh clock sync. |
| Port forwarding not working | Service binds to `127.0.0.1` inside sandbox, or ports were never published. | Ensure service binds to `0.0.0.0`. Add mappings with `sbx ports --publish <HOST:SANDBOX> <name>`. Ports are post-hoc only. |
| "sandbox not found" after stop | Stopped sandboxes exist but are not running. Some commands expect a running sandbox. | Run `sbx ls` to check status. Restart with `sbx run <name>`. |
| Agent can't authenticate | Secret not set, or global secret added after sandbox creation. | Check `sbx secret ls`. Global secrets only apply at creation time. Recreate the sandbox after adding or changing global secrets. |
| Network requests blocked | Network policy is denying outbound traffic. | Check active rules with `sbx policy ls`. Inspect `sbx policy log` for blocked domains. Add allows with `sbx policy allow network <hosts>`. |
| Custom template not found | Image path is not fully qualified. | Use the full registry path: `docker.io/org/image:tag`. Run `sbx login` first if pulling from a private registry. |
| First run is very slow | Initial image download is large. | This is expected. Subsequent runs use the cached image and start much faster. |
| Branch mode worktree conflicts | Uncommitted changes in the main working tree are not visible in the worktree. | Commit or stash changes before creating a branch-mode sandbox. Ensure `.sbx/` is in `.gitignore`. |
| `sbx reset` destroyed my secrets | Default behavior of `sbx reset` wipes everything including secrets. | Use `sbx reset --preserve-secrets` to keep keychain entries. There is no recovery for already-deleted secrets. |
| Sandbox won't start | Name collision with an existing sandbox, or leftover state from a failed creation. | Check `sbx ls` for conflicts. Remove the old sandbox with `sbx rm -f <name>` and recreate. |

## Network Connectivity Deep Dive

Only HTTP and HTTPS traffic is proxied through the sandbox network layer. Raw TCP, UDP, ICMP, and SSH are not supported.

- DNS resolution happens through the proxy. If DNS is failing, the proxy itself may be misconfigured or the domain may be blocked by policy.
- The `balanced` default policy blocks most outbound traffic. Use `sbx policy log` to see exactly what is being denied.
- To allow a specific host:

```bash
sbx policy allow network "example.com"
```

- Wildcard matching has a critical gotcha: `*.pypi.org` allows `files.pypi.org` but does NOT match the bare domain `pypi.org`. To cover both, specify them explicitly:

```bash
sbx policy allow network "pypi.org,*.pypi.org"
```

- Deny rules always win over allow rules. If traffic is blocked despite an allow rule, check for a conflicting deny rule with `sbx policy ls`.
- To debug connectivity from inside the sandbox:

```bash
sbx exec -it my-sandbox bash
# Then inside the sandbox:
curl -v https://example.com
```

## Credential Troubleshooting

Start by checking what secrets are currently stored:

```bash
sbx secret ls
```

### Global vs Per-Sandbox Secrets

- Global secrets (set with `-g`) are injected into the sandbox at creation time only. If you add or change a global secret after the sandbox exists, it will not take effect until you recreate the sandbox.
- Per-sandbox secrets override global secrets for the same provider.

### Agent Still Can't Authenticate

The sandbox proxy injects authentication headers into outbound requests. If the agent still fails to authenticate:

1. Verify the secret is set for the correct provider with `sbx secret ls`.
2. Confirm the API endpoint the agent targets is allowed by network policy. A valid secret won't help if the request is blocked.
3. Try removing and re-setting the secret:

```bash
sbx secret rm anthropic
sbx secret set -g anthropic
```

Then recreate the sandbox.

### Custom Environment Variables

For environment variables not covered by the built-in `sbx secret` providers, write them to the persistent environment file inside the sandbox:

```bash
sbx exec -it my-sandbox bash -c 'echo "export MY_VAR=value" >> /etc/sandbox-persistent.sh'
```

This file is sourced on sandbox start and persists across restarts.

## Lifecycle Troubleshooting

### State Preservation

- `sbx stop` preserves all filesystem state. The sandbox can be restarted with `sbx run <name>`.
- `sbx rm` permanently deletes the sandbox and its filesystem. This is irreversible.
- `sbx reset` is nuclear. It removes all sandboxes, all cached images, and (unless `--preserve-secrets` is used) all stored secrets.

### Recovering from a Bad State

If a sandbox is stuck, unresponsive, or in an unknown state:

```bash
# Force remove the broken sandbox
sbx rm -f my-sandbox

# Recreate it
sbx run claude --name my-sandbox ~/projects/myapp
```

### Worktree Cleanup

When a sandbox created with `--branch` is removed via `sbx rm`, the associated git worktree is also deleted. If worktree cleanup fails (e.g., due to a force-killed process), manually clean up:

```bash
git worktree list
git worktree remove <path>
```

## Diagnostic Commands

```bash
# Check sandbox status
sbx ls

# Detailed JSON output for scripting or inspection
sbx ls --json

# View active network policy rules
sbx policy ls

# View log of allowed and blocked network requests
sbx policy log

# View stored credentials (names only, not values)
sbx secret ls

# Shell into a sandbox for manual inspection
sbx exec -it my-sandbox bash

# View current port mappings for a sandbox
sbx ports my-sandbox

# View port mappings as JSON
sbx ports --json my-sandbox
```

## FAQ

### Do I need Docker Desktop?

No. `sbx` is a standalone tool that runs its own microVMs. Install it with:

```bash
brew install docker/tap/sbx
```

It does not depend on Docker Desktop being installed or running.

### Can I use Rancher Desktop or other container runtimes?

Yes. `sbx` operates independently of any container runtime you may have installed. They do not conflict.

### Can I run multiple sandboxes at once?

Yes. Each sandbox runs in its own isolated microVM. You can create and run as many as your system resources allow.

### Is my host filesystem safe?

Only explicitly mounted workspaces are accessible inside the sandbox. However, agents running inside the sandbox CAN modify any file within those mounted workspaces, including git hooks, CI configuration files, and build scripts. Mount sensitive directories as read-only (`:ro`) if modification is a concern.

### Can I SSH into a sandbox?

No. SSH is not supported. Use `sbx exec` instead:

```bash
sbx exec -it my-sandbox bash
```

### Why did my port mapping disappear?

Port mappings are ephemeral and are lost when a sandbox is stopped. After restarting a sandbox, re-add port mappings with:

```bash
sbx ports --publish 8080:3000 my-sandbox
```

### Can agents install packages inside the sandbox?

Yes. Agents have sudo access inside the sandbox and can install packages freely. To preserve a customized environment as a reusable template, use:

```bash
sbx save my-sandbox docker.io/myorg/my-template:v1
```

### How do I increase sandbox memory?

Use the `-m` flag when creating or running a sandbox. The value is in megabytes:

```bash
sbx run claude -m 8192 ~/projects/myapp
```

The default is 4096 MB (4 GB).
