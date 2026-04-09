# Docker Sandbox Security & Isolation Deep-Dive

## Table of Contents

- [Isolation Architecture](#isolation-architecture)
  - [Hypervisor Layer](#hypervisor-layer)
  - [Network Proxy Layer](#network-proxy-layer)
  - [Docker Engine Isolation](#docker-engine-isolation)
  - [Credential Proxying](#credential-proxying)
- [Network Policy Model](#network-policy-model)
  - [Policy Templates](#policy-templates)
  - [Policy Rule Commands](#policy-rule-commands)
  - [Wildcard Behavior](#wildcard-behavior)
  - [Debugging Connectivity](#debugging-connectivity)
- [Residual Risks](#residual-risks)
  - [Workspace Modification](#workspace-modification)
  - [Branch Mode Is Not a Security Boundary](#branch-mode-is-not-a-security-boundary)
  - [Host Config Not Mounted](#host-config-not-mounted)
  - [Exfiltration via Allowed Destinations](#exfiltration-via-allowed-destinations)
  - [No File Integrity Monitoring](#no-file-integrity-monitoring)
- [Post-Session Security Checklist](#post-session-security-checklist)

## Isolation Architecture

Docker Sandboxes enforce isolation through four independent layers. Each layer addresses a different class of threat, and together they form a defense-in-depth model around untrusted agent execution.

### Hypervisor Layer

Each sandbox runs in its own microVM with a dedicated Linux kernel. This is the primary security control.

Key properties:

- Processes inside the sandbox are invisible to the host. The host cannot `ps` them, and they cannot see host processes.
- The hypervisor boundary is the security control, not in-VM privilege separation. In-VM root/sudo is expected and by design.
- Agents have sudo/root inside the sandbox. This is intentional. The microVM boundary prevents privilege from escaping to the host.
- MicroVMs are fundamentally different from containers. Containers share the host kernel and rely on namespaces/cgroups for isolation. MicroVMs run a separate kernel, so a kernel exploit inside the sandbox does not compromise the host kernel.

```text
+------------------+     +------------------+
|   Sandbox VM     |     |   Sandbox VM     |
|  (own kernel)    |     |  (own kernel)    |
|  agent has root  |     |  agent has root  |
+--------+---------+     +--------+---------+
         |                        |
    +----+------------------------+----+
    |         Hypervisor               |
    +----------------------------------+
    |           Host OS                |
    +----------------------------------+
```

### Network Proxy Layer

All HTTP and HTTPS traffic from the sandbox is routed through a host-side proxy. No other protocols are permitted.

Key properties:

- Only HTTP and HTTPS traffic is allowed. Raw TCP, UDP, and ICMP are blocked.
- DNS resolution goes through the proxy.
- The proxy enforces network policies (allow/deny rules per host).
- The proxy injects credential headers into outbound API requests (see Credential Proxying below).
- There is no way for the agent to bypass the proxy from inside the sandbox. Non-HTTP protocols simply have no path out.

What this means in practice:

- An agent cannot open a raw TCP socket to exfiltrate data over a custom protocol.
- An agent cannot ping external hosts or use ICMP-based tunneling.
- SSH, FTP, and other non-HTTP protocols are blocked. If the agent needs to interact with a Git remote, it must use HTTPS, not SSH.
- WebSocket connections are permitted since they upgrade from HTTP, but they still go through the proxy and are subject to network policies.

### Docker Engine Isolation

Sandboxes that include Docker (the `-docker` image variants) run their own isolated Docker daemon.

Key properties:

- Each sandbox has its own Docker daemon, completely separate from the host Docker daemon.
- The sandbox Docker daemon cannot access host containers, images, volumes, or networks.
- Containers built inside the sandbox are confined to the sandbox VM.
- `DOCKER_SANDBOXES_DOCKER_SIZE` controls disk allocation for the inner Docker daemon (default 8192 MB).

```text
+-------------------------------+
|         Sandbox VM            |
|  +-------------------------+  |
|  | Inner Docker daemon     |  |
|  | (isolated from host)    |  |
|  |  +-------+ +-------+   |  |
|  |  | ctr A | | ctr B |   |  |
|  |  +-------+ +-------+   |  |
|  +-------------------------+  |
+-------------------------------+
         |
    [ Hypervisor ]
         |
+-------------------------------+
|         Host OS               |
|  +-------------------------+  |
|  | Host Docker daemon      |  |
|  | (no shared state)       |  |
|  +-------------------------+  |
+-------------------------------+
```

### Credential Proxying

Secrets never enter the sandbox VM. The host-side proxy intercepts outbound API requests and injects the appropriate auth headers.

Key properties:

- Secrets are stored in the host OS keychain.
- The proxy matches outbound requests to configured credentials and injects headers automatically.
- The agent inside the sandbox does not have access to raw credential values. It sends requests without auth, and the proxy adds auth before forwarding.
- Credentials are scoped: global (`-g` flag on `sbx credential add`) or per-sandbox.
- If the agent attempts to read credentials from environment variables or files inside the VM, it will find nothing. The credentials exist only on the host side.

```text
Agent (in VM) --[ unauthenticated request ]--> Proxy (on host)
Proxy: matches request to credential, injects header
Proxy --[ authenticated request ]--> External API
```

Why this matters:

- Even if an agent is compromised or behaves maliciously, it cannot extract API keys, tokens, or passwords. The secrets literally do not exist inside the VM.
- If the agent logs all environment variables or dumps `/proc/*/environ`, no credentials will appear.
- Credential injection is transparent to the agent. The agent makes a normal HTTP request (e.g., to `api.github.com`), and the proxy adds the `Authorization` header before forwarding. The agent does not need to know which credential is used.
- Removing a credential from the host keychain immediately stops the proxy from injecting it. No sandbox restart is needed.

## Network Policy Model

### Policy Templates

Network policy templates are selected at `sbx login` or changed later with `sbx policy set-default`. They control the default posture for outbound HTTP/HTTPS.

| Template | Value | Behavior |
|----------|-------|----------|
| Open | `allow-all` | All outbound HTTP/HTTPS is allowed |
| Balanced | `balanced` | Deny-by-default with common dev sites pre-allowed (npm, PyPI, GitHub, Docker Hub, etc.) |
| Locked Down | `deny-all` | All outbound traffic blocked; each host must be explicitly allowed |

### Policy Rule Commands

```bash
# Allow outbound to specific hosts (comma-separated)
sbx policy allow network github.com,api.github.com

# Deny outbound to specific hosts
sbx policy deny network evil.example.com

# List all active rules
sbx policy ls

# View request log (allowed and blocked)
sbx policy log

# Reset all rules and re-prompt for default template
sbx policy reset
```

### Wildcard Behavior

Wildcards match subdomains but NOT the bare domain:

- `*.example.com` matches `api.example.com`, `cdn.example.com`, etc.
- `*.example.com` does NOT match `example.com` itself.

To allow both a domain and all its subdomains, specify both:

```bash
sbx policy allow network example.com,*.example.com
```

### Debugging Connectivity

When the agent reports network errors, the policy log is the first place to check:

```bash
# Show allowed and blocked requests
sbx policy log

# Check current rules
sbx policy ls
```

The log shows every request the proxy handled, including which rule matched and whether it was allowed or denied.

**Deny always beats allow.** If a domain matches both an allow rule and a deny rule, the deny rule wins regardless of specificity or the order in which rules were added. There is no way to override a deny with a more-specific allow.

## Residual Risks

This section covers what the sandbox does NOT protect against. These are the primary attack surfaces that remain even with all four isolation layers active.

### Workspace Modification

The workspace mount is the primary attack surface. The agent has full read/write access to every file in the mounted workspace directory. This means the agent can modify files that will later execute on the host.

High-risk targets:

- **Git hooks** (`.git/hooks/`) -- An agent can install hooks that execute on your host when you run `git commit`, `git push`, `git checkout`, etc. Git hooks are invisible to `git diff` and `git status`. You must check `.git/hooks/` manually.
- **CI/CD configs** (`.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`) -- An agent can modify CI pipelines to run arbitrary code in your CI environment.
- **IDE task files** (`.vscode/tasks.json`, `.idea/runConfigurations/`) -- An agent can add auto-run tasks that execute when you open the project in your IDE.
- **Build scripts** (`Makefile`, `Justfile`, `package.json` scripts, `build.gradle`) -- An agent can modify build commands to include malicious steps.
- **Dependency manifests** (`package.json`, `Cargo.toml`, `requirements.txt`, `Gemfile`, `go.mod`) -- An agent can add malicious dependencies that execute code at install time.
- **Shell configs** (`.envrc`, `.tool-versions`, `.node-version`) -- An agent can modify files that tools like `direnv` auto-source when you enter the directory.

### Branch Mode Is Not a Security Boundary

The `--branch` flag is documented as a convenience feature only. It creates a git worktree, which is just another filesystem view of the same repository. Branch mode does NOT add any isolation beyond what the workspace mount already provides.

Specifically:

- The worktree shares the same `.git` directory as the main checkout. Hooks installed in the worktree's `.git/hooks/` affect the worktree, but the agent can also modify the shared `.git` directory.
- Changes made on the branch are trivially mergeable into any other branch. Branch mode provides a workflow convenience (easy `git diff` of the agent's changes), not a security control.
- Do not rely on `--branch` to contain untrusted agent behavior. The same post-session checklist applies regardless of whether branch mode was used.

### Host Config Not Mounted

Only the project workspace directory is mounted into the sandbox. `~/.claude` and other user-level agent configuration directories remain on the host and are not accessible to the agent. This is a deliberate design choice that prevents the agent from modifying your global Claude Code configuration.

### Exfiltration via Allowed Destinations

The network proxy controls which hosts the agent can reach, but it does not inspect or restrict the content of requests to allowed hosts. If a host is allowed by network policy, the agent can send any data to it. This includes:

- Source code exfiltration to an allowed API endpoint
- Sensitive data sent as query parameters, headers, or request bodies
- Encoding data in DNS queries (though DNS goes through the proxy, the proxy does not inspect DNS payload content beyond resolution)

The only mitigation is to restrict the allow list to the minimum set of hosts required.

### No File Integrity Monitoring

The sandbox does not track which files were created, modified, or deleted during a session. There is no built-in diff, audit log, or integrity check. You must use standard git tools to review changes after each session.

This gap is particularly relevant for:

- Files outside of git tracking (untracked files, `.gitignore`'d paths) -- these will not appear in `git diff` or `git status`.
- Binary files that git does not diff well by default.
- Symlinks created by the agent that point to unexpected locations within the workspace.

## Post-Session Security Checklist

Run these checks after every sandbox session, especially when the agent had write access to a workspace:

```bash
# Check for modified or newly created git hooks
ls -la .git/hooks/

# Review all uncommitted changes
git diff

# Review staged changes
git diff --cached

# Look for modified CI/CD configs, Dockerfiles, or build files
git diff --name-only | grep -E '\.(github|gitlab|circleci)|Makefile|Justfile|Dockerfile'

# Check for dependency manifest changes
git diff --name-only | grep -E 'package\.json|Cargo\.toml|requirements\.txt|Gemfile|go\.mod|go\.sum'

# Check for new or modified hidden files (excluding .git internals)
find . -name '.*' -newer .git/index -not -path './.git/*'

# Check for new shell hook files that direnv or similar tools auto-source
ls -la .envrc .tool-versions .node-version .ruby-version 2>/dev/null

# If using VS Code, check for task file modifications
git diff --name-only | grep -E '\.vscode/|\.idea/'
```

Review every change before committing. Pay special attention to files that execute automatically (hooks, CI configs, IDE tasks, dependency install scripts).
