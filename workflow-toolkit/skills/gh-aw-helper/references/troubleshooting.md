# GitHub Agentic Workflows — Troubleshooting Reference

Comprehensive error reference, debugging procedures, and FAQ for GitHub Agentic Workflows (gh-aw).

## Table of Contents

1. [Debugging Workflow](#debugging-workflow)
2. [Installation Issues](#installation-issues)
3. [Enterprise / Organization Issues](#enterprise--organization-issues)
4. [Compilation Errors](#compilation-errors)
5. [Trigger / Schedule Errors](#trigger--schedule-errors)
6. [Permission Errors](#permission-errors)
7. [Strict Mode Errors](#strict-mode-errors)
8. [Tool / MCP Issues](#tool--mcp-issues)
9. [Network Issues](#network-issues)
10. [Engine Issues](#engine-issues)
11. [Context / Expression Issues](#context--expression-issues)
12. [Cache / Memory Issues](#cache--memory-issues)
13. [Lockdown Mode Issues](#lockdown-mode-issues)
14. [PR / Discussion Issues](#pr--discussion-issues)
15. [FAQ](#faq)
16. [Quick Reference: CLI Debugging Commands](#quick-reference-cli-debugging-commands)

---

## Debugging Workflow

### Step-by-step debugging process

1. **Check logs:** `gh aw logs <workflow-name>`
2. **Audit specific run:** `gh aw audit <run-id>`
3. **Inspect MCP config:** `gh aw mcp inspect <workflow>`
4. **Enable verbose:** `gh aw compile --verbose`
5. **Enable Actions debug:** Set repo secret `ACTIONS_STEP_DEBUG = true`
6. **Use Copilot:** `/agent agentic-workflows debug <description>`

---

## Installation Issues

| Problem | Solution |
|---------|----------|
| `gh extension install` fails | Use standalone: `curl -sL https://raw.githubusercontent.com/github/gh-aw/main/install-gh-aw.sh \| bash` |
| "unknown command" after install | Verify: `gh --version`, `gh auth status`, check PATH includes `~/.local/share/gh/extensions` |
| Permission errors | Check `~/.local/share/gh/extensions` is writable |

---

## Enterprise / Organization Issues

### Actions not allowed in enterprise

**Error:** `The action github/gh-aw/actions/setup@... is not allowed`

**Solutions:**
- **Solution 1:** Org Settings → Actions → Allow select actions → add `github/gh-aw@*`
- **Solution 2:** `.github` repo `policies/actions.yml` with `allowed_actions: ["github/gh-aw@*"]`

### Actions restrictions during init

Fix in **Repo Settings → Actions → General:**

1. Actions disabled → **Enable**
2. Local-only → **Allow all or GitHub-created**
3. Selective allowlist → **Enable "Allow actions created by GitHub"**

---

## Compilation Errors

| Error | Cause | Solution |
|-------|-------|---------|
| `frontmatter not properly closed` | Missing closing `---` | Add closing `---` after frontmatter |
| `failed to parse frontmatter` | YAML syntax error | Check indentation (spaces not tabs), colons with spaces, quoted special chars |
| `timeout-minutes must be an integer` | Wrong type | Use `10` not `"10"` |
| `Unknown property: permisions` | Typo (fuzzy matching) | Use suggested spelling |
| `imports field must be an array` | Wrong format | Use `imports: [- shared/tools.md]` array format |
| `multiple agent files found in imports` | More than 1 agent file | Import only one `.github/agents/` file per workflow |
| `workflow file not found` | File missing | Verify file exists in `.github/workflows/` |
| `failed to resolve import` | Import path wrong | Ensure imported file exists, check path (relative to repo root) |
| `invalid workflowspec` | Wrong import format | Use `owner/repo/path[@ref]` format |
| Lock file not generated | Compilation errors | Run `gh aw compile 2>&1 \| grep -i error` |
| Orphaned lock files | Deleted .md but .lock.yml remains | `gh aw compile --purge` |

---

## Trigger / Schedule Errors

| Error | Cause | Solution |
|-------|-------|---------|
| `cannot use 'command' with 'issues'` | Conflicting triggers | Remove event trigger; slash_command handles events automatically. Restrict with `events:` field. Label-only triggers OK. |
| `invalid time delta format` | Wrong stop-after syntax | Use `+25h`, `+7d`, `+1d12h30m`. Min unit: hours (not minutes). |
| `minute unit 'm' is not allowed for stop-after` | Used minutes | Convert to hours: `+2h` not `+90m` |
| `time delta too large` | Exceeds max | Max: 12mo, 52w, 365d, 8760h |
| `duplicate unit` | Repeated unit in delta | Combine: `+3d` not `+1d2d` |

---

## Permission Errors

| Problem | Solution |
|---------|----------|
| Write operations fail | Use safe-outputs, not direct write permissions |
| Safe outputs not creating items | Check if `staged: true` (preview mode) — set `staged: false` |
| Token permission errors | Grant permissions in frontmatter or use custom token via `github-token:` |
| Project field type errors | GitHub Projects reserves names like REPOSITORY. Use alternative names (e.g., `repo`). |

---

## Strict Mode Errors

| Error | Solution |
|-------|----------|
| `strict mode: 'network' configuration is required` | Add `network: defaults` or explicit allowed list or `network: {}` |
| `strict mode: write permission not allowed` | Use safe-outputs instead of direct write permissions |
| `strict mode: wildcard '*' not allowed in network` | Use specific domains, `*.cdn.example.com`, or ecosystem identifiers |
| `strict mode: custom MCP server requires network configuration` | Add network config to containerized MCP servers |
| `strict mode: engine does not support firewall` | Use copilot engine, compile without --strict, or use `network: defaults` |

---

## Tool / MCP Issues

| Problem | Solution |
|---------|----------|
| GitHub tools not available | Configure with `toolsets:` — e.g., `toolsets: [repos, issues]` |
| Toolset missing expected tools | Check docs, combine toolsets (`[default, actions]`), inspect: `gh aw mcp inspect` |
| MCP server connection failure | Verify config (command, args, env). Check secrets are set. |
| Playwright network denied | Add domains: `playwright: { allowed_domains: ["github.com"] }` |
| `Cannot find module 'playwright'` | Don't `require('playwright')` — use MCP tools: `mcp__playwright__browser_navigate()` |
| Playwright EOF error (`initialize: EOF`) | Upgrade to 0.41.0+: `gh extension upgrade gh-aw` |
| `invalid toolset` | Valid: context, repos, issues, pull_requests, users, actions, code_security, discussions, labels, notifications, orgs, projects, gists, search, dependabot, experiments, secret_protection, security_advisories, stargazers, default, all |
| `http MCP tool missing required 'url' field` | Add `url:` to HTTP MCP server config |
| `unable to determine MCP type` | Specify at least one of: type, url, command, or container |
| `cannot specify both 'container' and 'command'` | Use either container OR command, not both |
| `http MCP cannot use 'container'` | Remove `container:` from HTTP MCP configs |
| `repository features not enabled for safe outputs` | Enable feature in Settings → General → Features |

---

## Network Issues

| Problem | Solution |
|---------|----------|
| Firewall denials for packages | Add ecosystem identifiers: `allowed: [defaults, python, node, go]` |
| URLs appearing as "(redacted)" | Add domain to `network: { allowed: [...] }` |
| Cannot download remote imports | Check network (`curl -I https://raw.githubusercontent.com/...`) and auth (`gh auth status`) |
| MCP server connection timeout | Use local servers (`command: "node"` not remote URLs) |

---

## Engine Issues

| Problem | Solution |
|---------|----------|
| Copilot CLI not found | Verify compilation succeeded (includes CLI install steps) |
| Model not available | Use default or specify: `engine: { id: copilot, model: gpt-4 }` |

---

## Context / Expression Issues

| Problem | Solution |
|---------|----------|
| Unauthorized expression | Only allowed: `github.event.*`, `github.actor`, `github.repository`, `needs.*`, `steps.*`. Prohibited: `secrets.*`, `env.*` |
| `needs.activation.outputs.text` empty | Requires issue/PR/comment event trigger, not push |

---

## Cache / Memory Issues

| Problem | Solution |
|---------|----------|
| Cache not restoring | Verify cache key is consistent across runs. Caches expire after 7 days. |
| Cache memory not persisting | Configure: `cache-memory: { key: memory-${{ github.workflow }} }` |
| Repo memory not updating | Check `file-glob` matches files, files within `max-file-size` |
| Merge conflicts in repo memory | Use JSON Lines (append-only), separate branches, add run ID to filenames |

---

## Lockdown Mode Issues

| Problem | Solution |
|---------|----------|
| Workflows can't see external contributions | Lockdown filters to push-access users. Disable with `lockdown: false` only if: workflow validates input, uses restrictive safe outputs, doesn't access secrets. |

---

## PR / Discussion Issues

| Problem | Solution |
|---------|----------|
| `GitHub Actions is not permitted to create or approve pull requests` | Org Setting: Actions → Workflow permissions → Allow. OR use `fallback-as-issue: true` (default). OR use `create-issue: { assignees: [copilot] }`. |
| PRs don't trigger CI checks | Expected — GITHUB_TOKEN PRs don't trigger events. Use PAT/GitHub App or workflow_run trigger. |
| Discussion fails with `integration-forbidden` | Use announcement-capable categories. Check spelling (case-sensitive). Use `fallback-to-issue: true` (default). |

---

## FAQ

### Q: Is this non-deterministic?

**A:** Agentic workflows are 100% additive to CI/CD. Build/test/release stay deterministic. Agentic handles inherently non-deterministic tasks (triage, docs, research).

### Q: Can workflows access secrets?

**A:** No — agent runs read-only by default. Secrets not available to agentic step unless explicitly configured via MCP tool env vars.

### Q: Can workflows write to the repo?

**A:** Only through safe-outputs or explicit write permissions (not recommended).

### Q: What sanitization is done?

**A:** Secret redaction, URL domain filtering, XML escaping, size limits, control char stripping, GitHub reference escaping, HTTPS enforcement. Write ops in separate jobs.

### Q: Does the AI run in a sandbox?

**A:** Yes — AWF container with network egress control, filesystem isolation, GitHub Actions VM isolation.

### Q: Who pays for AI usage?

**A:** Copilot: your GitHub account (premium requests). Claude: Anthropic account. Codex: OpenAI account.

### Q: Cost per run?

**A:** Copilot uses 1-2 premium requests. Track with `gh aw logs`, `gh aw audit`. Optimize prompts, limit tools, cache results.

### Q: Can I test without affecting my repo?

**A:** Yes — use `gh aw trial` (TrialOps pattern) for isolated testing.

### Q: One workflow or many?

**A:** Start with 1-2, expand. Multiple = better separation of concerns, clearer audit trails.

### Q: What is a lock file?

**A:** `.lock.yml` = compiled GitHub Actions YAML from your `.md` source. Commit both. Lock file has SHA-pinned actions, resolved imports, security hardening.

---

## Quick Reference: CLI Debugging Commands

```bash
# View recent workflow logs
gh aw logs <workflow>

# View last 5 runs
gh aw logs <workflow> --count 5

# Detailed analysis of specific run
gh aw audit <run-id>

# Audit by URL
gh aw audit <run-url>

# Inspect MCP configuration
gh aw mcp inspect <workflow>

# Debug compilation with verbose output
gh aw compile --verbose

# Validate without writing files
gh aw compile --validate

# Apply automated fixes
gh aw fix --write

# Check all workflow states
gh aw status

# Find missing secrets
gh aw secrets bootstrap
```
