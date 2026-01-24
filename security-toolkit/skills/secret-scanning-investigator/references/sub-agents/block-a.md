# Parallel Block A: Sub-Agent Prompts

Use these prompts with the Task tool to launch parallel investigation agents. Each agent includes:
- **Objective**: Precise goal statement
- **Output**: Structured JSON format with artifact storage
- **Tools**: USE/AVOID guidance
- **Boundaries**: Explicit scope limits (what NOT to do)
- **Effort Scaling**: Expected tool call ranges

---

## Agent A1: Alert Acquisition

```
subagent_type: "Explore"
run_in_background: true
prompt: |
  ## Agent A1: Alert Acquisition

  ### Objective
  Gather complete alert data and location information from GitHub API.
  Determine whether the secret exists in the current codebase HEAD.

  ### Context
  Repository: {owner}/{repo}
  Alert Number: {alert_number}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/alert.json`:
  ```json
  {
    "agent": "A1",
    "status": "complete",
    "alert": {
      "number": 19,
      "secret_type": "github_app_private_key",
      "secret_type_display_name": "GitHub App Private Key",
      "state": "open",
      "validity": "unknown",
      "created_at": "2024-01-15T10:30:00Z",
      "resolution": null,
      "html_url": "https://..."
    },
    "location": {
      "file_path": "crates/zed/Zed.toml",
      "start_line": 10,
      "end_line": 35,
      "blob_sha": "abc123...",
      "commit_sha": "def456..."
    },
    "secret_preview": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...[first 100 chars]",
    "in_current_code": true,
    "is_base64_encoded": false,
    "publicly_leaked": false,
    "multi_repo": false
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/alert.json"}`

  ### Tools
  - USE: `gh api repos/.../secret-scanning/alerts/{n}`, `gh api .../locations`, `gh api .../contents/{path}`
  - AVOID: `git clone`, `trufflehog`, `gitleaks` (other agents handle these)

  ### Boundaries
  - DO NOT clone the repository (Agent A2 handles this)
  - DO NOT run security scanners (Agents B1, B2 handle this)
  - DO NOT analyze commit history (Agent A2 handles this)
  - DO NOT fetch PR/issue details (Agent A3 handles this)
  - STOP after writing artifact file

  ### Effort Scaling
  - Expected: 3-5 tool calls
  - If exceeding 8 calls: something is wrong, checkpoint and report

  ### Execution Steps
  1. Create artifact directory: `mkdir -p /tmp/secret-scan-{alert_number}`
  2. Fetch alert: `gh api repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}`
  3. Fetch locations: `gh api repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations`
  4. Check current HEAD: `gh api repos/{owner}/{repo}/contents/{file_path} --jq '.content' | base64 -d | grep -q "{pattern}"`
  5. Write JSON artifact
  6. Return artifact reference
```

---

## Agent A2: Repository Provenance

```
subagent_type: "Explore"
run_in_background: true
prompt: |
  ## Agent A2: Repository Provenance

  ### Objective
  Trace the exact commit that introduced the secret and map file rename history.
  Calculate the exposure timeline from introduction to present.

  ### Context
  Repository: {owner}/{repo}
  File Path: {file_path}
  Introducing Commit (from alert): {commit_sha}
  Secret Pattern (for pickaxe): {unique_secret_substring}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/provenance.json`:
  ```json
  {
    "agent": "A2",
    "status": "complete",
    "introducing_commit": {
      "sha": "abc123...",
      "author": "name <email>",
      "author_date": "2024-01-15T10:30:00Z",
      "message": "commit message verbatim"
    },
    "original_path": "path/when/introduced",
    "current_path": "path/now/or/null",
    "rename_chain": [
      {"from": "old/path", "to": "new/path", "commit": "def456...", "date": "2024-02-01"}
    ],
    "file_existed_before": false,
    "previous_content_summary": null,
    "exposure_days": 365,
    "in_current_head": true,
    "clone_path": "/tmp/{repo}-investigation"
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/provenance.json"}`

  ### Tools
  - USE: `git clone --depth=1000`, `git log -S "{secret_fragment}"`, `git log --follow`, `git show`
  - USE: `gh api repos/.../git/commits/{sha}` for commit dates
  - AVOID: Reading file contents beyond existence check (Agent B handles)
  - AVOID: Full clone without depth limit on large repos (>10k commits)

  ### Boundaries
  - DO NOT analyze secret content or validity (Agent B4 handles this)
  - DO NOT fetch PR/issue details (Agent A3 handles this)
  - DO NOT run security scanners (Agents B1, B2 handle this)
  - DO NOT delete the clone (other agents need it)
  - STOP after writing artifact file

  ### Effort Scaling
  - Simple (single file, no renames): 5-8 tool calls
  - Medium (1-2 renames): 8-12 tool calls
  - Complex (many renames, large repo): 12-18 tool calls
  - If exceeding 20 calls: checkpoint current state, report blocker

  ### Execution Steps
  1. Clone with depth limit: `git clone --depth=1000 https://github.com/{owner}/{repo}.git /tmp/{repo}-investigation`
  2. Find introduction commit: `git log -S "{secret_pattern}" --oneline -- "{file_patterns}"`
  3. Get file history with renames: `git log --follow --oneline -- "{file_path}"`
  4. Check state before introduction: `git show {sha}^:{file_path} 2>/dev/null`
  5. Get commit date from API for accurate timeline
  6. Calculate exposure_days
  7. Write JSON artifact
  8. Return artifact reference (DO NOT delete clone)
```

---

## Agent A3: Commit & PR Context

```
subagent_type: "Explore"
run_in_background: true
prompt: |
  ## Agent A3: Commit & PR Context

  ### Objective
  Gather contextual information about the introducing commit: associated PR,
  linked issues, security-related discussion, and author information.
  Assess whether secret inclusion appears intentional or accidental.

  ### Context
  Repository: {owner}/{repo}
  Introducing Commit SHA: {commit_sha}
  Artifact Directory: /tmp/secret-scan-{alert_number}

  ### Output
  Write findings to `/tmp/secret-scan-{alert_number}/context.json`:
  ```json
  {
    "agent": "A3",
    "status": "complete",
    "commit": {
      "sha": "abc123...",
      "message": "full message",
      "author_name": "Jane Doe",
      "author_email": "jane@example.com",
      "author_date": "2024-01-15T10:30:00Z"
    },
    "pr": {
      "number": 123,
      "title": "PR title",
      "body": "PR description",
      "author": "janedoe",
      "merged_at": "2024-01-16T14:00:00Z"
    },
    "linked_issues": [
      {"number": 456, "title": "Issue title", "body": "Issue body"}
    ],
    "security_comments": [
      {"user": "reviewer", "body": "Should we rotate this key?", "url": "..."}
    ],
    "author_profile": {
      "login": "janedoe",
      "name": "Jane Doe",
      "company": "ACME Inc"
    },
    "intent_assessment": {
      "classification": "accidental",
      "confidence": "medium",
      "evidence": ["No mention of secret in PR", "Appears to be config file copy"]
    }
  }
  ```

  Return only: `{"status": "complete", "artifact": "/tmp/secret-scan-{alert_number}/context.json"}`

  ### Tools
  - USE: `gh api repos/.../git/commits/{sha}`, `gh api repos/.../commits/{sha}/pulls`
  - USE: `gh api repos/.../issues/{n}`, `gh api repos/.../pulls/{n}/comments`
  - USE: `gh api /users/{login}` for author info
  - AVOID: `git clone`, `git log` (Agent A2 handles repository operations)

  ### Boundaries
  - DO NOT clone the repository (Agent A2 handles this)
  - DO NOT analyze file history (Agent A2 handles this)
  - DO NOT run security scanners (Agents B1, B2 handle this)
  - DO NOT analyze the secret itself (Agents B3, B4 handle this)
  - STOP after writing artifact file

  ### Effort Scaling
  - No PR found: 3-5 tool calls
  - PR with no linked issues: 5-8 tool calls
  - PR with linked issues and comments: 8-15 tool calls
  - If exceeding 18 calls: checkpoint and report

  ### Intent Assessment Criteria
  - "explicit": PR/commit explicitly mentions secret, credentials, or key rotation
  - "implicit": Context suggests awareness (e.g., "add config", config template pattern)
  - "accidental": No indication author knew secret was included

  ### Execution Steps
  1. Fetch commit details via API
  2. Fetch associated PR: `gh api repos/{owner}/{repo}/commits/{sha}/pulls`
  3. If PR found, extract issue references from body (#NNN patterns)
  4. Fetch each linked issue
  5. Search PR comments for security keywords
  6. Fetch author profile
  7. Assess intent based on collected evidence
  8. Write JSON artifact
  9. Return artifact reference
```
