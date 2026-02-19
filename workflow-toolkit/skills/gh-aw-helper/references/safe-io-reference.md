# Safe Inputs and Safe Outputs Reference

Complete technical reference for GitHub Agentic Workflows' Safe Inputs (custom MCP tools) and Safe Outputs (write operations).

## Table of Contents

1. [Safe Inputs (Custom MCP Tools)](#safe-inputs-custom-mcp-tools)
   - [Definition Structure](#definition-structure)
   - [Execution Models](#execution-models)
   - [Security Properties](#security-properties)
   - [JavaScript Model](#javascript-model)
   - [Shell Model](#shell-model)
   - [Python Model](#python-model)
   - [Go Model](#go-model)
   - [Input Parameter Types](#input-parameter-types)
   - [Environment Variables](#environment-variables)
   - [Timeouts](#timeouts)
2. [Safe Outputs](#safe-outputs)
   - [Architecture](#architecture)
   - [Security Invariants](#security-invariants)
   - [Complete Safe Output Types](#complete-safe-output-types)
   - [Common Configuration Options](#common-configuration-options)
   - [Temporary IDs](#temporary-ids)
   - [Workflow Markers](#workflow-markers)
   - [Custom Footer Messages](#custom-footer-messages)
   - [Custom Safe Output Jobs](#custom-safe-output-jobs)
   - [Validation Pipeline](#validation-pipeline)
   - [Content Sanitization](#content-sanitization)
   - [add-comment Constraints](#add-comment-constraints)

---

## Safe Inputs (Custom MCP Tools)

### Definition Structure

```yaml
safe-inputs:
  tool-name:
    description: "What the tool does"
    inputs:
      param1:
        type: string          # string|number|boolean|array|object
        required: true        # true|false
        default: value        # optional default value
        enum: [val1, val2]    # optional allowed values
      param2:
        type: number
        required: false
        default: 10
    script: |                 # JavaScript (CommonJS, in-process)
      const result = inputs.param1 + " processed";
      return result;
    run: |                    # Shell (Docker container)
      echo "Processing $INPUT_PARAM1"
    py: |                     # Python (Docker container)
      import json
      print(json.dumps({"result": inputs["param1"]}))
    go: |                     # Go (Docker container)
      package main
      import "encoding/json"
      // inputs available as map[string]any
    env:
      SECRET: "${{ secrets.SECRET }}"
      API_KEY: "${{ secrets.API_KEY }}"
    timeout: 60               # seconds, default 60
    dependencies: []          # npm packages for JavaScript
```

**Rules:**
- Use exactly ONE of: `script`, `run`, `py`, `go`
- Tool names must be unique within workflow
- Inputs are validated against schema before execution

### Execution Models

| Model | Language | Runtime | Input Format | Output Format | Globals Available |
|-------|----------|---------|--------------|---------------|-------------------|
| `script:` | JavaScript | In-process async | Destructured `inputs` object | Return value (serializable) | `github`, `context`, `core` |
| `run:` | Shell | Docker container | `INPUT_<UPPERCASE_NAME>` env vars | stdout (text) | Standard env vars only |
| `py:` | Python | Docker container | `inputs` dict | JSON to stdout | Standard env vars only |
| `go:` | Go | Docker container | `map[string]any` from stdin | JSON to stdout | Standard env vars only |

### Security Properties

1. **Secret Isolation**: Only explicitly declared `env:` secrets are available
2. **Process Isolation**: Shell/Python/Go run in ephemeral Docker containers
3. **Output Sanitization**: Outputs >500 characters saved to file instead of inline
4. **Timeout Enforcement**: Hard timeout with SIGTERM → SIGKILL escalation
5. **Read-Only Filesystem**: Containers have minimal write access
6. **Network Isolation**: No outbound network by default (configurable)

### JavaScript Model

**Context:**
```javascript
// Inputs automatically destructured
const { param1, param2 } = inputs;

// GitHub API client available
const issue = await github.rest.issues.get({
  owner: context.repo.owner,
  repo: context.repo.repo,
  issue_number: 123
});

// Logging
core.info("Processing started");
core.warning("Check this");
core.error("Failed operation");

// Return values
return { status: "success", data: result };
// OR
return "Simple string result";
```

**Available Globals:**
- `inputs`: Object with all declared parameters
- `github`: Octokit REST and GraphQL client (read-only token)
- `context`: Workflow context (repo, sha, ref, etc.)
- `core`: Actions toolkit core functions (logging, exporting)

**Dependencies:**
```yaml
safe-inputs:
  analyze-json:
    dependencies:
      - lodash@4.17.21
      - ajv@8.12.0
    script: |
      const _ = require('lodash');
      const Ajv = require('ajv');
      // ...
```

### Shell Model

**Context:**
```bash
#!/bin/bash
set -euo pipefail

# Inputs available as INPUT_<UPPERCASE>
echo "Param1: $INPUT_PARAM1"
echo "Param2: $INPUT_PARAM2"

# Secrets from env: section
curl -H "Authorization: Bearer $SECRET" https://api.example.com

# Output to stdout
echo "Result: success"
```

**Input Naming:**
- Input `paramName` → `INPUT_PARAMNAME`
- Input `my-param` → `INPUT_MY_PARAM`
- Input `API_KEY` → `INPUT_API_KEY`

**Working Directory:**
- `/workspace` — empty ephemeral directory
- No access to repository files unless explicitly mounted

### Python Model

**Context:**
```python
import json
import sys

# Inputs available as dictionary
inputs = json.loads(sys.stdin.read())
param1 = inputs["param1"]
param2 = inputs.get("param2", 10)  # with default

# Processing
result = {"status": "success", "value": param1 * param2}

# Output JSON to stdout
print(json.dumps(result))
```

**Requirements:**
```yaml
safe-inputs:
  analyze-data:
    py: |
      # pip install handled automatically if declared
      import pandas as pd
      import numpy as np
      # ...
    dependencies:
      - pandas==2.0.0
      - numpy==1.24.0
```

### Go Model

**Context:**
```go
package main

import (
    "encoding/json"
    "fmt"
    "os"
)

type Inputs struct {
    Param1 string `json:"param1"`
    Param2 int    `json:"param2"`
}

type Output struct {
    Status string `json:"status"`
    Result string `json:"result"`
}

func main() {
    var inputs Inputs
    json.NewDecoder(os.Stdin).Decode(&inputs)

    output := Output{
        Status: "success",
        Result: fmt.Sprintf("Processed: %s", inputs.Param1),
    }

    json.NewEncoder(os.Stdout).Encode(output)
}
```

**Dependencies:**
```yaml
safe-inputs:
  process-data:
    go: |
      package main
      import "github.com/yourorg/pkg"
      // ...
    dependencies:
      - github.com/yourorg/pkg@v1.2.3
```

### Input Parameter Types

| Type | JSON Schema Type | Example Values | Validation |
|------|------------------|----------------|------------|
| `string` | string | `"hello"`, `""` | Max 65536 chars |
| `number` | number | `42`, `3.14`, `-100` | JSON number limits |
| `boolean` | boolean | `true`, `false` | Strict boolean |
| `array` | array | `[1, 2, 3]`, `["a", "b"]` | Max 1000 items |
| `object` | object | `{"key": "value"}` | Max 100 keys, 10 levels deep |

**Enum Constraints:**
```yaml
inputs:
  severity:
    type: string
    enum: [low, medium, high, critical]
    required: true
```

**Default Values:**
```yaml
inputs:
  max_results:
    type: number
    default: 10
  include_closed:
    type: boolean
    default: false
```

### Environment Variables

**Secret Injection:**
```yaml
safe-inputs:
  api-call:
    env:
      API_TOKEN: "${{ secrets.API_TOKEN }}"
      DATABASE_URL: "${{ secrets.DATABASE_URL }}"
    script: |
      const token = process.env.API_TOKEN;
      // ...
```

**Built-in Environment Variables (all models):**
- `GITHUB_REPOSITORY`: `owner/repo`
- `GITHUB_REF`: `refs/heads/main`
- `GITHUB_SHA`: commit SHA
- `GITHUB_WORKFLOW`: workflow name
- `GITHUB_RUN_ID`: unique run ID
- `GITHUB_ACTOR`: user who triggered

### Timeouts

**Default:** 60 seconds

**Custom:**
```yaml
safe-inputs:
  long-running-task:
    timeout: 300  # 5 minutes
    script: |
      // Long-running operation
```

**Behavior:**
- Timeout exceeded → SIGTERM sent
- 5 seconds grace period
- If still running → SIGKILL
- Exit code 124 (timeout)
- Partial output discarded

**Limits:**
- Minimum: 1 second
- Maximum: 600 seconds (10 minutes)
- Default: 60 seconds

---

## Safe Outputs

### Architecture

**Read-Write Separation:**
```
┌─────────────────────────────────────────────────┐
│ Agent Job (read-only)                           │
│ - Runs LLM agent                                │
│ - Has read-only GitHub token                    │
│ - Generates structured output JSON              │
│ - NEVER has write permissions                   │
└─────────────────┬───────────────────────────────┘
                  │ outputs structured JSON
                  ▼
┌─────────────────────────────────────────────────┐
│ Safe Output Jobs (write permissions)            │
│ - Separate permission-controlled jobs           │
│ - Validate all agent outputs                    │
│ - Enforce limits and sanitization               │
│ - Execute GitHub API writes                     │
└─────────────────────────────────────────────────┘
```

### Security Invariants

| ID | Invariant | Enforcement |
|----|-----------|-------------|
| SP1 | Agent never possesses GitHub write tokens | Separate GITHUB_TOKEN in output jobs only |
| SP2 | All validation before API invocation | 7-stage validation pipeline |
| SP3 | Max limits strictly enforced | Hard limits with validation errors |
| SP4 | All content sanitized | Unicode, protocol, domain, markdown filters |
| SP5 | All resources include workflow provenance | Mandatory workflow markers (footer opt-out allowed) |
| SP6 | Cross-repo ops validated against allowlists | Explicit `allowed-repos:` or `target-repo:` required |
| SP7 | Deny-by-default (same-repo only without allowlist) | Cross-repo blocked unless explicitly allowed |

### Complete Safe Output Types

| Type | Default Max | Description |
|------|-------------|-------------|
| **Issues** | | |
| `create-issue` | 1 | Create new issue |
| `update-issue` | 1 | Update existing issue title/body |
| `close-issue` | 1 | Close issue with optional comment |
| `link-sub-issue` | 1 | Link issue as sub-task (requires parent) |
| **Discussions** | | |
| `create-discussion` | 1 | Create new discussion |
| `update-discussion` | 1 | Update discussion title/body |
| `close-discussion` | 1 | Close discussion |
| **Pull Requests** | | |
| `create-pull-request` | 1 | Create new PR from branch or workspace changes |
| `update-pull-request` | 1 | Update PR title/body |
| `close-pull-request` | 1 | Close PR without merging |
| **PR Reviews** | | |
| `create-pull-request-review-comment` | 10 | Add review comment at specific line |
| `reply-to-pull-request-review-comment` | 10 | Reply to existing review thread |
| `resolve-pull-request-review-thread` | 10 | Resolve review conversation |
| `submit-pull-request-review` | 10 | Submit review (approve/request changes/comment) |
| `push-to-pull-request-branch` | 10 | Push commits to PR branch |
| **Labels & Assignments** | | |
| `add-comment` | 1 | Add comment to issue/PR/discussion |
| `hide-comment` | 1 | Minimize comment (mark as off-topic/spam) |
| `add-labels` | 3 | Add labels to issue/PR |
| `remove-labels` | 3 | Remove labels from issue/PR |
| `add-reviewer` | 1 | Request PR review |
| `assign-milestone` | 1 | Assign milestone to issue/PR |
| `assign-to-agent` | 1 | Assign issue/PR to workflow agent |
| `assign-to-user` | 1 | Assign issue/PR to user |
| `unassign-from-user` | 1 | Remove user assignment |
| **Projects** | | |
| `create-project` | 1 | Create new project |
| `update-project` | 10 | Update project fields/items |
| `create-project-status-update` | 1 | Create project status update |
| **Security** | | |
| `create-code-scanning-alert` | unlimited | Create code scanning alert |
| `autofix-code-scanning-alert` | 10 | Auto-fix code scanning alert |
| **System** | | |
| `noop` | unlimited | No-op (validation only) |
| `missing-tool` | unlimited | Report missing tool usage |
| `missing-data` | unlimited | Report missing data |
| `dispatch-workflow` | 1 | Trigger another workflow |
| **Assets** | | |
| `upload-asset` | 10 | Upload release asset |
| `update-release` | 1 | Update release notes |

### Common Configuration Options

#### Global Options (apply to all handlers)

```yaml
safe-outputs:
  max: 5                     # Override default max for ALL handlers
  footer: true               # Enable footer on all outputs (default true)
  staged: true               # Preview mode: no real writes
  github-token: "${{ secrets.CUSTOM_PAT }}"  # Custom token for all operations
```

#### Per-Handler Options

**Title/Body Modifications:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      title-prefix: "[Bot] "
      footer: "if-body"      # Only add footer if body exists
```

**Auto-Labeling:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      labels: [bot-created, needs-triage]
      allowed-labels: [bug, enhancement, documentation]  # Restrict agent choices
```

**Auto-Assignment:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      assignees: [octocat, github-user]
```

**Expiration:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      expires: 7d            # Close after 7 days (2h, 3d, 2w formats supported)
      expires: 14            # Close after 14 days (integer = days)
```

**Close Previous:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      close-older-issues: true   # Close previous issues from this workflow
    create-discussion:
      close-older-discussions: true
```

**Hide Previous Comments:**
```yaml
safe-outputs:
  handlers:
    add-comment:
      hide-older-comments: true  # Minimize older workflow comments
```

**Operation Limits:**
```yaml
safe-outputs:
  handlers:
    create-pull-request-review-comment:
      max: 25                    # Allow up to 25 review comments
```

**Cross-Repository Operations:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      target-repo: org/other-repo              # Single target
      allowed-repos: [org/repo1, org/repo2]    # Multiple allowed targets
```

**Pull Request Options:**
```yaml
safe-outputs:
  handlers:
    create-pull-request:
      draft: false               # Create as ready-to-review (default true)
      base-branch: develop       # Target branch (default: repo default branch)
      commit-changes: true       # Auto-commit workspace changes (default true)
      reviewers: [user1, user2]  # Auto-request reviewers
      fallback-as-issue: true    # Create issue if PR fails (default true)
```

**Discussion Control:**
```yaml
safe-outputs:
  discussions: false   # Disable discussions:write permission (default true)
```

**Issue Grouping:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      group: parent-issue-123    # Group issues under parent (max 64 per parent)
```

### Temporary IDs

**Purpose:** Reference not-yet-created issues/PRs/discussions in same workflow run.

**Format:** `aw_<alphanumeric>` (e.g., `#aw_abc123`, `#aw_issue_001`)

**Example:**
```json
{
  "items": [
    {
      "type": "create-issue",
      "id": "aw_parent",
      "title": "Parent Issue",
      "body": "Main tracking issue"
    },
    {
      "type": "create-issue",
      "title": "Sub-task 1",
      "body": "Related to #aw_parent"
    },
    {
      "type": "link-sub-issue",
      "issue": "#aw_parent",
      "sub_issue": 456
    }
  ]
}
```

**Resolution:**
- Temporary IDs resolved to real numbers after creation
- Referenced in body/comments as `#aw_id`
- Cross-references automatically updated
- Invalid references cause validation errors

### Workflow Markers

**Minimal Markers (always present, even with `footer: false`):**
```html
<!-- gh-aw-workflow-id: WORKFLOW_NAME -->
<!-- gh-aw-tracker-id: unique-tracker-id -->
```

**Full Footer (when enabled):**
```markdown
---
> [!NOTE]
> This issue was created by [Workflow Name](https://github.com/owner/repo/actions/runs/123456)
> Triggered by #789

<!-- gh-aw-workflow-id: WORKFLOW_NAME -->
<!-- gh-aw-tracker-id: unique-tracker-id -->
```

**Searchability:**
```
repo:owner/repo "gh-aw-workflow-id: daily-team-status" in:body
repo:owner/repo "gh-aw-tracker-id: abc123" in:body
```

**Persistence:**
- Markers survive edits
- Enable workflow tracking
- Support close-older-issues/discussions
- Required for workflow provenance (SP5)

### Custom Footer Messages

**Global Custom Footer:**
```yaml
safe-outputs:
  messages:
    footer: "> 🤖 Powered by [{workflow_name}]({run_url})"
```

**Per-Handler Custom Footer:**
```yaml
safe-outputs:
  handlers:
    create-issue:
      messages:
        footer: "> Generated by AI • [View run]({run_url}) • Triggered by #{triggering_number}"
```

**Available Variables:**
- `{workflow_name}`: Workflow file name
- `{run_url}`: Full URL to workflow run
- `{triggering_number}`: Issue/PR number that triggered workflow
- `{repo}`: Repository name (owner/repo)
- `{actor}`: User who triggered workflow

**Footer Control:**
```yaml
footer: true        # Always add footer (default)
footer: false       # Never add footer (markers still present)
footer: "if-body"   # Add footer only if body exists
```

### Custom Safe Output Jobs

**Definition:**
```yaml
safe-outputs:
  jobs:
    slack-notify:
      description: "Send notification to Slack"
      runs-on: ubuntu-latest
      output: "Message sent to Slack"
      inputs:
        message:
          required: true
          type: string
        channel:
          required: false
          type: string
          default: "#general"
      steps:
        - name: Send Slack Message
          env:
            SLACK_WEBHOOK: "${{ secrets.SLACK_WEBHOOK }}"
          run: |
            MESSAGES=$(cat "$GH_AW_AGENT_OUTPUT" | jq -c '.items[] | select(.type == "slack_notify")')
            echo "$MESSAGES" | while IFS= read -r item; do
              MESSAGE=$(echo "$item" | jq -r '.message')
              CHANNEL=$(echo "$item" | jq -r '.channel // "#general"')
              curl -X POST "$SLACK_WEBHOOK" \
                -H "Content-Type: application/json" \
                -d "{\"channel\":\"$CHANNEL\",\"text\":\"$MESSAGE\"}"
            done
```

**Environment Variables:**
- `$GH_AW_AGENT_OUTPUT`: Path to agent output JSON file
- All standard GitHub Actions env vars
- Secrets available via `${{ secrets.NAME }}`

**Output Handling:**
- `output:` field shown in workflow summary
- Can reference `{workflow_name}`, `{run_url}`, etc.
- No validation beyond schema (custom logic in steps)

### Validation Pipeline

**7-Stage Pipeline (executed in order):**

| Stage | Error Code | Description | Checks |
|-------|------------|-------------|--------|
| 1. Schema Validation | E001 | JSON structure validation | Type correctness, required fields, format |
| 2. Limit Enforcement | E002 | Max operation limits | Per-handler max, global max, grouping limits |
| 3. Content Sanitization | E008 | Content cleaning/filtering | Unicode, protocols, domains, markdown |
| 4. Domain Filtering | E003 | URL domain allowlisting | Allowed/blocked domain lists |
| 5. Cross-Repository | E004 | Cross-repo allowlist validation | target-repo, allowed-repos enforcement |
| 6. Dependency Resolution | E005 | Temporary ID resolution | aw_* ID validation and replacement |
| 7. GitHub API Invocation | E007 | Final API execution | Network errors, API failures |

**Error Response Format:**
```json
{
  "error": "E002",
  "message": "Operation limit exceeded for create-issue: 5 > max 3",
  "item_index": 4,
  "details": {
    "type": "create-issue",
    "requested": 5,
    "max": 3
  }
}
```

**Validation Stops at First Error:**
- No partial execution
- All items validated before any execution
- Atomic: all succeed or all fail

### Content Sanitization

**Applied in Order:**

1. **Unicode Normalization**
   - NFC (canonical decomposition + composition)
   - Remove zero-width characters (U+200B, U+200C, U+200D, U+FEFF)
   - Remove non-printable control chars (except \n, \r, \t)

2. **Protocol Filtering**
   - Allowed: `http://`, `https://`, `mailto:`
   - Blocked: `javascript:`, `data:`, `file:`, `ftp:`, custom protocols
   - Invalid protocols replaced with `#invalid-protocol`

3. **Domain Filtering (if configured)**
   ```yaml
   safe-outputs:
     allowed-domains: [github.com, docs.example.com]
     blocked-domains: [malicious.com]
   ```
   - Check all extracted URLs
   - Block if domain not in allowed-domains
   - Block if domain in blocked-domains
   - Replace blocked URLs with `[blocked-domain]`

4. **Command Neutralization**
   - Escape slash commands: `/command` → `\/command`
   - Prevents unintended GitHub command execution
   - Applies to: `/close`, `/reopen`, `/assign`, etc.

5. **Mention Filtering**
   ```yaml
   safe-outputs:
     allowed-mentions: [octocat, team-leads]
   ```
   - Count `@username` mentions
   - Enforce max-mentions limit (default: 10)
   - Filter unauthorized mentions (if allowlist configured)
   - Replace unauthorized: `@user` → `@\u200Buser`

6. **Markdown Safety**
   - Remove XML/HTML comments: `<!-- ... -->`
   - Balance code fences (ensure closing \`\`\`)
   - Escape HTML tags (optional, configurable)
   - Prevent XSS via markdown injection

7. **Truncation**
   - Max content length: 524,288 characters (512 KB)
   - Truncate at last complete sentence before limit
   - Append: `\n\n[Content truncated]`

**Sanitization Configuration:**
```yaml
safe-outputs:
  sanitization:
    max-mentions: 5
    max-links: 25
    allowed-domains: [github.com]
    blocked-domains: [spam.com]
    escape-html: true
    preserve-comments: false
```

### add-comment Constraints

**Hard Limits (enforced before sanitization):**

| Constraint | Limit | Error Code |
|------------|-------|------------|
| Body length | 65,536 chars | E002 |
| Mentions | 10 per comment | E002 |
| Links | 50 per comment | E002 |

**Footer Overhead:**
- Minimal footer: ~200 chars
- Full footer with note: ~500 chars
- Effective body limit: 65,036 chars (with minimal footer)

**Validation Example:**
```json
{
  "type": "add-comment",
  "issue_number": 123,
  "body": "Comment with @user1 @user2 ... @user11"
}
```
**Error:** `E002: Mention limit exceeded: 11 > max 10`

**Link Validation:**
```json
{
  "type": "add-comment",
  "issue_number": 123,
  "body": "Links: [1](url1) [2](url2) ... [51](url51)"
}
```
**Error:** `E002: Link limit exceeded: 51 > max 50`

**Length Validation:**
```json
{
  "type": "add-comment",
  "issue_number": 123,
  "body": "<65,537 character string>"
}
```
**Error:** `E002: Comment body exceeds maximum length: 65,537 > 65,536`

**Note:** Footer is added AFTER body length validation, so body must fit within limit minus footer overhead.

---

## End of Reference

This reference covers all Safe Inputs and Safe Outputs features in complete technical detail. For workflow examples and integration patterns, see `workflow-patterns-reference.md`.
