# Source Handlers Reference

Reference documentation for how safe-skill-install acquires skill content from different sources.

## GitHub Archive Download (Preferred)

### Why It's Safer Than Git Clone

| Risk | Git Clone | Archive Download |
|------|-----------|-----------------|
| **Git hooks** | `.git/hooks/` scripts can run on clone | No .git directory — no hooks |
| **Submodule attacks** | `--recurse-submodules` can fetch malicious repos | No submodule processing |
| **Symlink traversal** | Symlinks can escape repo boundaries | Tar extraction is constrained |
| **LFS filter attacks** | Custom LFS filters can run code | No LFS processing |
| **fsmonitor attacks** | Custom fsmonitor scripts can run | No fsmonitor |
| **CVE-2024-32002** | Exploitable via crafted repos on case-insensitive FS | Not applicable |

Archive download reduces the attack surface by avoiding the entire git machinery. The download is a simple HTTP GET of a tarball — no code runs during the process.

### How It Works

```bash
# 1. Validate branch name from API (defense against crafted default_branch values)
BRANCH=$(gh api "repos/{owner}/{repo}" --jq '.default_branch')
if ! printf '%s' "$BRANCH" | grep -qE '^[a-zA-Z0-9._/-]+$'; then
  echo "ERROR: Invalid branch name from API. Aborting."
  exit 1
fi

# 2. Resolve the commit SHA (TOCTOU protection — quote $BRANCH)
COMMIT_SHA=$(gh api "repos/{owner}/{repo}/commits/${BRANCH}" --jq '.sha')

# 3. Download archive at that exact SHA — curl -f fails on HTTP errors
ARCHIVE_FILE="$SCAN_DIR/archive.tar.gz"
curl -fsSL "https://github.com/{owner}/{repo}/archive/${COMMIT_SHA}.tar.gz" \
  -o "$ARCHIVE_FILE"

# 4. Extract safely (BSD tar strips absolute paths by default; --strip-components is POSIX)
tar xzf "$ARCHIVE_FILE" -C "$SCAN_DIR" --strip-components=1
rm -f "$ARCHIVE_FILE"
```

The branch name is validated first (API-returned `default_branch` could be attacker-controlled for a crafted repo). The SHA is captured, then the archive is downloaded at that exact SHA. `curl -f` ensures HTTP errors are not silently swallowed. BSD tar (macOS default) strips absolute paths by default; GNU tar requires `--no-absolute-names` but we avoid GNU-specific flags for portability.

### When It's Available

- Any public GitHub repository
- GitHub Enterprise instances (with appropriate URL adjustment)
- Requires `gh` CLI for SHA resolution, `curl` for download

### When It's NOT Available

- Non-GitHub hosts (GitLab, Bitbucket, self-hosted)
- Private repositories (returns 404/403 — see Private Repo Handling below)
- Repositories with archive downloads disabled (rare)

---

## Hardened Git Clone (Fallback)

When archive download is unavailable, use a hardened git clone with all code-running vectors disabled.

### Full Command

```bash
GIT_TERMINAL_PROMPT=0 \
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
git -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -c core.symlinks=false \
    -c core.protectHFS=true \
    -c core.protectNTFS=true \
    -c core.autocrlf=false \
    -c filter.lfs.smudge=cat \
    -c filter.lfs.process=cat \
    -c filter.lfs.required=false \
    -c protocol.file.allow=never \
    -c receive.fsckObjects=true \
    -c transfer.fsckObjects=true \
    -c fetch.fsckObjects=true \
    clone --depth 1 --no-recurse-submodules \
    "$REPO_URL" "$SCAN_DIR/repo"
```

### Flag Explanation

| Flag | Purpose |
|------|---------|
| `GIT_TERMINAL_PROMPT=0` | Disable interactive credential prompts (prevents hanging on auth) |
| `GIT_CONFIG_GLOBAL=/dev/null` | Ignore user's global git config (may contain unexpected settings) |
| `GIT_CONFIG_SYSTEM=/dev/null` | Ignore system git config |
| `core.hooksPath=/dev/null` | Disable all git hooks |
| `core.fsmonitor=false` | Disable filesystem monitor scripts |
| `core.symlinks=false` | Disable symlink creation during checkout |
| `core.protectHFS=true` | Prevent `.git` directory attacks on case-insensitive HFS+ (macOS) |
| `core.protectNTFS=true` | Prevent `.git` directory attacks on NTFS (Windows) |
| `core.autocrlf=false` | Prevent line ending conversion (avoids content modification) |
| `filter.lfs.smudge=cat` | Replace LFS smudge filter with `cat` (no LFS code runs) |
| `filter.lfs.process=cat` | Replace LFS process filter with `cat` |
| `filter.lfs.required=false` | Don't fail if LFS content is unavailable |
| `protocol.file.allow=never` | Block `file://` protocol (prevents local file access via submodules) |
| `receive.fsckObjects=true` | Validate objects on receive (detects corrupted/crafted objects) |
| `transfer.fsckObjects=true` | Validate objects during transfer |
| `fetch.fsckObjects=true` | Validate objects during fetch |
| `--depth 1` | Shallow clone — only latest commit (reduces attack surface and bandwidth) |
| `--no-recurse-submodules` | Do not process submodules |

### Post-Clone SHA Capture

```bash
COMMIT_SHA=$(git -C "$SCAN_DIR/repo" rev-parse HEAD)
```

---

## skills.sh / npx Skills Ecosystem

### Discovery

```bash
# Interactive search
npx skills find [query]

# Returns: name, description, install command, skills.sh link
```

### Download for Scanning

For skills.sh packages, extract the underlying GitHub repository URL when available, then use the archive download path. If no GitHub URL is available, download via the npx skills ecosystem to a temp directory.

### Installation

```bash
# Standard install (auto-confirms prompts)
npx skills add {owner/repo@skill} -g -y

# Secure mode install (preserves all downstream prompts)
npx skills add {owner/repo@skill} -g
```

Note: `npx skills add` fetches from remote, NOT from the scanned local copy. This creates a TOCTOU gap. Always run post-install SHA verification (see Step 6 in SKILL.md).

---

## Marketplace Plugin Resolution

### Discovery

Marketplace plugins are resolved via their marketplace URL:
```
/plugin marketplace add {marketplace-url}
/plugin install {name}@{marketplace}
```

### Download for Scanning

Extract the underlying repository URL from the marketplace reference. Then use the GitHub archive download path (if GitHub-hosted) or hardened git clone fallback.

### Installation

After scanning, install via the marketplace commands. Since marketplace install fetches from remote, post-install verification is recommended.

---

## Local Path Handling

### When It Applies

- User provides a local filesystem path: `"scan skill at /path/to/skill"`
- Scanning already-installed skills (`"scan installed skills"`)
- User manually cloned a private repo

### Workflow

1. Validate path exists and is a directory
2. Skip download phases entirely (Phase A, B, C)
3. Run scan directly against the local path (Phase D)
4. Set `COMMIT_SHA="local"` in the audit log

### No Hardening Steps

Local paths are NOT hardened (no symlink removal, no exec bit stripping). Rationale:
- The user already has these files on their system
- Modifying local files would be destructive and unexpected
- The scan should report what's there, not modify it

---

## Post-Download Hardening Steps

Applied to all downloaded/cloned content (NOT local paths):

### 1. Remove .git Directory

```bash
rm -rf "$SCAN_DIR"/.git "$SCAN_DIR"/repo/.git
```

**Why:** The scanner doesn't need git metadata. Removing `.git` eliminates hook-based attacks if any subprocess invokes git operations on the scanned directory.

### 2. Strip Executable Bits

```bash
find "$SCAN_DIR" -type f -exec chmod 644 {} +
```

**Why:** Skill files are configuration and code — they should be read-only. Stripping executable bits prevents accidental running of downloaded scripts. The scanner reads files; it doesn't run them.

### 3. Remove Symlinks

```bash
SYMLINKS=$(find "$SCAN_DIR" -type l)
if [ -n "$SYMLINKS" ]; then
  find "$SCAN_DIR" -type l -delete
fi
```

**Why:** Symlinks have no legitimate use in skill packages. A symlink in a skill could:
- Point outside the scan directory (directory traversal)
- Create circular references (DoS the scanner)
- Point to sensitive files on the host system

All symlinks are removed and flagged in the report as suspicious.

### 4. Flag Large Files

```bash
LARGE_FILES=$(find "$SCAN_DIR" -type f -size +5M)
```

**Why:** Skills are typically small text files (markdown, JSON, YAML, small scripts). A file over 5MB is unusual and may indicate:
- Binary payloads
- Embedded data exfiltration payloads
- Scanner DoS via resource exhaustion

Large files are flagged in the report but NOT removed — the scanner should analyze them.

---

## Private Repository Handling

### Detection

Private repos are detected when:
- GitHub API returns 403 (Forbidden) or 404 (Not Found)
- Archive download returns HTTP 404
- `gh api repos/{owner}/{repo}` fails with authentication error

### User Message

```
This repo requires authentication or is private.

To scan a private repo:
1. Clone it locally: git clone https://github.com/{owner}/{repo}
2. Then scan: "scan skill at /path/to/local/clone"

safe-skill-install does not use your GitHub token for private repo access.
This is a deliberate security boundary — the scanner should not have
access to your authentication credentials.
```

### Why No Authenticated Fetches

- The scanner processes untrusted content. If compromised, it could exfiltrate the auth token.
- The skill's runtime context should not have access to credentials beyond what's needed.
- Local clone + local scan is equally effective and keeps the auth boundary clean.

---

## Temp Directory Security

### Creation

```bash
SCAN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/skill-scan-XXXXXXXX")
chmod 700 "$SCAN_DIR"
```

- `mktemp -d` generates an unpredictable directory name (8 random characters)
- `chmod 700` restricts access to the current user only
- `${TMPDIR:-/tmp}` respects the system's temp directory preference

### Cleanup

Cleanup runs on ALL exit paths:
- Successful installation
- User rejection
- Scanner failure
- Unexpected errors

In MANUAL/SECURE mode, cleanup is delayed until after the user's decision to allow content inspection.

### Why Not Predictable Paths

A predictable path like `/tmp/skill-scan-myskill/` allows:
- **Symlink attacks**: Attacker pre-creates a symlink at the expected path
- **Content substitution**: Attacker replaces fetched content with clean files before the scan
- **Information disclosure**: Other users on the system can read the fetched content

`mktemp -d` with `chmod 700` mitigates all three vectors.
