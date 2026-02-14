---
name: kcap
description: |
  Capture and distill knowledge from URLs into structured markdown notes.
  Supports web articles, YouTube videos, and Twitter/X posts. Extracts
  content using the best available tool, synthesizes key insights via a
  sandboxed sub-agent, generates YAML frontmatter with auto-suggested
  tags, and saves to a configured directory. Optionally integrates with
  Obsidian for direct vault linking.

  Use this skill when users want to:
  (1) Save/capture/distill a URL to a structured note
  (2) Create knowledge base entries from web content
  (3) Capture YouTube video transcripts as notes
  (4) Save Twitter threads as structured summaries
  (5) Build an Obsidian vault or markdown knowledge base from web sources

  For saving/distilling a specific URL to a note, use kcap. For browsing,
  discovering, or searching AI tweets, use ai-twitter-radar instead.
triggers:
  - "capture this url"
  - "save this article"
  - "kcap"
  - "knowledge capture"
  - "distill this"
  - "save to obsidian"
  - "capture this video"
  - "capture this tweet"
  - "save this for later"
allowed-tools:
  - Bash(trafilatura *)
  - Bash(curl -sL --max-redirs 3 --proto =https *)
  - Bash(yt-dlp --dump-json --skip-download *)
  - Bash(yt-dlp --write-auto-subs --sub-lang * --skip-download *)
  - Bash(youtube_transcript_api *)
  - Bash(bird thread *)
  - Bash(mktemp -d *)
  - Bash(mkdir -p ~/*)
  - Bash(chmod 700 ${TMPDIR:-/tmp}/kcap-*)
  - Bash(mv ${TMPDIR:-/tmp}/kcap-*/* *)
  - Bash(rm -rf ${TMPDIR:-/tmp}/kcap-*)
  - Bash(grep -Frl *)
  - Bash(wc -w *)
  - Bash(html2text *)
  - Bash(head -c *)
  - Bash(open obsidian://*)
  - Bash(python3 -c "import socket;*")
  - Bash(python3 -c "import sys*from urllib.parse*")
  - Bash(python3 -c "import re*")
---

# kcap — Knowledge Capture

Capture web content as structured, searchable markdown notes with YAML frontmatter.

## Security Model

kcap processes untrusted web content that could contain prompt injection. To prevent
injected instructions from persisting through file writes or command execution, the
skill uses a **dual-agent pattern**:

1. **Main agent** (privileged) — validates URLs, extracts content via Bash, writes files
2. **Synthesis sub-agent** (sandboxed Explore type) — analyzes content, returns structured JSON

The synthesis agent has NO Write, Edit, Bash, or Task tools. It receives raw content
in `<external_content>` delimiter tags and returns only structured JSON. The main agent
validates the JSON schema and sanitizes all field content before writing to disk.

**Defense layers:** Tool restriction, context isolation, content tagging, structured
output format, output validation + sanitization, allowed-tools scoping, SSRF blocking.

**Accepted residual risks:**
- The Explore sub-agent retains Read/Glob/Grep access. A successful injection could
  read local files and embed content in JSON output. Impact is low — output goes to
  a user-owned note file, not transmitted externally.
- trafilatura may follow HTTP redirects to non-HTTPS destinations. The curl fallback
  uses `--proto =https` to enforce HTTPS-only. Pre-fetch SSRF validation catches
  private IPs for the original hostname but not redirect targets. Cloud metadata
  endpoints (169.254.x.x) would need a redirect chain through a public host.

This differs from the wrapper+agent pattern in safe-skill-install (ADR-001) because
kcap's security boundary is between two agents rather than between a shell script and
an agent. The deterministic extraction happens in Bash; the AI synthesis happens in
a privilege-restricted sub-agent.

## Related Skills

- **kcap** — Save/distill a specific URL to a structured note
- **ai-twitter-radar** — Browse, discover, or search AI tweets (read-only exploration)

Both use bird-cli for Twitter access but serve different purposes.

## Usage

```
kcap <url> [focus question]
kcap --deep <url> [focus question]
```

| Argument | Required | Description |
|----------|----------|-------------|
| `<url>` | Yes | HTTPS URL to capture (web article, YouTube video, or Twitter/X post) |
| `[focus question]` | No | Optional angle for the synthesis (e.g., "focus on security implications") |
| `--deep` | No | Extended analysis with critical analysis, counterarguments, and action items |

## Workflow

### Step 0: Config & Prerequisites

1. Check for `.claude/research-toolkit.local.md`
   - If file exists: parse YAML frontmatter, look for `kcap:` key
   - If file exists but no `kcap:` key: append defaults (preserve other content)
   - If file missing: prompt user to create with defaults
2. Apply defaults for any missing config values:
   - `output_path: ~/Documents/kcap`
   - `subfolder: "captures"`
   - `synthesis_model: sonnet`
   - `default_mode: standard`
   - No vault integration
3. Validate `subfolder` matches `^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$` — reject `..`, absolute paths
4. Validate `output_path` is writable — `mkdir -p` if missing
5. Check tool availability and report capabilities
6. Load [references/tool-setup.md](references/tool-setup.md) for install commands if tools missing

**Config format** (`.claude/research-toolkit.local.md` YAML frontmatter):
```yaml
kcap:
  output_path: ~/obsidian-vault
  vault_name: "My Vault"        # Optional — enables Obsidian URI
  subfolder: "kcap"
  default_tags: []
  synthesis_model: sonnet        # sonnet | opus
  default_mode: standard         # standard | deep (--deep flag overrides)
```

### Step 1: URL Validation

1. Require `https://` scheme — reject all others
2. Reject control characters and shell metacharacters
3. Block private/reserved IPs (SSRF prevention)
4. Use `--` before URL in ALL CLI calls (argument injection prevention)
5. Load [references/extractors.md](references/extractors.md) for validation regex and SSRF rules

### Step 2: Duplicate Check

1. Normalize the URL (strip tracking params, canonicalize youtube/twitter IDs)
2. `grep -rl` the normalized URL in the output directory
3. If duplicate found: show existing file path and date, prompt user:
   - **Update** — overwrite existing note
   - **New** — create separate note with `-N` suffix
   - **Skip** — abort capture
4. Load [references/extractors.md](references/extractors.md) for normalization rules

### Step 3: Content Extraction

1. Create isolated temp directory: `mktemp -d "${TMPDIR:-/tmp}/kcap-XXXXXXXX"` + `chmod 700`
2. Detect URL type (twitter, youtube, web) via regex
3. Route to appropriate extraction handler with fallback chain:
   - **Web**: trafilatura → html2text → FAIL
   - **YouTube**: youtube-transcript-api → yt-dlp subtitles → FAIL
   - **Twitter/X**: bird-cli → FAIL
4. Validate extraction output (minimum 50 words)
5. Check content size: if >15,000 words, truncate with notice
6. Load [references/extractors.md](references/extractors.md) for extraction commands and fallback chains

### Step 4: YouTube Metadata (YouTube URLs only)

1. Run `yt-dlp --dump-json --skip-download` for title, channel, duration, chapters
2. If yt-dlp unavailable: metadata will be inferred by synthesis sub-agent
3. Load [references/extractors.md](references/extractors.md) for metadata extraction commands

### Step 5: Synthesis (Sub-Agent)

1. Determine mode:
   - `--deep` flag on invocation → deep mode
   - Config `default_mode: deep` → deep mode
   - Otherwise → standard mode
2. Determine model: read `config.kcap.synthesis_model` (default: `sonnet`)
3. Spawn sub-agent via Task tool:
   - `subagent_type: "Explore"` (NO Write, Edit, Bash, or Task)
   - `model:` from config (`"sonnet"` or `"opus"`) — passed as Task tool parameter
4. Sub-agent prompt includes:
   - Content in `<external_content>` tags
   - Metadata (YouTube JSON or URL/type info)
   - User's focus question (if provided)
   - JSON schema for the appropriate mode
5. Extract JSON from response (handle markdown fences, preamble text)
6. If invalid JSON: retry once with corrective prompt
7. Validate required fields: `title`, `tldr`, `summary`, `takeaways`, `tags`
8. Sanitize all field content before use
9. Load [references/output-templates.md](references/output-templates.md) for prompts, schemas, and sanitization rules

**Mode × Model combinations:**

| | Standard | Deep |
|---|---------|------|
| **Sonnet** | Fast daily capture | Extended analysis, lower cost |
| **Opus** | High-quality summary | Maximum quality + depth |

### Step 6: Assemble & Write

1. Build markdown from validated JSON + content-type template (article/video/tweet)
2. Generate filename: `YYYY-MM-DD-slug.md` (slug: lowercase, hyphens, max 50 chars)
3. Handle collisions: append `-2`, `-3`, etc. if filename exists for different URL
4. Atomic write: write to temp file in WORK_DIR → validate non-empty UTF-8 → `mv` to final path
5. Create output directory if needed (`mkdir -p`)
6. Load [references/output-templates.md](references/output-templates.md) for template assembly

### Step 7: Cleanup & Output

1. Remove temp directory: `rm -rf "$WORK_DIR"`
2. Report file path to user
3. If `vault_name` configured: generate Obsidian URI and attempt `open` (suppress errors)
4. If no `vault_name`: report file path only
5. Load [references/error-handling.md](references/error-handling.md) for cleanup failure handling

## Error Handling

| Error | Behavior |
|-------|----------|
| Config missing | Use defaults, prompt to create |
| Output dir missing | `mkdir -p` and continue |
| Output dir not writable | FAIL with message |
| URL not https:// | FAIL: "Only https:// URLs supported" |
| All extraction tools missing | FAIL with install commands |
| One tool in chain missing | Fallback to next |
| Extraction returns empty | FAIL: "No content extracted" |
| Network timeout | FAIL after 60s |
| Sub-agent invalid JSON | Retry once, then FAIL with raw content path |
| Duplicate URL detected | Prompt: Update / New / Skip |
| Cleanup fails | Warn but succeed |
| Obsidian URI fails | Silently continue |

Full error matrix with recovery procedures: [references/error-handling.md](references/error-handling.md)

## Known Limitations

- **JavaScript-rendered pages:** SPAs and client-side rendered content may extract
  poorly. trafilatura and curl do not execute JavaScript.
- **Paywalled/login-gated content:** Pages requiring authentication will fail or
  return only preview text.
- **Non-English YouTube transcripts:** Extraction targets English subtitles
  (`--sub-lang en`). Videos with only non-English transcripts will fail.
- **Twitter/X authentication:** Requires bird-cli with valid browser cookies.
- **Content size:** Extractions >15,000 words are truncated. Deep mode on large
  content may incur higher API costs.

## Headless / Automation

kcap can be invoked via `claude -p "kcap URL [focus]"` for Raycast or automation.
The synthesis model and mode are controlled by the config file, not the CLI `--model`
flag (which sets the orchestrator model, not the sub-agent).
