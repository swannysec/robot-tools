# Error Handling Reference

Complete error behavior matrix and recovery procedures for kcap.

## Error Matrix

### Configuration Errors

| Error | Detection | Behavior | User Message |
|-------|-----------|----------|--------------|
| Config file missing | `.claude/research-toolkit.local.md` not found | Use defaults, prompt to create | "No kcap config found. Using defaults (output: ~/Documents/kcap). Create .claude/research-toolkit.local.md to customize." |
| Config file exists, no kcap key | File exists but lacks `kcap:` section | Append defaults to file | "Added kcap defaults to existing config. Edit .claude/research-toolkit.local.md to customize." |
| Output dir missing | `output_path` directory doesn't exist | `mkdir -p` and continue | "Created output directory: {path}" |
| Output dir not writable | Write permission check fails | **FAIL** | "Cannot write to {path}. Check permissions or update kcap.output_path in config." |
| Invalid subfolder | Doesn't match `^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$` | **FAIL** | "Invalid subfolder '{value}'. Use only letters, numbers, hyphens, underscores, and forward slashes." |
| Invalid synthesis_model | Not `sonnet` or `opus` | Default to `sonnet`, warn | "Unknown synthesis_model '{value}'. Defaulting to sonnet." |
| Invalid default_mode | Not `standard` or `deep` | Default to `standard`, warn | "Unknown default_mode '{value}'. Defaulting to standard." |

### URL Errors

| Error | Detection | Behavior | User Message |
|-------|-----------|----------|--------------|
| Not https:// | Scheme check | **FAIL** | "Only https:// URLs are supported. Got: {scheme}://" |
| Contains shell metacharacters | Regex check | **FAIL** | "URL contains potentially dangerous characters. Please provide a clean URL." |
| Resolves to private IP | SSRF check | **FAIL** | "URL resolves to a private/reserved IP address ({ip}). This may be a security risk." |
| Malformed URL | Parse failure | **FAIL** | "Could not parse URL. Please provide a valid https:// URL." |
| Empty URL | No URL provided | **FAIL** | "No URL provided. Usage: kcap <url> [focus question]" |

### Extraction Errors

| Error | Detection | Behavior | User Message |
|-------|-----------|----------|--------------|
| All tools missing (web) | Neither trafilatura nor html2text found | **FAIL** | "No web extraction tools found. Install: `pip install trafilatura`" |
| All tools missing (youtube) | Neither youtube-transcript-api nor yt-dlp found | **FAIL** | "No YouTube extraction tools found. Install: `pip install youtube-transcript-api`" |
| bird not installed (twitter) | bird command not found | **FAIL** | "bird-cli not found. Install: `brew install steipete/formulae/bird`" |
| Primary tool fails | Non-zero exit or empty output | Try fallback | (silent — falls through to fallback) |
| All tools fail | Fallback also fails | **FAIL** | "Content extraction failed with all available tools. The URL may be unreachable or require authentication." |
| Empty content | <50 words extracted | **FAIL** | "Extracted content is too short ({N} words, minimum 50). The page may require JavaScript, authentication, or contain primarily non-text content." |
| Network timeout | >60 seconds | **FAIL** | "Request timed out after 60 seconds. The server may be slow or unreachable." |
| Content too large | >15,000 words | Truncate + warn | "Content truncated to first 15,000 of {N} words." |
| Content too large + deep mode | >15,000 words + deep mode | Warn + confirm | "Content is {N} words. Deep mode on large content may cost ~${estimate}. Proceed?" |

### Synthesis Errors

| Error | Detection | Behavior | User Message |
|-------|-----------|----------|--------------|
| Invalid JSON response | JSON parse fails | Extract JSON, retry once | (silent on first attempt) |
| Invalid JSON after retry | Second attempt also fails | **FAIL** with raw content | "Synthesis produced invalid output. Raw content saved to {temp_path} for manual review." |
| Missing required fields | Schema validation fails | **FAIL** with raw content | "Synthesis output missing required fields ({fields}). Raw content saved to {temp_path}." |
| `insufficient_content` error | Sub-agent returns error JSON | **FAIL** | "Content was too short or unclear for meaningful synthesis." |
| Sub-agent timeout | Task tool timeout | **FAIL** with raw content | "Synthesis timed out. Raw content saved to {temp_path}." |
| TL;DR too long | >30 words | Truncate to first 30 words + "..." | (silent truncation) |
| Invalid tags | Tags with spaces/special chars | Strip invalid, keep valid | (silent cleanup) |

### File Writing Errors

| Error | Detection | Behavior | User Message |
|-------|-----------|----------|--------------|
| File name collision (same URL) | Duplicate detection finds match | Prompt user | "This URL was already captured on {date}: {file}. Update existing / Create new / Skip?" |
| File name collision (different URL) | Same slug, different URL | Append `-N` suffix | "File name conflict. Saved as {filename-2}.md" |
| Write permission error | Write to temp file fails | **FAIL** | "Cannot write to output directory. Check permissions." |
| Move fails | `mv` from temp to final fails | **FAIL** (temp file preserved) | "Failed to save note. Temp file preserved at {temp_path}." |

### Post-Processing Errors

| Error | Detection | Behavior | User Message |
|-------|-----------|----------|--------------|
| Cleanup fails | `rm -rf` of WORK_DIR fails | Warn, succeed capture | "Note saved successfully. Warning: temp files at {WORK_DIR} could not be cleaned up." |
| Obsidian URI open fails | `open obsidian://` returns error | Silently continue | (file path reported as usual — no mention of Obsidian failure) |
| Obsidian not configured | No `vault_name` in config | Skip URI generation | (file path only — no Obsidian URI) |

## Recovery Procedures

### Manual Recovery: Raw Content Saved

When synthesis fails, the raw extracted content is saved to a temp file. The user can:
1. Read the temp file to review raw content
2. Re-run kcap with the same URL (fresh attempt)
3. Manually create a note from the raw content

### Config Reset

If config becomes corrupted:
1. Delete the `kcap:` section from `.claude/research-toolkit.local.md`
2. Re-run kcap — it will prompt to create defaults

### Temp File Cleanup

If temp files accumulate:
```bash
rm -rf ${TMPDIR:-/tmp}/kcap-*
```

This is safe to run at any time — active captures use unique directory names.

## Error Severity Levels

| Level | Meaning | Agent Behavior |
|-------|---------|---------------|
| **FAIL** | Cannot continue | Stop, report error, cleanup |
| **Warn** | Degraded but functional | Report warning, continue |
| **Silent** | Expected fallback | Continue without user-visible message |
