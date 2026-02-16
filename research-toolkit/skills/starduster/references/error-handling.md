# Error Handling Reference

Complete error behavior matrix and recovery procedures for starduster.

## Error Matrix

### Configuration Errors

| Error | Severity | Recovery | User Message |
|-------|----------|----------|--------------|
| Config file missing | WARN | Use defaults, prompt to create | "No starduster config found. Using defaults. Create .claude/research-toolkit.local.md to customize." |
| Config file exists, no starduster key | WARN | Append defaults to file | "Added starduster defaults to existing config." |
| Output dir missing | SILENT | `mkdir -p` and continue | "Created output directory: {path}" |
| Output dir not writable | FAIL | Stop | "Cannot write to {path}. Check permissions or update starduster.output_path in config." |
| Invalid subfolder | FAIL | Stop | "Invalid subfolder '{value}'. Use only letters, numbers, hyphens, underscores, and forward slashes. No '..' allowed." |
| Invalid synthesis_model | WARN | Default to `sonnet` | "Unknown synthesis_model '{value}'. Defaulting to sonnet." |
| Invalid synthesis_batch_size | WARN | Default to `25` | "Invalid batch size '{value}'. Defaulting to 25." |

### Authentication Errors

| Error | Severity | Recovery | User Message |
|-------|----------|----------|--------------|
| `gh` not installed | FAIL | Stop | "GitHub CLI (gh) not found. Install: `brew install gh`" |
| `jq` not installed | FAIL | Stop | "jq not found. Install: `brew install jq`" |
| `gh auth status` fails | FAIL | Stop | "Not authenticated with GitHub. Run `gh auth login` first." |
| Token lacks `repo` scope | FAIL | Stop | "GitHub token missing required scopes. Run `gh auth refresh -s repo`." |

### API Errors

| Error | Severity | Recovery | User Message |
|-------|----------|----------|--------------|
| Rate limit >10% usage | WARN | Report and continue | "This run will use ~{N} of {R} remaining API points ({P}%)." |
| Rate limit >25% usage | WARN | Ask to confirm | "This run needs ~{N} API points ({P}% of remaining budget). Continue or abort?" |
| Rate limit exceeded (403) | FAIL | Report reset time | "GitHub API rate limit exceeded. Resets at {time}. Try again later or use /starduster {limit} with a smaller limit." |
| 401 Unauthorized | FAIL | Stop | "GitHub authentication expired. Run `gh auth login`." |
| 404 Repo not found | WARN | Skip repo | (Silent — repo skipped, counted in summary) |
| 422 GraphQL error | WARN | Reduce batch, retry | "GraphQL query error. Retrying with smaller batch." |
| 502/503 Server error | WARN | Retry once | "GitHub server error. Retrying..." |
| Network timeout | FAIL | Stop with partial results | "Request timed out. {N} repos cataloged before failure." |
| Paginated response malformed | WARN | Try `jq 'flatten'` | (Silent — handled by normalization) |

### Synthesis Errors

| Error | Severity | Recovery | User Message |
|-------|----------|----------|--------------|
| Invalid JSON response | WARN | Extract JSON, retry once | (Silent on first attempt) |
| Invalid JSON after retry | WARN | Fall back to 1-at-a-time | "Batch synthesis failed. Processing repos individually." |
| Individual repo synthesis fails | WARN | Skip repo | "Could not synthesize {full_name}. Skipping." |
| Missing required fields | WARN | Use defaults | (Silent — auto-fill from metadata) |
| Category not in allowed list | WARN | Use "Uncategorized" | (Silent — auto-corrected) |
| Invalid topic format | WARN | Strip invalid topics | (Silent — topics removed) |
| Summary exceeds 300 chars | WARN | Truncate | (Silent — truncated at sentence boundary) |
| Sub-agent timeout | WARN | Retry batch, then 1-at-a-time | "Synthesis batch timed out. Retrying individually." |

### Batch Failure Cascade

When a full batch of `synthesis_batch_size` repos fails:

1. **First attempt:** Send full batch to sub-agent
2. **If fails:** Retry same batch once (may be transient)
3. **If retry fails:** Fall back to processing each repo in the failed batch individually (1-at-a-time)
4. **Individual failures:** Skip only the specific repos that fail individually
5. **Report:** "Batch {N} failed. Processed {X}/{Y} repos individually. {Z} skipped."

### File Writing Errors

| Error | Severity | Recovery | User Message |
|-------|----------|----------|--------------|
| Write permission denied | WARN | Skip file, continue | "Cannot write {filename}. Skipping. Check permissions." |
| Filename sanitization produces empty | WARN | Use fallback name | (Silent — uses `unknown-{timestamp}`) |
| Path traversal detected | FAIL | Skip file | "Path traversal detected in filename for {full_name}. Skipping." |
| Disk full | FAIL | Stop with partial results | "Disk full. {N} repos cataloged before failure." |
| YAML assembly produces invalid YAML | WARN | Skip repo | "Invalid YAML for {full_name}. Skipping." |

### Post-Processing Errors

| Error | Severity | Recovery | User Message |
|-------|----------|----------|--------------|
| Temp dir cleanup fails | WARN | Report, succeed | "Note saved. Warning: temp files at {WORK_DIR} could not be cleaned up." |
| Obsidian URI open fails | SILENT | Continue | (File path reported as usual) |
| Obsidian not configured | SILENT | Skip URI | (File path only) |
| Hub note write fails | WARN | Skip hub, continue | "Could not write hub note {name}. Continuing." |
| Base file write fails | WARN | Skip base, continue | "Could not write index {name}. Continuing." |

---

## Recovery Procedures

### Partial Run Recovery

If starduster fails mid-run, the vault is in a consistent state because:
- Each repo note is written independently (no transactional dependency)
- Hub notes are regenerated from scratch on every run
- `.base` files are regenerated from scratch on every run

To recover: simply re-run `/starduster`. The diff algorithm will detect already-cataloged
repos and skip to new ones.

### Temp File Cleanup

If temp files accumulate from failed runs:

```bash
rm -rf ${TMPDIR:-/tmp}/starduster-*
```

This is safe to run at any time — active captures use unique directory names.

### Config Reset

If config becomes corrupted:
1. Delete the `starduster:` section from `.claude/research-toolkit.local.md`
2. Re-run `/starduster` — it will prompt to create defaults

### Rate Limit Recovery

If rate-limited mid-run:
1. Check reset time: `gh api /rate_limit | jq '.resources.graphql.reset | todate'`
2. Wait for reset, then re-run with same or smaller limit
3. Already-cataloged repos will be skipped automatically

---

## Error Severity Levels

| Level | Meaning | Agent Behavior |
|-------|---------|---------------|
| **FAIL** | Cannot continue | Stop, report error, cleanup temp files |
| **WARN** | Degraded but functional | Report warning, continue with remaining repos |
| **SILENT** | Expected fallback | Continue without user-visible message |

---

## Accepted Residual Risks

See the SKILL.md Security Model section for the canonical list of accepted residual risks.
They are documented there to avoid duplication.
