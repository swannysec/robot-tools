# Configuration

The portable configuration location is `~/.config/robot-tools/research-toolkit.json`.

```json
{
  "schema_version": 1,
  "starduster": {
    "output_path": "~/obsidian-vault/GitHub Stars",
    "subfolder": "tools/github",
    "vault_name": null,
    "synthesis_profile": "balanced",
    "synthesis_batch_size": 25
  }
}
```

`output_path` must be a non-empty string. `subfolder` is a relative path made of
letters, numbers, hyphens, underscores, and `/`; it cannot contain `..`. `vault_name`
is either a string or `null`. `synthesis_batch_size` is a positive bounded integer.
Profiles are `fast`, `balanced`, and `deep`. Unknown fields, malformed JSON, missing
selected files, unsupported schema versions, and an absent `starduster` section in an
otherwise selected JSON configuration fail safely.

## First-run destination

When neither an explicit `--output-dir` nor a Starduster configuration section is
available, `sync` returns `output_path_required` before contacting GitHub or starting
synthesis. Its safe details include a suggested dedicated catalog directory. An
interactive host asks once for the user's exact directory, runs:

```text
python3 "$STARDUSTER_SKILL_DIR/scripts/starduster.py" configure --output-dir "PATH"
```

and retries the original `sync` command. `configure` atomically updates the normal
user configuration file with mode `0600`, preserves the Kcap section and unrelated
valid settings, stores the selected directory as `output_path`, and uses `subfolder:
"."` so that directory is the exact catalog root.

`sync --output-dir PATH` is a one-run, non-persistent override. A configuration named
by `RESEARCH_TOOLKIT_CONFIG` is never changed by `configure`; a caller using it must
update that selected file itself or pass `--output-dir`. Noninteractive and headless
runs return the same machine-readable `output_path_required` result instead of
prompting.

## Precedence

1. File named by `RESEARCH_TOOLKIT_CONFIG`
2. `~/.config/robot-tools/research-toolkit.json`
3. Project `.claude/research-toolkit.local.md` through research-toolkit `0.6.x`
4. Built-in non-destination defaults after the user supplies `--output-dir`

Public `sync` does not use the built-in destination silently. Without a Starduster
section or `--output-dir`, it returns `output_path_required` so the host can ask once.

An explicitly selected missing configuration fails. A legacy file is read only; the
controller never appends defaults or modifies it. A present legacy file without a
`starduster` section fails instead of silently using defaults. Omitted fields in a
valid legacy Starduster section retain their historical defaults during the compatibility
period. Legacy `main_model` is ignored with a migration warning. Legacy
`synthesis_model` maps as follows:

| Legacy model | Portable profile | Claude model | Codex reasoning |
|---|---|---|---|
| `haiku` | `fast` | `haiku` | `low` |
| `sonnet` | `balanced` | `sonnet` | `medium` |
| `opus` | `deep` | `opus` | `high` |

## Runtime and interaction

The controller selects Claude or Codex from known host indicators when exactly one host
is present. `RESEARCH_TOOLKIT_RUNTIME=claude|codex` explicitly overrides that detection
for automation and unusual hosts. Unknown and ambiguous environments fail rather than
guessing. `RESEARCH_TOOLKIT_NONINTERACTIVE=1` disables prompts and application opening.
A rate estimate that needs confirmation returns `confirmation_required` with bounded
core and GraphQL call estimates, the percentage estimate, the 25 percent threshold, and
rerun information; it does not assume approval.

The controller resolves a relative `output_path` from `--project-dir`, then joins the
validated subfolder. A configured vault produces a URL-encoded `obsidian_uri` only; the
controller never invokes `open` or another app launcher.

## Codex authentication

`RESEARCH_TOOLKIT_CODEX_AUTH` accepts `auto`, `oauth`, or `api_key` when Codex is the
selected runtime. `auto` prefers file-backed OAuth and uses API-key authentication only
when OAuth is unavailable and `OPENAI_API_KEY` was explicitly configured. `oauth`
requires a readable, regular OAuth file. `api_key` requires `OPENAI_API_KEY` and starts
an ephemeral API-key login; billing then belongs to that API account rather than an
OAuth Desktop session.

The adapter opens the OAuth source without following symlinks, copies it to a private
`0600` App Server home, verifies that the source did not change across that copy
boundary, and removes the private copy during cleanup. A later Desktop credential
refresh is allowed and does not invalidate completed synthesis. Credentials never
appear in prompts, controller JSON, model output, event
reports, or host diagnostics. The optional live
API-key acceptance leg is requested only through
`RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY`; an ambient `OPENAI_API_KEY` never requests it.
