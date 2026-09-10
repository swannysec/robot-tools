# Configuration

The portable configuration path is `~/.config/robot-tools/research-toolkit.json`.

```json
{
  "schema_version": 1,
  "kcap": {
    "output_path": "~/Documents/kcap",
    "subfolder": "captures",
    "vault_name": null,
    "default_tags": [],
    "default_mode": "standard",
    "synthesis_profile": "fast"
  }
}
```

`output_path` must be a non-empty string. `subfolder` must be a relative path made of
letters, numbers, hyphens, underscores, and `/`; `"."` is the sole special value and
means the exact `output_path` itself. Other dot forms, including `./captures` and
`..`, are not valid. Tags must be lowercase and hyphenated.
Modes are `standard`, `deep`, and `full`; profiles are `fast`, `balanced`, and `deep`.
Unknown fields and unsupported schema versions fail.

## Output destination setup

The configured destination is the exact `output_path` selected by the user with
`subfolder` set to `"."`; the resulting note directory is that exact destination, not an
extra implicit `captures` directory. An interactive host that receives
`output_path_required` asks once for the exact destination (suggest
`~/Documents/kcap/captures`) and runs:

```text
python3 "$KCAP_SKILL_DIR/scripts/kcap.py" configure --output-dir "$OUTPUT_DIR"
```

`configure` updates only the portable user JSON. It writes a schema-version-1 document
with a private `0600` mode through an atomic merge, preserving valid unrelated settings
such as another toolkit section. It never modifies a file explicitly selected with
`RESEARCH_TOOLKIT_CONFIG`, a project legacy configuration, or any legacy file. A selected
configuration is therefore intentionally immutable to this setup flow and returns
`config_selected`.

This is a narrow public state transition, not an alternate capture command. When a host
needs approval for it, the approval may authorize only the write to
`~/.config/robot-tools/research-toolkit.json`; it must not elevate `capture` or grant
access to the selected output directory.

`capture --output-dir PATH` is a one-off output override. It applies only to that capture
and never persists or rewrites any configuration file. In a noninteractive host,
`output_path_required` stops rather than choosing or configuring a destination.

An exact configured path may retain `vault_name`, but an Obsidian URI is optional. The
controller emits one only when it can prove a vault-relative path below the configured
output root; if it cannot prove that relationship (including a note directly at the
root), it suppresses the URI rather than guessing.

## Precedence

1. File named by `RESEARCH_TOOLKIT_CONFIG`
2. User JSON above
3. Project `.claude/research-toolkit.local.md` through research-toolkit `0.6.x`
4. Built-in defaults when no configuration exists

An explicitly selected missing file fails. A present JSON file without a `kcap`
section fails. A legacy file must contain a valid `kcap` section; omitted fields in
that section retain the historical built-in defaults during the compatibility period.
The legacy file is never modified. A present legacy file without a `kcap` section does
not silently fall back to defaults.

Legacy model mapping is `haiku -> fast`, `sonnet -> balanced`, and `opus -> deep`.
After the `0.6.x` compatibility period, a legacy-only setup must fail with migration
instructions rather than use defaults.

Profile mapping remains the configuration and legacy-migration contract and controls
Claude selection:

| Profile | Claude |
|---|---|
| `fast` | `haiku` |
| `balanced` | `sonnet` |
| `deep` | `opus` |

Deep and full capture force the effective `synthesis_profile` to `balanced`; for Claude,
that selects `sonnet`. Codex uses fixed selection by effective capture mode: standard is
`gpt-5.6-luna` with medium effort, deep is `gpt-5.6-luna` with high effort, and full
non-video capture is `gpt-5.6-luna` with medium effort. Full YouTube capture falls back
to standard and therefore uses Luna with medium effort.

`RESEARCH_TOOLKIT_RUNTIME=claude|codex` selects a runtime explicitly. Without that
override, Codex or ChatGPT Desktop host indicators select Codex; both Claude and Codex
indicators fail as ambiguous. `RESEARCH_TOOLKIT_NONINTERACTIVE=1` makes the controller
own noninteractive confirmation and duplicate behavior; a host must not invent a
collision or consent default. The controller never opens Obsidian.

## Codex authentication

`RESEARCH_TOOLKIT_CODEX_AUTH` accepts `auto`, `oauth`, or `api_key` and applies only
when the selected runtime is Codex. `auto` prefers file-backed Desktop OAuth and falls
back to an explicitly configured API key only if OAuth is unavailable. Separately, when
the caller does not provide `--codex-bin`, the adapter prefers the bundled ChatGPT
Desktop Codex binary and then `codex` on `PATH`. `oauth` requires a readable regular
OAuth file; the controller copies it into a private temporary App Server home, verifies
the source snapshot again at that immediate copy boundary, and removes the copy during
cleanup. This does not claim that the independently managed source can never be
refreshed later. When that immediate boundary check succeeds, its safe report records
`auth_copy_boundary_verified: true` alongside the limited `source_unchanged` evidence.
`api_key` requires `OPENAI_API_KEY` and uses an ephemeral API-key login.
API-key model use is billed to that API account and is not an OAuth Desktop session.

Authentication material is never included in controller JSON, host diagnostics, model
prompts, or App Server event reports. The live-acceptance API-key leg is intentionally
separate: it is requested only by `RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY`; an ambient
`OPENAI_API_KEY` must not cause the test leg to run.

The public `capture --project-dir PATH` operation resolves `output_path` relative to the
supplied project directory when needed, joins it with `subfolder`, and uses the absolute
result internally. Hosts must not call the low-level `config` command or independently
join configuration fields.
