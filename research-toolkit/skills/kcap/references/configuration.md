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
letters, numbers, hyphens, underscores, and `/`. Tags must be lowercase and hyphenated.
Modes are `standard`, `deep`, and `full`; profiles are `fast`, `balanced`, and `deep`.
Unknown fields and unsupported schema versions fail.

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

Profile mapping:

| Profile | Claude | Codex reasoning |
|---|---|---|
| `fast` | `haiku` | `low` |
| `balanced` | `sonnet` | `medium` |
| `deep` | `opus` | `high` |

Deep and full capture force `balanced`. `RESEARCH_TOOLKIT_RUNTIME=claude|codex`
selects a runtime explicitly. `RESEARCH_TOOLKIT_NONINTERACTIVE=1` makes the controller
own noninteractive confirmation and duplicate behavior; a host must not invent a
collision or consent default. The controller never opens Obsidian.

## Codex authentication

`RESEARCH_TOOLKIT_CODEX_AUTH` accepts `auto`, `oauth`, or `api_key` and applies only
when the selected runtime is Codex. `auto` prefers file-backed OAuth and falls back to
an explicitly configured API key only if OAuth is unavailable. `oauth` requires a
readable regular OAuth file; the controller copies it into a private temporary App
Server home, verifies the source snapshot again at that immediate copy boundary, and
removes the copy during cleanup. This does not claim that the independently managed
source can never be refreshed later. `api_key` requires `OPENAI_API_KEY` and uses an
ephemeral API-key login. API-key model use is billed to that API account and is not an
OAuth Desktop session.

Authentication material is never included in controller JSON, host diagnostics, model
prompts, or App Server event reports. The live-acceptance API-key leg is intentionally
separate: it is requested only by `RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY`; an ambient
`OPENAI_API_KEY` must not cause the test leg to run.

The public `capture --project-dir PATH` operation resolves `output_path` relative to the
supplied project directory when needed, joins it with `subfolder`, and uses the absolute
result internally. Hosts must not call the low-level `config` command or independently
join configuration fields.
