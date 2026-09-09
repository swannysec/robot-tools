# Codex desktop runtime

Local Codex in the desktop app discovers the shared `SKILL.md` through its catalog.
Resolve `KCAP_SKILL_DIR` to the catalog-reported package directory, then invoke the
public controller once. Do not ask the privileged Codex host agent to read or summarize
raw content.

```text
python3 "$KCAP_SKILL_DIR/scripts/kcap.py" capture "$URL" \
  [--mode standard|deep|full] [--focus TEXT] [--project-dir PATH] \
  [--output-dir PATH] [--collision suffix|replace|skip] [--confirm-large] \
  [--preserve-on-failure]
```

Handle only the controller's safe JSON. If it returns `confirmation_required` during
interactive use, use its safe details to ask for large-capture consent or a collision
choice, then rerun that same command with the chosen explicit `--confirm-large` or
`--collision` flag. `skipped_duplicate` is a terminal success. Noninteractive behavior
is controller-owned. The URL argument is the raw shell-quoted URL, never a Markdown link
expression.

If an interactive capture returns `output_path_required`, ask once for the exact
destination (suggest `~/Documents/kcap/captures`), run
`python3 "$KCAP_SKILL_DIR/scripts/kcap.py" configure --output-dir "$OUTPUT_DIR"`, and
automatically retry the original capture. Approval for `configure` may cover only the
write to `~/.config/robot-tools/research-toolkit.json`; do not elevate capture. A
noninteractive host stops instead. For `write_pending`, request approval naming the
returned output target, then use all returned fields in:

```text
python3 "$KCAP_SKILL_DIR/scripts/kcap.py" commit-output "$PENDING" \
  --output-root "$ROOT" --output-dir "$DIR" --filename "$FILE" \
  --collision "$POLICY" --capsule-digest "$DIGEST"
```

Prefer structured argv; otherwise quote every value. The digest binds the capsule and
the target fields bind publication. Do not elevate capture, inspect the capsule or note,
replace fields, or replace the normal safe controller result.

## Runtime selection and synthesis model

In Codex or ChatGPT Desktop, the controller selects the Codex adapter when it detects
one of `CODEX_SESSION_ID`, `CODEX_THREAD_ID`, `CODEX_SANDBOX`, or `CODEX_CI`.
`RESEARCH_TOOLKIT_RUNTIME=claude|codex` explicitly overrides host detection. If both
Claude and Codex indicators are present without an override, the controller fails as
ambiguous instead of selecting either adapter.

Codex synthesis uses the following fixed selection:

| Effective capture mode | Model | Effort |
|---|---|---|
| `standard` | `gpt-5.6-luna` | `medium` |
| `deep` | `gpt-5.6-luna` | `high` |
| `full` for articles and Twitter/X | `gpt-5.6-luna` | `medium` |
| `full` for YouTube | Falls back to `standard` | `medium` |

A host or orchestrator starting a capture should prefer `gpt-5.6-luna` with medium
effort. This is a recommendation for task creation only: the skill cannot change the
model of an already-running Codex task. `agents/openai.yaml` has no supported
model-selection field, so the package does not declare one there.

## Authentication

`RESEARCH_TOOLKIT_CODEX_AUTH` selects the Codex authentication mode:

| Value | Behavior |
|---|---|
| `auto` (default) | Prefer file-backed Desktop OAuth. Use API-key authentication only when OAuth is unavailable and `OPENAI_API_KEY` was explicitly configured. |
| `oauth` | Require a readable, regular OAuth authentication file. Fail closed if it is unavailable or unsafe to copy. |
| `api_key` | Require `OPENAI_API_KEY` and start an ephemeral API-key login. API-key use is billed to that API account; it is distinct from an OAuth-authenticated Desktop session. |

OAuth source material is never modified by this adapter. The adapter snapshots a regular,
readable OAuth file, copies that snapshot to a private `0600` App Server home, checks the
source again immediately after the copy, and removes the private copy during cleanup. The
resulting `source_unchanged` evidence is limited to that immediate copy boundary; it does
not claim that a long-lived OAuth source cannot be independently refreshed later. The
acceptance report records `auth_copy_boundary_verified: true` when that immediate copy
boundary is verified. It does not turn `source_unchanged` into a claim about a later
independent refresh. The adapter never passes OAuth material or an API key through a
prompt, result, event report,
or host diagnostic. The acceptance runner requests its optional API-key live leg only
through `RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY`; an ambient `OPENAI_API_KEY` does not
request that leg.

## Isolated App Server

Codex is an external host dependency, not a file supplied by this package. When the
caller does not supply an explicit `--codex-bin`, the adapter prefers the bundled ChatGPT
Desktop Codex binary and then falls back to `codex` on `PATH`; an explicit executable
takes precedence over both. In the default automatic path, this bundled Desktop binary
and Desktop OAuth are preferred together when available. It starts a short-lived stdio
App Server and creates one ephemeral thread for the controller-owned synthesis.

The least-authority boundary permits Code Mode `exec` and `wait` only for bounded
computation. That allowlist does not approve arbitrary process or filesystem access.
Filesystem, process, network, browser/computer, MCP, app, plugin, nested-agent, dynamic
tool, external-tool, shell-tool, and direct-artifact-reader capabilities require direct
enforcement evidence before use: the negotiated configuration or attestation must govern
the effect, and lifecycle/event checks and tests must confirm it. This adapter requires
the App Server to fail closed rather than accept any such capability without that evidence.

The model receives empty thread and turn environments and empty workspace roots; the
App Server process receives only the minimal launch environment needed to run. Its
permission profile denies network access and access to the filesystem root and temporary root. The
adapter must verify the negotiated capability surface before use, record the Code Mode
lifecycle, and reject any prohibited event. A sandbox is only one layer: it does not
authorize an effect it cannot govern.

The controller reads raw content from its private workspace, builds the synthesis input,
and the broker sends that input in the App Server `turn/start` request over its
broker-owned local stdio JSON-RPC transport. Private files therefore constrain the
controller-side artifact boundary; they are not the only path by which raw input reaches
the isolated computation. The adapter validates and sanitizes the structured result,
writes it inside the private workspace, and returns only safe status metadata. It never
returns raw transcript, model output, OAuth data, API-key data, prompts, or tool payloads
to the privileged host.

The broker opts out of incremental agent-message deltas, token-usage updates, and other
passive lifecycle or status notifications that kcap does not consume. It still derives
the authoritative synthesis result from `item/completed` and requires `turn/completed`.
The remaining stream is bounded independently by the operation timeout, per-message and
total-output byte limits, and a 16,384-event ceiling. The event ceiling is a final guard
against an abnormal server stream, not a normal-workload budget.

When explicitly requested, the adapter writes one bounded, redacted acceptance report for
that successful invocation. It records the selected binary and version, temporary catalog
source, one public `kcap.py capture` command, App Server transport and lifecycle,
authentication copy-boundary and cleanup evidence, sandbox/environment posture, selected
synthesis model and effort, and prohibited-event count. The report is run-scoped evidence,
not a claim that a live-host acceptance has passed in another environment or at another
time. Output success is determined from the resulting filesystem state, not final host
prose.

## Confirmation, retry, and failure

The public controller remains the only host action. On `confirmation_required`, the host
uses the safe structured details to ask for consent or a collision choice and reruns the
same command with the explicit selected flag. The adapter retries one invalid structured
synthesis response inside a new isolated App Server session, then returns a structured
failure. It fails closed when authentication, App Server startup, capabilities, the
permission profile, lifecycle, event inspection, validation, or cleanup cannot satisfy
this boundary.

Use the internal adapter's `--dry-run` only for focused conformance testing. It returns
safe App Server configuration evidence and schema identity without invoking a model. Do
not orchestrate `extract`, `codex-synthesize`, `render`, or artifact readers from the
host.
