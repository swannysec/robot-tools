# Claude Code runtime

Use this adapter only when the current host is Claude Code. The shared workflow and
output contracts remain authoritative; this file defines dispatch mechanics.

## Model assignment

| Role | Model | Effort | Isolation |
|---|---|---|---|
| Three discovery roles | `claude-opus-5-5` | high | Fresh CLI executions; no discovery output shared between them |
| Fix author | `claude-opus-5-5` | high | Separate author agent on the authorized fix branch; never verifies its own patch |
| Native verifier, including fix verification | `claude-opus-5-5` | high | Fresh CLI execution; receives only its staged verification packet |
| Cross-provider verifier, including fix verification | `gpt-6.1-sol` | high | Fresh Codex execution under a read-only permission profile with a temporary `CODEX_HOME` |
| Intake roles (GHSA mode) | `claude-haiku-5-5` | high | Fresh `claude -p` execution with no tools, no network, and no GitHub token |

The table gives the expected models. The analysis tier follows the orchestrating model:
the orchestrator may identify its own model from its context or harness metadata, and if
it is not `claude-opus-5-5`, it stops and asks the user before dispatch. `gpt-6.1-sol` is
the default cross-provider model; `--cross-model <model>` overrides it with another
OpenAI model, recorded in provenance. Intake roles make no security judgment, so the
cross-provider rule does not apply to them.

Pin `claude-opus-5-5` and high effort on every native role dispatch. The fix author
remains a separate author agent on the authorized fix branch and follows the shared
fix workflow and its write authorization and gates; the analysis restrictions below do
not prohibit its authorized writes.

## Host launch and native capability

Run the orchestrating host in an execution-enabled permission mode that authorizes
bounded computation and provider dispatch. Auto mode is suitable when available;
preflight the actual command forms. A tool listing alone is never proof that a role
can execute. Supply authentication externally. Never include
credentials or organization-specific secret references in the package or packets.

Before analysis, exercise the same fresh CLI settings and isolation used for roles.
Probe a bounded, non-sensitive file read and a complete role-schema fixture, including
required empty fields. Verify the actual model from run metadata, structured output and
cold-input read isolation. Print-mode output does not report the effective effort level,
so record high effort as requested and unverified. Failure to establish a required
capability makes the corresponding role `MISSING` and the run `INCOMPLETE`.

Native children use an explicit environment allowlist. Include the Anthropic credential
only for native Claude execution, and exclude host session indicators and
`CLAUDE_CODE_EFFORT_LEVEL` (it overrides `--effort`). Cross-provider
Codex children must exclude Anthropic credentials. Do not load session state, user or
project instructions, or memory into a native analysis child.

## Preflight

Before sending report or source material to another provider:

1. Confirm the user or organization permits the relevant material to be sent to OpenAI.
2. Resolve Codex from an explicitly configured executable first, then `codex` on `PATH`.
3. Check the selected executable's help output for `exec`, `--model`, `--output-schema`,
   `--disable`, and reasoning-effort configuration, and that its version supports permission
   profiles (verified with codex-cli 0.162.0). The intake launch form under "GHSA mode" also
   uses `--sandbox` and `--ignore-user-config`.
4. Confirm authentication with a bounded non-sensitive probe; configuration or a saved
   login alone is not proof that execution works.
5. Record the executable version and effective model/effort in run provenance.

If a required capability or authorization is absent, mark the cross-provider role
`MISSING` and the run `INCOMPLETE`. Do not silently choose another model, provider, or
same-family verifier. A model change that runtime metadata reports after dispatch is a
disclosed role fallback under `orchestrator-contract.md`, never a silent substitution.

## Model and refusal metadata

Never pass `--fallback-model` or a `fallbackModel` setting to a child. Claude Code also
re-runs requests that its safety classifier flags on an older model by default (for
example, cybersecurity-flagged Opus 5.5 requests on Opus 4.8). Leave that behavior on and
detect it; the skill discloses it as a role fallback. Read these fields from each child:

- Actual model: the keys of the result's `modelUsage` object (each with `canonicalModel`
  and `provider`), and `message.model` on `stream-json` assistant events. Any key other
  than the requested model is a fallback.
- Provider-side switch: `stream-json` system events with subtype `model_refusal_fallback`
  (`original_model`, `fallback_model`).
- Hard refusal: system subtype `model_refusal_no_fallback`, a non-zero `safety_stops`, or
  a refusal reported through `stop_reason` or `terminal_reason`, with no schema output.
- Non-model failure: `is_error: true` or `terminal_reason` values such as `api_error`,
  which are `FAILED`, not refusals.

The refusal fields were identified from documentation and the CLI, not from an induced
refusal; live verification confirms them. Use `stream-json` output when the role needs the
system events.

## Native dispatch

Freeze all three discovery prompts before dispatch. Launch them in parallel as fresh
`claude -p` executions using JSON output and `--json-schema` with the full discovery role schema, exact
`claude-opus-5-5` model and high effort. Use bare, restricted, safe execution
(`--bare --restricted --safe-mode`; `--restricted` is what keeps user settings,
including their environment block, out of the child, which `--bare` alone does not) with only the read tools required by the role; disable Agent and
delegation. Close standard input. Each child receives
only its frozen packet, and no session, instruction, or memory loading. Do not expose
one discovery result to another role.

Claude Code 2.1.322 under `--restricted` offers no `Grep` or `Glob` tool (`--tools
Read,Grep,Glob` yields only `Read`), and `Read` on a directory fails with `EISDIR`. A
probed working form for read-only roles is `--restricted --safe-mode --permission-mode
dontAsk --tools Read,Bash`, launched from inside the pinned snapshot. In that probe,
read-only commands inside the working directory ran, while reads outside it, relative
escapes (`../`), and writes were denied. Some legitimate searches were also denied: shell
globs, `cd` into a sibling supporting-context snapshot, and compound pipelines. Give roles
concrete paths in their packets. In a probe on 2026-11-11, a `curl` request was denied by the
permission layer (`dontAsk` allows only commands Claude Code treats as read-only); no
OS-level network sandbox was tested.

Require exit status zero, `is_error: false`, and a `structured_output` object that
validates against the complete applicable schema. Validate citations and other literal
contract checks as well. Wait for all discovery roles and complete schema and citation
validation, including any permitted retry and terminal status recording, before any
verifier is dispatched. Do not infer missing required fields from free-form output.

Launch the native verifier through a fresh schema-bound `claude -p` execution for each
stage after candidate packets are frozen. Apply the same isolation and result checks as
for discovery. The two stages follow [cross-model-verification.md](cross-model-verification.md):
require a `COMPLETE` observation-only Stage 1 before dispatching Stage 2. Stage 2 does
not receive Stage 1 or the other verifier's output. Use the existing Claude and Codex
CLIs; do not add a controller or dependency.

## Cross-provider dispatch

Invoke Codex directly; do not depend on a companion plugin or named plugin agent. Use a
fresh execution rooted at the target repository, with:

- model `gpt-6.1-sol`;
- reasoning effort `high`;
- a read-only permission profile instead of `--sandbox` (see below);
- apps and plugins disabled (`--disable apps --disable plugins`), so no account connector
  starts an MCP server outside the sandbox;
- the applicable role-specific schema resolved from the skill directory (`schemas/discovery-result.schema.json`, `schemas/verifier-stage1-result.schema.json`, `schemas/verifier-stage2-result.schema.json`, `schemas/fix-verifier-stage2-result.schema.json`, or `schemas/computation-result.schema.json`);
- no user instructions: the temporary `CODEX_HOME` below supplies none (do not use
  `--ignore-user-config`, which would also skip the profile);
- no writable directory added; and
- an explicit environment allowlist excluding Anthropic credentials and host session indicators; and
- a temporary `HOME` and `CODEX_HOME` (mode 700) whose only content is a link to the existing
  Codex credential file and the permission profile's `config.toml`, so no user skills, global
  instructions, or memories load and the session record stays out of the user's Codex home.
  Remove both after capturing the run.

Codex `--json` events do not name the model. Read the actual model from `turn_context.model`
in the session file under the temporary `CODEX_HOME` (not `--ephemeral`, which discards it);
`turn_context.effort` in the same record verifies the reasoning effort. Treat any `model_reroute` event (`from_model`, `to_model`, `reason`) or "model rerouted"
notice as a role fallback. Never set `allow_provider_model_fallback`. Treat the error codes
`cyber_policy`, `bio_policy`, and `content_filter` as hard refusals; their exact event shape
is confirmed by live verification.

The legacy `read-only` sandbox limits writes, not reads: the child can read any file the
user can, including other role artifacts under the run root. Confine reads with a Codex
permission profile written to the temporary `CODEX_HOME/config.toml`:

```toml
default_permissions = "sva-read"

[permissions.sva-read.filesystem]
":minimal" = "read"
"<codex-install-prefix>" = "read"

[permissions.sva-read.filesystem.":workspace_roots"]
"." = "read"

[permissions.sva-read.network]
enabled = false
```

Replace `<codex-install-prefix>` with the directory tree holding the Codex executable (for a
Homebrew install, the Homebrew prefix); without it, Codex cannot start its own sandbox
helper. Add a `"<path>" = "read"` entry for each supporting-context snapshot the packet
cites (from the documented profile syntax; the probe used only the working directory). The
`network` table follows the Codex permissions documentation; the probe's session record showed
network `restricted`. Do not pass `--sandbox` or set `sandbox_mode`: per the Codex permissions
documentation, either makes Codex use the legacy sandbox instead of the profile. Do not pass
`--ignore-user-config` either; it would presumably skip the `config.toml` that holds the
profile (inferred, not tested). The session file's `turn_context.permission_profile` records the
enforced profile. Check that `turn_context.permission_profile.file_system.type` is
`restricted` and `turn_context.permission_profile.network` is `restricted` (the top-level
`type` is `managed`). Check that the `file_system.entries` read entries are exactly the
profile's: the Codex install prefix, the workspace root, each supporting snapshot, and
`:minimal`. Codex also adds its own temporary `arg0` read entry, which is expected (observed
with codex-cli 0.162.0). Verified with
codex-cli 0.162.0 on 2026-11-11: reads inside the working directory succeeded, and reads of
a sibling directory by relative and absolute path failed with `Operation not permitted`, with
and without apps and plugins disabled.

Send the prompt through standard input and close the stream immediately. Treat standard
output as untrusted until it passes the expected schema. Do not expose raw verifier
output to the native verifier or discovery roles.

Use one fresh execution for Stage 1 and a second fresh execution for Stage 2. Stage 2
receives the same normalized challenge packet as the native verifier and no Stage 1
artifact, agent identities, vote counts, consensus language, or other verifier output.

## Source citations

Before discovery, capture snapshot intake and file hashes once and freeze the independently prepared pinned source registry, rejecting changes during freezing. Retain its expected digest independently in frozen caller dispatch and provenance outside role control; never derive it from a mutable companion manifest at acceptance. Pass that digest to the packaged deterministic extractor on each role artifact before completion checks and downstream use, and verify its envelope as required by [source-citations.md](source-citations.md). This applies to discovery, both verifier stages and providers, and fix artifacts. Preserve every raw attempt; extraction never chooses locations or changes judgments.

## Computation adapter

Do not send deterministic-check execution to a model or a shell. Run the packaged
`scripts/deterministic-check.py` as described in `deterministic-validation.md`. It accepts only `SOURCE_SLICE_SHA256` fields or a
`FROZEN_TEST_REFERENCE` present in the pre-discovery registry, or a separately frozen supplemental fix-check registry under `deterministic-validation.md`. Supplemental checks preserve `DISPUTED` and cannot resolve a verifier split. For a frozen test, execute
the registry's argument array directly with no shell in a temporary pinned-revision copy,
network denied, environment empty or allowlisted, target and package read-only, bounded
time/output, and writes confined to the temporary directory. A source digest never resolves
a verifier split. Any extra kind, role-emitted
argument, unknown test ID, revision mismatch, or unavailable isolation yields `NOT_RUN`
and routes the split to `DISPUTED`.

Compute CVSS v4.0 scores only with the packaged `scripts/cvss4-score.py`, never through a
model, as described under "Computed CVSS v4.0 scores" in `orchestrator-contract.md`.

## Waiting, retry, and failure

- Wait for every role in a round; do not interpret partial results.
- Retry a `FAILED`, `MALFORMED`, or `REFUSED` role, including schema or citation failures, once with the same frozen role contract and input.
- Do not change the claim, reveal other outputs, or add coaching on retry.
- After the retry fails, preserve the role status and render an `INCOMPLETE` run.
- A single verifier can provide analysis, but cannot confer `CROSS-MODEL VERIFIED`.

For Stage 2 fix verification, including verification invoked by `--develop-fix`, bind `schemas/fix-verifier-stage2-result.schema.json` for both providers; use `schemas/verifier-stage2-result.schema.json` for ordinary analysis. Apply the fix-mode semantic checks and routing in [fix-verification-mode.md](fix-verification-mode.md).

## GHSA mode

Follow [ghsa-triage-mode.md](ghsa-triage-mode.md) and [ghsa-deduplication.md](ghsa-deduplication.md).

**Tokens.** `ghsa-fetch.py` uses `gh` authentication, or `SVA_GHSA_READ_TOKEN` when set.
`SVA_GHSA_WRITE_TOKEN_REF` (a 1Password `op://` reference) is set only in the writer
child's environment. No GitHub token or token reference is ever placed in an intake or
step 1a child's environment.

**Intake roles (H2, H4).** Freeze the packet (authorization statement, role
instructions, and the captured advisory as untrusted data) to a file, then launch from an
empty temporary directory with a scrubbed environment and no tools:

```bash
cd "$EMPTY_TMP_DIR" && env -i HOME="$HOME" PATH="$PATH" ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  claude -p --bare --restricted --safe-mode --model claude-haiku-5-5 --effort high \
  --tools "" --strict-mcp-config --no-session-persistence --permission-mode dontAsk \
  --verbose --output-format stream-json \
  --json-schema "$(cat "$SKILL_DIR/schemas/intake-h2-completeness.schema.json")" < "$PACKET_FILE"
```

Use the H4 schema for H4. The init event must list only `StructuredOutput`
as a tool and no MCP servers; otherwise the role is `MISSING`. `env -i` keeps GitHub tokens
and `SVA_GHSA_*` variables out. Where only OAuth authentication is available, omit `--bare`
and `ANTHROPIC_API_KEY`; `--restricted` still keeps user settings out. Check every result
with `scripts/intake-check.py` and read model and refusal metadata as above.

**Step 1a legs.** Follow [ghsa-deduplication.md](ghsa-deduplication.md) for the steps. Every leg
runs on a frozen packet from `scripts/intake-check.py`, with no tools. Native legs (issue
listing, native classification of added issues, comparisons) run `claude-opus-5-5` at High
effort in the intake launch form above, with the step's schema: `schemas/issue-list.schema.json`,
`schemas/issue-review.schema.json` (classification), or `schemas/issue-compare.schema.json`.
Cross-provider legs (issue review, comparison confirmation) run `gpt-6.1-sol` at High effort in
the capability-free intake launch form of [runtime-codex.md](runtime-codex.md) "GHSA mode": an
empty temporary directory, temporary `HOME` and `CODEX_HOME`, and every tool surface disabled
(including `shell_tool` and `unified_exec`), with the model and `--output-schema` replaced by
gpt-6.1-sol and the step's schema. A read-only permission profile alone is not enough here: it
limits what commands can reach but still offers command tools to a leg that reads untrusted
report text. Pass each check command the literal `--provider` and `--model` from
runtime metadata: the hosts use different vocabularies (Claude `modelUsage` reports an access
channel such as `firstParty`; the Codex session file reports `model_provider` such as `openai`),
and the scripts only require the native and cross values to differ.

**Writer child.** After the user approves write-back and each item, launch a minimal child
that can run only the write-back script and receives only file paths:

```bash
printf '%s' "Run exactly this command and report its output: uv run python3 -I $SKILL_DIR/scripts/ghsa-writeback.py --plan $PLAN --approvals $APPROVALS --records $RECORDS" |
env -i HOME="$HOME" PATH="$PATH" ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  SVA_GHSA_WRITE_TOKEN_REF="$SVA_GHSA_WRITE_TOKEN_REF" \
  claude -p --bare --restricted --safe-mode --model claude-haiku-5-5 --effort high \
  --tools "Bash" --allowedTools "Bash(uv run python3 -I $SKILL_DIR/scripts/ghsa-writeback.py --plan $PLAN --approvals $APPROVALS --records $RECORDS)" \
  --strict-mcp-config --no-session-persistence --permission-mode dontAsk \
  --output-format json
```

`op read` inside the script triggers the maintainer's Touch ID prompt for that process
tree (verified 2026-11-10); the child cannot satisfy it. The maintainer may instead run the
same command in their own terminal. Verified live 2026-11-10: this launch ran the allowed
command with no permission denials, and the same launch denied any other Bash command.
