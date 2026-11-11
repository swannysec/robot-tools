# Codex and ChatGPT Desktop runtime

Use this adapter only in local Codex or ChatGPT Desktop. The shared workflow and output
contracts remain authoritative; this file defines dispatch mechanics.

## Model assignment

| Role | Model | Effort | Isolation |
|---|---|---|---|
| Three discovery roles | `gpt-6.1-sol` | high | Fresh agents with no inherited turns |
| Fix author | `gpt-6.1-sol` | high | Separate author agent on the authorized fix branch; never verifies its own patch |
| Native verifier, including fix verification | `gpt-6.1-sol` | high | Fresh agent with no inherited turns |
| Cross-provider verifier, including fix verification | `claude-opus-5-5` | high | Fresh non-persistent restricted Claude execution |
| Intake roles (GHSA mode) | `gpt-6-luna` | high | Fresh `codex exec` with no file, command, or network tool and no GitHub token |

The table gives the expected models. The analysis tier follows the orchestrating model:
the orchestrator may identify its own model from its context or harness metadata, and if
it is not `gpt-6.1-sol`, it stops and asks the user before dispatch. `claude-opus-5-5` is
the default cross-provider model; `--cross-model <model>` overrides it with another
Anthropic model, recorded in provenance. Intake roles make no security judgment, so the
cross-provider rule does not apply to them. Codex has no verified zero-tool launch, so
intake isolation is defined by capability: no tool that reads files, runs commands, or
reaches the network. Residual tools that remain offered (patch application under a
read-only sandbox, user-input requests in a non-interactive run, MCP resource listing with
no servers) cannot reach files, commands, or the network; live verification confirms this
on the final launch form.

For native roles, dispatch `gpt-6.1-sol` with high effort and `fork_turns: none`. Supply
all required task context explicitly; do not rely on conversation inheritance.

Before analysis, prove native dispatch and a bounded file read with a non-sensitive
fixture. Use a working read-only file-inspection tool, including literal CLI file reads
when that is the host's available reader. Permitting source inspection does not permit
executing source text, tests, payloads, or shell expansion examples. A blanket ban on
all commands must not accidentally disable the only supported source reader. Freeze
the selected reader and allowed ranges with the role packet before dispatch.

## Preflight

Before sending report or source material to another provider:

1. Confirm the user or organization permits the relevant material to be sent to Anthropic.
2. Resolve Claude Code from an explicitly configured executable first, then `claude` on
   `PATH`. Do not hard-code a user-specific installation path.
3. Check the selected executable's help output for print mode, `--model`, `--effort`,
   `--restricted`, `--safe-mode`, `--no-session-persistence`, permission controls, and
   structured JSON output.
4. Confirm authentication with a bounded non-sensitive probe; executable discovery or a
   saved login alone is not proof that execution works.
5. Record the executable version and effective model/effort in run provenance.

If a required capability or authorization is absent, mark the cross-provider role
`MISSING` and the run `INCOMPLETE`. Do not silently choose another model, provider, or
same-family verifier. A model change that runtime metadata reports after dispatch is a
disclosed role fallback under `orchestrator-contract.md`, never a silent substitution.

## Model and refusal metadata

- Native agents: record the model the host reports for each agent. Where the host reports
  none, record the requested model and mark the actual model unverified.
- `codex exec` children (intake): `--json` events do not name the model. Run with a
  temporary `HOME` and `CODEX_HOME` (mode 700) holding only a link to the existing Codex
  credential file, and read `turn_context.model` and `turn_context.effort` from the session
  file there; `--ephemeral` discards that file. Treat any `model_reroute` event
  (`from_model`, `to_model`, `reason`) or "model rerouted" notice as a role fallback. Never
  set `allow_provider_model_fallback`. Treat the error codes `cyber_policy`, `bio_policy`,
  and `content_filter` as hard refusals; their exact event shape is confirmed by live
  verification. Remove the temporary homes after capturing the run.
- Claude cross-provider children: never pass `--fallback-model`. Claude Code re-runs
  safety-classifier-flagged requests on an older model by default; leave that on and
  detect it from the result's `modelUsage` keys and `stream-json` system subtype
  `model_refusal_fallback`. Subtype `model_refusal_no_fallback`, a non-zero
  `safety_stops`, or a refusal `stop_reason`/`terminal_reason` without schema output is a
  hard refusal; `is_error: true` with an API error is `FAILED`. Exclude
  `CLAUDE_CODE_EFFORT_LEVEL` from the child environment, and record high effort as
  requested and unverified, because print mode does not report it.

## Native dispatch

Freeze all three discovery prompts before dispatch. Launch the three native roles in
parallel with model `gpt-6.1-sol`, high effort, and no inherited conversation turns. Do
not give any role another role's output. Wait for the entire round before schema
validation or mechanical reconciliation.

Launch the native verifier only after candidate packets have been frozen. Its two stages
follow [cross-model-verification.md](cross-model-verification.md). Require a `COMPLETE`
observation-only Stage 1 before dispatching Stage 2. Stage 2 does not receive Stage 1 or
the other verifier's output.

The legacy Codex `read-only` sandbox limits writes, not reads (observed with `codex exec -s
read-only`). A `codex exec` child can be confined with the permission profile in
[runtime-claude.md](runtime-claude.md) "Cross-provider dispatch"; read confinement of in-app
native roles is unverified. Keep run artifacts out of the roles' working directory.

## Cross-provider dispatch

Invoke Claude Code directly in non-interactive print mode; do not depend on a named
plugin agent. Use a fresh execution rooted at the target repository, with:

- model `claude-opus-5-5` and effort `high`;
- restricted and safe modes (restricted mode is what keeps user settings, including
  their environment block, out of the child);
- no session persistence;
- permission mode `dontAsk` and no permission-prompt handler;
- only bounded read/search tools needed by the packet (Claude Code under `--restricted` has
  no `Grep` or `Glob`; see the probed `--tools Read,Bash` form in
  [runtime-claude.md](runtime-claude.md) "Native dispatch"); and
- the applicable role-specific schema resolved from the skill directory (`schemas/discovery-result.schema.json`, `schemas/verifier-stage1-result.schema.json`, `schemas/verifier-stage2-result.schema.json`, `schemas/fix-verifier-stage2-result.schema.json`, or `schemas/computation-result.schema.json`).

Send the prompt through standard input. Treat the response as untrusted until it passes
the expected schema. Do not expose raw verifier output to the native verifier or
discovery roles.

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
- Retry a `FAILED`, `MALFORMED`, or `REFUSED` role once with the same frozen role contract and input.
- Do not change the claim, reveal other outputs, or add coaching on retry.
- After the retry fails, preserve the role status and render an `INCOMPLETE` run.
- A single verifier can provide analysis, but cannot confer `CROSS-MODEL VERIFIED`.

For Stage 2 fix verification, including verification invoked by `--develop-fix`, bind `schemas/fix-verifier-stage2-result.schema.json` for both providers; use `schemas/verifier-stage2-result.schema.json` for ordinary analysis. Apply the fix-mode semantic checks and routing in [fix-verification-mode.md](fix-verification-mode.md).

## GHSA mode

Follow [ghsa-triage-mode.md](ghsa-triage-mode.md) and [ghsa-deduplication.md](ghsa-deduplication.md).

**Tokens.** `ghsa-fetch.py` uses `gh` authentication, or `SVA_GHSA_READ_TOKEN` when set.
`SVA_GHSA_WRITE_TOKEN_REF` (a 1Password `op://` reference) is used only by
`ghsa-writeback.py`. No GitHub token or token reference is ever placed in an intake, D4,
M2, or M4 child's environment.

**Intake roles (H1/D1, H2, H4).** Freeze the packet to a file and launch a fresh `codex exec`
from an empty temporary directory, with temporary `HOME` and `CODEX_HOME` (mode 700) whose
only content is a link to the existing Codex `auth.json`, and every tool surface disabled:

```bash
env -i HOME="$TMP_HOME" CODEX_HOME="$TMP_CODEX_HOME" PATH="$PATH" codex exec \
  --ignore-user-config --ignore-rules --skip-git-repo-check -C "$EMPTY_TMP_DIR" -s read-only \
  -m gpt-6-luna -c 'model_reasoning_effort="high"' -c 'web_search="disabled"' \
  --disable shell_tool --disable unified_exec --disable code_mode_host --disable view_image \
  --disable image_generation --disable apps --disable plugins --disable browser_use \
  --disable browser_use_external --disable computer_use --disable hooks --disable skill_search \
  --disable tool_suggest --disable sleep_tool --disable goals --disable multi_agent --disable memories \
  --output-schema "$SKILL_DIR/schemas/intake-h1-claims.schema.json" --json - < "$PACKET_FILE"
```

Use the H2 or H4 schema for those roles. `env -i` keeps GitHub tokens and `SVA_GHSA_*`
variables out. Code mode reports that it fails closed; that error item is expected. This is
capability-based isolation: no tool that reads files, runs commands, or reaches the network
(see "Model assignment"). Read the actual model and any reroute from the session file under
`$TMP_CODEX_HOME`, check every result with `scripts/intake-check.py`, and remove the
temporary homes afterward.

**D4 and M4.** Dispatch both providers exactly as the native and cross-provider verifiers,
cold and in parallel, with the packet from `ghsa-dedup.py d4-packet` or `m4-packet` and
`schemas/dedup-d4-result.schema.json` or `schemas/dedup-m4-result.schema.json`. For D4, the
wrapper passes the packet's `question` verbatim and does not restate, paraphrase, or add to
it, so both providers answer the same question. Pass
`route-d4` and `route-m` the literal provider values from runtime metadata (the Codex session
file's `model_provider`, such as `openai`; Claude `modelUsage` reports an access channel such
as `firstParty`); the routers only require the two values to differ. **M2** is a
fix-author dispatch whose packet is `ghsa-dedup.py m2-packet` output only.

**Writer.** After the user approves write-back and each item, the maintainer runs
`uv run python3 -I scripts/ghsa-writeback.py --plan <plan> --approvals <approvals> --records <records>`
in their own terminal with `SVA_GHSA_WRITE_TOKEN_REF` set; `op read` prompts for Touch ID.
A Codex writer child would need network access for `gh` without a general shell; that
launch form is unverified and is checked in live verification before it is documented.
