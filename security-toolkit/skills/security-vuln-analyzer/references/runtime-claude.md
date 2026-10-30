# Claude Code runtime

Use this adapter only when the current host is Claude Code. The shared workflow and
output contracts remain authoritative; this file defines dispatch mechanics.

## Model assignment

| Role | Model | Effort | Isolation |
|---|---|---|---|
| Three discovery roles | `claude-opus-5-5` | high | Fresh CLI executions; no discovery output shared between them |
| Fix author | `claude-opus-5-5` | high | Separate author agent on the authorized fix branch; never verifies its own patch |
| Native verifier, including fix verification | `claude-opus-5-5` | high | Fresh CLI execution; receives only its staged verification packet |
| Cross-provider verifier, including fix verification | `gpt-6.1-sol` | high | Fresh ephemeral Codex execution in read-only mode |

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
required empty fields. Verify the exact model and high effort, structured output and
cold-input read isolation. Failure to establish a required capability makes the
corresponding role `MISSING` and the run `INCOMPLETE`.

Native children use an explicit environment allowlist. Include the Anthropic credential
only for native Claude execution, and exclude host session indicators. Cross-provider
Codex children must exclude Anthropic credentials. Do not load session state, user or
project instructions, or memory into a native analysis child.

## Preflight

Before sending report or source material to another provider:

1. Confirm the user or organization permits the relevant material to be sent to OpenAI.
2. Resolve Codex from an explicitly configured executable first, then `codex` on `PATH`.
3. Check the selected executable's help output for `exec`, `--model`, `--sandbox`,
   `--ephemeral`, `--output-schema`, and reasoning-effort configuration.
4. Confirm authentication with a bounded non-sensitive probe; configuration or a saved
   login alone is not proof that execution works.
5. Record the executable version and effective model/effort in run provenance.

If a required capability or authorization is absent, mark the cross-provider role
`MISSING` and the run `INCOMPLETE`. Do not silently choose another model, provider, or
same-family verifier.

## Native dispatch

Freeze all three discovery prompts before dispatch. Launch them in parallel as fresh
`claude -p` executions using JSON output and `--json-schema` with the full discovery role schema, exact
`claude-opus-5-5` model and high effort. Use bare, restricted, safe execution with only
the read tools required by the role; disable Agent and delegation. Each child receives
only its frozen packet, and no session, instruction, or memory loading. Do not expose
one discovery result to another role.

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
fresh ephemeral execution rooted at the target repository, with:

- model `gpt-6.1-sol`;
- reasoning effort `high`;
- sandbox `read-only`;
- the applicable role-specific schema resolved from the skill directory (`schemas/discovery-result.schema.json`, `schemas/verifier-stage1-result.schema.json`, `schemas/verifier-stage2-result.schema.json`, or `schemas/computation-result.schema.json`);
- user and project instruction loading disabled when supported;
- no writable directory added; and
- an explicit environment allowlist excluding Anthropic credentials and host session indicators.

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
`FROZEN_TEST_REFERENCE` present in the pre-discovery registry. For a frozen test, execute
the registry's argument array directly with no shell in a temporary pinned-revision copy,
network denied, environment empty or allowlisted, target and package read-only, bounded
time/output, and writes confined to the temporary directory. A source digest never resolves
a verifier split. Any extra kind, role-emitted
argument, unknown test ID, revision mismatch, or unavailable isolation yields `NOT_RUN`
and routes the split to `DISPUTED`.

## Waiting, retry, and failure

- Wait for every role in a round; do not interpret partial results.
- Retry a `FAILED` or `MALFORMED` role, including schema or citation failures, once with the same frozen role contract and input.
- Do not change the claim, reveal other outputs, or add coaching on retry.
- After the retry fails, preserve the role status and render an `INCOMPLETE` run.
- A single verifier can provide analysis, but cannot confer `CROSS-MODEL VERIFIED`.
