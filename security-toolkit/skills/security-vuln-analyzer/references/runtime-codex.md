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
same-family verifier.

## Native dispatch

Freeze all three discovery prompts before dispatch. Launch the three native roles in
parallel with model `gpt-6.1-sol`, high effort, and no inherited conversation turns. Do
not give any role another role's output. Wait for the entire round before schema
validation or mechanical reconciliation.

Launch the native verifier only after candidate packets have been frozen. Its two stages
follow [cross-model-verification.md](cross-model-verification.md). Require a `COMPLETE`
observation-only Stage 1 before dispatching Stage 2. Stage 2 does not receive Stage 1 or
the other verifier's output.

## Cross-provider dispatch

Invoke Claude Code directly in non-interactive print mode; do not depend on a named
plugin agent. Use a fresh execution rooted at the target repository, with:

- model `claude-opus-5-5` and effort `high`;
- restricted and safe modes;
- no session persistence;
- permission mode `dontAsk` and no permission-prompt handler;
- only bounded read/search tools needed by the packet; and
- the applicable role-specific schema resolved from the skill directory (`schemas/discovery-result.schema.json`, `schemas/verifier-stage1-result.schema.json`, `schemas/verifier-stage2-result.schema.json`, or `schemas/computation-result.schema.json`).

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
`FROZEN_TEST_REFERENCE` present in the pre-discovery registry. For a frozen test, execute
the registry's argument array directly with no shell in a temporary pinned-revision copy,
network denied, environment empty or allowlisted, target and package read-only, bounded
time/output, and writes confined to the temporary directory. A source digest never resolves
a verifier split. Any extra kind, role-emitted
argument, unknown test ID, revision mismatch, or unavailable isolation yields `NOT_RUN`
and routes the split to `DISPUTED`.

## Waiting, retry, and failure

- Wait for every role in a round; do not interpret partial results.
- Retry a `FAILED` or `MALFORMED` role once with the same frozen role contract and input.
- Do not change the claim, reveal other outputs, or add coaching on retry.
- After the retry fails, preserve the role status and render an `INCOMPLETE` run.
- A single verifier can provide analysis, but cannot confer `CROSS-MODEL VERIFIED`.
