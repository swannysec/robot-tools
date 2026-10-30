---
name: fix-verification-mode
description: Independent, cold-artifact verification of a candidate or shipped fix.
---

# Fix-Verification Mode (`--verify-fix`)

Use this mode to test whether a named fix closes a confirmed finding's frozen Invariant + Adversarial Test Contract. It is disproof-biased: the question is “what input defeats this fix?”, not “does this patch resemble the recommendation?” The fix author never verifies its own work.

Use High effort for both verifier stages. In Claude Code, dispatch `claude-opus-5-5` natively and `gpt-6.1-sol` cross-provider; in Codex/ChatGPT, dispatch `gpt-6.1-sol` natively and `claude-opus-5-5` cross-provider. Any discovery needed to reconstruct a missing contract uses the host's native model at High effort.

## Invocation, fresh-session bootstrap, and preflight

Require `--tracker <URL|path>` and one or more `--fix <PR-or-commit>` values. `--tracker` accepts a GitHub/GHSA or other approved issue URL, a local path, or a `file://` URL; `--fix` accepts PR URLs or commit SHAs. `--analysis <path>` is optional. These inputs make the mode invocable from a fresh session without remembered state.

Capture the tracker body verbatim, resolve each fix diff, and pin the vulnerable/base and patched revisions. Load the original finding and converged Invariant + Adversarial Test Contract from `--analysis` or the tracker when present. If the contract is absent, dispatch the three isolated discovery roles against the pinned base material to produce a new proposed contract, then require the normal cross-model verification and human acceptance before using it as a fix oracle. Do not infer a contract from the patch or improve one after seeing the patch. Until a contract is accepted and tied to the revisions, return `INCOMPLETE`.

Require a specific stable finding ID, contract version, source artifact and hash of the full contract, and frozen test identifiers/hashes before test execution. Bind the handoff to both contract version and artifact hash; a matching version alone does not establish identical content. The orchestrator may validate the hash but does not adjudicate contract compatibility. Missing or invalid binding returns `INCOMPLETE`. If a supplied contract is disputed or cannot be tied to the pinned revisions, return `INCOMPLETE`.

Freeze two separate cold verification packets. The Stage 1 packet is observation-only: it contains only the pinned base and candidate revisions, precise predeclared locations and scope, and generic comparison questions. It contains no normalized proposition, finding conclusion, author reasoning, discovery output, contract, patch diff, test/oracle material, or verifier output.

Before independent verification, freeze the Stage 2 normalized proposition as the positive assertion that the named candidate satisfies the frozen fix contract. Thus shared `REFUTED` means that assertion was refuted and routes to `NO`; do not reuse the analysis-mode vulnerability proposition. In a fresh Stage 2 execution, provide a separate packet containing the normalized proposition, patch diff, frozen contract, tests, and deterministic oracle, cited evidence and counterevidence, primitive-class enumeration, and bounded context. Do not provide any Stage 1 artifact or other verifier work; exclude author reasoning, discovery consensus, agent identities, and counts.

## Procedure

1. Audit attribution: cite which change actually closes the original contract and separately label unrelated or defense-in-depth changes.
2. Run the frozen exploit tests against the untouched base revision, then the patched revision. For each adversarial input class, record expected and actual behavior.
3. Run the frozen benign/negative controls, sink-coverage check, and project regression suite. Record exact commands, tool versions, revision, exit status, bounded output, and test evidence state.
4. Construct and test contract-supported variants from the canonical primitive-class enumeration. Unenumerated or uncertain members remain uncertainty, not passing evidence.
5. Run native and cross-provider cold verification under [cross-model-verification.md](cross-model-verification.md). Reconcile mechanically under [orchestrator-contract.md](orchestrator-contract.md); a missing cross-provider leg or mandatory stage is `INCOMPLETE`, never `NOT VERIFIED` or a same-family fallback.

Use [deterministic-validation.md](deterministic-validation.md) for literal evidence states and the predeclared oracle. Runtime mechanics belong to [runtime-claude.md](runtime-claude.md) or [runtime-codex.md](runtime-codex.md).

## Result

For every finding, preserve stable IDs, status, provenance, evidence, counterevidence, assumptions, uncertainty, four-gate state, and the literal test evidence state. For Stage 2 in `--verify-fix` (including verification invoked by `--develop-fix`), both verifiers must use `schemas/fix-verifier-stage2-result.schema.json`. Ordinary analysis continues to use `schemas/verifier-stage2-result.schema.json`. The fix schema retains every ordinary Stage 2 field and requires `closure_recommendation` (`YES`, `CONDITIONAL YES`, `NO`, or `INCONCLUSIVE`) and `closure_conditions` (an array of objects). Each condition requires string fields `residual_scope_or_uncertainty`, `tracking_reference`, `owner`, and `acceptance_required`. The verifier supplies this information; the orchestrator preserves it verbatim and does not infer it. After schema validation, mechanically require at least one condition for `CONDITIONAL YES` and an empty `closure_conditions` array for `YES`. Reject any condition field that is empty after trimming ASCII whitespace. A violation makes the result `MALFORMED`; apply the normal identical-packet retry and then `INCOMPLETE` if unrepaired. The existing Stage 2 verdict-dependent citation and cardinality checks still apply. Recommendations and conditions are role-scoped; never merge or discard them.

The oracle state is `SATISFIED` only when the accepted, revision-bound predeclared fix oracle and all its required base, patched, control, sink-coverage, and regression executions have valid recorded results satisfying their frozen expectations. It is `FAILED` when a valid execution contradicts a frozen expectation. It is `UNAVAILABLE` when the oracle, binding, required execution, or valid result is missing, invalid, unexecutable, or unresolved. A written but unrun test is not a satisfied oracle. Preserve the literal results and evidence state; do not infer the state from verifier prose.

Apply the following ordered rules mechanically, after normal schema, citation, revision, mandatory artifact and shared reconciliation checks. Missing or invalid mandatory artifacts route to shared `INCOMPLETE` before closure routing, including when the shared verdict would otherwise be `REFUTED`. The first matching rule determines the closure outcome:

1. Shared `INCOMPLETE`, `DISPUTED`, or `NOT VERIFIED` maps to the same outcome, regardless of recommendations or oracle state.
2. If one recommendation is `NO` and the other differs, return `DISPUTED`. Preserve both records and the oracle evidence; do not select a verifier's recommendation or interpret prose to resolve the conflict.
3. Shared `REFUTED`, two `NO` recommendations, or a `FAILED` oracle maps to `NO`.
4. An `UNAVAILABLE` oracle maps to `INCOMPLETE`.
5. With shared `CROSS-MODEL VERIFIED` and a `SATISFIED` oracle: two `YES` recommendations map to `YES`; any pair consisting only of `YES` and `CONDITIONAL YES` with at least one `CONDITIONAL YES` maps to `CONDITIONAL YES`, preserving all conditional records for tracked human acceptance; two `INCONCLUSIVE` recommendations map to `NOT VERIFIED`; and one `INCONCLUSIVE` with a different recommendation maps to `DISPUTED`.

No other combination is a closure recommendation: invalid or missing values are `MALFORMED` and, after retry, `INCOMPLETE`. A verifier must use `NO` for a demonstrated contract-supported bypass or failed gate and cite its evidence; it must not recommend `YES` where such evidence remains. The orchestrator does not decide whether prose demonstrates a bypass or whether conditions are persuasive. `YES` requires unanimous `YES` and the satisfied oracle; `CONDITIONAL YES` requires the satisfied oracle and the recorded conditions. `NO`, `DISPUTED`, `INCOMPLETE`, and `NOT VERIFIED` do not close the issue.

`YES` and `CONDITIONAL YES` are recommendations for human closure only. They do not authorize an autonomous merge, issue closure, or disclosure action.

## Disclosure-safe landing

Do not place vulnerability details, PoCs, contracts, or provenance on public branches, commit messages, or PR text before disclosure. A human controls any merge and disclosure route. See [develop-fixes-mode.md](develop-fixes-mode.md).
