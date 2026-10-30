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

Require a specific stable finding ID and frozen test identifiers/hashes before test execution. If a supplied contract is disputed or cannot be tied to the pinned revisions, return `INCOMPLETE`.

Freeze two separate cold verification packets. The Stage 1 packet is observation-only: it contains only the pinned base and candidate revisions, precise predeclared locations and scope, and generic comparison questions. It contains no normalized proposition, finding conclusion, author reasoning, discovery output, contract, patch diff, test/oracle material, or verifier output.

In a fresh Stage 2 execution, provide a separate packet containing the normalized proposition, patch diff, frozen contract, tests, and deterministic oracle, cited evidence and counterevidence, primitive-class enumeration, and bounded context. Do not provide any Stage 1 artifact or other verifier work; exclude author reasoning, discovery consensus, agent identities, and counts.

## Procedure

1. Audit attribution: cite which change actually closes the original contract and separately label unrelated or defense-in-depth changes.
2. Run the frozen exploit tests against the untouched base revision, then the patched revision. For each adversarial input class, record expected and actual behavior.
3. Run the frozen benign/negative controls, sink-coverage check, and project regression suite. Record exact commands, tool versions, revision, exit status, bounded output, and test evidence state.
4. Construct and test contract-supported variants from the canonical primitive-class enumeration. Unenumerated or uncertain members remain uncertainty, not passing evidence.
5. Run native and cross-provider cold verification under [cross-model-verification.md](cross-model-verification.md). Reconcile mechanically under [orchestrator-contract.md](orchestrator-contract.md); a missing cross-provider leg or mandatory stage is `INCOMPLETE`, never `NOT VERIFIED` or a same-family fallback.

Use [deterministic-validation.md](deterministic-validation.md) for literal evidence states and the predeclared oracle. Runtime mechanics belong to [runtime-claude.md](runtime-claude.md) or [runtime-codex.md](runtime-codex.md).

## Result

For every finding, preserve stable IDs, status, provenance, evidence, counterevidence, assumptions, uncertainty, four-gate state, and the literal test evidence state. The only closure outcomes are:

- `YES`: the contract's deterministic oracle is satisfied, independent verification reconciles as allowed, and no contract-supported bypass remains demonstrated.
- `CONDITIONAL YES`: the oracle is satisfied, but explicit residual scope or uncertainty requires tracked human acceptance. This is not a claim of complete coverage.
- `NO`: a reproducible contract-supported bypass or failed gate prevents closure.
- `DISPUTED`: complete verifiers split and the unique predeclared deterministic oracle is absent, conflicting, unexecutable, or non-resolving. The issue does not close.
- `INCOMPLETE`: a mandatory role, stage, provider capability, schema, citation, revision, or execution artifact is unavailable or invalid.
- `NOT VERIFIED`: all mandatory artifacts are complete, but both Stage 2 verifiers are `INCONCLUSIVE`.

Mechanical mapping from the shared final status is exhaustive: `CROSS-MODEL VERIFIED` plus a satisfied fix oracle permits `YES` or evidence-bounded `CONDITIONAL YES`; `REFUTED` or a demonstrated bypass maps to `NO`; `DISPUTED` maps to `DISPUTED`; `NOT VERIFIED` maps to `NOT VERIFIED`; and `INCOMPLETE` maps to `INCOMPLETE`. Agents supply the closure recommendation fields; the orchestrator applies only this lookup.

`YES` and `CONDITIONAL YES` are recommendations for human closure only. They do not authorize an autonomous merge, issue closure, or disclosure action.

## Disclosure-safe landing

Do not place vulnerability details, PoCs, contracts, or provenance on public branches, commit messages, or PR text before disclosure. A human controls any merge and disclosure route. See [develop-fixes-mode.md](develop-fixes-mode.md).
