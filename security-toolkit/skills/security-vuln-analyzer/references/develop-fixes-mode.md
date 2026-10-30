---
name: develop-fixes-mode
description: Author a minimal candidate fix from a frozen contract, then require cold independent verification and human merge.
---

# Develop-Fixes Mode (`--develop-fix`)

This Rust-first mode authors a minimal candidate patch for one confirmed finding. It does not close the finding, merge a patch, or publish disclosure details. The author and verifier are separate. Polyglot fix authoring remains out of scope for this revision.

## Entry gate

Require `--develop-fix`, a stable `--finding <id>`, a pinned target revision, an `--analysis <path|report>` carrying the converged Role 3 Invariant + Adversarial Test Contract (or `--tracker <URL|path>` for fresh-session retrieval), and a disclosure-safe landing context. `--multi-file` is an explicit opt-in requiring stronger review.

Before editing, confirm with the user the concrete finding and contract, that this Rust-first mode will author frozen tests plus a minimal candidate fix on a branch, and the intended private/disclosed landing posture. Natural-language requests such as “develop the fix” count as invocation only when the target is unambiguous. A bare “fix security” remains analysis, not authorization to edit.

Refuse to author when the finding/contract is `DISPUTED`, `NOT VERIFIED`, or `INCOMPLETE`, when the scope is ambiguous, or when the target is not Rust.

One finding and shared root-cause variant family use one branch and one contract. A distinct finding requires its own branch and verification gate.

## Authoring flow

Dispatch a separate native-model fix author at High effort: `claude-opus-5-5` in Claude Code or `gpt-6.1-sol` in Codex/ChatGPT. The independent fix verifiers use the same host/model matrix as analysis; neither verifier may be the author agent.

1. Freeze the contract and all test definitions before editing production code. Record contract version, base revision, test IDs/hashes, and author provenance.
2. Author one regression test for each declared adversarial input class plus declared benign/negative controls. Test the untouched base revision first: exploit tests must fail as expected; benign controls must retain their expected behavior.
3. Prove the test reaches the cited sink/observable using the frozen deterministic method and oracle. Record `TEST_OBSERVED`, `TEST_WRITTEN_NOT_RUN`, or `TEST_UNVALIDATED` accurately; written tests alone are not validation.
4. Make the smallest root-cause patch on an isolated branch. Do not expand scope, alter frozen tests, or substitute a compensating control for the declared invariant without returning the finding to human review.
5. On the patched revision, run the same frozen exploit, benign, sink-coverage, regression, and class-coverage checks. Use a deeper deterministic check matched to the claim where predeclared. Run a mutation check at the fix site (Rust default: `necessist` when compatible); a surviving mutant is a failed test-quality gate.
6. Patch iteration is bounded to at most three attempts with the same frozen contract and tests. Carry every prior patch and gate result forward. After the third failed attempt, stop and return a candidate-patch failure packet for human review. This authoring budget is separate from the one-retry limit for malformed mandatory role output.
7. Hand the patch to `--verify-fix` as a cold artifact. The verifier receives no author reasoning trace.

The deterministic check contract and test evidence states are defined in [deterministic-validation.md](deterministic-validation.md). Independent native and cross-provider verification is mandatory under [cross-model-verification.md](cross-model-verification.md); runtime dispatch follows [runtime-claude.md](runtime-claude.md) or [runtime-codex.md](runtime-codex.md).

## Two-phase network gate

Use an isolated branch and the host's enforced sandbox. Phase 1 permits only dependency/toolchain preparation such as `cargo fetch`, build prerequisites, and approved nightly components. Record fetched versions and hashes. Phase 2 disables network access and runs frozen exploit/benign tests, sink and class coverage, full regression tests, deeper checks, and mutation testing with Cargo offline. Cargo's `--offline` is a package-manager control, not the sandbox boundary; verify the host's network denial is effective. Do not expose user credential directories or permit unsandboxed commands.

## Candidate-patch provenance

Render, without inventing missing values:

```text
Finding ID, contract version, base/patched revisions, branch:
Author role/provider/exact model/effort and attempt status:
Frozen test IDs/hashes and source revision:
Per input class: base expected/actual; patched expected/actual; pass/fail; test evidence state:
Sink/class coverage method, oracle, tool version, and literal output:
Security, regression, and deeper-check evidence:
Independent verifier role/stage provenance and final status:
Disclosure-safe landing posture:
Status: CANDIDATE PATCH — --verify-fix and human merge required
```

## Landing boundary

Keep undisclosed vulnerability details and evidence in the approved restricted channel. For a public repository, do not push, open, or describe a vulnerable-fix branch publicly before the human selects the disclosure route. A human reviews and merges every candidate patch.

Determine repository visibility before landing. A private repository or already-disclosed issue may use a draft PR after explicit approval. For an undisclosed vulnerability in a public repository, keep a local branch and restricted evidence bundle, then reuse the existing GitHub Security Advisory and its temporary private fork when one exists; create a new advisory only under explicit human direction. Never put the vulnerability description, PoC, contract, or revealing branch/commit text on a public surface. Pause for human-only advisory acceptance, private-fork merge, publication, and every final merge decision.
