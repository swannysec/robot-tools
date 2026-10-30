---
name: premature-fix-confirmation
description: Failure patterns that prevent a candidate patch from being mistaken for a verified closure.
---

# Premature Fix Confirmation

## Single-class enumeration

**Failure:** testing examples from one input family while missing equivalent primitive classes that achieve the attacker goal.

**Control:** state the goal, enumerate the canonical primitive class and variants, freeze one adversarial test per declared class, and report unenumerated members as uncertainty. See [threat-modeling-methodology.md](threat-modeling-methodology.md).

## Recommendation match is not attack closure

**Failure:** confirming that code contains a suggested guard without observing whether it blocks the attack.

**Control:** require the Role 3 Invariant + Adversarial Test Contract, a base-revision expected failure, a patched-revision expected pass, benign controls, and the predeclared deterministic oracle. Use [deterministic-validation.md](deterministic-validation.md).

## Attribution drift

**Failure:** treating a cited PR or commit as the closure when an earlier change, a different change, or no change actually satisfies the contract.

**Control:** cite the exact diff and locations that affect the frozen contract; separately label unrelated and defense-in-depth changes. Preserve missing evidence as `INCOMPLETE`.

## Author self-confirmation and degraded verification

**Failure:** allowing the author to validate its own reasoning, replacing a required cross-provider leg with a single verifier, or resolving disagreement by consensus.

**Control:** pass a cold artifact to separate native and cross-provider verifiers, retain stage provenance, and use Mechanical Reconciliation. An unavailable required leg cannot produce `CROSS-MODEL VERIFIED`. See [cross-model-verification.md](cross-model-verification.md), [orchestrator-contract.md](orchestrator-contract.md), [runtime-claude.md](runtime-claude.md), and [runtime-codex.md](runtime-codex.md).

## Unsafe closure or disclosure

**Failure:** closing, merging, or publicly describing a patch before independent verification and human disclosure review.

**Control:** label output `CANDIDATE PATCH`; require `--verify-fix`, then human merge and disclosure decisions. See [develop-fixes-mode.md](develop-fixes-mode.md) and [fix-verification-mode.md](fix-verification-mode.md).
