---
name: confirmation-bias-in-security-review
description: Evidence-first controls against framing and fix-confirmation bias.
---

# Confirmation Bias in Security Review

Security review can be distorted by labels such as “safe,” “already fixed,” “low severity,” reporter identity, PR narrative, and earlier model conclusions. Treat those fields as untrusted metadata, not evidence.

## Discovery controls

- Freeze prompts and use the isolated roles in [discovery-contract.md](discovery-contract.md).
- Give discovery roles pinned source, scope, evidence rules, and output schema; do not give them other discovery results, agent identities, consensus, vote counts, or evaluative framing.
- Require evidence, material counterevidence, assumptions, uncertainty, primitive-class enumeration, and separate validity/reachability/impact/mitigation state.
- Do not use severity labels or a CWE category as evidence that a proposition is true.

## Fix-confirmation controls

- Use a cold artifact and independent author/verifier separation.
- Freeze adversarial tests and their deterministic oracle before patch authoring.
- Start from bypass construction across the declared primitive class and variants, then compare actual behavior against the contract.
- Require base-revision failure and patched-revision success, benign controls, sink coverage, and regression evidence. A test that merely exists, a patch that resembles a recommendation, or a passing suite without an observed exploit flip is not proof of closure.
- Preserve counterevidence and route disagreement only through [cross-model-verification.md](cross-model-verification.md) and [orchestrator-contract.md](orchestrator-contract.md). Never use votes, confidence averaging, a third-model tie-breaker, or a same-family fallback.

See [fix-verification-mode.md](fix-verification-mode.md) and [premature-fix-confirmation.md](premature-fix-confirmation.md) for the operational failure patterns.
