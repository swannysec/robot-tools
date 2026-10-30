---
name: cross-model-verification
description: Two-stage, cold native and cross-provider verification with deterministic dispute routing.
---

# Cross-Model Verification

Every vulnerability finding and primary-control weakness requires two mandatory, cold verifiers at High reasoning effort: one native-family verifier and one cross-provider verifier. The host selects the families: Claude Code uses `claude-opus-5-5` native and `gpt-6.1-sol` cross-provider; Codex/ChatGPT uses `gpt-6.1-sol` native and `claude-opus-5-5` cross-provider. Same-family fallback is forbidden.

The cross-provider verifier may run only after preflight establishes executable availability, authentication, exact model selection, structured-output support, read isolation, and authorization to share the frozen packet with that provider. If it cannot run, the analysis is incomplete and no claim may be labeled `CROSS-MODEL VERIFIED`.

## Two-stage cold procedure

1. **Independent location analysis.** Each verifier receives only the pinned revision, the pre-discovery mechanical intake packet, scope, generic observation questions, and an observation-only schema. Without receiving a proposed proposition, conclusion, or discovery-selected context, it records cited behavior, data/control flow, trust transitions, controls, and reachable effects. It does not return `CONFIRMED`, `REFUTED`, or `INCONCLUSIVE`.
2. **Normalized challenge.** In a fresh execution, each verifier receives the same identity-free normalized proposition, cited evidence, cited counterevidence (including any whole-finding discovery refutation), declared assumptions/uncertainty, and the exact byte-preserved role-scoped set of all emitted deterministic checks and routing tables. Nothing is selected, merged, or suppressed. Stage 1 artifacts are not included. It challenges the proposition and returns a final result. It never receives the other verifier's work, finder consensus, agent identities, or vote counts.

Include every completed discovery artifact's top-level evidence and counterevidence as shared context, even when its candidate array is empty. Preserve candidate-local counterevidence with its exact source proposition, assumptions, uncertainty, and checks; the orchestrator cannot decide relevance by interpreting the claim. Each verifier decides only the packet's target proposition and treats other proposition-scoped records as untrusted context.

Discovery-authored prose must satisfy the role-local ID restriction and post-schema check in `discovery-contract.md` and `orchestrator-contract.md` before any verifier is dispatched. Use only verified derived artifacts as specified in `source-citations.md`; preserve raw artifacts and provenance. Do not repair or rewrite prose to construct an identity-free packet. The same extraction applies to both stages and both providers, and to fix artifacts.

The verifier must not substitute stage 2 for stage 1. Track all four provider/stage artifacts separately. Retry a failed or malformed stage once with the identical packet. All four artifacts must be `COMPLETE` before Mechanical Reconciliation; otherwise the claim is `INCOMPLETE`, even if a Stage 2 verdict exists.

After JSON Schema validation, apply these verdict-dependent cardinality checks without interpreting content:

- A `COMPLETE` Stage 1 result has at least one structured location, one nonempty observation string, and one valid evidence citation.
- A `COMPLETE` Stage 2 `CONFIRMED` result has at least one affected gate and one valid supporting-evidence citation.
- A `COMPLETE` Stage 2 `REFUTED` result has at least one affected gate and one valid counterevidence citation.
- A `COMPLETE` Stage 2 `INCONCLUSIVE` result has at least one affected gate and at least one nonempty item across evidence, counterevidence, remaining assumptions, or uncertainty.

Extract and verify repository quotations before these completion and cardinality checks. Trim ASCII whitespace only to test whether a string is nonempty. Do not assess whether an observation or citation is persuasive. If a cardinality check fails, preserve the raw artifact, set its effective role status to `MALFORMED`, perform the one permitted identical-packet retry, and route an unrepaired result to `INCOMPLETE`.

## Four-gate verification contract

Stage 1 records observations corresponding to these gates without an asserted property or verdict. Stage 2 assesses, separately and with citations:

1. **Validity:** Does the code/configuration actually have the asserted security-relevant property?
2. **Reachability:** Can the stated attacker or input class reach it under the pinned deployment and trust-boundary evidence?
3. **Impact:** Does the reachable condition produce the claimed security consequence, rather than a reliability-only effect?
4. **Mitigation/fix state:** Does a primary or compensating control demonstrably prevent the asserted consequence across the enumerated primitive class and variants?

The Stage 2 result is `CONFIRMED`, `REFUTED`, or `INCONCLUSIVE`, with citations for supporting evidence and counterevidence, affected gate(s), remaining assumptions/uncertainty, and any executed deterministic-check evidence. Verifiers do not assign an outcome from another agent's confidence or count.

## Verification packet and result

Stage 1 packets identify the pinned targets, precise scope, intake locations, and packet revision; no candidate ID or proposition exists in that cold packet. Stage 2 packets identify the mechanically assigned `candidate_id`/`finding_id`, primary target and revision, supporting-context repositories/revisions, precise scope, structured locations, and packet revision. Stage 2 adds the normalized proposition, primitive class and variants, four-gate questions, structured cited evidence/counterevidence, and the role-scoped set of typed checks/tables. Results include provider, exact model, effort, stage, role status, packet revision, and cited gate-level material. Fields not required for a particular verdict may be empty, but the post-schema cardinality rules above are mandatory; only Stage 2 may set a security verification result.

## Routing boundary

Mechanical Reconciliation, not a verifier or orchestrator opinion, applies `orchestrator-contract.md` only after all four stage artifacts are `COMPLETE`. Both confirmations with valid citations/revision checks are `CROSS-MODEL VERIFIED`; dual refutation with non-empty counterevidence whose citations/revisions validate is `REFUTED`; a split dispatches only the specified computation-only check when its test, proposition hash, registry digest, and routing table match the immutable pre-discovery registry, then routes the literal output through that table. An unexecutable, unbound, or unresolved split remains `DISPUTED`. Dual inconclusive results are `NOT VERIFIED`. There is no majority vote, confidence averaging, third-model tie-breaker, or silent downgrade.

For Stage 2 fix verification, including verification invoked by `--develop-fix`, both providers use `schemas/fix-verifier-stage2-result.schema.json` and the additional semantic checks and closure routing in [fix-verification-mode.md](fix-verification-mode.md). Ordinary analysis uses `schemas/verifier-stage2-result.schema.json`. Shared reconciliation precedes fix closure routing.
