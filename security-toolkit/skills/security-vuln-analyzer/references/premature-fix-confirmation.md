---
name: premature-fix-confirmation
description: Failure pattern reference for premature fix confirmation — single-class enumeration, recommendation-match vs attack-closure, PR attribution drift, reporter-discovers-bypass
---

# Premature Fix Confirmation — Failure Pattern Reference

## Pattern 1 — Single-class enumeration

PATTERN: Analysis identifies one primitive class as "the attack vector" and enumerates exemplars within that class.
TRIGGER: A vulnerability with multiple primitive classes that achieve the same attacker goal (most sanitization, encoding, and authorization vulns).
COUNTER: Apply Primitive Class Enumeration (threat-modeling-methodology.md). State the attacker goal; enumerate the full equivalence class; verify the fix scope covers each member.
GENERALIZED EXAMPLE: A fix filters one family of invisible characters (e.g., bidi controls) to prevent UI spoofing but does not filter the broader whitespace family that achieves the same visual obfuscation goal through different codepoints.

## Pattern 2 — Recommendation-match ≠ attack-closure

PATTERN: Verifier confirms "fix implements the recommendation" without constructing inputs the fix is supposed to handle.
TRIGGER: Any fix-verification task that begins from "is this fixed by PR X?" rather than "what inputs defeat this fix?"
COUNTER: Apply Invariant + Adversarial Test Contract (step-2-agent-prompts.md FINDER 3). For every input class in the contract, run the fix and verify the output. A satisfied recommendation with a failed contract test means the fix is incomplete.
GENERALIZED EXAMPLE: A recommendation says "collapse runs of more than N consecutive separator characters." Implementation uses a counter that resets on any non-separator character. Recommendation satisfied (counter present, cap is N). Attack not closed (interleaved benign character defeats counter).

## Pattern 3 — PR attribution drift

PATTERN: An issue is closed against a cited fix PR, but the actual closure was effected by a different PR (often earlier, often broader). Or the cited PR contains unrelated changes that share a tracker ticket.
TRIGGER: Multi-PR fix flows where defense-in-depth, refactors, and primary mitigations all attach to one ticket.
COUNTER: PR Attribution Audit (fix-verification-mode.md). For each cited PR, confirm it contains the code change that closes the original PoC; flag PRs that are unrelated or defense-in-depth.
GENERALIZED EXAMPLE: A vulnerability is closed against PR-B in a ticket. PR-B adds extraction of nested structures inside a parser. The original PoC was already blocked by PR-A (an earlier PR that added validation rejecting the parser construct outright). PR-B is defense-in-depth, not the primary fix. Closure citation is misleading.

## Pattern 4 — Reporter discovers the bypass

PATTERN: A reporter's second submission identifies a bypass within hours/days of the fix shipping.
TRIGGER: Fixes shipped without an adversarial bypass-construction step.
COUNTER: Mandatory --verify-fix before closure (SKILL.md). Adversarial bypass construction (evidence-validation-techniques.md). The reporter's second submission is the cheapest bypass-discovery channel, but it incurs a credibility cost; structured proactive verification at fix-merge time catches the same bypasses without the second round.
GENERALIZED EXAMPLE: A fix ships to production. A reporter constructs a one-line variant of the original PoC that defeats the fix and submits a follow-up advisory the next day. The variant is in the same primitive class the original analysis enumerated; it was not in the test suite.

## Cross-references

- Primitive Class Enumeration → references/threat-modeling-methodology.md
- Invariant + Adversarial Test Contract → references/step-2-agent-prompts.md (FINDER 3)
- Fix-confirmation bias mechanics → references/confirmation-bias-in-security-review.md
- Fix-verification mode → references/fix-verification-mode.md
- Adversarial bypass construction → references/evidence-validation-techniques.md
