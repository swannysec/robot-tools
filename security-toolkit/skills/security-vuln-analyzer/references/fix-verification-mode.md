---
name: fix-verification-mode
description: --verify-fix invocation mode — bypass construction against shipped fixes, mandatory before vulnerability issue closure
---

# Fix-Verification Mode (`--verify-fix`)

A specialization of the security-vuln-analyzer workflow that runs after a fix has shipped, with bypass construction as the explicit framing. Mandatory before any vulnerability issue moves to closed/done state.

## When to use this mode

- A vulnerability issue has a cited fix PR or commit
- Closure verdict is needed (YES / CONDITIONAL YES / NO)
- The original analysis report is available locally OR the tracker issue has enough context to reconstruct it

Do NOT use this mode for initial vulnerability discovery — that's the default skill invocation.

## Invocation contract

Required arguments:
- `--tracker <URL|path>` — Issue/advisory/GHSA that tracks the vulnerability. REQUIRED. Accepts either a URL (fetched) or a local file path / `file://` URL (read from disk). The local-file form is for offline advisories, pasted reports, and acceptance fixtures. Without this, a fresh session has no context for what was being fixed. Examples: GHSA URL, Linear issue URL, Bugzilla URL, internal ticket URL, or a local `advisory.md` file.
- `--fix <PR-or-commit>` — The fix being verified. REQUIRED. PR URL or commit SHA. Multiple values allowed if the fix spans PRs (comma-separated or repeated flag).

Optional arguments:
- `--analysis <PATH>` — Path to the original analysis report if available locally. If omitted, agent reconstructs context from `--tracker`.

## Workflow

1. **Obtain the issue body from `--tracker`.** If `--tracker` is a URL, fetch it (`gh api` for GHSA/GitHub, WebFetch otherwise). If it is a local file path or `file://` URL, read the file from disk. Either way, capture: original vulnerability description, recommended fix, and (if R1.2 was applied at original analysis time) the Invariant + Adversarial Test Contract.

2. **Fetch the fix diff(s) from `--fix`.** For each cited PR or commit, retrieve the diff (for a PR URL use `gh`; for a local commit SHA, run from the repository checkout and use `git show <SHA>`). If multiple, retrieve all.

3. **Build a SURFACE MAP focused on the fix locus + the Invariant.** This parallels Step 1.5 in the default workflow but scoped to the fix's blast radius rather than the whole vulnerability surface. Apply Primitive Class Enumeration from `threat-modeling-methodology.md` to the Invariant — what input classes must the fix handle?

4. **Dispatch finders specifically tasked with:**
   - **Bypass construction** — produce inputs the fix is supposed to handle and trace each output. If any test from the contract fails, the fix is incomplete.
   - **PR attribution audit** — verify the cited fix PR(s) actually contain the relevant code changes, not unrelated work that shares a ticket. Flag PRs that are defense-in-depth or unrelated.
   - **Regression check** — flag changes that weaken adjacent security controls.
   - **Test coverage audit** — for every primitive class enumerated in the original analysis, confirm a regression test exists in the fix PR or in the test suite.

   Finder roles use the rotation table in `SKILL.md` § Verify-Fix Rotation Table.

5. **Dispatch adversarial verifiers (Step 3.5-equivalent) on bypass candidates.** VERIFIERs apply the COUNTER instruction from `adversarial-verification.md`: "Reframe the verification task as bypass construction. Your job is to break the fix, not to confirm it implements the recommendation."

6. **Output a Closure Verdict** with one of:
   - `YES` — All contract tests pass; gate-by-gate reasoning cites traced outputs; PR attribution clean.
   - `CONDITIONAL YES` — Original PoC closed; residual gaps documented (e.g., a primitive class member outside fix scope but tracked as known limitation). Explicit residuals listed.
   - `NO` — Bypassable. Reproducible bypass with file:line trace. New finding required; existing issue does NOT close.

Each verdict requires:
- Gate-by-gate reasoning (per the 4-gate review framework: Reachability, Real Impact, Mitigation Check, Environment Check)
- File:line citations for every claim
- For NO verdict: at least one constructed adversarial input that defeats the fix, with traced output

## Fresh-session invocability

This mode is designed to run in a fresh session with NO prior state. The orchestrator only needs `--tracker` and `--fix` URLs to bootstrap. Do not assume the analyst remembers anything from the original analysis — re-derive from the tracker body.

## Output

A `--verify-fix` run produces a single report (separate format from initial-discovery reports):

- Closure Verdict (YES / CONDITIONAL YES / NO)
- Per-gate reasoning with citations
- For each contract test: input class → expected output → actual output → pass/fail
- For NO verdict: bypass PoC with reproduction steps
- For CONDITIONAL YES: residual-gap inventory
- PR attribution audit results

## Mandatory before closure

The skill enforces: a vulnerability issue cannot move to closed/done state until a `--verify-fix` run completes with `YES` or `CONDITIONAL YES`. Not severity-gated. The failure mode this addresses is fast confirmation that misses a bypass; severity-gating would carve out exactly the bucket where premature confirmations occur.

## Cross-references

- Default workflow → `SKILL.md`
- Rotation table → `SKILL.md` § Verify-Fix Rotation Table
- VERIFIER COUNTER instruction → `adversarial-verification.md`
- Why this mode exists → `premature-fix-confirmation.md`
- Empirical grounding → `confirmation-bias-in-security-review.md` § Fix-Confirmation Bias
- Bypass-construction methodology → `evidence-validation-techniques.md` § 6 Adversarial Bypass Construction
