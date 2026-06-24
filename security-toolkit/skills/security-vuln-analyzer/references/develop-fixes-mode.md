---
name: develop-fixes-mode
description: --develop-fix invocation mode — author validated regression tests + a minimum fix on a branch, gate it (exploit-fail-to-pass + co-equal regression) in a two-phase-network sandbox, emit a candidate patch with provenance, then hand off mandatorily to the independent --verify-fix gate. Author never confirms its own fix. v1 Rust-first.
---

# Develop-Fixes Mode (`--develop-fix`)

A specialization of the security-vuln-analyzer workflow that **authors and lands a candidate fix** for a confirmed finding, then routes mandatorily to the independent `--verify-fix` gate. It slots in *front of* fix-verification: develop-fixes writes the fix and its oracle; `--verify-fix` confirms it. **The author never confirms its own fix.** Output is a **candidate patch** with a provenance trail — a human approves the merge, always. v1 is **Rust-first**.

## Contents

- [When to use this mode](#when-to-use-this-mode)
- [Invocation contract](#invocation-contract)
- [Core invariants](#core-invariants)
- [The 8-step flow](#the-8-step-flow)
- [Test authoring — the three validity guards](#test-authoring--the-three-validity-guards)
- [Sink-coverage guard (deterministic)](#sink-coverage-guard-deterministic)
- [Security + regression gates](#security--regression-gates)
- [Sandbox — two-phase network](#sandbox--two-phase-network)
- [Mandatory handoff + dual-verifier policy](#mandatory-handoff--dual-verifier-policy)
- [Scope rule](#scope-rule)
- [Rust-first templating priority](#rust-first-templating-priority)
- [Landing — visibility-gated](#landing--visibility-gated)
- [Candidate-patch + provenance schema](#candidate-patch--provenance-schema)
- [Cross-references](#cross-references)

## When to use this mode

- A finding is **confirmed** (survived the analysis pipeline) and carries its **Invariant + Adversarial Test Contract** (emitted by FINDER 3 at analysis time, recorded in the report).
- You want a **candidate fix authored, landed on a branch, and gated** — not just a suggested fix.

Do **NOT** use this mode for:
- Initial vulnerability discovery → default skill invocation.
- Assessing an **already-shipped** fix (PR/commit) → `--verify-fix` mode.
- A finding whose Contract is **DISPUTED or non-converged** → refuse to author, escalate to a human (you cannot author against a spec that has not converged).

## Invocation contract

Required:
- `--develop-fix` — the explicit flag (mirrors `--verify-fix`).
- `--finding <id>` — the specific confirmed finding to fix.
- `--analysis <path|report>` — the analysis report carrying the finding + its Contract. If omitted in a fresh session, re-derive context from `--tracker`.

Optional:
- `--tracker <URL|path>` — issue/advisory/GHSA tracking the vulnerability (URL fetched; local path / `file://` read from disk). When the vuln arrived via an existing GHSA, this is the advisory the landing step **reuses** (see [Landing](#landing--visibility-gated)).
- `--multi-file` — opt in to a fix that spans more than one file (requires stronger review; off by default).

**First-class entry via BOTH the flag AND natural language** — "develop/build/author the fix for finding N", "remediate this finding". **Any** invocation (flag or NL) must FIRST **confirm the concrete target** — a specific finding + its *converged* Contract — and that it will author tests + a minimal fix + land on a branch, **before acting**. Never silently auto-author as a side effect of an ambiguous analysis phrase: a bare "fix security" with no concrete target is an *analysis* request, not an authoring instruction. Supports same-session continuation (reuse in-context finding/Contract) and fresh-session re-derive (bootstrap from `--analysis`/`--tracker`).

## Core invariants

1. **Author ≠ verifier.** develop-fixes never confirms its own fix. Confirmation is the separately-invoked `--verify-fix` gate, on a **cold artifact** (no author reasoning trace), disproof-biased.
2. **Single strong author — no author-side mesh.** A single strong author beats a multi-agent author at far lower cost; separate the *verifier*, not the author.
3. **Exploit-fail-to-pass is the security gate** — the frozen tests must FAIL on the original untouched code and PASS on the patched code. Rescan / "tests pass" is insufficient (misses a deceptively-passing class).
4. **Regression is co-equal** — the full project suite must stay green; block on any pass→fail flip.
5. **Test-validity guards (non-negotiable):** fail-on-unpatched + reach-the-sink (sink-coverage) + freeze-before-authoring.
6. **Bounded iteration N≤3**, carrying the prior failed patch + gate output + Contract forward; then STOP and escalate to a human with failure evidence. Over-refinement increases vulns — never iterate unbounded.
7. **Branches, not worktrees**, as the work substrate; **visibility-gated landing** (never leak an undisclosed public-repo vuln).
8. **Human review before merge, always.** Output is a "candidate patch" + provenance trail.

## The 8-step flow

1. **Input + contract-convergence gate.** Load the finding + its Invariant + Adversarial Test Contract. If the Contract is DISPUTED or has not converged → **refuse to author, escalate to a human.**
2. **Author regression tests** from the Contract's adversarial input classes (see [validity guards](#test-authoring--the-three-validity-guards)). Each test must (a) **fail on the original untouched code**, (b) **reach the finding's `file:line` sink**, (c) be **frozen** before fix authoring.
3. **Implement the minimum fix on a branch** — root-cause-first, scoped to the finding's files/functions. Multi-file requires `--multi-file` + stronger review.
4. **Run the gates in an ephemeral two-phase-network sandbox**, capturing evidence even on failure (see [gates](#security--regression-gates) and [sandbox](#sandbox--two-phase-network)).
5. **Bounded iteration:** on gate failure, retry at most N≤3, carrying the prior failed patch + gate output + Contract forward. After N, STOP and escalate with failure evidence.
6. **Emit a candidate patch** (branch + frozen tests + verification report) labeled "candidate patch," with the [provenance trail](#candidate-patch--provenance-schema). Persist the validated tests into the repo suite as durable regression anchors.
7. **Mandatory handoff to independent verification** (`--verify-fix`) — non-skippable; the verifier receives a cold artifact and never the author's reasoning trace.
8. **Human review before merge** — always. The human also routes disclosure (see [Landing](#landing--visibility-gated)).

## Test authoring — the three validity guards

develop-fixes authors *both* the fix and its oracle, so every authored test must be **validated before it is trusted**:

- **(a) Fail-on-unpatched** — the test must FAIL on the original, untouched code. A test that passes before the fix proves nothing.
- **(b) Reach-the-sink** — the test must demonstrably execute the finding's `file:line` sink (see [Sink-coverage guard](#sink-coverage-guard-deterministic)).
- **(c) Freeze-before-authoring** — commit or hash-record the tests before writing the fix; the harness rejects post-freeze edits so the author cannot tune the oracle to the patch.

Post-fix, a **mutation check** (`necessist`) must confirm the frozen tests KILL a mutant at the fix site; a test that still passes when the fix is mutated away is weak and must be strengthened before merge.

Rust test forms (one per adversarial input class in the Contract):
- **`#[test]` PoC** — call the vulnerable function with attacker input; `#[should_panic(expected=...)]` to encode the unpatched panic, then assert the correct non-panicking output after the fix. (ToB's panic-returning-Result lint excludes `#[test]` fns, so intentional unwrap/expect in tests won't trip it.)
- **`proptest`** — write the security invariant as a property (e.g. `prop_assert!(canonicalized.starts_with(root))` for CWE-22; `a.checked_add(b).is_some() || …` for CWE-190).
- **`cargo-fuzz`** — for parser/deserializer panic-surface sinks; the crash artifact `fuzz/artifacts/<target>/crash-<hash>` IS the frozen exploit (`cargo +nightly fuzz run <target> <artifact>` fails on unpatched, passes on patched).
- **`derive_fuzztest`** — one invariant emits BOTH a proptest and a libFuzzer target.
- **Class Coverage Check** — for filtering-class fixes, enumerate every member of the named primitive class from its canonical source and emit one frozen test per member the filter must reject (see `deterministic-validation.md`).
- **Negative PoC** — pair every exploit-fail-to-pass test with a benign-still-passes companion so the fix is proven not over-restrictive.

## Sink-coverage guard (deterministic)

Validity guard (b) — a test must demonstrably REACH the finding's `file:line` sink — is enforced by the **deterministic sink-coverage check** (no LLM judgment): `cargo-llvm-cov --json` region count `> 0` at the finding's `file:line`. **Critical gotcha:** a source line carries multiple coverage segments, so the check must AGGREGATE the count over the line (`| max`, or "any segment with count > 0") — a bare per-segment test emits spurious `0`s. An unreached line yields `null` → FAIL. Where llvm-cov is unavailable/flaky, fall back to a Miri/CodeQL execution trace or (for type-state/newtype fixes that make the sink unconstructable) a `trybuild` compile-fail proof; record the method used in provenance.

**Full procedure** (commands + verified segment shape + fallbacks) → `deterministic-validation.md` § Sink-Coverage Check.

## Security + regression gates

Run both in the sandbox, capturing evidence even on failure:

- **Security gate — exploit-fail-to-pass:** the frozen tests flip from FAIL (unpatched) to PASS (patched). The PoC must run against the **original untouched** code to earn the "fail" half.
- **Regression gate (co-equal):** the full project suite stays green — block on any pass→fail flip. Rust default: `cargo +nightly careful test` + clippy restriction lints as `#![deny(...)]` (`unwrap_used`, `arithmetic_side_effects`, `indexing_slicing`, `undocumented_unsafe_blocks`) + `cargo audit` / `cargo deny check` (the fix must not pull a vulnerable/untrusted dep).
- **Deeper verification matched to the finding class, kept DIFFERENT from the author's mechanism:** Miri (unsafe/UB — UAF, aliasing, data races), Kani (bounded proof of panic/overflow/memory-safety freedom), or CodeQL Rust taint (injection). A verifier that shares the author's mechanism does not provide independent signal.

**Nightly caveat:** Miri, Kani, `cargo-careful`, `cargo-fuzz`, and `-Zsanitizer` flags all require the **nightly** toolchain; Cackle is Linux-only. Set up nightly components in the network phase.

## Sandbox — two-phase network

v1 uses **built-in OS sandbox modes** (Docker / `sbx` microVM is the v2 hardening). The sandbox is the security boundary while the gates run.

- **Claude Code:** `sandbox.enabled: true`; `filesystem.denyRead` for `~/.aws` and `~/.ssh`; `allowUnsandboxedCommands: false`.
- **Codex:** `sandbox_mode = workspace-write` with `[sandbox_workspace_write] network_access` toggled per phase.

**Two-phase network:**
- **Phase 1 (network ON):** `cargo fetch` / `cargo build` + nightly-component setup.
- **Phase 2 (network OFF, `--offline`):** run the gates, so no gate step can reach the network.

**Verified (this repo's toolchain):** the `cargo fetch` (online) → `cargo test --offline` (cache-only) handoff works end-to-end — phase 2 builds dependencies from the phase-1 cache with no network. **Note:** network *enforcement* is config-gated and not on by default — confirm `sandbox.enabled: true` (Claude Code) and `network_access = false` (Codex phase 2) are actually set for the gate phase; the cargo `--offline` flag is the mechanism the mode controls, the OS sandbox is the enforcement layer behind it.

## Mandatory handoff + dual-verifier policy

After emitting the candidate patch, hand off to `--verify-fix` — **non-skippable**. The verifier receives a **cold artifact** (finding + Contract + patch diff + frozen tests) and **never the author's reasoning trace**; it is disproof-biased ("You did NOT write this finding").

**Verifier models:** run **two independent verifiers — Opus 4.8 and gpt-5.5** — for complementary cross-model perspectives. If the author is Opus 4.8, the Opus verifier leg relies on **capability asymmetry** (read-only + test-execution-only, cold artifact) and the gpt-5.5 leg provides true cross-family independence. **Disagreement is settled deterministically by executing the frozen tests against the patch** — fix-verification has a real oracle. Do not exceed two verifier models. The gpt-5.5 leg sends code to OpenAI (same data-classification caveat as FINDER 5); on unavailability, degrade to Claude-only with a **loud cross-model-unavailable warning**.

## Scope rule

**One finding → one branch → one Contract → one verification gate.** Batch only the **variants of a single finding** (same root cause / shared Contract) on that one branch and gate — covering the Contract's multiple adversarial input classes together. A **truly distinct finding gets its own branch** (the synthesis "instantiation rule"). Never batch verification across distinct findings.

## Rust-first templating priority

**v1 is Rust-only — state this limitation explicitly to the user.** Polyglot support is deferred. Author secure-fix tests + idioms in this priority order:

1. **Rust-first (do these first):** Send/Sync misimpl (most prolific Rust class), panic/unwrap DoS (CWE-248), integer overflow (CWE-190), unsafe UAF/buffer (CWE-416 / CWE-119), deserialization recursion (CWE-502).
2. **Web-app CWEs (second):** command injection (CWE-78), path traversal (CWE-22), SQLi (CWE-89), SSRF (CWE-918), XSS (CWE-79) — ready-made bypass catalogs in `cwe-verification-procedures.md`.

Secure-fix idioms (minimum-fix, root-cause-first) per CWE live in `remediation-patterns.md` and `rust-security.md`; ground the target version against RustSec `[versions].patched` when the finding maps to a known advisory.

## Landing — visibility-gated

Branches are the work substrate; **"open a PR" is an explicit, visibility-gated terminal step, off by default for public repos.** This prevents leaking an as-yet-undisclosed public-repo vulnerability (the diff, branch name, PR title/body would reveal it).

1. **Detect visibility first** — `gh repo view --json visibility,isPrivate` gates everything downstream.
2. **Private repo (or already post-disclosure):** local branch → push → **draft PR** is acceptable; full provenance trail in the PR body.
3. **Public repo, undisclosed vulnerability:** **never auto-push, never open a normal PR.** Default to a **local branch + a patch/evidence bundle** (diff + frozen tests + verification report). Route the fix through GitHub's **repository security advisory → temporary private fork**, then merge + publish under human control.
4. **Reuse-or-create, keyed on the advisory's `private_fork` field:**
   - If the vuln arrived via an existing GHSA (typically `--tracker`), **reuse it**:
     `gh api /repos/OWNER/REPO/security-advisories/GHSA-… --jq '.private_fork'`
     - `null` → `POST /repos/OWNER/REPO/security-advisories/GHSA-…/forks`, then poll (~5 min; async 202) until non-null.
     - an **object** → clone `private_fork.full_name` directly. *(Verified via GitHub REST docs: `private_fork` is a Simple-Repository object — `id`, `name`, `full_name`, `html_url`, … — and `null` before a fork exists.)*
   - Create a **new** advisory (`POST /repos/OWNER/REPO/security-advisories`, always with `patched_versions` set) **only if none exists**. Externally-reported submissions arrive as `state==triage` (must be accepted → `draft`); maintainer drafts as `state==draft`.
5. **Never write the vulnerability description, PoC, or Contract into any public-visible surface** — PR title/body, branch name, commit message on a public-safe branch. The public-safe branch carries **code only**; finding details + Contract + provenance stay in the private channel.
6. **Two steps are web-UI-only — PAUSE for the human:** `Merge pull request(s)` and the triage→draft `Accept and open as draft` have **no REST/GraphQL/`gh` equivalent**. Surface the advisory URL and stop. *(Verified: the update endpoint accepts `state ∈ {published, closed, draft}`, but triage→draft via PATCH is NOT documented to work — treat the triage acceptance as web-UI-only.)* The advisory merge **bypasses branch protections**, so develop-fixes' own security + regression gates are the **sole enforcement** before merge. Structure the fix as exactly **one PR** to the base branch (multiple PRs block the merge step). Publishing (`PATCH /repos/OWNER/REPO/security-advisories/GHSA-… --field state=published`) IS API-reachable and **must follow merge** — it assigns the GHSA id, fires Dependabot alerts, and deletes the private fork.

## Candidate-patch + provenance schema

Emit the candidate patch labeled **"candidate patch"** with a provenance trail:

- **Finding ID** + **Contract version** (the converged Contract used as the oracle)
- **Author model**; **verifier models** (Opus 4.8 + gpt-5.5, or "Claude-only — cross-model unavailable")
- **Branch name**; **frozen-test identifiers / hashes**; **retry count** (of N≤3)
- **Per-test row:** `input-class → expected → actual → pass/fail`, before (unpatched) and after (patched)
- **Sink-coverage method + evidence** (llvm-cov segment count, or the documented Miri/CodeQL trace / trybuild fallback)
- **Gate results:** security (exploit-fail-to-pass) + regression (full-suite) + deeper-verification tool + mutation-kill result
- **Landing posture:** repo visibility + chosen path (draft PR | bundle + GHSA private fork) — never the vuln details on a public surface

The candidate patch is **not** an autonomous production closure — a human approves the merge, and the mandatory `--verify-fix` gate must return YES / CONDITIONAL YES first.

## Cross-references

- Default workflow + mode registration → `SKILL.md`
- The gate develop-fixes hands to → `fix-verification-mode.md`
- Sink-coverage + Class Coverage Check (deterministic) → `deterministic-validation.md`
- Rust secure-fix idioms by CWE → `remediation-patterns.md`, `rust-security.md`, `cwe-verification-procedures.md`
- Verifier COUNTER instruction (cold-artifact, disproof-biased) → `adversarial-verification.md`
- The Contract this mode consumes → `step-2-agent-prompts.md` (FINDER 3) and `report-template.md`
- Design rationale (internal decision records, not shipped): ADR-013 (develop-fixes mode), ADR-014 (disclosure-safe landing)
