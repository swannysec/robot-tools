---
name: ghsa-deduplication
description: Claim-level GHSA relations, the D0-D6 pipeline, the confidence rule, and the fix-oracle-backed membership check.
---

# GHSA Deduplication

A duplicate is a report that one fix resolves (the consensus definition used by Bugcrowd,
Intigriti, OSV aliases, and AIxCC patch grouping). Deduplication records relations between
claims as a separate artifact. It never modifies, merges, suppresses, or re-identifies a
finding, and it never changes a finding's status. Confidence comes from the design: no
public source reports a false-merge rate.

Deterministic work runs in `scripts/ghsa-dedup.py`; model work uses the analysis tier with
both providers under [orchestrator-contract.md](orchestrator-contract.md), including the
authorization statement, refusal handling, and fallback disclosure.

## Relation vocabulary

Relations are recorded per claim, after bundled advisories are split into claims (D1).

| Relation | Meaning |
|---|---|
| `SAME_TEXT` | Near-identical report text with identical extracted literal sets; human-confirmed |
| `SAME_ROOT_CAUSE` | The only duplicate relation: one fix resolves both claims (confidence rule below) |
| `VARIANT` | Shares a root-cause family but needs its own analysis; never a duplicate |
| `RELATED` | Shares literals, lineage references, or context; recorded for ordering only |
| `DISTINCT` | Compared and found to have different root causes |
| `UNRESOLVED` | D4 verifiers split and no frozen D5 result applies, or D4 agreement conflicts with a failed D5 result; both verdicts are preserved and the human decides at D6 |

An advisory is a duplicate only if every one of its claims is `SAME_ROOT_CAUSE` with a
canonical claim.

## Pipeline

| Stage | Who | What |
|---|---|---|
| D0 Fingerprint | Script (`ghsa-dedup.py index`, `cluster`) | Normalized-text hash and shingle similarity; literal extraction (paths, symbols, config keys, advisory and CVE IDs, SHAs, versions); compare against advisories in all states. Produces candidate pairs only |
| D1 Claim split | Intake tier, one advisory per packet | Distinct claims with exact quotes, entry point, and typed literals (H1, see [ghsa-triage-mode.md](ghsa-triage-mode.md)) |
| D2 Candidate clusters | Script (`ghsa-dedup.py cluster`) | Join on shared literals and lineage references; orders the queue |
| D3 Re-anchoring | Script (`ghsa-dedup.py reanchor`) | Map verified locations to one common revision; anchor on symbols, with lines as supporting detail; compare at the control site. Anchors come from `ghsa-dedup.py records` (`anchors.json`, built from role-named `control_site` values) |
| D4 Root-cause comparison | Analysis tier, both providers, cold | Code-derived records only, no reporter text (`ghsa-dedup.py d4-packet`); each side is a claim set from `records`, with every member listed unmerged and the set ID as the side's record ID; returns `SAME_ROOT_CAUSE`, `VARIANT`, or `DISTINCT` (`schemas/dedup-d4-result.schema.json`) |
| D5 Fix oracle | Deterministic (`scripts/deterministic-check.py`) | Run Y's skill-authored adversarial-input regression test on X's fix revision; pass supports `SAME_ROOT_CAUSE`, fail means `VARIANT` or an incomplete fix |
| D6 Human confirmation | Human, with a decision brief | Confirm, pick the canonical, or mark variant, distinct, related, or needs more; outward actions stay manual |

`index` takes typed literals only from an H1 check whose `effective_status` is `COMPLETE`.
An advisory without checked literals clusters on D0 literals alone; the command result
counts such entries (`entries_without_typed_literals`) so they are not silently missed.

D5 tests are authored and their registry is frozen before D4 dispatch, so a D5 result can
never be a check invented after seeing verifier results
([deterministic-validation.md](deterministic-validation.md)). Y's test is authored by the
fix-author role from Y's own claim record and contract, passes the registry PoC-overlap
check (`intake-check.py poc-overlap`), and is never a reporter's proof of concept.

**D5 execution path.** `deterministic-check.py` binds each registry test to one repository
and revision and requires the checkout `HEAD` to equal it. Apply Y's frozen test patch to
the base revision and to X's fix revision, producing two derived commits, and register two
entries with the same argument vector, each bound to its derived SHA with its own expected
exit status and the D5 proposition hash. The base entry's oracle expects the failing exit status, so its literal result `PASSED` means the test failed as expected on base; pass the two results to `ghsa-dedup.py route-d4` as `--d5-base` and `--d5-fix` (`route-m` uses `--m3-base` and `--m3-fix`). The adapter's routing table accepts only finding
statuses, so every D5 registry routing entry preserves `DISPUTED`; `ghsa-dedup.py` maps the
literal results to relations through the table below. A patch that does not apply, or a
test that cannot run, yields `NOT_RUN` or `UNRESOLVED`, which counts as no D5 result.

## Confidence rule

`SAME_ROOT_CAUSE` requires both D4 providers to agree, or a D5 result when they split.
Otherwise the relation is `VARIANT` or `DISTINCT`, never a duplicate, or `UNRESOLVED` when
the verifiers split and no frozen D5 result applies.

## Mechanical routing (`ghsa-dedup.py route-d4`)

A D5 result "passed" means Y's test failed as expected on the base revision and passed on
X's fix revision; "failed" means it still failed on X's fix revision. Anything else is no
D5 result.

| D4 native | D4 cross-provider | D5 | Relation |
|---|---|---|---|
| `SAME_ROOT_CAUSE` | `SAME_ROOT_CAUSE` | none or passed | `SAME_ROOT_CAUSE` |
| `SAME_ROOT_CAUSE` | `SAME_ROOT_CAUSE` | failed | `UNRESOLVED` |
| `VARIANT` | `VARIANT` | any | `VARIANT` |
| `DISTINCT` | `DISTINCT` | any | `DISTINCT` |
| any split | | passed | `SAME_ROOT_CAUSE` |
| any split | | failed | `VARIANT` |
| any split | | none | `UNRESOLVED` |
| either leg non-complete after its retry | | any | no relation; both advisories go to full analysis |

Every relation other than `RELATED` and `DISTINCT` is a proposal until the human confirms
it at D6 (`ghsa-dedup.py human`). `ghsa-dedup.py relate` records a D0 `SAME_TEXT` proposal or
a relation the human sets directly. `route-d4` and `route-m` take each leg's provider and model
from runtime metadata, not role output, and refuse to record a relation unless the two legs
come from different providers. The routers check pair identity, status, `declined_scope`, and
verdict only; validate each D4 or M4 artifact against its schema and citations before
routing it. A `SAME_TEXT` match is proposed by D0 only when the normalized texts are
near-identical and the extracted literal sets are identical; one differing config key
means it is not `SAME_TEXT`. After human confirmation, the original's analysis stands for
both advisories.

## Canonical advisory

The canonical advisory in a relation is the earliest received (`created_at`, then GHSA ID).
A human may override the choice; record the reason. A canonical finding produced with a
fallback model cannot serve as a membership-check canonical unless the user explicitly
permits that use.

## Membership check

The membership check avoids a full analysis of report Y when the canonical finding X is
`CROSS-MODEL VERIFIED`, has an accepted contract, and has a fix revision (a candidate patch
counts). X is the single finding record the fix was developed from, not a claim set. Y must be in X's D2 cluster. A membership check without the fix oracle may not
skip analysis; clusters without a fix use D4, D5, and full analysis.

- **M1 (script, `ghsa-dedup.py m1`):** match each typed literal in Y's D1 claims against
  X's locations, enumerated variants, and contract input classes. An unmatched control-site
  literal (a file path) ends the fast path. An unmatched entry-point symbol, config key, or
  command or setting name may proceed to M2 and M3, because the fix oracle is the evidence;
  the unmatched literals are recorded.
- **M2 (analysis tier, fix-author role):** one frozen adversarial-input regression test per
  Y claim at Y's entry point. The packet (`ghsa-dedup.py m2-packet`) contains only Y's
  script-validated typed literal fields and X's contract, never reporter free text. The
  test passes the PoC-overlap check before registration.
- **M3 (script, sandbox):** run Y's test through `deterministic-check.py` on derived
  revisions; it must fail as expected on base and pass on X's fix.
- **M4 (analysis tier, both providers, cold):** proposition "Y's claim shares X's root
  cause and is resolved by X's fix", given X's code-derived records, Y's claim quotes, and
  the M1 and M3 results, with no reporter text from X (`ghsa-dedup.py m4-packet`,
  `schemas/dedup-m4-result.schema.json`).
- **Routing (`ghsa-dedup.py route-m`):** `SAME_ROOT_CAUSE` (covered by X) only if M1 passed,
  M3 failed then passed, both M4 verifiers returned `CONFIRMED`, and the human confirms.
  Anything else sends Y to full analysis.

Y then inherits X's scoring and gets a relation record, not its own verified finding. The
membership check cannot discover new siblings that only Y hints at.

**Per-cluster order:** analyze one advisory, fix it, then membership-check the rest of the
cluster against that fix.

## Confidentiality

- Each advisory has its own run directory; the cross-advisory index holds IDs, digests,
  hashed shingles, and typed literals, never report text.
- D4 packets contain code-derived records only. D4 and M4 packets never contain reporter
  text from the other advisory.
- H4 drafts are scoped to the advisory's own records ([ghsa-triage-mode.md](ghsa-triage-mode.md)).
  For an unpublished duplicate, use "previously reported" wording; disclosing that another
  report exists is the human's decision.

## Relation records

`schemas/dedup-relation.schema.json`. Each record holds the relation ID, the canonical and
other advisory and claim IDs, the relation, its basis (`D0`, `D4`, `D5`, `MEMBERSHIP`, or
`HUMAN`), the D4 verdicts with provider, model, and artifact digests, D5 and M1-M4 result
references, the canonical choice and any override reason, the human decision, and the
digests it depends on. It contains no report text.

**Invalidation (`ghsa-dedup.py invalidate`).** A relation is invalidated when any digest it
depends on changes: either advisory's description digest or `updated_at`, either D1 claim
set, X's finding record or final status, X's fix revision, or a D4, D5, or membership
artifact superseded by a stage retry. Invalidated relations are preserved and labeled, and
the pair is re-run from the earliest affected stage.
