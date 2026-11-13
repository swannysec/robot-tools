---
name: ghsa-deduplication
description: Issue-level GHSA deduplication (step 1a) before analysis - a two-provider issue list, a directional per-issue comparison with earlier advisories, scripted dispositions, and human confirmation of obvious duplicates.
---

# GHSA Deduplication (step 1a)

A later report's issue is **covered** by an earlier report when both providers say the earlier
report states the same vulnerable mechanism reached through the same trigger, so that fixing it
as the earlier report describes would also stop the later issue. Similar is not same: sharing a
component, file, function, or weakness class is not enough. This is the directional, fix-based
test bug bounty programs use ("fixing one removes the need to fix the other"). Scripts and models
propose; a human decides whether a report skips analysis, and write-back stays human-approved.
Deduplication never modifies, merges, suppresses, or re-identifies a finding and never changes a
finding's status.

Step 1a runs before analysis, once per selected advisory, oldest first. Deterministic work runs
in `scripts/intake-check.py` (packets and role-output checks) and `scripts/ghsa-dedup.py`
(comparison plan, dispositions, confirmation). Model legs use the analysis tier of both
providers, with no tools, under [orchestrator-contract.md](orchestrator-contract.md): the
authorization statement, refusal handling, and fallback disclosure apply. Launch forms are in the
runtime guides under "Step 1a legs". Not yet implemented: the currency check against the
default-branch commit at the advisory's creation time, and post-fix coverage checks inside
`--develop-fix` (a test that already passes on a base containing the canonical's merged fix).

## Scope and preflight

- **Queue mode:** capture every listed advisory (`ghsa-fetch.py queue --state all`, then
  `ghsa-fetch.py advisory` for each; capture is read-only). Step 1a runs on triage or draft
  advisories that have no `step1a/dispositions.json` in any run of that advisory.
- **Single `--ghsa`:** fetch the queue listing and capture each advisory that `compare-plan`
  names for the report.
- **Preflight:** before any model call, run `compare-plan` for each selected report and show the
  number of reports, the number of comparisons, and an estimate: about $0.30 per report for
  listing and classification, plus about $0.05 per comparison, plus one cross-provider run for
  each comparison where the native leg says YES. The user confirms. Backfilling an existing queue
  is the user's choice at this prompt.

## Steps

| Step | Who | Command | Output (conventional name in `<run>/step1a/`) |
|---|---|---|---|
| 1. Issue listing | Native provider | `intake-check.py issue-packet`, then `issue-check` | `issue.check.json` |
| 2. Issue review | Cross provider, cold | `intake-check.py review-packet`, then `review-check` | `review.check.json` |
| 3. Native classification of added issues (only when needed, below) | Native provider | `intake-check.py kinds-packet`, then `review-check` | `kinds.check.json` |
| 4. Merge | Script | `intake-check.py issues` | `issues.json` |
| 5. Comparison plan | Script | `ghsa-dedup.py compare-plan` | `compare-plan.json` |
| 6. Comparisons | Native leg for every planned report; cross leg, cold on the same packet, only when the native leg answered YES for some issue | `intake-check.py compare-packet`, then `compare-check --leg native` or `--leg cross` | `compare/<earlier GHSA ID>/` |
| 7. Dispositions | Script | `ghsa-dedup.py dispositions` | `dispositions.json` |
| 8. Confirmation of an obvious-duplicate proposal | Human | `ghsa-dedup.py confirm`, then `dispositions --confirmation` | `confirmation.json` |

Check commands take `--provider` and `--model` from runtime metadata, never from role output, and
`--fallback-model` and `--fallback-use-permitted` under the fallback rules. The commands check
these bindings and refuse input that breaks one: `issue-check` and `review-check` require the
packet to have been built from the same capture; `issues` requires the review and the native
classification to belong to that native listing (and review); `dispositions` requires each
comparison packet to match the planned pair and the current issue list, each leg check to answer
that packet, and each earlier advisory's current capture to have the state the plan recorded.
Other digests in packet metadata and checks are recorded for audit only. Every directory is
created with mode 700 and every file 600.

## Issue list

The listing names each issue the report claims: one vulnerable mechanism reached through one
trigger, with `mechanism`, `trigger`, `kind`, an exact `quote` (at most 300 characters), and the
code `literals` the report writes for it (file paths, symbols, config keys). `issue-check` and
`review-check` require every quote to be an exact substring of one captured advisory field after
line endings are normalized; a failed quote makes the output `MALFORMED` (one identical-packet
retry). A literal that is not verbatim is dropped and listed in `dropped_literals`, with no retry:
literals only aid lookups. If the native listing is still non-complete after its retry, the
refusal and incompleteness rules flag it to the user and step 1a stops for that report.

The review packet lists the native issues by fixed ID (`I1`, `I2`, ...) without their kinds. The
cross provider classifies each listed ID and adds issues the listing missed; added issues take the
next IDs. Kinds:

- `TECHNICAL`: a behavior of the code as it is now (something vulnerable runs, is loaded, or is
  reachable, or a protection fails to stop it).
- `DOCUMENTATION_UI`: only documentation, user-interface wording, warnings, or guidance text.
- `FIX_GUIDANCE`: a critique of a proposed, possible, or existing remediation rather than a
  separate behavior of the current code.

An issue is ignored for deduplication only when both providers' kinds are non-technical. An added
issue the cross provider calls technical is technical. An added issue it calls non-technical needs
the native provider's kind: `issues` reports `PENDING_NATIVE_KINDS` and lists the IDs until
`kinds-packet` and `--native-kinds-check` supply it; if that leg fails, the issue stays technical.
If the review leg is missing, failed, or refused after its retry, comes from the listing's
provider, or comes from a fallback model without the user's permission, `cross_leg` records why,
nothing is ignored, and no obvious duplicate can be proposed. Ignored issues stay in the decision
brief, and fix-guidance issues go to the fix author.

## Comparison set

`compare-plan` reads the queue listing and the captures. The later report must be in the listing
in triage or draft state, and each earlier capture's description digest and `updated_at` must
match its listing entry (otherwise the command asks for a recapture).

| Earlier advisory (by `created_at`, then GHSA ID) | Role | Effect of a match |
|---|---|---|
| Triage or draft | `OPEN` | Covers the issue; canonical candidate |
| Published | `PUBLISHED` | Flagged as a possible regression or incomplete fix; the issue is still analyzed |
| Closed with comments (count above zero, unknown, or comment capture incomplete) | `CLOSED_WITH_COMMENTS` | Shown in the brief with its closing comment; the issue is still analyzed |
| Closed with no comments | excluded | none |
| Created later, or the report itself | excluded | none |

## Comparison

The packet holds both full rendered reports in labeled untrusted-data blocks whose BEGIN and END
lines carry a random per-packet token (report text cannot know it, so it cannot imitate a data
boundary), the later report's technical issues by ID as one-line summaries marked as data, and the
fixed question: YES when the earlier report states the same
mechanism through the same trigger; NO when the issue would need its own change; UNSURE when the
reports lack the detail to decide. `compare-check` requires the packet's pair and each listed ID
exactly once, and writes `native.check.json` or `cross.check.json` beside the packet. Rebuilding a
packet deletes that pair's earlier leg checks.

## Dispositions

For each technical issue and each planned earlier report:

| Answers | Open report | Published or closed report |
|---|---|---|
| Both providers YES | Covers the issue | Match flag |
| Exactly one YES (including a cross YES after a native NO or UNSURE, or a native YES whose cross leg is missing, failed, same-provider, or an unpermitted fallback) | Unresolved: `ONE_PROVIDER_YES` | Information only |
| Native leg not complete | Unresolved: `COMPARISON_INCOMPLETE` | Information only |
| Earlier report's rendered text changed since its packet, and some provider said YES | Unresolved: `EARLIER_REPORT_CHANGED`; pair listed in `rerun_pairs` | Information only |
| No YES | No effect | No effect |

UNSURE counts as not YES. A fallback-model leg counts only with the user's recorded permission.
An issue is `COVERED` when any open report covers it: the canonical is the earliest such report,
and the rest are listed in `also_covered_by`. Coverage stands when another pair failed or a
published report also matches. Otherwise the issue is `UNRESOLVED` when any open report gave an
unresolved outcome, and `NEW` when none did. Non-technical issues are `IGNORED`.

| Verdict | When | `analysis_issue_ids` |
|---|---|---|
| `LIST_UNREVIEWED` | The review leg is not complete | Every technical issue |
| `NO_TECHNICAL_ISSUES` | Every issue is ignored | Every listed issue |
| `OBVIOUS_DUPLICATE` (proposal) | Every technical issue is covered | None, once confirmed |
| `PARTIAL` | Some technical issues are covered | New and unresolved issues |
| `NOT_COVERED` | No technical issue is covered | Every technical issue |

`analysis_status` is `AWAITING_CONFIRMATION` for an obvious-duplicate proposal without a current
confirmation: the report is neither analyzed nor paused for missing evidence until the human
decides. Otherwise it is `READY`. Covered issues of a partial report skip analysis without a
separate confirmation; the write-back brief lists them.

## Confirmation

Queue mode continues past obvious-duplicate proposals and presents them in one decision brief at
the end of step 1a. For each report the brief shows every issue with its canonical, both
providers' reasons (from the check files), `cross_leg`, ignored issues and fix guidance, and
published and closed matches. `confirm` records `CONFIRMED` or `REJECTED`, a reason, and the
dispositions' `decision_digest`: a digest of what the human judged, namely the verdict, each
issue's disposition and canonical, the issue list, and each canonical's rendered text, with no
timestamps. Additional covering reports (`also_covered_by`) are listed in the brief but are not
part of the digest. `dispositions --confirmation` accepts only `CONFIRMED` or `REJECTED` for the
same report and applies the decision only when the digest still matches: confirmed means no
analysis, and rejected sends every technical issue to analysis. A re-listed report, an edited
canonical, or any other change to the decision voids the confirmation (`confirmation.stale`).

## Reruns

Rerun `dispositions` before each use; it makes no model calls. Write-back to an earlier advisory
moves its `updated_at` but not its rendered text, so recapture it and later dispositions stay
current. When an earlier report's text changed and the pair had a YES, rebuild that pair's packet
and rerun its legs (`rerun_pairs`). When an earlier advisory's state changes, `dispositions`
stops once its capture is refreshed: re-list the queue, recapture, and rerun `compare-plan` and
then `dispositions`; a canonical that is published or closed no longer covers.
A change to the report itself stops dependent steps through the change-since-capture check;
rerun step 1a from the listing.

## Formats

- `issues.json`: `record_type` `ghsa_issue_list`, `ghsa_id`, `status` (`COMPLETE` or
  `PENDING_NATIVE_KINDS`), `issues` (`issue_id`, `source`, `mechanism`, `trigger`, `quote`,
  `literals`, `kinds` with `native` and `cross`, `technical`), `cross_leg`, `native_kinds_leg`,
  `dropped_literals`, `needs_native_kinds`, `inputs` (check digests).
- `dispositions.json`: `record_type` `ghsa_dispositions`, `ghsa_id`, `verdict`, `cross_leg`,
  `analysis_status`, `analysis_issue_ids`, `issues` (`issue_id`, `mechanism`, `technical`,
  `kinds`, `disposition`, `canonical`, `also_covered_by`, `unresolved`, `published_matches`,
  `closed_matches`, `information`), `ignored`, `fix_guidance`, `rerun_pairs`, `decision_digest`,
  `confirmation`, `depends_on`.
- `confirmation.json`: `record_type` `ghsa_confirmation`, `ghsa_id`, `decision_digest`,
  `decision`, `reason`, `recorded_at_utc`.

## Confidentiality

- Comparison packets contain the full text of both reports and go to both providers; preflight
  consent covers this. They stay in the later report's run directory inside the restricted run
  root.
- `dispositions.json` carries the later report's own mechanisms and other advisories' IDs, never
  another report's text. Providers' reasons stay in the check files and reach only the human
  brief.
- H4 drafts never name another advisory. For a duplicate, use "previously reported" wording;
  disclosing that another report exists is the human's decision.
