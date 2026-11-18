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
runtime guides under "Step 1a legs". The currency check against the default-branch commit at the
advisory's creation time runs after analysis ([ghsa-currency-check.md](ghsa-currency-check.md)).
For a published advisory, only step 1a's issue listing runs (the issue list, the cold review, any native
classification, and `issues`, which accept a published capture); comparison planning and dispositions do not, so
a published advisory has no dispositions. It reaches analysis and the currency check only through the
research-only path in [ghsa-triage-mode.md](ghsa-triage-mode.md), whose results are never triage decisions.
After the canonical's fix has merged, and while the canonical is still open, the post-fix coverage
check (Track 2, [develop-fixes-mode.md](develop-fixes-mode.md) "Coverage entry") may test whether
that fix also closes a later report's covered issue: a frozen test that fails at the fix's first
parent and passes at the fix proposes `COVERED_BY_FIX`, which `--verify-fix` must confirm; a test that
still fails overturns the coverage for that issue. Its results are proposals for the human and never
change dispositions, H4, or write-back.

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

| Step | Who | Command | Output (in `<run>/step1a/`; file names conventional) |
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
these bindings and refuse input that breaks one: every role result must echo its packet's
`packet_revision` (the step name and the packet's random token), so a result from an earlier or
other packet fails its check; `issue-check` and `review-check` require the
packet to have been built from the same capture; `issues` requires the review and the native
classification to belong to that native listing (and review); `dispositions` requires each
comparison packet to match the planned pair and the current issue list, each leg check to answer
that packet, and each earlier advisory's current capture to have the state the plan recorded.
Every step 1a output must lie in `<run>/step1a/` of a run directory whose
`intake/intake-record.json` captures the same advisory, and a comparison packet must be in
`step1a/compare/<earlier GHSA ID>/` for its own earlier report (`dispositions --compare-dir` must
be the `compare/` directory in the same `step1a/` as its `--out`); the commands refuse any other
location, because queue selection looks only for `dispositions.json` in each run's `step1a/`.
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
nothing is ignored, and no obvious duplicate can be proposed. A native listing from a fallback
model without the user's permission keeps its reported kinds, but its kinds never count toward
ignoring an issue (`native_leg` records `FALLBACK_NOT_PERMITTED`). Packet builders and `issues`
refuse checks that belong to another advisory. Ignored issues stay in the decision
brief, and fix-guidance issues go to the fix author.

## Comparison set

`compare-plan` reads the queue listing and the captures. The listing must cover every state
(`ghsa-fetch.py queue --state all`), since a filtered listing would omit comparison candidates.
The later report must be in the listing
in triage or draft state, and each earlier capture's description digest and `updated_at` must
match its listing entry (otherwise the command asks for a recapture). Every listed advisory
appears in the plan, either under `planned` or under `excluded` with its reason, including the
report itself.

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
decides. A current `CONFIRMED` decision makes it `NO_ANALYSIS` (nothing is analyzed and
`records` does not run; H4 may still draft a "previously reported" comment). Otherwise, including
after a current `REJECTED` decision, it is `READY`. Covered issues of a partial report skip
analysis without a separate confirmation; the write-back brief lists them.

## Confirmation

Queue mode continues past obvious-duplicate proposals and presents them in one decision brief at
the end of step 1a, rendered by `ghsa-dedup.py brief --dispositions <dispositions.json> --out
<file>` (repeat `--dispositions` for each report; add `--captures <map>` to show each closed
match's last captured comment). It opens with a "Decision needed" line naming the reports
awaiting a decision (or "none"). For each report the brief shows a context line (the run
directory, the target repository and pinned revision from the run's
`intake/intake-record.json`, and the mode; `brief` refuses a dispositions file outside a run
with that capture), the verdict, analysis status, `cross_leg`, and decision digest; for each
technical issue, its canonical and `also_covered_by`; both providers' answers and reasons for
the canonical pair, for each unresolved entry, and for each published or closed match; a link to
each closed-match advisory; `information` entries; ignored issues with their kinds and
mechanisms; fix guidance; for each proposal awaiting confirmation, the options with their
consequences (`CONFIRMED`: nothing is analyzed, and an H4 draft may still say an issue was
previously reported; `REJECTED`: every technical issue goes to analysis, and no issue is treated
as previously reported) and a decision line, with a warning that until the decision is recorded
and `dispositions` is rerun, the report is not analyzed and gets no H4 draft or write-back; or the
decision already applied. When a recorded decision no longer applies (`confirmation.stale`), the
brief says so for any analysis status, naming the decision, when it was recorded, and the
report's status now; a report the change moved to `READY` goes to analysis without a new
decision. A leg that `dispositions` did not count is labeled ("not counted: fallback not
permitted" or "same provider as native"). It reads the checks in `compare/` beside each
dispositions file and refuses when any pair's checks differ from what `dispositions` read,
whether or not the brief prints that pair, so rerun `dispositions` first. With `--captures` it
refuses a capture for another advisory, and marks a closed match's comment "(capture changed
since the comparison)" when the capture no longer matches the text the providers compared. The
brief names other advisories and is for the human only: keep it in the restricted run root and
never send it to a model. `confirm` records `CONFIRMED` or `REJECTED`, a reason, and the
dispositions' `decision_digest`: a digest of what the human judged, namely the verdict, each
issue's disposition and canonical, the issue list, and each canonical's rendered text, with no
timestamps. Additional covering reports (`also_covered_by`) are listed in the brief but are not
part of the digest. `dispositions --confirmation` accepts only `CONFIRMED` or `REJECTED` for the
same report and applies the decision only when the digest still matches: confirmed means no
analysis (`NO_ANALYSIS`), and rejected sends every technical issue to analysis (`READY`). A
re-listed report, an edited canonical, or any other change to the decision voids the
confirmation (`confirmation.stale`).

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
  `literals`, `kinds` with `native` and `cross`, `technical`), `native_leg`, `cross_leg`, `native_kinds_leg`,
  `dropped_literals`, `needs_native_kinds`, `inputs` (check digests).
- `dispositions.json`: `record_type` `ghsa_dispositions`, `ghsa_id`, `verdict`, `cross_leg`,
  `analysis_status`, `analysis_issue_ids`, `issues` (`issue_id`, `mechanism`, `technical`,
  `kinds`, `disposition`, `canonical`, `also_covered_by`, `unresolved`, `published_matches`,
  `closed_matches`, `information`), `ignored`, `fix_guidance`, `rerun_pairs`, `decision_digest`,
  `confirmation` (`applied`, `stale`, `decision`, `reason`, `recorded_at_utc`; a stale decision
  keeps its `decision`, `reason`, and time with `applied` false, and only an applied decision
  counts), `depends_on`.
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
