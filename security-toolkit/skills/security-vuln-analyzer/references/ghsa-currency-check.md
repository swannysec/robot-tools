---
name: ghsa-currency-check
description: GHSA mode currency check (ADR-016 decision 5) for issues that analysis at the pin does not confirm, with the report's creation-time revision, change flags, and human-decided outcome proposals.
---

# GHSA Currency Check

A report describes the code as it was when it was filed. Analysis runs on the current default
branch (the pin), so an issue the pin does not confirm may never have been a vulnerability, may
have been fixed since the report, or may sit in code that was removed. The currency check gathers
evidence at both revisions so a human can tell these apart. It never dismisses, closes, or writes
back anything by itself, and nothing in it makes a network call or weighs evidence: the
deterministic work is in `scripts/currency-check.py`, and every judgment comes from the existing
analysis roles or from a frozen test.

## When it runs

After analysis at the pin and `ghsa-dedup.py records`, for a report whose dispositions are
`READY`. Only technical issues in `analysis_issue_ids` that analysis at the pin did not confirm
get the two-revision check. Change flags run on every technical issue and appear in the brief as
information.

## Flow

1. **Report revision.** `currency-check.py revision --repo-dir <clone> --intake
   <intake-record.json> --default-branch <branch> --out <file>` finds the first-parent commit of
   `origin/<branch>` at the advisory's `created_at` in a local clone of the repository (the
   operator fetches the clone first). Reporter-quoted versions are information only and never pin
   anything. The selection uses committer dates, so a commit committed before the report but
   merged after it can be chosen; on a squash-merge history the two dates coincide. It refuses
   when `created_at` is missing or not an ISO-8601 time, when the clone path is not the clone's
   top level, when no commit precedes the creation time, when the clone lacks `origin/<branch>`,
   when the clone's `origin` names another repository than the capture, when the capture's pinned
   revision is not in the clone, and when the report revision is not an ancestor of the pin.
   Output `revision.json`: `ghsa_id`, `repository`, `created_at`, `default_branch`,
   `report_revision`, `pin`, `first_parent_commits_between`, `intake_sha256`.
2. **Scope.** `currency-check.py plan --issues <issues.json> --dispositions <dispositions.json>
   --records <report-records.json> --out <file>` lists each technical issue in
   `analysis_issue_ids` with no `CROSS-MODEL VERIFIED` record answering it. A verified record that
   is not `ghsa_eligible` (for example a split resolved by a frozen test) still counts as
   confirmed. Each planned issue carries a reason, the most significant of its records' final
   statuses in the order `DISPUTED`, `INCOMPLETE`, `NOT VERIFIED`, `REFUTED`, or `NO_RECORD` when
   no record answers it; an empty or unknown final status counts as `INCOMPLETE`. It refuses dispositions that are not `READY`, dispositions computed from
   another issue list, and records for another advisory or issue list. Output `plan.json`:
   `planned` (`issue_id`, `mechanism`, `reason`), `not_planned` (`CONFIRMED` or
   `NOT_TECHNICAL`), `primary_revision`, and the digests of its three inputs.
3. **Flags.** `currency-check.py flags --repo-dir <clone> --revision <revision.json> --issues
   <issues.json> [--records <report-records.json> ...] --out <file>` checks, for every technical
   issue, its anchors: the issue's checked `file_paths` and `symbols`, plus the `control_site` of
   each `CROSS-MODEL VERIFIED` record answering it in any `--records` file (the pin's analysis,
   and the report revision's analysis once it has run). Each `--records` file must carry the same
   issue list's digest. An anchor that is not a plain relative path or identifier (an absolute
   path, a `..` segment, a leading `-`, shell punctuation) is rejected, recorded under
   `rejected_anchors`, and never passed to `git`. Between the report revision and the pin, per
   issue:
   - `presence`: each path at both revisions, following a rename in either direction
     (`report_path`, `pin_path`), so a control site written with the pin's path still names the
     report revision's file;
   - `renames`: renames from `git diff -M` between the two endpoints (git's similarity
     detection: a file both renamed and heavily rewritten, or a rename beyond git's rename limit,
     shows as removed with no rename);
   - `symbols`: each symbol's last segment at both revisions, matched as a whole word (a segment
     shorter than three characters, or one that is not a plain identifier, is kept as an anchor
     but not checked);
   - `definitions` and `function_commits`: the files that define `fn <name>` at the report
     revision (Rust function syntax; this version is Rust-first), using only the issue's own named
     files when any defines it, otherwise the single defining file when there is exactly one, and
     none when a generic name is defined in several files (`definition_count` shows how many);
     then the commits touching that function (hash, subject, symbol, path). `git log -L` runs with
     git's built-in Rust function-header rule, so indented methods in `impl` blocks are found;
   - `function_history`: per function and file, `OK`; `UNAVAILABLE_AT_PIN` when git cannot follow
     it (for example the function is gone at the pin); or `AMBIGUOUS_IN_FILE` when the file defines
     several functions with that name (for example methods of two types), since `git log -L` would
     follow only the first. Neither is the same as unchanged;
   - `file_commit_count` and `file_history`: commits touching the named files (a count only; busy
     files change constantly, so it does not discriminate);
   - `no_anchor`: true when no path and no symbol could be checked.

   The output also carries the issue list's digest (`issues_sha256`).

   A function's range follows git's `-L :<funcname>` rule: it runs from the definition line to
   the line before the next function header, so an edit just below a function also flags it.
   Function commits are therefore pointers for a human, including unverified candidates for the
   fixing commit, never a determination. Flags never change an outcome.

4. **Analysis at the report revision.** For the planned issues only, run the existing analysis
   flow at `report_revision`: a fresh read-only snapshot and source registry at that commit, the
   Phase 1 issue listing from `intake-check.py issue-scope --issues <issues.json> --dispositions
   <dispositions.json> --currency-plan <plan.json> --intake <intake-record.json> --out <file>`
   (exactly the planned issues; it refuses a plan for another advisory, issue list, or
   dispositions file, an empty plan, a plan naming an issue outside `analysis_issue_ids`, and a
   missing or foreign intake record). An issue whose quote is not in the summary or description
   (it came from a comment or a reporter field) has its quote withheld from the listing, so a fix
   named there cannot reach the analysis; the output lists those issues as `quotes_withheld` and
   reports fix wording in the listing's own text (model-written mechanisms and triggers included)
   as `fix_terms_found`, and the advisory rendered with
   `intake-check.py render --intake <intake-record.json> --fix-blind --out <file>`. The fix-blind
   rendering keeps only the summary and description: comments, which may name a fixing change, and
   every reporter vulnerability field (package, version range, patched versions, vulnerable
   functions) are left out. Wording in the summary or description that announces a fix ("fixed
   in", "patched in", "## Patches", "patched versions", matched across line breaks) cannot be
   removed without editing report text, so `render` reports it as `fix_terms_found`, with the
   advisory's `ghsa_id`, for the brief. Role packets for this analysis carry
   no result of the analysis at the pin. Then run `ghsa-dedup.py records` for it with
   `--primary-revision <report_revision>` and an `--out-dir` of its own (for example
   `report-revision/` under the run's `currency/`), and rerun `flags` with both records files, so
   the report revision's control sites add anchors.
5. **Test at both revisions (not yet usable; phase 2b).** `outcome` refuses test results in this
   version (see [develop-fixes-mode.md](develop-fixes-mode.md) "Test-only entry" for why). The
   design, for phase 2b: for a planned issue whose
   report-revision analysis produced a converged Invariant + Adversarial Test Contract, the human
   may run the `--develop-fix` test-only entry
   ([develop-fixes-mode.md](develop-fixes-mode.md) "Test-only entry"). Its result is written by
   `currency-check.py test-result` from the adapters' own outputs, never by hand: the
   `deterministic-check.py` results of every declared test at both revisions (one frozen-test
   registry), `cargo-llvm-cov` JSON and the sink location at each revision, and an `ACCEPT`
   `poc-overlap` check for each test file. It declares which tests are adversarial-input tests
   and which are benign controls (at least one of each), and refuses results at another revision,
   a missing or extra test, results from two registries, and any `poc-overlap` that is not
   `ACCEPT` (the checks' test-file digests are recorded for the human, not yet compared with the
   frozen tests). Output (in the run's `currency/`, for example `test-<issue ID>.json`):
   `base_validation` (`state` `TEST_OBSERVED` only when every adversarial-input test failed, every
   control passed, and the sink was reached at the report revision; otherwise `TEST_UNVALIDATED`),
   `pin_validation` (controls and sink at the pin), and `at_pin` (`PASSED` when every
   adversarial-input test passes there, `FAILED` when any still fails, `UNRESOLVED` when any could
   not run), with the digests of every input.
6. **Outcome.** `currency-check.py outcome --revision <revision.json> --plan <plan.json>
   [--report-records <report-revision records>] [--test <result> ...] --out <file>` proposes one
   outcome per planned issue; the first matching rule applies:

   | Rule | Condition | Outcome | Evidence, reason |
   |---|---|---|---|
   | 1 | The report revision is the pin (nothing can have changed) | `UNDECIDED` | `ANALYSIS`, `SAME_REVISION` |
   | 2 | A validated test cannot run at the pin (a timeout, an output limit, or a test that could not start) | `UNDECIDED` | `TEST`, `TEST_UNRESOLVED_AT_PIN` |
   | 3 | A validated test ran at the pin, but the sink was not reached there or a benign control failed | `UNDECIDED` | `TEST`, `TEST_NOT_AT_SINK_AT_PIN` |
   | 4 | A validated test passes at the pin | `FIXED_SINCE_REPORT` | `TEST` |
   | 5 | A validated test fails at the pin | `STILL_PRESENT` (contradicts the pin's analysis; flagged) | `TEST` |
   | 6 | The report revision has not been analyzed | `UNDECIDED` | `ANALYSIS`, `INCOMPLETE` |
   | 7 | Either analysis is `DISPUTED` for the issue (at the report revision, any `DISPUTED` record counts, even beside a verified one) | `UNDECIDED` | `ANALYSIS`, `DISPUTED` |
   | 8 | Either analysis is `INCOMPLETE` (including an empty or unknown final status; at the report revision, any such record counts) | `UNDECIDED` | `ANALYSIS`, `INCOMPLETE` |
   | 9 | The report revision's only confirmation is a verified record that is not bridged (`ghsa_eligible` false) | `UNDECIDED` | `ANALYSIS`, `UNBRIDGED_AT_REPORT` |
   | 10 | The report revision confirms the issue with a bridged verified record and the pin did not | `FIXED_SINCE_REPORT` | `ANALYSIS` |
   | 11 | The report revision does not confirm it (`REFUTED`, `NOT VERIFIED`, or no record) | `NOT_CONFIRMED_AT_REPORT` | `ANALYSIS`, that status |

   Rules 2 to 5 take effect with phase 2b; until then `outcome` refuses every test result, so
   outcomes come from rules 1 and 6 to 11. A test is validated only when its base state is `TEST_OBSERVED`: at the report revision it
   failed, its benign controls passed, and it reached the sink. Any other test result is shown but
   is not evidence. `outcome` accepts only results written by `test-result`, bound to the plan's
   issue list and a frozen-test registry digest, with true-or-false checks.
   `NOT_CONFIRMED_AT_REPORT` means the issue was never a vulnerability as reported, or the
   analysis missed it; the human decides which. A variant that analysis confirms at the pin is
   never in the plan: the pin's analysis reports it as usual. Flags are not an input. `outcome`
   refuses a test result for an unplanned issue, another advisory, issue list, or revision, one not
   written by `test-result`, one without a registry digest or with a non-boolean check, an unknown
   state or `at_pin`, two results for one issue, a plan for another advisory or pin, and
   report-revision records for another issue list or revision.
7. **Brief.** `currency-check.py brief --outcome <outcome.json> [--flags <flags.json>]
   [--fix-terms <saved render output>] --out <file>` renders, for the human only, per planned
   issue: the outcome with its evidence and reason, both analyses' statuses, the test result at
   both revisions, a contradiction note when a test fails at the pin, the flags (anchors, presence,
   renames, each function's definition count and whether its history was looked up, rejected
   anchors, function commits labeled as unverified fixing-commit candidates, unavailable history,
   file-commit count), the fix wording the report-revision analysis saw, and the options: accept
   the proposal, or analyze again. Mechanisms, anchors, and commit subjects appear as one-line JSON
   strings. It refuses flags for another advisory, revision, or issue list (issue IDs are joined
   only when both outputs carry the same issue-list digest) and a render output for another
   advisory. Never send the brief to a model.

## Operator sequence for one report

1. `git fetch origin` in the local clone (the operator's step; the scripts never fetch).
2. `currency-check.py revision`, then `plan` with the pin's `report-records.json`.
3. `flags` with the pin's records (every technical issue gets flags, planned or not).
4. If `plan` lists issues: a snapshot and source registry at `report_revision`; `render
   --fix-blind` (save its output for the brief); `issue-scope --currency-plan`; the analysis;
   `records` for it with `--primary-revision <report_revision>`; then `flags` again with both
   records files.
5. (Phase 2b, not yet usable.) Per planned issue and with the user's confirmation, the
   `--develop-fix --test-only` entry: `currency-check.py sandbox-profile`, `checkout` for each
   endpoint, the frozen tests and coverage under the profile, then `test-result`.
6. `outcome`, then `brief`, and present the brief to the human. Record the human's decision per
   issue in the run's notes; the scripts store none and write nothing back.

## Outputs and location

Every output is written directly in the run's `currency/` directory, beside the run's `intake/`,
and the commands refuse any other location. Directories are mode 700 and files mode 600. The
outputs carry each issue's mechanism, its anchors (including rejected ones, verbatim), commit
hashes, commit subjects, and paths, so they stay in the restricted run root with the rest of the
run.

## Git use

`currency-check.py` runs `git` with fixed argument vectors against the given clone only. Global
and system configuration are ignored; the clone's own configuration is still read, so the
settings that could start a program or reach the network are overridden on the command line or
in the environment: signature verification in `git log`, file-system monitors, external diff
drivers, and text conversion are off; lazy fetches from a partial clone and every transport are
blocked (a partial clone missing an object fails instead of fetching); pathspecs are literal; and
prompts and optional locks are off. Report text reaches `git` only as validated paths and
identifiers, never as an option. It reads history; it never checks out, fetches, or writes to the
clone. `git log -L` reads a one-line attributes file from a temporary directory outside the clone.
