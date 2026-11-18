---
name: develop-fixes-mode
description: Author a minimal candidate fix from a frozen contract, then require cold independent verification and human merge.
---

# Develop-Fixes Mode (`--develop-fix`)

This Rust-first mode authors a minimal candidate patch for one confirmed finding. It does not close the finding, merge a patch, or publish disclosure details. The author and verifier are separate. Polyglot fix authoring remains out of scope for this revision.

## Entry gate

Require `--develop-fix`, a stable `--finding <id>`, a pinned target revision, an `--analysis <path|report>` carrying the converged Role 3 Invariant + Adversarial Test Contract (or `--tracker <URL|path>` for fresh-session retrieval), and a disclosure-safe landing context. `--multi-file` is an explicit opt-in requiring stronger review.

Before editing, confirm with the user the concrete finding and contract, that this Rust-first mode will author frozen tests plus a minimal candidate fix on a branch, and the intended private/disclosed landing posture. Natural-language requests such as “develop the fix” count as invocation only when the target is unambiguous. A bare “fix security” remains analysis, not authorization to edit.

Refuse to author when the finding/contract is `DISPUTED`, `NOT VERIFIED`, or `INCOMPLETE`, when the scope is ambiguous, or when the target is not Rust.

One finding and shared root-cause variant family use one branch and one contract. A distinct finding requires its own branch and verification gate.

## Authoring flow

Dispatch a separate fix author at High effort on the host's analysis-tier model (see `SKILL.md` and the runtime guide), with a packet built by `scripts/analysis-packets.py author --mode develop-fix` from the frozen contract (`--fix-guidance <dispositions.json> --issues <issues.json>` adds each fix-guidance issue's mechanism and quote as reporter-supplied, non-binding data; that packet holds report text, so it must lie in the advisory's run directory). The frozen contract is a JSON record with `record_type` `sva_frozen_contract`, `candidate_id`, `proposition`, `contract_version`, `base_revision`, and `contract` (the role's `invariant_test_contract`, applicable, verbatim); check the author's result with `analysis-packets.py role-check --kind author` and the output schema `schemas/fix-author-tests.schema.json`. The independent fix verifiers use the same host-adaptive selection as analysis; neither verifier may be the author agent.

Every packet in this mode carries the `--develop-fix` / `--verify-fix` authorization statement from [orchestrator-contract.md](orchestrator-contract.md), after the repository authorization check passes. The execution prohibition there applies in full: never execute, compile, adapt, or register reporter-supplied proof-of-concept code, payloads, or exploit scripts, and never produce a working exploit. The author writes its own small adversarial-input regression tests from the frozen contract; a reporter's proof of concept is never copied into a test or registered as one.

1. Freeze the contract and all test definitions before editing production code; when the finding arrived through GHSA mode, each test passes `scripts/intake-check.py poc-overlap` before registration ([deterministic-validation.md](deterministic-validation.md)), and the fix author's packet carries the report's fix-guidance issues (`fix_guidance` in `step1a/dispositions.json`) as reporter-supplied, non-binding data; tests are still written from the frozen contract. Record the contract version, source artifact and hash of the full contract, base revision, test IDs/hashes, and author provenance. Bind the handoff to both version and artifact hash; a matching version alone does not establish identical content. The orchestrator may validate the hash but does not adjudicate contract compatibility.
2. Author one regression test for each declared adversarial input class plus declared benign/negative controls. Test the untouched base revision first: adversarial-input regression tests must fail as expected; benign controls must retain their expected behavior.
3. Prove the test reaches the cited sink/observable using the frozen deterministic method and oracle. Record `TEST_OBSERVED`, `TEST_WRITTEN_NOT_RUN`, or `TEST_UNVALIDATED` accurately; written tests alone are not validation.
4. Make the smallest root-cause patch on an isolated branch. Do not expand scope, alter frozen tests, or substitute a compensating control for the declared invariant without returning the finding to human review.
5. On the patched revision, run the same frozen adversarial-input regression tests, benign controls, sink-coverage, regression, and class-coverage checks. Use a deeper deterministic check matched to the claim where predeclared. Run a mutation check at the fix site (Rust default: `necessist` when compatible); a surviving mutant is a failed test-quality gate. On macOS in GHSA mode, the security gate's evidence for steps 2, 3, and 5 (every adversarial-input test fails at the base and passes on the patch, with the sink reached and the benign controls holding at both) comes from one bound result: `scripts/currency-check.py fix-revision --kind develop-fix --repo-dir <landing repository> --intake <run intake> --issues <issues.json> --analysis-records <records> --landing-branch <branch> --patched <commit> --out <file>` (in the run's `develop-fix/`; the patched commit must be on the landing branch and descend from the analysis revision; `--patched` must be a commit ID, 4 to 40 hexadecimal characters with no ref name or suffix, and a prefix of the commit it resolves to, so a ref spelled like a commit ID cannot redirect it; the record names `landing_branch`), then `checkout --which base|target`, `registry`, Phase 1 and Phase 2, and `test-result` with that pair exactly as in "Coverage entry", its output also in the run's `develop-fix/`. When the patched commit already contains the frozen test file, check out the target without `--test-file` (`checkout` adds new files only); the registry's `required_files` still bind the committed copy by digest. The result (`ghsa_develop_fix_test`) adds `security_gate` (`PASSED` or `NOT_PASSED`) and `security_gate_reason` (empty when passed; otherwise `TEST_UNVALIDATED`, `TEST_UNRESOLVED_AT_TARGET`, `TEST_NOT_AT_SINK_AT_TARGET`, or `TEST_FAILS_AT_TARGET`). The regression, class-coverage, deeper, and mutation gates stay as described, run under the same profile.
6. Patch iteration is bounded to at most three attempts with the same frozen contract and tests. Carry every prior patch and gate result forward. After the third failed attempt, stop and return a candidate-patch failure packet for human review. This authoring budget is separate from the one-retry limit for malformed mandatory role output.
7. Hand the patch to `--verify-fix` as a cold artifact, including original test results and any supplemental checks from [deterministic-validation.md](deterministic-validation.md), clearly distinguished in the existing finding record. The verifier receives no author reasoning trace. Preserve prior results and explicit corrections rather than changing frozen tests to make a patch pass.

The deterministic check contract and test evidence states are defined in [deterministic-validation.md](deterministic-validation.md). Independent native and cross-provider verification is mandatory under [cross-model-verification.md](cross-model-verification.md); runtime dispatch follows [runtime-claude.md](runtime-claude.md) or [runtime-codex.md](runtime-codex.md).

## Two-phase network gate

Use an isolated branch and the host's enforced sandbox. Phase 1 permits only dependency/toolchain preparation such as `cargo fetch`, build prerequisites, and approved nightly components. Record fetched versions and hashes. Phase 2 disables network access and runs frozen adversarial-input regression tests and benign controls, sink and class coverage, full regression tests, deeper checks, and mutation testing with Cargo offline. Cargo's `--offline` is a package-manager control, not the sandbox boundary; verify the host's network denial is effective. Run every Phase 2 process with umask 022, the conventional default a repository's own tests assume (the author packet states it, so a frozen test may rely on it). The package cannot check the umask: the Phase 2 runner is operator-built, and `deterministic-check.py` passes on the umask it inherits. A runner that keeps its own files private (umask 077) must set 022 for its children. Do not expose user credential directories or permit unsandboxed commands.

## Test-only entry (currency check)

**Status: usable on macOS.** `currency-check.py outcome` accepts results written by
`currency-check.py test-result`. One frozen test runs at two revisions as a pair of registry
entries, a build entry separates a build failure from a test failure, and coverage is bound to
each checkout. The sandbox profile's limits are listed under "Sandbox profile" below.

The GHSA currency check ([ghsa-currency-check.md](ghsa-currency-check.md)) may ask whether an
issue that analysis at the current pin did not confirm was fixed since the report. This entry
answers with a frozen test at two revisions and authors no fix.

**Entry gate.** `--develop-fix --test-only` for one planned issue (listed in the run's currency
`plan.json`), with the report revision's analysis carrying a converged Invariant + Adversarial
Test Contract for a `CROSS-MODEL VERIFIED` candidate answering that issue. Before acting, confirm
with the user the issue, the contract, the two revisions (`report_revision` and `pin` from the
run's currency `revision.json`), and the cost: one build per revision, both cold when the two
revisions pin different Rust toolchains. Refuse when the contract is `DISPUTED`, `NOT VERIFIED`,
or `INCOMPLETE`, or when the target is not Rust. The execution prohibition in
[orchestrator-contract.md](orchestrator-contract.md) applies in full: tests are written from the
frozen contract, pass `scripts/intake-check.py poc-overlap`, and never copy or adapt a reporter's
proof of concept.

**Steps.**

1. **Sandbox.** Choose an empty sandbox directory outside the home directory, the temporary
   directory, the run root, and the clone, and write the Phase 2 profile with
   `scripts/currency-check.py sandbox-profile --sandbox-dir <dir> --run-root <run root> --repo-dir
   <clone> --out <file>`, with `--out` outside the sandbox and the `TMPDIR` directory or the per-user folder (code in
   Phase 2 can write the sandbox, and other processes on the host write the temporary areas, so either could rewrite a
   profile kept there). It creates the sandbox's own
   Cargo home, home directory, and temporary directory and reports the environment Phase 2 must
   set (`HOME`, `RUSTUP_HOME`, `CARGO_HOME`, `TMPDIR`).
2. **Checkouts.** `currency-check.py checkout --repo-dir <clone> --revision <revision.json>
   --which report` and `--which pin` make a detached checkout of each endpoint inside the
   sandbox (`git clone --local --no-hardlinks --dissociate`, hooks disabled, so the checkout
   borrows no objects from the clone), so `deterministic-check.py` can confirm each checkout's
   HEAD. The clone itself is only read. Tests are new integration-test files: pass each as
   `--test-file <relative path>=<frozen file>` to both `checkout` commands, which copy it
   byte-identical and report its digest (for `required_files`). The path must be a `.rs` file
   directly in a crate's `tests/` directory that does not exist at that revision, and a
   directory leading out of the checkout is refused. A sink reachable only through private
   functions cannot be tested this way, and the issue keeps its analysis outcome. Run no other git
   command in the checkouts after Phase 2 begins (code under test can write their `.git`, and an
   index-touching command such as `git status` would start a program named there), and delete the
   sandbox when the result is written.
3. **Freeze.** Freeze the contract and tests as in "Authoring flow" steps 1-3, with the base
   revision set to `report_revision`, the author's packet built by `analysis-packets.py author --mode test-only`
   (its tests assert only the invariant's observable effect, never a return value, error kind, or
   message the invariant does not name, because the pin may hold someone else's fix that chose
   another API behavior), and run `intake-check.py poc-overlap` on every test file.
   Register, in one frozen-test registry, entries that each start with `sandbox-exec -f
   <profile>` (the system `sandbox-exec`, with the profile's real path: absolute, with no link or `..`
   in it, since `test-result` resolves `--profile` and compares) followed directly by `cargo`, and expect exit 0 (`deterministic-check.py` runs outside the profile, and
   `test-result` refuses any other entry), with requests naming the verified candidate the tests
   were written for:
   - each test as a pair, `<name>@report` and `<name>@pin`, identical in every field except
     `revision`. Each runs exactly one test (`... -- --exact <test name>`) and lists its own files
     in `required_files` (relative path to SHA-256), which `deterministic-check.py` checks before
     launch. Declare which are adversarial-input tests and which are benign controls (at least
     one of each);
   - a build pair, `<build>@report` and `<build>@pin`: `cargo test --no-run -p <crate> --offline
     --locked` under the profile, expected exit 0. A test that does not compile exits like a
     failing test (101), so only the build entry tells them apart;
   - coverage entries `<coverage>@report`, running exactly the adversarial-input tests (`cargo
     llvm-cov test ... --ignore-run-fail --json --output-path <checkout-relative file> --
     --exact <adversarial test names>`), and `<coverage>@pin`, running every declared test (no
     filter, or every name). At the pin a fix may stop the adversarial input before the sink, so
     the controls show that the sink still exists and runs. With `--ignore-run-fail` the command
     exits 0 even when a test fails, so a coverage entry's `PASSED` means only that coverage was
     collected. Coverage entries run in the checkout root (`working_directory` `.`), where their
     `--output-path` file is read, write a fresh report (`--json`, never `--no-report` or
     `--no-run`), and use the same build options as the tests (test targets, packages, manifest,
     features, profile); only `--ignore-run-fail`, `--json`, and `--output-path` differ. The build
     entry uses the tests' options apart from `--no-run` and the test target, and every entry runs
     with the same environment. Each entry has at most one `--`, and only options before it (a test name goes after
     it). After `--`, use only `--exact`, test names, `--nocapture`, `--show-output`,
     `--include-ignored`, and `--test-threads=<n>`; anything else, such as `--skip`, is refused.

   Every entry's `routing_table` maps each literal result to `DISPUTED`: a currency test changes
   no record's final status (`test-result` reads the literals itself), so the table only has to be
   well formed. The registry is mechanical and depends on nothing Phase 1 produces, so freeze it
   (and record its digest) before Phase 1 starts. Write it with `scripts/currency-check.py registry
   --spec <spec> --out-dir <new directory>` (directly beside the revision record, in the run; refused
   anywhere else, a sandbox included), which writes exactly these entries (the coverage entries
   also list the test file in `required_files`, since they run it) and one `deterministic-check.py`
   request per entry, once, from a JSON spec naming the revision record (`revision`), the
   profile's real path (`profile`), the Phase 2 environment (`environment`, names to strings), the crate
   (`crate`, a Cargo package name, which may contain `-`; the other names are plain identifiers), the test file and its digest (`test_file`, `test_file_sha256`), the test target
   (`test_target`), the adversarial-input tests and benign controls (`adversarial`, `benign`, lists of
   test names), the candidate and proposition (`candidate_id`, `proposition`), the build and coverage
   entry names (`build_name`, `coverage_name`), the coverage output path (`coverage_output`), and
   optionally the timeout (`timeout_seconds`, at most and by default 600 seconds) and the tool version
   (`tool_version`); it refuses a spec that breaks any rule above.
4. **Phase 1 (network on), per checkout.** Let `rustup` provide the revision's toolchain, with
   the `llvm-tools` component `cargo-llvm-cov` needs for that toolchain, and run
   `cargo fetch --locked` with `CARGO_HOME` set to the sandbox's Cargo home, so every dependency is
   downloaded fresh into the sandbox. A fetch failure that names a missing or older package version
   may be a package firewall or a registry problem, not the code: check the firewall's events
   first. If the endpoint still cannot be prepared, its tests are `UNRESOLVED`.
5. **Phase 2 (network off), per checkout.** Under `sandbox-exec -f <profile>` with the reported
   environment and umask 022 (see "Two-phase network gate"), building only the crate under test (`cargo ... -p <crate> --offline --locked`):
   first pre-build with no time limit (`cargo test --no-run`, and one run of the coverage command
   with `--no-report` in place of its report options, since `cargo llvm-cov` has no compile-only
   mode; the pre-build then leaves no report file the coverage entry could be mistaken for), started with no controlling terminal and standard input from
   the null device (the profile allows writes to the terminal device, so build scripts must not
   get an interactive terminal); then run every registry entry for that revision (tests,
   build, coverage) through `scripts/deterministic-check.py`. The two revisions may pin different
   Rust toolchains; then both builds are cold. `deterministic-check.py` caps an entry at 600
   seconds and runs outside the profile, so each frozen argument vector itself starts with
   `sandbox-exec`; the pre-build keeps the cold build out of that limit.
6. **Result.** `currency-check.py test-result` builds the result for the currency check from those
   outputs alone (see [ghsa-currency-check.md](ghsa-currency-check.md) step 5); never write it by
   hand. A pass at the pin counts as evidence only when the sink is reached there and the benign
   controls still pass there. For each adversarial-input test that fails, the result records the
   first failure message from its output, so the human can see which assertion failed (for
   example a containment check, or an expected error that a correct fix may legitimately not
   return).

**Trust limit.** Code under test (the target's own build scripts, its dependencies' build scripts
and procedural macros, and the tests) runs in the sandbox and can write both checkouts: their
coverage files, their `.git`, and anything else there. `deterministic-check.py` and
`test-result` run outside the sandbox and read those files, so their bindings (HEAD, digests,
file names, one test run) catch a wrong input or an operator mix-up, not code that forges results
on purpose. Use a new sandbox directory for every run and delete it afterwards
(`sandbox-profile` refuses a sandbox whose `tmp`, `home`, or `cargo-home` is a link).

No fix is authored, no branch is created or landed, and nothing goes to `--verify-fix`. A human
reviews the frozen tests with the currency brief: a test that passes at the pin is evidence that
the behavior changed, and only the human decides that the issue was fixed.

**Sandbox profile (macOS Seatbelt, v1).** Every compiled dependency's build scripts and
procedural macros run inside this profile, so it is the boundary for third-party code. It allows
everything except:

- all network access, LaunchServices (`lsopen`), and Apple events (handing work to an
  unsandboxed process);
- reads of the whole home directory, except the home directory entry itself, the rustup home, and
  the rustup proxies directory; and reads of credential paths (`.ssh`, `.aws`, `.gnupg`,
  `.netrc`, `.git-credentials`, `.docker`, Cargo's credentials, the GitHub CLI and 1Password CLI
  configuration, the keychains), the run root, and the clone, each also at its real path when it
  is a symbolic link;
- reads of the shared areas outside the home directory (the system temporary areas `/tmp` and
  `tmp` under `var`, and the `Shared` folder beside the users' home directories, each at its real
  path) and of the user's temporary areas (the directory `TMPDIR` names, and the whole per-user folder macOS
  assigns, which holds its per-user temporary and cache directories and their siblings and which `TMPDIR`
  does not move: a shell may point `TMPDIR` elsewhere while tools such as `xcrun` keep using the per-user
  one), except the sandbox itself; the directories leading from such an area to the sandbox
  allow metadata only, so paths inside the sandbox resolve while nothing else there can be listed
  or read. The credential, run-root, and clone denial is the last read rule, so no allow reopens it;
- writes anywhere other than the sandbox directory and the null, terminal, and descriptor
  devices. The Cargo and rustup homes in the home directory and the user's temporary directory are
  not writable; Phase 2's `TMPDIR` is a directory inside the sandbox.

Paths are resolved, because Seatbelt matches real paths. The command refuses a sandbox directory
inside, or containing, the home directory, the `TMPDIR` directory or the per-user folder, the run root, or the clone; a
sandbox directory that is, or contains, one of the shared areas (its read allow would reopen
it); an `--out` inside the sandbox or the `TMPDIR` directory or the per-user folder; a `RUSTUP_HOME` that is, or
contains, the home directory (the profile makes the rustup home readable); and a `RUSTUP_HOME` or
rustup proxies directory inside any of these areas (the profile denies reads there). An existing directory chosen for
`--out` keeps its mode; a new one is created private. Verified on macOS on
2026-11-16 with a real Rust workspace checkout (the earlier profile, which still allowed writes to the
user's temporary directory): network access, a credential file, an ordinary home file, the run
root, and a write to the home directory were denied; a write in the sandbox directory and reads
of the toolchain were allowed; and with the reported environment, an offline `cargo test
--no-run` of one crate completed from a Cargo home filled by a fresh Phase 1 fetch. Without the
sandbox's own `HOME`, the same build failed: Cargo's git library could not read the real home's
configuration and reported a git dependency as needing an update. Verified again on 2026-11-16
with this profile and a small zero-dependency crate: denied were a hard link from the sandbox to
a home file, reads of a home file directly and through the Data volume's alias of the home directory, reads of `.ssh`
files and a shell startup file, `launchctl submit` (no job ran), a file-based keychain item (not
found from inside), network access, and writes to the home directory and the user's temporary
directory; allowed were writes to the sandbox's `TMPDIR`, the build, its tests, and
`cargo-llvm-cov`. The linker's `xcrun` could not write its cache in the user's temporary
directory (it does not use `TMPDIR`) and printed a note; the build still succeeded. A rustup
proxy started from a working directory in the home directory cannot find its working directory,
so Phase 2 commands run from inside the sandbox checkout. Verified a third time on 2026-11-16 with one crate of a real Rust workspace at two revisions that pin different toolchains (1.92 and 1.98.1): `checkout` of both, Phase 1 (toolchain with `llvm-tools`, a fresh `cargo fetch --locked` into the sandbox's Cargo home, about 4 GB and 1-3 minutes), and under this profile the pre-build (about 20 s per revision, 173-175 crates), the build entries through `deterministic-check.py` (`PASSED`), and one `cargo llvm-cov` instrumented build per revision (about 0.7 GB more per target directory) all completed, with network denied; `xcrun` cache errors appeared as compiler and linker warnings and did not stop the build. Not tested live: `lsopen` and
`appleevent-send`, data-protection keychain items (reached through a system service rather than
a file), and other system services. Verified on 2026-11-17 with the temporary-area read denials:
from inside, reads of a file in the system temporary area outside the sandbox (also through the
`/tmp` alias) and of a file in the user's temporary directory, and listings of `/tmp` and of a
directory there, were denied, while a `stat` of `/tmp` and reads, listings, and writes in the sandbox
were allowed (the earlier profile allowed all five denied reads); a cold offline `cargo test
--no-run` of one crate of a real Rust workspace and a `cargo llvm-cov` run of its tests completed.
The build was slower (about 2 minutes against about 25 seconds with the earlier profile): `xcrun`
can no longer read its SDK cache in the user's temporary directory, and one `xcrun --show-sdk-path`
took 1.9 seconds against 0.35 seconds. Verified again on 2026-11-17 (macOS 26.7) with
marker files in the system temporary area (directly in it and in a directory there), directly in
the home directory, and in the per-user temporary directory: from inside, a hard link or an APFS
clone (`cp -c`) of each into the sandbox was refused, as were reads through the data volume's
alias for each path, while writes and reads in the sandbox were allowed; outside the profile the
same markers were readable. Verified on 2026-11-17 with the whole per-user folder denied: markers in its cache
directory, its `0` directory, and its temporary directory could be neither read nor listed from inside, while the
sandbox stayed writable and readable; a fresh `cargo fetch --locked` (about 3 minutes) and a cold offline `cargo test
--no-run` of one crate of a real Rust workspace (about 75 seconds) completed under the profile, with only the
known `xcrun` cache notes. A microVM is the v2 hardening.

Other hosts (Linux, Codex's own sandbox) are not verified for this entry; on them, run the
test-only entry only after an equivalent denial check.

## Coverage entry (post-fix coverage, Track 2)

**Status: usable on macOS** (ADR-016 decision 4, Track 2 option C). Step 1a may find a later
report's issue covered by an open canonical. Once the canonical's fix has merged, this entry asks
whether that fix also closes the later report's issue: a frozen test that fails at the fix's first
parent and passes at the fix proposes `COVERED_BY_FIX`. The window is narrow: a canonical that is
published or closed no longer covers ([ghsa-deduplication.md](ghsa-deduplication.md)), so the entry
applies while the canonical is still in triage or draft and its fix is already on the default
branch. A research variant runs the same check on a published, known-fixed advisory (a known
positive), with no canonical. The entry authors no fix.

**Entry gate.** `--develop-fix --coverage --canonical <GHSA ID> --fix-commit <revision>` for a later
report whose current dispositions (rerun before use) name the canonical for at least one issue
(`COVERED` by it, first or also, or `UNRESOLVED` with a comparison against it), with the canonical's
current capture in triage or draft; or `--develop-fix --coverage --research --fix-commit
<revision>` for a published advisory. Confirm with the user the issues, the fix commit, and the
cost (one analysis at the base unless an earlier one is reused; one build per revision). The
execution prohibition in [orchestrator-contract.md](orchestrator-contract.md) applies in full, and
everything under "Test-only entry" about the sandbox, Phase 1, Phase 2, the umask, and the trust
limit applies unchanged.

**Steps.**

1. **Pair.** `scripts/currency-check.py fix-revision --repo-dir <clone> --intake <run intake (the run's own intake record, by digest)>
   --issues <issues.json> --fix-commit <F> --default-branch <branch> --dispositions
   <dispositions.json> --canonical <GHSA ID> --canonical-intake <its capture> --out
   <file>` (`revision.json` in the run's `coverage/`; or `--research` in place of the three triage arguments). It checks
   that the clone's origin is the capture's repository and holds the capture's pin, that F is on the
   first-parent line of `origin/<branch>` and an ancestor of the pin, and takes F's first parent as
   the base (F must be a commit ID, 4 to 40 hexadecimal characters with no ref name or suffix, and a
   prefix of the commit it resolves to, so a ref spelled like a commit ID cannot redirect it; `--canonical`
   must be a GHSA ID). It refuses dispositions from another issue list, awaiting a rerun or a confirmation, a
   canonical that is not open ("a published or closed match"), and a report none of whose issues
   names the canonical. The record (`ghsa_revision_pair`, `kind` `coverage`) carries `base`,
   `target`, `pin`, `canonical`, `research_only`, `issues`, `analysis_revision`, and the digests of
   its inputs. Outputs of this entry live directly in the run's `coverage/` directory (mode 700 and 600).
2. **Analysis at the base.** For the pair's issues, run the analysis flow at `base`: a snapshot and
   source registry at `base`, the fix-blind rendering, `scripts/intake-check.py issue-scope
   --coverage-plan <pair> --intake <run intake>` (the capture the pair bound) with `--dispositions <dispositions.json>` on the triage path or
   `--research` on the research path (exactly the pair's issues, covered ones included,
   with quotes and literals from text the fix-blind rendering leaves out withheld; a confirmed obvious
   duplicate is accepted), `analysis-packets.py phase1 --fix-blind`, discovery, verification, and
   `scripts/ghsa-dedup.py records --coverage-plan <pair> --primary-revision <base>` (with the same
   `--dispositions` or `--research`) into
   `base-records/` in the run's `coverage/`. Coverage records carry `coverage: true` and are never write-back
   eligible; write-back, `h4-packet`, the currency `plan`, `outcome`, and `test-result` refuse them. An earlier analysis may
   supply the contract instead, only when it ran at the base or an ancestor of it: pass its records
   to `fix-revision --analysis-records`, which checks that and binds them by digest
   (`analysis_revision`).
3. **Tests.** Freeze the contract of a `CROSS-MODEL VERIFIED`, bridged candidate answering the
   issue (as in "Authoring flow"), author the tests with `analysis-packets.py author --mode
   coverage` (invariant only), and run `intake-check.py poc-overlap` on every test file against the
   later report's intake and, on the triage path, the canonical's capture too (the captures the
   pair bound, `intake_sha256` and `canonical_intake_sha256`; `test-result` refuses a check run
   against any other capture). Make the checkouts
   with `currency-check.py checkout --revision <pair> --which base` and `--which target`, write the
   registry with `currency-check.py registry` from a spec naming the pair (entries `<name>@base` and
   `<name>@target`), and run Phase 1 and Phase 2 as in "Test-only entry" steps 4 and 5.
4. **Result.** `currency-check.py test-result --revision <pair>` with the same arguments as the
   test-only entry except `--plan` (refused: the pair names its issues); `--target-result`,
   `--target-checkout`, and `--target-sink` spell the `--pin-*` options. The records must be the
   ones made at the pair's `analysis_revision` (coverage records at the base, or the reused records
   bound by digest). The result (`ghsa_coverage_test`) carries `base_validation`,
   `target_validation`, and `at_target`.
5. **Outcome and brief.** `currency-check.py coverage-outcome --revision <pair> --records <records>
   --test <result> ... --out <file>` (`outcome.json` in the run's `coverage/`), then `coverage-brief
   --outcome <outcome.json> --out <file>` (for example `brief.txt` there), a human-only brief: per issue
   the proposal and reason, the base, target, and pin (and the analysis revision when it differs from the
   base), the test at both revisions with its build, sinks and counts, candidate and proposition, and
   failure messages at the target as one-line JSON; the canonical only by its ID; values that are not well
   formed are shown as one-line JSON or `unknown`.
   `coverage-outcome` refuses a test result that is not this pair's `test-result` output or is
   malformed (an unknown `at_target` or base state, a missing validation block, a non-boolean check,
   no registry, profile, or candidate), so a malformed result never reads as rule C6. Rules, first
   match, every outcome a proposal:

   | Rule | Condition | Outcome | Reason |
   |---|---|---|---|
   | C1 | No bridged `CROSS-MODEL VERIFIED` record answering the issue in the records | `UNDECIDED` | `NO_CONTRACT_AT_BASE` |
   | C2 | No test result, or a test not validated at the base (it passed, a control failed, or the sink was not reached) | `UNDECIDED` | `TEST_UNVALIDATED` |
   | C3 | A validated test could not run at the target | `UNDECIDED` | `TEST_UNRESOLVED_AT_TARGET` |
   | C4 | A validated test ran at the target, but the sink was not reached there or a control failed | `UNDECIDED` | `TEST_NOT_AT_SINK_AT_TARGET` |
   | C5 | A validated test passes at the target | `COVERED_BY_FIX` (needs `--verify-fix`) | — |
   | C6 | A validated test fails at the target | `NOT_COVERED_BY_FIX` | — |

   The brief shows the proposal, both revisions, the analysis revision when it is not the base, the
   sinks and counts, the failure messages at the target as one-line JSON, and names the canonical
   only by its ID.
6. **Confirmation.** A `COVERED_BY_FIX` proposal stays a proposal until `--verify-fix` (cold, two
   providers, disproof-biased) confirms that F closes the later report's frozen contract; the brief
   records no `--verify-fix` result. For `NOT_COVERED_BY_FIX`, step 1a's coverage is overturned for
   that issue: check first whether the test asserts more than the invariant, then the issue needs
   its own analysis at the pin or its own fix. Dispositions, H4, and write-back are unchanged; the
   human records each decision in the run notes.

## Candidate-patch provenance

Render, without inventing missing values:

```text
Finding ID, contract version, full contract source artifact/hash, base/patched revisions, branch:
Author role/provider/exact model/effort and attempt status:
Frozen test IDs/hashes and source revision:
Per input class: base expected/actual; patched expected/actual; pass/fail; test evidence state:
Sink/class coverage method, oracle, tool version, and literal output:
Security, regression, and deeper-check evidence:
Independent verifier role/stage provenance and final status:
Disclosure-safe landing posture:
Status: CANDIDATE PATCH — --verify-fix and human merge required
```

## Landing boundary

Keep undisclosed vulnerability details and evidence in the approved restricted channel. For a public repository, do not push, open, or describe a vulnerable-fix branch publicly before the human selects the disclosure route. A human reviews and merges every candidate patch.

Determine repository visibility before landing. A private repository or already-disclosed issue may use a draft PR after explicit approval. For an undisclosed vulnerability in a public repository, keep a local branch and restricted evidence bundle, then reuse the existing GitHub Security Advisory and its temporary private fork when one exists; create a new advisory only under explicit human direction. Never put the vulnerability description, PoC, contract, or revealing branch/commit text on a public surface. Pause for advisory acceptance, private-fork merge, publication, and every final merge decision. In GHSA mode, accept-to-draft and private-fork creation may run through `scripts/ghsa-writeback.py` only after the user approves each item ([ghsa-triage-mode.md](ghsa-triage-mode.md)); private-fork merge, publication, and final merge stay human-only. When the run arrived via `--ghsa`, use that GHSA ID to reuse its private fork.
