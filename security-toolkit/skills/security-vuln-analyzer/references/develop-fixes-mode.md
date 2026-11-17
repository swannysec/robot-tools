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

Dispatch a separate fix author at High effort on the host's analysis-tier model (see `SKILL.md` and the runtime guide). The independent fix verifiers use the same host-adaptive selection as analysis; neither verifier may be the author agent.

Every packet in this mode carries the `--develop-fix` / `--verify-fix` authorization statement from [orchestrator-contract.md](orchestrator-contract.md), after the repository authorization check passes. The execution prohibition there applies in full: never execute, compile, adapt, or register reporter-supplied proof-of-concept code, payloads, or exploit scripts, and never produce a working exploit. The author writes its own small adversarial-input regression tests from the frozen contract; a reporter's proof of concept is never copied into a test or registered as one.

1. Freeze the contract and all test definitions before editing production code; when the finding arrived through GHSA mode, each test passes `scripts/intake-check.py poc-overlap` before registration ([deterministic-validation.md](deterministic-validation.md)), and the fix author's packet carries the report's fix-guidance issues (`fix_guidance` in `step1a/dispositions.json`) as reporter-supplied, non-binding data; tests are still written from the frozen contract. Record the contract version, source artifact and hash of the full contract, base revision, test IDs/hashes, and author provenance. Bind the handoff to both version and artifact hash; a matching version alone does not establish identical content. The orchestrator may validate the hash but does not adjudicate contract compatibility.
2. Author one regression test for each declared adversarial input class plus declared benign/negative controls. Test the untouched base revision first: adversarial-input regression tests must fail as expected; benign controls must retain their expected behavior.
3. Prove the test reaches the cited sink/observable using the frozen deterministic method and oracle. Record `TEST_OBSERVED`, `TEST_WRITTEN_NOT_RUN`, or `TEST_UNVALIDATED` accurately; written tests alone are not validation.
4. Make the smallest root-cause patch on an isolated branch. Do not expand scope, alter frozen tests, or substitute a compensating control for the declared invariant without returning the finding to human review.
5. On the patched revision, run the same frozen adversarial-input regression tests, benign controls, sink-coverage, regression, and class-coverage checks. Use a deeper deterministic check matched to the claim where predeclared. Run a mutation check at the fix site (Rust default: `necessist` when compatible); a surviving mutant is a failed test-quality gate.
6. Patch iteration is bounded to at most three attempts with the same frozen contract and tests. Carry every prior patch and gate result forward. After the third failed attempt, stop and return a candidate-patch failure packet for human review. This authoring budget is separate from the one-retry limit for malformed mandatory role output.
7. Hand the patch to `--verify-fix` as a cold artifact, including original test results and any supplemental checks from [deterministic-validation.md](deterministic-validation.md), clearly distinguished in the existing finding record. The verifier receives no author reasoning trace. Preserve prior results and explicit corrections rather than changing frozen tests to make a patch pass.

The deterministic check contract and test evidence states are defined in [deterministic-validation.md](deterministic-validation.md). Independent native and cross-provider verification is mandatory under [cross-model-verification.md](cross-model-verification.md); runtime dispatch follows [runtime-claude.md](runtime-claude.md) or [runtime-codex.md](runtime-codex.md).

## Two-phase network gate

Use an isolated branch and the host's enforced sandbox. Phase 1 permits only dependency/toolchain preparation such as `cargo fetch`, build prerequisites, and approved nightly components. Record fetched versions and hashes. Phase 2 disables network access and runs frozen adversarial-input regression tests and benign controls, sink and class coverage, full regression tests, deeper checks, and mutation testing with Cargo offline. Cargo's `--offline` is a package-manager control, not the sandbox boundary; verify the host's network denial is effective. Do not expose user credential directories or permit unsandboxed commands.

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
   <clone> --out <file>`, with `--out` outside the sandbox and the temporary directory (code in
   Phase 2 can write both and could rewrite a profile kept there). It creates the sandbox's own
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
   revision set to `report_revision`, and run `intake-check.py poc-overlap` on every test file.
   Register, in one frozen-test registry, entries that each start with `sandbox-exec -f
   <profile>` (the system `sandbox-exec`, with the profile's absolute path written exactly as passed to
   `test-result --profile`) followed directly by `cargo`, and expect exit 0 (`deterministic-check.py` runs outside the profile, and
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
4. **Phase 1 (network on), per checkout.** Let `rustup` provide the revision's toolchain, with
   the `llvm-tools` component `cargo-llvm-cov` needs for that toolchain, and run
   `cargo fetch --locked` with `CARGO_HOME` set to the sandbox's Cargo home, so every dependency is
   downloaded fresh into the sandbox. A fetch failure that names a missing or older package version
   may be a package firewall or a registry problem, not the code: check the firewall's events
   first. If the endpoint still cannot be prepared, its tests are `UNRESOLVED`.
5. **Phase 2 (network off), per checkout.** Under `sandbox-exec -f <profile>` with the reported
   environment, building only the crate under test (`cargo ... -p <crate> --offline --locked`):
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
   controls still pass there.

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
- writes anywhere other than the sandbox directory and the null, terminal, and descriptor
  devices. The Cargo and rustup homes in the home directory and the user's temporary directory are
  not writable; Phase 2's `TMPDIR` is a directory inside the sandbox.

Paths are resolved, because Seatbelt matches real paths. The command refuses a sandbox directory
inside, or containing, the home directory, the temporary directory, the run root, or the clone; an
`--out` inside the sandbox or the temporary directory; and a `RUSTUP_HOME` that is, or contains,
the home directory (the profile makes the rustup home readable). An existing directory chosen for
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
a file), and other system services. A microVM is the v2 hardening.

Other hosts (Linux, Codex's own sandbox) are not verified for this entry; on them, run the
test-only entry only after an equivalent denial check.

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
