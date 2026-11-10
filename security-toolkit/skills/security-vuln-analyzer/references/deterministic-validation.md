# Deterministic validation

Deterministic validation checks a declared proposition against a predeclared oracle. It
does not discover findings, weigh evidence, select a winner, or supply missing judgment.
The orchestrator runs the packaged non-model adapter `scripts/deterministic-check.py`
to execute them. The result must be a
file digest or frozen-test observation, not model interpretation. A discovery or verifier
role never supplies shell text, an executable, or arguments.

## Typed checks and preventive boundary

Only two check kinds are accepted. The pre-discovery registry below governs claim reconciliation; supplemental fix checks follow the separate execution rules under “Post-patch checks” and cannot resolve a split:

- `SOURCE_SLICE_SHA256`: read the named line slice from the named pinned revision,
  normalize line endings to LF, hash the exact UTF-8 bytes with SHA-256, and return
  `MATCHED` or `NOT_MATCHED`. The role supplies only repository, revision, canonical
  relative path, positive line range, and expected lowercase digest. This check validates
  artifact identity only. Every routing-table entry for it must preserve `DISPUTED`.
  Source lines are delimited by CR, LF, or CRLF bytes, matching the citation extractor;
  Unicode and other control separators inside a physical line do not increment the line number.
- `FROZEN_TEST_REFERENCE`: name a `frozen_test_id` registered before discovery. The
  registry, not a model result, contains the executable and argument vector, working
  directory, timeout, environment allowlist, expected exit/output oracle, and tool
  version and result-to-status table. Return `PASSED`, `FAILED`, or `UNRESOLVED`.

Invoke the adapter with a JSON request, an immutable checkout path, and, for a frozen
test, the frozen JSON registry. The executable, arguments, oracle, routing table, and
SHA-256 of the exact NFC- and LF-normalized proposition the test measures are all
registered before discovery. Record the SHA-256 of the complete registry bytes in every
discovery packet and do not modify the registry after dispatch. Before any test enters a
registry (pre-discovery, supplemental, `--develop-fix`, D5, or M2), when the finding has a
checked GHSA H1 result, run `scripts/intake-check.py poc-overlap` on each test source file
against that H1 result; `REJECT` blocks registration. The check matches long verbatim spans
from H1-extracted proof-of-concept blocks only; without an H1 result, or for a reworded
copy, the execution prohibition in `orchestrator-contract.md` is the only safeguard, so the
test author must write tests from the frozen contract, never from a reporter's proof of
concept. The adapter verifies the
registry digest, proposition binding, checkout `HEAD`, path containment, and routing-table identity, records adapter
name and version, and emits `schemas/computation-result.schema.json`. It rejects every other kind
and every inconsistent sentinel combination. It
never invokes a shell or evaluates metacharacters. It runs a frozen test as the exact
argument vector in an immutable checkout or temporary copy of the pinned revision, with
network denied, an empty or allowlisted environment, a bounded timeout and streaming
output capture, and
writes limited to its temporary directory. The target repository and skill package stay
read-only. The executed argument vector is recorded in the result but cannot come from
the role output.

Capture stdout and stderr separately and enforce the output limit across both streams.
The registry's `expected_stdout_sha256` hashes only stdout bytes; matching stderr cannot
satisfy that oracle. Keep stderr as labeled diagnostic output in the bounded result.

The host must run the adapter in the runtime guide's read-only, network-denied temporary
environment; the portable script cannot create an operating-system sandbox itself.
Frozen-test execution requires POSIX process groups and selectable subprocess pipes.
On native Windows or another unsupported platform, it returns `FAILED` / `NOT_RUN`
before launching a test child, with empty `executed_argv`. No Windows frozen-test capability
is claimed; a required fix oracle that cannot run leaves verification `INCOMPLETE`.

For `SOURCE_SLICE_SHA256`, `frozen_test_id` is empty. For `FROZEN_TEST_REFERENCE`, path,
line, and digest fields use the registry's frozen values or the schema's empty/zero
sentinels. A role-emitted test ID absent from the applicable frozen registry is unexecutable; only the original pre-discovery registry is eligible for dispute resolution.

Only a pre-discovery `FROZEN_TEST_REFERENCE` whose frozen proposition hash exactly matches
the disputed proposition may resolve a verifier split. A source digest cannot do so. Do not invent a
check after seeing verifier results. If the packet has no suitable check,
the check cannot execute, or its oracle does not decide the disputed proposition, return
`UNRESOLVED`. Mechanical Reconciliation then preserves `DISPUTED`.

## Result schema

For each proposition return:

- finding/candidate ID and proposition;
- `MATCHED`, `NOT_MATCHED`, `PASSED`, `FAILED`, `UNRESOLVED`, or `NOT_RUN`;
- check kind and ID, adapter name/version, tool version, pinned revision, bounded result, and adapter-recorded
  argument vector when a frozen test ran;
- the byte-preserved predeclared routing table; and
- no security conclusion beyond that literal result.

`TEST_WRITTEN` is not evidence that behavior was observed. Reports distinguish:

- `STATICALLY_CONFIRMED`—source/configuration directly supports the proposition;
- `TEST_WRITTEN_NOT_RUN`—a test exists but was not observed;
- `TEST_OBSERVED`—the recorded test ran on the named revision;
- `TEST_UNVALIDATED`—the test or its provenance cannot be checked.

Execution status and assertion outcome are separate. A completed test whose exit/output
contradicts its oracle is `COMPLETE` / `FAILED`. A timeout, output-limit stop, or capture
failure after launch is `FAILED` / `UNRESOLVED`, with the executed arguments and available
bounded diagnostics retained. A test that never launched is `FAILED` / `NOT_RUN`, with
empty `executed_argv`. Neither interruption nor launch failure demonstrates a failed
security assertion. `TEST_OBSERVED` records execution, not a passing assertion; a required
check without a valid completed result leaves the fix oracle `UNAVAILABLE`.

## Post-patch checks

Before adding a check, the author or verifier identifies the source-supported concern
and which fix, acceptance, or disposition decision its result could change. Use existing
project tests and the finding's contract first. Check the reported defect on the base
where feasible, patched secure behavior, required contract checks, relevant existing
regressions, and credible bypasses or sibling paths sharing the affected control. State
why reproduction or a relevant check could not run; static support is not an observed pass.

Preserve the original finding, contract, test definitions, registry, and raw results.
For a credible concern discovered after the original freeze, use a supplemental check:

- The authorized test author or human registers the existing runner's exact argv, test
  ID/hash, expected behavior/oracle, tool version, and pinned revision before execution.
  Reuse the adapter's registry format and sandbox; verifier output cannot supply commands.
- Freeze a separate registry and retain its digest independently before execution. Label
  it and its results **supplemental, added after patch inspection** in the existing finding
  record. All its routing entries must preserve `DISPUTED`; it never replaces the original
  registry, repairs an original failed oracle, or settles a verifier disagreement.
- Preserve base and patched observations, benign controls, and any infeasible or uncertain
  cases. If an original test is wrong, retain it and explain the correction with a separately
  identified test and result; do not rewrite history or count the old result as a pass.
- Capture supplemental results before freezing Stage 2 so both independent verifiers see
  the same identity-free evidence. Later evidence that changes acceptance requires a new
  frozen packet under the existing cold-verification rules, not an edited retry packet.

Verifiers assess whether a demonstrated bypass defeats the original contract or reveals
an out-of-contract concern; the orchestrator does not make that judgment. Keep distinct
findings on their own analysis path and link them rather than silently expanding scope.
Passing supplemental checks supports only the paths observed. Stop when required checks
and concrete concerns support the decision, or record the remaining gap and its effect
on acceptance. Hypothetical variants alone do not require more rounds or artifacts; an
execution budget ending is not evidence of closure.

## Class Coverage Check

Use this only when a control claims to cover a named primitive class.

1. Identify the canonical class source named in the packet, such as a protocol grammar,
   Unicode property file, database quoting rules, or documented sink inventory.
2. Enumerate its members without using the candidate control as the source of truth.
3. For every member, run the same binary recognition/rejection check.
4. Return members covered, missed, and not testable. Do not infer that an unlisted member
   is safe.

## Sink-Coverage Check for `--develop-fix`

An authored regression test must reach the cited sink before it is frozen. For Rust,
prefer `cargo-llvm-cov` JSON and aggregate all instrumented segments on the sink line:

```bash
cargo llvm-cov --ignore-run-fail --json --output-path cov.json test
jq '[.data[].files[]
     | select(.filename | endswith("src/auth.rs"))
     | .segments[] | select(.[0] == TARGET_LINE) | .[2]] | max' cov.json
```

`null` or zero is `NOT_REACHED`; a positive maximum is `REACHED`. A line can contain
multiple coverage segments, so testing one emitted segment is invalid. Record the exact
file, line, count, command, and tool version.

Where line coverage is unsuitable, use a recorded Miri/CodeQL execution trace or a
`trybuild` compile-fail proof for type-state/newtype fixes that deliberately make the
unsafe call unconstructable. The fallback and its oracle must be frozen before patch
verification.

## Fix-verification oracle

For a candidate patch, execute the frozen tests against both named revisions:

- vulnerable/base revision: adversarial-input regression tests must fail in the expected way;
- patched revision: adversarial-input regression tests must pass;
- benign negative controls and the project regression suite must pass on the patch.

This oracle may resolve whether the frozen contract was satisfied. It cannot prove that
the contract enumerated every possible bypass; residual or out-of-contract propositions
remain separately verified or disputed.
