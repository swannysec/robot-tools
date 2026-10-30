# Deterministic validation

Deterministic validation checks a declared proposition against a predeclared oracle. It
does not discover findings, weigh evidence, select a winner, or supply missing judgment.
The orchestrator runs the packaged non-model adapter `scripts/deterministic-check.py`
to execute them. The result must be a
file digest or frozen-test observation, not model interpretation. A discovery or verifier
role never supplies shell text, an executable, or arguments.

## Typed checks and preventive boundary

Only two check kinds are accepted:

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
discovery packet and do not modify the registry after dispatch. The adapter verifies the
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
sentinels. A role-emitted test ID absent from the pre-discovery registry is unexecutable.

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

- vulnerable/base revision: exploit regression must fail in the expected way;
- patched revision: exploit regression must pass;
- benign negative controls and the project regression suite must pass on the patch.

This oracle may resolve whether the frozen contract was satisfied. It cannot prove that
the contract enumerated every possible bypass; residual or out-of-contract propositions
remain separately verified or disputed.
