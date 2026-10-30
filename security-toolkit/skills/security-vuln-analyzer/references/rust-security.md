# Rust Security Reference

Use this as review guidance, not as a vulnerability predicate. A finding still requires a pinned revision, attacker-reachable path, evidence, counterevidence, and the workflow's independent verification.

## Unsafe and FFI

- Treat each `unsafe` block, `unsafe fn`, raw pointer, transmute, layout assumption, and FFI boundary as an invariant boundary. Trace who establishes bounds, validity, alignment, aliasing, lifetime, ownership, threading, and ABI invariants—and who can influence them.
- Require a nearby, specific `SAFETY:` explanation for nontrivial unsafe code. Missing documentation is normally a clarity and risk-control concern, not proof of memory unsafety.
- Prefer narrow safe wrappers over exposing raw handles. Keep unsafe operations local; use `#![deny(unsafe_code)]` where a crate should not need them.
- At FFI boundaries, validate lengths, nullability, enum discriminants, ownership transfer, callbacks, and integer conversions before allocation or pointer arithmetic.

## Availability and untrusted data

- An `unwrap`, `expect`, `panic!`, unchecked index, or assertion is security-relevant only when an untrusted or attacker-controlled path can reach it and the failure has a material security effect. Otherwise record it, where useful, as reliability guidance.
- Use checked arithmetic and explicit conversion checks at size, offset, quota, duration, count, and allocation boundaries. Do not infer safety from debug-only overflow behavior.
- Bound parser input, recursion/depth, collection growth, decompression, decoded dimensions, frame counts, response bodies, and background work. Validate before allocating when the format permits it.
- Treat deserialization as shape parsing, not authorization. Enforce semantic validation, limits, and explicit handling of unknown fields where compatibility permits.

## Make invalid states difficult to represent

- Use newtypes for validated identifiers, paths, URLs, tokens, tenant IDs, and externally supplied names. Keep construction private or fallible.
- Use type-state or capability types where state transitions matter, such as authenticated versus unauthenticated sessions, validated versus raw input, or sealed versus unsealed credentials.
- Design APIs to be safe by default: restrictive configuration, explicit opt-in to privilege, parameterized interfaces instead of shell strings, and return types that preserve validation state.

## OS, async, and filesystem boundaries

- For subprocesses, trace executable selection, argument construction, current directory, inherited environment, standard streams, credential exposure, timeouts, output limits, and cancellation. Prefer fixed executables, argument arrays, `env_clear` plus an allowlist where appropriate, and least-privileged child processes.
- For filesystem paths, distinguish lexical cleaning from authorization. Resolve or open relative to a trusted root; handle symlinks, junctions, case behavior, replacement races, and time-of-check/time-of-use windows. `canonicalize` alone does not make a later path operation race-free.
- For async code, identify authorization checks separated from use by awaits, cancellation/cleanup gaps, unbounded queues or fan-out, task lifetime, and shared-state races. A lock or atomic is not an authorization proof.
- Treat network, IPC, extensions, plugins, and local project content as separate trust boundaries; do not assume local content is trusted merely because it is on disk.

## Useful evidence tools

These tools locate candidates; they do not validate a security conclusion.

| Tool | Useful review signal |
| --- | --- |
| `cargo clippy` | Panic-prone operations, suspicious arithmetic, indexing, and API misuse, subject to configured lints. |
| `cargo audit` / `cargo deny` | Dependency advisory and policy candidates. |
| `cargo geiger` | Unsafe-code inventory and concentration. |
| Miri, fuzzing, property tests | Dynamic evidence for selected invariants; coverage and execution conditions must be reported. |

## Classification guardrails

- Missing `SAFETY:` documentation, a safer API opportunity, or a defensive limit can be a hardening or secure-code note without inflating the vulnerability count.
- A compensating control must be evidenced at the pinned revision and on the actual path; a nearby check is not automatically a control.
- State whether an assertion is static confirmation, a test written, a test observed, or an unvalidated test claim.
