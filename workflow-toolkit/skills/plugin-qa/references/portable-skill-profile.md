# Portable Skill Profile v1

## Purpose and scope

Portable Skill Profile v1 defines one skill package that can be copied unchanged into Claude Code and local Codex in the ChatGPT/Codex desktop app. It applies to the skill package itself, not to ChatGPT on the web or to every capability in a Claude plugin.

A conforming skill works without hplumb. Hplumb or another installer is optional
distribution tooling, not a runtime dependency: it may distribute the same package, but
it must not generate host-specific behavioral variants, supply missing runtime files, or
be present when the skill runs. A distributor may add non-semantic provenance or
compatibility metadata when the resulting package preserves the source instructions,
contains every required package file, and still passes this profile.

## Normative requirements

### Package structure

A portable skill directory must contain:

```text
<skill-name>/
├── SKILL.md
├── agents/
│   └── openai.yaml
└── references/
    ├── runtime-claude.md
    └── runtime-codex.md
```

Scripts, schemas, prompts, fixtures used at runtime, and other assets must live below the same skill directory. The package may add `scripts/`, `schemas/`, `assets/`, and additional `references/` files as needed.

All local references must be relative to the skill package and resolve to existing files inside it. A package must not depend on the robot-tools checkout, a Claude plugin root, a particular installed-skill path, or files reached through `..` or an escaping symlink. Runtime code must find its own package directory instead of assuming the current working directory.

Direct copying of the complete source skill directory, unchanged, into either host's normal skill directory is a supported installation method. Distribution-tool transformations are optional and must not be necessary for either host to run the source package.

### Shared `SKILL.md`

There is exactly one host-neutral `SKILL.md`. Its YAML frontmatter may contain only these shared top-level fields:

- `name` (required): at most 64 lower-case letters, digits, and single separating hyphens; it must equal the skill directory name.
- `description` (required): a non-empty description that provides sufficient discovery and activation context for both hosts.
- `license` (optional non-empty string).
- `allowed-tools` (optional non-empty string or list of non-empty strings).
- `metadata` (optional mapping).

The `triggers` field is forbidden because it is not accepted by Codex. Discovery intent belongs in `description`. `allowed-tools` is Claude permission preapproval only; it does not restrict the tools an agent can call and must never be treated as an isolation or security boundary.

Host-neutral workflow and output requirements remain in `SKILL.md`. Host-specific invocation, model selection, sandboxing, and feature controls belong in the runtime references. `SKILL.md` must link to both `references/runtime-claude.md` and `references/runtime-codex.md` and direct the executing host to use exactly its matching reference.

### Codex metadata

`agents/openai.yaml` is both the portable-profile marker and Codex desktop UI metadata. It must be valid YAML and contain an `interface` mapping with non-empty `display_name`, `short_description`, and `default_prompt` strings. `short_description` must be 25–64 characters. `default_prompt` must name the skill as `$<skill-name>` so copied or stale metadata is detected.

Any icon paths in `agents/openai.yaml` must be package-relative, exist, and remain inside the skill directory.

### Runtime boundaries

The Claude runtime reference must state how Claude Code executes the shared workflow, including any permission or isolation assumptions. The Codex runtime reference must state how local Codex in the desktop app executes it and which unavailable or unsafe capabilities cause a fail-closed result.

An executable discovered from a bundled Desktop installation, an explicitly configured
location, or `PATH` is an external host dependency, not a package file. The Codex runtime
reference must state its selection order and fail closed if the selected host executable
or required capability evidence is unavailable. If the controller reads untrusted input
from a private file and then sends it to an isolated runtime through a local broker
transport, document both boundaries; private files are not, by themselves, the complete
input path.

Host selection must be explicit or deterministic. An ambiguous or unknown host must fail with a useful diagnostic rather than guess. The skill must not require hplumb, target-specific generated instructions, or knowledge of the source repository.

For content-processing skills, untrusted input must not reach a privileged parent merely because `allowed-tools` is present. Extraction, isolation, broker transport where used, schema validation, sanitization, and rendering boundaries must be documented and enforced by the implementation appropriate to each host. A bounded, redacted acceptance report may support a particular run, but it does not prove a different host or a later run. OAuth copy-boundary evidence must describe the immediate snapshot and verification around the private copy; it must not claim that an independently managed source file can never be refreshed.

### Recommended deterministic top-level operations

For workflows with dependent commands, state transitions, or untrusted-content
boundaries, provide one deterministic top-level operation that owns the sequence and
returns safe structured status. This keeps the host from reconstructing state, reading
intermediate artifacts, or treating untrusted/model prose as a completion signal.

This is reusable design guidance, not a universal Portable Skill Profile validator
requirement. A portable skill may expose a different public interface when its workflow
does not need a controller; the standalone validator must not fail such a package merely
because it lacks a deterministic top-level operation.

## Capability-assessment matrix

First classify the authority a host or adapter provides:

- `native`: the host supplies the capability directly and the package uses it without an adapter.
- `adapter`: the package implements a host-specific adapter behind shared behavior.
- `host-only`: the capability intentionally remains available on only one host and is not required for the portable skill contract.
- `unsupported`: required behavior cannot currently be delivered safely on that host.
- `not-assessed`: no compatibility conclusion has been reached; this cannot be used for a release claim.

Then classify the actual effect of every enabled tool or operation:

- `computation-only`: bounded transformation or analysis with no external side effect.
- `local-state`: reads or changes explicitly scoped local state.
- `external-effect`: can reach a network service, launch an app, delegate to another
  agent, or otherwise affect systems outside the bounded local operation.
- `privileged-context`: can disclose untrusted content or sensitive material to a more
  privileged agent or context.

A computation-only tool may remain native when the host can constrain its exact
operations and the migration has evidence for its lifecycle and result handling. For
example, constrained Code Mode `exec` and `wait` may be acceptable for computation-only
work; their presence does not authorize arbitrary process or filesystem access. Do not
impose a tool-free rule merely because computation is implemented through a tool. For
filesystem, process, network, browser/computer, MCP, app, plugin, local-state, or
external-effect capabilities, require preventive controls that govern the specific
effect, direct enforcement evidence, and tests that demonstrate the controls.
Sandboxing compensates only for effects the sandbox actually governs; it does not justify
an unrelated capability. Event inspection, provenance, and postcondition checks are
defense in depth, not a substitute for preventive controls.

Complete this matrix before migrating a skill or evaluating a broader plugin:

| Capability | Claude Code | Codex Desktop | Evidence or adapter |
|---|---|---|---|
| Skill discovery and instructions | not-assessed | not-assessed | |
| Scripts, references, schemas, and assets | not-assessed | not-assessed | |
| Configuration and persistent state | not-assessed | not-assessed | |
| CLI dependencies and authentication | not-assessed | not-assessed | |
| Model selection and subagent dispatch | not-assessed | not-assessed | |
| Commands, agents, and hooks | not-assessed | not-assessed | |
| MCP servers and apps | not-assessed | not-assessed | |
| UI metadata | not-assessed | not-assessed | |
| Direct installation and plugin updates | not-assessed | not-assessed | |

Record each material tool's effect classification and the preventive control or evidence
next to this matrix. A capability may be `native` and `computation-only`, or `adapter`
and `external-effect`; the two classifications answer different questions.

A plugin may contain `host-only` commands, agents, or hooks while also contributing conforming portable skills. Assess those plugin components separately; do not imply that portable skill conformance makes the whole plugin portable.

## Migration checklist

1. Inventory each skill, command, agent, hook, MCP server, app, script, asset, external command, configuration source, state store, and authentication dependency.
2. Classify every capability for Claude Code and Codex Desktop using the authority matrix and assign each material tool or operation an effect classification. Resolve every `not-assessed` item that is material to the intended support claim.
3. Separate portable skill behavior from plugin-only extensions. A host-only extension must not be a hidden prerequisite for the shared skill.
4. Define host selection, configuration precedence, model mapping, untrusted-input boundaries, deterministic validation, failure behavior, and output compatibility.
5. For each material effect, identify the preventive control and a test that exercises it. Treat sandboxing as compensation only for effects it governs; retain event inspection, provenance, and filesystem checks as defense in depth.
6. For a workflow with dependent commands, state, or untrusted-content boundaries, decide whether one deterministic top-level operation should own the sequence and return safe structured status. Document that boundary without treating it as a universal validator requirement.
7. Make runtime dependencies package-relative and add `agents/openai.yaml` plus both runtime references. Run the standalone validator.
8. Test a direct, unchanged copy in each host without hplumb. Then test any supported distributor using temporary sources and destinations.
9. Test native Claude plugin installation and update behavior when the skill is shipped in a plugin.
10. Record fixture, direct-host, live-host, plugin-update, and distribution evidence. Do not convert research or child-agent conclusions into compatibility claims without central verification.
11. Update the native plugin manifest and any existing changelog. Keep one authoritative plugin version; do not add another version source to a marketplace entry or portability file.

## Non-goals

Portable Skill Profile v1 does not define:

- a generalized cross-host plugin manifest;
- target-specific `SKILL.md` generation;
- hook, command, agent, MCP, or app emulation;
- a requirement to use hplumb or any other distribution tool;
- compatibility with ChatGPT on the web;
- automatic migration of unrelated plugins such as context-keeper.

The standalone validator checks structural conformance. It cannot prove the semantic safety of prompts, isolation controls, host behavior, authentication, live integrations, or plugin-update behavior; those require the migration and acceptance evidence above.
