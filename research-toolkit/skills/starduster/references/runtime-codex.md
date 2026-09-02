# Codex Desktop runtime

Local Codex in the desktop app discovers the shared package through its catalog. Resolve
`STARDUSTER_SKILL_DIR` to that catalog-reported package directory and invoke the public
controller once:

```text
python3 "$STARDUSTER_SKILL_DIR/scripts/starduster.py" sync \
  [--limit N] [--full] [--project-dir PATH] [--confirm-rate] [--preserve-on-failure]
```

The controller automatically selects Codex when the current process exposes a known
Codex host indicator. `RESEARCH_TOOLKIT_RUNTIME=codex` is the explicit override for
automation and unusual hosts. If both Claude and Codex indicators are present, or no
known host is present, it fails closed instead of guessing.

Handle only safe JSON. On interactive `confirmation_required`, ask the rate question in
the safe details and rerun the same command with explicit `--confirm-rate`. Do not read
the controller workspace, GitHub artifacts, prompts, or model output.

## Authentication and App Server isolation

`RESEARCH_TOOLKIT_CODEX_AUTH=auto|oauth|api_key` chooses the authentication behavior
described in [configuration.md](configuration.md). OAuth is copied only to a private
App Server home, verified again after synthesis, and removed during cleanup. The
selected Codex executable is an external host dependency: `STARDUSTER_CODEX_BIN` is the
explicit override, followed by the bundled Desktop executable and then `codex` on
`PATH`. Each source must pass the same capability and isolation checks. The release live
proof is intentionally stricter: it uses only the bundled, signed Desktop build.
Missing executables, authentication, capability evidence, or isolation controls fail
closed.

The adapter starts a short-lived stdio App Server with one ephemeral controller-owned
thread. It passes raw input over its broker-owned local transport; private workspace
files constrain the controller artifact boundary but are not the only path to the
isolated computation. The model environment and workspace roots are empty. Network,
filesystem, browser/computer, MCP, app, plugin, nested-agent, dynamic-tool, external-
tool, shell-tool, and direct-artifact-reader effects remain denied unless their specific
preventive control is evidenced. Code Mode may perform only bounded `exec` and `wait`
computation. The adapter verifies negotiated capabilities and lifecycle events, rejects
prohibited events, validates the structured result, and returns safe status metadata.

The App Server wire schema uses the JSON Schema subset supported by OpenAI Structured
Outputs: an object root containing the synthesis array. The package's canonical schema
remains stricter. In particular, the wire schema omits unsupported `uniqueItems`
keywords, and deterministic validation enforces those uniqueness constraints before
any model value can reach rendering. An unsupported schema or an invalid response fails
closed rather than weakening the output contract.

When explicitly requested, the controller writes a bounded, redacted run-scoped report
of its inner App Server operation: selected binary/version, transport and lifecycle,
authentication evidence, sandbox/environment posture, and prohibited-event count. OAuth
evidence confirms that a private copy was removed and its source was unchanged. API-key
evidence confirms only ephemeral login and absence of persistent credentials; it makes
no OAuth-copy claim. The acceptance runner, separately, combines catalog discovery, the
exact public controller command, and filesystem-derived output provenance. Neither
report contains live GitHub data, model prose, prompts, OAuth material, or API keys.
