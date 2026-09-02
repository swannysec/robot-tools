# Claude Code runtime

Claude Code discovers this shared package through its normal skill directories. Resolve
`STARDUSTER_SKILL_DIR` to the discovered package directory and invoke the public
controller once:

```text
python3 "$STARDUSTER_SKILL_DIR/scripts/starduster.py" sync \
  [--limit N] [--full] [--project-dir PATH] [--confirm-rate] [--preserve-on-failure]
```

Set the Claude Bash tool's `timeout` field to `600000` milliseconds for this single
command. A five-repository run can exceed Bash's default two-minute timeout because
the controller performs isolated synthesis sequentially. The timeout setting changes
only how long the host waits; it does not change the command or broaden its authority.

The controller automatically selects Claude when the current process exposes a known
Claude host indicator. `RESEARCH_TOOLKIT_RUNTIME=claude` is the explicit override for
automation and unusual hosts. If both Claude and Codex indicators are present, or no
known host is present, it fails closed instead of guessing.

Handle only the safe JSON result. If it reports `confirmation_required` during an
interactive run, use the safe details to ask for rate approval and rerun the same
command with `--confirm-rate`. Noninteractive behavior remains controller-owned.

Internally, the controller keeps raw GitHub files in its private workspace and builds a
bounded batch JSON document for synthesis. It launches `claude -p` in a separate
ephemeral directory with safe mode, no session persistence, no Chrome, no slash
commands, an empty tool surface, strict empty MCP configuration, and `dontAsk`
permissions. The child retains only the user identity variables needed for Claude's
managed login plus locale and `PATH`; GitHub, OpenAI, Anthropic, proxy, SSH-agent, and
outer-host variables are removed. Claude's documented safe mode keeps authentication
available while disabling user and project customizations. The controller sends the
bounded batch JSON through standard input rather than a
command argument or a raw-file path, applies the selected model profile, validates the
structured response, and returns only safe status metadata. It retries one invalid
structured response and then fails closed.

The adapter checks `claude --help` and stops if a required isolation control is absent.
Claude permission preapproval may allow the exact public controller command, but it is
not a sandbox or a substitute for the child isolation boundary. Do not call `gh`, a
subagent, a renderer, or an artifact reader as host orchestration.
