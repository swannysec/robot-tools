# Claude Code runtime

Claude Code discovers the shared `SKILL.md` from its normal skill directories. Resolve
`KCAP_SKILL_DIR` to that discovered package directory, then invoke the public controller
once. The privileged host agent must never read raw extraction, metadata, child output,
synthesis, or rendered-note files.

```text
python3 "$KCAP_SKILL_DIR/scripts/kcap.py" capture URL \
  [--mode standard|deep|full] [--focus TEXT] [--project-dir PATH] \
  [--collision suffix|replace|skip] [--confirm-large] [--preserve-on-failure]
```

Handle only the controller's safe JSON. If it returns `confirmation_required` during
interactive use, use its safe details to ask for large-capture consent or a collision
choice, then rerun that same command with the chosen explicit `--confirm-large` or
`--collision` flag. `skipped_duplicate` is a terminal success. Noninteractive behavior
is controller-owned.

Internally, the controller's Claude adapter:

- reads raw files only inside the private kcap workspace;
- launches `claude -p` in a separate ephemeral directory with safe mode, no session
  persistence, no Chrome, no slash commands, an empty tool surface, strict empty MCP
  configuration, and `dontAsk` permissions;
- sends untrusted content through standard input rather than a command argument;
- applies the bundled output schema and configured model mapping;
- captures child output inside deterministic code, validates and sanitizes it, and
  writes only `$WORK_DIR/synthesis.json`;
- returns only safe status metadata; and
- retries one invalid response, then fails closed.

The adapter interrogates `claude --help` and stops when a required isolation option is
unavailable. Interactive Claude use may ask for permission to invoke the bundled public
controller. A caller may preapprove that exact command for noninteractive use, but host
permission preapproval is not the child isolation boundary. Do not orchestrate
`extract`, `claude-synthesize`, `render`, or artifact readers from the host.
