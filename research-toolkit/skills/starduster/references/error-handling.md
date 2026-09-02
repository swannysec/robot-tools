# Error handling

The public controller emits one safe JSON envelope. A failure has `ok: false` and an
`error` object containing a stable code, a bounded message, and safe details when they
are needed to make the next decision. It never includes raw GitHub responses, README
text, prompts, model prose, command arguments containing credentials, or tokens.

## Configuration and preflight

Malformed selected JSON, unsupported schema versions, unknown fields, invalid paths,
missing selected files, and a legacy file without a `starduster` section fail before
fetching. A valid legacy section may omit fields and receives historical defaults during
the `0.6.x` compatibility period. Legacy `main_model` is ignored with a warning; legacy
`synthesis_model` maps through the portable profile table in
[configuration.md](configuration.md).

The controller verifies the `gh` dependency and authentication before star fetching or
synthesis. Authentication, rate-limit, network, and malformed-response failures stop
safely. Repository-level unavailable data may be counted as a warning when the remaining
catalog is still valid.

## Confirmation and noninteractive use

When the estimate exceeds the confirmation threshold, the controller returns
`confirmation_required` with bounded `estimated_core_calls`,
`estimated_graphql_calls`, `estimated_percent`, `threshold_percent`, and the
`--confirm-rate` rerun instruction. The host may ask the user and rerun exactly once
with that explicit flag.
With `RESEARCH_TOOLKIT_NONINTERACTIVE=1`, the controller returns the same structured
error with `noninteractive: true`; it does not prompt, open an application, or preserve
a workspace.

## Synthesis, rendering, and recovery

The selected adapter fails closed for unknown or ambiguous runtime, unsupported isolation controls,
authentication failures, invalid structured synthesis, prohibited events, or bounded
timeout. The controller validates the entire result before writing each artifact.
Rendering failures leave no partial public result.

If Python 3 or PyYAML is unavailable, startup returns `missing_dependency` before GitHub
authentication or artifact creation. Install PyYAML in the controller's Python
environment, then rerun the same public command; the controller never installs it.

Private workspaces are removed after success and ordinary failures. With explicit
`--preserve-on-failure`, a `recovery_path` is returned only after post-fetch synthesis,
validation, or rendering failure; configuration and confirmation failures never preserve
one. A failed cleanup becomes a safe warning. Recovery is by rerunning the same public
`sync` command after correcting the underlying condition; this reference intentionally
does not provide destructive cleanup commands.
