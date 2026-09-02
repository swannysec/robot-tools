# Error handling

The public `capture` controller emits one safe JSON object to stdout on success.
Expected validation and runtime failures emit this safe shape to stderr and exit `1`:

```json
{"ok": false, "error": {"code": "invalid_url", "message": "..."}}
```

Invocation or internal contract errors exit `2`. The controller never emits raw external
content or model prose. It may report a recovery path only after an explicit
`--preserve-on-failure` choice. Hosts must not treat final host prose as a success signal;
use the controller result and verified output file instead.

## Stable error families

| Codes | Action |
|---|---|
| `invalid_config`, `missing_config`, `missing_config_section`, `unsupported_schema` | Stop and report the neutral configuration path. |
| `invalid_legacy_config`, `missing_legacy_section` | Stop and provide migration instructions; do not modify the legacy file. |
| `invalid_runtime`, `unknown_runtime`, `ambiguous_runtime` | Stop and request an explicit runtime override. |
| `invalid_url`, `dns_error`, `ssrf_blocked`, `network_error` | Stop before processing fetched content. |
| `missing_extractor`, `extraction_failed`, `insufficient_content`, `content_too_large` | Stop and report the source/tool limitation. |
| `invalid_synthesis`, `synthesis_error` | Retry once in isolation, then stop. |
| `confirmation_required` | Inspect safe details. Ask for large-capture consent and rerun with `--confirm-large`, or ask for `suffix`, `replace`, or `skip` and rerun with that `--collision` value. Noninteractive behavior is controller-owned. |
| `duplicate_ambiguous` | Stop: `replace` found more than one normalized-source match. Report the safe paths and require the user to resolve the ambiguity. |
| `codex_auth_error` | Stop. The requested OAuth source or API-key login did not meet the selected authentication mode; never fall back from explicit `oauth` or `api_key`. |
| `codex_capability_error`, `codex_app_server_error`, `codex_app_server_auth_error` | Stop; never relax the App Server capability, authentication, or permission boundary. |
| `codex_app_server_protocol_error`, `codex_app_server_exit`, `codex_app_server_limit`, `codex_app_server_timeout` | Stop and discard the child result. Prohibited Code Mode activity, a missing lifecycle event, an unsafe event, or an exceeded resource bound is not recoverable. |
| `claude_isolation_unsupported`, `claude_failed`, `claude_output_error` | Stop; never relax the empty child tool surface. |
| `output_error`, `invalid_work_dir`, `invalid_acceptance_report`, `process_failed` | Apply the controller's cleanup policy and report only the safe write, process, or acceptance-contract failure. |

Missing optional extractors are not automatically installed. The controller never opens
Obsidian or another app. Cleanup warnings do not invalidate a note whose atomic move
completed, but a recovery path is reported only when `--preserve-on-failure` was an
explicit user choice and must not be read by the host.

Every external command and downloaded artifact is limited to 10 MiB. Full mode
preserves all substantive content only within that finite safety bound.

`skipped_duplicate` is a successful controller status, not an error. It reports sorted
existing paths and a count without extraction or synthesis.

For an explicitly requested live Codex authentication leg, unavailable OAuth or an
unavailable API-key login is an incomplete acceptance result with a nonzero outcome; it
is not evidence that the leg was skipped successfully. If the optional API-key test
variable was not supplied, that leg is `not_requested`, not skipped.
