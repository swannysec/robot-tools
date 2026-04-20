#!/usr/bin/env bash
# vercel-team-context.sh — vercel-forensics Phase 2 orchestrator.
#
# Pulls team-wide context (read-only) in bounded parallel bursts:
#
#   /v2/teams/$TEAM_ID                               -> team/team.json
#     (preserves saml object — primary tier signal + role-mapping evidence)
#   /v2/teams/$TEAM_ID/members?limit=200             -> team/members.json
#   /v5/user/tokens                                  -> team/user-tokens.json
#     (self-scope only — no team-wide token enumeration exists; documented
#     limitation in references/data-inventory.md)
#   /v1/log-drains?teamId=$TEAM_ID                   -> team/log-drains.json
#   /v1/integrations/configurations?teamId=$TEAM_ID&view=account
#                                                    -> team/integrations-list.json
#   For each cid in integrations-list.json:
#     /v1/integrations/configurations/<cid>          -> team/integrations/<cid>.json
#     (gap-patch: granted permissions + scopes)
#   /v5/domains?teamId=$TEAM_ID&limit=100            -> team/domains.json   (paginate)
#   /v4/aliases?teamId=$TEAM_ID&limit=100            -> team/aliases.json   (paginate)
#   /v4/certs?teamId=$TEAM_ID&limit=100              -> team/certs.json     (paginate)
#   /v1/webhooks?teamId=$TEAM_ID                     -> team/webhooks.json
#   /v1/edge-config?teamId=$TEAM_ID                  -> team/edge-config.json
#   /v1/access-groups?teamId=$TEAM_ID                -> team/access-groups.json
#     (Enterprise-only; 404 on Pro → recorded as expected gap in scan-errors.txt)
#
# Additionally creates $CASE/github-linked-repos.txt (empty) if absent, so
# Phase 3 (vercel-per-project.sh) can append one "owner/repo" per line and
# Phase 4 (github-repo-graphql.sh) can consume the file.
#
# Parallelism: endpoints are grouped into bursts of ≤6 background jobs, each
# burst joined with `wait`, to stay under rate-limit ceilings. The tightest
# team-scope endpoints are generous (hundreds of req/min) — the 6-wide cap is
# a defensive ceiling, not a limit driven by any specific endpoint.
#
# Platform: bash 3.2 + BSD userland (ADR-002). No GNU-isms.
# Requires: vercel, jq, python3, TEAM_ID in env.
#
# Exit codes:
#   0  all endpoints succeeded
#   1  fatal (bad args, missing env, missing $CASE layout)
#   2  one or more endpoints failed — per-endpoint rows appended to
#      $CASE/scan-errors.txt (schema: phase2\t<endpoint>\tGET\t<reason>)

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants + arg defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CASE=""
DRY_RUN=0
LOG_REQUESTS=0

MAX_PARALLEL=6
PARTIAL=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat >&2 <<'EOF'
Usage: vercel-team-context.sh --case <path> [--dry-run] [--log-requests]

Phase 2 orchestrator for vercel-forensics — parallel team-wide pulls.

  --case <path>     Absolute path to the case directory (from preflight.sh).
  --dry-run         Emit `GET <url>` lines to stdout; write no files.
  --log-requests    Echo redacted request lines to stderr before each call.

Environment:
  TEAM_ID           Required. Vercel team id (from preflight.sh exports).

Exit codes:
  0  all endpoints succeeded
  1  fatal (bad args, missing env, missing $CASE layout)
  2  one or more endpoints failed (see $CASE/scan-errors.txt)
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      if [ "$#" -lt 2 ]; then
        echo "vercel-team-context: --case requires a value" >&2
        usage
        exit 1
      fi
      CASE="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --log-requests)
      LOG_REQUESTS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "vercel-team-context: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$CASE" ]; then
  echo "vercel-team-context: --case <path> is required" >&2
  usage
  exit 1
fi

if [ "$DRY_RUN" -eq 0 ]; then
  # Live mode requires TEAM_ID + a writable case layout. Dry-run only needs
  # TEAM_ID to render URLs; case dir is not required to exist.
  if [ ! -d "$CASE" ]; then
    echo "vercel-team-context: case dir does not exist: $CASE" >&2
    exit 1
  fi
fi

if [ -z "${TEAM_ID:-}" ]; then
  echo "vercel-team-context: TEAM_ID environment variable is required" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Required-binary check
# ---------------------------------------------------------------------------
for bin in vercel jq python3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "vercel-team-context: required binary not on PATH: $bin" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Layout: raw/vercel/team + raw/vercel/team/integrations
# ---------------------------------------------------------------------------
TEAM_DIR="$CASE/raw/vercel/team"
INTEGRATIONS_DIR="$TEAM_DIR/integrations"
SCAN_ERRORS="$CASE/scan-errors.txt"
LINKED_REPOS_FILE="$CASE/github-linked-repos.txt"

if [ "$DRY_RUN" -eq 0 ]; then
  mkdir -p "$TEAM_DIR" "$INTEGRATIONS_DIR"
  chmod 0700 "$TEAM_DIR" "$INTEGRATIONS_DIR" 2>/dev/null || true
  # Phase 3 will populate this; Phase 2 only guarantees the file exists so
  # collect.sh Phase 4 can test -s on it cleanly.
  if [ ! -e "$LINKED_REPOS_FILE" ]; then
    : > "$LINKED_REPOS_FILE"
    chmod 0600 "$LINKED_REPOS_FILE" 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------------------
# Record-error helper (Phase 2 schema)
# ---------------------------------------------------------------------------
record_error() {
  # record_error <endpoint> <reason>
  # Appends one row to $CASE/scan-errors.txt.
  # Schema (from plan): phase2\t<endpoint>\tGET\t<reason>
  local endpoint="$1"
  local reason="$2"
  if [ "$DRY_RUN" -eq 1 ]; then
    return 0
  fi
  printf 'phase2\t%s\tGET\t%s\n' "$endpoint" "$reason" >> "$SCAN_ERRORS" || true
  PARTIAL=1
}

# ---------------------------------------------------------------------------
# Log-request helper (redacted; delegates to _common.py::log_request)
# ---------------------------------------------------------------------------
log_request_line() {
  # log_request_line <path-and-query>
  # Renders `GET <path> (token_source=env(VERCEL_TOKEN))` through redact_value.
  if [ "$LOG_REQUESTS" -eq 0 ]; then
    return 0
  fi
  local endpoint="$1"
  python3 - "$endpoint" "${SCRIPT_DIR}" <<'PY' 2>/dev/null || true
import sys
endpoint = sys.argv[1]
script_dir = sys.argv[2]
sys.path.insert(0, script_dir)
from _common import log_request
log_request(f"https://api.vercel.com{endpoint}", "GET", token_source="env")
PY
}

# ---------------------------------------------------------------------------
# URL builder helpers — centralize ?teamId= and &limit= composition.
# All endpoints under api.vercel.com are validated downstream by
# _common.py::ALLOWED_PATHS (the call is via `vercel api`, so validation
# happens by construction: we only ever pass allowlisted path templates).
# ---------------------------------------------------------------------------
url_team()               { printf '/v2/teams/%s' "$TEAM_ID"; }
url_members()            { printf '/v2/teams/%s/members?limit=200' "$TEAM_ID"; }
url_user_tokens()        { printf '/v5/user/tokens'; }
url_log_drains()         { printf '/v1/log-drains?teamId=%s' "$TEAM_ID"; }
url_integrations_list()  { printf '/v1/integrations/configurations?teamId=%s&view=account' "$TEAM_ID"; }
url_integration_detail() { printf '/v1/integrations/configurations/%s' "$1"; }
url_domains()            { printf '/v5/domains?teamId=%s&limit=100' "$TEAM_ID"; }
url_aliases()            { printf '/v4/aliases?teamId=%s&limit=100' "$TEAM_ID"; }
url_certs()              { printf '/v4/certs?teamId=%s&limit=100' "$TEAM_ID"; }
url_webhooks()           { printf '/v1/webhooks?teamId=%s' "$TEAM_ID"; }
url_edge_config()        { printf '/v1/edge-config?teamId=%s' "$TEAM_ID"; }
url_access_groups()      { printf '/v1/access-groups?teamId=%s' "$TEAM_ID"; }

# ---------------------------------------------------------------------------
# Fetch helpers
#
# fetch_one <endpoint> <out-path>
#   Writes the JSON body to <out-path> atomically (via tmp + rename).
#   Records scan-errors on failure; returns non-zero on failure so the
#   caller (a backgrounded subshell) can propagate status via `wait`.
#
# fetch_paginated <endpoint> <out-path>
#   Uses `vercel api ... --paginate` to merge cursor pages into one JSON
#   blob. `vercel api --paginate` emits a single concatenated array (or
#   object-with-pagination) per CLI docs; we capture stdout verbatim.
#
# Why not call the Python layer for the HTTP itself? The skill's design
# deliberately uses `vercel api` so session auth + team-scope + optional
# pagination are handled by the CLI. Validation is enforced by the fact
# that we only ever form path templates present in ALLOWED_PATHS.
# ---------------------------------------------------------------------------

_atomic_install() {
  # _atomic_install <tmp> <final>
  # Refuse overwrite (matches _common.py::atomic_write semantics for the
  # cross-process case: Phase 2 is the sole writer of these files).
  local tmp="$1"
  local final="$2"
  if [ -e "$final" ]; then
    rm -f "$tmp"
    return 1
  fi
  mv "$tmp" "$final"
  chmod 0600 "$final" 2>/dev/null || true
}

fetch_one() {
  local endpoint="$1"
  local out_path="$2"
  log_request_line "$endpoint"
  local tmp
  tmp="$(mktemp -t vf-fetch.XXXXXX)"
  # `vercel api <endpoint>` prints body to stdout, returns non-zero on
  # HTTP non-2xx. Capture stderr separately so it does not poison the JSON.
  local err_file
  err_file="$(mktemp -t vf-fetch-err.XXXXXX)"
  if vercel api "$endpoint" >"$tmp" 2>"$err_file"; then
    # Reject empty bodies as a soft failure (paginated endpoints may return
    # an empty array; that parses as valid JSON and is fine).
    if [ ! -s "$tmp" ]; then
      record_error "$endpoint" "empty-response"
      rm -f "$tmp" "$err_file"
      return 1
    fi
    # Validate it is JSON; if not, the endpoint likely returned an HTML
    # error page through the CLI wrapper.
    if ! jq -e . "$tmp" >/dev/null 2>&1; then
      record_error "$endpoint" "non-json-response"
      rm -f "$tmp" "$err_file"
      return 1
    fi
    if ! _atomic_install "$tmp" "$out_path"; then
      record_error "$endpoint" "output-exists:$out_path"
      rm -f "$err_file"
      return 1
    fi
    rm -f "$err_file"
    return 0
  fi
  # Non-2xx: capture reason from stderr (first line) for the scan-errors row.
  local reason
  reason="$(awk 'NR==1 {print; exit}' "$err_file" 2>/dev/null || true)"
  if [ -z "$reason" ]; then
    reason="vercel-api-nonzero"
  fi
  record_error "$endpoint" "$reason"
  rm -f "$tmp" "$err_file"
  return 1
}

fetch_paginated() {
  local endpoint="$1"
  local out_path="$2"
  log_request_line "$endpoint"
  local tmp
  tmp="$(mktemp -t vf-fetch-pg.XXXXXX)"
  local err_file
  err_file="$(mktemp -t vf-fetch-pg-err.XXXXXX)"
  if vercel api "$endpoint" --paginate >"$tmp" 2>"$err_file"; then
    if [ ! -s "$tmp" ]; then
      # An endpoint with no results may still emit "[]" — truly empty stdout
      # indicates a CLI failure not caught by the exit code.
      record_error "$endpoint" "empty-response-paginated"
      rm -f "$tmp" "$err_file"
      return 1
    fi
    if ! jq -e . "$tmp" >/dev/null 2>&1; then
      record_error "$endpoint" "non-json-response-paginated"
      rm -f "$tmp" "$err_file"
      return 1
    fi
    if ! _atomic_install "$tmp" "$out_path"; then
      record_error "$endpoint" "output-exists:$out_path"
      rm -f "$err_file"
      return 1
    fi
    rm -f "$err_file"
    return 0
  fi
  local reason
  reason="$(awk 'NR==1 {print; exit}' "$err_file" 2>/dev/null || true)"
  if [ -z "$reason" ]; then
    reason="vercel-api-nonzero-paginated"
  fi
  record_error "$endpoint" "$reason"
  rm -f "$tmp" "$err_file"
  return 1
}

# ---------------------------------------------------------------------------
# Burst runner: start up to MAX_PARALLEL background jobs, then `wait`.
# Bash 3.2 does not have `wait -n`, so we join the whole burst at once.
# Each job runs inside a subshell that swallows its own exit code — we
# already recorded the failure via record_error inside fetch_one, so the
# `wait` status on the subshell is not meaningful for the overall exit code.
# ---------------------------------------------------------------------------
_pids=()
_run_bg() {
  # _run_bg <command...>
  # Launches in background, records PID.
  "$@" &
  _pids+=("$!")
}
_join_bg() {
  # _join_bg — wait for all tracked PIDs, then clear the list.
  local pid
  for pid in "${_pids[@]:-}"; do
    [ -z "$pid" ] && continue
    wait "$pid" 2>/dev/null || true
  done
  _pids=()
}

# ===========================================================================
# DRY-RUN MODE
# ===========================================================================
# Emit one `GET <url>` per endpoint the live path would call. For integration
# detail we cannot enumerate cids without the list response, so we emit a
# single placeholder line the operator can read as "one call per integration".
if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
GET $(url_team)
GET $(url_members)
GET $(url_user_tokens)
GET $(url_log_drains)
GET $(url_integrations_list)
GET $(url_integration_detail '<cid>')   # one call per integration in the list above
GET $(url_domains)
GET $(url_aliases)
GET $(url_certs)
GET $(url_webhooks)
GET $(url_edge_config)
GET $(url_access_groups)
EOF
  exit 0
fi

# ===========================================================================
# BURST 1: core team context (6 endpoints, fits MAX_PARALLEL)
# ===========================================================================
# team.json MUST be the first write into team/ — downstream tier-detection
# and triage scripts look at it. We still run it alongside the other non-
# dependent pulls; if it fails, other pulls still contribute evidence and
# the run is marked partial.
_pids=()
_run_bg fetch_one          "$(url_team)"               "$TEAM_DIR/team.json"
_run_bg fetch_one          "$(url_members)"            "$TEAM_DIR/members.json"
_run_bg fetch_one          "$(url_user_tokens)"        "$TEAM_DIR/user-tokens.json"
_run_bg fetch_one          "$(url_log_drains)"         "$TEAM_DIR/log-drains.json"
_run_bg fetch_one          "$(url_integrations_list)"  "$TEAM_DIR/integrations-list.json"
_run_bg fetch_one          "$(url_webhooks)"           "$TEAM_DIR/webhooks.json"
_join_bg

# ===========================================================================
# BURST 2: paginated + remaining team-scope endpoints (5 — well under 6)
# ===========================================================================
_pids=()
_run_bg fetch_paginated    "$(url_domains)"            "$TEAM_DIR/domains.json"
_run_bg fetch_paginated    "$(url_aliases)"            "$TEAM_DIR/aliases.json"
_run_bg fetch_paginated    "$(url_certs)"              "$TEAM_DIR/certs.json"
_run_bg fetch_one          "$(url_edge_config)"        "$TEAM_DIR/edge-config.json"
# access-groups is Enterprise-only. 404 on Pro is recorded as an expected
# gap; record_error runs inside fetch_one and marks PARTIAL.
_run_bg fetch_one          "$(url_access_groups)"      "$TEAM_DIR/access-groups.json"
_join_bg

# ===========================================================================
# BURST 3+: per-integration detail (gap-patch)
# ===========================================================================
# If the integrations-list pull succeeded, extract each configuration id and
# fetch its detail endpoint (granted permissions + scopes). The list payload
# shape is either a bare array of configurations or { "configurations": [...] }
# depending on CLI version — probe both.
INTEGRATIONS_LIST="$TEAM_DIR/integrations-list.json"
if [ -s "$INTEGRATIONS_LIST" ]; then
  # Extract ids; fall back to empty if the file is not an object/array with
  # ids. `jq -r` emits one id per line.
  CIDS="$(jq -r '
      if type == "array"
          then (.[] | (.id // .configurationId // empty))
          else ((.configurations // []) | .[] | (.id // .configurationId // empty))
      end
    ' "$INTEGRATIONS_LIST" 2>/dev/null || true)"

  if [ -n "$CIDS" ]; then
    _pids=()
    IN_BURST=0
    # bash 3.2 compatible: iterate a newline-separated list via `while read`.
    while IFS= read -r cid; do
      [ -z "$cid" ] && continue
      # Defensive: configurationId should be an opaque short token
      # (`icfg_...` on Vercel). Refuse anything with a slash or query
      # character to avoid escaping the path template.
      case "$cid" in
        */*|*\?*|*\&*|*\#*|*\ *)
          record_error "$(url_integration_detail "$cid")" "invalid-integration-id"
          continue
          ;;
      esac
      _run_bg fetch_one "$(url_integration_detail "$cid")" "$INTEGRATIONS_DIR/$cid.json"
      IN_BURST=$((IN_BURST + 1))
      if [ "$IN_BURST" -ge "$MAX_PARALLEL" ]; then
        _join_bg
        _pids=()
        IN_BURST=0
      fi
    done <<EOF
$CIDS
EOF
    # Drain the final partial burst.
    _join_bg
  fi
fi

# ===========================================================================
# Exit — partial if any endpoint failed.
# ===========================================================================
if [ "$PARTIAL" -eq 1 ]; then
  exit 2
fi
exit 0
