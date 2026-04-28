#!/usr/bin/env bash
# activity-paginate.sh — vercel-forensics Phase 1
#
# Paginate Vercel's /v3/events team-wide activity log via `vercel activity
# --all --format json --since 90d --limit 100` using the `.pagination.next`
# cursor. Honors three safety rails (see references/collection-patterns.md
# §"Activity-log paginator" + vercel-cli-quirks.md §"vercel activity hang
# under load"):
#
#   1. Throttle ≤50 req/min (ceiling 60 — leave 10 for retries). Sleep 1.2s
#      between pages.
#   2. Per-page HTTP timeout of 60s via `gtimeout` when available, otherwise
#      the ADR-004 portable bash watchdog (no GNU `timeout` on macOS BSD).
#   3. 5-minute idle-progress watchdog — if no new events are received for
#      5 minutes straight, abort with `partial=true` in a sidecar note and
#      write the reason to $CASE/scan-errors.txt.
#
# 429 handling: the `vercel activity` CLI does not expose response headers,
# so we parse the command's stderr for a `retry-after` hint or fall back to
# the recommended 30s cool-down; on explicit rate-limit signals we sleep
# appropriately and retry the same cursor.
#
# Targets bash 3.2 + BSD userland (ADR-002). No `timeout`/`gtimeout` assumed;
# no `$EPOCHSECONDS`; uses `date +%s`.
#
# Inputs:
#   --case <path>         Required. Case directory (must already exist).
#   --dry-run             Print planned commands to stdout; write nothing.
#   --log-requests        Append each `vercel activity` invocation (with
#                         cursor) to $CASE/raw/vercel/activity-requests.log.
#
# Environment:
#   TEAM_ID               Required (set by preflight.sh). Missing →
#                         scan-errors.txt + exit 2.
#   RESUME_FROM           Optional cursor to resume an interrupted pull.
#
# Outputs (non dry-run):
#   $CASE/raw/vercel/activity.jsonl              One event per line.
#   $CASE/raw/vercel/activity.json               Merged array via jq -s '.'.
#   $CASE/raw/vercel/activity-pagination.log     iso_ts<TAB>cursor<TAB>count.
#   $CASE/raw/vercel/activity.partial            Present iff partial pull.
#
# Exit codes:
#   0  completed (full pull)
#   2  partial pull, TEAM_ID missing, or other recoverable failure
#      (details appended to $CASE/scan-errors.txt)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults + arg parsing
# ---------------------------------------------------------------------------
CASE=""
DRY_RUN=0
LOG_REQUESTS=0

usage() {
  cat >&2 <<'USAGE'
Usage: activity-paginate.sh --case <path> [--dry-run] [--log-requests]

  --case <path>      Case directory (required; must already exist).
  --dry-run          Emit the exact commands that would run to stdout; do
                     not touch the filesystem or hit the network.
  --log-requests     Record each invocation (url + cursor) under
                     $CASE/raw/vercel/activity-requests.log.

Environment:
  TEAM_ID            Required — set by preflight.sh.
  RESUME_FROM        Optional cursor (ms-epoch) to continue from.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      if [ "$#" -lt 2 ]; then
        echo "activity-paginate: --case requires a value" >&2
        usage
        exit 2
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
      echo "activity-paginate: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "${CASE}" ]; then
  echo "activity-paginate: --case <path> is required" >&2
  usage
  exit 2
fi

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
SINCE="90d"                 # Matches the activity-log retention window on Pro.
LIMIT=100                   # /v3/events hard cap.
THROTTLE_SECS="1.2"         # ≤50 req/min (60 ceiling with 10 for retries).
PAGE_TIMEOUT=60             # Per-page HTTP timeout (seconds).
IDLE_LIMIT=300              # 5-min idle-progress watchdog (seconds).
MAX_PAGES=500               # Runaway guard — at 100/pg = 50k events.
RATE_LIMIT_FALLBACK=30      # Sleep seconds when no retry-after hint is found.

# ---------------------------------------------------------------------------
# Dry-run mode: print the exact commands we would run, write nothing, exit 0.
# ---------------------------------------------------------------------------
if [ "${DRY_RUN}" -eq 1 ]; then
  cat <<DRY
# activity-paginate.sh --dry-run
# Read-only. No filesystem writes. No network calls.
# TEAM_ID would be read from env (set by preflight.sh).
# RESUME_FROM (optional) overrides first-page behaviour with --next <cursor>.

# First page (no cursor):
vercel activity --all --format json --since ${SINCE} --limit ${LIMIT}

# Subsequent pages (cursor from \`.pagination.next\`):
vercel activity --all --format json --since ${SINCE} --limit ${LIMIT} --next <CURSOR>

# Wrapped per page with a 60s timeout:
#   gtimeout 60 vercel activity --all --format json --since ${SINCE} --limit ${LIMIT} [--next <CURSOR>]
# Or ADR-004 watchdog when gtimeout is unavailable.
# Sleep ${THROTTLE_SECS}s between pages (≤50 req/min).
# Abort if no new events for ${IDLE_LIMIT}s straight (5-min idle watchdog).
DRY
  exit 0
fi

# ---------------------------------------------------------------------------
# TEAM_ID gate — write scan-errors.txt and exit 2 if missing.
# ---------------------------------------------------------------------------
# We only reach this block when not in --dry-run, so $CASE is load-bearing.
SCAN_ERRORS="${CASE}/scan-errors.txt"

record_error() {
  # record_error <reason>
  # Append one iso_ts<TAB>reason line; create parent dir if somehow missing.
  local reason="$1"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "${CASE}" 2>/dev/null || true
  printf '%s\tactivity-paginate: %s\n' "${ts}" "${reason}" >> "${SCAN_ERRORS}"
}

if [ -z "${TEAM_ID:-}" ]; then
  record_error "TEAM_ID not set in environment (preflight.sh must be sourced first)"
  echo "activity-paginate: TEAM_ID not set — see ${SCAN_ERRORS}" >&2
  exit 2
fi

if [ ! -d "${CASE}" ]; then
  record_error "case directory does not exist: ${CASE}"
  echo "activity-paginate: case directory does not exist: ${CASE}" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Output paths + setup
# ---------------------------------------------------------------------------
OUT_DIR="${CASE}/raw/vercel"
mkdir -p "${OUT_DIR}"

OUT_JSONL="${OUT_DIR}/activity.jsonl"
OUT_JSON="${OUT_DIR}/activity.json"
PAGINATION_LOG="${OUT_DIR}/activity-pagination.log"
REQUEST_LOG="${OUT_DIR}/activity-requests.log"
PARTIAL_FLAG="${OUT_DIR}/activity.partial"

# Validate RESUME_FROM cursor charset before any use — Vercel activity
# cursors are opaque ms-epoch-ish strings. Reject anything outside a
# safe set to prevent an operator who pastes a multi-line cursor (or
# an attacker with shell-env access) from corrupting the request URL.
if [ -n "${RESUME_FROM:-}" ]; then
  case "${RESUME_FROM}" in
    *[!A-Za-z0-9_=.:-]*)
      echo "activity-paginate.sh: RESUME_FROM contains disallowed characters; refusing." >&2
      echo "  expected charset: [A-Za-z0-9_=.:-]" >&2
      exit 2
      ;;
  esac
fi

# Truncate outputs on fresh runs; preserve on RESUME_FROM so we accumulate.
if [ -z "${RESUME_FROM:-}" ]; then
  : > "${OUT_JSONL}"
  : > "${PAGINATION_LOG}"
fi

# Per-page stdout + stderr go to temp files (required for backgrounded-watchdog
# capture; see ADR-004). Clean up on any exit path.
TMP_STDOUT="$(mktemp -t vf-activity-stdout.XXXXXX)"
TMP_STDERR="$(mktemp -t vf-activity-stderr.XXXXXX)"

cleanup() {
  rm -f -- "${TMP_STDOUT}" "${TMP_STDERR}" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Timeout wrapper — prefer gtimeout, otherwise ADR-004 watchdog.
# ---------------------------------------------------------------------------
HAS_GTIMEOUT=0
if command -v gtimeout >/dev/null 2>&1; then
  HAS_GTIMEOUT=1
fi

# run_with_timeout TIMEOUT_SECS STDOUT_FILE STDERR_FILE -- CMD [ARGS ...]
# Runs CMD with a hard wall-clock timeout. Returns the command's exit code,
# or 124 on timeout (matching GNU `timeout` convention).
run_with_timeout() {
  local secs="$1" outfile="$2" errfile="$3"
  shift 3
  # Drop the literal "--" separator if present.
  if [ "${1:-}" = "--" ]; then shift; fi

  if [ "${HAS_GTIMEOUT}" -eq 1 ]; then
    gtimeout "${secs}" "$@" >"${outfile}" 2>"${errfile}"
    return $?
  fi

  # ADR-004 portable watchdog: background the command, spawn a watchdog that
  # sleeps then kills, wait for the command, then clean up the watchdog.
  : > "${outfile}"
  : > "${errfile}"
  "$@" >"${outfile}" 2>"${errfile}" &
  local cmd_pid=$!

  (
    trap 'exit 0' TERM
    sleep "${secs}"
    # kill -0 guard against PID reuse (ADR-004); astronomically unlikely
    # race window between the guard and the actual kill, accepted.
    if kill -0 "${cmd_pid}" 2>/dev/null; then
      kill -TERM "${cmd_pid}" 2>/dev/null || true
      sleep 1
      if kill -0 "${cmd_pid}" 2>/dev/null; then
        kill -KILL "${cmd_pid}" 2>/dev/null || true
      fi
    fi
  ) &
  local wd_pid=$!

  local rc=0
  wait "${cmd_pid}" 2>/dev/null || rc=$?

  # Shut the watchdog down cleanly whether or not it already fired.
  if kill -0 "${wd_pid}" 2>/dev/null; then
    kill -TERM "${wd_pid}" 2>/dev/null || true
    wait "${wd_pid}" 2>/dev/null || true
  fi

  # The BSD shell reports SIGTERM as exit 143; remap to 124 so callers can
  # treat it identically to GNU `timeout`.
  if [ "${rc}" -eq 143 ]; then
    rc=124
  fi
  return "${rc}"
}

# ---------------------------------------------------------------------------
# 429 / rate-limit detection on stderr.
# ---------------------------------------------------------------------------
# `vercel activity` does not echo response headers, so we inspect stderr
# for "429", "rate limit", or "too many requests", and try to extract a
# `retry-after: <N>` or `x-ratelimit-reset: <epoch>` hint if the CLI happens
# to surface one. Falls back to RATE_LIMIT_FALLBACK seconds otherwise.
#
# Echoes the sleep seconds on stdout (integer); empty output = no rate-limit.
detect_rate_limit_sleep() {
  local errfile="$1"
  [ -s "${errfile}" ] || return 0
  # Fast reject: no rate-limit keywords anywhere.
  if ! LC_ALL=C grep -Eiq '429|rate[[:space:]]*limit|too[[:space:]]*many[[:space:]]*requests' "${errfile}"; then
    return 0
  fi

  local retry_after reset_epoch now sleep_for
  retry_after="$(LC_ALL=C grep -Eio 'retry-after[[:space:]]*[:=][[:space:]]*[0-9]+' "${errfile}" \
    | head -n1 | LC_ALL=C grep -Eo '[0-9]+' | head -n1 || true)"
  if [ -n "${retry_after}" ]; then
    printf '%s\n' "${retry_after}"
    return 0
  fi

  reset_epoch="$(LC_ALL=C grep -Eio 'x-ratelimit-reset[[:space:]]*[:=][[:space:]]*[0-9]+' "${errfile}" \
    | head -n1 | LC_ALL=C grep -Eo '[0-9]+' | head -n1 || true)"
  if [ -n "${reset_epoch}" ]; then
    now="$(date +%s)"
    sleep_for=$(( reset_epoch - now ))
    if [ "${sleep_for}" -gt 0 ]; then
      printf '%s\n' "${sleep_for}"
      return 0
    fi
  fi

  printf '%s\n' "${RATE_LIMIT_FALLBACK}"
}

# ---------------------------------------------------------------------------
# Main pagination loop
# ---------------------------------------------------------------------------
NEXT="${RESUME_FROM:-}"
PAGE=0
TOTAL_EVENTS=0
LAST_PROGRESS="$(date +%s)"
PARTIAL=0
PARTIAL_REASON=""

while : ; do
  PAGE=$((PAGE + 1))

  if [ "${PAGE}" -gt "${MAX_PAGES}" ]; then
    PARTIAL=1
    PARTIAL_REASON="MAX_PAGES=${MAX_PAGES} exceeded (last cursor=${NEXT})"
    break
  fi

  # Build command argv.
  if [ -n "${NEXT}" ]; then
    set -- vercel activity --all --format json --since "${SINCE}" --limit "${LIMIT}" --next "${NEXT}"
  else
    set -- vercel activity --all --format json --since "${SINCE}" --limit "${LIMIT}"
  fi

  if [ "${LOG_REQUESTS}" -eq 1 ]; then
    # Filter-before-write: cursor is ms-epoch, not a secret. Safe to log verbatim.
    printf '%s\tpage=%d\tcursor=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${PAGE}" "${NEXT:-<initial>}" \
      >> "${REQUEST_LOG}"
  fi

  # Run with 60s per-page timeout.
  rc=0
  run_with_timeout "${PAGE_TIMEOUT}" "${TMP_STDOUT}" "${TMP_STDERR}" -- "$@" || rc=$?

  # --- Rate-limit branch: sleep then retry the same cursor (no PAGE++ penalty).
  if [ "${rc}" -ne 0 ]; then
    sleep_secs="$(detect_rate_limit_sleep "${TMP_STDERR}" || true)"
    if [ -n "${sleep_secs}" ]; then
      record_error "rate-limit on page ${PAGE} (cursor=${NEXT:-<initial>}); sleeping ${sleep_secs}s"
      sleep "${sleep_secs}"
      PAGE=$((PAGE - 1))   # retry the same page
      continue
    fi

    if [ "${rc}" -eq 124 ]; then
      PARTIAL=1
      PARTIAL_REASON="per-page HTTP timeout (${PAGE_TIMEOUT}s) on page ${PAGE} (cursor=${NEXT:-<initial>})"
      break
    fi

    # Any other non-zero exit: record and stop. Emit stderr tail for diagnostics.
    stderr_tail="$(tail -c 512 "${TMP_STDERR}" 2>/dev/null | tr '\n' ' ' | tr -s ' ')"
    PARTIAL=1
    PARTIAL_REASON="vercel activity exited ${rc} on page ${PAGE} (cursor=${NEXT:-<initial>}); stderr=${stderr_tail}"
    break
  fi

  # --- Parse response.
  # Guard against non-JSON stdout (e.g. progress bleed) by validating via jq.
  if ! jq -e . >/dev/null 2>&1 <"${TMP_STDOUT}"; then
    stderr_tail="$(tail -c 512 "${TMP_STDERR}" 2>/dev/null | tr '\n' ' ' | tr -s ' ')"
    PARTIAL=1
    PARTIAL_REASON="malformed JSON on page ${PAGE} (cursor=${NEXT:-<initial>}); stderr=${stderr_tail}"
    break
  fi

  COUNT="$(jq -r '(.events // []) | length' <"${TMP_STDOUT}" 2>/dev/null || echo 0)"
  # Defensive: ensure COUNT is a non-negative integer.
  if ! printf '%s' "${COUNT}" | LC_ALL=C grep -Eq '^[0-9]+$'; then
    COUNT=0
  fi

  if [ "${COUNT}" -gt 0 ]; then
    jq -c '.events[]' <"${TMP_STDOUT}" >>"${OUT_JSONL}"
    TOTAL_EVENTS=$((TOTAL_EVENTS + COUNT))
    LAST_PROGRESS="$(date +%s)"
  fi

  # Pagination log line: iso_ts<TAB>cursor<TAB>count.
  printf '%s\t%s\t%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${NEXT:-<initial>}" "${COUNT}" \
    >>"${PAGINATION_LOG}"

  # --- Idle-progress watchdog.
  NOW="$(date +%s)"
  IDLE=$(( NOW - LAST_PROGRESS ))
  if [ "${IDLE}" -ge "${IDLE_LIMIT}" ]; then
    PARTIAL=1
    PARTIAL_REASON="idle watchdog tripped at page ${PAGE} after ${IDLE}s with no new events (last cursor=${NEXT:-<initial>})"
    break
  fi

  # --- Cursor advance.
  NEW_NEXT="$(jq -r '.pagination.next // empty' <"${TMP_STDOUT}" 2>/dev/null || true)"
  if [ -z "${NEW_NEXT}" ] || [ "${NEW_NEXT}" = "null" ]; then
    # End of stream — clean finish.
    break
  fi
  NEXT="${NEW_NEXT}"

  sleep "${THROTTLE_SECS}"
done

# ---------------------------------------------------------------------------
# Merge JSONL → JSON array (always, even on partial pulls so downstream
# analysis gets whatever we captured).
# ---------------------------------------------------------------------------
if [ -s "${OUT_JSONL}" ]; then
  if ! jq -s '.' "${OUT_JSONL}" >"${OUT_JSON}" 2>/dev/null; then
    record_error "jq -s failed to merge ${OUT_JSONL} into ${OUT_JSON}"
    PARTIAL=1
    PARTIAL_REASON="${PARTIAL_REASON:-jq merge failed on activity.jsonl}"
  fi
else
  # Empty pull — still emit a valid empty-array JSON for downstream consumers.
  printf '[]\n' >"${OUT_JSON}"
fi

# ---------------------------------------------------------------------------
# Partial flag + scan-errors entry.
# ---------------------------------------------------------------------------
if [ "${PARTIAL}" -eq 1 ]; then
  {
    printf 'partial=true\n'
    printf 'reason=%s\n' "${PARTIAL_REASON}"
    printf 'pages=%d\n' "${PAGE}"
    printf 'events=%d\n' "${TOTAL_EVENTS}"
    printf 'last_cursor=%s\n' "${NEXT:-<initial>}"
    printf 'iso_ts=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"${PARTIAL_FLAG}"
  record_error "${PARTIAL_REASON}"
  exit 2
fi

# Success: remove any stale partial flag from a prior run.
rm -f -- "${PARTIAL_FLAG}" 2>/dev/null || true
exit 0
