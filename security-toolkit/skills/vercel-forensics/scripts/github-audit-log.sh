#!/usr/bin/env bash
# github-audit-log.sh — vercel-forensics Phase 4b
#
# Pull GitHub's REST audit log for an org or enterprise over a trailing window
# (default 180 days — the documented REST audit log retention ceiling). The
# log is collected in 14-day chunks to stay below the observed ~18-day
# dense-activity rate-limit wall (collection-patterns.md §5). Each chunk is
# fetched serially via `gh api --paginate` with a short 2s pause between
# chunks to smooth rate usage (hard ceiling: 1,750 requests/hr per user+IP).
#
# Personal accounts have NO REST audit log endpoint; that case is logged to
# scan-errors.txt and the script exits 0 (documented gap, not an error).
#
# Rate-limit recovery (collection-patterns.md §5): if `gh api --paginate`
# concatenates a `{"message":"API rate limit exceeded..."}` object onto the
# end of an otherwise-valid JSON array, we salvage the last-good JSON via
# `JSONDecoder.raw_decode` (inline Python heredoc), note the salvage in
# scan-errors.txt, honor the `X-RateLimit-Reset` header if it was surfaced
# (fallback: 1 hour), then resume remaining chunks.
#
# Targets bash 3.2 + BSD userland (ADR-002). Uses `date -u -v-Nd +%Y-%m-%d`
# for window arithmetic — no GNU `date -d`.
#
# Inputs:
#   --case <path>         Required. Case directory (must already exist).
#   --dry-run             Emit the exact gh api commands for each chunk.
#   --log-requests        Append each invocation (endpoint + phrase) to
#                         $CASE/raw/github/audit-requests.log.
#   --window-days <N>     Override window size (default 180).
#
# Target source:
#   $CASE/github-audit-target.txt  — one line, written by vercel-per-project.sh:
#       org <slug>        → endpoint /orgs/<slug>/audit-log
#       enterprise <slug> → endpoint /enterprises/<slug>/audit-log
#       user <login>      → skip (no endpoint exists); exit 0
#
# Outputs (non dry-run):
#   $CASE/raw/github/audit-log-180d.json     Merged JSON array (all chunks).
#   $CASE/raw/github/audit-log-180d.jsonl    One event per line.
#   $CASE/raw/github/audit-requests.log      When --log-requests is set.
#
# Exit codes:
#   0  completed (full pull) or deliberately skipped (user-account case)
#   2  partial pull, missing target, or other recoverable failure
#      (details appended to $CASE/scan-errors.txt)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults + arg parsing
# ---------------------------------------------------------------------------
CASE=""
DRY_RUN=0
LOG_REQUESTS=0
WINDOW_DAYS=180

usage() {
  cat >&2 <<'USAGE'
Usage: github-audit-log.sh --case <path> [--dry-run] [--log-requests] [--window-days <N>]

  --case <path>       Case directory (required; must already exist).
  --dry-run           Emit the exact gh api commands for each planned chunk;
                      do not touch the filesystem or hit the network.
  --log-requests      Record each invocation (endpoint + phrase) under
                      $CASE/raw/github/audit-requests.log.
  --window-days <N>   Trailing window in days (default 180 — REST audit log
                      retention ceiling).

Target source: $CASE/github-audit-target.txt (written by vercel-per-project.sh).
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      if [ "$#" -lt 2 ]; then
        echo "github-audit-log: --case requires a value" >&2
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
    --window-days)
      if [ "$#" -lt 2 ]; then
        echo "github-audit-log: --window-days requires a value" >&2
        usage
        exit 2
      fi
      WINDOW_DAYS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "github-audit-log: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "${CASE}" ]; then
  echo "github-audit-log: --case <path> is required" >&2
  usage
  exit 2
fi

# Validate --window-days is a positive integer.
if ! printf '%s' "${WINDOW_DAYS}" | LC_ALL=C grep -Eq '^[1-9][0-9]*$'; then
  echo "github-audit-log: --window-days must be a positive integer (got: ${WINDOW_DAYS})" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------
CHUNK_DAYS=14               # 14-day windows stay under ~18d dense-activity wall.
INTER_CHUNK_PAUSE=2         # Seconds between chunks (rate smoothing).
RATE_LIMIT_FALLBACK=3600    # 1 hour if no X-RateLimit-Reset surfaced.
PER_PAGE=100                # Audit log max.

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# record_error PHASE SLOT KIND MSG — structured scan-errors line.
record_error() {
  # phase4b\t<slot>\t<kind>\t<msg>
  local slot="$1" kind="$2" msg="$3"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "${CASE}" 2>/dev/null || true
  printf '%s\tphase4b\t%s\t%s\t%s\n' \
    "${ts}" "${slot}" "${kind}" "${msg}" \
    >> "${CASE}/scan-errors.txt"
}

# BSD-safe date arithmetic: offset from today in YYYY-MM-DD (UTC).
# Usage: offset_date -N  → date N days ago
date_offset_days() {
  # $1 is a signed int (e.g., -14, -180, 0). BSD `date -v` syntax.
  local offset="$1"
  if [ "${offset}" -eq 0 ]; then
    date -u +%Y-%m-%d
  elif [ "${offset}" -lt 0 ]; then
    # -v-Nd goes back N days.
    date -u -v"${offset}"d +%Y-%m-%d
  else
    # -v+Nd goes forward N days.
    date -u -v"+${offset}d" +%Y-%m-%d
  fi
}

# ---------------------------------------------------------------------------
# Read audit target BEFORE dry-run so dry-run mode still shows the planned
# endpoint + chunks using real data.
# ---------------------------------------------------------------------------
AUDIT_TARGET_FILE="${CASE}/github-audit-target.txt"

if [ ! -f "${AUDIT_TARGET_FILE}" ]; then
  if [ "${DRY_RUN}" -eq 1 ]; then
    cat <<DRY
# github-audit-log.sh --dry-run
# No target file at: ${AUDIT_TARGET_FILE}
# Run vercel-per-project.sh first to populate it.
DRY
    exit 0
  fi
  record_error "audit-log" "missing-target" "no ${AUDIT_TARGET_FILE} — run vercel-per-project.sh first"
  echo "github-audit-log: no audit target recorded at ${AUDIT_TARGET_FILE}" >&2
  exit 2
fi

TARGET_LINE="$(awk 'NR==1{print; exit}' "${AUDIT_TARGET_FILE}" 2>/dev/null || true)"
TARGET_KIND="$(printf '%s' "${TARGET_LINE}" | awk '{print $1}')"
TARGET_SLUG="$(printf '%s' "${TARGET_LINE}" | awk '{print $2}')"

if [ -z "${TARGET_KIND}" ] || [ -z "${TARGET_SLUG}" ]; then
  if [ "${DRY_RUN}" -eq 1 ]; then
    cat <<DRY
# github-audit-log.sh --dry-run
# Target file ${AUDIT_TARGET_FILE} is empty or malformed.
# Expected one of: "org <slug>", "enterprise <slug>", "user <login>".
DRY
    exit 0
  fi
  record_error "audit-log" "bad-target" "malformed ${AUDIT_TARGET_FILE}: '${TARGET_LINE}'"
  echo "github-audit-log: malformed target file: '${TARGET_LINE}'" >&2
  exit 2
fi

# Personal accounts: documented gap. Log and exit 0 (per spec).
if [ "${TARGET_KIND}" = "user" ]; then
  if [ "${DRY_RUN}" -eq 1 ]; then
    cat <<DRY
# github-audit-log.sh --dry-run
# Target is a personal account (${TARGET_SLUG}).
# REST audit log endpoints are NOT available for User accounts.
# Would log to scan-errors.txt: phase4\t${TARGET_SLUG}\tuser-audit\tunavailable (personal account)
# Exit 0 (skipped, not an error).
DRY
    exit 0
  fi
  # Spec calls for phase4 (not phase4b) + user-audit for this particular row.
  local_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "${CASE}" 2>/dev/null || true
  printf '%s\tphase4\t%s\tuser-audit\tunavailable (personal account)\n' \
    "${local_ts}" "${TARGET_SLUG}" \
    >> "${CASE}/scan-errors.txt"
  echo "github-audit-log: target is a personal account (${TARGET_SLUG}); no REST audit log available — skipped"
  exit 0
fi

# Build endpoint.
case "${TARGET_KIND}" in
  org)
    ENDPOINT="/orgs/${TARGET_SLUG}/audit-log"
    ;;
  enterprise)
    ENDPOINT="/enterprises/${TARGET_SLUG}/audit-log"
    ;;
  *)
    if [ "${DRY_RUN}" -eq 1 ]; then
      cat <<DRY
# github-audit-log.sh --dry-run
# Unknown target kind: '${TARGET_KIND}' (expected org|enterprise|user).
DRY
      exit 0
    fi
    record_error "audit-log" "bad-target" "unknown target kind: '${TARGET_KIND}'"
    echo "github-audit-log: unknown target kind: '${TARGET_KIND}'" >&2
    exit 2
    ;;
esac

# Slug regex guard — matches preflight's validation pattern.
if ! printf '%s' "${TARGET_SLUG}" | LC_ALL=C grep -Eq '^[A-Za-z0-9._-]{1,64}$'; then
  if [ "${DRY_RUN}" -eq 1 ]; then
    cat <<DRY
# github-audit-log.sh --dry-run
# Slug '${TARGET_SLUG}' fails the ^[A-Za-z0-9._-]{1,64}$ regex.
DRY
    exit 0
  fi
  record_error "audit-log" "bad-slug" "slug fails regex: '${TARGET_SLUG}'"
  echo "github-audit-log: invalid slug: '${TARGET_SLUG}'" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Compute chunk boundaries.
# Chunks cover [start, end] inclusive in YYYY-MM-DD. Oldest chunk first so
# ordering of the merged JSON array is chronologically ascending after the
# per-chunk pages (GitHub returns newest-first within each chunk, but across
# chunks we want the oldest chunk's events to land first in the file).
# We'll collect chunks newest-to-oldest instead, matching GitHub's natural
# ordering — downstream analysis is timestamp-driven and does not rely on
# file order.
# ---------------------------------------------------------------------------
# chunk_starts array holds the "N days ago" offsets for each chunk boundary.
# e.g. window=180, chunk=14 → offsets: 0, -14, -28, ..., -180.
# Each chunk is [offset - chunk_days + 1, offset] day range, capped at window.
#
# To keep bash 3.2 friendly (no associative arrays), we just iterate integers.

TODAY="$(date_offset_days 0)"
WINDOW_START="$(date_offset_days "-${WINDOW_DAYS}")"

# Total chunk count (ceil division).
NUM_CHUNKS=$(( (WINDOW_DAYS + CHUNK_DAYS - 1) / CHUNK_DAYS ))

# ---------------------------------------------------------------------------
# Dry-run mode: enumerate the exact commands per chunk. No side effects.
# ---------------------------------------------------------------------------
if [ "${DRY_RUN}" -eq 1 ]; then
  cat <<DRY
# github-audit-log.sh --dry-run
# Read-only. No filesystem writes. No network calls.
# Endpoint:       ${ENDPOINT}
# Window:         ${WINDOW_DAYS} days (${WINDOW_START} .. ${TODAY})
# Chunk size:     ${CHUNK_DAYS} days
# Chunks:         ${NUM_CHUNKS}
# Per-page:       ${PER_PAGE}
# Inter-chunk:    ${INTER_CHUNK_PAUSE}s pause between chunks
# Rate ceiling:   1,750 req/hr (user+IP); 1h fallback on 403
DRY
  i=0
  while [ "${i}" -lt "${NUM_CHUNKS}" ]; do
    chunk_end_offset=$(( -1 * i * CHUNK_DAYS ))
    chunk_start_offset=$(( chunk_end_offset - CHUNK_DAYS + 1 ))
    if [ "${chunk_start_offset}" -lt $(( -1 * WINDOW_DAYS )) ]; then
      chunk_start_offset=$(( -1 * WINDOW_DAYS ))
    fi
    chunk_end="$(date_offset_days "${chunk_end_offset}")"
    chunk_start="$(date_offset_days "${chunk_start_offset}")"
    phrase="created:${chunk_start}..${chunk_end}"
    printf '\n# Chunk %d of %d (%s .. %s):\n' \
      "$(( i + 1 ))" "${NUM_CHUNKS}" "${chunk_start}" "${chunk_end}"
    printf 'gh api %s --method GET --paginate -f per_page=%s -f phrase=%s\n' \
      "${ENDPOINT}" "${PER_PAGE}" "'${phrase}'"
    i=$(( i + 1 ))
  done
  exit 0
fi

# ---------------------------------------------------------------------------
# Live-run setup.
# ---------------------------------------------------------------------------
if [ ! -d "${CASE}" ]; then
  record_error "audit-log" "missing-case" "case directory does not exist: ${CASE}"
  echo "github-audit-log: case directory does not exist: ${CASE}" >&2
  exit 2
fi

OUT_DIR="${CASE}/raw/github"
mkdir -p "${OUT_DIR}"

# Output filenames are keyed by the configured window so the default run
# matches the spec even if someone calls with a custom --window-days.
OUT_JSON="${OUT_DIR}/audit-log-${WINDOW_DAYS}d.json"
OUT_JSONL="${OUT_DIR}/audit-log-${WINDOW_DAYS}d.jsonl"
REQUEST_LOG="${OUT_DIR}/audit-requests.log"

# Atomic-write pattern: accumulate into .tmp files, then rename.
TMP_JSONL="${OUT_JSONL}.tmp"
TMP_JSON="${OUT_JSON}.tmp"

: > "${TMP_JSONL}"

# Per-chunk temp buffers (stdout + stderr).
TMP_STDOUT="$(mktemp -t vf-ghaudit-stdout.XXXXXX)"
TMP_STDERR="$(mktemp -t vf-ghaudit-stderr.XXXXXX)"
TMP_SALVAGE="$(mktemp -t vf-ghaudit-salvage.XXXXXX)"

cleanup() {
  rm -f -- "${TMP_STDOUT}" "${TMP_STDERR}" "${TMP_SALVAGE}" \
           "${TMP_JSONL}" "${TMP_JSON}" 2>/dev/null || true
}
trap cleanup EXIT

# Check gh availability up front.
if ! command -v gh >/dev/null 2>&1; then
  record_error "audit-log" "missing-tool" "gh CLI not found on PATH"
  echo "github-audit-log: gh CLI not found on PATH" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Per-chunk iteration.
# ---------------------------------------------------------------------------
PARTIAL=0
TOTAL_EVENTS=0
i=0

while [ "${i}" -lt "${NUM_CHUNKS}" ]; do
  chunk_end_offset=$(( -1 * i * CHUNK_DAYS ))
  chunk_start_offset=$(( chunk_end_offset - CHUNK_DAYS + 1 ))
  if [ "${chunk_start_offset}" -lt $(( -1 * WINDOW_DAYS )) ]; then
    chunk_start_offset=$(( -1 * WINDOW_DAYS ))
  fi
  chunk_end="$(date_offset_days "${chunk_end_offset}")"
  chunk_start="$(date_offset_days "${chunk_start_offset}")"
  phrase="created:${chunk_start}..${chunk_end}"

  if [ "${LOG_REQUESTS}" -eq 1 ]; then
    # phrase is not secret; cursor/token never logged.
    printf '%s\tchunk=%d/%d\tendpoint=%s\tphrase=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$(( i + 1 ))" "${NUM_CHUNKS}" "${ENDPOINT}" "${phrase}" \
      >> "${REQUEST_LOG}"
  fi

  : > "${TMP_STDOUT}"
  : > "${TMP_STDERR}"

  rc=0
  # --include surfaces response headers so we can parse X-RateLimit-Reset on
  # rate-limit-driven failures. When `--paginate` is combined with `--include`,
  # `gh` emits one header block per response; that's fine — we only consult
  # the headers on the failure path via the JSON-salvage logic.
  gh api "${ENDPOINT}" \
    --method GET \
    --paginate \
    -f "per_page=${PER_PAGE}" \
    -f "phrase=${phrase}" \
    >"${TMP_STDOUT}" 2>"${TMP_STDERR}" || rc=$?

  # --------- Success path: parse JSON, append events.
  if [ "${rc}" -eq 0 ] && jq -e . >/dev/null 2>&1 <"${TMP_STDOUT}"; then
    count="$(jq -r 'if type=="array" then length else 0 end' <"${TMP_STDOUT}" 2>/dev/null || echo 0)"
    if ! printf '%s' "${count}" | LC_ALL=C grep -Eq '^[0-9]+$'; then
      count=0
    fi
    if [ "${count}" -gt 0 ]; then
      jq -c '.[]' <"${TMP_STDOUT}" >> "${TMP_JSONL}"
      TOTAL_EVENTS=$(( TOTAL_EVENTS + count ))
    fi
    i=$(( i + 1 ))
    if [ "${i}" -lt "${NUM_CHUNKS}" ]; then
      sleep "${INTER_CHUNK_PAUSE}"
    fi
    continue
  fi

  # --------- Failure path: attempt 403 rate-limit salvage (collection-patterns.md §5).
  # The canonical failure mode is that --paginate appended a
  # `{"message":"API rate limit exceeded...","status":"403"}` object onto
  # the end of an otherwise-valid JSON array. Salvage via JSONDecoder.raw_decode.
  salvaged=0
  salvaged_count=0
  reset_hint=""

  # Best-effort extraction of X-RateLimit-Reset from stderr (gh sometimes
  # includes debug-style headers there; absent on most paths but cheap to try).
  reset_hint="$(LC_ALL=C grep -Eio 'x-ratelimit-reset[[:space:]]*[:=][[:space:]]*[0-9]+' "${TMP_STDERR}" 2>/dev/null \
    | head -n1 | LC_ALL=C grep -Eo '[0-9]+' | head -n1 || true)"

  # Detect the inline 403 signature in stdout.
  if LC_ALL=C grep -q 'API rate limit exceeded' "${TMP_STDOUT}" 2>/dev/null; then
    : > "${TMP_SALVAGE}"
    # Inline Python salvage — stdlib only; reads path from argv; writes
    # salvaged event count to a counter file and the recovered JSON array
    # to the salvage path. We use a separate script-via-heredoc then invoke
    # it, rather than command-substitution-plus-heredoc, to avoid bash 3.2
    # parser quirks with heredocs inside $(...).
    TMP_PY="$(mktemp -t vf-ghaudit-salvage.XXXXXX.py)"
    TMP_COUNT="$(mktemp -t vf-ghaudit-salvage.XXXXXX.count)"
    cat > "${TMP_PY}" <<'PY'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
try:
    with open(src, 'r', encoding='utf-8', errors='replace') as fh:
        data = fh.read()
except OSError:
    print(0)
    sys.exit(0)

dec = json.JSONDecoder()
events = []
pos = 0
n = len(data)
while pos < n:
    while pos < n and data[pos] in ' \t\r\n':
        pos += 1
    if pos >= n:
        break
    try:
        obj, end = dec.raw_decode(data, pos)
    except json.JSONDecodeError:
        break
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict) and item.get('status') == '403' \
               and isinstance(item.get('message'), str) \
               and 'rate limit exceeded' in item['message'].lower():
                continue
            events.append(item)
    elif isinstance(obj, dict):
        if obj.get('status') == '403' \
           and isinstance(obj.get('message'), str) \
           and 'rate limit exceeded' in obj['message'].lower():
            pass
        else:
            events.append(obj)
    pos = end

try:
    with open(dst, 'w', encoding='utf-8') as out:
        json.dump(events, out)
except OSError:
    print(0)
    sys.exit(0)

print(len(events))
PY

    salvaged_count="$(python3 "${TMP_PY}" "${TMP_STDOUT}" "${TMP_SALVAGE}" 2>/dev/null || echo 0)"
    rm -f -- "${TMP_PY}" "${TMP_COUNT}" 2>/dev/null || true

    # Sanitize salvaged_count.
    if ! printf '%s' "${salvaged_count}" | LC_ALL=C grep -Eq '^[0-9]+$'; then
      salvaged_count=0
    fi

    if [ "${salvaged_count}" -gt 0 ] && [ -s "${TMP_SALVAGE}" ]; then
      # Append salvaged events to the JSONL accumulator.
      if jq -c '.[]' <"${TMP_SALVAGE}" >> "${TMP_JSONL}" 2>/dev/null; then
        salvaged=1
        TOTAL_EVENTS=$(( TOTAL_EVENTS + salvaged_count ))
        salvage_label="chunk $(( i + 1 ))/${NUM_CHUNKS} [${chunk_start}..${chunk_end}]"
        record_error "audit-log" "salvaged" \
          "${salvage_label} hit 403 rate-limit; salvaged ${salvaged_count} events via raw_decode"
      fi
    fi
  fi

  # --------- Determine wait time before resuming remaining chunks.
  if [ -n "${reset_hint}" ]; then
    now="$(date +%s)"
    wait_secs=$(( reset_hint - now ))
    if [ "${wait_secs}" -lt 60 ]; then
      wait_secs=60
    fi
  else
    wait_secs="${RATE_LIMIT_FALLBACK}"
  fi

  # If salvage succeeded, sleep until reset and advance to next chunk.
  # If salvage did not succeed but the chunk clearly failed on rate-limit,
  # still sleep and advance — partial=true, remaining chunks still attempted.
  # If the failure was NOT rate-limit related, record and advance (don't loop
  # forever on an endpoint error).
  chunk_label="chunk $(( i + 1 ))/${NUM_CHUNKS} [${chunk_start}..${chunk_end}]"
  if [ "${salvaged}" -eq 1 ] \
     || LC_ALL=C grep -q 'API rate limit exceeded' "${TMP_STDOUT}" 2>/dev/null \
     || LC_ALL=C grep -Eiq 'rate[[:space:]]*limit|429' "${TMP_STDERR}" 2>/dev/null; then
    PARTIAL=1
    record_error "audit-log" "rate-limit" \
      "${chunk_label} rate-limited; sleeping ${wait_secs}s before next chunk"
    sleep "${wait_secs}"
  else
    # Non-rate-limit failure (e.g. 404, network error). Record and advance.
    stderr_tail="$(tail -c 512 "${TMP_STDERR}" 2>/dev/null | tr '\n' ' ' | tr -s ' ')"
    PARTIAL=1
    record_error "audit-log" "chunk-failed" \
      "${chunk_label} gh api exited ${rc}; stderr=${stderr_tail}"
    # Short pause to avoid hot-looping on persistent errors.
    sleep "${INTER_CHUNK_PAUSE}"
  fi

  i=$(( i + 1 ))
done

# ---------------------------------------------------------------------------
# Merge JSONL → JSON array (always; atomic rename at the very end).
# ---------------------------------------------------------------------------
if [ -s "${TMP_JSONL}" ]; then
  if ! jq -s '.' "${TMP_JSONL}" > "${TMP_JSON}" 2>/dev/null; then
    record_error "audit-log" "jq-merge" "jq -s failed to merge ${TMP_JSONL} → ${TMP_JSON}"
    PARTIAL=1
    # Fall through and still write whatever we have (jsonl is untouched).
    printf '[]\n' > "${TMP_JSON}"
  fi
else
  # Empty — emit a valid empty-array JSON for downstream consumers.
  printf '[]\n' > "${TMP_JSON}"
fi

# Atomic rename: cleanup() will rm any leftover .tmp on unexpected exit, but
# on success these renames commit the final outputs.
mv -f -- "${TMP_JSONL}" "${OUT_JSONL}"
mv -f -- "${TMP_JSON}" "${OUT_JSON}"

# Clear the trap's tmp-file paths that we just renamed so cleanup() doesn't
# try to remove them (they're now the real outputs).
TMP_JSONL=""
TMP_JSON=""

# ---------------------------------------------------------------------------
# Exit.
# ---------------------------------------------------------------------------
if [ "${PARTIAL}" -eq 1 ]; then
  echo "github-audit-log: completed with partial failures (${TOTAL_EVENTS} events; see scan-errors.txt)"
  exit 2
fi

echo "github-audit-log: completed — ${TOTAL_EVENTS} event(s) across ${NUM_CHUNKS} chunk(s) (${WINDOW_START} .. ${TODAY})"
exit 0
