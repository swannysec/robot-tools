#!/usr/bin/env bash
# github-repo-graphql.sh — vercel-forensics Phase 4 per-repo GraphQL pull.
#
# Issues ONE GraphQL query per repo that batches the confirmed-schema fields:
#
#   repository(owner:$owner, name:$name) {
#     isArchived
#     pushedAt
#     visibility
#     defaultBranchRef {
#       name
#       branchProtectionRule {
#         allowsDeletions
#         allowsForcePushes
#         dismissesStaleReviews
#         isAdminEnforced
#         requiresApprovingReviews
#         requiredApprovingReviewCount
#         requiresCodeOwnerReviews
#         requiresConversationResolution
#         requiresLinearHistory
#         requiresStatusChecks
#         requiresStrictStatusChecks
#         restrictsPushes
#         restrictsReviewDismissals
#       }
#     }
#     deployKeys(first: 25, after: $cursor) {
#       pageInfo { endCursor hasNextPage }
#       nodes { id title readOnly createdAt verified }
#     }
#   }
#
# NOTE — webhooks are NOT queried here. The `webhooks` connection is NOT in
# the confirmed GitHub GraphQL schema per the plan; webhooks must be pulled
# via REST (`GET /repos/:o/:r/hooks`) in a separate pass. A companion REST
# puller (github-audit-log.sh or a dedicated webhook puller) is responsible.
#
# gh api graphql does NOT auto-paginate (see references/vercel-cli-quirks.md
# §7) — deployKeys cursor is hand-rolled via pageInfo.endCursor/hasNextPage.
# first:25 keeps per-query cost at ~30 points against the 5000 points/hr
# budget; a repo with ≤25 deploy keys is one query, more keys add one query
# per extra page.
#
# Output:
#   $CASE/raw/github/repos/<owner>__<name>/metadata.json
#     Single JSON object. If deployKeys paginated, the `deployKeys.nodes`
#     array contains the union of all pages and `deployKeys.pageInfo` holds
#     the final page's cursor state (hasNextPage=false on completion).
#
# Platform: bash 3.2 + BSD userland (ADR-002). No GNU-isms.
# Requires: gh, jq. GH_TOKEN / gh auth already established by preflight.sh.
#
# Exit codes:
#   0  success
#   1  fatal (bad args, missing env, missing $CASE layout, missing binaries)
#   2  repo inaccessible (404/403) or query error — row written to
#      $CASE/scan-errors.txt (schema: phase4\t<repo>\tgraphql\t<reason>)

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants + arg defaults
# ---------------------------------------------------------------------------
CASE=""
REPO=""
DRY_RUN=0
LOG_REQUESTS=0

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
  cat >&2 <<'EOF'
Usage: github-repo-graphql.sh --case <path> --repo <owner/name> [--dry-run] [--log-requests]

Phase 4 per-repo GraphQL pull for vercel-forensics.

  --case <path>         Absolute path to the case directory (from preflight.sh).
  --repo <owner/name>   Single GitHub repo (owner/name form; no URL, no .git).
  --dry-run             Emit the GraphQL query + resolved variables to stdout;
                        write no files; exit 0.
  --log-requests        Echo redacted request lines to stderr.

Exit codes:
  0  success
  1  fatal (bad args, missing env, missing $CASE layout)
  2  repo inaccessible (404/403) or query error — see $CASE/scan-errors.txt
EOF
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      if [ "$#" -lt 2 ]; then
        echo "github-repo-graphql: --case requires a value" >&2
        usage
        exit 1
      fi
      CASE="$2"
      shift 2
      ;;
    --repo)
      if [ "$#" -lt 2 ]; then
        echo "github-repo-graphql: --repo requires a value" >&2
        usage
        exit 1
      fi
      REPO="$2"
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
      echo "github-repo-graphql: unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [ -z "$CASE" ]; then
  echo "github-repo-graphql: --case <path> is required" >&2
  usage
  exit 1
fi

if [ -z "$REPO" ]; then
  echo "github-repo-graphql: --repo <owner/name> is required" >&2
  usage
  exit 1
fi

# ---------------------------------------------------------------------------
# Validate --repo — exactly one slash, safe charset per GitHub rules.
# Owner: alphanumeric + single hyphen (not leading/trailing), ≤39 chars.
# Repo:  alphanumeric + `._-`, ≤100 chars.
# We intentionally use a permissive-but-bounded regex — preflight already
# enforces tighter rules on operator input; this is defense-in-depth so a
# malformed value cannot slip a shell-metachar into the GraphQL variables.
# ---------------------------------------------------------------------------
case "$REPO" in
  */*/*|'')
    echo "github-repo-graphql: invalid --repo (expect owner/name): $REPO" >&2
    exit 1
    ;;
  */*)
    :
    ;;
  *)
    echo "github-repo-graphql: invalid --repo (expect owner/name): $REPO" >&2
    exit 1
    ;;
esac

OWNER="${REPO%%/*}"
NAME="${REPO##*/}"

if [ -z "$OWNER" ] || [ -z "$NAME" ]; then
  echo "github-repo-graphql: invalid --repo (empty owner or name): $REPO" >&2
  exit 1
fi

# Charset check — reject anything outside [A-Za-z0-9._-]. Upper bound length
# is a sanity ceiling, not a GitHub-spec match.
_check_ident() {
  local label="$1"
  local value="$2"
  local max="$3"
  local len=${#value}
  if [ "$len" -lt 1 ] || [ "$len" -gt "$max" ]; then
    echo "github-repo-graphql: --repo $label length out of range (1..$max): $value" >&2
    exit 1
  fi
  case "$value" in
    *[!A-Za-z0-9._-]*)
      echo "github-repo-graphql: --repo $label has invalid character: $value" >&2
      exit 1
      ;;
  esac
}
_check_ident "owner" "$OWNER" 39
_check_ident "name"  "$NAME"  100

# ---------------------------------------------------------------------------
# Required-binary check
# ---------------------------------------------------------------------------
for bin in gh jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "github-repo-graphql: required binary not on PATH: $bin" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Layout: $CASE/raw/github/repos/<owner>__<name>/metadata.json
# The double-underscore join keeps the dir name filesystem-safe (no slash)
# and stable for the freeze manifest — <owner>/<name> would collide with
# the `raw/github/repos/` path separator on case-insensitive FS.
# ---------------------------------------------------------------------------
REPO_DIR="$CASE/raw/github/repos/${OWNER}__${NAME}"
OUT_PATH="$REPO_DIR/metadata.json"
SCAN_ERRORS="$CASE/scan-errors.txt"

if [ "$DRY_RUN" -eq 0 ]; then
  if [ ! -d "$CASE" ]; then
    echo "github-repo-graphql: case dir does not exist: $CASE" >&2
    exit 1
  fi
  mkdir -p "$REPO_DIR"
  chmod 0700 "$REPO_DIR" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Record-error helper (Phase 4 schema)
# ---------------------------------------------------------------------------
record_error() {
  # record_error <reason>
  # Appends one row to $CASE/scan-errors.txt.
  # Schema (from plan): phase4\t<repo>\tgraphql\t<reason>
  local reason="$1"
  if [ "$DRY_RUN" -eq 1 ]; then
    return 0
  fi
  printf 'phase4\t%s\tgraphql\t%s\n' "$REPO" "$reason" >> "$SCAN_ERRORS" || true
}

# ---------------------------------------------------------------------------
# Log-request helper (stderr only; never writes)
# ---------------------------------------------------------------------------
log_request_line() {
  if [ "$LOG_REQUESTS" -eq 0 ]; then
    return 0
  fi
  # Cursor value is not a secret, but keep the line shape consistent with
  # other scripts — `POST https://api.github.com/graphql repo=<owner/name>`.
  printf 'POST https://api.github.com/graphql repo=%s cursor=%s\n' "$REPO" "${1:-<initial>}" >&2
}

# ---------------------------------------------------------------------------
# GraphQL query text — single source of truth.
#
# Variables:
#   $owner  String!   Repo owner login
#   $name   String!   Repo name
#   $cursor String    deployKeys page cursor (null on first page)
#
# Per-query budget ~30 points:
#   - repository lookup:            1
#   - scalars (isArchived etc):     0 (included in parent)
#   - defaultBranchRef:             1
#   - branchProtectionRule scalars: 0
#   - deployKeys(first:25):         1 + up to 25 node fetches (~2 per node
#                                   worst-case for linked objects)
# Total well under the 5000 points/hour ceiling even if pagination runs.
# ---------------------------------------------------------------------------
read -r -d '' QUERY <<'GRAPHQL' || true
query RepoForensics($owner: String!, $name: String!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    isArchived
    pushedAt
    visibility
    defaultBranchRef {
      name
      branchProtectionRule {
        allowsDeletions
        allowsForcePushes
        dismissesStaleReviews
        isAdminEnforced
        requiresApprovingReviews
        requiredApprovingReviewCount
        requiresCodeOwnerReviews
        requiresConversationResolution
        requiresLinearHistory
        requiresStatusChecks
        requiresStrictStatusChecks
        restrictsPushes
        restrictsReviewDismissals
      }
    }
    deployKeys(first: 25, after: $cursor) {
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        id
        title
        readOnly
        createdAt
        verified
      }
    }
  }
}
GRAPHQL

# ===========================================================================
# DRY-RUN MODE
# ===========================================================================
if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
# GraphQL query (github-repo-graphql.sh dry-run)
# Endpoint: POST https://api.github.com/graphql (via \`gh api graphql\`)
# Variables:
#   owner=${OWNER}
#   name=${NAME}
#   cursor=<null on first page; hand-rolled after that>
# Output (live mode): ${OUT_PATH}
# Webhooks NOT queried here — pulled via REST in companion script.
#
${QUERY}
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Paginator — hand-rolled cursor loop (gh api graphql does NOT auto-paginate).
#
# Strategy:
#   1. First page: cursor empty, pass as explicit null via -F cursor=...
#      (gh converts the literal string "null" as a string, not JSON null).
#      Using `-F` with a variable reference is the gh-supported form; for
#      the null sentinel we instead call without `-F cursor=` on page 1 —
#      the GraphQL `String` typed variable will default to null when the
#      variable is omitted from the variables map.
#   2. Subsequent pages: pass the endCursor string via -F cursor="$CURSOR".
#   3. Accumulate nodes into a jq-merged JSON object rebuilt at the end.
#
# On any gh non-zero exit or GraphQL `errors[]` array, record a scan-error
# row and exit 2. The metadata.json file is only written on full success
# (all pages). Partial pagination is treated as failure — incomplete
# evidence is worse than a recorded gap the analyst can re-pull.
# ---------------------------------------------------------------------------

TMP_DIR="$(mktemp -d -t vf-ghgql.XXXXXX)"
# Bash 3.2 trap-based cleanup; subshells cannot mutate parent TMP_DIR.
trap 'rm -rf "$TMP_DIR"' EXIT

# First-page response is the scaffold we mutate (deployKeys.nodes extended,
# deployKeys.pageInfo overwritten with each subsequent page's pageInfo).
FIRST_PAGE="$TMP_DIR/page-0.json"
MERGED="$TMP_DIR/merged.json"

log_request_line ""

if ! gh api graphql \
      -F owner="$OWNER" \
      -F name="$NAME" \
      -f query="$QUERY" \
      >"$FIRST_PAGE" 2>"$TMP_DIR/err-0.txt"; then
  # Extract an identifiable reason — HTTP status line or first stderr line.
  reason="$(awk 'NR==1 {print; exit}' "$TMP_DIR/err-0.txt" 2>/dev/null || true)"
  if [ -z "$reason" ]; then
    reason="gh-api-nonzero"
  fi
  # Normalize common cases the plan cares about (404, 403).
  case "$reason" in
    *"HTTP 404"*|*"404 Not Found"*|*"Could not resolve to a Repository"*)
      reason="404"
      ;;
    *"HTTP 403"*|*"403 Forbidden"*|*"Resource not accessible"*)
      reason="403"
      ;;
  esac
  record_error "$reason"
  exit 2
fi

# GraphQL returns 200 even on logical errors — inspect `.errors` array.
if jq -e '.errors and (.errors | length > 0)' "$FIRST_PAGE" >/dev/null 2>&1; then
  err_type="$(jq -r '.errors[0].type // "UNKNOWN"' "$FIRST_PAGE" 2>/dev/null || echo "UNKNOWN")"
  case "$err_type" in
    NOT_FOUND) reason="404" ;;
    FORBIDDEN) reason="403" ;;
    *)         reason="graphql-error:${err_type}" ;;
  esac
  record_error "$reason"
  exit 2
fi

# Defensive: `.data.repository` must exist — otherwise the repo is silently
# unreachable (happens when a token can authenticate but lacks Metadata
# read on that specific repo — rare on fine-grained PATs).
if ! jq -e '.data.repository' "$FIRST_PAGE" >/dev/null 2>&1; then
  record_error "repository-null"
  exit 2
fi

cp "$FIRST_PAGE" "$MERGED"

HAS_NEXT="$(jq -r '.data.repository.deployKeys.pageInfo.hasNextPage // false' "$MERGED" 2>/dev/null || echo false)"
CURSOR="$(jq -r '.data.repository.deployKeys.pageInfo.endCursor // empty' "$MERGED" 2>/dev/null || echo "")"

PAGE_IDX=1
# Ceiling: 25 nodes * 100 pages = 2500 deploy keys. Real repos have ≤10.
# This is a runaway-prevention belt rather than a real limit.
MAX_PAGES=100

while [ "$HAS_NEXT" = "true" ]; do
  if [ "$PAGE_IDX" -ge "$MAX_PAGES" ]; then
    record_error "deploy-keys-pagination-runaway"
    exit 2
  fi
  if [ -z "$CURSOR" ]; then
    record_error "deploy-keys-pagination-missing-cursor"
    exit 2
  fi

  PAGE_FILE="$TMP_DIR/page-${PAGE_IDX}.json"
  PAGE_ERR="$TMP_DIR/err-${PAGE_IDX}.txt"

  log_request_line "$CURSOR"

  if ! gh api graphql \
        -F owner="$OWNER" \
        -F name="$NAME" \
        -F cursor="$CURSOR" \
        -f query="$QUERY" \
        >"$PAGE_FILE" 2>"$PAGE_ERR"; then
    reason="$(awk 'NR==1 {print; exit}' "$PAGE_ERR" 2>/dev/null || true)"
    if [ -z "$reason" ]; then
      reason="gh-api-nonzero-page${PAGE_IDX}"
    fi
    record_error "$reason"
    exit 2
  fi

  if jq -e '.errors and (.errors | length > 0)' "$PAGE_FILE" >/dev/null 2>&1; then
    err_type="$(jq -r '.errors[0].type // "UNKNOWN"' "$PAGE_FILE" 2>/dev/null || echo "UNKNOWN")"
    record_error "graphql-error-page${PAGE_IDX}:${err_type}"
    exit 2
  fi

  # Merge: append this page's nodes, overwrite pageInfo. Both merged and
  # page files are jq-validated above.
  MERGED_NEXT="$TMP_DIR/merged-${PAGE_IDX}.json"
  if ! jq -n \
        --slurpfile base "$MERGED" \
        --slurpfile page "$PAGE_FILE" \
        '
          $base[0] as $b
          | $page[0] as $p
          | $b
          | .data.repository.deployKeys.nodes =
              (($b.data.repository.deployKeys.nodes // [])
               + ($p.data.repository.deployKeys.nodes // []))
          | .data.repository.deployKeys.pageInfo =
              ($p.data.repository.deployKeys.pageInfo // $b.data.repository.deployKeys.pageInfo)
        ' \
        >"$MERGED_NEXT" 2>"$TMP_DIR/merge-err-${PAGE_IDX}.txt"; then
    record_error "jq-merge-failed-page${PAGE_IDX}"
    exit 2
  fi
  mv "$MERGED_NEXT" "$MERGED"

  HAS_NEXT="$(jq -r '.data.repository.deployKeys.pageInfo.hasNextPage // false' "$MERGED" 2>/dev/null || echo false)"
  CURSOR="$(jq -r '.data.repository.deployKeys.pageInfo.endCursor // empty' "$MERGED" 2>/dev/null || echo "")"
  PAGE_IDX=$((PAGE_IDX + 1))
done

# ---------------------------------------------------------------------------
# Atomic write: tmp + rename. Refuse overwrite — Phase 4 should write each
# metadata.json exactly once per run. This matches vercel-team-context.sh's
# _atomic_install semantics and _common.py::atomic_write for the
# cross-process case.
# ---------------------------------------------------------------------------
if [ -e "$OUT_PATH" ]; then
  record_error "output-exists:$OUT_PATH"
  exit 2
fi

OUT_TMP="$OUT_PATH.tmp"
# Validate once more before committing.
if ! jq -e . "$MERGED" >/dev/null 2>&1; then
  record_error "merged-non-json"
  exit 2
fi

cp "$MERGED" "$OUT_TMP"
chmod 0600 "$OUT_TMP" 2>/dev/null || true
mv "$OUT_TMP" "$OUT_PATH"

exit 0
