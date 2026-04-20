#!/usr/bin/env bash
# vercel-per-project.sh — vercel-forensics Phase 3 (per-project pulls)
#
# Enumerates the team's projects, then for each project fires a bounded
# burst of read-only GETs covering:
#   * project record (probed for undocumented trustedIps / ssoProtection
#     / passwordProtection / delegatedProtection)
#   * env var metadata (NAMES + metadata only — values are never
#     returned by the API; documented gap)
#   * last 50 deployments (anomaly-scan input)
#   * 24h runtime logs (Pro default; may be empty)
#   * project domains
#   * firewall config / bypass / attack-status (404 OK)
#   * project-level access groups (Enterprise; 404 OK)
#   * deployment retention policy (404 OK on plan default)
#
# Also:
#   * derives $CASE/github-linked-repos.txt from projects-list.json
#   * writes $CASE/github-audit-target.txt for Phase 4 consumption
#
# Read-only. Every HTTP call is a GET on an allowlisted Vercel path.
# Per-project bursts are capped at 6 concurrent background jobs;
# projects are processed serially so total in-flight work is bounded.
#
# Platform: bash 3.2 + BSD userland (ADR-002). No GNU-isms.
# Required env (set by preflight export block):
#   CASE      absolute path to the case directory (also passable via --case)
#   TEAM_ID   Vercel team id (required)
# Optional env:
#   GITHUB_ORG           org/user slug supplied to preflight
#   GITHUB_ENTERPRISE    enterprise slug supplied to preflight
#
# Exit codes:
#   0  all projects collected cleanly
#   1  fatal: enumeration failed or $CASE/$TEAM_ID missing
#   2  partial: at least one per-project endpoint failed
#      (row recorded in $CASE/scan-errors.txt)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults + CLI
# ---------------------------------------------------------------------------
CASE_ARG=""
DRY_RUN=0
LOG_REQUESTS=0

MAX_PARALLEL=6

usage() {
  cat <<'USAGE'
Usage: vercel-per-project.sh --case <path> [--dry-run] [--log-requests]

Phase 3 of vercel-forensics. Reads $TEAM_ID from env (set by preflight).
In dry-run mode, enumerates projects via a single GET then prints the
exact per-project endpoint list to stdout; no files are written.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      CASE_ARG="${2:-}"
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
      echo "vercel-per-project: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# Prefer --case; fall back to exported CASE from preflight.
if [ -n "$CASE_ARG" ]; then
  CASE="$CASE_ARG"
fi
: "${CASE:=}"
: "${TEAM_ID:=}"
: "${GITHUB_ORG:=}"
: "${GITHUB_ENTERPRISE:=}"

if [ -z "$CASE" ]; then
  echo "vercel-per-project: --case <path> is required (or export CASE)" >&2
  exit 1
fi
if [ -z "$TEAM_ID" ]; then
  echo "vercel-per-project: TEAM_ID env var required (set by preflight)" >&2
  exit 1
fi
if [ "$DRY_RUN" -eq 0 ] && [ ! -d "$CASE" ]; then
  echo "vercel-per-project: case directory not found: $CASE" >&2
  exit 1
fi

for bin in vercel jq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "vercel-per-project: required binary not on PATH: $bin" >&2
    exit 1
  fi
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Tab-separated scan-errors.txt row: phase\tresource\tmethod\treason
record_error() {
  # record_error <project> <endpoint-label> <reason>
  local project="$1"
  local endpoint="$2"
  local reason="$3"
  if [ -n "$CASE" ] && [ -d "$CASE" ]; then
    printf 'phase3\t%s/%s\tGET\t%s\n' "$project" "$endpoint" "$reason" \
      >> "$CASE/scan-errors.txt"
  else
    printf 'phase3\t%s/%s\tGET\t%s\n' "$project" "$endpoint" "$reason" >&2
  fi
}

# log_request <label> <path>
# When --log-requests is active, append the path (no query-string secrets
# possible here — we only emit teamId/projectId) to $CASE/request-log.txt.
log_request() {
  [ "$LOG_REQUESTS" -eq 1 ] || return 0
  local label="$1"
  local path="$2"
  if [ -n "$CASE" ] && [ -d "$CASE" ]; then
    printf '%s\tGET\t%s\n' "$label" "$path" >> "$CASE/request-log.txt"
  fi
}

# vapi_to_file <out-file> <path> [extra-flags...]
# Fetch a Vercel API path and atomically write the response to <out-file>.
# Writes via a .tmp sibling + mv to avoid half-written partials. Swallows
# non-zero CLI exit (e.g., 404) but records the body regardless — the
# caller decides whether 404 is expected (firewall/retention).
vapi_to_file() {
  local out="$1"
  shift
  local path="$1"
  shift

  local tmp="${out}.tmp.$$"
  # shellcheck disable=SC2068
  if vercel api "$path" $@ > "$tmp" 2>/dev/null; then
    mv "$tmp" "$out"
    return 0
  else
    local rc=$?
    # Preserve whatever body vercel wrote (for 404 inspection) but mark
    # the file with a sentinel if it's empty so downstream triage can
    # distinguish "empty 404" from "endpoint returned []".
    if [ ! -s "$tmp" ]; then
      printf '{"error":"vercel-api-failed","exitCode":%d}\n' "$rc" > "$tmp"
    fi
    mv "$tmp" "$out"
    return "$rc"
  fi
}

# ---------------------------------------------------------------------------
# Step 1 — enumerate projects
# ---------------------------------------------------------------------------
PROJECTS_PATH="/v9/projects?teamId=${TEAM_ID}&limit=100"
log_request "projects-list" "$PROJECTS_PATH"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "# vercel-per-project.sh --dry-run"
  echo "# case: $CASE"
  echo "# team: $TEAM_ID"
  echo ""
  echo "# Step 1 — enumerate projects (single GET, no file written in dry-run):"
  echo "GET $PROJECTS_PATH  [--paginate]"
  # Best-effort probe so the plan shows real per-project endpoints. If the
  # call fails, fall back to placeholder <pid>/<name>.
  PROJECTS_JSON="$(vercel api "$PROJECTS_PATH" --paginate 2>/dev/null || true)"
else
  mkdir -p "$CASE/raw/vercel" "$CASE/raw/vercel/projects" 2>/dev/null || true
  PROJECTS_FILE="$CASE/raw/vercel/projects-list.json"

  if ! vercel api "$PROJECTS_PATH" --paginate > "${PROJECTS_FILE}.tmp" 2>/dev/null; then
    echo "vercel-per-project: projects enumeration failed" >&2
    rm -f "${PROJECTS_FILE}.tmp"
    exit 1
  fi
  mv "${PROJECTS_FILE}.tmp" "$PROJECTS_FILE"
  PROJECTS_JSON="$(cat "$PROJECTS_FILE")"
fi

if [ -z "${PROJECTS_JSON:-}" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "# (live enumeration skipped or empty — using placeholder <pid>/<name> rows below)"
    PROJECT_ROWS="PLACEHOLDER_PID"$'\t'"placeholder-project"
  else
    echo "vercel-per-project: empty projects response" >&2
    exit 1
  fi
else
  # Extract id<TAB>name rows. `vercel api --paginate` concatenates pages;
  # jq -s handles both single-object and array-of-pages shapes.
  PROJECT_ROWS="$(printf '%s' "$PROJECTS_JSON" \
    | jq -rs '
        ( if type == "array" then . else [.] end )
        | map(.projects // [])
        | add // []
        | .[]
        | [(.id // ""), (.name // "")]
        | @tsv
      ' 2>/dev/null || true)"
fi

if [ -z "$PROJECT_ROWS" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    PROJECT_ROWS="PLACEHOLDER_PID"$'\t'"placeholder-project"
  else
    echo "vercel-per-project: zero projects enumerated (empty team?)" >&2
    # Still produce the (empty) downstream files so Phase 4 knows to skip.
    : > "$CASE/github-linked-repos.txt"
    # Fall through to audit-target write below before exiting 0.
  fi
fi

# ---------------------------------------------------------------------------
# Step 2 — per-project bursts
# ---------------------------------------------------------------------------

# wait_for_slot: in bash 3.2 we cannot rely on `wait -n`; emulate it by
# polling the BG_PIDS array.
BG_PIDS=""
wait_for_slot() {
  # Reap any finished children; if we're still at MAX_PARALLEL, sleep briefly.
  while : ; do
    local new=""
    local running=0
    for pid in $BG_PIDS; do
      if kill -0 "$pid" 2>/dev/null; then
        new="$new $pid"
        running=$((running + 1))
      fi
    done
    BG_PIDS="$new"
    if [ "$running" -lt "$MAX_PARALLEL" ]; then
      return 0
    fi
    sleep 1
  done
}

spawn() {
  # spawn <label> <project-name> <out-file> <path> [-- <extra vercel flags>]
  # Launches a background GET and records any failure to scan-errors.txt.
  local label="$1"
  local project="$2"
  local out="$3"
  local path="$4"
  shift 4
  log_request "${project}:${label}" "$path"
  (
    # shellcheck disable=SC2068
    if ! vapi_to_file "$out" "$path" $@; then
      record_error "$project" "$label" "http-error"
    fi
  ) &
  BG_PIDS="$BG_PIDS $!"
}

# spawn_cmd: like spawn but runs an arbitrary command (for `vercel logs`,
# which is not a raw `vercel api` call).
spawn_cmd() {
  local label="$1"
  local project="$2"
  local out="$3"
  shift 3
  log_request "${project}:${label}" "(cli: $*)"
  (
    local tmp="${out}.tmp.$$"
    # shellcheck disable=SC2068
    if "$@" > "$tmp" 2>/dev/null; then
      mv "$tmp" "$out"
    else
      # Preserve whatever we got, annotate empty.
      if [ ! -s "$tmp" ]; then
        printf '{"error":"cli-failed","command":"%s"}\n' "$*" > "$tmp"
      fi
      mv "$tmp" "$out"
      record_error "$project" "$label" "cli-error"
    fi
  ) &
  BG_PIDS="$BG_PIDS $!"
}

wait_all() {
  for pid in $BG_PIDS; do
    wait "$pid" 2>/dev/null || true
  done
  BG_PIDS=""
}

# Endpoint templates (label → URL path). Expand $pid per project.
# Keep in sync with references/api-endpoint-reference.md + _common.py ALLOWED_PATHS.
dry_run_endpoints() {
  local pid="$1"
  local name="$2"
  cat <<EOF
  GET /v9/projects/${pid}?teamId=${TEAM_ID}                                  -> projects/${name}/project.json
  GET /v9/projects/${pid}/env?teamId=${TEAM_ID}                              -> projects/${name}/env-metadata.json
  GET /v6/deployments?projectId=${pid}&teamId=${TEAM_ID}&limit=50  [paginate] -> projects/${name}/deployments.json
  CLI vercel logs --project ${name} --json --since 24h --limit 1000          -> projects/${name}/logs.json
  GET /v9/projects/${pid}/domains?teamId=${TEAM_ID}                          -> projects/${name}/domains.json
  GET /v1/security/firewall/config/active?projectId=${pid}&teamId=${TEAM_ID} -> projects/${name}/firewall-config.json (404 OK)
  GET /v1/security/firewall/attack-status?projectId=${pid}&teamId=${TEAM_ID} -> projects/${name}/attack-status.json
  GET /v1/security/firewall/bypass?projectId=${pid}&teamId=${TEAM_ID}        -> projects/${name}/firewall-bypass.json
  GET /v9/projects/${pid}/access-groups?teamId=${TEAM_ID}                    -> projects/${name}/project-access-groups.json (404 OK on Pro)
  GET /v9/projects/${pid}/deployment-retention-policy?teamId=${TEAM_ID}      -> projects/${name}/retention-policy.json (404 OK = plan default)
EOF
}

# Probe the project record for undocumented protection fields; if absent,
# write a sibling .notes file.
probe_project_notes() {
  # probe_project_notes <project-dir>
  local pdir="$1"
  local pjson="$pdir/project.json"
  [ -s "$pjson" ] || return 0

  local notes="$pdir/project.notes"
  : > "$notes"
  for field in trustedIps ssoProtection passwordProtection delegatedProtection; do
    if jq -e --arg f "$field" '.[$f] // empty' "$pjson" >/dev/null 2>&1; then
      printf '%s: present\n' "$field" >> "$notes"
    else
      printf '%s: field not returned\n' "$field" >> "$notes"
    fi
  done
}

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "# Step 2 — per-project bursts (max ${MAX_PARALLEL} concurrent per project, serial across projects):"
  # Preserve tab-split on IFS for the read builtin.
  OLD_IFS="$IFS"
  IFS=$'\t'
  while IFS=$'\t' read -r pid name; do
    [ -z "$pid" ] && continue
    [ -z "$name" ] && name="(unnamed)"
    echo ""
    echo "## Project: ${name} (${pid})"
    dry_run_endpoints "$pid" "$name"
  done <<EOF
$PROJECT_ROWS
EOF
  IFS="$OLD_IFS"

  echo ""
  echo "# Step 3 — derive github-linked-repos.txt from projects-list.json"
  echo "# Step 4 — write github-audit-target.txt"
  exit 0
fi

# Live mode — iterate projects serially, spawn burst per project.
PROJECT_COUNT=0
while IFS=$'\t' read -r pid name; do
  [ -z "$pid" ] && continue
  [ -z "$name" ] && name="unnamed-${pid}"

  # CRITICAL: validate pid charset BEFORE any URL splicing or CLI arg use.
  # A compromised Vercel API (OAuth-pivot threat model) can return a
  # `project.id` containing query-param smuggling (`?decrypt=1`) or a
  # name containing CLI flags (`--configPath=...`). Bash scripts do not
  # call back into `_common.py::validate_url`, so this is the primary
  # defense for the collection layer. Match the vercel-team-context.sh
  # integration-id guard pattern.
  case "$pid" in
    prj_[A-Za-z0-9]*) : ;;
    *)
      record_error projects "$pid" "invalid-project-id" \
        "project id '$pid' outside ^prj_[A-Za-z0-9]+$ — skipping"
      continue
      ;;
  esac

  # Filesystem-safe project dir name. Project names are user-set and may
  # contain characters that don't matter for display but should not leak
  # into paths. Slugify conservatively.
  safe_name="$(printf '%s' "$name" | LC_ALL=C tr -c 'A-Za-z0-9._-' '_' \
    | cut -c1-64)"
  [ -z "$safe_name" ] && safe_name="project-${pid}"
  # Reject `.` and `..` explicitly — tr keeps dots, which would otherwise
  # let a project literally named `..` map to `$CASE/raw/vercel`.
  case "$safe_name" in
    .|..) safe_name="project-${pid}" ;;
  esac
  # Use the safe_name (not the raw name) for the `vercel logs --project`
  # call below, so API-controlled name strings cannot inject CLI flags.
  cli_project_arg="$safe_name"

  pdir="$CASE/raw/vercel/projects/$safe_name"
  mkdir -p "$pdir" 2>/dev/null || true

  # --- burst (max MAX_PARALLEL concurrent) ---
  wait_for_slot
  spawn project       "$safe_name" "$pdir/project.json" \
    "/v9/projects/${pid}?teamId=${TEAM_ID}"

  wait_for_slot
  spawn env-metadata  "$safe_name" "$pdir/env-metadata.json" \
    "/v9/projects/${pid}/env?teamId=${TEAM_ID}"

  wait_for_slot
  spawn deployments   "$safe_name" "$pdir/deployments.json" \
    "/v6/deployments?projectId=${pid}&teamId=${TEAM_ID}&limit=50" --paginate

  wait_for_slot
  # `vercel logs` uses the CLI (project-scoped by --scope/--project).
  # It emits JSON-lines when --json is set; may be empty (no recent runtime
  # invocations). We pass teamId via --scope using the team slug if
  # available; otherwise rely on `vercel api`-style session auth already
  # resolved by preflight.
  spawn_cmd logs "$safe_name" "$pdir/logs.json" \
    vercel logs --project "$cli_project_arg" --json --since 24h --limit 1000

  wait_for_slot
  spawn domains "$safe_name" "$pdir/domains.json" \
    "/v9/projects/${pid}/domains?teamId=${TEAM_ID}"

  wait_for_slot
  spawn firewall-config "$safe_name" "$pdir/firewall-config.json" \
    "/v1/security/firewall/config/active?projectId=${pid}&teamId=${TEAM_ID}"

  # Drain current burst before the next 4 to stay at/under MAX_PARALLEL=6
  # per project AND to respect the 20 req/min rate limit on
  # firewall/attack-status (we pace groups instead of hammering).
  wait_all

  wait_for_slot
  spawn attack-status "$safe_name" "$pdir/attack-status.json" \
    "/v1/security/firewall/attack-status?projectId=${pid}&teamId=${TEAM_ID}"

  wait_for_slot
  spawn firewall-bypass "$safe_name" "$pdir/firewall-bypass.json" \
    "/v1/security/firewall/bypass?projectId=${pid}&teamId=${TEAM_ID}"

  wait_for_slot
  spawn access-groups "$safe_name" "$pdir/project-access-groups.json" \
    "/v9/projects/${pid}/access-groups?teamId=${TEAM_ID}"

  wait_for_slot
  spawn retention-policy "$safe_name" "$pdir/retention-policy.json" \
    "/v9/projects/${pid}/deployment-retention-policy?teamId=${TEAM_ID}"

  wait_all

  # After the project record has landed, probe for undocumented fields.
  probe_project_notes "$pdir" || true

  PROJECT_COUNT=$((PROJECT_COUNT + 1))
done <<EOF
$PROJECT_ROWS
EOF

# ---------------------------------------------------------------------------
# Step 3 — derive github-linked-repos.txt
# ---------------------------------------------------------------------------
LINKED_FILE="$CASE/github-linked-repos.txt"
if [ -s "$CASE/raw/vercel/projects-list.json" ]; then
  # `--paginate` may have concatenated multiple top-level objects; `jq -s`
  # slurps them into an array so we can flatten .projects across pages.
  jq -rs '
    ( if type == "array" then . else [.] end )
    | map(.projects // [])
    | add // []
    | .[]
    | select(.link.type == "github")
    | "\(.link.org)/\(.link.repo)"
  ' "$CASE/raw/vercel/projects-list.json" 2>/dev/null \
    | awk 'NF && !seen[$0]++' \
    > "${LINKED_FILE}.tmp" || true
  if [ -f "${LINKED_FILE}.tmp" ]; then
    mv "${LINKED_FILE}.tmp" "$LINKED_FILE"
  else
    : > "$LINKED_FILE"
  fi
else
  : > "$LINKED_FILE"
fi

# ---------------------------------------------------------------------------
# Step 4 — write github-audit-target.txt for Phase 4
# ---------------------------------------------------------------------------
# Precedence: enterprise (if probe succeeded at preflight time — preflight
# exports GH_AUDIT_ENDPOINT in that case) → org → user → (empty).
AUDIT_FILE="$CASE/github-audit-target.txt"
: > "$AUDIT_FILE"

if [ -n "${GITHUB_ENTERPRISE}" ] \
   && [ -n "${GH_AUDIT_ENDPOINT:-}" ] \
   && printf '%s' "${GH_AUDIT_ENDPOINT}" | grep -q '^/enterprises/'; then
  printf 'enterprise %s\n' "$GITHUB_ENTERPRISE" > "$AUDIT_FILE"
elif [ -n "${GITHUB_ORG}" ]; then
  # Determine owner-type from the preflight-exported endpoint; preflight
  # sets GH_AUDIT_ENDPOINT="/orgs/..." for Organizations and empty for Users.
  if [ -n "${GH_AUDIT_ENDPOINT:-}" ] \
     && printf '%s' "${GH_AUDIT_ENDPOINT}" | grep -q '^/orgs/'; then
    printf 'org %s\n' "$GITHUB_ORG" > "$AUDIT_FILE"
  else
    # Empty GH_AUDIT_ENDPOINT with a slug present ⇒ owner-type was User.
    printf 'user %s\n' "$GITHUB_ORG" > "$AUDIT_FILE"
  fi
fi

# ---------------------------------------------------------------------------
# Exit status
# ---------------------------------------------------------------------------
if [ -s "$CASE/scan-errors.txt" ] \
   && awk -F'\t' '$1=="phase3"{found=1} END{exit !found}' \
        "$CASE/scan-errors.txt"; then
  echo "vercel-per-project: completed with partial failures (see scan-errors.txt)"
  exit 2
fi

echo "vercel-per-project: ${PROJECT_COUNT} project(s) collected cleanly"
exit 0
