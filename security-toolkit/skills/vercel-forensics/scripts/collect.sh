#!/usr/bin/env bash
# collect.sh — vercel-forensics Phase 0-5 orchestrator.
#
# Read-only. NEVER invokes any mutation verb on any API. All HTTP calls
# happen inside the sub-scripts in this directory; this file only sequences
# them, enforces per-phase idle-progress watchdogs (ADR-004), records
# partial failures to $CASE/scan-errors.txt, and returns a compound exit
# code (0 clean / 1 fatal / 2 partial).
#
# Platform: bash 3.2 + BSD userland (ADR-002). No GNU-isms: `date +%s`
# instead of $EPOCHSECONDS, no `timeout`, no `gtimeout`.
#
# Sub-scripts invoked (all in the same dir as this file):
#   preflight.sh              Phase 0 — auth/tier/owner-type; writes $CASE dir layout
#   activity-paginate.sh      Phase 1 — /v3/events team-wide activity log
#   vercel-team-context.sh    Phase 2 — team, members, drains, integrations, domains, ...
#   vercel-per-project.sh     Phase 3 — per-project deployments, env metadata, logs, ...
#   github-repo-graphql.sh    Phase 4a — per-repo metadata (invoked once per linked repo)
#   github-audit-log.sh       Phase 4b — /orgs/:org/audit-log or /enterprises/:ent/audit-log
#   vercel-build-logs.sh      Phase 5 — build events for incident-window deployments
#
# Each sub-script supports `--dry-run` (prints planned endpoints to stdout,
# no HTTP calls). This orchestrator captures those into
# `$CASE/DRY-RUN-PLAN.md`.

set -euo pipefail

# ---------------------------------------------------------------------------
# Locate companion scripts (same directory as this file)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NO_GITHUB=0
DRY_RUN=0
LOG_REQUESTS=0
TEAM_SLUG=""
GITHUB_ORG=""
GITHUB_ENTERPRISE=""
INCIDENT_WINDOW=""          # ISO-8601 timestamp; empty -> default 24h-ago (set below)

IDLE_LIMIT=600              # 10-min per-phase idle-progress watchdog (seconds)

# Exit code accumulator: 0 clean, 2 partial. 1 only set for fatal-start paths.
RUN_STATUS=0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
PASSTHRU_ARGS=()            # bash array for preflight + sub-script pass-through

usage() {
  cat <<'USAGE'
Usage: collect.sh [--team <slug>] [--github-org <slug>] [--github-enterprise <slug>]
                  [--incident-window <ISO-timestamp>]
                  [--no-github] [--dry-run] [--log-requests]

Preservation-first Phase 0-5 collection orchestrator for the
vercel-forensics skill. Read-only; no mutations.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-github)
      NO_GITHUB=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --log-requests)
      LOG_REQUESTS=1
      shift
      ;;
    --team)
      TEAM_SLUG="${2:-}"
      shift 2
      ;;
    --github-org)
      GITHUB_ORG="${2:-}"
      shift 2
      ;;
    --github-enterprise)
      GITHUB_ENTERPRISE="${2:-}"
      shift 2
      ;;
    --incident-window)
      INCIDENT_WINDOW="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "collect.sh: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# Default incident window = 24h ago (UTC, ISO-8601). BSD date syntax.
if [ -z "$INCIDENT_WINDOW" ]; then
  INCIDENT_WINDOW="$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)"
fi

# ---------------------------------------------------------------------------
# Helper: re-build the arg list that sub-scripts need to inherit.
# preflight.sh accepts the same --team/--github-org/--github-enterprise flags
# (plus --dry-run and --log-requests). Passing through verbatim keeps one
# source of truth for slug validation inside preflight.
# ---------------------------------------------------------------------------
build_passthru_args() {
  # Bash 3.2 supports arrays; use one here to preserve arg boundaries and
  # avoid the word-split trap if a slug regex is ever loosened to allow
  # whitespace. Each element is a single argv slot.
  PASSTHRU_ARGS=()
  if [ -n "$TEAM_SLUG" ]; then
    PASSTHRU_ARGS+=(--team "$TEAM_SLUG")
  fi
  if [ -n "$GITHUB_ORG" ]; then
    PASSTHRU_ARGS+=(--github-org "$GITHUB_ORG")
  fi
  if [ -n "$GITHUB_ENTERPRISE" ]; then
    PASSTHRU_ARGS+=(--github-enterprise "$GITHUB_ENTERPRISE")
  fi
  if [ "$LOG_REQUESTS" -eq 1 ]; then
    PASSTHRU_ARGS+=(--log-requests)
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    PASSTHRU_ARGS+=(--dry-run)
  fi
}
build_passthru_args

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
banner() {
  echo ""
  echo "=== $1 ==="
}

record_error() {
  # record_error <phase> <resource> <stage> <reason>
  # Schema: tab-separated, append to $CASE/scan-errors.txt.
  local phase="$1"
  local resource="$2"
  local stage="$3"
  local reason="$4"
  if [ -n "${CASE:-}" ] && [ -d "$CASE" ]; then
    printf '%s\t%s\t%s\t%s\n' "$phase" "$resource" "$stage" "$reason" \
      >> "$CASE/scan-errors.txt"
  else
    printf 'scan-error (no CASE dir): %s\t%s\t%s\t%s\n' \
      "$phase" "$resource" "$stage" "$reason" >&2
  fi
  RUN_STATUS=2
}

phase_ok() {
  echo "$1 OK"
}

phase_fail() {
  # phase_fail <name> <reason>
  echo "$1 FAIL (reason: $2)"
}

# ---------------------------------------------------------------------------
# Watchdog-wrapped phase runner (ADR-004 portable timeout pattern).
#
# run_phase <phase-name> <command...>
#   - Runs the command in the background, streams its stdout/stderr live.
#   - A watchdog subshell monitors <stamp-file> mtime; if no progress for
#     IDLE_LIMIT seconds, it kills the command.
#   - Progress is defined as "the sub-script emitted a line to stdout or
#     stderr" — we tee output through a line-reader that touches <stamp>.
#   - Returns the command's exit status, or 124 on watchdog kill.
# ---------------------------------------------------------------------------
run_phase() {
  local phase_name="$1"
  shift

  local stamp
  stamp="$(mktemp -t vf-stamp.XXXXXX)"
  # Initial mark: "now"
  : > "$stamp"

  # FIFO for the child's output so we can both tee to the tty and update stamp.
  local fifo_dir
  fifo_dir="$(mktemp -d -t vf-fifo.XXXXXX)"
  local fifo="$fifo_dir/out"
  mkfifo "$fifo"

  # Reader: for each line, touch stamp, echo to stdout.
  (
    while IFS= read -r line; do
      # Touch stamp (mtime = now) — BSD + GNU touch both support no-flags form.
      : > "$stamp"
      printf '%s\n' "$line"
    done < "$fifo"
  ) &
  local reader_pid=$!

  # Child: run the actual sub-script, both streams into the FIFO.
  (
    "$@" 2>&1
  ) > "$fifo" &
  local child_pid=$!

  # Watchdog: every 15s, check age of stamp; kill child if it exceeds
  # IDLE_LIMIT. Exits cleanly on TERM from the parent.
  (
    trap 'exit 0' TERM
    while kill -0 "$child_pid" 2>/dev/null; do
      sleep 15
      if ! kill -0 "$child_pid" 2>/dev/null; then
        break
      fi
      local now last age
      now=$(date +%s)
      # stat -f %m : BSD; stat -c %Y : GNU. ADR-002 requires BSD.
      last=$(stat -f %m "$stamp" 2>/dev/null || echo "$now")
      age=$((now - last))
      if [ "$age" -ge "$IDLE_LIMIT" ]; then
        kill -TERM "$child_pid" 2>/dev/null || true
        sleep 2
        kill -KILL "$child_pid" 2>/dev/null || true
        exit 124
      fi
    done
  ) &
  local watchdog_pid=$!

  # Wait for the child. `wait` preserves the child's exit status.
  local child_status=0
  if wait "$child_pid"; then
    child_status=0
  else
    child_status=$?
  fi

  # Tear down watchdog.
  if kill -0 "$watchdog_pid" 2>/dev/null; then
    kill -TERM "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
  fi

  # Close the reader: closing the FIFO writer end happens automatically
  # when the child exits; the reader will then see EOF.
  wait "$reader_pid" 2>/dev/null || true

  rm -f "$fifo"
  rmdir "$fifo_dir" 2>/dev/null || true
  rm -f "$stamp"

  # If the child was killed by watchdog, `wait` returns 143 (128+15) or 137
  # (128+9). Treat any of those as timeout.
  case "$child_status" in
    124|137|143)
      return 124
      ;;
    *)
      return "$child_status"
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Dry-run plan accumulator
# ---------------------------------------------------------------------------
append_dry_run_plan() {
  # append_dry_run_plan <section-title> <command...>
  # Runs the sub-script with its --dry-run flag and appends the output to
  # $CASE/DRY-RUN-PLAN.md under a named section. No HTTP calls fire.
  local title="$1"
  shift
  if [ -z "${CASE:-}" ] || [ ! -d "$CASE" ]; then
    echo "collect.sh: dry-run plan: no CASE dir, cannot append $title" >&2
    return 1
  fi
  {
    echo ""
    echo "## $title"
    echo ""
    echo '```'
    "$@" 2>&1 || echo "(sub-script exited non-zero during --dry-run enumeration)"
    echo '```'
  } >> "$CASE/DRY-RUN-PLAN.md"
}

# ===========================================================================
# PHASE 0: Preflight
# ===========================================================================
banner "PHASE 0: Preflight"

# Preflight runs synchronously; it is the gate for the entire run. No
# idle-watchdog: if it hangs, the run has no case dir anyway and the
# operator should Ctrl-C.
#
# Preflight writes $CASE/ and emits the path to stdout on its last line.
# We capture stdout so we can extract $CASE, but still show it to the
# operator via a tee to /dev/tty.
PREFLIGHT_OUT="$(mktemp -t vf-preflight.XXXXXX)"

# bash-3.2 + set -u: an empty array expansion raises "unbound variable".
# The `${name[@]+…}` guard sidesteps it — emit the array only if defined.
if "$SCRIPT_DIR/preflight.sh" ${PASSTHRU_ARGS[@]+"${PASSTHRU_ARGS[@]}"} 2>&1 | tee "$PREFLIGHT_OUT"; then
  :
else
  echo ""
  phase_fail "Phase 0" "preflight.sh exited non-zero"
  rm -f "$PREFLIGHT_OUT"
  exit 1
fi

# Preflight contract: the final non-empty line of stdout is the absolute
# path to the case directory.
CASE="$(awk 'NF {line=$0} END {print line}' "$PREFLIGHT_OUT")"
rm -f "$PREFLIGHT_OUT"

if [ -z "$CASE" ] || [ ! -d "$CASE" ]; then
  phase_fail "Phase 0" "preflight did not produce a valid case directory"
  exit 1
fi

export CASE
: > "$CASE/scan-errors.txt" || true   # Create empty; tolerate read-only race.

if [ "$DRY_RUN" -eq 1 ]; then
  cat > "$CASE/DRY-RUN-PLAN.md" <<EOF
# vercel-forensics — dry-run plan

Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Case dir: $CASE
Incident window: $INCIDENT_WINDOW
Skip Phase 4 (GitHub): $NO_GITHUB

No HTTP calls were made. No freeze was performed. Each section below
lists the endpoints the corresponding sub-script would have called if
invoked in live mode.
EOF
fi

phase_ok "Phase 0"

# ===========================================================================
# PHASE 1: Vercel activity log
# ===========================================================================
banner "PHASE 1: Activity log"

PHASE1_CMD="$SCRIPT_DIR/activity-paginate.sh"

if [ "$DRY_RUN" -eq 1 ]; then
  append_dry_run_plan "Phase 1 — activity log" \
    "$PHASE1_CMD" --case "$CASE" --dry-run \
    $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" )
  phase_ok "Phase 1"
else
  # shellcheck disable=SC2086
  if run_phase "Phase 1" \
      "$PHASE1_CMD" --case "$CASE" \
      $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" ); then
    phase_ok "Phase 1"
  else
    PHASE1_RC=$?
    if [ "$PHASE1_RC" -eq 124 ]; then
      record_error "phase1" "activity-log" "watchdog" \
        "idle-progress watchdog tripped after ${IDLE_LIMIT}s"
      phase_fail "Phase 1" "watchdog timeout"
    else
      record_error "phase1" "activity-log" "exit" \
        "activity-paginate.sh exited $PHASE1_RC"
      phase_fail "Phase 1" "sub-script exited $PHASE1_RC"
    fi
  fi
fi

# ===========================================================================
# PHASE 2: Team-wide context (parallel inside the sub-script)
# ===========================================================================
banner "PHASE 2: Team context"

PHASE2_CMD="$SCRIPT_DIR/vercel-team-context.sh"

if [ "$DRY_RUN" -eq 1 ]; then
  append_dry_run_plan "Phase 2 — team context" \
    "$PHASE2_CMD" --case "$CASE" --dry-run \
    $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" )
  phase_ok "Phase 2"
else
  # shellcheck disable=SC2086
  if run_phase "Phase 2" \
      "$PHASE2_CMD" --case "$CASE" \
      $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" ); then
    phase_ok "Phase 2"
  else
    PHASE2_RC=$?
    if [ "$PHASE2_RC" -eq 124 ]; then
      record_error "phase2" "team-context" "watchdog" \
        "idle-progress watchdog tripped after ${IDLE_LIMIT}s"
      phase_fail "Phase 2" "watchdog timeout"
    else
      record_error "phase2" "team-context" "exit" \
        "vercel-team-context.sh exited $PHASE2_RC"
      phase_fail "Phase 2" "sub-script exited $PHASE2_RC"
    fi
  fi
fi

# ===========================================================================
# PHASE 3: Per-project pulls (parallel inside the sub-script, per project)
# ===========================================================================
banner "PHASE 3: Per-project pulls"

PHASE3_CMD="$SCRIPT_DIR/vercel-per-project.sh"

if [ "$DRY_RUN" -eq 1 ]; then
  append_dry_run_plan "Phase 3 — per-project pulls" \
    "$PHASE3_CMD" --case "$CASE" --dry-run \
    $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" )
  phase_ok "Phase 3"
else
  # vercel-per-project.sh handles per-project partial failures internally
  # and records them to $CASE/scan-errors.txt. Its own exit status is 0 on
  # complete success, 2 on any per-project partial failure, non-zero other
  # values for fatal errors that prevent enumeration.
  # shellcheck disable=SC2086
  if run_phase "Phase 3" \
      "$PHASE3_CMD" --case "$CASE" \
      $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" ); then
    phase_ok "Phase 3"
  else
    PHASE3_RC=$?
    case "$PHASE3_RC" in
      2)
        # Sub-script already wrote rows to scan-errors.txt; mark partial
        # without adding a second duplicate row.
        RUN_STATUS=2
        phase_ok "Phase 3 (with per-project partials — see scan-errors.txt)"
        ;;
      124)
        record_error "phase3" "per-project" "watchdog" \
          "idle-progress watchdog tripped after ${IDLE_LIMIT}s"
        phase_fail "Phase 3" "watchdog timeout"
        ;;
      *)
        record_error "phase3" "per-project" "exit" \
          "vercel-per-project.sh exited $PHASE3_RC"
        phase_fail "Phase 3" "sub-script exited $PHASE3_RC"
        ;;
    esac
  fi
fi

# ===========================================================================
# PHASE 4: GitHub adjacent (optional; --no-github skips)
# ===========================================================================
banner "PHASE 4: GitHub adjacent"

if [ "$NO_GITHUB" -eq 1 ]; then
  echo "Phase 4 SKIPPED (--no-github)"
else
  # Phase 4a: per-linked-repo GraphQL metadata.
  # The list of linked repos is derived by preflight/phase-2 and written
  # to $CASE/github-linked-repos.txt (one "owner/repo" per line). If the
  # file is absent or empty, skip cleanly — that's not an error (e.g.,
  # no Git integration on this team).
  LINKED_REPOS_FILE="$CASE/github-linked-repos.txt"
  PHASE4A_CMD="$SCRIPT_DIR/github-repo-graphql.sh"

  if [ -s "$LINKED_REPOS_FILE" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      # In dry-run mode, emit one plan section per repo.
      while IFS= read -r repo; do
        [ -z "$repo" ] && continue
        append_dry_run_plan "Phase 4a — GitHub repo: $repo" \
          "$PHASE4A_CMD" --case "$CASE" --repo "$repo" --dry-run \
          $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" )
      done < "$LINKED_REPOS_FILE"
      phase_ok "Phase 4a"
    else
      PHASE4A_FAIL=0
      while IFS= read -r repo; do
        [ -z "$repo" ] && continue
        # shellcheck disable=SC2086
        if run_phase "Phase 4a: $repo" \
            "$PHASE4A_CMD" --case "$CASE" --repo "$repo" \
            $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" ); then
          :
        else
          RC=$?
          PHASE4A_FAIL=1
          if [ "$RC" -eq 124 ]; then
            record_error "phase4a" "$repo" "watchdog" \
              "idle-progress watchdog tripped after ${IDLE_LIMIT}s"
          else
            record_error "phase4a" "$repo" "exit" \
              "github-repo-graphql.sh exited $RC"
          fi
        fi
      done < "$LINKED_REPOS_FILE"
      if [ "$PHASE4A_FAIL" -eq 0 ]; then
        phase_ok "Phase 4a"
      else
        phase_fail "Phase 4a" "one or more repos failed — see scan-errors.txt"
      fi
    fi
  else
    echo "Phase 4a SKIPPED (no linked repos found at $LINKED_REPOS_FILE)"
  fi

  # Phase 4b: org / enterprise audit log.
  PHASE4B_CMD="$SCRIPT_DIR/github-audit-log.sh"

  # preflight wrote $CASE/github-audit-target.txt with either
  # "org <slug>" or "enterprise <slug>" or "user <login>" (user = skip).
  AUDIT_TARGET_FILE="$CASE/github-audit-target.txt"
  if [ -s "$AUDIT_TARGET_FILE" ]; then
    AUDIT_KIND="$(awk 'NR==1 {print $1}' "$AUDIT_TARGET_FILE")"
    if [ "$AUDIT_KIND" = "user" ]; then
      echo "Phase 4b SKIPPED (owner type is 'user' — no audit log available)"
    else
      if [ "$DRY_RUN" -eq 1 ]; then
        append_dry_run_plan "Phase 4b — GitHub audit log" \
          "$PHASE4B_CMD" --case "$CASE" --dry-run \
          $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" )
        phase_ok "Phase 4b"
      else
        # shellcheck disable=SC2086
        if run_phase "Phase 4b" \
            "$PHASE4B_CMD" --case "$CASE" \
            $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" ); then
          phase_ok "Phase 4b"
        else
          PHASE4B_RC=$?
          if [ "$PHASE4B_RC" -eq 124 ]; then
            record_error "phase4b" "audit-log" "watchdog" \
              "idle-progress watchdog tripped after ${IDLE_LIMIT}s"
            phase_fail "Phase 4b" "watchdog timeout"
          else
            record_error "phase4b" "audit-log" "exit" \
              "github-audit-log.sh exited $PHASE4B_RC"
            phase_fail "Phase 4b" "sub-script exited $PHASE4B_RC"
          fi
        fi
      fi
    fi
  else
    echo "Phase 4b SKIPPED (no audit target recorded at $AUDIT_TARGET_FILE)"
  fi
fi

# ===========================================================================
# PHASE 5: Incident-window build logs
# ===========================================================================
banner "PHASE 5: Build logs (incident window)"

PHASE5_CMD="$SCRIPT_DIR/vercel-build-logs.sh"

if [ "$DRY_RUN" -eq 1 ]; then
  append_dry_run_plan "Phase 5 — incident-window build logs" \
    "$PHASE5_CMD" --case "$CASE" --incident-window "$INCIDENT_WINDOW" --dry-run \
    $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" )
  phase_ok "Phase 5"
else
  # shellcheck disable=SC2086
  if run_phase "Phase 5" \
      "$PHASE5_CMD" --case "$CASE" --incident-window "$INCIDENT_WINDOW" \
      $( [ "$LOG_REQUESTS" -eq 1 ] && echo "--log-requests" ); then
    phase_ok "Phase 5"
  else
    PHASE5_RC=$?
    if [ "$PHASE5_RC" -eq 124 ]; then
      record_error "phase5" "build-logs" "watchdog" \
        "idle-progress watchdog tripped after ${IDLE_LIMIT}s"
      phase_fail "Phase 5" "watchdog timeout"
    else
      record_error "phase5" "build-logs" "exit" \
        "vercel-build-logs.sh exited $PHASE5_RC"
      phase_fail "Phase 5" "sub-script exited $PHASE5_RC"
    fi
  fi
fi

# ===========================================================================
# Wrap-up
# ===========================================================================
banner "collection complete"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "Dry-run plan written to: $CASE/DRY-RUN-PLAN.md"
  echo "No HTTP calls were made. No freeze was performed."
  # Intentional: freeze.sh is NOT invoked in dry-run mode so the operator
  # can rm -rf the case dir without fighting the immutable bit.
  exit 0
fi

if [ -s "$CASE/scan-errors.txt" ]; then
  echo "Partial failures recorded in: $CASE/scan-errors.txt"
fi

echo "Case directory: $CASE"
echo "Next step: run redact.py and freeze.sh per SKILL.md §Workflow."

exit "$RUN_STATUS"
