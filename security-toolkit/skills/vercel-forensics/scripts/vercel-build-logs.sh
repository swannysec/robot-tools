#!/usr/bin/env bash
# vercel-build-logs.sh — vercel-forensics Phase 5 (per-deployment build logs)
#
# For every project enumerated in Phase 3, re-read the per-project
# deployments.json and select deployments whose `createdAt` is at or after
# the incident window (default: 24 hours ago). For each selected deployment,
# pull `/v3/deployments/<uid>/events?teamId=$TEAM_ID&builds=1` and write the
# response to:
#
#   $CASE/raw/vercel/projects/<name>/build-logs/<uid>.json
#
# Also writes a per-project manifest:
#
#   $CASE/raw/vercel/projects/<name>/build-logs/_manifest.json
#
# Build logs are immutable per deployment (unlike runtime logs, they do not
# expire within 24h — documented limitation captured in data-inventory.md)
# so the incident-window filter is the useful selector here.
#
# Implementation notes (see references/collection-patterns.md §8):
#   * There is NO bulk endpoint — one HTTP call per deployment.
#   * Parallelizing via shell `&` has been observed to hit
#     "failed to change user ID" OS errors under some macOS sandbox
#     policies, so we use SERIAL Python inside a heredoc.
#   * Each pull is ~1s; 24 deploys ≈ 25s.
#   * Deployments endpoint is 500 req/min on Pro (2000 Enterprise); serial
#     is far below the ceiling — no client-side throttle needed.
#
# Platform: bash 3.2 + BSD userland (ADR-002). No GNU-isms.
#   * `date -u -v-24H +%Y-%m-%dT%H:%M:%SZ` is BSD-only — exactly what we need
#     since the skill is macOS-first.
#
# Required env (set by preflight export block):
#   CASE      absolute path to the case directory (also passable via --case)
#   TEAM_ID   Vercel team id (required)
#
# Args:
#   --case <path>               required (or export CASE)
#   --incident-window <ISO>     optional (default: 24 hours ago, ISO-8601 UTC)
#   --dry-run                   enumerate uids + GET URLs, no files, exit 0
#   --log-requests              append request paths to $CASE/request-log.txt
#
# Exit codes:
#   0  all selected deployments pulled cleanly (or zero selected)
#   1  fatal: enumeration failed, $CASE/$TEAM_ID missing, projects-list.json absent
#   2  partial: at least one per-deployment pull failed
#      (row recorded in $CASE/scan-errors.txt with phase5 tag)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults + CLI
# ---------------------------------------------------------------------------
CASE_ARG=""
INCIDENT_WINDOW=""
DRY_RUN=0
LOG_REQUESTS=0

usage() {
  cat <<'USAGE'
Usage: vercel-build-logs.sh --case <path> [--incident-window <ISO-8601>]
                            [--dry-run] [--log-requests]

Phase 5 of vercel-forensics. Reads $TEAM_ID from env (set by preflight).

--incident-window defaults to 24 hours ago (UTC, ISO-8601). Deployments
with createdAt >= window are pulled.

In dry-run mode, enumerates uids + GET URLs from existing deployments.json
files without firing any HTTP calls; no files are written.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      CASE_ARG="${2:-}"
      shift 2
      ;;
    --incident-window)
      INCIDENT_WINDOW="${2:-}"
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
      echo "vercel-build-logs: unknown argument: $1" >&2
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

if [ -z "$CASE" ]; then
  echo "vercel-build-logs: --case <path> is required (or export CASE)" >&2
  exit 1
fi
if [ -z "$TEAM_ID" ]; then
  echo "vercel-build-logs: TEAM_ID env var required (set by preflight)" >&2
  exit 1
fi
if [ "$DRY_RUN" -eq 0 ] && [ ! -d "$CASE" ]; then
  echo "vercel-build-logs: case directory not found: $CASE" >&2
  exit 1
fi

# Default incident window: 24 hours ago (BSD date).
if [ -z "$INCIDENT_WINDOW" ]; then
  INCIDENT_WINDOW="$(date -u -v-24H +%Y-%m-%dT%H:%M:%SZ)"
fi

for bin in vercel python3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "vercel-build-logs: required binary not on PATH: $bin" >&2
    exit 1
  fi
done

PROJECTS_LIST="$CASE/raw/vercel/projects-list.json"
if [ ! -s "$PROJECTS_LIST" ]; then
  echo "vercel-build-logs: projects-list.json missing or empty at $PROJECTS_LIST" >&2
  echo "vercel-build-logs: run Phase 3 (vercel-per-project.sh) first" >&2
  exit 1
fi

PROJECTS_DIR="$CASE/raw/vercel/projects"
if [ ! -d "$PROJECTS_DIR" ]; then
  echo "vercel-build-logs: projects directory missing: $PROJECTS_DIR" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Driver — serial Python, one HTTP call per deployment
# ---------------------------------------------------------------------------
# Exports for the heredoc (env is inherited).
export CASE TEAM_ID INCIDENT_WINDOW
export VBL_DRY_RUN="$DRY_RUN"
export VBL_LOG_REQUESTS="$LOG_REQUESTS"

python3 <<'PYEOF'
"""Phase 5 driver: per-project, per-deployment build-log pulls.

Serial (not parallel) per collection-patterns.md §8. Reads deployments.json
under each project directory, filters by createdAt >= INCIDENT_WINDOW, and
invokes `vercel api /v3/deployments/<uid>/events?teamId=<tid>&builds=1` once
per selected deployment. Outputs:

  $CASE/raw/vercel/projects/<name>/build-logs/<uid>.json     (per deploy)
  $CASE/raw/vercel/projects/<name>/build-logs/_manifest.json (uid + createdAt list)

Partial failure handling: per-deployment failures append a phase5 row to
$CASE/scan-errors.txt and set the partial flag. The script exits 2 when any
partial occurred, 0 otherwise. Enumeration errors (missing projects-list,
unparseable deployments.json) are bubbled up as fatal (exit 1).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

CASE = os.environ["CASE"]
TEAM_ID = os.environ["TEAM_ID"]
INCIDENT_WINDOW = os.environ["INCIDENT_WINDOW"]
DRY_RUN = os.environ.get("VBL_DRY_RUN", "0") == "1"
LOG_REQUESTS = os.environ.get("VBL_LOG_REQUESTS", "0") == "1"

PROJECTS_LIST = os.path.join(CASE, "raw", "vercel", "projects-list.json")
PROJECTS_DIR = os.path.join(CASE, "raw", "vercel", "projects")
SCAN_ERRORS = os.path.join(CASE, "scan-errors.txt")
REQUEST_LOG = os.path.join(CASE, "request-log.txt")


def record_error(resource: str, reason: str) -> None:
    """Append a phase5 row to scan-errors.txt (tab-separated)."""
    if DRY_RUN:
        return
    if not os.path.isdir(CASE):
        sys.stderr.write(f"phase5\t{resource}\tbuild-events\t{reason}\n")
        return
    with open(SCAN_ERRORS, "a", encoding="utf-8") as fh:
        fh.write(f"phase5\t{resource}\tbuild-events\t{reason}\n")


def log_request(label: str, path: str) -> None:
    if not LOG_REQUESTS or DRY_RUN:
        return
    if not os.path.isdir(CASE):
        return
    with open(REQUEST_LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{label}\tGET\t{path}\n")


def atomic_write(path: str, content: str, mode: int = 0o600) -> None:
    """Write content atomically via .tmp + rename. Refuse existing target + symlinks."""
    try:
        lst = os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        import stat as _stat
        if _stat.S_ISLNK(lst.st_mode):
            raise FileExistsError(f"atomic_write: refuse symlink target: {path}")
        raise FileExistsError(f"atomic_write: refuse overwrite: {path}")
    tmp = path + ".tmp"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(tmp, flags, mode)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.chmod(tmp, mode)
        os.rename(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_deployments(deploy_path: str) -> list:
    """Load deployments.json. `vercel api --paginate` may concatenate pages;
    slurp into a single list of deployment dicts."""
    with open(deploy_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    if not raw.strip():
        return []
    dec = json.JSONDecoder()
    pos = 0
    pages = []
    while pos < len(raw):
        try:
            obj, end = dec.raw_decode(raw, pos)
        except json.JSONDecodeError:
            break
        pages.append(obj)
        pos = end
        while pos < len(raw) and raw[pos] in " \n\t\r":
            pos += 1
    out: list = []
    for page in pages:
        if isinstance(page, list):
            out.extend(x for x in page if isinstance(x, dict))
        elif isinstance(page, dict):
            inner = page.get("deployments")
            if isinstance(inner, list):
                out.extend(x for x in inner if isinstance(x, dict))
            elif "uid" in page or "id" in page:
                out.append(page)
    return out


def deployment_uid(d: dict) -> str:
    """Vercel returns `uid` on /v6/deployments; some shapes use `id`."""
    return d.get("uid") or d.get("id") or ""


def deployment_created_iso(d: dict) -> str:
    """Normalize createdAt to ISO-8601 UTC Z string for comparison.

    /v6/deployments returns `created` (ms-epoch) and sometimes `createdAt`
    (ISO). Prefer `createdAt` if it's already a string; otherwise derive
    from ms-epoch `created`. Returns "" if neither is usable.
    """
    created_at = d.get("createdAt")
    if isinstance(created_at, str) and created_at:
        # Normalize trailing +00:00 to Z for lexicographic compare
        if created_at.endswith("+00:00"):
            created_at = created_at[:-6] + "Z"
        return created_at
    created = d.get("created")
    if isinstance(created, (int, float)):
        import datetime as _dt
        return (
            _dt.datetime.fromtimestamp(created / 1000.0, tz=_dt.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    return ""


def is_within_window(created_iso: str, window_iso: str) -> bool:
    """Lexicographic compare works for ISO-8601-UTC-Z strings of equal shape.

    Both sides are normalized to the same Z-suffixed UTC form, so this is
    safe. Empty created_iso is treated as out-of-window (conservative).
    """
    if not created_iso:
        return False
    return created_iso >= window_iso


def list_project_dirs() -> list[str]:
    if not os.path.isdir(PROJECTS_DIR):
        return []
    out: list[str] = []
    for name in sorted(os.listdir(PROJECTS_DIR)):
        full = os.path.join(PROJECTS_DIR, name)
        if os.path.isdir(full):
            out.append(name)
    return out


def run_vercel_api(path: str) -> tuple[int, str, str]:
    """Invoke `vercel api <path>`; capture stdout/stderr. 60s timeout.

    Exit code, stdout, stderr. Timeout surfaces as exit code -1.
    """
    try:
        proc = subprocess.run(
            ["vercel", "api", path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", "vercel-binary-missing"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
partial = False
selected_total = 0
pulled_total = 0

if DRY_RUN:
    print(f"# vercel-build-logs.sh --dry-run")
    print(f"# case: {CASE}")
    print(f"# team: {TEAM_ID}")
    print(f"# incident-window: {INCIDENT_WINDOW}")
    print("")

project_dirs = list_project_dirs()
if not project_dirs:
    # Not fatal — a team may genuinely have zero projects enumerated.
    # Just emit a note and exit 0.
    if DRY_RUN:
        print("# (no project directories under projects/ — nothing to enumerate)")
    else:
        sys.stderr.write(
            "vercel-build-logs: no project directories under "
            f"{PROJECTS_DIR}; exiting 0\n"
        )
    sys.exit(0)

for name in project_dirs:
    pdir = os.path.join(PROJECTS_DIR, name)
    deploy_path = os.path.join(pdir, "deployments.json")
    if not os.path.isfile(deploy_path):
        # No deployments.json for this project — skip silently.
        continue
    try:
        deploys = load_deployments(deploy_path)
    except (OSError, json.JSONDecodeError) as exc:
        record_error(f"{name}/deployments.json", f"parse-error:{exc.__class__.__name__}")
        partial = True
        continue

    # Filter to incident window.
    selected = []
    for d in deploys:
        uid = deployment_uid(d)
        if not uid:
            continue
        created_iso = deployment_created_iso(d)
        if is_within_window(created_iso, INCIDENT_WINDOW):
            selected.append((uid, created_iso))

    if not selected:
        continue
    selected_total += len(selected)

    logs_dir = os.path.join(pdir, "build-logs")

    if DRY_RUN:
        print(f"## Project: {name}  ({len(selected)} in-window deploy(s))")
        for uid, created_iso in selected:
            api_path = f"/v3/deployments/{uid}/events?teamId={TEAM_ID}&builds=1"
            print(f"  GET {api_path}  [createdAt={created_iso}]  -> {name}/build-logs/{uid}.json")
        print("")
        continue

    os.makedirs(logs_dir, mode=0o700, exist_ok=True)

    manifest_entries: list[dict] = []
    for uid, created_iso in selected:
        api_path = f"/v3/deployments/{uid}/events?teamId={TEAM_ID}&builds=1"
        log_request(f"{name}:build-events:{uid}", api_path)
        out_path = os.path.join(logs_dir, f"{uid}.json")
        if os.path.lexists(out_path):
            # Skip deployments we've already pulled (re-runs are forbidden
            # post-freeze; pre-freeze collisions mean this script was
            # invoked twice — preserve the first pull).
            manifest_entries.append({
                "uid": uid,
                "createdAt": created_iso,
                "status": "pre-existing",
            })
            continue

        rc, stdout, stderr = run_vercel_api(api_path)
        if rc != 0:
            reason_map = {
                -1: "timeout",
                -2: "vercel-binary-missing",
            }
            reason = reason_map.get(rc, f"http-error-rc-{rc}")
            record_error(f"{name}/{uid}", reason)
            partial = True
            # Still write a sentinel so the manifest accounts for it.
            sentinel = json.dumps({
                "error": "vercel-api-failed",
                "exitCode": rc,
                "stderr_excerpt": (stderr or "")[:200],
            }) + "\n"
            try:
                atomic_write(out_path, sentinel)
            except FileExistsError:
                pass
            manifest_entries.append({
                "uid": uid,
                "createdAt": created_iso,
                "status": "error",
                "reason": reason,
            })
            continue

        # Atomic write of the raw response body.
        try:
            atomic_write(out_path, stdout)
        except FileExistsError:
            # Race on repeat invocation — record and move on.
            record_error(f"{name}/{uid}", "atomic-write-exists")
            partial = True
            manifest_entries.append({
                "uid": uid,
                "createdAt": created_iso,
                "status": "skipped-exists",
            })
            continue
        pulled_total += 1
        manifest_entries.append({
            "uid": uid,
            "createdAt": created_iso,
            "status": "ok",
        })

    # Per-project manifest (atomic; refuse overwrite to preserve first run).
    manifest_path = os.path.join(logs_dir, "_manifest.json")
    manifest_doc = {
        "project": name,
        "incidentWindow": INCIDENT_WINDOW,
        "teamId": TEAM_ID,
        "selected": len(selected),
        "entries": manifest_entries,
    }
    try:
        atomic_write(
            manifest_path,
            json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n",
        )
    except FileExistsError:
        # A prior run wrote this manifest. Emit a sibling with a numeric suffix
        # so we never silently clobber. Downstream triage should prefer the
        # unsuffixed original; these siblings are diagnostic only.
        i = 2
        while True:
            alt = os.path.join(logs_dir, f"_manifest.{i}.json")
            if not os.path.lexists(alt):
                try:
                    atomic_write(
                        alt,
                        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n",
                    )
                except FileExistsError:
                    i += 1
                    continue
                break
            i += 1

if DRY_RUN:
    print(f"# Total in-window deployments across all projects: {selected_total}")
    sys.exit(0)

if partial:
    sys.stderr.write(
        f"vercel-build-logs: completed with partial failures "
        f"(selected={selected_total}, pulled={pulled_total}); see scan-errors.txt\n"
    )
    sys.exit(2)

sys.stderr.write(
    f"vercel-build-logs: pulled {pulled_total}/{selected_total} in-window "
    f"deployment build logs cleanly\n"
)
sys.exit(0)
PYEOF

# The heredoc exits the script via sys.exit; preserve its exit code.
RC=$?
exit "$RC"
