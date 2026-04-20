#!/usr/bin/env bash
# freeze.sh — evidence-directory freeze step for vercel-forensics (v1).
#
# Writes three artifacts at the root of the case directory:
#   1. MANIFEST.sha256       SHA-256 of every file in $CASE (deterministic,
#                            lexicographically sorted), in the exact output
#                            format of `shasum -a 256` (hash, two spaces,
#                            relative path).
#   2. COLLECTOR.json        Identity / host / case metadata.
#   3. CHAIN_OF_CUSTODY.md   Chronological custody ledger: collector header,
#                            phase start/end markers scraped from per-phase
#                            logs, and scan-errors events (if any).
#
# After writing all three atomically, the entire $CASE tree is marked
# read-only with `chmod -R a-w "$CASE"` — this is the only mutation the
# skill ever performs, and it operates only on local investigator-owned
# disk (see references/preservation-constraints.md §1.7).
#
# IDEMPOTENCE: refuses to re-freeze. If $CASE/MANIFEST.sha256 already
# exists, exits 1 with a clear message.
#
# Platform: bash 3.2 + BSD userland (ADR-002). Uses `shasum -a 256`
# (BSD) — NOT `sha256sum` (GNU). Uses `date +%s` — NOT `$EPOCHSECONDS`.
#
# TODO v2: add `--sign <fpr>` flag for GPG signing of MANIFEST.sha256;
# dual-location manifest copy to ~/.vercel-forensics/manifests/<case-id>/;
# verify-scene.sh companion that re-hashes and diffs against both copies;
# RFC 3161 `--tsa <url>` qualified-timestamp option. None of this ships
# in v1 — v1 is engineering-triage, not court-admissible.

set -euo pipefail

# ---------------------------------------------------------------------------
# Hard-coded tool version — v1 uses a local constant. plugin-qa (release
# mode) will later sync this with security-toolkit/.claude-plugin/plugin.json
# on every version bump. Keep the string format exactly "vX.Y.Z".
# ---------------------------------------------------------------------------
TOOL_VERSION="v0.1.0"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
CASE=""
DRY_RUN=0

usage() {
  cat <<'USAGE'
Usage: freeze.sh --case <path> [--dry-run]

Freeze a vercel-forensics case directory: write MANIFEST.sha256,
COLLECTOR.json, CHAIN_OF_CUSTODY.md, then chmod -R a-w the tree.

Options:
  --case <path>   Required. Path to the case directory to freeze.
  --dry-run       Enumerate what would be hashed and summarize the
                  COLLECTOR + CHAIN content. Writes nothing. Does NOT
                  chmod. Safe to re-run.

Exit codes:
  0   Clean freeze (or clean dry-run).
  1   Refuse (already frozen) or fatal error.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --case)
      CASE="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "freeze.sh: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$CASE" ]; then
  echo "freeze.sh: --case <path> is required" >&2
  usage >&2
  exit 1
fi

if [ ! -d "$CASE" ]; then
  echo "freeze.sh: case directory does not exist: $CASE" >&2
  exit 1
fi

# Normalize to an absolute path without resorting to GNU `readlink -f`.
CASE="$(cd "$CASE" && pwd)"

# ---------------------------------------------------------------------------
# Idempotence: refuse if already frozen.
# ---------------------------------------------------------------------------
if [ -e "$CASE/MANIFEST.sha256" ]; then
  echo "freeze.sh: already frozen — refusing to re-freeze" >&2
  echo "  (MANIFEST.sha256 exists at $CASE/MANIFEST.sha256)" >&2
  exit 1
fi

# Refuse to freeze a case where redact.py did not run to completion.
# redact.py always writes $CASE/analysis/redactions.log as its sidecar (even
# if zero matches were found — it emits the TSV header row). Absent log ==
# redaction skipped or crashed pre-write. Freezing an unredacted case would
# bake raw secrets into the WORM tree, which is exactly what the contract
# prohibits (Runtime Reinforcement §6; preservation-constraints §1.7).
if [ "$DRY_RUN" -ne 1 ] && [ ! -e "$CASE/analysis/redactions.log" ]; then
  echo "freeze.sh: refusing to freeze — redact.py has not run" >&2
  echo "  ($CASE/analysis/redactions.log is missing)" >&2
  echo "  Run: python3 '${SCRIPT_DIR:-$(dirname "$0")}/redact.py' --case '$CASE'" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Collect identity + timing metadata.
# ---------------------------------------------------------------------------
WHOAMI="$(id -un)"
HOSTNAME_SHORT="$(hostname -s)"
CASE_ID="$(basename "$CASE")"
TIMEZONE="$(date +%Z)"
COLLECTION_END_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [ -r "$CASE/.collection-start" ]; then
  # Tolerate trailing whitespace / newline.
  COLLECTION_START_ISO="$(head -n1 "$CASE/.collection-start" | tr -d '[:space:]')"
  if [ -z "$COLLECTION_START_ISO" ]; then
    COLLECTION_START_ISO="$COLLECTION_END_ISO"
  fi
else
  COLLECTION_START_ISO="$COLLECTION_END_ISO"
fi

# Incident-window argument — not currently passed into freeze.sh, but the
# CHAIN_OF_CUSTODY header reserves a slot. Keep empty in v1.
INCIDENT_WINDOW="${INCIDENT_WINDOW:-}"

# ---------------------------------------------------------------------------
# Enumerate files to hash.
#
# Rules:
#   - Every regular file under $CASE, recursively.
#   - Exclude the three artifacts being written right now
#     (MANIFEST.sha256, CHAIN_OF_CUSTODY.md, COLLECTOR.json) so the manifest
#     does not try to hash itself or its peers-in-the-same-write.
#   - Exclude .tmp sidecars from in-progress atomic writes (if any race).
#   - Paths in the manifest are relative to $CASE with a leading "./" —
#     this matches how `shasum -a 256 ./path` renders them and makes
#     verification trivial with `(cd "$CASE" && shasum -a 256 -c MANIFEST.sha256)`.
#   - Deterministic order via `LC_ALL=C sort` (byte-lexicographic).
#
# We materialize the path list into a temp file, then feed it to `shasum`
# via xargs. This keeps memory bounded for large cases and keeps the path
# list available for the dry-run summary.
# ---------------------------------------------------------------------------
TMP_FILELIST="$(mktemp -t vf-freeze-files.XXXXXX)"
trap 'rm -f "$TMP_FILELIST"' EXIT

(
  cd "$CASE"
  # NUL-delimited enumeration + sort so any filename containing a newline
  # cannot produce a spurious manifest row. Only regular files; only under
  # raw/ (the frozen-evidence root). analysis/ and handoff/ are *not*
  # manifested because they are produced by analysis scripts that run
  # AFTER freeze — they live outside the WORM carve-out (see the
  # `chmod -R a-w` block below).
  find raw -type f \
    ! -name 'MANIFEST.sha256' \
    ! -name 'MANIFEST.sha256.tmp' \
    ! -name 'CHAIN_OF_CUSTODY.md' \
    ! -name 'CHAIN_OF_CUSTODY.md.tmp' \
    ! -name 'COLLECTOR.json' \
    ! -name 'COLLECTOR.json.tmp' \
    -print0 \
  | LC_ALL=C sort -z \
  | tr '\0' '\n'
) > "$TMP_FILELIST"

# Guard: if any path contains a literal control char (CR/LF/TAB), abort.
# `shasum -c` cannot verify such a manifest. Vercel slugs + GitHub repo
# names are constrained to safe charsets upstream (preflight regex), so
# this should never fire — but the check is cheap and the alternative is
# a corrupt manifest.
if LC_ALL=C awk '/[\r\n\t]/ { print; found=1 } END { exit found ? 1 : 0 }' "$TMP_FILELIST" >&2; then
  :
else
  echo "freeze.sh: refusing to freeze — filename with control chars found (see above)" >&2
  exit 1
fi

FILE_COUNT=$(wc -l < "$TMP_FILELIST" | tr -d '[:space:]')

# ---------------------------------------------------------------------------
# DRY-RUN branch: print plan, write nothing, do not chmod.
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
  echo "freeze.sh: DRY RUN — no files written, no chmod applied"
  echo ""
  echo "Case directory: $CASE"
  echo "Case ID: $CASE_ID"
  echo ""
  echo "Would write: $CASE/MANIFEST.sha256"
  echo "Would write: $CASE/COLLECTOR.json"
  echo "Would write: $CASE/CHAIN_OF_CUSTODY.md"
  echo "Would chmod: -R a-w $CASE/raw + a-w on 3 root artifacts"
  echo "  (analysis/ and handoff/ stay writable — see freeze.sh §WORM)"
  echo ""
  echo "Files that would be hashed ($FILE_COUNT total):"
  if [ "$FILE_COUNT" -eq 0 ]; then
    echo "  (none)"
  else
    # Indent for readability.
    sed 's/^/  /' "$TMP_FILELIST"
  fi
  echo ""
  echo "COLLECTOR.json would contain:"
  echo "  whoami:                 $WHOAMI"
  echo "  hostname:               $HOSTNAME_SHORT"
  echo "  tool_version:           $TOOL_VERSION"
  echo "  case_id:                $CASE_ID"
  echo "  collection_start_iso:   $COLLECTION_START_ISO"
  echo "  collection_end_iso:     $COLLECTION_END_ISO"
  echo "  timezone:               $TIMEZONE"
  echo ""
  echo "CHAIN_OF_CUSTODY.md would include:"
  echo "  - header block (collector + case id + incident window)"
  dry_log_hits=0
  for f in \
      "$CASE/raw/vercel/activity-pagination.log" \
      "$CASE/raw/vercel/activity-requests.log" \
      "$CASE/raw/github/audit-requests.log"; do
    if [ -s "$f" ]; then
      dry_log_hits=$((dry_log_hits + 1))
      echo "  - phase markers from: ${f#$CASE/}"
    fi
  done
  if [ "$dry_log_hits" -eq 0 ]; then
    echo "  - (no phase log files found under $CASE/raw/)"
  fi
  if [ -s "$CASE/scan-errors.txt" ]; then
    err_rows=$(wc -l < "$CASE/scan-errors.txt" | tr -d '[:space:]')
    echo "  - $err_rows custody event(s) from scan-errors.txt"
  else
    echo "  - (no scan-errors.txt)"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Atomic write helper.
#
# Writes content to <dst>.tmp then renames to <dst>. Refuses to overwrite
# an existing <dst> (the MANIFEST.sha256 idempotence check already guards
# the primary case, but be defensive for the two sibling files).
# ---------------------------------------------------------------------------
atomic_write() {
  local dst="$1"
  local tmp="${dst}.tmp"
  # $2 is content on stdin via `<<<` or piped; we read from stdin here.
  # Usage: `atomic_write /path/to/file < source`  or  `... <<EOF ... EOF`.
  # Refuse symlink targets (TOCTOU defense) on BOTH dst and tmp. The
  # Python `_common.atomic_write` uses O_EXCL on the tmp path; bash has
  # no direct O_EXCL open but `set -C` (noclobber) approximates — it
  # causes `>` redirection to fail if the file exists, preventing a
  # pre-planted symlink at `.tmp` from being followed during the `cat >`.
  if [ -L "$dst" ] || [ -L "$tmp" ]; then
    echo "freeze.sh: refusing to write through symlink: $dst (or $tmp)" >&2
    return 1
  fi
  if [ -e "$dst" ]; then
    echo "freeze.sh: refusing to overwrite existing file: $dst" >&2
    return 1
  fi
  if [ -e "$tmp" ]; then
    echo "freeze.sh: refusing to write through existing tmp: $tmp" >&2
    return 1
  fi
  # Write tmp under noclobber, then rename. The subshell contains the
  # `set -C` to avoid leaking into the caller's shell state.
  ( set -C; cat > "$tmp" ) || {
    echo "freeze.sh: atomic_write failed for: $dst" >&2
    return 1
  }
  mv "$tmp" "$dst"
}

# ---------------------------------------------------------------------------
# 1. MANIFEST.sha256
#
# Format matches `shasum -a 256` output exactly:
#   <64-hex>  <path>
# (two-space separator, per BSD shasum). We invoke shasum per-batch via
# xargs to handle large file lists.
# ---------------------------------------------------------------------------
MANIFEST_TMP="$CASE/MANIFEST.sha256.tmp"
if [ -e "$MANIFEST_TMP" ]; then
  echo "freeze.sh: stale tmp exists, refusing: $MANIFEST_TMP" >&2
  exit 1
fi

(
  cd "$CASE"
  if [ "$FILE_COUNT" -eq 0 ]; then
    # Empty case dir — write an empty manifest rather than skipping.
    : > "$MANIFEST_TMP"
  else
    # Feed newline-separated list through xargs. Paths inside the case
    # dir are ours (created by collection scripts with sanitized names),
    # so they contain no newlines or special characters.
    tr '\n' '\0' < "$TMP_FILELIST" \
      | xargs -0 shasum -a 256 \
      > "$MANIFEST_TMP"
  fi
)

# Verify we actually produced output (or a clean empty for empty dirs).
if [ "$FILE_COUNT" -gt 0 ] && [ ! -s "$MANIFEST_TMP" ]; then
  echo "freeze.sh: manifest generation produced empty output despite $FILE_COUNT files" >&2
  rm -f "$MANIFEST_TMP"
  exit 1
fi

mv "$MANIFEST_TMP" "$CASE/MANIFEST.sha256"

# ---------------------------------------------------------------------------
# 2. COLLECTOR.json
#
# Hand-rolled JSON — Python 3 is available in this skill, but freeze.sh is
# bash-only to match the rest of the preservation layer. The field values
# are drawn from `id -un`, `hostname -s`, and `date +%Z`; none of them can
# contain JSON-breaking characters in practice. For defense, escape
# backslashes and double-quotes in each string.
# ---------------------------------------------------------------------------
# Defer JSON encoding to python3 so control chars, unicode, and quotes in
# any field (whoami / hostname / tz — unlikely but possible via scutil)
# land as valid JSON rather than invalid evidentiary metadata.
COLLECTOR_JSON="$(
  python3 -c '
import json, sys
fields = dict(zip(
    ("whoami","hostname","tool_version","case_id",
     "collection_start_iso","collection_end_iso","timezone"),
    sys.argv[1:8]))
print(json.dumps(fields, indent=2, sort_keys=False))
' \
    "$WHOAMI" "$HOSTNAME_SHORT" "$TOOL_VERSION" "$CASE_ID" \
    "$COLLECTION_START_ISO" "$COLLECTION_END_ISO" "$TIMEZONE"
)"

atomic_write "$CASE/COLLECTOR.json" <<EOF
$COLLECTOR_JSON
EOF

# ---------------------------------------------------------------------------
# 3. CHAIN_OF_CUSTODY.md
#
# Chronological ledger. Sections:
#   - Header block (collector identity + case id + freeze iso + incident
#     window if known).
#   - Custody events table. Columns: iso_ts | actor | event | artifact | sha256
#     (sha256 blank when the event is not file-write-related).
#
# Sources of events:
#   - Pagination logs (Vercel activity + GitHub audit) — each line records
#     a page read (iso_ts TAB cursor TAB count). Emit one row per line.
#   - scan-errors.txt (phase, resource, stage, reason) — one row per line.
#   - Final row: "freeze complete" at COLLECTION_END_ISO.
#
# Rows inside each section are emitted in file order (which for the
# pagination logs is already chronological). No attempt is made to merge
# globally — the header timestamp plus per-section headers keep this
# readable for a human investigator. A v2 timeline-fuse pass will handle
# strict global ordering if/when needed for admissibility.
# ---------------------------------------------------------------------------
CHAIN_TMP="$CASE/CHAIN_OF_CUSTODY.md.tmp"
if [ -e "$CHAIN_TMP" ]; then
  echo "freeze.sh: stale tmp exists, refusing: $CHAIN_TMP" >&2
  exit 1
fi

{
  echo "# Chain of Custody — $CASE_ID"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| case_id | \`$CASE_ID\` |"
  echo "| collector | \`$WHOAMI@$HOSTNAME_SHORT\` |"
  echo "| tool_version | \`$TOOL_VERSION\` |"
  echo "| collection_start_iso | \`$COLLECTION_START_ISO\` |"
  echo "| collection_end_iso | \`$COLLECTION_END_ISO\` |"
  echo "| timezone | \`$TIMEZONE\` |"
  if [ -n "$INCIDENT_WINDOW" ]; then
    echo "| incident_window | \`$INCIDENT_WINDOW\` |"
  else
    echo "| incident_window | _(not specified)_ |"
  fi
  echo ""
  echo "## Custody events"
  echo ""
  echo "| iso_ts | actor | event | artifact | sha256 |"
  echo "|---|---|---|---|---|"

  # Freeze-start marker.
  printf '| %s | %s | %s | %s | %s |\n' \
    "$COLLECTION_END_ISO" "$WHOAMI@$HOSTNAME_SHORT" "freeze-start" "-" "-"

  # --- Vercel activity pagination events.
  VPLOG="$CASE/raw/vercel/activity-pagination.log"
  if [ -s "$VPLOG" ]; then
    # Each line: iso_ts<TAB>cursor<TAB>count
    awk -F'\t' -v actor="$WHOAMI@$HOSTNAME_SHORT" '
      NF >= 3 {
        gsub(/\|/, "\\|", $1); gsub(/\|/, "\\|", $2); gsub(/\|/, "\\|", $3)
        printf "| %s | %s | %s | %s | %s |\n", \
          $1, actor, "vercel-activity-page", \
          "cursor=" $2 " count=" $3, "-"
      }
    ' "$VPLOG"
  fi

  # --- GitHub audit pagination events (if present as a pagination log).
  # The github-audit-log.sh writes requests to audit-requests.log (opt-in)
  # rather than a dedicated pagination log, so we scan it only when it
  # contains structured rows. Row shape: iso_ts<TAB>...
  GPLOG="$CASE/raw/github/audit-requests.log"
  if [ -s "$GPLOG" ]; then
    awk -F'\t' -v actor="$WHOAMI@$HOSTNAME_SHORT" '
      NF >= 2 {
        # First column should be an ISO timestamp. Defensive check: only
        # emit rows whose first field starts with a 4-digit year.
        if ($1 ~ /^[0-9]{4}-/) {
          gsub(/\|/, "\\|", $0)
          printf "| %s | %s | %s | %s | %s |\n", \
            $1, actor, "github-audit-request", $2, "-"
        }
      }
    ' "$GPLOG"
  fi

  # --- Vercel activity request log (opt-in --log-requests).
  VRLOG="$CASE/raw/vercel/activity-requests.log"
  if [ -s "$VRLOG" ]; then
    awk -F'\t' -v actor="$WHOAMI@$HOSTNAME_SHORT" '
      NF >= 2 {
        if ($1 ~ /^[0-9]{4}-/) {
          gsub(/\|/, "\\|", $0)
          printf "| %s | %s | %s | %s | %s |\n", \
            $1, actor, "vercel-activity-request", $2, "-"
        }
      }
    ' "$VRLOG"
  fi

  # --- scan-errors.txt events.
  # Row shape (from collect.sh): phase<TAB>resource<TAB>stage<TAB>reason.
  # These rows do not carry their own timestamp, so we stamp them with
  # COLLECTION_END_ISO (best-effort — exact per-error timestamps are a
  # v2 addition).
  SEFILE="$CASE/scan-errors.txt"
  if [ -s "$SEFILE" ]; then
    awk -F'\t' -v ts="$COLLECTION_END_ISO" -v actor="$WHOAMI@$HOSTNAME_SHORT" '
      NF >= 4 {
        gsub(/\|/, "\\|", $1); gsub(/\|/, "\\|", $2)
        gsub(/\|/, "\\|", $3); gsub(/\|/, "\\|", $4)
        printf "| %s | %s | %s | %s | %s |\n", \
          ts, actor, "scan-error", \
          $1 "/" $2 "/" $3 ": " $4, "-"
      }
    ' "$SEFILE"
  fi

  # Freeze-complete marker with manifest hash.
  if [ -s "$CASE/MANIFEST.sha256" ]; then
    # Hash the manifest itself so a reader can cross-check MANIFEST's own
    # integrity against this ledger row.
    MANIFEST_HASH="$(shasum -a 256 "$CASE/MANIFEST.sha256" | awk '{print $1}')"
  else
    MANIFEST_HASH="-"
  fi
  printf '| %s | %s | %s | %s | %s |\n' \
    "$COLLECTION_END_ISO" "$WHOAMI@$HOSTNAME_SHORT" "freeze-complete" \
    "MANIFEST.sha256" "$MANIFEST_HASH"

  echo ""
  echo "## Notes"
  echo ""
  echo "- Events above are chronological *within each source*; global"
  echo "  ordering across sources is best-effort in v1 (v2 adds a strict"
  echo "  merge via timeline-fuse)."
  echo "- Scan-error rows are stamped with \`collection_end_iso\` because"
  echo "  the underlying \`scan-errors.txt\` rows do not carry per-event"
  echo "  timestamps in v1."
  echo "- MANIFEST.sha256 was hashed *after* it was written and *before*"
  echo "  the \`chmod -R a-w\` read-only lock was applied."
} > "$CHAIN_TMP"

mv "$CHAIN_TMP" "$CASE/CHAIN_OF_CUSTODY.md"

# ---------------------------------------------------------------------------
# Close the integrity loop: append COLLECTOR.json + CHAIN_OF_CUSTODY.md
# hashes to MANIFEST.sha256.
#
# Without this, a post-freeze edit to either file is detectable only via
# the ledger's self-referential MANIFEST_HASH row — which is inside the
# document being edited (circular trust). Appending their hashes to
# MANIFEST (after they're finalized, before chmod locks the manifest)
# means `shasum -c MANIFEST.sha256` from inside $CASE covers all three
# root artifacts. MANIFEST still cannot hash itself — that remains the
# gap closed by GPG/TSA in v2.
# ---------------------------------------------------------------------------
(
  cd "$CASE"
  shasum -a 256 ./COLLECTOR.json ./CHAIN_OF_CUSTODY.md >> MANIFEST.sha256
)

# ---------------------------------------------------------------------------
# Software WORM: lock raw evidence + root artifacts read-only.
#
# The WORM carve-out is deliberate: analysis/ and handoff/ are writable
# after freeze so the analysis scripts (triage.py, timeline-fuse.py,
# per-actor-profile.py, build-log-scan.py, rotation-worklist.py) can write
# their outputs against a frozen input. Raw evidence (raw/) plus the three
# evidentiary artifacts at the case-dir root (MANIFEST.sha256,
# COLLECTOR.json, CHAIN_OF_CUSTODY.md) are the immutable surface.
#
# Contract: what the manifest hashes is what `chmod -R a-w` locks. Both
# operate over raw/ + the three root artifacts. Analysis outputs are not
# in the manifest because they are derivations, not evidence.
# ---------------------------------------------------------------------------
if [ -d "$CASE/raw" ]; then
  chmod -R a-w "$CASE/raw"
fi
chmod a-w "$CASE/MANIFEST.sha256" "$CASE/COLLECTOR.json" "$CASE/CHAIN_OF_CUSTODY.md"
if [ -e "$CASE/scan-errors.txt" ]; then
  chmod a-w "$CASE/scan-errors.txt"
fi

echo "freeze.sh: case frozen."
echo "  Files hashed:     $FILE_COUNT (raw/ + root artifacts)"
echo "  MANIFEST.sha256:  $CASE/MANIFEST.sha256"
echo "  COLLECTOR.json:   $CASE/COLLECTOR.json"
echo "  CHAIN_OF_CUSTODY: $CASE/CHAIN_OF_CUSTODY.md"
echo "  WORM scope:       raw/ + root artifacts (analysis/, handoff/ stay writable)"

exit 0
