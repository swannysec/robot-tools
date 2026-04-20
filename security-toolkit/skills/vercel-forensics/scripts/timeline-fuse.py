#!/usr/bin/env python3
"""Merge Vercel activity + GitHub audit-log events into a chronological TSV.

Input paths (under the frozen case directory):
  $CASE/raw/vercel/activity.jsonl           (one Vercel activity event per line)
  $CASE/raw/github/audit-log-180d.jsonl     (one GitHub audit event per line)

Output:
  $CASE/analysis/timeline.tsv
    Columns: iso_ts \t source \t event \t actor \t project \t correlated

Semantics:
  - `source` is `vercel` or `github`.
  - `event` is the event type (Vercel `type`, GitHub `action`).
  - `actor` is the email if available, else the UID/login/principalId (fallback).
  - `project` is the Vercel project name/id or the GitHub `repo`.
  - `correlated=1` iff another row in the opposite source shares the same
    (normalized, non-empty) actor email and sits within a 15-minute window of
    this row. Otherwise `0`. Correlation is symmetric across sources.

Timestamps:
  - Vercel activity events carry `createdAt` as milliseconds-since-epoch.
  - GitHub audit events carry `@timestamp` (ms) or `created_at` (ISO-8601 or
    ms) depending on endpoint. We try numeric first, fall back to ISO parse.

Behavior:
  - Either input may be absent. With `--no-github` we skip the GitHub file
    entirely. A missing input is a no-op (emits whatever the other source
    produced). If both are absent, the output is an empty (header-only) file.
  - Output is sorted ascending by `iso_ts` (UTC, `YYYY-MM-DDTHH:MM:SSZ`).
  - `--dry-run` prints the first 20 rows to stdout (header + up to 20 data
    rows) and does NOT write the output file.
  - Writes via `_common.atomic_write`. Python 3.10 stdlib only.

Exit codes:
  0  OK (including when one source was absent by design).
  2  Case directory missing or malformed argument.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from typing import Any, Iterator, Optional

from _common import atomic_write

# 15 minutes, in seconds — the correlation window per methodology §1b.
CORRELATION_WINDOW_SEC = 15 * 60

# TSV header (tab-separated, no trailing tab).
HEADER = ("iso_ts", "source", "event", "actor", "project", "correlated")

# Preview row cap for --dry-run output.
DRY_RUN_LIMIT = 20


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="timeline-fuse.py",
        description="Fuse Vercel + GitHub events into chronological timeline.tsv",
    )
    parser.add_argument("--case", required=True, help="Frozen case directory")
    parser.add_argument(
        "--no-github",
        action="store_true",
        help="Skip the GitHub audit-log source (Vercel-only timeline).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print first 20 rows to stdout; do not write timeline.tsv.",
    )
    return parser.parse_args(argv)


def _iter_jsonl(path: str) -> Iterator[dict[str, Any]]:
    """Yield parsed JSON objects from a JSONL file. Silently skip bad lines."""
    try:
        fh = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return
    with fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                # Malformed line — log to stderr and carry on. raw/ is pristine;
                # we never rewrite upstream files from this script.
                print(
                    f"timeline-fuse: skipping malformed JSONL line in {path}",
                    file=sys.stderr,
                )
                continue
            if isinstance(obj, dict):
                yield obj


def _to_epoch_seconds(value: Any) -> Optional[float]:
    """Coerce ms-epoch int/str OR ISO-8601 string to seconds-since-epoch.

    Returns None if parsing fails.

    Unit heuristic: numeric values below 1e12 are assumed to be
    seconds-since-epoch (GitHub audit-log `created_at` sometimes appears
    as seconds rather than ms, especially for older entries); values at
    or above 1e12 are ms-epoch (current time in ms is ~1.7e12). Timestamps
    before ~2001 in ms-epoch are below 1e12, but no Vercel/GitHub event
    predates the platforms, so this cutoff is safe.
    """
    if value is None:
        return None
    # Numeric (int or float) — autodetect seconds vs ms.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        v = float(value)
        return v if v < 1e12 else v / 1000.0
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # All-digit string — same autodetect.
        if s.isdigit():
            try:
                v = float(s)
            except ValueError:
                return None
            return v if v < 1e12 else v / 1000.0
        # Try ISO-8601. Accept trailing "Z".
        iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
        try:
            dt = datetime.datetime.fromisoformat(iso)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    return None


def _iso_from_epoch(secs: float) -> str:
    """Render UTC ISO-8601 second-precision (YYYY-MM-DDTHH:MM:SSZ)."""
    dt = datetime.datetime.fromtimestamp(secs, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sanitize_field(value: Any) -> str:
    """TSV-safe one-line string; strip tabs/newlines; '' for None."""
    if value is None:
        return ""
    s = str(value)
    # Flatten whitespace that would break TSV row/column framing.
    return s.replace("\t", " ").replace("\r", " ").replace("\n", " ").strip()


def _extract_vercel_row(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return a row dict or None if required fields missing."""
    epoch = _to_epoch_seconds(event.get("createdAt"))
    if epoch is None:
        return None
    etype = event.get("type") or ""
    # Actor: prefer payload.user.email, then top-level userEmail, then userId,
    # then principalId. Emails are what correlation joins on.
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    actor_email: Optional[str] = None
    user_obj = payload.get("user") if isinstance(payload, dict) else None
    if isinstance(user_obj, dict):
        maybe = user_obj.get("email")
        if isinstance(maybe, str) and maybe:
            actor_email = maybe
    if actor_email is None:
        maybe = event.get("userEmail")
        if isinstance(maybe, str) and maybe:
            actor_email = maybe
    actor_fallback = event.get("userId") or event.get("principalId") or ""
    actor = actor_email if actor_email else actor_fallback
    # Project: payload.projectName → payload.project.name → payload.projectId.
    project: Any = ""
    if isinstance(payload, dict):
        project = payload.get("projectName") or ""
        if not project:
            proj_obj = payload.get("project")
            if isinstance(proj_obj, dict):
                project = proj_obj.get("name") or proj_obj.get("id") or ""
        if not project:
            project = payload.get("projectId") or ""
    return {
        "epoch": epoch,
        "source": "vercel",
        "event": etype,
        "actor_email": actor_email or "",
        "actor": actor,
        "project": project,
    }


def _extract_github_row(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Return a row dict or None if required fields missing."""
    epoch = _to_epoch_seconds(event.get("@timestamp"))
    if epoch is None:
        epoch = _to_epoch_seconds(event.get("created_at"))
    if epoch is None:
        return None
    action = event.get("action") or ""
    # Actor email: only present on some actions; most events carry only the
    # `actor` login. `user` is sometimes the target rather than the actor.
    actor_email: Optional[str] = None
    for key in ("actor_email", "user_email", "email"):
        maybe = event.get(key)
        if isinstance(maybe, str) and maybe:
            actor_email = maybe
            break
    actor_login = event.get("actor") or event.get("user") or ""
    actor = actor_email if actor_email else actor_login
    repo = event.get("repo") or event.get("repository") or ""
    return {
        "epoch": epoch,
        "source": "github",
        "event": action,
        "actor_email": actor_email or "",
        "actor": actor,
        "project": repo,
    }


def _build_rows(case: str, skip_github: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    vercel_path = os.path.join(case, "raw", "vercel", "activity.jsonl")
    for ev in _iter_jsonl(vercel_path):
        row = _extract_vercel_row(ev)
        if row is not None:
            rows.append(row)

    if not skip_github:
        github_path = os.path.join(case, "raw", "github", "audit-log-180d.jsonl")
        for ev in _iter_jsonl(github_path):
            row = _extract_github_row(ev)
            if row is not None:
                rows.append(row)

    # Stable sort by epoch ascending. Python's sort is stable, so same-ts rows
    # retain input (per-source) order.
    rows.sort(key=lambda r: r["epoch"])
    return rows


def _mark_correlations(rows: list[dict[str, Any]]) -> None:
    """Set `correlated` = 1 on any row with a cross-source email match in window.

    Two-pointer sweep against the sorted-by-epoch list is O(n * w) where w is
    the average events per 15-minute window. Acceptable for forensic volumes.
    """
    n = len(rows)
    for r in rows:
        r["correlated"] = 0
    # Only rows with a non-empty normalized email are eligible to correlate.
    for i in range(n):
        ri = rows[i]
        email_i = ri["actor_email"].strip().lower()
        if not email_i:
            continue
        src_i = ri["source"]
        t_i = ri["epoch"]
        # Sweep forward until outside window.
        j = i + 1
        while j < n and (rows[j]["epoch"] - t_i) <= CORRELATION_WINDOW_SEC:
            rj = rows[j]
            if rj["source"] != src_i:
                email_j = rj["actor_email"].strip().lower()
                if email_j and email_j == email_i:
                    ri["correlated"] = 1
                    rj["correlated"] = 1
            j += 1


def _format_row(row: dict[str, Any]) -> str:
    fields = (
        _iso_from_epoch(row["epoch"]),
        row["source"],
        _sanitize_field(row["event"]),
        _sanitize_field(row["actor"]),
        _sanitize_field(row["project"]),
        "1" if row.get("correlated") else "0",
    )
    return "\t".join(fields)


def _render(rows: list[dict[str, Any]]) -> str:
    lines = ["\t".join(HEADER)]
    for row in rows:
        lines.append(_format_row(row))
    return "\n".join(lines) + "\n"


def _render_preview(rows: list[dict[str, Any]], limit: int) -> str:
    lines = ["\t".join(HEADER)]
    for row in rows[:limit]:
        lines.append(_format_row(row))
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    case = args.case
    if not os.path.isdir(case):
        print(f"timeline-fuse: case directory does not exist: {case}", file=sys.stderr)
        return 2

    rows = _build_rows(case, skip_github=args.no_github)
    _mark_correlations(rows)

    if args.dry_run:
        sys.stdout.write(_render_preview(rows, DRY_RUN_LIMIT))
        print(
            f"timeline-fuse: dry-run OK — {len(rows)} total rows "
            f"({sum(1 for r in rows if r['correlated'])} correlated); "
            f"showing up to {DRY_RUN_LIMIT}",
            file=sys.stderr,
        )
        return 0

    out_dir = os.path.join(case, "analysis")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "timeline.tsv")
    atomic_write(out_path, _render(rows), mode=0o600)
    print(
        f"timeline-fuse: wrote {out_path} ({len(rows)} rows, "
        f"{sum(1 for r in rows if r['correlated'])} correlated)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
