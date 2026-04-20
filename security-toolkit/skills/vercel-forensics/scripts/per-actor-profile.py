#!/usr/bin/env python3
"""Per-actor profile builder (analysis phase 1c).

Reads the fused timeline + raw Vercel evidence and emits two artifacts:

  - $CASE/analysis/per-actor.md   (human-readable report)
  - $CASE/analysis/actors.json    (structured data for downstream use)

For each actor observed in timeline events it computes:

  1. Primary owner candidacy — number of env vars where this actor appears as
     `lastUpdatedBy` (per-project env-metadata.json).
  2. Backup owner candidacy — count of deployments authored over the last
     90 days per project (bots filtered).
  3. 90-day baselines — event-type distribution + weekday/hour histogram over
     the whole window of timeline.tsv data for that actor.
  4. Anomaly flags during the incident window:
     * event types used in-window that the actor never performed outside it
     * weekday/hour buckets used in-window that are empty in baseline
     * non-corporate email domain (vs the modal domain of confirmed team
       members) — flags common personal providers explicitly
     * deployment source diversity / unique creator.uid anomalies

Inputs read (all paths relative to --case):
  analysis/timeline.tsv                                (from timeline-fuse.py)
  raw/vercel/team/members.json                         (from vercel-team-context.sh)
  raw/vercel/projects-list.json                        (from vercel-per-project.sh)
  raw/vercel/projects/<name>/deployments.json          (from vercel-per-project.sh)
  raw/vercel/projects/<name>/env-metadata.json         (from vercel-per-project.sh)
  scan-errors.txt                                      (optional, timestamp hints)
  vercel-activity-pagination.log                       (optional, timestamp hints)

Incident window (for in-window anomaly flagging):
  --incident-window-start <ISO>   explicit lower bound (UTC)
  otherwise inferred from earliest timestamp in scan-errors.txt /
  vercel-activity-pagination.log. If no window can be inferred, the last
  72 hours of timeline.tsv is used as a best-effort fallback and the report
  flags this.

Exit codes:
  0 — actors.json + per-actor.md written (or dry-run summary printed)
  1 — hard error (bad --case, missing required input, write failure)
  2 — timeline.tsv missing (timeline-fuse.py did not run); report not produced

Args: --case <path> required; --incident-window-start <ISO> optional;
      --dry-run optional.
Python 3.10 stdlib only. Uses _common.atomic_write.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from collections import Counter
from typing import Any, Iterable, Optional

from _common import atomic_write

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASELINE_DAYS = 90
_FALLBACK_WINDOW_HOURS = 72

# Personal / non-corporate email providers that should always be called out
# when they show up on an actor. The final "home domain" comparison catches
# anything else unusual; this set is just the always-loud list.
_PERSONAL_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com",
    "yahoo.com", "yahoo.co.uk", "ymail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "aol.com", "duck.com", "fastmail.com", "tutanota.com",
    "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com",
})

# Bot / CI identity filters. Applied to emails or email-shaped strings.
# Evaluated case-insensitively. An actor is considered a bot if ANY matches.
_BOT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^vercel@", re.IGNORECASE),
    re.compile(r"-bot@", re.IGNORECASE),
    re.compile(r"\[bot\]", re.IGNORECASE),
    re.compile(r"^github-actions(\[bot\])?@", re.IGNORECASE),
    re.compile(r"^dependabot(\[bot\])?@", re.IGNORECASE),
    re.compile(r"^renovate(\[bot\])?@", re.IGNORECASE),
    re.compile(r"noreply@", re.IGNORECASE),
)

# ISO-8601 timestamp regex — loose enough to capture variants that appear
# in scan-errors.txt / activity pagination logs.
_ISO_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso(value: str) -> Optional[_dt.datetime]:
    """Parse an ISO-8601 timestamp to a tz-aware UTC datetime. None on failure."""
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return dt.astimezone(_dt.timezone.utc)


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _email_domain(email: str) -> str:
    if not email or "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()


def _is_bot(identity: str) -> bool:
    if not identity:
        return False
    for pat in _BOT_PATTERNS:
        if pat.search(identity):
            return True
    return False


def _tsv_rows(path: str) -> Iterable[list[str]]:
    """Yield rows of timeline.tsv, skipping a leading header line if present."""
    with open(path, "r", encoding="utf-8") as fh:
        first = True
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if first:
                first = False
                # timeline-fuse.py emits a header; drop it if detected.
                if parts and parts[0].lower().startswith("iso"):
                    continue
            yield parts


# ---------------------------------------------------------------------------
# Incident window inference
# ---------------------------------------------------------------------------

def _infer_incident_window_start(case_dir: str) -> tuple[Optional[_dt.datetime], str]:
    """Inspect scan-errors.txt + activity-pagination log for the earliest ts.

    Returns (datetime_or_none, source_label). source_label names the hint
    origin so the report can document provenance ("explicit", "scan-errors",
    "pagination-log", "fallback-72h", "none").
    """
    candidates: list[_dt.datetime] = []

    scan_errors = os.path.join(case_dir, "scan-errors.txt")
    if os.path.isfile(scan_errors):
        try:
            with open(scan_errors, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _ISO_RE.search(line)
                    if m:
                        dt = _parse_iso(m.group(1))
                        if dt is not None:
                            candidates.append(dt)
        except OSError:
            pass

    pagination_log = os.path.join(
        case_dir, "raw", "vercel", "activity-pagination.log"
    )
    if not os.path.isfile(pagination_log):
        # Also accept the alternative location mentioned in the spec.
        alt = os.path.join(case_dir, "vercel", "activity-pagination.log")
        if os.path.isfile(alt):
            pagination_log = alt
    if os.path.isfile(pagination_log):
        try:
            with open(pagination_log, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = _ISO_RE.search(line)
                    if m:
                        dt = _parse_iso(m.group(1))
                        if dt is not None:
                            candidates.append(dt)
        except OSError:
            pass

    if candidates:
        return min(candidates), "scan-errors+pagination-log"
    return None, "none"


# ---------------------------------------------------------------------------
# Input loaders
# ---------------------------------------------------------------------------

def _load_members(case_dir: str) -> list[dict[str, Any]]:
    path = os.path.join(case_dir, "raw", "vercel", "team", "members.json")
    if not os.path.isfile(path):
        return []
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return []
    # members.json is typically {"members":[...]} but may be a bare list.
    if isinstance(data, dict):
        for key in ("members", "users", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return []
    if isinstance(data, list):
        return data
    return []


def _projects_root(case_dir: str) -> Optional[str]:
    """Return the directory holding per-project subdirs, or None."""
    candidates = [
        os.path.join(case_dir, "raw", "vercel", "projects"),
        os.path.join(case_dir, "vercel", "projects"),
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    return None


def _iter_project_dirs(case_dir: str) -> list[str]:
    root = _projects_root(case_dir)
    if root is None:
        return []
    out: list[str] = []
    try:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if os.path.isdir(full):
                out.append(full)
    except OSError:
        pass
    return out


def _load_env_metadata(project_dir: str) -> list[dict[str, Any]]:
    """Read env-metadata.json; return a flat list of env var dicts."""
    path = os.path.join(project_dir, "env-metadata.json")
    if not os.path.isfile(path):
        return []
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        for key in ("envs", "env", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return []
    if isinstance(data, list):
        return data
    return []


def _load_deployments(project_dir: str) -> list[dict[str, Any]]:
    path = os.path.join(project_dir, "deployments.json")
    if not os.path.isfile(path):
        return []
    try:
        data = _load_json(path)
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        for key in ("deployments", "data"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return []
    if isinstance(data, list):
        return data
    return []


# ---------------------------------------------------------------------------
# Actor model
# ---------------------------------------------------------------------------

class ActorState:
    """Mutable per-actor aggregator. Converted to dict for actors.json."""

    __slots__ = (
        "key", "email", "uid", "display_names",
        "event_types_in", "event_types_out",
        "bucket_in", "bucket_out",
        "sources_in", "sources_out",
        "deploy_creator_uids_in", "deploy_creator_uids_out",
        "total_events", "first_seen", "last_seen",
        "primary_owner_env_count", "primary_owner_env_keys",
        "backup_owner_deploys_90d", "backup_owner_projects",
        "is_bot",
    )

    def __init__(self, key: str) -> None:
        self.key = key
        self.email = key if "@" in key else ""
        self.uid = "" if "@" in key else key
        self.display_names: set[str] = set()
        self.event_types_in: Counter[str] = Counter()
        self.event_types_out: Counter[str] = Counter()
        self.bucket_in: Counter[tuple[int, int]] = Counter()
        self.bucket_out: Counter[tuple[int, int]] = Counter()
        self.sources_in: Counter[str] = Counter()
        self.sources_out: Counter[str] = Counter()
        self.deploy_creator_uids_in: set[str] = set()
        self.deploy_creator_uids_out: set[str] = set()
        self.total_events = 0
        self.first_seen: Optional[_dt.datetime] = None
        self.last_seen: Optional[_dt.datetime] = None
        self.primary_owner_env_count = 0
        self.primary_owner_env_keys: list[str] = []
        self.backup_owner_deploys_90d: Counter[str] = Counter()
        self.backup_owner_projects: set[str] = set()
        self.is_bot = _is_bot(key)


def _actor_key(email: str, uid: str) -> str:
    """Canonical actor key — email preferred, falls back to uid."""
    if email:
        return email.strip().lower()
    if uid:
        return uid.strip()
    return ""


def _get_or_make(
    table: dict[str, ActorState], email: str, uid: str
) -> Optional[ActorState]:
    key = _actor_key(email, uid)
    if not key:
        return None
    state = table.get(key)
    if state is None:
        state = ActorState(key)
        if email:
            state.email = email.strip().lower()
        if uid:
            state.uid = uid.strip()
        table[key] = state
    else:
        if email and not state.email:
            state.email = email.strip().lower()
        if uid and not state.uid:
            state.uid = uid.strip()
    return state


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _build_actors_from_timeline(
    timeline_path: str,
    incident_start: Optional[_dt.datetime],
    now_utc: _dt.datetime,
) -> tuple[dict[str, ActorState], Optional[_dt.datetime], Optional[_dt.datetime]]:
    """Walk timeline.tsv once, aggregate per-actor in/out-of-window stats.

    Returns (actors, earliest_seen, latest_seen).
    """
    actors: dict[str, ActorState] = {}
    earliest: Optional[_dt.datetime] = None
    latest: Optional[_dt.datetime] = None

    baseline_cutoff = now_utc - _dt.timedelta(days=_BASELINE_DAYS)

    for row in _tsv_rows(timeline_path):
        if len(row) < 4:
            continue
        iso_ts, source, event, actor = row[0], row[1], row[2], row[3]
        # row[4] = project (unused here); row[5] = correlated flag (optional)
        ts = _parse_iso(iso_ts)
        if ts is None:
            continue
        key = actor.strip()
        if not key:
            continue
        state = _get_or_make(actors, email=key if "@" in key else "", uid=key if "@" not in key else "")
        if state is None:
            continue

        state.total_events += 1
        if state.first_seen is None or ts < state.first_seen:
            state.first_seen = ts
        if state.last_seen is None or ts > state.last_seen:
            state.last_seen = ts
        if earliest is None or ts < earliest:
            earliest = ts
        if latest is None or ts > latest:
            latest = ts

        # Only count events inside the 90d baseline window for baseline stats.
        if ts < baseline_cutoff:
            continue

        bucket = (ts.weekday(), ts.hour)
        event_label = f"{source}:{event}" if source else event

        in_window = incident_start is not None and ts >= incident_start
        if in_window:
            state.event_types_in[event_label] += 1
            state.bucket_in[bucket] += 1
        else:
            state.event_types_out[event_label] += 1
            state.bucket_out[bucket] += 1

    return actors, earliest, latest


def _apply_env_ownership(
    actors: dict[str, ActorState], project_dirs: list[str]
) -> None:
    """Count env vars where actor is lastUpdatedBy — primary owner candidacy."""
    for pdir in project_dirs:
        envs = _load_env_metadata(pdir)
        project_name = os.path.basename(pdir)
        for env in envs:
            if not isinstance(env, dict):
                continue
            updater = env.get("lastUpdatedBy")
            display = env.get("lastUpdatedByDisplayName") or ""
            if not updater:
                continue
            state = _get_or_make(actors, email=updater if "@" in updater else "", uid=updater if "@" not in updater else "")
            if state is None:
                continue
            if display:
                state.display_names.add(str(display))
            state.primary_owner_env_count += 1
            key = env.get("key")
            if key:
                state.primary_owner_env_keys.append(f"{project_name}:{key}")


def _apply_deployment_activity(
    actors: dict[str, ActorState],
    project_dirs: list[str],
    incident_start: Optional[_dt.datetime],
    now_utc: _dt.datetime,
) -> dict[str, dict[str, Any]]:
    """Accumulate backup-owner counts + deployment-source/creator-uid stats.

    Returns per-project summary keyed by project dir basename for the report's
    deployment-anomalies section.
    """
    ninety_days_ago = now_utc - _dt.timedelta(days=_BASELINE_DAYS)
    per_project: dict[str, dict[str, Any]] = {}

    for pdir in project_dirs:
        project_name = os.path.basename(pdir)
        deployments = _load_deployments(pdir)
        deployer_counts: Counter[str] = Counter()
        creator_uids: set[str] = set()
        sources: Counter[str] = Counter()
        in_window_sources: Counter[str] = Counter()
        in_window_creator_uids: set[str] = set()

        for dep in deployments:
            if not isinstance(dep, dict):
                continue
            creator = dep.get("creator") or {}
            if not isinstance(creator, dict):
                creator = {}
            email = (creator.get("email") or "").strip()
            uid = (creator.get("uid") or "").strip()
            display = creator.get("username") or creator.get("name") or ""
            created_raw = dep.get("created")
            # `created` is commonly ms-epoch in Vercel API; also accept ISO.
            created_dt: Optional[_dt.datetime] = None
            if isinstance(created_raw, (int, float)):
                try:
                    created_dt = _dt.datetime.fromtimestamp(
                        created_raw / 1000.0, tz=_dt.timezone.utc
                    )
                except (OverflowError, OSError, ValueError):
                    created_dt = None
            elif isinstance(created_raw, str):
                created_dt = _parse_iso(created_raw)

            source = dep.get("source") or "unknown"
            sources[source] += 1
            if uid:
                creator_uids.add(uid)

            identity = email or uid
            # Backup-owner candidates exclude bots.
            if identity and not _is_bot(identity) and created_dt is not None:
                if created_dt >= ninety_days_ago:
                    deployer_counts[identity] += 1

            # Per-actor deployment source + uid tracking (in/out of window)
            if identity:
                state = _get_or_make(
                    actors,
                    email=email if "@" in identity else "",
                    uid=uid if uid and "@" not in identity else "",
                )
                if state is not None:
                    if display:
                        state.display_names.add(str(display))
                    in_window = (
                        incident_start is not None
                        and created_dt is not None
                        and created_dt >= incident_start
                    )
                    if in_window:
                        state.sources_in[source] += 1
                        in_window_sources[source] += 1
                        if uid:
                            state.deploy_creator_uids_in.add(uid)
                            in_window_creator_uids.add(uid)
                    else:
                        state.sources_out[source] += 1
                        if uid:
                            state.deploy_creator_uids_out.add(uid)

        # Attribute backup owner: most frequent non-bot deployer in last 90d.
        if deployer_counts:
            top_identity, top_count = deployer_counts.most_common(1)[0]
            state = _get_or_make(
                actors,
                email=top_identity if "@" in top_identity else "",
                uid=top_identity if "@" not in top_identity else "",
            )
            if state is not None:
                state.backup_owner_deploys_90d[project_name] = top_count
                state.backup_owner_projects.add(project_name)

        per_project[project_name] = {
            "total_deployments": sum(sources.values()),
            "unique_creator_uids": len(creator_uids),
            "sources": dict(sources),
            "in_window_sources": dict(in_window_sources),
            "in_window_unique_creator_uids": len(in_window_creator_uids),
        }

    return per_project


def _home_domain(members: list[dict[str, Any]]) -> Optional[str]:
    """Pick the modal confirmed-member email domain as the corporate domain."""
    counter: Counter[str] = Counter()
    for m in members:
        if not isinstance(m, dict):
            continue
        if m.get("confirmed") is False:
            continue
        email = m.get("email") or ""
        domain = _email_domain(email)
        if not domain:
            continue
        if domain in _PERSONAL_EMAIL_DOMAINS:
            continue
        counter[domain] += 1
    if not counter:
        return None
    return counter.most_common(1)[0][0]


def _compute_anomalies(
    state: ActorState, home_domain: Optional[str]
) -> dict[str, Any]:
    """Per-actor anomaly flags for the incident window."""
    flags: list[str] = []

    # Event-type novelty: event labels used in-window but never out-of-window.
    novel_events = sorted(
        evt for evt in state.event_types_in
        if evt not in state.event_types_out
    )
    if novel_events:
        flags.append("novel-event-type")

    # Time-bucket novelty: weekday/hour buckets used in-window but empty in
    # out-of-window baseline.
    novel_buckets = sorted(
        f"{wd}:{hr:02d}" for (wd, hr) in state.bucket_in
        if (wd, hr) not in state.bucket_out
    )
    if novel_buckets:
        flags.append("novel-time-bucket")

    domain = _email_domain(state.email)
    domain_flags: list[str] = []
    if domain:
        if domain in _PERSONAL_EMAIL_DOMAINS:
            domain_flags.append("personal-email-provider")
        if home_domain and domain != home_domain and domain not in _PERSONAL_EMAIL_DOMAINS:
            domain_flags.append("non-home-domain")
    if domain_flags:
        flags.extend(domain_flags)

    # Deployment anomalies: new sources or new creator UIDs in-window.
    new_sources = sorted(s for s in state.sources_in if s not in state.sources_out)
    if new_sources:
        flags.append("novel-deployment-source")
    new_uids = sorted(
        u for u in state.deploy_creator_uids_in
        if u not in state.deploy_creator_uids_out
    )
    if new_uids:
        flags.append("novel-deployment-creator-uid")

    return {
        "flags": flags,
        "novel_events": novel_events,
        "novel_time_buckets": novel_buckets,
        "email_domain": domain,
        "domain_flags": domain_flags,
        "novel_deployment_sources": new_sources,
        "novel_deployment_creator_uids": new_uids,
    }


# ---------------------------------------------------------------------------
# Output shaping
# ---------------------------------------------------------------------------

def _state_to_public(state: ActorState, anomalies: dict[str, Any]) -> dict[str, Any]:
    """Serialize an ActorState + anomaly dict into actors.json-friendly form."""
    total_baseline = (
        sum(state.event_types_in.values())
        + sum(state.event_types_out.values())
    )
    return {
        "key": state.key,
        "email": state.email,
        "uid": state.uid,
        "display_names": sorted(state.display_names),
        "is_bot": state.is_bot,
        "total_timeline_events": state.total_events,
        "baseline_event_count_90d": total_baseline,
        "first_seen": state.first_seen.isoformat() if state.first_seen else None,
        "last_seen": state.last_seen.isoformat() if state.last_seen else None,
        "event_types_in_window": dict(state.event_types_in),
        "event_types_out_of_window": dict(state.event_types_out),
        "weekday_hour_buckets_in_window": {
            f"{wd}:{hr:02d}": n for (wd, hr), n in state.bucket_in.items()
        },
        "weekday_hour_buckets_out_of_window": {
            f"{wd}:{hr:02d}": n for (wd, hr), n in state.bucket_out.items()
        },
        "deployment_sources_in_window": dict(state.sources_in),
        "deployment_sources_out_of_window": dict(state.sources_out),
        "unique_deployment_creator_uids_in_window": sorted(state.deploy_creator_uids_in),
        "unique_deployment_creator_uids_out_of_window": sorted(state.deploy_creator_uids_out),
        "primary_owner_env_count": state.primary_owner_env_count,
        "primary_owner_env_keys": sorted(state.primary_owner_env_keys),
        "backup_owner_projects": sorted(state.backup_owner_projects),
        "backup_owner_deploy_counts_90d": dict(state.backup_owner_deploys_90d),
        "anomalies": anomalies,
    }


def _render_markdown(
    actors_public: list[dict[str, Any]],
    per_project: dict[str, dict[str, Any]],
    home_domain: Optional[str],
    incident_start: Optional[_dt.datetime],
    incident_source: str,
    timeline_bounds: tuple[Optional[_dt.datetime], Optional[_dt.datetime]],
) -> str:
    lines: list[str] = []
    lines.append("# Per-Actor Profile")
    lines.append("")
    lines.append("Source: `analysis/timeline.tsv` + `raw/vercel/` evidence.")
    lines.append("")
    lines.append("## Run context")
    lines.append("")
    earliest, latest = timeline_bounds
    lines.append(f"- Timeline earliest: `{earliest.isoformat() if earliest else '(none)'}`")
    lines.append(f"- Timeline latest: `{latest.isoformat() if latest else '(none)'}`")
    lines.append(
        f"- Incident window start: `{incident_start.isoformat() if incident_start else '(unknown)'}` "
        f"(source: {incident_source})"
    )
    lines.append(f"- Home (corporate) email domain: `{home_domain or '(not resolved)'}`")
    lines.append(f"- Actors observed: {len(actors_public)}")
    lines.append("")

    if incident_source == "fallback-72h":
        lines.append(
            "> WARNING: no explicit --incident-window-start and no timestamp "
            "hint found in scan-errors.txt or activity-pagination.log. "
            f"Using last {_FALLBACK_WINDOW_HOURS} hours of timeline as a "
            "best-effort fallback window. Treat anomaly flags with caution."
        )
        lines.append("")

    lines.append("## Owners")
    lines.append("")
    lines.append("| Actor | Email | Primary-owner env count | Backup-owner projects |")
    lines.append("|---|---|---|---|")
    for a in sorted(
        actors_public,
        key=lambda x: (
            -int(x.get("primary_owner_env_count") or 0),
            -len(x.get("backup_owner_projects") or []),
            x.get("key") or "",
        ),
    )[:50]:
        bpk = ", ".join(a.get("backup_owner_projects") or []) or "-"
        lines.append(
            f"| `{a['key']}` | `{a.get('email') or '-'}` | "
            f"{a.get('primary_owner_env_count', 0)} | {bpk} |"
        )
    lines.append("")

    lines.append("## Anomaly flags (incident window)")
    lines.append("")
    flagged = [a for a in actors_public if (a.get("anomalies") or {}).get("flags")]
    if not flagged:
        lines.append("_No actors flagged._")
        lines.append("")
    else:
        lines.append("| Actor | Flags | Details |")
        lines.append("|---|---|---|")
        for a in sorted(flagged, key=lambda x: x.get("key") or ""):
            an = a["anomalies"]
            flag_str = ", ".join(an.get("flags") or [])
            detail_bits: list[str] = []
            if an.get("novel_events"):
                detail_bits.append("novel events: " + ", ".join(an["novel_events"][:5]))
            if an.get("novel_time_buckets"):
                detail_bits.append(
                    "novel buckets (wd:hh): " + ", ".join(an["novel_time_buckets"][:5])
                )
            if an.get("domain_flags"):
                detail_bits.append(
                    f"domain={an.get('email_domain') or '-'} ({', '.join(an['domain_flags'])})"
                )
            if an.get("novel_deployment_sources"):
                detail_bits.append(
                    "new sources: " + ", ".join(an["novel_deployment_sources"])
                )
            if an.get("novel_deployment_creator_uids"):
                detail_bits.append(
                    f"new creator.uids: {len(an['novel_deployment_creator_uids'])}"
                )
            lines.append(
                f"| `{a['key']}` | {flag_str} | " + "; ".join(detail_bits) + " |"
            )
        lines.append("")

    lines.append("## Deployment anomalies (per project)")
    lines.append("")
    if not per_project:
        lines.append("_No deployment evidence loaded._")
        lines.append("")
    else:
        lines.append(
            "| Project | Total deploys | Unique creator.uids | Source diversity | "
            "In-window unique creator.uids | In-window sources |"
        )
        lines.append("|---|---|---|---|---|---|")
        for name in sorted(per_project):
            p = per_project[name]
            src_div = len(p.get("sources") or {})
            in_src = ", ".join(sorted((p.get("in_window_sources") or {}).keys())) or "-"
            lines.append(
                f"| `{name}` | {p.get('total_deployments', 0)} | "
                f"{p.get('unique_creator_uids', 0)} | {src_div} | "
                f"{p.get('in_window_unique_creator_uids', 0)} | {in_src} |"
            )
        lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append("- Primary owner = env var `lastUpdatedBy` from env-metadata.json.")
    lines.append(
        "- Backup owner = most-frequent non-bot deployer over last 90 days, per project."
    )
    lines.append(
        "- Baselines span the 90 days prior to now; buckets are (weekday, hour-of-day) UTC."
    )
    lines.append(
        "- Anomaly flags describe deviation from baseline only — they are NOT attribution. "
        "See `references/analysis-methodology.md` §5 for attribution caution."
    )
    lines.append("")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "").splitlines()[0] if __doc__ else "",
    )
    parser.add_argument("--case", required=True, help="Case directory root")
    parser.add_argument(
        "--incident-window-start",
        dest="incident_window_start",
        default=None,
        help="ISO-8601 UTC timestamp marking the incident window start.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Compute but do not write per-actor.md / actors.json.",
    )
    args = parser.parse_args()

    case_dir = os.path.abspath(args.case)
    if not os.path.isdir(case_dir):
        print(f"per-actor-profile: --case not a directory: {case_dir}", file=sys.stderr)
        return 1

    timeline_path = os.path.join(case_dir, "analysis", "timeline.tsv")
    if not os.path.isfile(timeline_path):
        print(
            "per-actor-profile: analysis/timeline.tsv missing — run timeline-fuse.py first.",
            file=sys.stderr,
        )
        return 2

    now_utc = _dt.datetime.now(_dt.timezone.utc)

    # Incident window.
    incident_start: Optional[_dt.datetime] = None
    incident_source = "none"
    if args.incident_window_start:
        incident_start = _parse_iso(args.incident_window_start)
        if incident_start is None:
            print(
                f"per-actor-profile: --incident-window-start not ISO-8601: "
                f"{args.incident_window_start}",
                file=sys.stderr,
            )
            return 1
        incident_source = "explicit"
    else:
        inferred, src = _infer_incident_window_start(case_dir)
        if inferred is not None:
            incident_start = inferred
            incident_source = src
        else:
            incident_start = now_utc - _dt.timedelta(hours=_FALLBACK_WINDOW_HOURS)
            incident_source = "fallback-72h"

    # Build actor table from timeline first so every actor who acted is present.
    actors, earliest, latest = _build_actors_from_timeline(
        timeline_path, incident_start, now_utc
    )

    # Members (for home-domain resolution + display-name enrichment).
    members = _load_members(case_dir)
    for m in members:
        if not isinstance(m, dict):
            continue
        email = m.get("email") or ""
        uid = m.get("uid") or ""
        if not (email or uid):
            continue
        state = _get_or_make(actors, email=email, uid=uid)
        if state is None:
            continue
        name = m.get("name") or m.get("username") or ""
        if name:
            state.display_names.add(str(name))

    # Env + deployment ownership from per-project evidence.
    project_dirs = _iter_project_dirs(case_dir)
    _apply_env_ownership(actors, project_dirs)
    per_project = _apply_deployment_activity(
        actors, project_dirs, incident_start, now_utc
    )

    home_domain = _home_domain(members)

    actors_public: list[dict[str, Any]] = []
    for state in actors.values():
        anomalies = _compute_anomalies(state, home_domain)
        actors_public.append(_state_to_public(state, anomalies))

    actors_public.sort(key=lambda a: a["key"])

    out_json = {
        "generated_at": now_utc.isoformat(),
        "case": case_dir,
        "incident_window_start": incident_start.isoformat() if incident_start else None,
        "incident_window_source": incident_source,
        "timeline_bounds": {
            "earliest": earliest.isoformat() if earliest else None,
            "latest": latest.isoformat() if latest else None,
        },
        "home_domain": home_domain,
        "baseline_days": _BASELINE_DAYS,
        "per_project_deployment_stats": per_project,
        "actors": actors_public,
    }

    markdown = _render_markdown(
        actors_public, per_project, home_domain,
        incident_start, incident_source,
        (earliest, latest),
    )

    if args.dry_run:
        summary = {
            "actors": len(actors_public),
            "flagged_actors": sum(
                1 for a in actors_public if (a.get("anomalies") or {}).get("flags")
            ),
            "projects": len(per_project),
            "home_domain": home_domain,
            "incident_window_start": out_json["incident_window_start"],
            "incident_window_source": incident_source,
        }
        print(json.dumps(summary, indent=2))
        return 0

    analysis_dir = os.path.join(case_dir, "analysis")
    os.makedirs(analysis_dir, mode=0o700, exist_ok=True)
    json_path = os.path.join(analysis_dir, "actors.json")
    md_path = os.path.join(analysis_dir, "per-actor.md")

    try:
        atomic_write(
            json_path,
            json.dumps(out_json, indent=2, sort_keys=False) + "\n",
        )
    except FileExistsError:
        print(
            f"per-actor-profile: {json_path} already exists; refusing overwrite.",
            file=sys.stderr,
        )
        return 1
    try:
        atomic_write(md_path, markdown)
    except FileExistsError:
        print(
            f"per-actor-profile: {md_path} already exists; refusing overwrite.",
            file=sys.stderr,
        )
        return 1

    print(f"per-actor-profile: wrote {json_path}", file=sys.stderr)
    print(f"per-actor-profile: wrote {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
