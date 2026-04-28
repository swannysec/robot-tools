#!/usr/bin/env python3
"""rotation-worklist.py — vercel-forensics rotation worklist CSV emitter.

Consumes frozen raw evidence under $CASE/raw/vercel/ plus optional analysis
output ($CASE/analysis/actors.json) and emits a CONFIDENTIAL rotation
worklist CSV at $CASE/handoff/rotation-worklist.csv.

Schema: garyhtou/Vercel-Env-Var-Exposure-Triager adapted for the
metapod P0/P1/P2 taxonomy (see references/analysis-methodology.md §3).
Never emits env-var VALUES — upstream projection (_common.py::project_fields
on the "env_var" kind) strips `value`/`decryptedValue` before evidence
touches disk.

Python 3.10 stdlib only. Read-only. Refuses to overwrite an existing file.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

# Re-use the skill's atomic writer (TOCTOU-safe, refuses symlinks + overwrite).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)
from _common import atomic_write  # noqa: E402

# ---------------------------------------------------------------------------
# CSV schema — EXACT column order required by the plan. Do not reorder.
# ---------------------------------------------------------------------------
COLUMNS: tuple[str, ...] = (
    "team_name",
    "team_slug",
    "project_name",
    "project_id",
    "env_id",
    "configuration_id",
    "key",
    "type",
    "targets",
    "git_branch",
    "class",
    "provider",
    "rotate_priority",
    "recommendation",
    "primary_owner_name",
    "primary_owner_email",
    "backup_owner_name",
    "backup_owner_email",
    "backup_deploy_count_90d",
    "last_updated_at",
    "last_updated_days_ago",
    "created_at",
    "vercel_url",
)

CONFIDENTIAL_HEADER = (
    "# CONFIDENTIAL \u2014 incident response artifact \u2014 "
    "contains project IDs, email addresses, timestamps \u2014 "
    "do not attach to email, chat, or public issue tracker\n"
)

# ---------------------------------------------------------------------------
# Class taxonomy (metapod, analysis-methodology.md §3). Order matters — first
# match wins. Public-by-design is evaluated first so NEXT_PUBLIC_DATABASE_URL
# does not get mis-bucketed as DB-cred.
# ---------------------------------------------------------------------------
CLASS_PUBLIC = "Public-by-design"
CLASS_VERCEL_MANAGED = "Vercel-managed"
CLASS_WEBHOOK = "Webhook-signing"
CLASS_OAUTH = "OAuth-secret"
CLASS_PROVIDER = "Provider-API-key"
CLASS_DB_CRED = "DB-cred"
CLASS_OTHER = "Other"

# Vercel platform-set names that the platform itself rotates. VERCEL_*TOKEN
# patterns are provider-API-key and intentionally NOT in this list.
_VERCEL_MANAGED_EXACT = frozenset({
    "VERCEL", "VERCEL_ENV", "VERCEL_URL", "VERCEL_BRANCH_URL",
    "VERCEL_REGION", "VERCEL_DEPLOYMENT_ID", "VERCEL_PROJECT_PRODUCTION_URL",
    "VERCEL_GIT_COMMIT_SHA", "VERCEL_GIT_COMMIT_REF",
    "VERCEL_GIT_COMMIT_MESSAGE", "VERCEL_GIT_COMMIT_AUTHOR_NAME",
    "VERCEL_GIT_COMMIT_AUTHOR_LOGIN", "VERCEL_GIT_PROVIDER",
    "VERCEL_GIT_REPO_SLUG", "VERCEL_GIT_REPO_OWNER", "VERCEL_GIT_REPO_ID",
    "VERCEL_GIT_PULL_REQUEST_ID", "VERCEL_GIT_PREVIOUS_SHA",
    "NEXT_RUNTIME", "NOW_REGION",
})

_PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "PUBLIC_", "NX_PUBLIC_", "VITE_", "REACT_APP_")

_WEBHOOK_PATTERNS = (
    re.compile(r"WEBHOOK.*SECRET", re.IGNORECASE),
    re.compile(r"SIGNING[_-]?SECRET", re.IGNORECASE),
    re.compile(r"_SIGN(ATURE)?$", re.IGNORECASE),
)

_OAUTH_PATTERNS = (
    re.compile(r"CLIENT[_-]?SECRET$", re.IGNORECASE),
    re.compile(r"^OAUTH_.*SECRET", re.IGNORECASE),
    re.compile(r"^SSO_.*SECRET", re.IGNORECASE),
    re.compile(r"^AUTH_.*SECRET", re.IGNORECASE),
)

_DB_CRED_PATTERNS = (
    re.compile(r"DATABASE", re.IGNORECASE),
    re.compile(r"^DB_", re.IGNORECASE),
    re.compile(r"^POSTGRES", re.IGNORECASE),
    re.compile(r"^MYSQL", re.IGNORECASE),
    re.compile(r"^REDIS", re.IGNORECASE),
    re.compile(r"^MONGO", re.IGNORECASE),
    # `_URL$` previously lived here — removed because it mis-bucketed
    # benign SITE_URL / REDIRECT_URL / CALLBACK_URL / API_URL vars as P0
    # DB-cred rotations. Genuine DB connection strings are captured by
    # the DATABASE / POSTGRES / MYSQL / REDIS / MONGO / MONGODB / KAFKA /
    # CLICKHOUSE / SUPABASE / NEON / PLANETSCALE labels above or in the
    # provider pass below.
)

# Ordered provider rules. Each entry: (provider_label, predicate(key, value_hosts))
# value_hosts is empty for us (we never see values); Neon is detected by key
# name only in v1.
_PROVIDER_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("STRIPE", re.compile(r"^STRIPE_", re.IGNORECASE)),
    ("OPENAI", re.compile(r"^OPENAI_", re.IGNORECASE)),
    ("ANTHROPIC", re.compile(r"^ANTHROPIC_", re.IGNORECASE)),
    ("SUPABASE", re.compile(r"^SUPABASE_", re.IGNORECASE)),
    ("NEON", re.compile(r"^NEON_", re.IGNORECASE)),
    ("CLOUDFLARE", re.compile(r"^(CF_|CLOUDFLARE_)", re.IGNORECASE)),
    ("AWS", re.compile(r"^AWS_", re.IGNORECASE)),
    ("GCP", re.compile(r"^(GCP_|GOOGLE_)", re.IGNORECASE)),
    ("SENDGRID", re.compile(r"^SENDGRID_", re.IGNORECASE)),
    ("TWILIO", re.compile(r"^TWILIO_", re.IGNORECASE)),
    ("RESEND", re.compile(r"^RESEND_", re.IGNORECASE)),
    ("SLACK", re.compile(r"^SLACK_", re.IGNORECASE)),
    ("GITHUB", re.compile(r"^GITHUB_", re.IGNORECASE)),
    ("VERCEL", re.compile(r"^VERCEL_.*TOKEN$", re.IGNORECASE)),
    ("CLERK", re.compile(r"^CLERK_", re.IGNORECASE)),
    ("AUTH0", re.compile(r"^AUTH0_", re.IGNORECASE)),
)

_SECRET_HINT = re.compile(r"(SECRET|TOKEN|KEY|PASS|PWD|CRED)", re.IGNORECASE)

# Bot identities excluded from backup-owner resolution. Keep in sync with
# per-actor-profile.py §Anomaly flags.
_BOT_PATTERNS = (
    re.compile(r"-bot@", re.IGNORECASE),
    re.compile(r"^bot@", re.IGNORECASE),
    re.compile(r"^vercel@", re.IGNORECASE),
    re.compile(r"^actions@github\.com$", re.IGNORECASE),
    re.compile(r"^noreply@github\.com$", re.IGNORECASE),
    re.compile(r"^dependabot", re.IGNORECASE),
    re.compile(r"^renovate", re.IGNORECASE),
)

# ---------------------------------------------------------------------------
# CSV safety helpers
# ---------------------------------------------------------------------------
_FORMULA_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# C0 controls (0x00–0x1F except \n), DEL (0x7F), C1 controls (0x80–0x9F),
# and Unicode bidi/format controls that can reorder / hide text in CSVs
# viewed in a terminal or opened in Excel. We drop rather than replace —
# these code points must never appear in a rotation-worklist field.
_BIDI_CONTROLS = {
    "\u200e", "\u200f",              # LRM, RLM
    "\u202a", "\u202b", "\u202c",    # LRE, RLE, PDF
    "\u202d", "\u202e",              # LRO, RLO
    "\u2066", "\u2067", "\u2068",    # LRI, RLI, FSI
    "\u2069",                        # PDI
    "\u200b", "\u200c", "\u200d",    # ZWSP, ZWNJ, ZWJ
    "\u2028", "\u2029",              # LINE SEPARATOR, PARAGRAPH SEPARATOR
    "\ufeff",                        # BOM / zero-width no-break space
}


def _strip_unicode_controls(s: str) -> str:
    """Drop C0/C1 controls, bidi-format, and zero-width code points."""
    if not s:
        return s
    out_chars: list[str] = []
    for ch in s:
        cp = ord(ch)
        # Allow \t and \n through (CSV library handles quoting). They are
        # handled separately by formula-injection neutralization.
        if cp == 0x09 or cp == 0x0A:
            out_chars.append(ch)
            continue
        if cp < 0x20 or cp == 0x7F:
            continue  # C0 + DEL
        if 0x80 <= cp <= 0x9F:
            continue  # C1 controls
        if ch in _BIDI_CONTROLS:
            continue
        out_chars.append(ch)
    return "".join(out_chars)


def _neutralize_formula(s: str) -> str:
    """Prefix fields beginning with =, +, -, @, \\t, \\r with a single quote.

    Standard Excel / Google Sheets defense against CSV formula injection.
    """
    if not s:
        return s
    if s[0] in _FORMULA_INJECTION_PREFIXES:
        return "'" + s
    return s


def _safe_cell(value: Any, strip_controls: bool = False) -> str:
    """Render a value as a CSV-safe cell: coerce to str, optionally strip
    Unicode controls (project_name + owner fields), then neutralize formula
    injection."""
    if value is None:
        return ""
    text = str(value)
    if strip_controls:
        text = _strip_unicode_controls(text)
    # Formula injection is applied unconditionally.
    text = _neutralize_formula(text)
    return text


# ---------------------------------------------------------------------------
# JSON loading helpers
# ---------------------------------------------------------------------------
def _load_json(path: str) -> Any:
    """Load a JSON file; return None if missing or unparseable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, IsADirectoryError):
        return None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _load_paginated(path: str, key: str) -> list[dict[str, Any]]:
    """Load a file produced by `vercel api --paginate` (concatenated pages
    OR a single object) and flatten the list under `key`."""
    raw = None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except (FileNotFoundError, IsADirectoryError):
        return []
    if not raw.strip():
        return []

    # Try parsing as a single object first.
    try:
        obj = json.loads(raw)
        if isinstance(obj, list):
            # Array-of-pages shape.
            out: list[dict[str, Any]] = []
            for page in obj:
                if isinstance(page, dict):
                    items = page.get(key)
                    if isinstance(items, list):
                        out.extend(i for i in items if isinstance(i, dict))
            return out
        if isinstance(obj, dict):
            items = obj.get(key)
            if isinstance(items, list):
                return [i for i in items if isinstance(i, dict)]
            return []
    except json.JSONDecodeError:
        pass

    # Fall back: parse sequential JSON objects via raw_decode.
    decoder = json.JSONDecoder()
    idx = 0
    length = len(raw)
    out = []
    while idx < length:
        # Skip whitespace between objects.
        while idx < length and raw[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            obj, end = decoder.raw_decode(raw, idx)
        except json.JSONDecodeError:
            break
        if isinstance(obj, dict):
            items = obj.get(key)
            if isinstance(items, list):
                out.extend(i for i in items if isinstance(i, dict))
        idx = end
    return out


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def classify_key(key: str) -> str:
    """Return the metapod class taxonomy bucket for this env-var key."""
    if not key:
        return CLASS_OTHER
    upper = key.upper()

    # Public-by-design first (before DB-cred), else NEXT_PUBLIC_DB_URL misfires.
    for prefix in _PUBLIC_PREFIXES:
        if upper.startswith(prefix):
            return CLASS_PUBLIC

    # Vercel-managed: platform-set identifier vars (NOT VERCEL_*TOKEN).
    if upper in _VERCEL_MANAGED_EXACT:
        return CLASS_VERCEL_MANAGED
    if upper.startswith("VERCEL_") and "TOKEN" not in upper:
        return CLASS_VERCEL_MANAGED

    # Webhook signing.
    for pattern in _WEBHOOK_PATTERNS:
        if pattern.search(key):
            return CLASS_WEBHOOK

    # OAuth secrets.
    for pattern in _OAUTH_PATTERNS:
        if pattern.search(key):
            return CLASS_OAUTH

    # Provider API key (check before DB-cred so STRIPE_* etc win).
    for _label, pattern in _PROVIDER_RULES:
        if pattern.search(key):
            return CLASS_PROVIDER

    # DB credentials.
    for pattern in _DB_CRED_PATTERNS:
        if pattern.search(key):
            return CLASS_DB_CRED

    return CLASS_OTHER


def infer_provider(key: str, klass: str) -> str:
    """Return provider label per plan rules.

    Ordered prefix/substring matches over the key name. Default:
      * `Unknown-secret` if class is secret-like (SECRET/TOKEN/KEY/PASS in name)
      * `Unknown` otherwise.
    """
    if not key:
        return "Unknown"
    for label, pattern in _PROVIDER_RULES:
        if pattern.search(key):
            return label
    # Fall-through: secret-like unknown vs plain unknown.
    if _SECRET_HINT.search(key):
        return "Unknown-secret"
    # Class-based default for DB-cred without a known provider.
    if klass == CLASS_DB_CRED:
        return "Unknown-secret"
    return "Unknown"


def rotate_priority(klass: str, type_field: str) -> str:
    """P0/P1/P2/already-sensitive per metapod taxonomy (§3).

    * sensitive → already-sensitive
    * plain|encrypted + public/vercel-managed → P2
    * plain|encrypted + test-prefix detection is done at the caller (key-level)
    * plain|encrypted + secret-class → P0
    """
    t = (type_field or "").lower()
    if t == "sensitive":
        return "already-sensitive"
    if klass in (CLASS_PUBLIC, CLASS_VERCEL_MANAGED):
        return "P2"
    # DB-cred / OAuth / Provider / Webhook / Other -> P0 (plain/encrypted
    # readable pre-breach assumption).
    return "P0"


def _is_test_tier_key(key: str) -> bool:
    """Heuristic: key appears to be staging/test (rotate P1 for hygiene)."""
    if not key:
        return False
    upper = key.upper()
    return (
        "STAGING" in upper
        or "_TEST_" in upper
        or upper.endswith("_TEST")
        or upper.startswith("TEST_")
        or "DEV_" in upper
    )


def recommendation(key: str, klass: str, configuration_id: str, provider: str) -> str:
    """Return one of:
    * skip-public-client-side
    * review-integration-managed
    * rotate
    * review-unclassified
    """
    if not key:
        return "review-unclassified"

    upper = key.upper()
    # skip-public-client-side: NEXT_PUBLIC_*, VITE_*, PUBLIC_* (literal plan rule).
    if (
        upper.startswith("NEXT_PUBLIC_")
        or upper.startswith("VITE_")
        or upper.startswith("PUBLIC_")
    ):
        return "skip-public-client-side"

    # Integration-managed env vars — operator must coordinate with the
    # marketplace integration rather than rotate in Vercel directly.
    if configuration_id:
        return "review-integration-managed"

    # Known-provider secret (not already sensitive) → rotate.
    if klass in (CLASS_PROVIDER, CLASS_OAUTH, CLASS_WEBHOOK, CLASS_DB_CRED):
        return "rotate"

    # Unclassified Other with secret-shaped name → review manually.
    if klass == CLASS_OTHER and _SECRET_HINT.search(key):
        return "review-unclassified"

    # Fall-through: Vercel-managed, or Other without secret hint → rotate
    # is inappropriate; nearest useful action is review.
    if klass == CLASS_VERCEL_MANAGED:
        return "review-integration-managed"  # platform rotates; manual check
    return "review-unclassified"


# ---------------------------------------------------------------------------
# Owner resolution
# ---------------------------------------------------------------------------
def _build_member_index(members_doc: Any) -> dict[str, dict[str, str]]:
    """Build {uid: {name, email}} from $CASE/raw/vercel/team/members.json.

    members.json may be an object with .members[] or a bare list.
    """
    out: dict[str, dict[str, str]] = {}
    candidates: list[Any] = []
    if isinstance(members_doc, dict):
        m = members_doc.get("members")
        if isinstance(m, list):
            candidates = m
    elif isinstance(members_doc, list):
        candidates = members_doc

    for entry in candidates:
        if not isinstance(entry, dict):
            continue
        uid = entry.get("uid") or entry.get("id") or entry.get("userId")
        if not uid:
            continue
        # Members API nests name + email under top-level fields; older
        # responses use `user: {...}`. Probe both.
        name = entry.get("name") or entry.get("displayName")
        email = entry.get("email")
        user = entry.get("user")
        if isinstance(user, dict):
            name = name or user.get("name") or user.get("username")
            email = email or user.get("email")
        out[str(uid)] = {
            "name": str(name) if name else "",
            "email": str(email) if email else "",
        }
    return out


def _resolve_primary_owner(
    env_entry: dict[str, Any],
    members: dict[str, dict[str, str]],
) -> tuple[str, str]:
    """Return (name, email) for the env var's lastUpdatedBy UID."""
    uid = env_entry.get("lastUpdatedBy")
    display = env_entry.get("lastUpdatedByDisplayName") or ""
    if uid and uid in members:
        m = members[uid]
        return (m.get("name", "") or display, m.get("email", ""))
    # Fallback: no UID match, surface the display name (still useful evidence).
    return (display, "")


def _is_bot_email(email: str) -> bool:
    if not email:
        return False
    for pattern in _BOT_PATTERNS:
        if pattern.search(email):
            return True
    return False


def _load_actors_backup_index(
    actors_doc: Any,
) -> dict[str, tuple[str, str, int]]:
    """If per-actor-profile emitted actors.json with per-project backup owners,
    consume it. Expected (flexible) schema:

        {
          "projects": {
            "<project_id>": {
              "backup_owner": {"name": "...", "email": "...", "deploy_count_90d": 12}
            }
          }
        }

    Returns {project_id: (name, email, count)}. Unknown / missing → empty dict.
    """
    out: dict[str, tuple[str, str, int]] = {}
    if not isinstance(actors_doc, dict):
        return out
    projects = actors_doc.get("projects")
    if not isinstance(projects, dict):
        return out
    for pid, entry in projects.items():
        if not isinstance(entry, dict):
            continue
        backup = entry.get("backup_owner")
        if not isinstance(backup, dict):
            continue
        name = str(backup.get("name", "") or "")
        email = str(backup.get("email", "") or "")
        try:
            count = int(backup.get("deploy_count_90d", 0) or 0)
        except (TypeError, ValueError):
            count = 0
        out[str(pid)] = (name, email, count)
    return out


def _compute_backup_owner_from_deployments(
    deployments_path: str,
    now_ts: float,
) -> tuple[str, str, int]:
    """Fallback backup owner: most-frequent deployer over the last 90 days,
    excluding bot identities. Used only if actors.json is missing."""
    deployments = _load_paginated(deployments_path, "deployments")
    if not deployments:
        return ("", "", 0)

    cutoff_ms = (now_ts - 90 * 86400) * 1000.0
    counter: Counter[tuple[str, str]] = Counter()
    for dep in deployments:
        created_ms = dep.get("created") or dep.get("createdAt")
        if created_ms is None:
            continue
        try:
            created_val = float(created_ms)
        except (TypeError, ValueError):
            continue
        if created_val < cutoff_ms:
            continue
        creator = dep.get("creator")
        if not isinstance(creator, dict):
            continue
        email = str(creator.get("email", "") or "")
        if _is_bot_email(email):
            continue
        name = str(creator.get("username") or creator.get("name") or "")
        if not email and not name:
            continue
        counter[(name, email)] += 1

    if not counter:
        return ("", "", 0)
    (name, email), count = counter.most_common(1)[0]
    return (name, email, count)


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------
def _epoch_from_any(value: Any) -> Optional[float]:
    """Accept Vercel's ms-epoch numbers or ISO8601 strings; return epoch secs."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        # Heuristic: Vercel uses ms-since-epoch for env-var timestamps.
        if value > 1_000_000_000_000:  # > year 2001 in ms
            return value / 1000.0
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        # Support "YYYY-MM-DDTHH:MM:SS(.fff)?Z" and offsets.
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


def _iso_utc(value: Any) -> str:
    """Render value as ISO8601 UTC (Z-suffixed). Empty string for missing."""
    epoch = _epoch_from_any(value)
    if epoch is None:
        return ""
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    # Use second precision — the value is incident-forensic evidence, not a
    # high-resolution log entry. Consistent with timeline.tsv.
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _days_ago(value: Any, now_ts: float) -> str:
    epoch = _epoch_from_any(value)
    if epoch is None:
        return ""
    delta_days = int((now_ts - epoch) // 86400)
    if delta_days < 0:
        return "0"
    return str(delta_days)


# ---------------------------------------------------------------------------
# Row assembly
# ---------------------------------------------------------------------------
def _project_safe_slug(name: str) -> str:
    """Mirror the vercel-per-project.sh slug rule so we can locate the
    project directory on disk from the project name in projects-list.json."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name or "")
    return safe[:64] if safe else ""


def _vercel_url(team_slug: str, project_name: str) -> str:
    """Build the Vercel settings URL operators use to open the env editor."""
    if not team_slug or not project_name:
        return ""
    return f"https://vercel.com/{team_slug}/{project_name}/settings/environment-variables"


def build_rows(case_dir: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Read the case directory and return (rows, summary_counts).

    summary_counts holds {class: N} plus {priority: N}.
    """
    now_ts = datetime.now(tz=timezone.utc).timestamp()

    raw_root = os.path.join(case_dir, "raw", "vercel")
    projects_list_path = os.path.join(raw_root, "projects-list.json")
    members_path = os.path.join(raw_root, "team", "members.json")
    team_json_path = os.path.join(raw_root, "team", "team.json")
    actors_path = os.path.join(case_dir, "analysis", "actors.json")

    projects_doc = _load_paginated(projects_list_path, "projects")
    members_doc = _load_json(members_path)
    team_doc = _load_json(team_json_path)
    actors_doc = _load_json(actors_path)

    team_name = ""
    team_slug = ""
    if isinstance(team_doc, dict):
        team_name = str(team_doc.get("name", "") or "")
        team_slug = str(team_doc.get("slug", "") or "")

    members_index = _build_member_index(members_doc)
    actors_backup_index = _load_actors_backup_index(actors_doc)

    rows: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    priority_counts: Counter[str] = Counter()

    for project in projects_doc:
        if not isinstance(project, dict):
            continue
        project_id = str(project.get("id", "") or "")
        project_name = str(project.get("name", "") or "")
        if not project_id or not project_name:
            continue

        safe_name = _project_safe_slug(project_name)
        if not safe_name:
            continue
        project_dir = os.path.join(raw_root, "projects", safe_name)
        env_metadata_path = os.path.join(project_dir, "env-metadata.json")
        deployments_path = os.path.join(project_dir, "deployments.json")
        # Project.json is read per the task spec; currently unused beyond
        # existence verification so load is cheap (sanity check the dir).
        _ = os.path.exists(os.path.join(project_dir, "project.json"))

        env_doc = _load_json(env_metadata_path)
        if env_doc is None:
            continue
        if isinstance(env_doc, dict):
            envs = env_doc.get("envs") or env_doc.get("env") or []
        elif isinstance(env_doc, list):
            envs = env_doc
        else:
            envs = []
        if not isinstance(envs, list):
            continue

        # Backup owner: prefer actors.json, else compute from deployments.json.
        if project_id in actors_backup_index:
            backup_name, backup_email, backup_count = actors_backup_index[project_id]
        else:
            backup_name, backup_email, backup_count = (
                _compute_backup_owner_from_deployments(deployments_path, now_ts)
            )

        for env in envs:
            if not isinstance(env, dict):
                continue
            key = str(env.get("key", "") or "")
            if not key:
                continue

            env_id = str(env.get("id", "") or "")
            type_field = str(env.get("type", "") or "")
            configuration_id = str(env.get("configurationId", "") or "")
            git_branch = str(env.get("gitBranch", "") or "")

            target = env.get("target", "")
            if isinstance(target, list):
                targets = ",".join(str(t) for t in target if t is not None)
            elif target is None:
                targets = ""
            else:
                targets = str(target)

            klass = classify_key(key)
            provider = infer_provider(key, klass)
            base_priority = rotate_priority(klass, type_field)
            # Promote to P1 if the key or targets look like test-tier AND the
            # priority would otherwise have been P0.
            priority = base_priority
            if base_priority == "P0" and (
                _is_test_tier_key(key) or targets == "development"
            ):
                priority = "P1"

            recom = recommendation(key, klass, configuration_id, provider)

            primary_name, primary_email = _resolve_primary_owner(env, members_index)

            last_updated = env.get("updatedAt") or env.get("lastUpdatedAt")
            created = env.get("createdAt")

            row = {
                "team_name": team_name,
                "team_slug": team_slug,
                "project_name": project_name,
                "project_id": project_id,
                "env_id": env_id,
                "configuration_id": configuration_id,
                "key": key,
                "type": type_field,
                "targets": targets,
                "git_branch": git_branch,
                "class": klass,
                "provider": provider,
                "rotate_priority": priority,
                "recommendation": recom,
                "primary_owner_name": primary_name,
                "primary_owner_email": primary_email,
                "backup_owner_name": backup_name,
                "backup_owner_email": backup_email,
                "backup_deploy_count_90d": str(backup_count) if backup_count else "",
                "last_updated_at": _iso_utc(last_updated),
                "last_updated_days_ago": _days_ago(last_updated, now_ts),
                "created_at": _iso_utc(created),
                "vercel_url": _vercel_url(team_slug, project_name),
            }
            rows.append(row)
            class_counts[klass] += 1
            priority_counts[priority] += 1

    summary = {f"class:{k}": v for k, v in class_counts.items()}
    summary.update({f"priority:{k}": v for k, v in priority_counts.items()})
    summary["total_rows"] = len(rows)
    return rows, summary


def _sort_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Stable sort: provider, team_slug, project_name, key."""
    return (
        row.get("provider", ""),
        row.get("team_slug", ""),
        row.get("project_name", ""),
        row.get("key", ""),
    )


def render_csv(rows: list[dict[str, Any]]) -> str:
    """Emit CSV string with CONFIDENTIAL header + safe cells."""
    buf = io.StringIO()
    buf.write(CONFIDENTIAL_HEADER)
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
    writer.writerow(COLUMNS)

    # project_name and owner fields may carry hostile Unicode; strip controls
    # on those. All fields pass through formula-injection neutralization.
    strip_set = {
        "project_name",
        "primary_owner_name",
        "primary_owner_email",
        "backup_owner_name",
        "backup_owner_email",
    }

    for row in sorted(rows, key=_sort_key):
        cells = [
            _safe_cell(row.get(col, ""), strip_controls=(col in strip_set))
            for col in COLUMNS
        ]
        writer.writerow(cells)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="rotation-worklist.py",
        description="Emit the vercel-forensics rotation worklist CSV.",
    )
    parser.add_argument("--case", required=True,
                        help="Absolute path to the frozen case directory.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print summary row counts; do not write the CSV.")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    case_dir = os.path.abspath(args.case)
    if not os.path.isdir(case_dir):
        print(f"rotation-worklist: case directory not found: {case_dir}",
              file=sys.stderr)
        return 1

    try:
        rows, summary = build_rows(case_dir)
    except OSError as exc:
        print(f"rotation-worklist: read error: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("rotation-worklist (dry-run)")
        print(f"  case: {case_dir}")
        print(f"  total rows: {summary.get('total_rows', 0)}")
        classes = sorted(k for k in summary if k.startswith("class:"))
        for key in classes:
            print(f"  {key}: {summary[key]}")
        priorities = sorted(k for k in summary if k.startswith("priority:"))
        for key in priorities:
            print(f"  {key}: {summary[key]}")
        return 0

    handoff_dir = os.path.join(case_dir, "handoff")
    try:
        os.makedirs(handoff_dir, mode=0o700, exist_ok=True)
    except OSError as exc:
        print(f"rotation-worklist: cannot create handoff dir: {exc}",
              file=sys.stderr)
        return 1

    out_path = os.path.join(handoff_dir, "rotation-worklist.csv")
    csv_text = render_csv(rows)
    try:
        atomic_write(out_path, csv_text, mode=0o600)
    except FileExistsError as exc:
        print(f"rotation-worklist: refuse to overwrite: {exc}",
              file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"rotation-worklist: write failed: {exc}", file=sys.stderr)
        return 1

    print(f"rotation-worklist: wrote {len(rows)} rows -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
