#!/usr/bin/env python3
"""Phase 1a triage: consume a FROZEN case dir (read-only) and emit
`<case>/analysis/triage.md` summarizing the 8 interpretive dimensions defined
in `references/analysis-methodology.md §1a/§2/§3`.

Section layout (matches plan):
  1. Event-type counters      — top-20 Vercel activity types + top-20 GitHub audit actions
  2. Security-relevant slices — exfil, blocked deploys, member churn, high-signal GitHub actions
  3. Per-project env-var type counts (sensitive / encrypted / plain / system)
  4. Env-var class taxonomy   — metapod key-name regex rules (§3)
  5. P0/P1/P2 rotate-priority per env var
  6. Account-surface audit table (tokens, integrations, webhooks, log drains, domains)
  7. Local CLI hygiene note   — stat ~/Library/Application Support/com.vercel.cli/auth.json
  8. Runtime-log availability finding — empty log drains + >24h window => MEDIUM

Args:
  --case <path>  required. Must already contain a frozen raw/ tree.
  --dry-run      print what would be written; emit nothing to disk.

Constraints:
  - Python 3.10 stdlib only.
  - Write via `_common.atomic_write` (never direct open-for-write).
  - Raw evidence is read-only (freeze already set a-w). We only read.
  - Idempotent: removes existing analysis/triage.md before rewriting.
  - Partial-failure: a missing/unparseable raw file yields an in-section note
    rather than aborting. Layout-level surprises append to `scan-errors.txt`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

# _common lives next to this script.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import atomic_write  # noqa: E402

# --- Env-var class taxonomy (metapod; see analysis-methodology.md §3) --------
#
# Order matters: the first matching class wins. Public-by-design is checked
# BEFORE Provider-API-key / DB-cred so a `NEXT_PUBLIC_STRIPE_KEY` lands in
# Public rather than Provider-API-key.

_CLASS_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Public-by-design", re.compile(
        r"^(NEXT_PUBLIC_|PUBLIC_|NX_PUBLIC_|NUXT_PUBLIC_|REACT_APP_|VITE_|GATSBY_|EXPO_PUBLIC_)",
    )),
    ("Vercel-managed", re.compile(
        r"^(VERCEL_(?!.*TOKEN)|NEXT_RUNTIME$|NOW_)",
    )),
    ("Webhook-signing", re.compile(
        r"(WEBHOOK.*SECRET|SIGNING_SECRET|WEBHOOK_SIGN)",
        re.IGNORECASE,
    )),
    ("OAuth-secret", re.compile(
        r"(CLIENT_SECRET|OAUTH.*SECRET|SSO.*SECRET|AUTH_SECRET)",
        re.IGNORECASE,
    )),
    # `_URL$` intentionally NOT matched here — it over-bucketed benign vars
    # like SITE_URL / REDIRECT_URL / CALLBACK_URL / API_URL as DB-cred.
    ("DB-cred", re.compile(
        r"(DATABASE|_DB_|POSTGRES|MYSQL|REDIS|MONGO|KAFKA|RABBITMQ|CLICKHOUSE|SUPABASE|NEON|PLANETSCALE)",
        re.IGNORECASE,
    )),
    ("Provider-API-key", re.compile(
        r"^(STRIPE|OPENAI|ANTHROPIC|AWS|GCP|GOOGLE|AZURE|SENDGRID|TWILIO|RESEND|"
        r"SLACK|DISCORD|GITHUB_TOKEN|VERCEL_.*TOKEN|CLERK|AUTH0|OKTA|DATADOG|"
        r"SENTRY|LINEAR|NOTION|LOOPS|POSTMARK|MAILGUN|CLOUDFLARE|VERCEL_TOKEN)",
        re.IGNORECASE,
    )),
)

# Test-tier prefixes — applied to key names and (where the metadata exposes
# them) target/value markers. We don't read values from env-metadata.json
# because redacted metadata does not contain values; the check runs on keys.
_TEST_TIER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"_TEST($|_)", re.IGNORECASE),
    re.compile(r"^(SK_TEST_|PK_TEST_|RK_TEST_)", re.IGNORECASE),
    re.compile(r"STAGING|PREVIEW_ONLY|DEV_ONLY", re.IGNORECASE),
)

# GitHub audit actions considered high-signal per §1a.
_GH_HIGH_SIGNAL_PREFIXES: tuple[str, ...] = (
    "protected_branch.policy_override",
    "hook.",
    "integration_installation.create",
    "personal_access_token.",
    "repo.create_actions_secret",
)

# Vercel-activity types signifying team/project-member churn.
_CHURN_TYPES: tuple[str, ...] = (
    "team-member-joined",
    "team-member-removed",
    "team-member-invited",
    "team-role-changed",
    "project-member-added",
    "project-member-removed",
)

# Vercel-activity exfil + blocked-deploy type markers. We match by substring
# because Vercel emits a dotted-hierarchy like `env-variable-read:cli:env:pull`
# and sometimes `.` vs `:` variants.
_EXFIL_RE = re.compile(r"env[-_]variable[-_]read.*cli", re.IGNORECASE)
_BLOCKED_DEPLOY_RE = re.compile(r"deployment[-_]creation[-_]blocked", re.IGNORECASE)


# --- I/O helpers -------------------------------------------------------------


def _append_scan_error(case_dir: str, rel_path: str, reason: str) -> None:
    """Append a triage note to $CASE/scan-errors.txt (TSV, same format as redact.py)."""
    line = f"triage\t{rel_path}\tparse\t{reason}\n".encode("utf-8")
    path = os.path.join(case_dir, "scan-errors.txt")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_json(path: str) -> tuple[Any, str | None]:
    """Return (obj, None) on success, (None, reason) on missing/parse error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "missing"
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable:{exc.__class__.__name__}"


def _iter_jsonl(path: str) -> Iterable[tuple[int, dict[str, Any] | None, str | None]]:
    """Yield (line_no, obj, err) per line. Missing file -> one (0, None, 'missing')."""
    try:
        fh = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        yield 0, None, "missing"
        return
    except OSError as exc:
        yield 0, None, f"unreadable:{exc.__class__.__name__}"
        return
    try:
        for idx, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                yield idx, json.loads(line), None
            except json.JSONDecodeError as exc:
                yield idx, None, f"parse:line-{idx}:{exc.msg}"
    finally:
        fh.close()


# --- Classification ---------------------------------------------------------


def _classify_key(key: str) -> str:
    for label, pattern in _CLASS_RULES:
        if pattern.search(key):
            return label
    return "Other"


def _is_test_tier(key: str) -> bool:
    return any(p.search(key) for p in _TEST_TIER_PATTERNS)


def _priority(key: str, env_type: str, klass: str) -> str:
    """Map (key, type, class) -> one of P0 / P1 / P2 / already-sensitive."""
    if env_type == "sensitive":
        return "already-sensitive"
    if klass in ("Public-by-design", "Vercel-managed"):
        return "P2"
    if _is_test_tier(key):
        return "P1"
    # Non-public secret stored as encrypted/plain/system.
    if env_type in ("encrypted", "plain", "system"):
        return "P0"
    # Unknown type — treat conservatively as P0 (value state unclear).
    return "P0"


# --- Section builders --------------------------------------------------------


def _event_counters(case_dir: str, out: list[str]) -> None:
    out.append("## 1. Event-type counters\n")

    # Vercel activity
    activity_path = os.path.join(case_dir, "raw", "vercel", "activity.jsonl")
    v_counter: Counter[str] = Counter()
    v_errors = 0
    v_missing = False
    for _, obj, err in _iter_jsonl(activity_path):
        if err == "missing":
            v_missing = True
            break
        if err is not None:
            v_errors += 1
            continue
        if isinstance(obj, dict):
            t = obj.get("type")
            if isinstance(t, str):
                v_counter[t] += 1

    out.append("### Top 20 Vercel activity types\n")
    if v_missing:
        out.append("- _note: `raw/vercel/activity.jsonl` missing — no counts available._\n")
    elif not v_counter:
        out.append("- _no events parsed._\n")
    else:
        out.append("| rank | type | count |")
        out.append("|---|---|---:|")
        for i, (k, c) in enumerate(v_counter.most_common(20), start=1):
            out.append(f"| {i} | `{k}` | {c} |")
        out.append("")
        if v_errors:
            out.append(f"- _parse errors: {v_errors} line(s) skipped; see scan-errors.txt._\n")

    # GitHub audit
    audit_path = os.path.join(case_dir, "raw", "github", "audit-log-180d.jsonl")
    g_counter: Counter[str] = Counter()
    g_errors = 0
    g_missing = False
    for _, obj, err in _iter_jsonl(audit_path):
        if err == "missing":
            g_missing = True
            break
        if err is not None:
            g_errors += 1
            continue
        if isinstance(obj, dict):
            a = obj.get("action")
            if isinstance(a, str):
                g_counter[a] += 1

    out.append("### Top 20 GitHub audit actions\n")
    if g_missing:
        out.append("- _note: `raw/github/audit-log-180d.jsonl` not present — skipping GitHub section._\n")
    elif not g_counter:
        out.append("- _no actions parsed._\n")
    else:
        out.append("| rank | action | count |")
        out.append("|---|---|---:|")
        for i, (k, c) in enumerate(g_counter.most_common(20), start=1):
            out.append(f"| {i} | `{k}` | {c} |")
        out.append("")
        if g_errors:
            out.append(f"- _parse errors: {g_errors} line(s) skipped; see scan-errors.txt._\n")


def _security_slices(case_dir: str, out: list[str]) -> None:
    out.append("## 2. Security-relevant slices\n")

    activity_path = os.path.join(case_dir, "raw", "vercel", "activity.jsonl")
    exfil: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    churn: list[dict[str, Any]] = []
    v_missing = False
    for _, obj, err in _iter_jsonl(activity_path):
        if err == "missing":
            v_missing = True
            break
        if err is not None or not isinstance(obj, dict):
            continue
        t = obj.get("type")
        if not isinstance(t, str):
            continue
        if _EXFIL_RE.search(t):
            exfil.append(obj)
        if _BLOCKED_DEPLOY_RE.search(t):
            blocked.append(obj)
        if t in _CHURN_TYPES:
            churn.append(obj)

    # Exfil
    out.append("### env-variable-read (CLI) — exfil channel\n")
    if v_missing:
        out.append("- _activity.jsonl missing — cannot enumerate._\n")
    elif not exfil:
        out.append("- _none observed._\n")
    else:
        out.append(f"- {len(exfil)} event(s):")
        out.append("")
        out.append("| createdAt | type | userId | principalId |")
        out.append("|---|---|---|---|")
        for ev in exfil[:100]:
            out.append(
                f"| {ev.get('createdAt', '?')} | `{ev.get('type', '?')}` "
                f"| {ev.get('userId', '?')} | {ev.get('principalId', '?')} |"
            )
        if len(exfil) > 100:
            out.append(f"- _truncated at 100 rows ({len(exfil)} total)._")
        out.append("")

    # Blocked deploys
    out.append("### deployment-creation-blocked\n")
    if v_missing:
        out.append("- _activity.jsonl missing — cannot enumerate._\n")
    elif not blocked:
        out.append("- _none observed._\n")
    else:
        out.append(f"- {len(blocked)} event(s):")
        out.append("")
        out.append("| createdAt | userId | payload.projectId | payload.commitSha |")
        out.append("|---|---|---|---|")
        for ev in blocked[:100]:
            payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
            out.append(
                f"| {ev.get('createdAt', '?')} | {ev.get('userId', '?')} "
                f"| {payload.get('projectId', '?')} | {payload.get('commitSha', '?')} |"
            )
        if len(blocked) > 100:
            out.append(f"- _truncated at 100 rows ({len(blocked)} total)._")
        out.append("")

    # Churn
    out.append("### Team / project member churn\n")
    if v_missing:
        out.append("- _activity.jsonl missing — cannot enumerate._\n")
    elif not churn:
        out.append("- _none observed._\n")
    else:
        out.append(f"- {len(churn)} event(s):")
        out.append("")
        out.append("| createdAt | type | userId |")
        out.append("|---|---|---|")
        for ev in churn[:100]:
            out.append(
                f"| {ev.get('createdAt', '?')} | `{ev.get('type', '?')}` | {ev.get('userId', '?')} |"
            )
        if len(churn) > 100:
            out.append(f"- _truncated at 100 rows ({len(churn)} total)._")
        out.append("")

    # GitHub high-signal
    audit_path = os.path.join(case_dir, "raw", "github", "audit-log-180d.jsonl")
    gh_hits: list[dict[str, Any]] = []
    gh_missing = False
    for _, obj, err in _iter_jsonl(audit_path):
        if err == "missing":
            gh_missing = True
            break
        if err is not None or not isinstance(obj, dict):
            continue
        action = obj.get("action")
        if not isinstance(action, str):
            continue
        if any(action.startswith(p) for p in _GH_HIGH_SIGNAL_PREFIXES):
            gh_hits.append(obj)

    out.append("### GitHub high-signal actions\n")
    if gh_missing:
        out.append("- _audit-log-180d.jsonl not present — skipping._\n")
    elif not gh_hits:
        out.append("- _none observed._\n")
    else:
        out.append(f"- {len(gh_hits)} event(s):")
        out.append("")
        out.append("| @timestamp | action | actor | repo |")
        out.append("|---|---|---|---|")
        for ev in gh_hits[:100]:
            out.append(
                f"| {ev.get('@timestamp', '?')} | `{ev.get('action', '?')}` "
                f"| {ev.get('actor', '?')} | {ev.get('repo', '?')} |"
            )
        if len(gh_hits) > 100:
            out.append(f"- _truncated at 100 rows ({len(gh_hits)} total)._")
        out.append("")


def _enumerate_projects(case_dir: str) -> list[tuple[str, str]]:
    """Return [(project_id, env_metadata_path), ...] for projects that have one."""
    projects_root = os.path.join(case_dir, "raw", "vercel", "projects")
    if not os.path.isdir(projects_root):
        return []
    out: list[tuple[str, str]] = []
    try:
        entries = sorted(os.listdir(projects_root))
    except OSError:
        return []
    for name in entries:
        pdir = os.path.join(projects_root, name)
        if not os.path.isdir(pdir):
            continue
        meta = os.path.join(pdir, "env-metadata.json")
        out.append((name, meta))
    return out


def _project_env_sections(
    case_dir: str, out: list[str]
) -> tuple[
    dict[str, Counter[str]],       # per-project type counts
    dict[str, Counter[str]],       # per-project class counts
    dict[str, Counter[str]],       # per-project priority counts
    list[tuple[str, str, str, str, str]],  # flat rows for P-tier listing
]:
    """Iterate all projects' env-metadata.json and build per-project breakdowns.

    Emits sections 3 and 4. Section 5 is emitted later using the returned data.
    """
    projects = _enumerate_projects(case_dir)

    type_counts: dict[str, Counter[str]] = {}
    class_counts: dict[str, Counter[str]] = {}
    priority_counts: dict[str, Counter[str]] = {}
    # (project, key, type, class, priority) — used by section 5.
    flat_rows: list[tuple[str, str, str, str, str]] = []

    out.append("## 3. Per-project env-var type counts (sensitive vs non-sensitive)\n")

    if not projects:
        out.append("- _no `raw/vercel/projects/*/env-metadata.json` found._\n")
        out.append("\n## 4. Env-var class taxonomy\n")
        out.append("- _no project env metadata; taxonomy skipped._\n")
        return type_counts, class_counts, priority_counts, flat_rows

    out.append("| project | sensitive | encrypted | plain | system | other | total | non-sensitive summary |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---|")

    for pid, meta_path in projects:
        envs_obj, err = _read_json(meta_path)
        if err is not None:
            if err != "missing":
                _append_scan_error(case_dir, os.path.relpath(meta_path, case_dir), err)
            out.append(
                f"| `{pid}` | — | — | — | — | — | — | _env-metadata {err}_ |"
            )
            continue

        # env-metadata.json is expected to be a list of env_var objects
        # (projected via project_fields). Accept {"envs": [...]} as a fallback.
        if isinstance(envs_obj, dict) and "envs" in envs_obj:
            envs = envs_obj["envs"]
        elif isinstance(envs_obj, list):
            envs = envs_obj
        else:
            _append_scan_error(
                case_dir, os.path.relpath(meta_path, case_dir), "unexpected-shape"
            )
            out.append(f"| `{pid}` | — | — | — | — | — | — | _unexpected shape_ |")
            continue

        t_ctr: Counter[str] = Counter()
        c_ctr: Counter[str] = Counter()
        p_ctr: Counter[str] = Counter()

        for ev in envs:
            if not isinstance(ev, dict):
                continue
            key = ev.get("key")
            env_type = ev.get("type")
            if not isinstance(key, str):
                continue
            if not isinstance(env_type, str):
                env_type = "other"
            klass = _classify_key(key)
            prio = _priority(key, env_type, klass)

            t_ctr[env_type] += 1
            c_ctr[klass] += 1
            p_ctr[prio] += 1
            flat_rows.append((pid, key, env_type, klass, prio))

        type_counts[pid] = t_ctr
        class_counts[pid] = c_ctr
        priority_counts[pid] = p_ctr

        total = sum(t_ctr.values())
        sensitive = t_ctr.get("sensitive", 0)
        non_sensitive = total - sensitive
        summary = f"{non_sensitive}/{total} non-sensitive"
        out.append(
            f"| `{pid}` "
            f"| {sensitive} "
            f"| {t_ctr.get('encrypted', 0)} "
            f"| {t_ctr.get('plain', 0)} "
            f"| {t_ctr.get('system', 0)} "
            f"| {total - sensitive - t_ctr.get('encrypted', 0) - t_ctr.get('plain', 0) - t_ctr.get('system', 0)} "
            f"| {total} "
            f"| {summary} |"
        )
    out.append("")

    # Section 4 — class taxonomy per project
    out.append("## 4. Env-var class taxonomy (metapod)\n")
    out.append(
        "Classes: `DB-cred`, `OAuth-secret`, `Provider-API-key`, "
        "`Webhook-signing`, `Vercel-managed`, `Public-by-design`, `Other`.\n"
    )
    all_classes = (
        "DB-cred", "OAuth-secret", "Provider-API-key",
        "Webhook-signing", "Vercel-managed", "Public-by-design", "Other",
    )
    header = "| project |" + "".join(f" {c} |" for c in all_classes)
    sep = "|---|" + ("---:|" * len(all_classes))
    out.append(header)
    out.append(sep)
    for pid, _ in projects:
        ctr = class_counts.get(pid)
        if ctr is None:
            out.append(f"| `{pid}` |" + " — |" * len(all_classes))
            continue
        out.append(
            f"| `{pid}` |" + "".join(f" {ctr.get(c, 0)} |" for c in all_classes)
        )
    out.append("")

    return type_counts, class_counts, priority_counts, flat_rows


def _priority_section(
    priority_counts: dict[str, Counter[str]],
    flat_rows: list[tuple[str, str, str, str, str]],
    out: list[str],
) -> None:
    out.append("## 5. P0 / P1 / P2 rotate-priority\n")
    if not priority_counts:
        out.append("- _no env vars to prioritize._\n")
        return

    out.append("### Per-project priority counts\n")
    out.append("| project | P0 | P1 | P2 | already-sensitive | total |")
    out.append("|---|---:|---:|---:|---:|---:|")
    totals = Counter()
    for pid, ctr in priority_counts.items():
        p0 = ctr.get("P0", 0)
        p1 = ctr.get("P1", 0)
        p2 = ctr.get("P2", 0)
        asn = ctr.get("already-sensitive", 0)
        total = p0 + p1 + p2 + asn
        totals["P0"] += p0
        totals["P1"] += p1
        totals["P2"] += p2
        totals["already-sensitive"] += asn
        totals["total"] += total
        out.append(f"| `{pid}` | {p0} | {p1} | {p2} | {asn} | {total} |")
    out.append(
        f"| **total** | **{totals['P0']}** | **{totals['P1']}** "
        f"| **{totals['P2']}** | **{totals['already-sensitive']}** "
        f"| **{totals['total']}** |"
    )
    out.append("")

    # Per-var listing, filtered to P0/P1 only (P2 is no-op, already-sensitive
    # is informational). Sorted by priority then project/key.
    ranked = [r for r in flat_rows if r[4] in ("P0", "P1")]
    ranked.sort(key=lambda r: (0 if r[4] == "P0" else 1, r[0], r[1]))
    out.append("### P0 / P1 env var listing\n")
    if not ranked:
        out.append("- _no P0 or P1 rotations required._\n")
        return
    out.append("| priority | project | key | type | class |")
    out.append("|---|---|---|---|---|")
    for pid, key, env_type, klass, prio in ranked[:500]:
        out.append(f"| {prio} | `{pid}` | `{key}` | {env_type} | {klass} |")
    if len(ranked) > 500:
        out.append(f"- _truncated at 500 rows ({len(ranked)} total)._")
    out.append("")


def _account_surface(case_dir: str, out: list[str]) -> tuple[bool, int | None]:
    """Emit section 6. Returns (log_drains_empty, most_recent_pushed_at_epoch_or_none).

    The log-drain-empty signal feeds section 8's >24h inference.
    """
    out.append("## 6. Account-surface audit\n")
    out.append("| surface | count | status |")
    out.append("|---|---:|---|")

    team_dir = os.path.join(case_dir, "raw", "vercel", "team")

    # Tokens
    tokens_path = os.path.join(team_dir, "user-tokens.json")
    tokens, err = _read_json(tokens_path)
    if err is not None:
        out.append(f"| tokens | — | _user-tokens.json {err}_ |")
    else:
        token_list = tokens if isinstance(tokens, list) else (
            tokens.get("tokens") if isinstance(tokens, dict) else None
        )
        if isinstance(token_list, list):
            out.append(
                f"| tokens | {len(token_list)} "
                f"| {'review' if len(token_list) else 'OK'} |"
            )
        else:
            out.append("| tokens | — | _unexpected shape_ |")

    # Integrations
    integ_path = os.path.join(team_dir, "integrations-list.json")
    integ, err = _read_json(integ_path)
    if err is not None:
        out.append(f"| integrations | — | _integrations-list.json {err}_ |")
    else:
        integ_list = integ if isinstance(integ, list) else (
            integ.get("configurations") if isinstance(integ, dict) else None
        )
        if isinstance(integ_list, list):
            out.append(
                f"| integrations | {len(integ_list)} "
                f"| {'review' if len(integ_list) else 'OK'} |"
            )
        else:
            out.append("| integrations | — | _unexpected shape_ |")

    # Webhooks
    webhooks_path = os.path.join(team_dir, "webhooks.json")
    webhooks, err = _read_json(webhooks_path)
    if err is not None:
        out.append(f"| webhooks | — | _webhooks.json {err}_ |")
    else:
        wh_list = webhooks if isinstance(webhooks, list) else (
            webhooks.get("webhooks") if isinstance(webhooks, dict) else None
        )
        if isinstance(wh_list, list):
            out.append(
                f"| webhooks | {len(wh_list)} "
                f"| {'review' if len(wh_list) else 'OK'} |"
            )
        else:
            out.append("| webhooks | — | _unexpected shape_ |")

    # Log drains
    drains_path = os.path.join(team_dir, "log-drains.json")
    drains, err = _read_json(drains_path)
    log_drains_empty = False
    if err is not None:
        out.append(f"| log-drains | — | _log-drains.json {err}_ |")
    else:
        drain_list = drains if isinstance(drains, list) else (
            drains.get("drains") if isinstance(drains, dict) else None
        )
        if isinstance(drain_list, list):
            log_drains_empty = len(drain_list) == 0
            status = "flagged" if log_drains_empty else "OK"
            out.append(f"| log-drains | {len(drain_list)} | {status} |")
        else:
            out.append("| log-drains | — | _unexpected shape_ |")

    # Domains
    domains_path = os.path.join(team_dir, "domains.json")
    domains, err = _read_json(domains_path)
    if err is not None:
        out.append(f"| domains | — | _domains.json {err}_ |")
    else:
        dom_list = domains if isinstance(domains, list) else (
            domains.get("domains") if isinstance(domains, dict) else None
        )
        if isinstance(dom_list, list):
            out.append(
                f"| domains | {len(dom_list)} "
                f"| {'review' if len(dom_list) else 'OK'} |"
            )
        else:
            out.append("| domains | — | _unexpected shape_ |")
    out.append("")

    # Compute most-recent pushedAt across project metadata for window inference.
    most_recent_epoch = _most_recent_pushed_at(case_dir)
    return log_drains_empty, most_recent_epoch


def _most_recent_pushed_at(case_dir: str) -> int | None:
    """Return max pushedAt epoch across project.json files under raw/vercel/projects/.

    pushedAt may be milliseconds or ISO-8601 depending on source; accept both.
    """
    projects_root = os.path.join(case_dir, "raw", "vercel", "projects")
    if not os.path.isdir(projects_root):
        return None
    best: int | None = None
    try:
        entries = sorted(os.listdir(projects_root))
    except OSError:
        return None
    for name in entries:
        pdir = os.path.join(projects_root, name)
        for cand in ("project.json", "metadata.json"):
            p = os.path.join(pdir, cand)
            obj, err = _read_json(p)
            if err is not None:
                continue
            if not isinstance(obj, dict):
                continue
            for field in ("pushedAt", "updatedAt", "latestDeploymentAt"):
                val = obj.get(field)
                epoch = _coerce_epoch(val)
                if epoch is not None and (best is None or epoch > best):
                    best = epoch
    return best


def _coerce_epoch(val: Any) -> int | None:
    """Accept int millis, int seconds, or ISO-8601 string; return UTC seconds."""
    if isinstance(val, (int, float)):
        v = int(val)
        # Heuristic: >= year-3000 in seconds => millis.
        if v > 32503680000:
            v //= 1000
        return v
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            return None
    return None


def _local_cli_hygiene(out: list[str]) -> None:
    out.append("## 7. Local CLI hygiene\n")
    # macOS canonical path; do NOT read file contents.
    auth_path = os.path.expanduser(
        "~/Library/Application Support/com.vercel.cli/auth.json"
    )
    try:
        st = os.stat(auth_path)
    except FileNotFoundError:
        out.append(f"- `{auth_path}` — not present. OK.\n")
        return
    except OSError as exc:
        out.append(f"- `{auth_path}` — stat failed ({exc.__class__.__name__}).\n")
        return
    mode = st.st_mode & 0o777
    mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    note = "MEDIUM — local Vercel CLI session present."
    perm_note = "" if mode <= 0o600 else f" (permissions {oct(mode)} looser than 0600 → LOW hygiene flag)"
    out.append(
        f"- `{auth_path}` — present. mtime={mtime}, mode={oct(mode)}. {note}{perm_note}\n"
    )


def _runtime_log_finding(
    case_dir: str, log_drains_empty: bool, most_recent_epoch: int | None, out: list[str]
) -> None:
    out.append("## 8. Runtime-log availability\n")
    if not log_drains_empty:
        out.append("- Log drains configured OR log-drains.json not parseable — no forensics-blind finding.\n")
        return
    now = int(datetime.now(tz=timezone.utc).timestamp())
    if most_recent_epoch is None:
        out.append(
            "- Log drains empty, but no pushedAt/updatedAt found under "
            "`raw/vercel/projects/*/project.json` to infer the window. "
            "Cannot determine if runtime logs have expired.\n"
        )
        return
    window_hours = max(0, (now - most_recent_epoch) / 3600.0)
    if window_hours > 24:
        out.append(
            f"- **MEDIUM finding:** log drains empty AND latest project activity is "
            f"{window_hours:.1f}h ago (>24h). Runtime logs expired — forensics-blind "
            f"beyond the 24h window.\n"
        )
    else:
        out.append(
            f"- Log drains empty but latest project activity is {window_hours:.1f}h ago "
            f"(≤24h). Runtime logs may still be queryable via `vercel logs`.\n"
        )


# --- Main --------------------------------------------------------------------


def _build_markdown(case_dir: str) -> str:
    out: list[str] = []
    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out.append(f"# Triage — {os.path.basename(os.path.abspath(case_dir))}\n")
    out.append(f"_generated {ts} by `triage.py`_\n")
    out.append("")

    _event_counters(case_dir, out)
    _security_slices(case_dir, out)
    type_counts, class_counts, priority_counts, flat_rows = _project_env_sections(case_dir, out)
    _priority_section(priority_counts, flat_rows, out)
    log_drains_empty, most_recent_epoch = _account_surface(case_dir, out)
    _local_cli_hygiene(out)
    _runtime_log_finding(case_dir, log_drains_empty, most_recent_epoch, out)

    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Phase 1a triage — emit analysis/triage.md from a frozen case dir."
    )
    ap.add_argument("--case", required=True, help="Path to frozen case directory.")
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Print the would-be-written markdown to stdout; do not touch disk.",
    )
    args = ap.parse_args()

    case_dir = os.path.abspath(args.case)
    if not os.path.isdir(case_dir):
        print(f"error: --case is not a directory: {case_dir}", file=sys.stderr)
        return 2

    raw_dir = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw_dir):
        print(f"error: missing raw/ under case dir: {raw_dir}", file=sys.stderr)
        return 2

    markdown = _build_markdown(case_dir)

    if args.dry_run:
        print(markdown, end="")
        return 0

    analysis_dir = os.path.join(case_dir, "analysis")
    os.makedirs(analysis_dir, mode=0o700, exist_ok=True)
    out_path = os.path.join(analysis_dir, "triage.md")

    # Idempotence: atomic_write refuses overwrite by design, so remove first.
    try:
        os.unlink(out_path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(
            f"error: could not remove previous triage.md ({exc}): {out_path}",
            file=sys.stderr,
        )
        return 2

    atomic_write(out_path, markdown, mode=0o600)
    print(f"wrote {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
