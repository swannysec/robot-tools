#!/usr/bin/env python3
"""IOC regex scan across per-deployment build logs (Phase 1d / build-log-scan).

Walks $CASE/raw/vercel/projects/*/build-logs/*.json (produced by
vercel-build-logs.sh in Phase 5), extracts the text field from each build
event defensively (handles both {text: "..."} and {payload: {text: "..."}}
shapes plus a few cousins), and applies the IOC regex catalogue from
references/collection-patterns.md §9.

Severity calibration:
  - "high"-tagged patterns (network-tool-pipe-shell, encoded-payload decode,
    dynamic code exec, literal env-var echoes, suspicious outbound hosts,
    postinstall shell-outs) auto-flag the deployment as HIGH.
  - "noise"-tagged matches (bare postinstall/preinstall) stay LOW on their
    own and are promoted to HIGH only when paired with a high-tagged hit
    in the same log.

Output: $CASE/analysis/build-log-scan.md with per-deployment findings
(deployment uid, project, matched patterns, line numbers) and a
cross-deployment hosts histogram flagging hosts outside the allowlist.

Args:
  --case <path>   Case directory (required). Must contain raw/vercel/projects.
  --dry-run       Scan + print counts to stderr; do not write the report.

Exit codes:
  0  clean
  1  fatal (missing case dir)
  2  partial (one or more build-log files unreadable / un-parseable)

Python 3.10 stdlib only. Uses _common.atomic_write for the markdown output.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from typing import Any, Iterable

from _common import atomic_write, display_safe


# ---------------------------------------------------------------------------
# IOC catalogue (copied from references/collection-patterns.md §9).
# Each entry: (category, severity_tag, compiled_regex).
# severity_tag is "high" or "noise".
# ---------------------------------------------------------------------------

_IOC_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    # Network-tool-pipe-shell (high)
    ("network-tool-pipe-shell", "high", re.compile(r"\bcurl\b.*\|\s*(?:ba)?sh")),
    ("network-tool-pipe-shell", "high", re.compile(r"\bwget\b.*\|\s*(?:ba)?sh")),
    ("network-tool-pipe-shell", "high", re.compile(r"\bnc\b")),
    ("network-tool-pipe-shell", "high", re.compile(r"\bnetcat\b")),

    # Lifecycle-script indicators (noise — counted, promoted only when paired)
    ("lifecycle-script", "noise", re.compile(r"\bpostinstall\b")),
    ("lifecycle-script", "noise", re.compile(r"\bpreinstall\b")),

    # Encoded-payload decode (high)
    ("encoded-payload-decode", "high", re.compile(r"\bbase64\s+-d\b")),
    ("encoded-payload-decode", "high", re.compile(r"\bbase64\s+--decode\b")),
    ("encoded-payload-decode", "high", re.compile(r"\batob\s*\(")),

    # Dynamic code execution (high)
    ("dynamic-code-exec", "high", re.compile(r"\beval\s*\(")),
    ("dynamic-code-exec", "high", re.compile(r"\bnew\s+Function\s*\(\s*[\"']")),
    ("dynamic-code-exec", "high", re.compile(r"\bFunction\s*\(\s*[\"']")),
    ("dynamic-code-exec", "high", re.compile(r"\bnode\s+-e\s+")),

    # Literal env-var echoes (high)
    ("env-var-echo", "high", re.compile(r"process\.env\.[A-Z_]+\s*[,\)\}]")),
    ("env-var-echo", "high",
     re.compile(r"\$[A-Z_]+\b.*>>?\s*(?:/dev/stdout|console|log)")),

    # Raw IP literal in URL (high)
    ("raw-ip-url", "high", re.compile(r"\bhttps?://\d{1,3}(?:\.\d{1,3}){3}\b")),

    # NPM/PyPI postinstall + shell-out (high — canonical supply-chain IOC)
    ("postinstall-shellout", "high",
     re.compile(r"postinstall.*\b(?:curl|wget|nc|bash|sh|python|node)\b")),
    ("postinstall-shellout", "high",
     re.compile(r"preinstall.*\b(?:curl|wget|nc|bash|sh|python|node)\b")),
]

# Host extraction regex (broad; we filter/allowlist post-hoc).
_HOST_RE = re.compile(
    r"https?://([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})",
    re.IGNORECASE,
)

# Known-good host allowlist (case-insensitive; matched as an exact equality
# or by dotted-suffix so sub.vercel.app matches vercel.app).
_HOST_ALLOWLIST = frozenset({
    "vercel.com",
    "vercel.app",
    "github.com",
    "githubusercontent.com",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "pythonhosted.org",
    "nextjs.org",
    "jsdelivr.net",
    "unpkg.com",
})

# Explicitly-bad TLDs + paste services + tunneling hosts.
_HOST_BAD_TLDS = frozenset({".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top"})

_HOST_BAD_EXACT = frozenset({
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "rentry.co",
    "termbin.com",
    "transfer.sh",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "loca.lt",
    "serveo.net",
})


# ---------------------------------------------------------------------------
# Defensive event-text extraction.
# ---------------------------------------------------------------------------

def _event_texts(event: Any) -> list[str]:
    """Return every plausible text field from one build event.

    Vercel's /v3/deployments/:uid/events returns heterogeneous shapes:
      - {type: "...", text: "foo", ...}
      - {type: "stdout", payload: {text: "foo", ...}, ...}
      - {type: "...", payload: {info: {text: "foo"}}, ...}
      - {type: "command", payload: {command: "npm install"}}

    We collect any of: .text, .payload.text, .payload.info.text,
    .payload.command. Non-strings are ignored. Order is stable for line
    numbering.
    """
    out: list[str] = []
    if not isinstance(event, dict):
        return out
    top_text = event.get("text")
    if isinstance(top_text, str):
        out.append(top_text)
    payload = event.get("payload")
    if isinstance(payload, dict):
        p_text = payload.get("text")
        if isinstance(p_text, str):
            out.append(p_text)
        p_cmd = payload.get("command")
        if isinstance(p_cmd, str):
            out.append(p_cmd)
        p_info = payload.get("info")
        if isinstance(p_info, dict):
            pi_text = p_info.get("text")
            if isinstance(pi_text, str):
                out.append(pi_text)
    return out


def _iter_events(doc: Any) -> Iterable[Any]:
    """Yield event dicts from a parsed build-log JSON doc.

    Known shapes:
      - a bare list of events
      - {events: [...]}  (some CLI versions wrap)
      - a sentinel error doc from vercel-build-logs.sh {"error": "..."} — skip
    """
    if isinstance(doc, list):
        for ev in doc:
            yield ev
        return
    if isinstance(doc, dict):
        if "error" in doc and "events" not in doc:
            return  # sentinel from failed pull
        events = doc.get("events")
        if isinstance(events, list):
            for ev in events:
                yield ev
            return
        # Last resort: treat single-object doc as one event.
        yield doc


# ---------------------------------------------------------------------------
# Per-file scan.
# ---------------------------------------------------------------------------

def _host_bucket(host: str) -> str:
    """Classify a host as allow / flagged / unknown."""
    h = host.lower().rstrip(".")
    for good in _HOST_ALLOWLIST:
        if h == good or h.endswith("." + good):
            return "allow"
    for bad_tld in _HOST_BAD_TLDS:
        if h.endswith(bad_tld):
            return "flagged"
    if h in _HOST_BAD_EXACT:
        return "flagged"
    return "unknown"


def _scan_text_block(
    text: str,
    line_offset: int,
    pattern_hits: dict[tuple[str, str], list[int]],
    hosts: dict[str, int],
) -> None:
    """Scan a multi-line text block. Append per-pattern line numbers; count hosts.

    line_offset is the 1-based event index; we use "event<N>:line<M>" style
    so the caller can distinguish which event a hit came from even though
    build logs don't carry native line numbers.
    """
    lines = text.splitlines() or [text]
    for local_line_no, line in enumerate(lines, start=1):
        for category, tag, pattern in _IOC_PATTERNS:
            if pattern.search(line):
                pattern_hits[(category, tag)].append(line_offset * 100000 + local_line_no)
        for host_match in _HOST_RE.findall(line):
            host_norm = host_match.lower().rstrip(".")
            hosts[host_norm] = hosts.get(host_norm, 0) + 1


def _format_line_ref(packed: int) -> str:
    ev = packed // 100000
    ln = packed % 100000
    return f"ev{ev}:L{ln}"


def _scan_file(
    log_path: str,
) -> tuple[dict[tuple[str, str], list[int]], dict[str, int], str | None]:
    """Scan one build-log JSON file.

    Returns (pattern_hits, hosts, error_reason_or_None).
    pattern_hits maps (category, tag) -> packed line refs (ev * 100000 + line).
    """
    pattern_hits: dict[tuple[str, str], list[int]] = defaultdict(list)
    hosts: dict[str, int] = {}

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        return pattern_hits, hosts, f"open:{exc.strerror or exc}"

    if not raw.strip():
        return pattern_hits, hosts, "empty-file"

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        return pattern_hits, hosts, f"json-decode:{exc.msg}"

    for ev_idx, event in enumerate(_iter_events(doc), start=1):
        for text in _event_texts(event):
            _scan_text_block(text, ev_idx, pattern_hits, hosts)

    return pattern_hits, hosts, None


# ---------------------------------------------------------------------------
# Report assembly.
# ---------------------------------------------------------------------------

def _severity_for(pattern_hits: dict[tuple[str, str], list[int]]) -> str:
    """Calibrate deployment severity.

    HIGH: any "high" hit OR a "noise" (lifecycle) hit paired with anything.
    LOW:  only "noise" hits.
    NONE: no hits at all.

    Per analysis-methodology.md §2 we never auto-label HIGH without a
    paired high-tag hit; bare lifecycle-script counts stay LOW.
    """
    has_high = any(tag == "high" for (_, tag) in pattern_hits)
    has_noise = any(tag == "noise" for (_, tag) in pattern_hits)
    if has_high:
        return "HIGH"
    if has_noise:
        return "LOW"
    return "NONE"


def _iter_build_logs(case_dir: str) -> Iterable[tuple[str, str, str]]:
    """Yield (project_name, uid, abs_path) for every *.json build log.

    Path layout produced by vercel-build-logs.sh:
      $CASE/raw/vercel/projects/<name>/build-logs/<uid>.json
    plus a _manifest.json which we skip.

    Projects without a build-logs/ directory (no Phase 5 pull for that
    project, or no in-window deployments) are silently skipped.
    """
    projects_root = os.path.join(case_dir, "raw", "vercel", "projects")
    if not os.path.isdir(projects_root):
        return
    for project_name in sorted(os.listdir(projects_root)):
        pdir = os.path.join(projects_root, project_name)
        if not os.path.isdir(pdir):
            continue
        logs_dir = os.path.join(pdir, "build-logs")
        if not os.path.isdir(logs_dir):
            continue
        for entry in sorted(os.listdir(logs_dir)):
            if not entry.endswith(".json"):
                continue
            if entry.startswith("_manifest"):
                continue
            abs_path = os.path.join(logs_dir, entry)
            if not os.path.isfile(abs_path):
                continue
            uid = entry[:-5]  # strip .json
            yield project_name, uid, abs_path


def _render_markdown(
    case_dir: str,
    per_deployment: list[dict[str, Any]],
    hosts_total: dict[str, int],
    skipped_projects: list[str],
    errors: list[tuple[str, str]],
) -> str:
    """Assemble the analysis/build-log-scan.md report body."""
    lines: list[str] = []
    lines.append("# Build-log IOC scan")
    lines.append("")
    lines.append(f"Case: `{case_dir}`")
    lines.append("")

    # Summary counts.
    sev_counts = {"HIGH": 0, "LOW": 0, "NONE": 0}
    for row in per_deployment:
        sev_counts[row["severity"]] = sev_counts.get(row["severity"], 0) + 1
    total = len(per_deployment)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Deployments scanned: **{total}**")
    lines.append(f"- HIGH: **{sev_counts['HIGH']}**")
    lines.append(f"- LOW (lifecycle-only): **{sev_counts['LOW']}**")
    lines.append(f"- Clean: **{sev_counts['NONE']}**")
    if skipped_projects:
        lines.append(
            f"- Projects skipped (no build-logs/ directory — Phase 5 not pulled "
            f"or no in-window deployments): **{len(skipped_projects)}**"
        )
    if errors:
        lines.append(f"- Files with read/parse errors: **{len(errors)}**")
    lines.append("")

    # Per-deployment findings, HIGH first then LOW then NONE.
    lines.append("## Per-deployment findings")
    lines.append("")
    ordered = sorted(
        per_deployment,
        key=lambda r: (
            {"HIGH": 0, "LOW": 1, "NONE": 2}.get(r["severity"], 3),
            r["project"],
            r["uid"],
        ),
    )
    if not ordered:
        lines.append("_No build logs found in this case._")
        lines.append("")
    for row in ordered:
        if row["severity"] == "NONE":
            # Don't spam the report with clean rows; one-line tally is enough.
            continue
        lines.append(f"### {row['severity']} — `{row['project']}` / `{row['uid']}`")
        lines.append("")
        lines.append(f"- Source: `raw/vercel/projects/{row['project']}/build-logs/{row['uid']}.json`")
        hits = row["hits"]
        # Group by category.
        by_cat: dict[str, list[tuple[str, list[int]]]] = defaultdict(list)
        for (category, tag), refs in hits.items():
            by_cat[category].append((tag, refs))
        for category in sorted(by_cat):
            pairs = by_cat[category]
            refs_all: list[int] = []
            tag_for_cat = "noise"
            for tag, refs in pairs:
                refs_all.extend(refs)
                if tag == "high":
                    tag_for_cat = "high"
            refs_all.sort()
            # Cap displayed refs to 10 to keep the report bounded; report
            # total count alongside.
            shown = [_format_line_ref(r) for r in refs_all[:10]]
            more = "" if len(refs_all) <= 10 else f" (+{len(refs_all) - 10} more)"
            lines.append(
                f"  - **{category}** ({tag_for_cat}, {len(refs_all)} hit(s)): "
                f"{', '.join(shown)}{more}"
            )
        lines.append("")

    # Clean list (bullet only).
    clean_rows = [r for r in ordered if r["severity"] == "NONE"]
    if clean_rows:
        lines.append("### Clean deployments")
        lines.append("")
        for row in clean_rows:
            lines.append(f"- `{row['project']}` / `{row['uid']}`")
        lines.append("")

    # Cross-deployment hosts histogram.
    lines.append("## Hosts histogram (cross-deployment)")
    lines.append("")
    if not hosts_total:
        lines.append("_No outbound URLs observed in any build log._")
        lines.append("")
    else:
        flagged: list[tuple[str, int]] = []
        unknown: list[tuple[str, int]] = []
        allowed: list[tuple[str, int]] = []
        for host, count in hosts_total.items():
            bucket = _host_bucket(host)
            if bucket == "flagged":
                flagged.append((host, count))
            elif bucket == "unknown":
                unknown.append((host, count))
            else:
                allowed.append((host, count))
        flagged.sort(key=lambda x: (-x[1], x[0]))
        unknown.sort(key=lambda x: (-x[1], x[0]))
        allowed.sort(key=lambda x: (-x[1], x[0]))

        if flagged:
            lines.append("### Flagged hosts (bad TLD / paste / tunneling)")
            lines.append("")
            for host, count in flagged:
                lines.append(f"- **{host}** — {count} hit(s)")
            lines.append("")
        if unknown:
            lines.append("### Unknown hosts (not in allowlist — review manually)")
            lines.append("")
            for host, count in unknown[:50]:
                lines.append(f"- `{host}` — {count} hit(s)")
            if len(unknown) > 50:
                lines.append(f"- _…and {len(unknown) - 50} more_")
            lines.append("")
        if allowed:
            lines.append("### Allowlisted hosts (informational)")
            lines.append("")
            for host, count in allowed[:20]:
                lines.append(f"- `{host}` — {count} hit(s)")
            if len(allowed) > 20:
                lines.append(f"- _…and {len(allowed) - 20} more_")
            lines.append("")

    # Errors + skipped projects.
    if skipped_projects:
        lines.append("## Projects skipped")
        lines.append("")
        lines.append(
            "These projects had no `build-logs/` directory. Either Phase 5 "
            "was not run against them, or they had no in-window deployments."
        )
        lines.append("")
        for project in skipped_projects:
            lines.append(f"- `{project}`")
        lines.append("")

    if errors:
        lines.append("## File-level errors")
        lines.append("")
        for path, reason in errors:
            lines.append(f"- `{path}` — {reason}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Patterns: references/collection-patterns.md §9. "
        "Severity calibration: references/analysis-methodology.md §2._"
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="IOC regex scan across per-deployment Vercel build logs."
    )
    parser.add_argument("--case", required=True, help="Case directory (contains raw/)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan + print per-deployment summary to stderr; do not write the report.",
    )
    args = parser.parse_args()

    case_dir = os.path.abspath(args.case)
    if not os.path.isdir(case_dir):
        print(f"build-log-scan: --case not a directory: {case_dir}", file=sys.stderr)
        return 1

    projects_root = os.path.join(case_dir, "raw", "vercel", "projects")
    if not os.path.isdir(projects_root):
        print(
            f"build-log-scan: no raw/vercel/projects in case: {projects_root}",
            file=sys.stderr,
        )
        return 1

    # Enumerate projects to compute skipped list (projects without build-logs/).
    all_projects: list[str] = []
    for name in sorted(os.listdir(projects_root)):
        pdir = os.path.join(projects_root, name)
        if os.path.isdir(pdir):
            all_projects.append(name)
    projects_with_logs: set[str] = set()

    per_deployment: list[dict[str, Any]] = []
    hosts_total: dict[str, int] = defaultdict(int)
    errors: list[tuple[str, str]] = []

    for project_name, uid, abs_path in _iter_build_logs(case_dir):
        projects_with_logs.add(project_name)
        pattern_hits, hosts, err = _scan_file(abs_path)
        if err is not None:
            rel = os.path.relpath(abs_path, case_dir)
            errors.append((rel, err))
            # Still record the deployment as NONE so the summary is accurate.
            per_deployment.append({
                "project": project_name,
                "uid": uid,
                "severity": "NONE",
                "hits": {},
            })
            continue
        for host, count in hosts.items():
            hosts_total[host] += count
        severity = _severity_for(pattern_hits)
        per_deployment.append({
            "project": project_name,
            "uid": uid,
            "severity": severity,
            "hits": dict(pattern_hits),
        })

    skipped_projects = [p for p in all_projects if p not in projects_with_logs]

    if args.dry_run:
        sev_counts: dict[str, int] = defaultdict(int)
        for row in per_deployment:
            sev_counts[row["severity"]] += 1
        print(
            f"build-log-scan (dry-run): deployments={len(per_deployment)} "
            f"HIGH={sev_counts['HIGH']} LOW={sev_counts['LOW']} "
            f"NONE={sev_counts['NONE']} errors={len(errors)} "
            f"skipped_projects={len(skipped_projects)}",
            file=sys.stderr,
        )
        for row in per_deployment:
            if row["severity"] == "NONE":
                continue
            cats = sorted({cat for (cat, _tag) in row["hits"]})
            print(
                f"  {row['severity']}\t{row['project']}\t{row['uid']}\t"
                f"{','.join(cats)}",
                file=sys.stderr,
            )
        return 2 if errors else 0

    analysis_dir = os.path.join(case_dir, "analysis")
    os.makedirs(analysis_dir, mode=0o700, exist_ok=True)
    report_path = os.path.join(analysis_dir, "build-log-scan.md")
    body = _render_markdown(
        case_dir=case_dir,
        per_deployment=per_deployment,
        hosts_total=dict(hosts_total),
        skipped_projects=skipped_projects,
        errors=errors,
    )
    try:
        atomic_write(report_path, body)
    except FileExistsError:
        # Analysis scripts are re-runnable pre-freeze; overwrite via tmp+rename
        # is not allowed by atomic_write. Fall back to a numbered sibling so
        # we never silently clobber a prior run.
        i = 2
        while True:
            alt = os.path.join(analysis_dir, f"build-log-scan.{i}.md")
            if not os.path.lexists(alt):
                try:
                    atomic_write(alt, body)
                except FileExistsError:
                    i += 1
                    continue
                print(
                    f"build-log-scan: prior report present; wrote {alt}",
                    file=sys.stderr,
                )
                break
            i += 1

    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
