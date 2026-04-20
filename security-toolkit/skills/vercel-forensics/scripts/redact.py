#!/usr/bin/env python3
"""Walk $CASE/raw/ and emit redacted siblings alongside each file.

Per preservation contract, raw/ is pristine: redacted output is written as
<name>.redacted.json (JSON mode) or <name>.redacted (line mode) next to the
source. Redaction happens in memory before the first on-disk write; we never
write unredacted bytes to the redacted sibling path.

Sidecar log: $CASE/analysis/redactions.log — TSV of
    <iso_ts>\t<relative_path>\t<pattern_name>\t<count>
Values are NEVER logged, only pattern names + counts.

Partial-failure protocol: a .json file that fails to parse is logged to
$CASE/scan-errors.txt ("redact\t<path>\tparse\t<reason>") and processed in
line-by-line mode instead. Any such fallback flips the exit code to 2.

Exit: 0 clean; 2 partial (at least one parse fallback).
Python 3.10 stdlib only. Uses _common.redact_value / _common.atomic_write.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from typing import Any

from _common import atomic_write, redact_value

# Tagged versions of the redaction regexes in _common._REDACTION_RULES. Used
# ONLY to count per-pattern hits for the sidecar log and dry-run summary; the
# actual substitution is always done via _common.redact_value so the two paths
# can never diverge on what gets redacted.
_COUNT_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("discord-webhook",
     re.compile(r"(https?://discord\.com/api/webhooks/\d+/)([A-Za-z0-9_\-]+)")),
    ("slack-webhook",
     re.compile(r"https?://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("basic-auth-url",
     re.compile(r"(https?://)([^/:@\s]+):([^/@\s]+)@")),
    ("querystring-secret",
     re.compile(
         r"([?&](?:api_?key|token|secret|access_token|client_secret|password|"
         r"authorization|sig|sv|X-Amz-Signature|X-Amz-Credential)=)"
         r"([^&#\s]+)",
         re.IGNORECASE,
     )),
    ("github-pat",
     re.compile(r"\b(ghp_|github_pat_|gho_|ghu_|ghs_)[A-Za-z0-9_]{20,255}\b")),
    ("stripe-key",
     re.compile(r"\b(sk_live_|rk_live_|whsec_)[A-Za-z0-9]{16,}\b")),
    ("jwt",
     re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("gcp-sa-private-key",
     re.compile(
         r'"private_key"\s*:\s*"-----BEGIN[^"]+?-----\\n[^"]+?-----END[^"]+?-----\\n?"')),
    ("rfc1918-ip",
     re.compile(
         r"\b(?:10(?:\.\d{1,3}){3}|"
         r"192\.168(?:\.\d{1,3}){2}|"
         r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b")),
]


def _count_patterns(s: str, counts: dict[str, int]) -> None:
    """Accumulate per-pattern match counts for s into counts (in place)."""
    if not s:
        return
    for name, pattern in _COUNT_RULES:
        hits = len(pattern.findall(s))
        if hits:
            counts[name] = counts.get(name, 0) + hits


def _walk_json(obj: Any, counts: dict[str, int]) -> Any:
    """Recursively redact every string leaf in obj; accumulate pattern counts.

    Keys are redacted in the same pass: attacker-planted integration /
    env-var names can themselves contain secret-prefixed strings (e.g., an
    integration literally named ``ghp_stoleneurope...``). The redaction
    must therefore apply to keys as well as values, or those attacker
    strings survive into `raw/` → MANIFEST → WORM verbatim.
    """
    if isinstance(obj, str):
        _count_patterns(obj, counts)
        return redact_value(obj)
    if isinstance(obj, list):
        return [_walk_json(item, counts) for item in obj]
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            if isinstance(key, str):
                _count_patterns(key, counts)
                red_key = redact_value(key)
            else:
                red_key = key
            out[red_key] = _walk_json(value, counts)
        return out
    return obj


def _iso_ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_log(log_path: str, lines: list[str]) -> None:
    """Append TSV lines to redactions.log. File is created 0o600 on first write."""
    data = ("".join(lines)).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(log_path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _append_scan_error(case_dir: str, rel_path: str, reason: str) -> None:
    """Append a parse-fallback entry to $CASE/scan-errors.txt."""
    line = f"redact\t{rel_path}\tparse\t{reason}\n".encode("utf-8")
    path = os.path.join(case_dir, "scan-errors.txt")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)


def _redacted_sibling(src_path: str) -> str:
    """Sibling path: foo.json -> foo.redacted.json, foo.jsonl -> foo.redacted.jsonl.

    When the source has an extension, insert ".redacted" before it. When no
    extension, append ".redacted".
    """
    directory, basename = os.path.split(src_path)
    stem, ext = os.path.splitext(basename)
    if ext:
        return os.path.join(directory, f"{stem}.redacted{ext}")
    return os.path.join(directory, f"{basename}.redacted")


def _process_json(src_path: str, rel_path: str, dry_run: bool
                  ) -> tuple[dict[str, int], str | None]:
    """Parse + redact JSON. Returns (counts, fallback_reason_or_None).

    If parse fails, returns (empty counts, reason) so the caller can log
    scan-errors and re-dispatch to line mode.
    """
    with open(src_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {}, f"json-decode:{exc.msg}"
    counts: dict[str, int] = {}
    redacted = _walk_json(obj, counts)
    if not dry_run:
        out = json.dumps(redacted, ensure_ascii=False, sort_keys=False)
        dst = _redacted_sibling(src_path)
        atomic_write(dst, out)
    return counts, None


def _process_lines(src_path: str, dry_run: bool) -> dict[str, int]:
    """Line-by-line redact. Used for .jsonl, text, or JSON-parse fallbacks."""
    counts: dict[str, int] = {}
    redacted_lines: list[str] = []
    with open(src_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            _count_patterns(line, counts)
            redacted_lines.append(redact_value(line))
    if not dry_run:
        dst = _redacted_sibling(src_path)
        atomic_write(dst, "".join(redacted_lines))
    return counts


def _iter_raw_files(raw_root: str):
    """Yield (abs_path, rel_path_from_raw_root) for every file under raw/."""
    for dirpath, _dirnames, filenames in os.walk(raw_root):
        for name in filenames:
            abs_path = os.path.join(dirpath, name)
            rel = os.path.relpath(abs_path, raw_root)
            yield abs_path, rel


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--case", required=True, help="Case directory (contains raw/)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Scan + emit per-file pattern counts; write nothing")
    parser.add_argument("--log-requests", action="store_true",
                        help="Propagated flag; no network here, but accepted for parity")
    args = parser.parse_args()

    case_dir = os.path.abspath(args.case)
    if not os.path.isdir(case_dir):
        print(f"redact: --case not a directory: {case_dir}", file=sys.stderr)
        return 1
    raw_root = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw_root):
        print(f"redact: no raw/ subdirectory in case: {raw_root}", file=sys.stderr)
        return 1

    analysis_dir = os.path.join(case_dir, "analysis")
    os.makedirs(analysis_dir, mode=0o700, exist_ok=True)
    log_path = os.path.join(analysis_dir, "redactions.log")

    partial = False
    log_batch: list[str] = []

    for abs_path, rel in _iter_raw_files(raw_root):
        # Skip anything that was already written as a redacted sibling (idempotent re-runs).
        # Matches foo.redacted, foo.redacted.json, foo.redacted.jsonl, etc.
        _stem, _ext = os.path.splitext(os.path.basename(abs_path))
        if _stem.endswith(".redacted") or os.path.basename(abs_path).endswith(".redacted"):
            continue
        # Safety: the file must actually live under raw_root (symlinks etc).
        real_abs = os.path.realpath(abs_path)
        real_raw = os.path.realpath(raw_root)
        if not real_abs.startswith(real_raw + os.sep) and real_abs != real_raw:
            print(f"redact: skipping out-of-tree path: {abs_path}", file=sys.stderr)
            continue

        counts: dict[str, int] = {}
        fallback: str | None = None

        if abs_path.endswith(".json"):
            counts, fallback = _process_json(abs_path, rel, args.dry_run)
            if fallback is not None:
                partial = True
                if not args.dry_run:
                    _append_scan_error(case_dir, rel, fallback)
                counts = _process_lines(abs_path, args.dry_run)
        else:
            counts = _process_lines(abs_path, args.dry_run)

        if args.dry_run:
            if counts:
                summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
                print(f"{rel}\t{summary}")
            else:
                print(f"{rel}\t(no matches)")
        else:
            ts = _iso_ts()
            for pattern_name, count in sorted(counts.items()):
                log_batch.append(f"{ts}\t{rel}\t{pattern_name}\t{count}\n")

    # Always create redactions.log on a live run — even with zero matches —
    # so freeze.sh's sentinel check confirms "redact.py ran to completion"
    # rather than "redact.py didn't run". Clean cases would otherwise fail
    # freeze; worse, the absence-of-file alone would become a trivial
    # bypass (`touch redactions.log`). The TSV header row + completion
    # marker together sentinel actual completion.
    if not args.dry_run:
        if log_batch:
            _append_log(log_path, log_batch)
        else:
            _append_log(log_path, [f"{_iso_ts()}\t(no-matches)\t-\t0\n"])

    return 2 if partial else 0


if __name__ == "__main__":
    sys.exit(main())
