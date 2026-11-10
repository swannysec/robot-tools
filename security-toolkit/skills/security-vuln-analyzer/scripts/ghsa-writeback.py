#!/usr/bin/env python3
"""Execute a hashed, per-item human-approved GHSA write plan.

Allowed operations only: accept a triage advisory to draft, update `cwe_ids`,
`cvss_vector_string`, `severity`, or `vulnerabilities`, and create the temporary private fork.
Publish, close, CVE requests, collaborator and credit changes, and comment posting are
refused. Every value must equal a verified report record whose digest the plan names.
GitHub derives `severity` from a CVSS vector and clears the vector when `severity` is set
(verified 2026-11-10), so a severity update is refused alongside a CVSS update and stopped
when the live advisory already has a CVSS vector.
Before each write the advisory is re-fetched; any change since capture stops the run.

The write token is read only here, through `op read "$SVA_GHSA_WRITE_TOKEN_REF"` (a
1Password secret reference), and is passed to `gh` as `GH_TOKEN` for each subprocess. It
is never printed or written to disk.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unicodedata
from typing import Any

ADAPTER_NAME = "security-vuln-analyzer-ghsa-writeback"
ADAPTER_VERSION = "1.0.0"
API_VERSION = "2022-11-28"
WRITE_TOKEN_REF_ENV = "SVA_GHSA_WRITE_TOKEN_REF"
GHSA_ID_PATTERN = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
# operation -> (HTTP method, advisory field set by PATCH or "" for the fork endpoint)
ALLOWED_OPERATIONS = {
    "set_state_draft": ("PATCH", "state"),
    "set_cwe_ids": ("PATCH", "cwe_ids"),
    "set_cvss_vector": ("PATCH", "cvss_vector_string"),
    "set_severity": ("PATCH", "severity"),
    "set_vulnerabilities": ("PATCH", "vulnerabilities"),
    "create_private_fork": ("POST", ""),
}
FORBIDDEN_OPERATIONS = {
    "publish": "publishing is a human decision",
    "close": "closing is a human decision",
    "request_cve": "CVE requests are a human decision",
    "set_collaborators": "collaborator changes are a human decision",
    "set_credits": "credit changes are a human decision",
    "post_comment": "reporter comments are drafts; a human posts them",
}
SEVERITIES = ("critical", "high", "medium", "low")
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REFUSED = 6
EXIT_STOPPED = 7


class Refusal(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def text_digest(text: str) -> str:
    normalized = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    return sha256_bytes(normalized.encode("utf-8"))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load(path: Path) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    return json.loads(raw.decode("utf-8")), raw


def validate_item(item: dict[str, Any], records: dict[str, dict[str, Any]]) -> None:
    operation = item.get("operation")
    if operation in FORBIDDEN_OPERATIONS:
        raise Refusal(f"{operation} refused: {FORBIDDEN_OPERATIONS[operation]}")
    if operation not in ALLOWED_OPERATIONS:
        raise Refusal(f"operation {operation!r} is not in the allowlist")
    refs = item.get("record_refs")
    if not isinstance(refs, list) or not refs:
        raise Refusal("every item must cite at least one verified report record")
    cited = []
    for ref in refs:
        record = records.get(str(ref.get("record_id"))) if isinstance(ref, dict) else None
        if record is None:
            raise Refusal("item cites a record that is not in the verified record set")
        if canonical_digest(record) != ref.get("sha256"):
            raise Refusal(f"record {ref.get('record_id')} does not match its digest in the plan")
        if record.get("final_status") != "CROSS-MODEL VERIFIED":
            raise Refusal(f"record {ref.get('record_id')} is not CROSS-MODEL VERIFIED")
        if record.get("fallback_model") is True and record.get("fallback_use_permitted") is not True:
            raise Refusal(f"record {ref.get('record_id')} came from a fallback model without the user's permission for this use")
        cited.append(record)
    method, field = ALLOWED_OPERATIONS[operation]
    if operation == "set_state_draft":
        if item.get("new_value") != "draft":
            raise Refusal("the only state this script sets is draft")
        if item.get("old_value") != "triage":
            raise Refusal("accept-to-draft applies only to a triage advisory")
    elif operation == "set_severity" and item.get("new_value") not in SEVERITIES:
        raise Refusal("severity must be critical, high, medium, or low")
    elif operation == "create_private_fork":
        if item.get("new_value") not in (None, ""):
            raise Refusal("private-fork creation takes no value")
    elif not any(record.get("values", {}).get(field) == item.get("new_value") for record in cited):
        raise Refusal(f"new value for {field} does not equal any cited verified record")


class Gh:
    def __init__(self, fixtures: Path | None, token: str) -> None:
        self.fixtures = fixtures
        self.token = token
        self.sent: list[dict[str, Any]] = []

    def call(self, method: str, path: str, body: Any = None) -> Any:
        if self.fixtures is not None:
            if method == "GET":
                queue = sorted(self.fixtures.glob(re.sub(r"[^A-Za-z0-9._-]", "_", path) + "*.json"))
                consumed = sum(1 for entry in self.sent if entry["method"] == "GET" and entry["path"] == path)
                self.sent.append({"method": method, "path": path})
                if not queue:
                    raise RuntimeError(f"fixture missing for GET {path}")
                return json.loads(queue[min(consumed, len(queue) - 1)].read_text(encoding="utf-8"))
            self.sent.append({"method": method, "path": path, "body": body})
            return {}
        argv = ["gh", "api", "-X", method, "-H", "Accept: application/vnd.github+json",
                "-H", f"X-GitHub-Api-Version: {API_VERSION}", path]
        stdin = None
        if body is not None:
            argv += ["--input", "-"]
            stdin = json.dumps(body).encode("utf-8")
        environment = {key: value for key, value in os.environ.items() if key not in ("GH_TOKEN", "GITHUB_TOKEN")}
        environment["GH_TOKEN"] = self.token
        process = subprocess.run(argv, input=stdin, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=120)
        self.sent.append({"method": method, "path": path})
        if process.returncode != 0:
            raise RuntimeError(f"{method} {path} failed: {process.stderr.decode('utf-8', errors='replace').strip()[-300:]}")
        return json.loads(process.stdout.decode("utf-8") or "{}")


def has_cvss_vector(advisory: dict[str, Any]) -> bool:
    raw = advisory.get("cvss_severities")
    severities: dict[str, Any] = raw if isinstance(raw, dict) else {}
    for version in ("cvss_v3", "cvss_v4"):
        entry = severities.get(version)
        if isinstance(entry, dict) and entry.get("vector_string"):
            return True
    legacy = advisory.get("cvss")
    return isinstance(legacy, dict) and bool(legacy.get("vector_string"))


def read_token() -> str:
    reference = os.environ.get(WRITE_TOKEN_REF_ENV, "")
    if not reference.startswith("op://"):
        raise Refusal(f"{WRITE_TOKEN_REF_ENV} must hold a 1Password op:// secret reference")
    process = subprocess.run(["op", "read", reference], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
    token = process.stdout.decode("utf-8").strip()
    if process.returncode != 0 or not token:
        raise Refusal("op read did not return the write token (authorization denied or reference invalid)")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--approvals", required=True, type=Path)
    parser.add_argument("--records", required=True, type=Path, help="verified report records")
    parser.add_argument("--out", type=Path, help="results file (default: writeback-results.json beside the plan)")
    parser.add_argument("--api-fixtures", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()

    results: list[dict[str, Any]] = []
    outcome = {"adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION, "started_at_utc": utc_now(), "items": results}
    out = args.out or args.plan.with_name("writeback-results.json")
    exit_code = EXIT_OK
    try:
        plan, plan_raw = load(args.plan)
        approvals, _ = load(args.approvals)
        records_file, _ = load(args.records)
        outcome["plan_sha256"] = sha256_bytes(plan_raw)
        if approvals.get("plan_sha256") != outcome["plan_sha256"]:
            raise Refusal("approvals do not match this plan's SHA-256; nothing was written")
        repository, ghsa_id = plan.get("repository", ""), plan.get("ghsa_id", "")
        if not REPOSITORY_PATTERN.match(repository) or not GHSA_ID_PATTERN.match(ghsa_id):
            raise Refusal("plan repository or GHSA ID is malformed")
        records = {r["record_id"]: r for r in records_file.get("records", []) if isinstance(r, dict) and "record_id" in r}
        approved = set(approvals.get("approved_items", []))
        items = plan.get("items", [])
        for item in items:
            validate_item(item, records)  # every item is checked before any write
        operations = {item["operation"] for item in items}
        if {"set_severity", "set_cvss_vector"} <= operations:
            raise Refusal("a plan may not set both severity and a CVSS vector; GitHub derives severity from the vector")
        captured = plan.get("captured", {})
        expected_updated, expected_body = captured.get("updated_at"), captured.get("body_sha256")
        gh = Gh(args.api_fixtures, "" if args.api_fixtures else read_token())
        advisory_path = f"repos/{repository}/security-advisories/{ghsa_id}"
        for item in items:
            record = {"item_id": item.get("item_id"), "operation": item["operation"]}
            if item.get("item_id") not in approved:
                record["status"] = "NOT_APPROVED"
                results.append(record)
                continue
            current = gh.call("GET", advisory_path)
            if current.get("updated_at") != expected_updated or text_digest(current.get("description") or "") != expected_body:
                record["status"] = "STOPPED_CHANGED_SINCE_CAPTURE"
                results.append(record)
                exit_code = EXIT_STOPPED
                break
            if item["operation"] == "set_state_draft" and current.get("state") != "triage":
                record["status"] = "STOPPED_STATE_NOT_TRIAGE"
                results.append(record)
                exit_code = EXIT_STOPPED
                break
            if item["operation"] == "set_severity" and has_cvss_vector(current):
                record["status"] = "STOPPED_WOULD_CLEAR_CVSS"
                results.append(record)
                exit_code = EXIT_STOPPED
                break
            method, field = ALLOWED_OPERATIONS[item["operation"]]
            if method == "PATCH":
                gh.call("PATCH", advisory_path, {field: item["new_value"]})
            else:
                gh.call("POST", f"{advisory_path}/forks")
            after = gh.call("GET", advisory_path)
            if text_digest(after.get("description") or "") != expected_body:
                record["status"] = "WRITTEN_THEN_CHANGED"
                results.append(record)
                exit_code = EXIT_STOPPED
                break
            expected_updated = after.get("updated_at")  # our own write moves updated_at
            record["status"] = "WRITTEN"
            results.append(record)
        if args.api_fixtures is not None:
            outcome["fixture_calls"] = gh.sent
    except Refusal as error:
        outcome["refusal"] = str(error)
        exit_code = EXIT_REFUSED
    except (OSError, KeyError, TypeError, json.JSONDecodeError, RuntimeError, subprocess.SubprocessError) as error:
        outcome["error"] = str(error)
        exit_code = EXIT_USAGE
    outcome["finished_at_utc"] = utc_now()
    try:
        descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(outcome, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except OSError:
        pass
    print(json.dumps({k: outcome[k] for k in outcome if k != "fixture_calls"}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
