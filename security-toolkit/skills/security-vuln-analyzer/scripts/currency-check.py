#!/usr/bin/env python3
"""Deterministic currency check for security-vuln-analyzer GHSA mode (ADR-016 decision 5).

Subcommands:
  revision  the default-branch commit at the advisory's creation time (first-parent history), from a local clone
  plan      the technical issues that analysis at the pin did not confirm: the scope of the two-revision check
  flags     function-level, rename-aware presence and change flags per technical issue (information only)
  outcome   per planned issue, a proposal for the human: FIXED_SINCE_REPORT, STILL_PRESENT, NOT_CONFIRMED_AT_REPORT, UNDECIDED
  brief     the human's currency brief: outcomes with their evidence, both analyses, any test, and the flags
  test-result, checkout, sandbox-profile  parts of the --develop-fix test-only entry, which is not yet usable (phase 2b):
            `outcome` refuses test results in this version

No command makes a network call, weighs evidence, or dismisses an issue. `git` runs with fixed argument
vectors against the given clone, with global and system configuration ignored; anchors taken from report
text are validated before they reach `git`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any
import unicodedata

ADAPTER_NAME = "security-vuln-analyzer-currency-check"
ADAPTER_VERSION = "1.0.0"
VERIFIED = "CROSS-MODEL VERIFIED"
EXIT_OK = 0
EXIT_USAGE = 2
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
PATH_PATTERN = re.compile(r"^[A-Za-z0-9_.@+][A-Za-z0-9_.@+/-]{0,299}$")
SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_:.]{0,199}$")
FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}$")
# A non-confirming issue's reason, most significant first: an issue with several records takes the first that applies.
REASON_ORDER = ("DISPUTED", "INCOMPLETE", "NOT VERIFIED", "REFUTED")
GIT_TIMEOUT = 300
ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


class UsageError(ValueError):
    pass


def load(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise UsageError(f"cannot read JSON {path}: {error}") from error


def file_sha256(path: str | Path) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as error:
        raise UsageError(f"cannot read {path}: {error}") from error


def restricted_dir(path: Path) -> Path:
    """Create every missing level with mode 700, not only the leaf (mkdir(parents=True) uses the umask)."""
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
    os.chmod(path, 0o700)
    return path


def dump_private(path: str | Path, value: Any) -> None:
    restricted_dir(Path(path).parent)
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)  # O_CREAT's mode applies only to a new file
        handle.write(text)


def currency_out(path: str | Path, ghsa_id: str) -> Path:
    """Currency outputs live directly in <run>/currency/ of the advisory's own run."""
    out = Path(path).resolve()
    record = out.parent.parent / "intake" / "intake-record.json"
    if out.parent.name != "currency" or not record.is_file() or load(record).get("advisory", {}).get("ghsa_id") != ghsa_id:
        raise UsageError(f"currency outputs for {ghsa_id} belong directly in <run>/currency/ of a run directory whose "
                         "intake/intake-record.json captures that advisory")
    return out


# Command-line configuration overrides the clone's own: no signature program from log.showSignature, no file-system
# monitor. The environment blocks lazy fetches from a partial clone and every transport, and makes pathspecs literal.
GIT_CONFIG = ("core.fsmonitor=false", "core.quotepath=off", "log.showSignature=false")
GIT_ENVIRONMENT = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
                   "GIT_ALLOW_PROTOCOL": "", "GIT_LITERAL_PATHSPECS": "1", "LC_ALL": "C"}
# Used only for git log -L: git's built-in Rust function-header rule, so indented methods in impl blocks match.
RUST_ATTRIBUTES = "*.rs diff=rust\n"


def git(repo: Path, *args: str, allow_failure: bool = False, config: tuple[str, ...] = ()) -> tuple[int, str]:
    """Run git with a fixed argument vector against one clone, never fetching, prompting, or writing to it."""
    environment = dict(GIT_ENVIRONMENT, PATH=os.environ.get("PATH", os.defpath), GIT_CONFIG_GLOBAL=os.devnull, HOME=os.devnull)
    argv = ["git", "-C", str(repo)]
    for item in GIT_CONFIG + config:
        argv += ["-c", item]
    argv += list(args)
    try:
        process = subprocess.run(argv, check=False, capture_output=True, encoding="utf-8", errors="replace",
                                 env=environment, timeout=GIT_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as error:
        raise UsageError(f"git {args[0]} could not run: {error}") from error
    if process.returncode != 0 and not allow_failure:
        raise UsageError(f"git {args[0]} failed: {process.stderr.strip()[:300]}")
    return process.returncode, process.stdout


def clone_path(value: str) -> Path:
    repo = Path(value).resolve()
    code, out = git(repo, "rev-parse", "--is-inside-work-tree", allow_failure=True)
    if code != 0 or out.strip() != "true":
        raise UsageError(f"{repo} is not a git clone")
    if git(repo, "rev-parse", "--show-cdup")[1].strip():
        raise UsageError(f"{repo} is inside a clone; pass the clone's top-level directory")
    return repo


def github_repository(url: str) -> str:
    match = re.match(r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)([^/]+/[^/]+?)(?:\.git)?/?$", url.strip())
    return match.group(1).lower() if match else ""


def commit_exists(repo: Path, revision: str) -> bool:
    return git(repo, "cat-file", "-e", f"{revision}^{{commit}}", allow_failure=True)[0] == 0


# ---------- revision ----------

def command_revision(args: argparse.Namespace) -> dict[str, Any]:
    intake = load(args.intake)
    advisory, pinned = intake.get("advisory", {}), intake.get("pinned_target", {})
    ghsa_id, created_at = advisory.get("ghsa_id", ""), advisory.get("created_at", "")
    out = currency_out(args.out, ghsa_id)
    if not created_at:
        raise UsageError("the intake record has no advisory created_at, so the report's revision cannot be found")
    if not ISO_TIME.match(created_at):
        raise UsageError(f"the advisory created_at {created_at!r} is not an ISO-8601 time")
    if not BRANCH_PATTERN.match(args.default_branch) or ".." in args.default_branch:
        raise UsageError(f"not a valid branch name: {args.default_branch!r}")
    repo = clone_path(args.repo_dir)
    repository = str(pinned.get("repository", ""))
    _, url = git(repo, "config", "--get", "remote.origin.url", allow_failure=True)
    if not repository or github_repository(url) != repository.lower():
        raise UsageError(f"the clone's origin names another repository than {repository or '(none in the intake)'}")
    ref = f"refs/remotes/origin/{args.default_branch}"
    if git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", allow_failure=True)[0] != 0:
        raise UsageError(f"the clone has no origin/{args.default_branch}")
    pin = str(pinned.get("revision", ""))
    if not SHA_PATTERN.match(pin) or not commit_exists(repo, pin):
        raise UsageError(f"the capture's pinned revision {pin or '(none)'} is not in the clone; fetch origin first")
    _, found = git(repo, "rev-list", "-1", "--first-parent", f"--before={created_at}", ref)
    report_revision = found.strip()
    if not SHA_PATTERN.match(report_revision):
        raise UsageError(f"no commit on origin/{args.default_branch} at or before {created_at}")
    if git(repo, "merge-base", "--is-ancestor", report_revision, pin, allow_failure=True)[0] != 0:
        raise UsageError("the report's revision is not an ancestor of the pin; the capture and the clone disagree")
    _, count = git(repo, "rev-list", "--count", "--first-parent", f"{report_revision}..{pin}")
    document = {"record_type": "ghsa_currency_revision", "ghsa_id": ghsa_id, "repository": repository, "created_at": created_at,
                "default_branch": args.default_branch, "report_revision": report_revision, "pin": pin,
                "first_parent_commits_between": int(count.strip() or 0), "intake_sha256": file_sha256(args.intake)}
    dump_private(out, document)
    return {"status": "COMPLETE", "report_revision": report_revision, "pin": pin, "out": str(out)}


# ---------- plan ----------

KNOWN_STATUSES = (VERIFIED, "DISPUTED", "INCOMPLETE", "NOT VERIFIED", "REFUTED")


def issue_statuses(records: list[dict[str, Any]], ghsa_id: str, eligible_only: bool = False) -> dict[str, list[str]]:
    """Each issue's records' final statuses. An unknown or empty status is INCOMPLETE. With eligible_only, a verified
    record that is not ghsa_eligible counts as UNBRIDGED (analysis evidence for 'fixed' needs a bridged record)."""
    statuses: dict[str, list[str]] = {}
    for record in records:
        status = str(record.get("final_status", ""))
        status = status if status in KNOWN_STATUSES else "INCOMPLETE"
        if eligible_only and status == VERIFIED and record.get("ghsa_eligible") is not True:
            status = "UNBRIDGED"
        for answer in record.get("answers", []):
            if answer.get("ghsa_id") == ghsa_id:
                statuses.setdefault(answer.get("issue_id", ""), []).append(status)
    return statuses


def command_plan(args: argparse.Namespace) -> dict[str, Any]:
    issues_doc, dispositions, records_doc = load(args.issues), load(args.dispositions), load(args.records)
    ghsa_id = issues_doc.get("ghsa_id", "")
    out = currency_out(args.out, ghsa_id)
    issues_sha = file_sha256(args.issues)
    if dispositions.get("record_type") != "ghsa_dispositions" or dispositions.get("ghsa_id") != ghsa_id:
        raise UsageError("the dispositions belong to another advisory")
    if dispositions.get("depends_on", {}).get("issues_sha256") != issues_sha:
        raise UsageError("the dispositions were computed from another issue list")
    if dispositions.get("analysis_status") != "READY":
        raise UsageError(f"the currency check needs analysis_status READY, not {dispositions.get('analysis_status')!r}")
    if records_doc.get("ghsa_id") != ghsa_id or records_doc.get("issues_sha256") != issues_sha:
        raise UsageError("the records belong to another advisory or another issue list")
    technical = {item["issue_id"]: item for item in issues_doc.get("issues", []) if item.get("technical")}
    statuses = issue_statuses(records_doc.get("records", []), ghsa_id)
    planned, not_planned = [], []
    for issue_id in dispositions.get("analysis_issue_ids", []):
        if issue_id not in technical:
            not_planned.append({"issue_id": issue_id, "reason": "NOT_TECHNICAL"})
            continue
        found = statuses.get(issue_id, [])
        if VERIFIED in found:  # confirmed at the pin, bridged or not (a split resolved by a frozen test is not bridged)
            not_planned.append({"issue_id": issue_id, "reason": "CONFIRMED"})
            continue
        reason = next((status for status in REASON_ORDER if status in found), "NO_RECORD")
        planned.append({"issue_id": issue_id, "mechanism": technical[issue_id].get("mechanism", ""), "reason": reason})
    document = {"record_type": "ghsa_currency_plan", "ghsa_id": ghsa_id, "primary_revision": records_doc.get("primary_revision", ""),
                "issues_sha256": issues_sha, "dispositions_sha256": file_sha256(args.dispositions),
                "records_sha256": file_sha256(args.records), "planned": planned, "not_planned": not_planned}
    dump_private(out, document)
    return {"status": "COMPLETE", "planned": [entry["issue_id"] for entry in planned], "out": str(out)}


# ---------- flags ----------

def valid_path(value: Any) -> bool:
    return isinstance(value, str) and bool(PATH_PATTERN.match(value)) and ".." not in value.split("/")


def symbol_name(value: str) -> str:
    """The last segment of a qualified name (`a::b.c` gives `c`), or empty when it is not a plain identifier."""
    name = re.split(r"::|\.", value)[-1]
    return name if FUNCTION_NAME.match(name) else ""


def word_pattern(name: str) -> str:
    return f"(^|[^A-Za-z0-9_]){name}([^A-Za-z0-9_]|$)"


def anchors_for(issue: dict[str, Any], sites: list[dict[str, Any]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    anchors, rejected, seen = [], [], set()

    def add(kind: str, value: Any, source: str) -> None:
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        ok = valid_path(value) if kind == "path" else isinstance(value, str) and bool(SYMBOL_PATTERN.match(value))
        (anchors if ok else rejected).append({"kind": kind, "value": str(value), "source": source})

    literals = issue.get("literals", {})
    for value in literals.get("file_paths", []):
        add("path", value, "literal")
    for value in literals.get("symbols", []):
        add("symbol", value, "literal")
    for site in sites:
        add("path", site.get("relative_path", ""), "control_site")
        add("symbol", site.get("symbol", ""), "control_site")
    return anchors, rejected


def renamed_paths(repo: Path, start: str, end: str) -> dict[str, str]:
    _, out = git(repo, "diff", "-M", "--no-ext-diff", "--no-textconv", "--diff-filter=R", "--name-status", start, end)
    renames = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].startswith("R"):
            renames[parts[1]] = parts[2]
    return renames


def path_present(repo: Path, revision: str, path: str) -> bool:
    return git(repo, "cat-file", "-e", f"{revision}:{path}", allow_failure=True)[0] == 0


def grep_files(repo: Path, revision: str, pattern: str) -> list[str]:
    code, out = git(repo, "grep", "-l", "-I", "-E", "-e", pattern, revision, "--", allow_failure=True)
    if code not in (0, 1):  # 1 means no match
        raise UsageError("git grep failed")
    prefix = f"{revision}:"
    return sorted({line.removeprefix(prefix) for line in out.splitlines() if line})


def definitions_in_file(repo: Path, revision: str, name: str, path: str) -> int:
    code, out = git(repo, "grep", "-c", "-E", "-e", f"fn {name}([^A-Za-z0-9_]|$)", revision, "--", path, allow_failure=True)
    if code not in (0, 1):
        raise UsageError("git grep failed")
    return sum(int(line.rpartition(":")[2] or 0) for line in out.splitlines() if line.rpartition(":")[2].isdigit())


def function_commits(repo: Path, start: str, end: str, name: str, path: str, attributes: Path) -> list[dict[str, str]] | None:
    """Commits in start..end that touch `fn name` in `path` (the path as it is at `end`); None when git cannot follow
    it (for example the function is gone at `end`), which is not the same as unchanged."""
    code, out = git(repo, "log", "--no-ext-diff", "--no-textconv", "--format=%x00%H%x09%s", "--no-patch",
                    f"-L:fn {name}[^A-Za-z0-9_]:{path}", f"{start}..{end}", allow_failure=True,
                    config=(f"core.attributesFile={attributes}",))
    if code != 0:
        return None
    commits = []
    for chunk in out.split("\x00"):
        line = chunk.strip().splitlines()[0] if chunk.strip() else ""
        commit, _, subject = line.partition("\t")
        if SHA_PATTERN.match(commit):
            commits.append({"commit": commit, "subject": subject})
    return commits


def command_flags(args: argparse.Namespace) -> dict[str, Any]:
    revision = load(args.revision)
    if revision.get("record_type") != "ghsa_currency_revision":
        raise UsageError("--revision is not a currency revision record")
    ghsa_id, start, end = revision.get("ghsa_id", ""), revision.get("report_revision", ""), revision.get("pin", "")
    out = currency_out(args.out, ghsa_id)
    issues_doc = load(args.issues)
    if issues_doc.get("ghsa_id") != ghsa_id:
        raise UsageError("the issue list belongs to another advisory")
    repo = clone_path(args.repo_dir)
    if not (SHA_PATTERN.match(start) and SHA_PATTERN.match(end) and commit_exists(repo, start) and commit_exists(repo, end)):
        raise UsageError("the revision record's commits are not in the clone")
    issues_sha = file_sha256(args.issues)
    sites_by_issue: dict[str, list[dict[str, Any]]] = {}
    for path in args.records or []:
        document = load(path)
        if document.get("ghsa_id") != ghsa_id:
            raise UsageError(f"{path} belongs to another advisory")
        if document.get("issues_sha256") != issues_sha:
            raise UsageError(f"{path} was computed from another issue list")
        for record in document.get("records", []):
            if record.get("final_status") != VERIFIED or not isinstance(record.get("control_site"), dict):
                continue
            for answer in record.get("answers", []):
                if answer.get("ghsa_id") == ghsa_id:
                    sites_by_issue.setdefault(answer.get("issue_id", ""), []).append(record["control_site"])
    renames = renamed_paths(repo, start, end)
    with tempfile.TemporaryDirectory() as scratch:  # outside the clone; holds only the Rust attribute line for -L
        attributes = Path(scratch) / "attributes"
        attributes.write_text(RUST_ATTRIBUTES, encoding="utf-8")
        results = [issue_flags(repo, start, end, issue, sites_by_issue.get(issue["issue_id"], []), renames, attributes)
                   for issue in issues_doc.get("issues", []) if issue.get("technical")]
    document = {"record_type": "ghsa_currency_flags", "ghsa_id": ghsa_id, "report_revision": start, "pin": end, "issues_sha256": issues_sha,
                "note": "Flags are information only: they never change an outcome or dismiss an issue.", "issues": results}
    dump_private(out, document)
    return {"status": "COMPLETE", "issues": len(results), "out": str(out)}


def issue_flags(repo: Path, start: str, end: str, issue: dict[str, Any], sites: list[dict[str, Any]], renames: dict[str, str],
                attributes: Path) -> dict[str, Any]:
    anchors, rejected = anchors_for(issue, sites)
    paths = [a["value"] for a in anchors if a["kind"] == "path"]
    pin_paths = {renames.get(path, path) for path in paths}
    # A path names the same file whether written at the report revision or at the pin (a pin-side control site).
    named = set(paths) | {old for old, new in renames.items() if new in pin_paths or new in paths}
    presence, issue_renames, file_commits, file_history = {}, [], set(), "OK"
    reverse = {new: old for old, new in renames.items()}
    for path in paths:
        pin_path, report_path = renames.get(path, path), reverse.get(path, path)
        presence[path] = {"report_revision": path_present(repo, start, report_path), "pin": path_present(repo, end, pin_path),
                          "report_path": report_path, "pin_path": pin_path}
        if pin_path != path:
            issue_renames.append({"from": path, "to": pin_path})
        code, log = git(repo, "log", "--format=%H", "--follow", f"{start}..{end}", "--", pin_path, allow_failure=True)
        if code != 0:
            file_history = "UNAVAILABLE"
        file_commits.update(line for line in log.split() if SHA_PATTERN.match(line))
    symbols, definitions, history, commits = {}, {}, [], {}
    for anchor in (a for a in anchors if a["kind"] == "symbol"):
        name = symbol_name(anchor["value"])
        if not name:
            continue
        symbols[anchor["value"]] = {"report_revision": bool(grep_files(repo, start, word_pattern(name))),
                                    "pin": bool(grep_files(repo, end, word_pattern(name)))}
        defined = grep_files(repo, start, f"fn {name}([^A-Za-z0-9_]|$)")
        # The issue's own files first; otherwise only a unique definition, since a generic name defined in several files
        # would list commits from unrelated code.
        scoped = [path for path in defined if path in named] or (defined if len(defined) == 1 else [])
        definitions[name] = {"files": scoped, "definition_count": len(defined)}
        for path in scoped:
            if definitions_in_file(repo, start, name, path) > 1:  # git log -L would follow the first one only
                history.append({"symbol": name, "path": path, "status": "AMBIGUOUS_IN_FILE"})
                continue
            found = function_commits(repo, start, end, name, renames.get(path, path), attributes)
            history.append({"symbol": name, "path": path, "status": "OK" if found is not None else "UNAVAILABLE_AT_PIN"})
            for entry in found or []:
                commits.setdefault(entry["commit"], dict(entry, symbol=name, path=path))
    return {"issue_id": issue["issue_id"], "anchors": anchors, "rejected_anchors": rejected, "presence": presence,
            "renames": issue_renames, "symbols": symbols, "definitions": definitions, "function_history": history,
            "function_commits": sorted(commits.values(), key=lambda entry: entry["commit"]),
            "file_commit_count": len(file_commits), "file_history": file_history, "no_anchor": not presence and not symbols}


# ---------- outcome ----------

TEST_STATES = ("TEST_OBSERVED", "TEST_UNVALIDATED")
AT_PIN = ("PASSED", "FAILED", "UNRESOLVED")
NOT_CONFIRMED = ("REFUTED", "NOT VERIFIED", "NO_RECORD")
# At the report revision a dispute or an incomplete analysis outranks a confirmation (evidence for "fixed" must be clean).
REPORT_ORDER = ("DISPUTED", "INCOMPLETE", VERIFIED, "UNBRIDGED", "NOT VERIFIED", "REFUTED")
TEST_PRODUCER = "currency-check.py test-result"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def revision_record(path: str) -> dict[str, Any]:
    revision = load(path)
    if revision.get("record_type") != "ghsa_currency_revision" or not SHA_PATTERN.match(str(revision.get("report_revision", ""))) \
            or not SHA_PATTERN.match(str(revision.get("pin", ""))):
        raise UsageError("--revision is not a currency revision record")
    return revision


def load_test(path: str, ghsa_id: str, revision: dict[str, Any], plan: dict[str, Any], planned: set[str]) -> dict[str, Any]:
    """A --develop-fix test-only result, as written by `test-result`, for one planned issue at this revision pair."""
    test = load(path)
    if test.get("record_type") != "ghsa_currency_test" or test.get("ghsa_id") != ghsa_id:
        raise UsageError(f"{path} is not a currency test result for {ghsa_id} (another advisory or another kind of file)")
    if test.get("producer") != TEST_PRODUCER:
        raise UsageError(f"{path} was not written by {TEST_PRODUCER}")
    if test.get("issue_id") not in planned:
        raise UsageError(f"{path} is for {test.get('issue_id')!r}, which is not planned")
    if test.get("issues_sha256") != plan.get("issues_sha256"):
        raise UsageError(f"{path} was produced for another issue list")
    if (test.get("report_revision"), test.get("pin")) != (revision["report_revision"], revision["pin"]):
        raise UsageError(f"{path} was run at another revision than the revision record names")
    if not HEX64.match(str(test.get("registry_sha256", ""))):
        raise UsageError(f"{path} names no frozen-test registry digest")
    base, at_pin_checks = test.get("base_validation"), test.get("pin_validation")
    if not isinstance(base, dict) or base.get("state") not in TEST_STATES:
        raise UsageError(f"{path} has an unknown base_validation state")
    if not isinstance(at_pin_checks, dict):
        raise UsageError(f"{path} has no pin_validation")
    for name, block in (("base_validation", base), ("pin_validation", at_pin_checks)):
        for key in ("controls_hold", "sink_reached") + (("fails_at_base",) if name == "base_validation" else ()):
            if not isinstance(block.get(key), bool):
                raise UsageError(f"{path}: {name}.{key} must be true or false")
    if test.get("at_pin") not in AT_PIN:
        raise UsageError(f"{path} has an unknown at_pin result")
    return test


def validated(test: dict[str, Any] | None) -> bool:
    """A test counts as evidence only when it was observed failing at the report revision, with its benign controls
    holding and the sink reached there."""
    base = (test or {}).get("base_validation", {})
    return bool(test) and base.get("state") == "TEST_OBSERVED" and base.get("fails_at_base") is True \
        and base.get("controls_hold") is True and base.get("sink_reached") is True


def pin_evidence(test: dict[str, Any]) -> bool:
    """A result at the pin counts only when the test still reaches the sink there and the benign controls hold."""
    checks = test.get("pin_validation", {})
    return checks.get("sink_reached") is True and checks.get("controls_hold") is True


def decide(main: str, report: str | None, test: dict[str, Any] | None, same_revision: bool = False) -> tuple[str, str, str]:
    """(outcome, evidence, reason); first match wins. Every outcome is a proposal for the human."""
    if same_revision:  # nothing can have changed between the report and the pin
        return "UNDECIDED", "ANALYSIS", "SAME_REVISION"
    if test is not None and validated(test):
        at_pin = test["at_pin"]
        if at_pin == "UNRESOLVED":
            return "UNDECIDED", "TEST", "TEST_UNRESOLVED_AT_PIN"
        if not pin_evidence(test):
            return "UNDECIDED", "TEST", "TEST_NOT_AT_SINK_AT_PIN"
        if at_pin == "PASSED":
            return "FIXED_SINCE_REPORT", "TEST", ""
        return "STILL_PRESENT", "TEST", ""
    if report is None:  # the report revision has not been analyzed
        return "UNDECIDED", "ANALYSIS", "INCOMPLETE"
    if "DISPUTED" in (main, report):  # disputed at either revision
        return "UNDECIDED", "ANALYSIS", "DISPUTED"
    if "INCOMPLETE" in (main, report):
        return "UNDECIDED", "ANALYSIS", "INCOMPLETE"
    if report == "UNBRIDGED":
        return "UNDECIDED", "ANALYSIS", "UNBRIDGED_AT_REPORT"
    if report == VERIFIED and main in NOT_CONFIRMED:
        return "FIXED_SINCE_REPORT", "ANALYSIS", ""
    if report in NOT_CONFIRMED:
        return "NOT_CONFIRMED_AT_REPORT", "ANALYSIS", report
    return "UNDECIDED", "ANALYSIS", "INCOMPLETE"


def command_outcome(args: argparse.Namespace) -> dict[str, Any]:
    revision = revision_record(args.revision)
    plan = load(args.plan)
    ghsa_id = revision.get("ghsa_id", "")
    out = currency_out(args.out, ghsa_id)
    if plan.get("record_type") != "ghsa_currency_plan" or plan.get("ghsa_id") != ghsa_id:
        raise UsageError("the plan belongs to another advisory")
    if plan.get("primary_revision") != revision["pin"]:
        raise UsageError("the plan's analysis was at another pin than the revision record names")
    planned = {entry["issue_id"]: entry for entry in plan.get("planned", [])}
    report_status: dict[str, str] | None = None
    if args.report_records:
        records = load(args.report_records)
        if records.get("ghsa_id") != ghsa_id or records.get("issues_sha256") != plan.get("issues_sha256"):
            raise UsageError("the report-revision records belong to another advisory or another issue list")
        if records.get("primary_revision") != revision["report_revision"]:
            raise UsageError("the report-revision records describe another revision than the report revision")
        statuses = issue_statuses(records.get("records", []), ghsa_id, eligible_only=True)
        report_status = {issue_id: next((s for s in REPORT_ORDER if s in found), "NO_RECORD") for issue_id, found in statuses.items()}
    if args.test:
        raise UsageError("test results are not accepted in this version: the --develop-fix test-only entry is not yet usable "
                         "(deterministic-check.py binds each frozen test to one revision, and a build failure reads as a test "
                         "failure); outcomes come from the analyses until phase 2b (develop-fixes-mode.md, Test-only entry)")
    tests: dict[str, dict[str, Any]] = {}
    for path in args.test or []:
        test = load_test(path, ghsa_id, revision, plan, set(planned))
        if test["issue_id"] in tests:
            raise UsageError(f"two test results for {test['issue_id']}")
        tests[test["issue_id"]] = test
    issues = []
    for issue_id, entry in planned.items():
        main = entry.get("reason", "")
        report = None if report_status is None else report_status.get(issue_id, "NO_RECORD")
        test = tests.get(issue_id)
        outcome, evidence, reason = decide(main, report, test, revision["report_revision"] == revision["pin"])
        issues.append({"issue_id": issue_id, "mechanism": entry.get("mechanism", ""), "outcome": outcome, "evidence": evidence,
                       "reason": reason, "main_status": main, "report_status": report,
                       "test": None if test is None else {"base_validation": test["base_validation"], "pin_validation": test["pin_validation"],
                                                          "at_pin": test["at_pin"], "validated": validated(test)},
                       "contradiction": outcome == "STILL_PRESENT"})  # a failing test at the pin contradicts the pin's analysis
    document = {"record_type": "ghsa_currency_outcome", "ghsa_id": ghsa_id, "issues_sha256": plan.get("issues_sha256", ""),
                "report_revision": revision["report_revision"],
                "pin": revision["pin"], "note": "Every outcome is a proposal for the human; nothing is dismissed, closed, or written back.",
                "issues": issues}
    dump_private(out, document)
    return {"status": "COMPLETE", "outcomes": {entry["issue_id"]: entry["outcome"] for entry in issues}, "out": str(out)}


# ---------- brief ----------

def json_escape(char: str) -> str:
    code = ord(char)
    if code > 0xFFFF:  # JSON writes characters outside the BMP as a surrogate pair
        code -= 0x10000
        return "\\u%04x\\u%04x" % (0xD800 + (code >> 10), 0xDC00 + (code & 0x3FF))
    return "\\u%04x" % code


def one_line_json(value: Any) -> str:
    """JSON with every control, format, and line or paragraph separator escaped (json.dumps leaves U+2028, U+2029, C1
    controls, and bidirectional overrides raw), so a value can neither forge a line nor reorder or recolor one on a terminal."""
    text = json.dumps(value, ensure_ascii=False)
    return "".join(json_escape(char) if unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") else char for char in text)


def flag_lines(entry: dict[str, Any]) -> list[str]:
    if entry.get("no_anchor"):
        return ["  Flags (information only): no anchor could be checked"]
    lines = ["  Flags (information only; they never change the outcome):",
             "    anchors: " + one_line_json([f"{a['kind']}:{a['value']} ({a['source']})" for a in entry.get("anchors", [])])]
    for path, state in entry.get("presence", {}).items():
        lines.append(f"    path {one_line_json(path)}: report revision {state.get('report_revision')} "
                     f"({one_line_json(state.get('report_path', path))}), pin {state.get('pin')} ({one_line_json(state.get('pin_path', path))})")
    for name, state in entry.get("symbols", {}).items():
        lines.append(f"    symbol {one_line_json(name)}: report revision {state.get('report_revision')}, pin {state.get('pin')}")
    for name, definition in entry.get("definitions", {}).items():
        files = definition.get("files", [])
        looked_up = f"history looked up in {one_line_json(files)}" if files else (
            "history not looked up (no definition found)" if not definition.get("definition_count")
            else "history not looked up (defined in several files, none named by the issue)")
        lines.append(f"    function {one_line_json(name)}: defined in {definition.get('definition_count', 0)} file(s); {looked_up}")
    if entry.get("rejected_anchors"):
        lines.append("    rejected anchors (not checked): " + one_line_json([a.get("value", "") for a in entry["rejected_anchors"]]))
    commits = entry.get("function_commits", [])
    lines.append(f"    function commits (unverified fixing-commit candidates): {len(commits)}")
    lines += [f"      {c['commit']} {one_line_json(c.get('subject', ''))} ({one_line_json(c.get('symbol', ''))} in "
              f"{one_line_json(c.get('path', ''))})" for c in commits]
    unavailable = [h for h in entry.get("function_history", []) if h.get("status") != "OK"]
    if unavailable:
        lines.append("    history not followed (not the same as unchanged): "
                     + one_line_json([f"{h['symbol']} in {h['path']}: {h['status']}" for h in unavailable]))
    lines.append(f"    file commits: {entry.get('file_commit_count', 0)}")
    return lines


def command_brief(args: argparse.Namespace) -> dict[str, Any]:
    outcome = load(args.outcome)
    if outcome.get("record_type") != "ghsa_currency_outcome":
        raise UsageError("--outcome is not a currency outcome")
    ghsa_id = outcome.get("ghsa_id", "")
    out = currency_out(args.out, ghsa_id)
    flags_by_issue: dict[str, dict[str, Any]] = {}
    if args.flags:
        flags = load(args.flags)
        if flags.get("record_type") != "ghsa_currency_flags" or flags.get("ghsa_id") != ghsa_id:
            raise UsageError("the flags belong to another advisory")
        if (flags.get("report_revision"), flags.get("pin")) != (outcome.get("report_revision"), outcome.get("pin")):
            raise UsageError("the flags were computed for another revision than the outcome")
        if not HEX64.match(str(flags.get("issues_sha256", ""))) or flags.get("issues_sha256") != outcome.get("issues_sha256"):
            raise UsageError("the flags were computed from another issue list than the outcome; issue IDs would not match")
        flags_by_issue = {entry["issue_id"]: entry for entry in flags.get("issues", [])}
    fix_terms = None
    if args.fix_terms:
        render = load(args.fix_terms)
        if render.get("check") != "render" or not isinstance(render.get("fix_terms_found"), list):
            raise UsageError("--fix-terms is not the output of intake-check.py render --fix-blind")
        if render.get("ghsa_id") != ghsa_id:
            raise UsageError("--fix-terms belongs to another advisory")
        fix_terms = [term for term in render["fix_terms_found"] if isinstance(term, str)]
    lines = ["# Currency check brief",
             ("Rendered by currency-check.py brief for the human decision. Outcomes are proposals; nothing has been dismissed, "
              "closed, or written back. Anchors and commit subjects come from the report and the repository; they appear as "
              "one-line JSON strings."),
             f"Context: advisory {ghsa_id}, report revision {outcome.get('report_revision')}, pin {outcome.get('pin')}",
             "Fix wording in the description the report-revision analysis saw: "
             + ("not checked (pass --fix-terms)" if fix_terms is None
                else ", ".join(one_line_json(term) for term in fix_terms) or "none of the listed phrases"),
             ""]
    for entry in outcome.get("issues", []):
        lines += [f"## {entry['issue_id']}", f"Mechanism: {one_line_json(entry.get('mechanism', ''))}",
                  f"Outcome: {entry['outcome']} (evidence {entry['evidence']})" + (f", reason {entry['reason']}" if entry.get("reason") else ""),
                  (f"Analysis at the pin: {entry.get('main_status')} | at the report revision: "
                   f"{entry.get('report_status') or 'not analyzed'}")]
        test = entry.get("test")
        if test:
            base, at_pin_checks = test.get("base_validation", {}), test.get("pin_validation", {})
            flag = lambda value: "yes" if value is True else "no"  # booleans only; never raw text
            lines.append(f"Test: base {one_line_json(base.get('state'))} (fails at base {flag(base.get('fails_at_base'))}, controls hold "
                         f"{flag(base.get('controls_hold'))}, sink reached {flag(base.get('sink_reached'))}); at the pin "
                         f"{one_line_json(test.get('at_pin'))} (controls hold {flag(at_pin_checks.get('controls_hold'))}, sink reached "
                         f"{flag(at_pin_checks.get('sink_reached'))})" + ("" if test.get("validated") else "; not validated, so not evidence"))
        else:
            lines.append("Test: none")
        if entry.get("contradiction"):
            lines.append("Note: the test still fails at the pin, which contradicts the analysis at the pin; a human should look.")
        if entry["issue_id"] in flags_by_issue:
            lines += flag_lines(flags_by_issue[entry["issue_id"]])
        lines += ["Options: accept the proposal, or analyze again (for example with a test, or at a newer pin).", ""]
    restricted_dir(out.parent)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write("\n".join(lines))
    return {"status": "COMPLETE", "issues": len(outcome.get("issues", [])), "out": str(out)}


# ---------- test-only entry: checkout, sandbox profile, result ----------

def command_checkout(args: argparse.Namespace) -> dict[str, Any]:
    """A detached checkout of one endpoint inside the sandbox directory, so deterministic-check can read its HEAD.
    The clone is only read: `git clone --local --no-hardlinks` copies its objects; hooks are disabled in the copy."""
    revision = revision_record(args.revision)
    sha = revision["report_revision"] if args.which == "report" else revision["pin"]
    repo = clone_path(args.repo_dir)
    sandbox = Path(args.sandbox_dir).resolve(strict=True)
    destination = sandbox / args.which
    if destination.exists():
        raise UsageError(f"{destination} already exists")
    if sandbox == repo or sandbox.is_relative_to(repo) or repo.is_relative_to(sandbox):
        raise UsageError("the sandbox directory must not be the clone, inside it, or contain it")
    environment = dict(GIT_ENVIRONMENT, PATH=os.environ.get("PATH", os.defpath), GIT_CONFIG_GLOBAL=os.devnull, HOME=os.devnull,
                       GIT_ALLOW_PROTOCOL="file")  # a local copy only; still no network transport
    for step, argv in (("clone", ["git", "clone", "-q", "--local", "--no-hardlinks", "--no-checkout", str(repo), str(destination)]),
                       ("checkout", ["git", "-C", str(destination), "-c", "core.hooksPath=" + os.devnull, "-c", "core.fsmonitor=false",
                                     "checkout", "-q", "--detach", sha])):
        try:
            process = subprocess.run(argv, check=False, capture_output=True, encoding="utf-8", errors="replace", env=environment,
                                     timeout=GIT_TIMEOUT)
        except (OSError, subprocess.SubprocessError) as error:
            raise UsageError(f"git could not run: {error}") from error
        if process.returncode != 0:
            raise UsageError(f"git {step} failed: {process.stderr.strip()[:300]}")
    head = git(destination, "rev-parse", "HEAD")[1].strip()
    if head != sha:
        raise UsageError(f"the checkout's HEAD is {head}, not {sha}")
    return {"status": "COMPLETE", "checkout": str(destination), "revision": sha}


# Credential locations; the profile denies the whole home directory, and these are also denied at their real paths,
# so a symbolic link to a directory outside the home directory is covered.
CREDENTIAL_PATHS = ((".ssh",), (".aws",), (".config", "gh"), (".gnupg",), ("Library", "Keychains"), (".config", "op"), (".netrc",),
                    (".git-credentials",), (".docker",), (".cargo", "credentials.toml"), (".cargo", "credentials"))


def real_directory(value: str, what: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_dir():
        raise UsageError(f"{what} {value} is not a directory")
    return path.resolve()


def sbpl(value: Path | str) -> str:
    text = str(value)
    if '"' in text or "\\" in text or "\n" in text:
        raise UsageError(f"path not usable in a sandbox profile: {text!r}")
    return f'"{text}"'


def command_sandbox_profile(args: argparse.Namespace) -> dict[str, Any]:
    """Phase 2 boundary for the test-only entry. Denied: all network access, LaunchServices and Apple events (handing work
    to an unsandboxed process), reads of the whole home directory except the Rust toolchain, reads of credential paths
    and of the run root and clone at their real paths, and writes anywhere but the sandbox directory, the temporary
    directory, and the null, terminal, and descriptor devices. Cargo's home is a directory inside the sandbox, filled in
    Phase 1, so nothing a build script writes can persist outside the sandbox."""
    home = real_directory(os.environ.get("HOME", "~"), "the home directory")
    sandbox = real_directory(args.sandbox_dir, "the sandbox directory")
    protected = [real_directory(args.run_root, "the run root"), real_directory(args.repo_dir, "the clone")]
    rustup_home = real_directory(os.environ.get("RUSTUP_HOME") or str(home / ".rustup"), "RUSTUP_HOME")
    cargo_bin = real_directory(str(home / ".cargo" / "bin"), "the rustup proxies directory")
    temporary = real_directory(tempfile.gettempdir(), "the temporary directory")
    for inner in [home, *protected]:
        if sandbox == inner or sandbox.is_relative_to(inner) or inner.is_relative_to(sandbox):
            raise UsageError(f"the sandbox directory must be outside, and must not contain, {inner}")
    cargo_home, sandbox_home = sandbox / "cargo-home", sandbox / "home"
    restricted_dir(cargo_home)
    restricted_dir(sandbox_home)  # HOME for Phase 2: tools (git's library in Cargo, among others) read no configuration from the real home
    credentials = []
    for parts in CREDENTIAL_PATHS:
        literal = home.joinpath(*parts)
        credentials.append(literal)
        if literal.exists() and literal.resolve() != literal:
            credentials.append(literal.resolve())
    denied_reads = " ".join(f"(subpath {sbpl(path)})" for path in [*credentials, *protected])
    devices = os.path.join(os.sep, "dev")
    profile = "\n".join([
        "(version 1)", "(allow default)", "(deny network*)", "(deny lsopen)", "(deny appleevent-send)",
        f"(deny file-read* (subpath {sbpl(home)}))",
        f"(allow file-read* (literal {sbpl(home)}) (subpath {sbpl(rustup_home)}) (subpath {sbpl(cargo_bin)}))",
        f"(deny file-read* {denied_reads})",
        "(deny file-write*)",
        (f"(allow file-write* (subpath {sbpl(sandbox)}) (subpath {sbpl(temporary)}) (literal {sbpl(os.devnull)}) "
         f'(literal {sbpl(os.path.join(devices, "tty"))}) (regex #"^{devices}/fd/"))'), ""])
    out = Path(args.out)
    restricted_dir(out.parent)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(profile)
    return {"status": "COMPLETE", "out": str(out), "cargo_home": str(cargo_home),
            "environment": {"HOME": str(sandbox_home), "RUSTUP_HOME": str(rustup_home), "CARGO_HOME": str(cargo_home)},
            "note": "Phase 1 (cargo fetch, network on) uses CARGO_HOME; Phase 2 (sandbox-exec, offline) sets all of environment."}


def coverage_count(path: str, sink: str) -> int:
    """The maximum count over cargo-llvm-cov JSON segments on the sink line (deterministic-validation.md)."""
    relative, _, line_text = sink.rpartition(":")
    if not valid_path(relative) or not line_text.isdigit() or int(line_text) < 1:
        raise UsageError(f"--*-sink must be <relative path>:<line>, not {sink!r}")
    line, counts = int(line_text), []
    for block in load(path).get("data", []):
        for entry in block.get("files", []) if isinstance(block, dict) else []:
            name = str(entry.get("filename", "")) if isinstance(entry, dict) else ""
            if name == relative or name.endswith("/" + relative):
                counts += [segment[2] for segment in entry.get("segments", [])
                           if isinstance(segment, list) and len(segment) >= 3 and segment[0] == line and isinstance(segment[2], int)]
    return max(counts) if counts else 0


def frozen_results(paths: list[str], revision: str, expected: set[str]) -> tuple[dict[str, str], str, list[str]]:
    """Each frozen test's literal result at one revision, from deterministic-check.py result files."""
    results, registries, digests = {}, set(), []
    for path in paths:
        result = load(path)
        if result.get("role_type") != "computation" or result.get("check_kind") != "FROZEN_TEST_REFERENCE":
            raise UsageError(f"{path} is not a deterministic-check.py frozen-test result")
        if result.get("target_revision") != revision:
            raise UsageError(f"{path} was run at another revision ({result.get('target_revision')}) than {revision}")
        test_id = str(result.get("frozen_test_id", ""))
        if test_id in results:
            raise UsageError(f"two results for frozen test {test_id} at {revision}")
        literal = result.get("literal_check_result") if result.get("status") == "COMPLETE" else "UNRESOLVED"
        results[test_id] = literal if literal in ("PASSED", "FAILED") else "UNRESOLVED"
        registries.add(str(result.get("registry_sha256", "")))
        digests.append(file_sha256(path))
    if set(results) != expected:
        raise UsageError(f"results at {revision} cover {sorted(results)}, not the declared tests {sorted(expected)}")
    if len(registries) != 1 or not HEX64.match(next(iter(registries))):
        raise UsageError(f"the results at {revision} do not share one frozen-test registry")
    return results, next(iter(registries)), digests


def command_test_result(args: argparse.Namespace) -> dict[str, Any]:
    revision = revision_record(args.revision)
    plan = load(args.plan)
    ghsa_id = revision.get("ghsa_id", "")
    out = currency_out(args.out, ghsa_id)
    if plan.get("record_type") != "ghsa_currency_plan" or plan.get("ghsa_id") != ghsa_id:
        raise UsageError("the plan belongs to another advisory")
    if args.issue_id not in {entry.get("issue_id") for entry in plan.get("planned", [])}:
        raise UsageError(f"{args.issue_id} is not planned")
    adversarial, benign = set(args.adversarial), set(args.benign or [])
    if not adversarial or not benign or adversarial & benign:
        raise UsageError("declare at least one adversarial-input test and one benign control, each in one role only")
    overlaps = []
    for path in args.poc_overlap:
        check = load(path)
        if check.get("check") != "poc-overlap" or check.get("ghsa_id") != ghsa_id or check.get("decision") != "ACCEPT":
            raise UsageError(f"{path} is not an ACCEPT poc-overlap check for {ghsa_id}; a test that copies the report is never run")
        overlaps.append({"test_file_sha256": check.get("test_file_sha256", ""), "check_sha256": file_sha256(path)})
    declared = adversarial | benign
    base, base_registry, base_digests = frozen_results(args.base_result, revision["report_revision"], declared)
    pin, pin_registry, pin_digests = frozen_results(args.pin_result, revision["pin"], declared)
    if base_registry != pin_registry:
        raise UsageError("the two revisions' results come from different frozen-test registries")
    base_count, pin_count = coverage_count(args.base_coverage, args.base_sink), coverage_count(args.pin_coverage, args.pin_sink)
    fails_at_base = all(base[test] == "FAILED" for test in adversarial)
    base_controls = all(base[test] == "PASSED" for test in benign)
    adversarial_at_pin = [pin[test] for test in adversarial]
    at_pin = "UNRESOLVED" if "UNRESOLVED" in adversarial_at_pin else "PASSED" if all(r == "PASSED" for r in adversarial_at_pin) else "FAILED"
    observed = fails_at_base and base_controls and base_count > 0
    document = {"record_type": "ghsa_currency_test", "producer": TEST_PRODUCER, "ghsa_id": ghsa_id, "issue_id": args.issue_id,
                "issues_sha256": plan.get("issues_sha256", ""), "report_revision": revision["report_revision"], "pin": revision["pin"],
                "registry_sha256": base_registry, "tests": {"adversarial": sorted(adversarial), "benign": sorted(benign)},
                "base_validation": {"state": "TEST_OBSERVED" if observed else "TEST_UNVALIDATED", "fails_at_base": fails_at_base,
                                    "controls_hold": base_controls, "sink_reached": base_count > 0,
                                    "sink": {"location": args.base_sink, "count": base_count}, "results": base},
                "pin_validation": {"controls_hold": all(pin[test] == "PASSED" for test in benign), "sink_reached": pin_count > 0,
                                   "sink": {"location": args.pin_sink, "count": pin_count}, "results": pin},
                "at_pin": at_pin,
                "inputs": {"base_results_sha256": base_digests, "pin_results_sha256": pin_digests,
                           "base_coverage_sha256": file_sha256(args.base_coverage), "pin_coverage_sha256": file_sha256(args.pin_coverage),
                           "poc_overlap": overlaps}}
    dump_private(out, document)
    return {"status": "COMPLETE", "state": document["base_validation"]["state"], "at_pin": at_pin, "out": str(out)}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("revision"); p.add_argument("--repo-dir", required=True, help="local clone of the repository (read only)")
    p.add_argument("--intake", required=True); p.add_argument("--default-branch", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("plan"); p.add_argument("--issues", required=True); p.add_argument("--dispositions", required=True)
    p.add_argument("--records", required=True, help="report-records.json of the analysis at the pin"); p.add_argument("--out", required=True)
    p = sub.add_parser("flags"); p.add_argument("--repo-dir", required=True); p.add_argument("--revision", required=True)
    p.add_argument("--issues", required=True)
    p.add_argument("--records", action="append", help="report-records.json whose verified control sites add anchors; repeatable")
    p.add_argument("--out", required=True)
    p = sub.add_parser("outcome"); p.add_argument("--revision", required=True); p.add_argument("--plan", required=True)
    p.add_argument("--report-records", help="report-records.json of the analysis at the report revision, once it has run")
    p.add_argument("--test", action="append", help="refused in this version: the test-only entry is not yet usable (phase 2b)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("brief"); p.add_argument("--outcome", required=True); p.add_argument("--flags")
    p.add_argument("--fix-terms", help="the saved output of intake-check.py render --fix-blind"); p.add_argument("--out", required=True)
    p = sub.add_parser("sandbox-profile"); p.add_argument("--sandbox-dir", required=True, help="outside the home directory")
    p.add_argument("--run-root", required=True); p.add_argument("--repo-dir", required=True)
    p.add_argument("--out", required=True, help="profile file for sandbox-exec -f")
    p = sub.add_parser("checkout"); p.add_argument("--repo-dir", required=True); p.add_argument("--revision", required=True)
    p.add_argument("--which", required=True, choices=["report", "pin"]); p.add_argument("--sandbox-dir", required=True)
    p = sub.add_parser("test-result"); p.add_argument("--revision", required=True); p.add_argument("--plan", required=True)
    p.add_argument("--issue-id", required=True)
    p.add_argument("--adversarial", action="append", required=True, help="frozen test ID of an adversarial-input test; repeat")
    p.add_argument("--benign", action="append", required=True, help="frozen test ID of a benign control; repeat")
    p.add_argument("--base-result", action="append", required=True, help="deterministic-check.py result at the report revision")
    p.add_argument("--pin-result", action="append", required=True, help="deterministic-check.py result at the pin")
    p.add_argument("--base-coverage", required=True, help="cargo-llvm-cov JSON at the report revision")
    p.add_argument("--base-sink", required=True, help="<relative path>:<line> of the sink at the report revision")
    p.add_argument("--pin-coverage", required=True); p.add_argument("--pin-sink", required=True)
    p.add_argument("--poc-overlap", action="append", required=True, help="intake-check.py poc-overlap output per test file")
    p.add_argument("--out", required=True)
    args = parser.parse_args()
    handlers = {"revision": command_revision, "plan": command_plan, "flags": command_flags, "outcome": command_outcome,
                "brief": command_brief, "sandbox-profile": command_sandbox_profile, "checkout": command_checkout,
                "test-result": command_test_result}
    try:
        outcome = handlers[args.command](args)
    except (UsageError, KeyError, TypeError, IndexError, AttributeError, OSError) as error:
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    outcome.update({"adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION})
    print(json.dumps(outcome, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
