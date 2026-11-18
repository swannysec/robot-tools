#!/usr/bin/env python3
"""Deterministic currency check for security-vuln-analyzer GHSA mode (ADR-016 decision 5).

Subcommands:
  revision  the default-branch commit at the advisory's creation time (first-parent history), from a local clone
  plan      the technical issues that analysis at the pin did not confirm: the scope of the two-revision check (with
            --research, for a published advisory without dispositions)
  flags     function-level, rename-aware presence and change flags per technical issue (information only)
  outcome   per planned issue, a proposal for the human: FIXED_SINCE_REPORT, STILL_PRESENT, NOT_CONFIRMED_AT_REPORT, UNDECIDED
  brief     the human's currency brief: outcomes with their evidence, both analyses, any test, and the flags
  test-result, checkout, sandbox-profile, registry  parts of the --develop-fix test-only entry (a frozen test at both revisions,
            macOS): the checkouts, the Phase 2 sandbox profile, the frozen-test registry, and the test result `outcome` accepts
  fix-revision  a revision pair for post-fix coverage (a fixing commit and its first parent; --research for a published
            advisory) or, with --kind develop-fix, the analysis revision and a candidate patch's commit; checkout,
            registry, and test-result accept it
  coverage-outcome, coverage-brief  per issue of a coverage pair, a proposal for the human (COVERED_BY_FIX, which needs
            --verify-fix, NOT_COVERED_BY_FIX, UNDECIDED) and the human-only brief

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
PATH_PATTERN = re.compile(r"^[A-Za-z0-9_.@+][A-Za-z0-9_.@+/-]{0,299}\Z")  # \Z: no trailing newline
SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_:.]{0,199}$")
FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}$")
# A non-confirming issue's reason, most significant first: an issue with several records takes the first that applies.
REASON_ORDER = ("DISPUTED", "INCOMPLETE", "NOT VERIFIED", "REFUTED")
GIT_TIMEOUT = 300
ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


class UsageError(ValueError):
    pass


def encoded(text: str, path: str | Path) -> bytes:
    """An output's UTF-8 bytes, made before its file is opened: an input holding a lone surrogate (valid in JSON, not in
    UTF-8) is a usage error, and the file keeps its bytes."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as error:
        raise UsageError(f"{path}: the output holds text that is not valid Unicode (a lone surrogate at {error.start}); "
                         "fix the input") from error


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
    data = encoded(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n", path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)  # O_CREAT's mode applies only to a new file
        handle.write(data)


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
# The same rule as a pattern (git's userdiff "rust" funcname), to find where each of several same-named definitions ends.
RUST_FUNCNAME = re.compile(r'^[\t ]*((pub(\([^\\)]+\))?[\t ]+)?((async|const|unsafe|extern([\t ]+"[^"]+"))[\t ]+)?'
                           r'(struct|enum|union|mod|trait|fn|impl|macro_rules!)[< \t]+[^;]*)$')


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


OPEN_STATES = ("triage", "draft")


def research_advisory(intake: dict[str, Any], ghsa_id: str) -> None:
    """The research-only path (no dispositions) is for published advisories; open ones keep using step 1a dispositions."""
    advisory = intake.get("advisory", {}) if isinstance(intake, dict) else {}
    if advisory.get("ghsa_id") != ghsa_id:
        raise UsageError("the intake record belongs to another advisory")
    state = advisory.get("state")
    if state in OPEN_STATES:
        raise UsageError(f"{ghsa_id} is {state!r}: open advisories use step 1a dispositions; the research-only path "
                         "(--research) is for published advisories")
    if state != "published":
        raise UsageError(f"the research-only path accepts only published advisories, not {state!r}")


# ---------- revision ----------

def pinned_clone(repo_dir: str, pinned: dict[str, Any], branch: str) -> tuple[Path, str, str, str]:
    """The clone (read only), the capture's repository, the default branch's remote ref, and the capture's pin, checked
    against each other: the clone's origin is the capture's repository and holds the pin."""
    if not BRANCH_PATTERN.match(branch) or ".." in branch:
        raise UsageError(f"not a valid branch name: {branch!r}")
    repo = clone_path(repo_dir)
    repository = str(pinned.get("repository", ""))
    _, url = git(repo, "config", "--get", "remote.origin.url", allow_failure=True)
    if not repository or github_repository(url) != repository.lower():
        raise UsageError(f"the clone's origin names another repository than {repository or '(none in the intake)'}")
    ref = f"refs/remotes/origin/{branch}"
    if git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", allow_failure=True)[0] != 0:
        raise UsageError(f"the clone has no origin/{branch}")
    pin = str(pinned.get("revision", ""))
    if not SHA_PATTERN.match(pin) or not commit_exists(repo, pin):
        raise UsageError(f"the capture's pinned revision {pin or '(none)'} is not in the clone; fetch origin first")
    return repo, repository, ref, pin


def command_revision(args: argparse.Namespace) -> dict[str, Any]:
    intake = load(args.intake)
    advisory, pinned = intake.get("advisory", {}), intake.get("pinned_target", {})
    ghsa_id, created_at = advisory.get("ghsa_id", ""), advisory.get("created_at", "")
    out = currency_out(args.out, ghsa_id)
    own_intake(args.intake, out)  # D3: the capture of the run this record is written into
    if not created_at:
        raise UsageError("the intake record has no advisory created_at, so the report's revision cannot be found")
    if not ISO_TIME.match(created_at):
        raise UsageError(f"the advisory created_at {created_at!r} is not an ISO-8601 time")
    repo, repository, ref, pin = pinned_clone(args.repo_dir, pinned, args.default_branch)
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


# ---------- coverage pair (phase 3: ADR-016 decision 4, Track 2 option C) ----------

def coverage_out(path: str | Path, ghsa_id: str, directory: str = "coverage") -> Path:
    """Coverage (and develop-fix pair) outputs live directly in <run>/coverage/ (or <run>/develop-fix/) of the advisory's own run."""
    out = Path(path).resolve()
    record = out.parent.parent / "intake" / "intake-record.json"
    if out.parent.name != directory or not record.is_file() or load(record).get("advisory", {}).get("ghsa_id") != ghsa_id:
        raise UsageError(f"{directory} outputs for {ghsa_id} belong directly in <run>/{directory}/ of a run directory whose "
                         "intake/intake-record.json captures that advisory")
    return out


def own_intake(intake: str, out: Path) -> None:
    """A revision record binds the capture of the run it is written into (compared by digest), so a later poc-overlap check
    is matched against that run's capture; each capture has its own run directory."""
    record = out.parent.parent / "intake" / "intake-record.json"
    if file_sha256(intake) != file_sha256(record):
        raise UsageError("--intake must be the run's own intake record (the intake/intake-record.json of the run --out is in, "
                         "compared by digest); a later capture has its own run")


def names_canonical(row: Any, canonical: str) -> bool:
    """A disposition that names the canonical: COVERED by it (first or also), or UNRESOLVED with a comparison against it."""
    if not isinstance(row, dict):
        return False
    if row.get("disposition") == "COVERED":
        return row.get("canonical") == canonical or canonical in (row.get("also_covered_by") or [])
    if row.get("disposition") == "UNRESOLVED":
        return any(isinstance(entry, dict) and entry.get("earlier_ghsa_id") == canonical for entry in row.get("unresolved") or [])
    return False


def command_fix_revision(args: argparse.Namespace) -> dict[str, Any]:
    """The coverage pair: the canonical's fixing commit (named by the human) and its first parent, for the later report's
    issues that name the canonical (triage), or every technical issue of a published advisory (research variant)."""
    if args.kind == "develop-fix":
        return develop_fix_pair(args)
    for flag, value in (("--landing-branch", args.landing_branch), ("--patched", args.patched)):
        if value:
            raise UsageError(f"{flag} is for --kind develop-fix")
    for flag, value in (("--fix-commit", args.fix_commit), ("--default-branch", args.default_branch)):
        if not value:
            raise UsageError(f"the coverage pair needs {flag}")
    intake = load(args.intake)
    advisory, pinned = intake.get("advisory", {}), intake.get("pinned_target", {})
    ghsa_id = str(advisory.get("ghsa_id", ""))
    out = coverage_out(args.out, ghsa_id)
    own_intake(args.intake, out)  # D3: the capture of the run this record is written into
    issues_doc = load(args.issues)
    if issues_doc.get("record_type") != "ghsa_issue_list" or issues_doc.get("ghsa_id") != ghsa_id:
        raise UsageError("the issue list belongs to another advisory")
    issues_sha = file_sha256(args.issues)
    triage = {"--dispositions": args.dispositions, "--canonical": args.canonical, "--canonical-intake": args.canonical_intake}
    if args.research:  # D13: a published advisory (a known positive), no canonical and no dispositions
        given = [flag for flag, value in triage.items() if value]
        if given:
            raise UsageError(f"--research takes no {', '.join(given)}: the research variant has no canonical and no dispositions")
        research_advisory(intake, ghsa_id)
        canonical = ""
        issue_ids = [item["issue_id"] for item in issues_doc.get("issues", []) if item.get("technical") is True]
        if not issue_ids:
            raise UsageError("the issue list has no technical issue")
    else:
        missing = [flag for flag, value in triage.items() if not value]
        if missing:
            raise UsageError(f"the coverage pair needs {', '.join(missing)} (or --research for a published advisory)")
        dispositions = load(args.dispositions)
        if dispositions.get("record_type") != "ghsa_dispositions" or dispositions.get("ghsa_id") != ghsa_id:
            raise UsageError("the dispositions belong to another advisory")
        if dispositions.get("depends_on", {}).get("issues_sha256") != issues_sha:
            raise UsageError("the dispositions were computed from another issue list; rerun dispositions")
        if dispositions.get("rerun_pairs"):
            raise UsageError(f"the dispositions await a rerun of the comparisons with {dispositions['rerun_pairs']}; rerun step 1a first")
        status = dispositions.get("analysis_status")
        if status not in ("READY", "NO_ANALYSIS"):
            raise UsageError(f"the dispositions are {status!r}: an obvious-duplicate proposal awaits confirmation")
        canonical = str(args.canonical)
        if not GHSA_PATTERN.match(canonical):  # it reaches the pair, the outcome, and the brief
            raise UsageError(f"--canonical must be a GHSA ID, not {canonical!r}")
        capture = load(args.canonical_intake).get("advisory", {})
        if capture.get("ghsa_id") != canonical:
            raise UsageError("--canonical-intake captures another advisory than --canonical")
        if capture.get("state") not in OPEN_STATES:
            raise UsageError(f"{canonical} is {capture.get('state')!r}: a published or closed match, which the pin's analysis covers; "
                             "post-fix coverage applies only while the canonical is open (triage or draft)")
        issue_ids = [row["issue_id"] for row in dispositions.get("issues", []) if names_canonical(row, canonical)]
        if not issue_ids:
            raise UsageError(f"no issue of {ghsa_id} names {canonical} in its dispositions")
    repo, repository, ref, pin = pinned_clone(args.repo_dir, pinned, args.default_branch)
    commit_id_argument("--fix-commit", args.fix_commit)
    code, resolved = git(repo, "rev-parse", "--verify", "--quiet", f"{args.fix_commit}^{{commit}}", allow_failure=True)
    target = resolved.strip()
    if code != 0 or not SHA_PATTERN.match(target):
        raise UsageError(f"--fix-commit {args.fix_commit!r} is not a commit in the clone; fetch origin first")
    shadowed_commit_id("--fix-commit", args.fix_commit, target)
    if target not in git(repo, "rev-list", "--first-parent", ref)[1].split():
        raise UsageError(f"{target} is not on the first-parent line of origin/{args.default_branch}: name the commit that merged the fix")
    if git(repo, "merge-base", "--is-ancestor", target, pin, allow_failure=True)[0] != 0:
        raise UsageError(f"{target} is not an ancestor of the pin {pin}: the capture predates it, or it is not on the default branch")
    code, parent = git(repo, "rev-parse", "--verify", "--quiet", f"{target}^1^{{commit}}", allow_failure=True)
    base = parent.strip()
    if code != 0 or not SHA_PATTERN.match(base):
        raise UsageError(f"{target} has no parent, so there is no base to test before the fix")
    analysis_revision, records_sha = base, ""
    if args.analysis_records:  # D9: an earlier analysis supplies the contract only when it ran at the base or an ancestor of it
        records = load(args.analysis_records)
        if records.get("ghsa_id") != ghsa_id or records.get("issues_sha256") != issues_sha:
            raise UsageError("the analysis records belong to another advisory or issue list")
        if (records.get("research_only") is True) != bool(args.research):
            raise UsageError("the analysis records come from the other path (research-only and triage)")
        revision = str(records.get("primary_revision", ""))
        if not SHA_PATTERN.match(revision) or not commit_exists(repo, revision) \
                or git(repo, "merge-base", "--is-ancestor", revision, base, allow_failure=True)[0] != 0:
            raise UsageError(f"the analysis records' revision {revision or '(none)'} is not the base or an ancestor of the base; "
                             "their contract cannot be reused")
        analysis_revision, records_sha = revision, file_sha256(args.analysis_records)
    document = {"record_type": "ghsa_revision_pair", "kind": "coverage", "ghsa_id": ghsa_id, "repository": repository,
                "default_branch": args.default_branch, "base": base, "target": target, "pin": pin, "canonical": canonical,
                "research_only": bool(args.research), "issues": issue_ids, "analysis_revision": analysis_revision,
                "intake_sha256": file_sha256(args.intake), "issues_sha256": issues_sha,
                "dispositions_sha256": file_sha256(args.dispositions) if args.dispositions else "",
                "canonical_intake_sha256": file_sha256(args.canonical_intake) if args.canonical_intake else "",
                "analysis_records_sha256": records_sha}
    dump_private(out, document)
    return {"status": "COMPLETE", "base": base, "target": target, "issues": issue_ids, "out": str(out)}


COMMIT_ID_PREFIX = re.compile(r"^[0-9A-Fa-f]{4,40}\Z")  # \Z: no trailing newline


def commit_id_argument(flag: str, given: str) -> None:
    """Only a commit ID (full or abbreviated): a ref name or a suffix (^, ~) would let a ref decide which commit is meant."""
    if not COMMIT_ID_PREFIX.match(given):
        raise UsageError(f"{flag} must be a commit ID (4 to 40 hexadecimal characters), not {given!r}")


def shadowed_commit_id(flag: str, given: str, resolved: str) -> None:
    """git resolves a ref name before a short object ID, so a tag or branch spelled like a commit ID would redirect it."""
    if COMMIT_ID_PREFIX.match(given) and not resolved.startswith(given.lower()):
        raise UsageError(f"{flag} {given!r} resolves to {resolved}, of which it is not a prefix: a ref spelled like a commit ID "
                         "shadows it; give the full commit ID")


def develop_fix_pair(args: argparse.Namespace) -> dict[str, Any]:
    """The develop-fix pair (D5c b): the analysis revision the fix was authored from and the candidate patch's commit on the
    local landing branch, so the security gate's evidence comes from the same bound test-result as the other kinds."""
    for flag, value in (("--fix-commit", args.fix_commit), ("--default-branch", args.default_branch), ("--dispositions", args.dispositions),
                        ("--canonical", args.canonical), ("--canonical-intake", args.canonical_intake), ("--research", args.research)):
        if value:
            raise UsageError(f"{flag} is not an argument of --kind develop-fix (the analysis records carry the path)")
    for flag, value in (("--landing-branch", args.landing_branch), ("--patched", args.patched), ("--analysis-records", args.analysis_records)):
        if not value:
            raise UsageError(f"--kind develop-fix needs {flag}")
    intake = load(args.intake)
    advisory, pinned = intake.get("advisory", {}), intake.get("pinned_target", {})
    ghsa_id, repository = str(advisory.get("ghsa_id", "")), str(pinned.get("repository", ""))
    out = coverage_out(args.out, ghsa_id, "develop-fix")
    own_intake(args.intake, out)  # D3: the capture of the run this record is written into
    issues_doc = load(args.issues)
    if issues_doc.get("record_type") != "ghsa_issue_list" or issues_doc.get("ghsa_id") != ghsa_id:
        raise UsageError("the issue list belongs to another advisory")
    records = load(args.analysis_records)
    if records.get("ghsa_id") != ghsa_id:
        raise UsageError("the analysis records belong to another advisory")
    if records.get("issues_sha256") != file_sha256(args.issues):
        raise UsageError("the analysis records were made for another issue list")
    if not repository or str(records.get("repository", "")).lower() != repository.lower():
        raise UsageError("the analysis records describe another repository than the capture")
    issue_ids = [item["issue_id"] for item in issues_doc.get("issues", []) if any(
        record.get("final_status") == VERIFIED and record.get("bridged") is True
        and any(answer.get("ghsa_id") == ghsa_id and answer.get("issue_id") == item["issue_id"] for answer in record.get("answers", []))
        for record in records.get("records", []))]
    if not issue_ids:
        raise UsageError("the analysis records have no bridged CROSS-MODEL VERIFIED finding answering an issue; there is no fix to gate")
    if not BRANCH_PATTERN.match(args.landing_branch) or ".." in args.landing_branch:
        raise UsageError(f"not a valid branch name: {args.landing_branch!r}")
    repo = clone_path(args.repo_dir)
    branch = f"refs/heads/{args.landing_branch}"
    if git(repo, "rev-parse", "--verify", "--quiet", f"{branch}^{{commit}}", allow_failure=True)[0] != 0:
        raise UsageError(f"the landing repository has no branch {args.landing_branch}")
    commit_id_argument("--patched", args.patched)
    code, resolved = git(repo, "rev-parse", "--verify", "--quiet", f"{args.patched}^{{commit}}", allow_failure=True)
    target = resolved.strip()
    if code != 0 or not SHA_PATTERN.match(target):
        raise UsageError(f"--patched {args.patched!r} is not a commit in the landing repository")
    shadowed_commit_id("--patched", args.patched, target)
    if git(repo, "merge-base", "--is-ancestor", target, branch, allow_failure=True)[0] != 0:
        raise UsageError(f"{target} is not on the landing branch {args.landing_branch}")
    base = str(records.get("primary_revision", ""))
    if not SHA_PATTERN.match(base) or base == target or not commit_exists(repo, base) \
            or git(repo, "merge-base", "--is-ancestor", base, target, allow_failure=True)[0] != 0:
        raise UsageError(f"the patched commit does not descend from the analysis revision {base or '(none)'}; the patch must be "
                         "authored on the revision the contract was converged at")
    document = {"record_type": "ghsa_revision_pair", "kind": "develop-fix", "ghsa_id": ghsa_id, "repository": repository,
                "base": base, "target": target, "landing_branch": args.landing_branch, "pin": str(pinned.get("revision", "")),
                "canonical": "", "research_only": records.get("research_only") is True, "issues": issue_ids, "analysis_revision": base,
                "intake_sha256": file_sha256(args.intake), "issues_sha256": file_sha256(args.issues),
                "analysis_records_sha256": file_sha256(args.analysis_records)}
    dump_private(out, document)
    return {"status": "COMPLETE", "base": base, "target": target, "issues": issue_ids, "out": str(out)}


# ---------- plan ----------

KNOWN_STATUSES = (VERIFIED, "DISPUTED", "INCOMPLETE", "NOT VERIFIED", "REFUTED")
NOT_ROUTED = "NOT ROUTED"  # ghsa-dedup.py records: a candidate no role marked as affecting a security claim


def issue_causes(records: list[dict[str, Any]], ghsa_id: str) -> dict[str, list[dict[str, Any]]]:
    """Each issue's recorded INCOMPLETE causes (from the verification manifest, through records), for the brief only."""
    causes: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        listed = record.get("status_causes")
        for cause in listed if isinstance(listed, list) else []:
            if not isinstance(cause, dict):
                continue
            for answer in record.get("answers", []):
                if answer.get("ghsa_id") == ghsa_id:
                    found = causes.setdefault(answer.get("issue_id", ""), [])
                    if cause not in found:
                        found.append(cause)
    return causes


def issue_records(records: list[dict[str, Any]], ghsa_id: str) -> dict[str, list[dict[str, Any]]]:
    """Each issue's answering records with their own statuses (D4 a), for the brief only: rule 7 decides the issue's
    status, and the human still sees a verified record beside a disputed one."""
    listed: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        entry = {"record_id": str(record.get("record_id", "")), "candidate_id": str(record.get("candidate_id", "")),
                 "final_status": str(record.get("final_status", "")), "bridged": record.get("bridged") is True,
                 "ghsa_eligible": record.get("ghsa_eligible") is True}
        for answer in record.get("answers", []):
            if answer.get("ghsa_id") == ghsa_id:
                found = listed.setdefault(answer.get("issue_id", ""), [])
                if entry not in found:
                    found.append(entry)
    return listed


def issue_statuses(records: list[dict[str, Any]], ghsa_id: str, eligible_only: bool = False) -> dict[str, list[str]]:
    """Each issue's records' final statuses. An unknown or empty status is INCOMPLETE; a NOT ROUTED record (no role said it
    affects a security claim) is left out. With eligible_only, a verified
    record that is not bridged counts as UNBRIDGED (analysis evidence for 'fixed' needs a bridged record; research-only
    records are bridged but never write-back eligible)."""
    statuses: dict[str, list[str]] = {}
    for record in records:
        status = str(record.get("final_status", ""))
        if status == NOT_ROUTED:  # no role said it affects a security claim: neither a confirmation nor an unfinished analysis
            continue
        status = status if status in KNOWN_STATUSES else "INCOMPLETE"
        if eligible_only and status == VERIFIED and record.get("bridged") is not True:
            status = "UNBRIDGED"
        for answer in record.get("answers", []):
            if answer.get("ghsa_id") == ghsa_id:
                statuses.setdefault(answer.get("issue_id", ""), []).append(status)
    return statuses


def command_plan(args: argparse.Namespace) -> dict[str, Any]:
    issues_doc, records_doc = load(args.issues), load(args.records)
    if records_doc.get("coverage") is True:
        raise UsageError("these are post-fix coverage records; the currency plan reads the analysis at the pin")
    ghsa_id = issues_doc.get("ghsa_id", "")
    out = currency_out(args.out, ghsa_id)
    issues_sha = file_sha256(args.issues)
    technical = {item["issue_id"]: item for item in issues_doc.get("issues", []) if item.get("technical")}
    if args.research:  # a published advisory: no dispositions, and analysis received every technical issue
        if args.dispositions:
            raise UsageError("--research takes no --dispositions: on the research-only path every technical issue was analyzed")
        if not args.intake:
            raise UsageError("--research needs --intake, so the advisory's captured state can be checked")
        research_advisory(load(args.intake), ghsa_id)
        if file_sha256(args.intake) != file_sha256(out.parent.parent / "intake" / "intake-record.json"):
            raise UsageError("--intake must be the run's own intake record (the run directory's intake record)")
        if records_doc.get("research_only") is not True:
            raise UsageError("--research needs research-only records (ghsa-dedup.py records --research)")
        analysis_ids = [item["issue_id"] for item in issues_doc.get("issues", []) if item.get("technical") is True]
        dispositions_sha, intake_sha = "", file_sha256(args.intake)
        disposition_rows: dict[str, dict[str, Any]] = {}
    else:
        if not args.dispositions:
            raise UsageError("plan needs --dispositions; a published advisory has none, so use the research-only path "
                             "(--research --intake)")
        dispositions = load(args.dispositions)
        if dispositions.get("record_type") != "ghsa_dispositions" or dispositions.get("ghsa_id") != ghsa_id:
            raise UsageError("the dispositions belong to another advisory")
        if dispositions.get("depends_on", {}).get("issues_sha256") != issues_sha:
            raise UsageError("the dispositions were computed from another issue list")
        if dispositions.get("analysis_status") != "READY":
            raise UsageError(f"the currency check needs analysis_status READY, not {dispositions.get('analysis_status')!r}")
        if records_doc.get("research_only") is True:
            raise UsageError("these are research-only records; plan them with --research")
        analysis_ids = list(dispositions.get("analysis_issue_ids", []))
        dispositions_sha, intake_sha = file_sha256(args.dispositions), ""
        disposition_rows = {row.get("issue_id", ""): row for row in dispositions.get("issues", []) if isinstance(row, dict)}
    if records_doc.get("ghsa_id") != ghsa_id or records_doc.get("issues_sha256") != issues_sha:
        raise UsageError("the records belong to another advisory or another issue list")
    revision = revision_record(args.revision)
    if revision.get("ghsa_id") != ghsa_id:
        raise UsageError("the revision record belongs to another advisory")
    if records_doc.get("primary_revision") != revision["pin"]:
        raise UsageError(f"the records describe an analysis at another pin ({records_doc.get('primary_revision')}) than the revision "
                         f"record's pin ({revision['pin']}); analyze at that pin, or compute the revision from the analysis run's own intake")
    statuses = issue_statuses(records_doc.get("records", []), ghsa_id)
    causes = issue_causes(records_doc.get("records", []), ghsa_id)
    answering = issue_records(records_doc.get("records", []), ghsa_id)
    every = {item["issue_id"]: item for item in issues_doc.get("issues", [])}
    planned, not_planned = [], []
    for issue_id in analysis_ids:
        mechanism = every.get(issue_id, {}).get("mechanism", "")
        if issue_id not in technical:
            not_planned.append({"issue_id": issue_id, "mechanism": mechanism, "reason": "NOT_TECHNICAL",
                                "kinds": every.get(issue_id, {}).get("kinds", {})})
            continue
        found = statuses.get(issue_id, [])
        if VERIFIED in found:  # confirmed at the pin, bridged or not (a split resolved by a frozen test is not bridged)
            not_planned.append({"issue_id": issue_id, "mechanism": mechanism, "reason": "CONFIRMED",
                                "records": answering.get(issue_id, [])})  # D5: a verified record beside a disputed one
            continue
        reason = next((status for status in REASON_ORDER if status in found), "NO_RECORD")
        planned.append({"issue_id": issue_id, "mechanism": mechanism, "reason": reason, "causes": causes.get(issue_id, []),
                        "records": answering.get(issue_id, [])})
    for issue_id, item in every.items():  # the rest of the list, so the brief can show every issue
        if issue_id in analysis_ids:
            continue
        row = disposition_rows.get(issue_id, {})
        if item.get("technical") is not True:
            not_planned.append({"issue_id": issue_id, "mechanism": item.get("mechanism", ""), "reason": "NOT_TECHNICAL",
                                "kinds": item.get("kinds", {})})
        elif row.get("disposition") == "COVERED":
            not_planned.append({"issue_id": issue_id, "mechanism": item.get("mechanism", ""), "reason": "COVERED",
                                "canonical": row.get("canonical", "")})
        else:
            not_planned.append({"issue_id": issue_id, "mechanism": item.get("mechanism", ""), "reason": "NOT_ANALYZED",
                                "disposition": row.get("disposition", "")})
    order = {issue_id: index for index, issue_id in enumerate(every)}
    not_planned.sort(key=lambda entry: order.get(entry["issue_id"], len(order)))
    document = {"record_type": "ghsa_currency_plan", "ghsa_id": ghsa_id, "mode": "RESEARCH_ONLY" if args.research else "TRIAGE",
                "primary_revision": records_doc.get("primary_revision", ""), "issues_sha256": issues_sha,
                "dispositions_sha256": dispositions_sha, "intake_sha256": intake_sha, "records_sha256": file_sha256(args.records),
                "planned": planned, "not_planned": not_planned}
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


def definition_ranges(repo: Path, revision: str, name: str, path: str) -> list[tuple[int, int]] | None:
    """Each `fn name` definition's line range in `path` at `revision`: from its line to the line before the next function
    header (git's -L :<funcname> rule), or the end of the file. None when the file cannot be read there."""
    code, text = git(repo, "show", f"{revision}:{path}", allow_failure=True)
    if code != 0:
        return None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    definition = re.compile(f"fn {name}([^A-Za-z0-9_]|$)")
    headers = [number for number, line in enumerate(lines, 1) if RUST_FUNCNAME.match(line)]
    ranges = []
    for number, line in enumerate(lines, 1):
        if definition.search(line):
            following = [header for header in headers if header > number]
            ranges.append((number, following[0] - 1 if following else len(lines)))
    return ranges


def function_commits(repo: Path, start: str, end: str, name: str, path: str, attributes: Path,
                     line_range: tuple[int, int] | None = None) -> list[dict[str, str]] | None:
    """Commits in start..end that touch `fn name` in `path` (the path as it is at `end`), or the given line range of it
    at `end`; None when git cannot follow it (for example the function is gone at `end`), which is not the same as unchanged."""
    spec = f"-L{line_range[0]},{line_range[1]}:{path}" if line_range else f"-L:fn {name}[^A-Za-z0-9_]:{path}"
    code, out = git(repo, "log", "--no-ext-diff", "--no-textconv", "--format=%x00%H%x09%s", "--no-patch",
                    spec, f"{start}..{end}", allow_failure=True,
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
        at_pin_only = not defined
        if at_pin_only:  # a control site added after the report: find it at the pin and follow it from the report revision
            defined = grep_files(repo, end, f"fn {name}([^A-Za-z0-9_]|$)")
        # The issue's own files first; otherwise only a unique definition, since a generic name defined in several files
        # would list commits from unrelated code.
        scoped = [path for path in defined if path in named or (at_pin_only and path in pin_paths)] or (defined if len(defined) == 1 else [])
        definitions[name] = {"files": scoped, "definition_count": len(defined), **({"defined_at": "pin"} if at_pin_only and defined else {})}
        for path in scoped:
            pin_path = path if at_pin_only else renames.get(path, path)
            count = definitions_in_file(repo, end if at_pin_only else start, name, path)
            if count > 1:  # several same-named definitions (methods of two types, platform variants): follow each one's range
                ranges = definition_ranges(repo, end, name, pin_path)
                if ranges is None:
                    history.append({"symbol": name, "path": path, "status": "AMBIGUOUS_IN_FILE"})
                    continue
                for line_range in ranges:
                    found = function_commits(repo, start, end, name, pin_path, attributes, line_range)
                    history.append({"symbol": name, "path": path, "status": "OK" if found is not None else "UNAVAILABLE_AT_PIN",
                                    "line": line_range[0]})
                    for entry in found or []:
                        commits.setdefault((entry["commit"], path, line_range[0]), dict(entry, symbol=name, path=path, line=line_range[0]))
                if len(ranges) < count:  # a definition is gone at the pin; which one cannot be told from line numbers
                    history.append({"symbol": name, "path": path, "status": "UNAVAILABLE_AT_PIN", "missing_definitions": count - len(ranges)})
                continue
            found = function_commits(repo, start, end, name, pin_path, attributes)
            history.append({"symbol": name, "path": path, "status": "OK" if found is not None else "UNAVAILABLE_AT_PIN"})
            for entry in found or []:
                commits.setdefault(entry["commit"], dict(entry, symbol=name, path=path))  # one entry per commit, as before
    return {"issue_id": issue["issue_id"], "anchors": anchors, "rejected_anchors": rejected, "presence": presence,
            "renames": issue_renames, "symbols": symbols, "definitions": definitions, "function_history": history,
            "function_commits": sorted(commits.values(), key=lambda entry: (entry["commit"], entry["path"], entry.get("line", 0))),
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


# The two endpoints of each kind of revision pair: the --which names and the registry suffixes (<name>@<suffix>).
PAIR_SUFFIXES = {"currency": ("report", "pin"), "coverage": ("base", "target"), "develop-fix": ("base", "target")}


def revision_pair(path: str) -> dict[str, Any]:
    """A currency revision record (report revision, pin) or a coverage pair record (base, target): its kind, its record,
    and per side (keyed "report" for the earlier endpoint and "pin" for the later one) the revision and the suffix."""
    record = load(path)
    if record.get("record_type") == "ghsa_currency_revision":
        revision_record(path)
        kind, revisions = "currency", (record["report_revision"], record["pin"])
    elif record.get("record_type") == "ghsa_revision_pair" and record.get("kind") in ("coverage", "develop-fix") \
            and SHA_PATTERN.match(str(record.get("base", ""))) and SHA_PATTERN.match(str(record.get("target", ""))):
        kind, revisions = str(record["kind"]), (record["base"], record["target"])
    else:
        raise UsageError("--revision is not a currency revision record or a coverage or develop-fix pair record")
    names = PAIR_SUFFIXES[kind]
    return {"kind": kind, "record": record, "revisions": {"report": revisions[0], "pin": revisions[1]},
            "suffix": {"report": names[0], "pin": names[1]}}


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
    if not HEX64.match(str(test.get("profile_sha256", ""))):
        raise UsageError(f"{path} names no sandbox profile digest")
    if not isinstance(test.get("candidate_id"), str) or not test["candidate_id"]:
        raise UsageError(f"{path} names no candidate")
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
    inputs = test.get("inputs") if isinstance(test.get("inputs"), dict) else {}
    checks = [entry for entry in inputs.get("poc_overlap") or [] if isinstance(entry, dict) and entry.get("ghsa_id") == ghsa_id]
    bound = str(revision.get("intake_sha256", ""))  # the binding test-result checked, held again here: a recapture keeps the revisions
    if not checks or not HEX64.match(bound) or any(entry.get("intake_sha256") != bound for entry in checks):
        raise UsageError(f"{path}: its poc-overlap checks were not run against the capture the revision record binds "
                         "(intake_sha256); rerun poc-overlap and test-result with that capture")
    return test


def failures_of(block: Any) -> dict[str, str]:
    """A validation block's recorded failure messages (test name -> excerpt); untrusted text for the human brief only."""
    found = block.get("failures") if isinstance(block, dict) else None
    return {str(name): text for name, text in found.items() if isinstance(text, str)} if isinstance(found, dict) else {}


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
    research = plan.get("mode") == "RESEARCH_ONLY"
    report_status: dict[str, str] | None = None
    if args.report_records:
        records = load(args.report_records)
        if records.get("ghsa_id") != ghsa_id or records.get("issues_sha256") != plan.get("issues_sha256"):
            raise UsageError("the report-revision records belong to another advisory or another issue list")
        if records.get("coverage") is True:  # never eligible, so every planned issue would read as NO_RECORD
            raise UsageError("these are post-fix coverage records; the currency check reads the report-revision analysis's records")
        if records.get("primary_revision") != revision["report_revision"]:
            raise UsageError("the report-revision records describe another revision than the report revision")
        if (records.get("research_only") is True) != research:
            raise UsageError("the plan and the report-revision records come from different paths: research-only inputs go "
                             "together (plan --research, records --research), and triage inputs go together")
        if any(not isinstance(record.get("bridged"), bool) for record in records.get("records", [])):
            raise UsageError("the report-revision records carry no bridged field; rerun ghsa-dedup.py records with this version")
        statuses = issue_statuses(records.get("records", []), ghsa_id, eligible_only=True)
        report_status = {issue_id: next((s for s in REPORT_ORDER if s in found), "NO_RECORD") for issue_id, found in statuses.items()}
        report_causes = issue_causes(records.get("records", []), ghsa_id)
        report_records = issue_records(records.get("records", []), ghsa_id)
    else:
        report_causes, report_records = {}, {}
    tests: dict[str, dict[str, Any]] = {}
    if args.test and not args.report_records:
        raise UsageError("--test needs --report-records: a test counts only with the report-revision records it was built from")
    for path in args.test or []:
        test = load_test(path, ghsa_id, revision, plan, set(planned))
        built_from = test.get("inputs", {}).get("report_records_sha256") if isinstance(test.get("inputs"), dict) else None
        if built_from != file_sha256(args.report_records):
            raise UsageError(f"{path} was built from other report-revision records than --report-records (the analysis changed since); "
                             "rerun test-result")
        if test["issue_id"] in tests:
            raise UsageError(f"two test results for {test['issue_id']}")
        tests[test["issue_id"]] = test
    issues = []
    for issue_id, entry in planned.items():
        main = entry.get("reason", "")
        report = None if report_status is None else report_status.get(issue_id, "NO_RECORD")
        test = tests.get(issue_id)
        outcome, evidence, reason = decide(main, report, test, revision["report_revision"] == revision["pin"])
        main_causes = [cause for cause in entry.get("causes", []) if isinstance(cause, dict)] if isinstance(entry.get("causes"), list) else []
        main_records = [record for record in entry.get("records", []) if isinstance(record, dict)] if isinstance(entry.get("records"), list) else []
        issues.append({"issue_id": issue_id, "mechanism": entry.get("mechanism", ""), "outcome": outcome, "evidence": evidence,
                       "reason": reason, "main_status": main, "report_status": report,
                       "main_causes": main_causes, "report_causes": report_causes.get(issue_id, []),
                       "main_records": main_records, "report_records": report_records.get(issue_id, []),
                       "test": None if test is None else {"base_validation": test["base_validation"], "pin_validation": test["pin_validation"],
                                                          "at_pin": test["at_pin"], "validated": validated(test),
                                                          "build": test.get("build", {}), "candidate_id": test.get("candidate_id", ""),
                                                          "proposition": test.get("proposition", ""),
                                                          "control_sites": test.get("control_sites", []),
                                                          "sink_matches_control_site": test.get("sink_matches_control_site") is True,
                                                          "failures": {"report": failures_of(test["base_validation"]),
                                                                       "pin": failures_of(test["pin_validation"])}},
                       # A failing test at the pin contradicts the pin's analysis only when that analysis refuted or did not verify
                       # the issue; a disputed or unfinished analysis is not contradicted.
                       "contradiction": outcome == "STILL_PRESENT" and main in NOT_CONFIRMED})
    document = {"record_type": "ghsa_currency_outcome", "ghsa_id": ghsa_id, "issues_sha256": plan.get("issues_sha256", ""),
                "research_only": research, "report_revision_analyzed": report_status is not None,
                "not_planned": [entry for entry in plan.get("not_planned", []) if isinstance(entry, dict)],
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
    return "".join(json_escape(char) if unicodedata.category(char) in ("Cc", "Cf", "Cs", "Zl", "Zp") else char for char in text)


def per_definition(entry: dict[str, Any]) -> dict[tuple[str, str], int]:
    """Functions followed definition by definition (several same-named definitions in one file), with how many."""
    counts: dict[tuple[str, str], int] = {}
    for item in entry.get("function_history", []):
        if isinstance(item.get("line"), int):
            key = (str(item.get("symbol", "")), str(item.get("path", "")))
            counts[key] = counts.get(key, 0) + 1
    return counts


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
        where = " at the pin only (not at the report revision)" if definition.get("defined_at") == "pin" else ""
        lines.append(f"    function {one_line_json(name)}: defined in {definition.get('definition_count', 0)} file(s){where}; {looked_up}")
    for (name, path), count in sorted(per_definition(entry).items()):
        lines.append(f"    function {one_line_json(name)} in {one_line_json(path)}: {count} same-named definition(s) followed separately")
    if entry.get("rejected_anchors"):
        lines.append("    rejected anchors (not checked): " + one_line_json([a.get("value", "") for a in entry["rejected_anchors"]]))
    commits = entry.get("function_commits", [])
    lines.append(f"    function commits (unverified fixing-commit candidates): {len(commits)}")
    lines += [f"      {c['commit']} {one_line_json(c.get('subject', ''))} ({one_line_json(c.get('symbol', ''))} in "
              f"{one_line_json(c.get('path', ''))}" + (f" at line {c['line']}" if isinstance(c.get("line"), int) else "") + ")"
              for c in commits]
    unavailable = [h for h in entry.get("function_history", []) if h.get("status") != "OK"]
    if unavailable:
        lines.append("    history not followed (not the same as unchanged): "
                     + one_line_json([f"{h['symbol']} in {h['path']}: " + (f"{h['missing_definitions']} definition gone at the pin"
                                      if isinstance(h.get("missing_definitions"), int) else h["status"]
                                      + (f" at line {h['line']}" if isinstance(h.get("line"), int) else "")) for h in unavailable]))
    lines.append(f"    file commits: {entry.get('file_commit_count', 0)}")
    return lines


CAUSE_KINDS = ("REFUSED", "MALFORMED", "FAILED", "MISSING")
GHSA_PATTERN = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\Z")


def cause_line(cause: dict[str, Any]) -> str:
    """Why an analysis is INCOMPLETE, from the verification manifest; every value is shown as one-line JSON."""
    kind = str(cause.get("kind", ""))
    text = {key: one_line_json(str(cause.get(key, ""))) for key in ("role", "stage", "provider", "model", "effort")}
    return (f"{kind if kind in CAUSE_KINDS else one_line_json(kind)} by {text['role']} ({text['stage']}; {text['provider']} {text['model']}, "
            f"effort {text['effort']}); declined or missing: {one_line_json(cause.get('items', []))}")


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
    research = [("Research only: a published advisory analyzed outside triage. This is not a triage decision, and nothing here "
                 "may be written back to the advisory or posted to the reporter.")] if outcome.get("research_only") is True else []
    lines = ["# Currency check brief", *research,
             ("Rendered by currency-check.py brief for the human decision. Outcomes are proposals; nothing has been dismissed, "
              "closed, or written back. Anchors and commit subjects come from the report and the repository; they appear as "
              "one-line JSON strings."),
             f"Context: advisory {ghsa_id}, report revision {outcome.get('report_revision')}, pin {outcome.get('pin')}",
             ("No report-revision analysis ran, so no fix wording reached one." if outcome.get("report_revision_analyzed") is False
              else "Fix wording in the description the report-revision analysis saw: "
              + ("not checked (pass --fix-terms)" if fix_terms is None
                 else ", ".join(one_line_json(term) for term in fix_terms) or "none of the listed phrases"))]
    not_planned = [entry for entry in outcome.get("not_planned", []) if isinstance(entry, dict)]
    if not outcome.get("issues") and any(entry.get("reason") == "CONFIRMED" for entry in not_planned):
        lines.append("Every analyzed technical issue was confirmed at the pin, so nothing was planned for the two-revision check.")
    lines.append("")
    for entry in outcome.get("issues", []):
        lines += [f"## {entry['issue_id']}", f"Mechanism: {one_line_json(entry.get('mechanism', ''))}",
                  f"Outcome: {entry['outcome']} (evidence {entry['evidence']})" + (f", reason {entry['reason']}" if entry.get("reason") else ""),
                  (f"Analysis at the pin: {entry.get('main_status')} | at the report revision: "
                   f"{entry.get('report_status') or 'not analyzed'}")]
        for side, key in (("the pin", "main_records"), ("the report revision", "report_records")):  # D4 (a): each record's own status
            lines += [f"Record at {side}: {one_line_json(record)}" for record in entry.get(key, []) if isinstance(record, dict)]
        for side, key in (("the pin", "main_causes"), ("the report revision", "report_causes")):
            lines += [f"Cause at {side}: {cause_line(cause)}" for cause in entry.get(key, []) if isinstance(cause, dict)]
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
        if test:
            build = test.get("build", {}) if isinstance(test.get("build"), dict) else {}
            shown = {side: build.get(side) if build.get(side) in ("PASSED", "FAILED", "UNRESOLVED") else "unknown" for side in SIDES}
            lines.append(f"Test build: build at the report revision {shown['report']}, at the pin {shown['pin']}")
            sinks = []
            for side, key in (("report revision", "base_validation"), ("pin", "pin_validation")):
                sink = test.get(key, {}).get("sink") if isinstance(test.get(key), dict) else None
                where = str(sink.get("location", "")) if isinstance(sink, dict) else ""
                path, _, line = where.rpartition(":")
                count = sink.get("count") if isinstance(sink, dict) and isinstance(sink.get("count"), int) else 0
                sinks.append(f"{side} {where if valid_path(path) and line.isdigit() else one_line_json(where)} (count {count})")
            lines.append("Test sinks: " + ", ".join(sinks))
            candidate = str(test.get("candidate_id", ""))
            candidate = candidate if re.fullmatch(r"[A-Za-z0-9_.:-]+", candidate) else one_line_json(candidate)
            lines.append(f"Test candidate: {candidate}; proposition: {one_line_json(str(test.get('proposition', '')))}")
            if test.get("sink_matches_control_site") is not True:
                sink = test.get("base_validation", {}).get("sink")
                location = str(sink.get("location", "")) if isinstance(sink, dict) else ""
                path, _, line = location.rpartition(":")
                location = location if valid_path(path) and line.isdigit() else one_line_json(location)
                named = []
                for site in test.get("control_sites", []) if isinstance(test.get("control_sites"), list) else []:
                    site_path = str(site.get("relative_path", "")) if isinstance(site, dict) else ""
                    site_line = site.get("line") if isinstance(site, dict) else None
                    named.append(f"{site_path}:{site_line}" if valid_path(site_path) and isinstance(site_line, int) else one_line_json(site))
                lines.append(f"Note: the test's sink ({location}) is not in a file named by a verified control site of the report "
                             "revision's analysis; check that the test reaches the reported code (verified control sites: "
                             + (", ".join(named) or "none") + ").")
        if test:
            failures = test.get("failures")
            for side, label in (("report", "the report revision"), ("pin", "the pin")):
                found = failures.get(side) if isinstance(failures, dict) else None
                for name, text in (found.items() if isinstance(found, dict) else ()):
                    shown = name if FUNCTION_NAME.match(str(name)) else one_line_json(str(name))
                    lines.append(f"Test failure at {label} ({shown}): " + (one_line_json(text) if text else "no failure message found"))
        if entry.get("outcome") == "STILL_PRESENT":
            check = "check whether the test asserts more than the invariant (see the failing assertion above)"
            main = str(entry.get("main_status", ""))
            lines.append(f"Note: the test still fails at the pin, which contradicts the analysis at the pin; {check}, and a human should look."
                         if entry.get("contradiction") else
                         f"Note: the test still fails at the pin, while the analysis at the pin was "
                         f"{main if main in REASON_ORDER + ('NO_RECORD',) else one_line_json(main)}; {check}.")
        if entry["issue_id"] in flags_by_issue:
            lines += flag_lines(flags_by_issue[entry["issue_id"]])
        lines += ["Options: accept the proposal, or analyze again (for example with a test, or at a newer pin).", ""]
    for entry in not_planned:
        reason = str(entry.get("reason", ""))
        canonical = str(entry.get("canonical", ""))
        details = {"CONFIRMED": " (a CROSS-MODEL VERIFIED record of the analysis at the pin answers it)",
                   "COVERED": f" (covered in step 1a by {canonical if GHSA_PATTERN.match(canonical) else one_line_json(canonical)}; "
                              "not analyzed)",
                   "NOT_TECHNICAL": f" (kinds {one_line_json(entry.get('kinds', {}))})",
                   "NOT_ANALYZED": f" (disposition {one_line_json(entry.get('disposition', ''))})"}
        lines += [f"## {entry.get('issue_id')} (not planned)", f"Mechanism: {one_line_json(entry.get('mechanism', ''))}",
                  f"Not planned: {reason if reason in details else one_line_json(reason)}{details.get(reason, '')}"]
        found = entry.get("records")
        listed = found if isinstance(found, list) else []
        lines += [f"Record at the pin: {one_line_json(record)}" for record in listed if isinstance(record, dict)]
        if entry.get("issue_id") in flags_by_issue:
            lines += flag_lines(flags_by_issue[entry["issue_id"]])
        lines.append("")
    restricted_dir(out.parent)
    data = encoded("\n".join(lines), out)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)
    return {"status": "COMPLETE", "issues": len(outcome.get("issues", [])), "out": str(out)}


# ---------- test-only entry: checkout, sandbox profile, result ----------

def command_checkout(args: argparse.Namespace) -> dict[str, Any]:
    """A detached checkout of one endpoint inside the sandbox directory, so deterministic-check can read its HEAD.
    The clone is only read: `git clone --local --no-hardlinks` copies its objects; hooks are disabled in the copy."""
    ends = revision_pair(args.revision)
    sides = {suffix: side for side, suffix in ends["suffix"].items()}
    if args.which not in sides:
        raise UsageError(f"--which {args.which} is not an endpoint of a {ends['kind']} record: use {' or '.join(PAIR_SUFFIXES[ends['kind']])}")
    sha = ends["revisions"][sides[args.which]]
    repo = clone_path(args.repo_dir)
    sandbox = Path(args.sandbox_dir).resolve(strict=True)
    destination = sandbox / args.which
    if destination.exists():
        raise UsageError(f"{destination} already exists")
    if sandbox == repo or sandbox.is_relative_to(repo) or repo.is_relative_to(sandbox):
        raise UsageError("the sandbox directory must not be the clone, inside it, or contain it")
    placements = test_files(args.test_file or [], repo, sha)
    environment = dict(GIT_ENVIRONMENT, PATH=os.environ.get("PATH", os.defpath), GIT_CONFIG_GLOBAL=os.devnull, HOME=os.devnull,
                       GIT_ALLOW_PROTOCOL="file")  # a local copy only; still no network transport
    for step, argv in (("clone", ["git", "clone", "-q", "--local", "--no-hardlinks", "--dissociate", "--no-checkout", str(repo),
                                  str(destination)]),
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
    placed = {}
    for relative, source in placements:
        target = destination / relative
        existing = target.parent
        while not existing.exists() and not existing.is_symlink():  # the nearest existing ancestor must already be inside,
            existing = existing.parent                              # so mkdir creates nothing through a link out
        if not existing.resolve().is_relative_to(destination):
            raise UsageError(f"--test-file {relative}: its directory leads out of the checkout, or the file exists")
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.parent.resolve().is_relative_to(destination) or target.exists() or target.is_symlink():
            raise UsageError(f"--test-file {relative}: its directory leads out of the checkout, or the file exists")
        data = source.read_bytes()
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        placed[relative] = hashlib.sha256(data).hexdigest()
    return {"status": "COMPLETE", "checkout": str(destination), "revision": sha, "test_files": placed}


def test_files(values: list[str], repo: Path, sha: str) -> list[tuple[str, Path]]:
    """--test-file <relative path>=<source>: a new integration-test file of a crate (a `.rs` file directly in a `tests/`
    directory), absent at the revision, so the frozen test is added beside the code and never edits it."""
    placements = []
    for value in values:
        relative, _, source = value.partition("=")
        parts = relative.split("/")
        if not valid_path(relative) or len(parts) < 2 or parts[-2] != "tests" or not relative.endswith(".rs") or not source:
            raise UsageError(f"--test-file {relative!r}: give <relative path>=<source>, a .rs file directly in a crate's tests/ directory")
        if commit_exists(repo, sha) and git(repo, "cat-file", "-e", f"{sha}:{relative}", allow_failure=True)[0] == 0:
            raise UsageError(f"--test-file {relative}: the file exists at that revision; the test-only entry adds new files only")
        path = Path(source)
        if not path.is_file():
            raise UsageError(f"--test-file {relative}: the source {source} is not a file")
        placements.append((relative, path))
    if len({relative for relative, _ in placements}) != len(placements):
        raise UsageError("--test-file names one path twice")
    return placements


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


USER_TEMP_DIR = 65537  # confstr name _CS_DARWIN_USER_TEMP_DIR (macOS <unistd.h>); Python's os.confstr_names omits it


def user_temporary_directory() -> str | None:
    """The per-user folder macOS assigns (independent of TMPDIR): the parent of its per-user temporary directory, holding
    that directory and its siblings (the per-user cache directory among them), or None where there is none."""
    try:
        found = os.confstr(USER_TEMP_DIR)
    except (OSError, ValueError):
        return None
    return os.path.dirname(os.path.normpath(found)) if found else None


def command_sandbox_profile(args: argparse.Namespace) -> dict[str, Any]:
    """Phase 2 boundary for the test-only entry. Denied: all network access, LaunchServices and Apple events (handing work
    to an unsandboxed process), reads of the whole home directory except the Rust toolchain, reads of the shared areas
    outside the home (the system temporary areas and the users' Shared folder) and of the user's temporary areas (TMPDIR's
    directory and the whole per-user folder macOS assigns) outside the sandbox, reads of credential paths and of the run root and clone at their real paths, and writes anywhere but the sandbox directory and the null,
    terminal, and descriptor devices. Cargo's home, HOME, and TMPDIR for Phase 2 are directories inside the sandbox
    (Cargo's home filled in Phase 1), so nothing a build script writes can persist outside the sandbox."""
    home = real_directory(os.environ.get("HOME", "~"), "the home directory")
    sandbox = real_directory(args.sandbox_dir, "the sandbox directory")
    protected = [real_directory(args.run_root, "the run root"), real_directory(args.repo_dir, "the clone")]
    rustup_home = real_directory(os.environ.get("RUSTUP_HOME") or str(home / ".rustup"), "RUSTUP_HOME")
    if rustup_home == home or home.is_relative_to(rustup_home):
        raise UsageError("RUSTUP_HOME must not be, or contain, the home directory: the profile makes the rustup home readable")
    cargo_bin = real_directory(str(home / ".cargo" / "bin"), "the rustup proxies directory")
    # The user's temporary areas: TMPDIR's directory, and the whole per-user folder macOS assigns (its temporary and cache
    # directories and their siblings), which TMPDIR does not move (a shell may point TMPDIR elsewhere, under /tmp for example,
    # while tools such as xcrun keep using the per-user one). TMPDIR's directory inside that folder is not listed twice.
    temporaries = [real_directory(tempfile.gettempdir(), "the temporary directory")]
    per_user = user_temporary_directory()
    if per_user:
        folder = real_directory(per_user, "the per-user folder")
        temporaries = [*[path for path in temporaries if not path.is_relative_to(folder)], folder]
    elif sys.platform == "darwin":  # never a profile that silently leaves the per-user folder readable
        raise UsageError("macOS named no per-user folder (confstr _CS_DARWIN_USER_TEMP_DIR failed), so the profile cannot deny it")
    for inner in [home, *temporaries, *protected]:
        if sandbox == inner or sandbox.is_relative_to(inner) or inner.is_relative_to(sandbox):
            raise UsageError(f"the sandbox directory must be outside, and must not contain, {inner}")
    # Reads of these areas are denied in Phase 2 (see the profile below): the shared areas outside the home (the system
    # temporary areas and the users' Shared folder) and the user's temporary directory. The sandbox may lie inside a shared one.
    shared_areas = [Path(os.path.join(os.sep, *parts)).resolve() for parts in (("tmp",), ("var", "tmp"), ("Users", "Shared"))]
    temporary_areas = list(dict.fromkeys([*shared_areas, *temporaries]))
    for area in temporary_areas:
        if area.is_relative_to(sandbox):
            raise UsageError(f"the sandbox directory must not be, or contain, the temporary area {area}: its read allow would reopen it")
        if rustup_home.is_relative_to(area) or cargo_bin.is_relative_to(area):
            raise UsageError(f"RUSTUP_HOME and the rustup proxies directory must not lie in the temporary area {area}: the profile "
                             "denies reads there")
    out = Path(args.out).resolve()
    if out.is_relative_to(sandbox) or any(out.is_relative_to(temporary) for temporary in temporaries):
        raise UsageError("--out must be outside the sandbox and the temporary areas: code in Phase 2 can write the sandbox, and "
                         "other processes on the host write the temporary areas, so either could rewrite the profile before the next "
                         "sandbox-exec reads it")
    cargo_home, sandbox_home, sandbox_tmp = sandbox / "cargo-home", sandbox / "home", sandbox / "tmp"
    for directory in (cargo_home, sandbox_home, sandbox_tmp):  # on a used sandbox, Phase 2 code may have replaced one with a link
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise UsageError(f"{directory} is a link or not a directory; use a new sandbox directory")
    restricted_dir(cargo_home)
    restricted_dir(sandbox_home)  # HOME for Phase 2: tools (git's library in Cargo, among others) read no configuration from the real home
    restricted_dir(sandbox_tmp)  # TMPDIR for Phase 2: a build's temporary files stay in the sandbox
    credentials = []
    for parts in CREDENTIAL_PATHS:
        literal = home.joinpath(*parts)
        credentials.append(literal)
        if literal.exists() and literal.resolve() != literal:
            credentials.append(literal.resolve())
    denied_reads = " ".join(f"(subpath {sbpl(path)})" for path in [*credentials, *protected])
    # Reads of the system temporary area (other users' and tools' files, Claude Code's session output among them) and of
    # the user's temporary directory are denied; the sandbox stays readable. Directories leading from a denied area to the
    # sandbox allow metadata only, so a path inside the sandbox resolves while nothing else there can be listed or read.
    ancestors: list[Path] = []
    for area in temporary_areas:
        if sandbox.is_relative_to(area):
            step = area
            ancestors.append(step)
            for part in sandbox.relative_to(area).parts[:-1]:
                step = step / part
                ancestors.append(step)
    metadata = [f"(allow file-read-metadata {' '.join(f'(literal {sbpl(path)})' for path in dict.fromkeys(ancestors))})"] if ancestors else []
    devices = os.path.join(os.sep, "dev")
    profile = "\n".join([
        "(version 1)", "(allow default)", "(deny network*)", "(deny lsopen)", "(deny appleevent-send)",
        f"(deny file-read* (subpath {sbpl(home)}))",
        f"(allow file-read* (literal {sbpl(home)}) (subpath {sbpl(rustup_home)}) (subpath {sbpl(cargo_bin)}))",
        f"(deny file-read* {' '.join(f'(subpath {sbpl(area)})' for area in temporary_areas)})",
        f"(allow file-read* (subpath {sbpl(sandbox)}))",
        *metadata,
        f"(deny file-read* {denied_reads})",  # last read rule: the credential, run-root, and clone denial is never reopened
        "(deny file-write*)",
        (f"(allow file-write* (subpath {sbpl(sandbox)}) (literal {sbpl(os.devnull)}) "
         f'(literal {sbpl(os.path.join(devices, "tty"))}) (regex #"^{devices}/fd/"))'), ""])
    if not out.parent.exists():  # an existing directory keeps its mode; a new one is private
        restricted_dir(out.parent)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(profile)
    return {"status": "COMPLETE", "out": str(out), "cargo_home": str(cargo_home),
            "environment": {"HOME": str(sandbox_home), "RUSTUP_HOME": str(rustup_home), "CARGO_HOME": str(cargo_home),
                            "TMPDIR": str(sandbox_tmp)},
            "note": "Phase 1 (cargo fetch, network on) uses CARGO_HOME; Phase 2 (sandbox-exec, offline) sets all of environment."}


SIDES = ("report", "pin")
PAIR_EXCLUDED = ("revision",)  # the only field in which the two entries of a pair may differ


def sink_location(sink: str) -> tuple[str, int]:
    relative, _, line_text = sink.rpartition(":")
    if not valid_path(relative) or not line_text.isdigit() or int(line_text) < 1:
        raise UsageError(f"--*-sink must be <relative path>:<line>, not {sink!r}")
    return relative, int(line_text)


def coverage_count(path: Path, checkout: Path, sink: str) -> int:  # path from coverage_file()
    """The maximum count over cargo-llvm-cov JSON segments on the sink line (deterministic-validation.md), for the sink file
    in this checkout only: cargo-llvm-cov names files by absolute real path."""
    relative, line = sink_location(sink)
    expected = str(checkout / relative)
    matches, elsewhere = [], []
    for block in load(path).get("data", []):
        for entry in block.get("files", []) if isinstance(block, dict) else []:
            name = str(entry.get("filename", "")) if isinstance(entry, dict) else ""
            if name == expected:
                matches.append(entry)
            elif name.endswith("/" + relative):
                elsewhere.append(name)
    if len(matches) > 1:
        raise UsageError(f"{path} lists {relative} several times; coverage must name the sink file once")
    if not matches and elsewhere:
        raise UsageError(f"{path} covers {relative} under another directory than the checkout {checkout}")
    counts = [segment[2] for entry in matches for segment in entry.get("segments", [])
              if isinstance(segment, list) and len(segment) >= 3 and segment[0] == line and isinstance(segment[2], int)]
    return max(counts) if counts else 0


COVERAGE_MAX_BYTES = 256 * 1024 * 1024
SANDBOX_EXEC = os.path.join(os.sep, "usr", "bin", "sandbox-exec")  # macOS Seatbelt launcher (built, so no absolute path is in the text)
LIBTEST_OPTIONS = ("--exact", "--nocapture", "--show-output", "--include-ignored")  # plus --test-threads=<n>; nothing that skips


# cargo options before `--` that take a separate value; any other bare word there is a positional argument (for
# example a test name filter), which is refused so the declared filter after `--` is the only one.
CARGO_VALUE_OPTIONS = ("-p", "--package", "--test", "--output-path", "--features", "-F", "--target", "--target-dir",
                       "--manifest-path", "--profile", "-j", "--jobs", "--color", "--message-format", "--config", "-Z")
CARGO_SUBCOMMANDS = ("test", "llvm-cov", "build")


def entry_parts(argv: list[Any]) -> tuple[list[str], list[str]]:
    """The cargo arguments before and after the single `--` of an entry, after the `sandbox-exec -f <profile>` prefix and
    the command. Refused: a second `--` (libtest would read what follows as more filters), `--` right after the profile
    (which would hide the selectors), and a positional argument before `--`."""
    command = [str(item) for item in argv[3:]]
    if not command or command[0].startswith("-"):
        raise UsageError("the command must follow the profile directly (`sandbox-exec -f <profile> <command> ...`)")
    rest = command[1:]
    if rest.count("--") > 1:
        raise UsageError("an entry may contain only one `--` (libtest would read anything after a second one as filters)")
    head, tail = (rest[:rest.index("--")], rest[rest.index("--") + 1:]) if "--" in rest else (rest, [])
    index = 0
    while index < len(head) and head[index] in CARGO_SUBCOMMANDS:
        index += 1
    while index < len(head):
        item = head[index]
        if item in CARGO_VALUE_OPTIONS:
            index += 2
            continue
        if not item.startswith("-"):
            raise UsageError(f"positional argument {item!r} before `--` (a test name filter belongs after `--`, with --exact)")
        index += 1
    return head, tail


def test_filter(argv: list[Any]) -> tuple[bool, list[str]]:
    """libtest arguments after the `--`: whether --exact is given, and the test names (Rust-first). Any other option
    (for example --skip, which would leave declared tests out) is refused."""
    tail = entry_parts(argv)[1]
    for item in tail:
        if item.startswith("-") and item not in LIBTEST_OPTIONS and not re.fullmatch(r"--test-threads=\d+", item):
            raise UsageError(f"libtest option {item!r} is not accepted after `--` (allowed: {', '.join(LIBTEST_OPTIONS)}, "
                             "--test-threads=<n>)")
    return "--exact" in tail, [item for item in tail if not item.startswith("-")]


COVERAGE_ONLY = ("--ignore-run-fail", "--json")  # with --output-path <file>: what a coverage entry adds to the tests' options
COVERAGE_REFUSED = ("--no-report", "--no-run")  # an entry with either writes no fresh report (an earlier file could be read)


def build_options(argv: list[Any]) -> list[tuple[str, ...]]:
    """The cargo options before `--` that decide what is built (package, test target, manifest, features, profile, and
    the rest), as sorted (option[, value]) groups, without the subcommand words."""
    head = [item for item in entry_parts(argv)[0] if item not in CARGO_SUBCOMMANDS]
    groups, index = [], 0
    while index < len(head):
        item = head[index]
        if item in CARGO_VALUE_OPTIONS:
            groups.append((item, head[index + 1] if index + 1 < len(head) else ""))
            index += 2
            continue
        groups.append(tuple(item.split("=", 1)) if item.startswith("--") and "=" in item else (item,))
        index += 1
    return sorted(groups)


def coverage_file(checkout: Path, relative: str) -> Path:
    """The coverage JSON a coverage entry wrote, inside its checkout: never through a link, never larger than the cap
    (code under test can write the checkout, so this guards against reading elsewhere, not against forged content)."""
    path = checkout / relative
    if path.is_symlink() or not path.resolve().is_relative_to(checkout):
        raise UsageError(f"the coverage file {relative} is a link or outside the checkout {checkout}")
    if not path.is_file():
        raise UsageError(f"the coverage entry passed but wrote no file at {path}")
    if path.stat().st_size > COVERAGE_MAX_BYTES:
        raise UsageError(f"the coverage file {path} is larger than {COVERAGE_MAX_BYTES} bytes")
    return path


def output_path(argv: list[Any]) -> str:
    """The checkout-relative coverage file a coverage entry writes (`--output-path <relative path>`)."""
    if "--output-path" not in argv or argv.index("--output-path") + 1 >= len(argv):
        raise UsageError("a coverage entry must write its JSON with --output-path <relative path>")
    value = str(argv[argv.index("--output-path") + 1])
    if not valid_path(value):
        raise UsageError(f"a coverage entry's --output-path must be a plain relative path, not {value!r}")
    return value


def without_revision(entry: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in entry.items() if key not in PAIR_EXCLUDED}


def registry_entries(registry: dict[str, Any], ends: dict[str, Any], names: list[str]) -> dict[str, dict[str, dict[str, Any]]]:
    """Each declared name's pair (<name>@report and <name>@pin, or <name>@base and <name>@target for the coverage kind),
    identical except for the revision each is bound to."""
    tests, pairs = registry.get("tests", {}), {}
    revisions = ends["revisions"]
    for name in names:
        pair = {}
        for side in SIDES:
            suffix = ends["suffix"][side]
            entry = tests.get(f"{name}@{suffix}") if isinstance(tests, dict) else None
            if not isinstance(entry, dict):
                raise UsageError(f"the registry has no entry {name}@{suffix}")
            if entry.get("revision") != revisions[side]:
                raise UsageError(f"{name}@{suffix} is bound to revision {entry.get('revision')!r}, not the {suffix} revision")
            pair[side] = entry
        if without_revision(pair["report"]) != without_revision(pair["pin"]):
            differing = sorted(key for key in set(pair["report"]) | set(pair["pin"])
                               if key not in PAIR_EXCLUDED and pair["report"].get(key) != pair["pin"].get(key))
            raise UsageError(f"the two entries of {name} differ in {differing}; a pair may differ only in its revision")
        pairs[name] = pair
    return pairs


def side_results(paths: list[str], side: str, revision: str, registry_sha: str, expected: set[str]) -> dict[str, dict[str, Any]]:
    """deterministic-check.py results at one revision, keyed by declared name, exactly the expected entries."""
    results: dict[str, dict[str, Any]] = {}
    for path in paths:
        result = load(path)
        if result.get("role_type") != "computation" or result.get("check_kind") != "FROZEN_TEST_REFERENCE":
            raise UsageError(f"{path} is not a deterministic-check.py frozen-test result")
        if result.get("target_revision") != revision:
            raise UsageError(f"{path} was run at another revision ({result.get('target_revision')}) than the {side} revision {revision}")
        if result.get("registry_sha256") != registry_sha:
            raise UsageError(f"{path} was run against another frozen-test registry than --registry")
        name, _, suffix = str(result.get("frozen_test_id", "")).rpartition("@")
        if suffix != side:
            raise UsageError(f"{path} is for {result.get('frozen_test_id')!r}, not an entry of the {side} revision")
        if name in results:
            raise UsageError(f"two results for {name}@{side}")
        results[name] = dict(result, sha256=file_sha256(path))
    if set(results) != expected:
        missing, extra = sorted(f"{name}@{side}" for name in expected - set(results)), sorted(set(results) - expected)
        raise UsageError(f"results at the {side} revision are missing {missing} or include undeclared entries {extra}")
    return results


def literal(result: dict[str, Any]) -> str:
    value = result.get("literal_check_result")
    return value if result.get("status") == "COMPLETE" and value in ("PASSED", "FAILED") else "UNRESOLVED"


RUNNING = re.compile(r"^running (\d+) tests?$", re.MULTILINE)


def test_outcomes(results: dict[str, dict[str, Any]], declared: list[str], build: str) -> tuple[dict[str, str], str]:
    """Each declared test's result at one revision. A build that did not pass leaves every test UNRESOLVED (a test that
    does not compile exits like a failing one); so does a result whose output does not show exactly one test run."""
    build_result = literal(results[build])
    outcomes = {}
    for name in declared:
        value = literal(results[name])
        if build_result != "PASSED" or (value in ("PASSED", "FAILED") and RUNNING.findall(str(results[name].get("bounded_output", ""))) != ["1"]):
            value = "UNRESOLVED"
        outcomes[name] = value
    return outcomes, build_result


# libtest's panic report: "panicked at <file>:<line>:<col>:\n<message>" (Rust 1.73 and later; from 1.91 the thread name is followed
# by its ID, "thread 'name' (12345) panicked at") or "panicked at '<message>', <file>"
PANICKED = re.compile(r"thread '[^'\n]*'(?: \(\d+\))? panicked at (?:'(?P<old>[^\n]*)', [^\n]*:\d+:\d+|[^\n]*:\d+:\d+:\n(?P<new>.*?))(?:\nnote: |\n\n|\Z)",
                      re.DOTALL)
FAILURE_CAP = 300


def failure_message(output: str) -> str:
    """The first failure message in a test's bounded output, capped, never interpreted (code under test wrote it)."""
    found = PANICKED.search(output)
    if not found:
        return ""
    return (found.group("old") if found.group("old") is not None else found.group("new") or "").rstrip()[:FAILURE_CAP]


def side_failures(results: dict[str, dict[str, Any]], outcomes: dict[str, str], adversarial: list[str]) -> dict[str, str]:
    return {name: failure_message(str(results[name].get("bounded_output", ""))) for name in adversarial if outcomes[name] == "FAILED"}


def head_of(checkout: Path) -> str:
    return git(checkout, "rev-parse", "HEAD", allow_failure=True)[1].strip()


def bind_coverage_records(path: str, pair: dict[str, Any]) -> dict[str, Any]:
    """D9: the records of the analysis the coverage pair names: its advisory, issue list, and path, at its analysis
    revision (the base, or an ancestor whose records fix-revision bound by digest)."""
    records = load(path)
    if records.get("ghsa_id") != pair.get("ghsa_id") or records.get("issues_sha256") != pair.get("issues_sha256"):
        raise UsageError("the records belong to another advisory or issue list than the coverage pair")
    if records.get("primary_revision") != pair.get("analysis_revision"):
        raise UsageError(f"the records were made at {records.get('primary_revision')!r}, not at the pair's analysis revision "
                         f"{pair.get('analysis_revision')}")
    if pair.get("analysis_records_sha256"):
        if file_sha256(path) != pair["analysis_records_sha256"]:
            raise UsageError("these are not the analysis records fix-revision bound to the pair (or they changed since)")
    elif records.get("coverage") is not True:
        raise UsageError("without reused analysis records, the records must be coverage records at the base "
                         "(ghsa-dedup.py records --coverage-plan)")
    if (records.get("research_only") is True) != (pair.get("research_only") is True):
        raise UsageError("the coverage pair and the records come from different paths (research-only and triage)")
    return records


def command_test_result(args: argparse.Namespace) -> dict[str, Any]:
    ends = revision_pair(args.revision)
    revision, coverage_kind = ends["record"], ends["kind"] != "currency"  # a coverage or develop-fix pair
    suffix = ends["suffix"]
    ghsa_id = revision.get("ghsa_id", "")
    canonical = str(revision.get("canonical", "")) if coverage_kind else ""
    out = coverage_out(args.out, ghsa_id, ends["kind"]) if coverage_kind else currency_out(args.out, ghsa_id)
    if coverage_kind:  # the pair record names its issues, issue list, and path; there is no currency plan
        if args.plan:
            raise UsageError("--plan is for the currency kind: a coverage pair record names its own issues")
        plan = {"issues_sha256": revision.get("issues_sha256", ""), "mode": "RESEARCH_ONLY" if revision.get("research_only") is True else "TRIAGE"}
        if args.issue_id not in revision.get("issues", []):
            raise UsageError(f"{args.issue_id} is not an issue of the coverage pair")
    else:
        if not args.plan:
            raise UsageError("the currency kind needs --plan")
        plan = load(args.plan)
        if plan.get("record_type") != "ghsa_currency_plan" or plan.get("ghsa_id") != ghsa_id:
            raise UsageError("the plan belongs to another advisory")
        if args.issue_id not in {entry.get("issue_id") for entry in plan.get("planned", [])}:
            raise UsageError(f"{args.issue_id} is not planned")
    adversarial, benign = list(dict.fromkeys(args.adversarial)), list(dict.fromkeys(args.benign or []))
    if not adversarial or not benign or set(adversarial) & set(benign) or {args.build, args.coverage} & set(adversarial + benign) \
            or args.build == args.coverage:
        raise UsageError("declare at least one adversarial-input test and one benign control, each in one role only, and a build "
                         "entry and a coverage entry distinct from the tests")
    declared = adversarial + benign
    registry_sha = file_sha256(args.registry)
    registry = load(args.registry)
    profile = Path(args.profile).resolve(strict=True)
    profile_sha = file_sha256(profile)
    pairs = registry_entries(registry, ends, declared + [args.build])
    names = {}
    for name in declared:
        exact, filters = test_filter(pairs[name]["report"].get("argv", []))
        if not exact or len(filters) != 1:
            raise UsageError(f"{name} must run exactly one test (`-- --exact <name>`), so its output can show that one test ran")
        names[name] = filters[0]
        required = pairs[name]["report"].get("required_files")
        if not isinstance(required, dict) or not required:
            raise UsageError(f"{name} names no required_files: the frozen test's own files must be bound by digest")
    tests = registry.get("tests", {})
    used: list[dict[str, Any]] = [pairs[name][side] for name in declared + [args.build] for side in SIDES]
    for side in SIDES:
        coverage_entry = tests.get(f"{args.coverage}@{suffix[side]}") if isinstance(tests, dict) else None
        if isinstance(coverage_entry, dict):
            used.append(coverage_entry)
    for entry in used:  # deterministic-check.py runs outside the profile, so each entry must enter it itself
        argv = [str(item) for item in entry.get("argv", [])]
        if len(argv) < 4 or argv[:3] != [SANDBOX_EXEC, "-f", str(profile)]:  # exact: the adapter resolves -f in the checkout
            raise UsageError(f"every entry must start with {SANDBOX_EXEC} -f {profile}; one runs {argv[:3]}")
        if entry.get("expected_exit_status") != 0:
            raise UsageError("every entry must expect exit 0 (a test passes, the build completes, coverage is collected)")
    test_options = {tuple(build_options(pairs[name]["report"].get("argv", []))) for name in declared}
    if len(test_options) != 1:
        raise UsageError("the declared tests must use the same build options (test targets, packages, manifest, features, profile)")
    options = list(next(iter(test_options)))
    environments = {json.dumps(entry.get("environment", {}), sort_keys=True) for entry in used}
    if len(environments) != 1:
        raise UsageError("every entry (tests, build, coverage) must run with the same environment")
    for side in SIDES:
        build = [group for group in build_options(pairs[args.build][side].get("argv", [])) if group != ("--no-run",)]
        if build != [group for group in options if group[0] != "--test"]:
            raise UsageError("the build entry must use the same build options as the tests (apart from --no-run and the test target)")
    coverage_entries = {}
    for side, want in (("report", sorted(names[n] for n in adversarial)), ("pin", sorted(names.values()))):
        entry = tests.get(f"{args.coverage}@{suffix[side]}") if isinstance(tests, dict) else None
        if not isinstance(entry, dict) or entry.get("revision") != ends["revisions"][side]:
            raise UsageError(f"the registry has no coverage entry {args.coverage}@{suffix[side]} bound to the {suffix[side]} revision")
        if entry.get("working_directory") != ".":
            raise UsageError(f"the coverage entry {args.coverage}@{suffix[side]} must run in the checkout root (working_directory \".\"), "
                             "where its --output-path file is read")
        exact, filters = test_filter(entry.get("argv", []))
        allowed = filters == [] if side == "pin" else False
        if not allowed and not (exact and sorted(filters) == want):
            raise UsageError(f"the coverage entry {args.coverage}@{suffix[side]} must run " + (
                "exactly the adversarial-input tests (`-- --exact <names>`), so the sink is shown reached by them" if side == "report"
                else "every declared test, so a control can show the sink still runs when a fix stops the adversarial input earlier"))
        argv = [str(item) for item in entry.get("argv", [])]
        if any(item in COVERAGE_REFUSED for item in argv) or "--json" not in argv:
            raise UsageError(f"the coverage entry {args.coverage}@{suffix[side]} must write a fresh JSON report (--json, and neither "
                             "--no-report nor --no-run)")
        coverage = [group for group in build_options(argv) if group[0] != "--output-path" and group not in [(o,) for o in COVERAGE_ONLY]]
        if coverage != options:
            raise UsageError(f"the coverage entry {args.coverage}@{suffix[side]} must use the same build options as the tests (test "
                             "targets, packages, manifest, features, profile); only --ignore-run-fail, --json, and --output-path differ")
        coverage_entries[side] = output_path(entry.get("argv", []))
    checkouts = {"report": Path(args.base_checkout).resolve(strict=True), "pin": Path(args.pin_checkout).resolve(strict=True)}
    for side, rev in ends["revisions"].items():
        if head_of(checkouts[side]) != rev:
            raise UsageError(f"the {suffix[side]} checkout's HEAD is not the {suffix[side]} revision {rev}")
    expected = set(declared) | {args.build, args.coverage}
    results = {side: side_results(paths, suffix[side], ends["revisions"][side], registry_sha, expected)
               for side, paths in (("report", args.base_result), ("pin", args.pin_result))}
    # A coverage entry that did not pass (for example after a failed build) wrote no file: its sink counts as not reached.
    coverage_files = {side: coverage_file(checkouts[side], coverage_entries[side]) if literal(results[side][args.coverage]) == "PASSED" else None
                      for side in SIDES}
    coverage_sha = {side: file_sha256(path) if path else None for side, path in coverage_files.items()}
    if coverage_sha["report"] and coverage_sha["report"] == coverage_sha["pin"]:
        raise UsageError("both revisions have the same coverage file; each revision's coverage must come from its own run")
    counts: dict[str, int] = {}
    for side, sink in (("report", args.base_sink), ("pin", args.pin_sink)):
        found = coverage_files[side]
        counts[side] = coverage_count(found, checkouts[side], sink) if found is not None else 0
    candidates = {str(result.get("candidate_id", "")) for side in SIDES for result in results[side].values()}
    if candidates != {args.candidate_id}:
        raise UsageError(f"results were written for another candidate than {args.candidate_id}: {sorted(candidates - {args.candidate_id})}")
    propositions = {str(result.get("proposition", "")) for side in SIDES for result in results[side].values()}
    if len(propositions) != 1:
        raise UsageError("the results do not share one proposition")
    file_digests = {digest for name in declared for digest in pairs[name]["report"]["required_files"].values()}
    overlaps = []
    checked = [ghsa_id] + ([canonical] if canonical else [])  # a test copies neither the later report nor the canonical's
    # each check must have read the capture the revision or pair record bound (a later capture may hold a new PoC)
    captures = {ghsa_id: str(revision.get("intake_sha256", "")), **({canonical: str(revision.get("canonical_intake_sha256", ""))} if canonical else {})}
    for path in args.poc_overlap:
        check = load(path)
        if check.get("check") != "poc-overlap" or check.get("ghsa_id") not in checked or check.get("decision") != "ACCEPT":
            raise UsageError(f"{path} is not an ACCEPT poc-overlap check for {' or '.join(checked)}; a test that copies a report is never run")
        if not HEX64.match(str(check.get("test_file_sha256", ""))):
            raise UsageError(f"the poc-overlap check {path} names no 64-hex test_file_sha256")
        if not HEX64.match(captures[check["ghsa_id"]]) or check.get("intake_sha256") != captures[check["ghsa_id"]]:
            raise UsageError(f"the poc-overlap check {path} was not run against the capture of {check['ghsa_id']} the revision record "
                             "binds (intake_sha256); rerun intake-check.py poc-overlap with that capture")
        overlaps.append({"ghsa_id": check["ghsa_id"], "test_file_sha256": check["test_file_sha256"], "intake_sha256": check["intake_sha256"],
                         "check_sha256": file_sha256(path)})
    for advisory_id in checked:
        if {entry["test_file_sha256"] for entry in overlaps if entry["ghsa_id"] == advisory_id} != file_digests:
            raise UsageError(f"the poc-overlap checks for {advisory_id} do not cover exactly the frozen tests' required files "
                             "(compare test_file_sha256)")
    records = load(args.report_records)
    if coverage_kind:
        records = bind_coverage_records(args.report_records, revision)
    else:
        if records.get("ghsa_id") != ghsa_id or records.get("issues_sha256") != plan.get("issues_sha256") \
                or records.get("primary_revision") != revision["report_revision"]:
            raise UsageError("the report-revision records belong to another advisory, issue list, or revision")
        if records.get("coverage") is True:
            raise UsageError("coverage records belong to the coverage kind, not to the currency check")
    if (records.get("research_only") is True) != (plan.get("mode") == "RESEARCH_ONLY"):
        raise UsageError("the plan and the report-revision records come from different paths (research-only and triage)")
    def answers_issue(record: dict[str, Any]) -> bool:
        return any(answer.get("ghsa_id") == ghsa_id and answer.get("issue_id") == args.issue_id for answer in record.get("answers", []))

    if not any(record.get("candidate_id") == args.candidate_id and record.get("final_status") == VERIFIED and record.get("bridged") is True
               and answers_issue(record) for record in records.get("records", [])):
        raise UsageError(f"the report revision's records have no CROSS-MODEL VERIFIED, bridged record for candidate {args.candidate_id} "
                         f"answering {args.issue_id}; the test-only entry needs that converged candidate")
    own_sites = [record["control_site"] for record in records.get("records", []) if record.get("candidate_id") == args.candidate_id
                 and record.get("final_status") == VERIFIED and isinstance(record.get("control_site"), dict) and answers_issue(record)]
    sites = [record["control_site"] for record in records.get("records", []) if record.get("final_status") == VERIFIED
             and isinstance(record.get("control_site"), dict) and any(answer.get("ghsa_id") == ghsa_id and answer.get("issue_id") == args.issue_id
                                                                      for answer in record.get("answers", []))]
    sink_file = sink_location(args.base_sink)[0]
    base, base_build = test_outcomes(results["report"], declared, args.build)
    pin, pin_build = test_outcomes(results["pin"], declared, args.build)
    fails_at_base = all(base[test] == "FAILED" for test in adversarial)
    base_controls = all(base[test] == "PASSED" for test in benign)
    adversarial_at_pin = [pin[test] for test in adversarial]
    at_pin = "UNRESOLVED" if "UNRESOLVED" in adversarial_at_pin else "PASSED" if all(r == "PASSED" for r in adversarial_at_pin) else "FAILED"
    observed = fails_at_base and base_controls and counts["report"] > 0
    document = {"record_type": "ghsa_currency_test", "producer": TEST_PRODUCER, "ghsa_id": ghsa_id, "issue_id": args.issue_id,
                "issues_sha256": plan.get("issues_sha256", ""), "report_revision": ends["revisions"]["report"], "pin": ends["revisions"]["pin"],
                "registry_sha256": registry_sha, "profile_sha256": profile_sha, "candidate_id": args.candidate_id,
                "proposition": next(iter(propositions)), "tests": {"adversarial": adversarial, "benign": benign},
                "build": {"report": base_build, "pin": pin_build},
                "base_validation": {"state": "TEST_OBSERVED" if observed else "TEST_UNVALIDATED", "fails_at_base": fails_at_base,
                                    "controls_hold": base_controls, "sink_reached": counts["report"] > 0,
                                    "sink": {"location": args.base_sink, "count": counts["report"]}, "results": base,
                                    "failures": side_failures(results["report"], base, adversarial)},
                "pin_validation": {"controls_hold": all(pin[test] == "PASSED" for test in benign), "sink_reached": counts["pin"] > 0,
                                   "sink": {"location": args.pin_sink, "count": counts["pin"]}, "results": pin,
                                   "failures": side_failures(results["pin"], pin, adversarial)},
                "at_pin": at_pin, "control_sites": sites,
                "sink_matches_control_site": any(site.get("relative_path") == sink_file for site in own_sites),  # the bound candidate's
                "inputs": {"registry_sha256": registry_sha, "profile": str(profile),
                           "results_sha256": {side: {name: results[side][name]["sha256"] for name in sorted(results[side])} for side in SIDES},
                           "coverage_sha256": coverage_sha, "checkouts": {side: str(checkouts[side]) for side in SIDES},
                           "poc_overlap": overlaps, "report_records_sha256": file_sha256(args.report_records)}}
    if coverage_kind:  # the same evidence, named for the coverage pair
        document = {"record_type": "ghsa_coverage_test" if ends["kind"] == "coverage" else "ghsa_develop_fix_test", "kind": ends["kind"],
                    "producer": TEST_PRODUCER, "ghsa_id": ghsa_id,
                    "issue_id": args.issue_id, "issues_sha256": plan.get("issues_sha256", ""), "base": ends["revisions"]["report"],
                    "target": ends["revisions"]["pin"], "pin": revision.get("pin", ""), "canonical": canonical,
                    "research_only": revision.get("research_only") is True, "analysis_revision": revision.get("analysis_revision", ""),
                    "pair_sha256": file_sha256(args.revision), "registry_sha256": registry_sha, "profile_sha256": profile_sha,
                    "candidate_id": args.candidate_id, "proposition": document["proposition"], "tests": document["tests"],
                    "build": {"base": base_build, "target": pin_build}, "base_validation": document["base_validation"],
                    "target_validation": document["pin_validation"], "at_target": at_pin, "control_sites": sites,
                    "sink_matches_control_site": document["sink_matches_control_site"], "inputs": document["inputs"]}
        if ends["kind"] == "develop-fix":  # the --develop-fix security gate: fails at the base, passes on the patch, at the sink
            proposal, reason = coverage_decide(True, document)
            document.update(landing_branch=revision.get("landing_branch", ""), security_gate="PASSED" if proposal == "COVERED_BY_FIX" else "NOT_PASSED",
                            security_gate_reason="" if proposal == "COVERED_BY_FIX" else reason or "TEST_FAILS_AT_TARGET")
    dump_private(out, document)
    return {"status": "COMPLETE", "state": document["base_validation"]["state"], ("at_target" if coverage_kind else "at_pin"): at_pin,
            "out": str(out)}


# ---------- coverage outcome and brief (phase 3) ----------

def coverage_pair(path: str) -> dict[str, Any]:
    ends = revision_pair(path)
    if ends["kind"] != "coverage":
        raise UsageError("--revision is not a coverage pair record (currency-check.py fix-revision)")
    return ends["record"]


def load_coverage_test(path: str, pair: dict[str, Any], pair_sha: str, records_sha: str) -> dict[str, Any]:
    """A test-result output for this coverage pair, built from these records."""
    test = load(path)
    if test.get("record_type") != "ghsa_coverage_test" or test.get("kind") != "coverage" or test.get("ghsa_id") != pair.get("ghsa_id"):
        raise UsageError(f"{path} is not a coverage test result for {pair.get('ghsa_id')} (test-result with a coverage pair)")
    if test.get("producer") != TEST_PRODUCER:
        raise UsageError(f"{path} was not written by {TEST_PRODUCER}")
    if test.get("pair_sha256") != pair_sha or (test.get("base"), test.get("target")) != (pair.get("base"), pair.get("target")):
        raise UsageError(f"{path} was run for another coverage pair")
    if test.get("issue_id") not in pair.get("issues", []):
        raise UsageError(f"{path} is for {test.get('issue_id')!r}, not an issue of the coverage pair")
    if test.get("inputs", {}).get("report_records_sha256") != records_sha:
        raise UsageError(f"{path} was built from other records than --records")
    if not HEX64.match(str(test.get("registry_sha256", ""))):
        raise UsageError(f"{path} names no frozen-test registry digest")
    if not HEX64.match(str(test.get("profile_sha256", ""))):
        raise UsageError(f"{path} names no sandbox profile digest")
    if not isinstance(test.get("candidate_id"), str) or not test["candidate_id"]:
        raise UsageError(f"{path} names no candidate")
    base, target = test.get("base_validation"), test.get("target_validation")  # a malformed result never reaches rule C6
    if not isinstance(base, dict) or base.get("state") not in TEST_STATES:
        raise UsageError(f"{path} has an unknown base_validation state")
    if not isinstance(target, dict):
        raise UsageError(f"{path} has no target_validation")
    for name, block in (("base_validation", base), ("target_validation", target)):
        for key in ("controls_hold", "sink_reached") + (("fails_at_base",) if name == "base_validation" else ()):
            if not isinstance(block.get(key), bool):
                raise UsageError(f"{path}: {name}.{key} must be true or false")
    if test.get("at_target") not in AT_PIN:
        raise UsageError(f"{path} has an unknown at_target result")
    return test


def coverage_decide(contract: bool, test: dict[str, Any] | None) -> tuple[str, str]:
    """(outcome, reason), first match (rules C1-C6); every outcome is a proposal, and COVERED_BY_FIX needs --verify-fix."""
    if not contract:
        return "UNDECIDED", "NO_CONTRACT_AT_BASE"
    if test is None or not validated(test):
        return "UNDECIDED", "TEST_UNVALIDATED"
    if test.get("at_target") == "UNRESOLVED":
        return "UNDECIDED", "TEST_UNRESOLVED_AT_TARGET"
    target = test.get("target_validation", {})
    if target.get("sink_reached") is not True or target.get("controls_hold") is not True:
        return "UNDECIDED", "TEST_NOT_AT_SINK_AT_TARGET"
    if test.get("at_target") == "PASSED":
        return "COVERED_BY_FIX", ""
    return "NOT_COVERED_BY_FIX", ""


def command_coverage_outcome(args: argparse.Namespace) -> dict[str, Any]:
    pair = coverage_pair(args.revision)
    ghsa_id = str(pair.get("ghsa_id", ""))
    out = coverage_out(args.out, ghsa_id)
    records = bind_coverage_records(args.records, pair)
    pair_sha, records_sha = file_sha256(args.revision), file_sha256(args.records)
    tests: dict[str, dict[str, Any]] = {}
    for path in args.test or []:
        test = load_coverage_test(path, pair, pair_sha, records_sha)
        if test["issue_id"] in tests:
            raise UsageError(f"two test results for {test['issue_id']}; give one per issue")
        tests[test["issue_id"]] = test
    issues = {}
    for issue_id in pair.get("issues", []):
        contract = any(record.get("final_status") == VERIFIED and record.get("bridged") is True
                       and any(answer.get("ghsa_id") == ghsa_id and answer.get("issue_id") == issue_id for answer in record.get("answers", []))
                       for record in records.get("records", []))
        test = tests.get(issue_id)
        outcome, reason = coverage_decide(contract, test)
        summary = None
        if test is not None:
            base, target = test.get("base_validation", {}), test.get("target_validation", {})
            summary = {"candidate_id": test.get("candidate_id", ""), "proposition": test.get("proposition", ""), "build": test.get("build", {}),
                       "base_state": base.get("state", ""), "base_sink": base.get("sink", {}), "at_target": test.get("at_target", ""),
                       "target_controls_hold": target.get("controls_hold"), "target_sink_reached": target.get("sink_reached"),
                       "target_sink": target.get("sink", {}), "target_failures": target.get("failures", {})}
        issues[issue_id] = {"outcome": outcome, "reason": reason, "verify_fix_required": outcome == "COVERED_BY_FIX", "test": summary}
    document = {"record_type": "ghsa_coverage_outcome", "ghsa_id": ghsa_id, "canonical": pair.get("canonical", ""),
                "research_only": pair.get("research_only") is True, "base": pair.get("base"), "target": pair.get("target"),
                "pin": pair.get("pin", ""), "analysis_revision": pair.get("analysis_revision", ""), "pair_sha256": pair_sha,
                "records_sha256": records_sha, "issues": issues,
                "note": "Proposals for a human. Nothing here changes dispositions, H4, or write-back; COVERED_BY_FIX needs --verify-fix."}
    dump_private(out, document)
    return {"status": "COMPLETE", "outcomes": {issue_id: entry["outcome"] for issue_id, entry in issues.items()}, "out": str(out)}


def command_coverage_brief(args: argparse.Namespace) -> dict[str, Any]:
    """The human-only coverage brief. Test output (failure messages) is code under test's text: one-line JSON, never interpreted."""
    outcome = load(args.outcome)
    if outcome.get("record_type") != "ghsa_coverage_outcome":
        raise UsageError("--outcome is not a coverage outcome (currency-check.py coverage-outcome)")
    ghsa_id = str(outcome.get("ghsa_id", ""))
    out = coverage_out(args.out, ghsa_id)
    base, target = outcome.get("base", ""), outcome.get("target", "")
    yes = lambda value: "yes" if value is True else "no"
    lines = [f"# Post-fix coverage for {ghsa_id}: proposals for a human",
             "Nothing here changes dispositions, H4, or write-back; record each decision in the run notes."]
    if outcome.get("research_only") is True:
        lines.append(f"Research only (known positive): no canonical; the fixing commit {target} was named by the human.")
    else:
        canonical = str(outcome.get("canonical", ""))
        lines.append(f"Canonical: {canonical if GHSA_PATTERN.match(canonical) else one_line_json(canonical)}; the commit that merged "
                     f"its fix: {target}.")
    lines.append(f"Base (the fix's first parent): {base}; target (the fix): {target}; pin: {outcome.get('pin', '')}")
    if outcome.get("analysis_revision") and outcome.get("analysis_revision") != base:
        lines.append(f"Analysis revision: {outcome['analysis_revision']} (an ancestor of the base; that analysis's contract was reused)")
    for issue_id, entry in outcome.get("issues", {}).items():
        reason = entry.get("reason", "")
        lines += ["", f"## {issue_id}", f"Proposal: {entry.get('outcome', '')}" + (f" ({reason})" if reason else "")]
        test = entry.get("test")
        if test:
            lines.append(f"Test: base {one_line_json(test.get('base_state', ''))}; at the target {one_line_json(test.get('at_target', ''))} "
                         f"(controls hold {yes(test.get('target_controls_hold'))}, sink reached {yes(test.get('target_sink_reached'))})")
            # as the currency brief: each value shown only when well formed, else as one-line JSON or "unknown"
            build = test.get("build", {}) if isinstance(test.get("build"), dict) else {}
            shown = {side: build.get(side) if build.get(side) in ("PASSED", "FAILED", "UNRESOLVED") else "unknown" for side in ("base", "target")}
            lines.append(f"Test build: base {shown['base']}, target {shown['target']}")
            sinks = []
            for side, key in (("base", "base_sink"), ("target", "target_sink")):
                sink = test.get(key)
                where = str(sink.get("location", "")) if isinstance(sink, dict) else ""
                path, _, line = where.rpartition(":")
                count = sink.get("count") if isinstance(sink, dict) and isinstance(sink.get("count"), int) else 0
                sinks.append(f"{side} {where if valid_path(path) and line.isdigit() else one_line_json(where)} (count {count})")
            lines.append("Test sinks: " + ", ".join(sinks))
            candidate = str(test.get("candidate_id", ""))
            candidate = candidate if re.fullmatch(r"[A-Za-z0-9_.:-]+", candidate) else one_line_json(candidate)
            lines.append(f"Test candidate: {candidate}; proposition: {one_line_json(test.get('proposition', ''))}")
            for name, message in sorted(test.get("target_failures", {}).items()):
                lines.append(f"Test failure at the target ({one_line_json(name)}): {one_line_json(message)}")
        else:
            lines.append("Test: none")
        if entry.get("outcome") == "COVERED_BY_FIX":
            lines.append("This is a proposal until --verify-fix (cold, two providers) confirms that the fix closes this report's contract; "
                         "this brief records no --verify-fix result.")
        if entry.get("outcome") == "NOT_COVERED_BY_FIX":
            lines.append("Step 1a's coverage is overturned for this issue: the test still fails after the fix. First check whether the test "
                         "asserts more than the invariant (see the failure lines); if it does not, the issue needs its own analysis at the pin "
                         "or its own fix.")
    restricted_dir(out.parent)
    data = encoded("\n".join(lines) + "\n", out)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)
    return {"status": "COMPLETE", "issues": len(outcome.get("issues", {})), "out": str(out)}


# ---------- frozen-test registry writer (test-only, coverage) ----------

IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")  # \Z: no trailing newline
CRATE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\Z")  # Cargo's package-name characters; never an option
ROUTING_LITERALS = ("PASSED", "FAILED", "UNRESOLVED", "NOT_RUN")
ADAPTER_TIMEOUT_CAP = 600  # deterministic-check.py caps an entry at 600 seconds


def proposition_digest(proposition: str) -> str:
    """deterministic-check.py's normalized_proposition_digest, copied: NFC, newlines normalized."""
    normalized = unicodedata.normalize("NFC", proposition).replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def command_registry(args: argparse.Namespace) -> dict[str, Any]:
    """The frozen-test registry and its deterministic-check.py requests, written once from a spec (develop-fixes-mode.md
    "Test-only entry" step 3). It decides nothing: names, roles, and the candidate come from the spec."""
    spec = load(args.spec)
    ends = revision_pair(str(spec.get("revision", "")))
    adversarial, benign = list(spec.get("adversarial") or []), list(spec.get("benign") or [])
    build, coverage = str(spec.get("build_name", "")), str(spec.get("coverage_name", ""))
    names = adversarial + benign + [build, coverage]
    if not adversarial or not benign:
        raise UsageError("the spec declares no adversarial-input test or no benign control (at least one of each)")
    if not all(isinstance(name, str) and IDENTIFIER.match(name) for name in names + [spec.get("test_target", "")]):
        raise UsageError("test, build, coverage, and test-target names must each be a plain identifier")
    if not isinstance(spec.get("crate"), str) or not CRATE_NAME.match(spec["crate"]):
        raise UsageError("crate must be a Cargo package name: a letter or _ first, then letters, digits, _, or -")
    if len(set(adversarial + benign)) != len(adversarial + benign):
        raise UsageError("a test is declared twice or in both roles; each test has one role")
    if len(set(names)) != len(names):
        raise UsageError("the build and coverage entries need names distinct from the tests and from each other")
    test_file = str(spec.get("test_file", ""))
    if not valid_path(test_file) or not re.fullmatch(r"(?:[A-Za-z0-9._-]+/)*tests/[A-Za-z0-9_]+\.rs", test_file):
        raise UsageError("test_file must be a .rs file directly in a crate's tests/ directory")
    if not HEX64.match(str(spec.get("test_file_sha256", ""))):
        raise UsageError("test_file_sha256 must be a 64-hex SHA-256")
    profile = str(spec.get("profile", ""))
    if not os.path.isabs(profile) or not Path(profile).is_file():
        raise UsageError("profile must be the absolute path of an existing profile file, written exactly as test-result's --profile")
    if str(Path(profile).resolve()) != profile:  # test-result compares every entry with the profile's resolved path
        raise UsageError(f"profile must be the profile file's real path, with no link or .. in it: {Path(profile).resolve()}")
    environment = spec.get("environment")
    if not isinstance(environment, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items()):
        raise UsageError("environment must map names to strings")
    coverage_output = str(spec.get("coverage_output", ""))
    if not valid_path(coverage_output):
        raise UsageError("coverage_output must be a checkout-relative path that does not leave the checkout")
    timeout = spec.get("timeout_seconds", ADAPTER_TIMEOUT_CAP)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 < timeout <= ADAPTER_TIMEOUT_CAP:
        raise UsageError(f"timeout_seconds must be a whole number from 1 to {ADAPTER_TIMEOUT_CAP} (the adapter's cap)")
    proposition = str(spec.get("proposition", ""))
    encoded(proposition, "the spec's proposition")  # hashed and written into every request below
    if not proposition.strip() or not str(spec.get("candidate_id", "")).startswith("SVA-"):
        raise UsageError("the spec names no candidate or proposition")
    out = Path(args.out_dir)
    if out.resolve().parent != Path(str(spec["revision"])).resolve().parent:  # D1: in the run, like every other output
        raise UsageError("the registry directory must be new and directly beside the revision record (in the run's currency/, "
                         "coverage/, or develop-fix/), never in a sandbox that Phase 2 code can write")
    ghsa_id = str(ends["record"].get("ghsa_id", ""))  # and the record's directory is the run's own (a copy elsewhere is not)
    if ends["kind"] == "currency":
        currency_out(out, ghsa_id)
    else:
        coverage_out(out, ghsa_id, ends["kind"])
    if out.exists():
        raise UsageError(f"{out} exists: a registry is written once, into a new directory")
    repository = str(ends["record"].get("repository", ""))
    routing = [{"literal_result": result, "final_status": "DISPUTED"} for result in ROUTING_LITERALS]
    prefix = [SANDBOX_EXEC, "-f", profile]
    base_options = ["-p", str(spec["crate"]), "--offline", "--locked"]
    test_options = base_options + ["--test", str(spec["test_target"])]

    def entry(argv: list[str], side: str, required: bool = True) -> dict[str, Any]:
        value = {"repository": repository, "revision": ends["revisions"][side], "proposition_sha256": proposition_digest(proposition),
                 "routing_table": routing, "argv": prefix + argv, "working_directory": ".", "timeout_seconds": timeout,
                 "expected_exit_status": 0, "environment": environment, "tool_version": str(spec.get("tool_version", "unrecorded"))}
        if required:
            value["required_files"] = {test_file: spec["test_file_sha256"]}
        return value

    tests: dict[str, dict[str, Any]] = {}
    for side in SIDES:
        suffix = ends["suffix"][side]
        for name in adversarial + benign:
            tests[f"{name}@{suffix}"] = entry(["cargo", "test"] + test_options + ["--", "--exact", name], side)
        tests[f"{build}@{suffix}"] = entry(["cargo", "test", "--no-run"] + base_options, side, required=False)
    coverage_argv = ["cargo", "llvm-cov", "test"] + test_options + ["--ignore-run-fail", "--json", "--output-path", coverage_output]
    tests[f"{coverage}@{ends['suffix']['report']}"] = entry(coverage_argv + ["--", "--exact"] + adversarial, "report")
    tests[f"{coverage}@{ends['suffix']['pin']}"] = entry(coverage_argv, "pin")
    data = encoded(json.dumps({"tests": tests}, ensure_ascii=False, indent=1, sort_keys=True), args.out_dir)
    registry_sha = hashlib.sha256(data).hexdigest()
    requests: dict[str, bytes] = {}  # every request encoded before anything is created
    for test_id in sorted(tests):
        side = "report" if test_id.endswith("@" + ends["suffix"]["report"]) else "pin"
        request = {"packet_revision": f"{ends['kind']}-test-{registry_sha[:12]}", "candidate_id": spec["candidate_id"],
                   "proposition": proposition, "check_id": test_id, "check_kind": "FROZEN_TEST_REFERENCE", "repository": repository,
                   "target_revision": ends["revisions"][side], "routing_table": routing, "registry_sha256": registry_sha,
                   "frozen_test_id": test_id}
        requests[test_id] = encoded(json.dumps(request, ensure_ascii=False, indent=1), f"the request for {test_id}")
    restricted_dir(out)
    (out / "requests").mkdir(mode=0o700)
    registry_path = out / "registry.json"
    with open(registry_path, "xb") as handle:
        handle.write(data)
    os.chmod(registry_path, 0o444)
    for test_id, request_bytes in requests.items():
        descriptor = os.open(out / "requests" / f"{test_id}.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(request_bytes)
    return {"status": "COMPLETE", "registry": str(registry_path), "registry_sha256": registry_sha, "entries": sorted(tests),
            "proposition_sha256": proposition_digest(proposition)}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("revision"); p.add_argument("--repo-dir", required=True, help="local clone of the repository (read only)")
    p.add_argument("--intake", required=True); p.add_argument("--default-branch", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("fix-revision"); p.add_argument("--repo-dir", required=True, help="local clone of the repository (read only)")
    p.add_argument("--intake", required=True, help="the later report's intake record (its run's own)")
    p.add_argument("--issues", required=True, help="the later report's issue list")
    p.add_argument("--kind", choices=("coverage", "develop-fix"), default="coverage")
    p.add_argument("--fix-commit", help="coverage: the commit that merged the canonical's fix, named by the human")
    p.add_argument("--default-branch", help="coverage: the default branch")
    p.add_argument("--landing-branch", help="develop-fix: the local landing branch")
    p.add_argument("--patched", help="develop-fix: the candidate patch's commit on the landing branch")
    p.add_argument("--dispositions", help="the later report's dispositions.json (triage path)")
    p.add_argument("--canonical", help="the GHSA ID of the open canonical (triage path)")
    p.add_argument("--canonical-intake", help="the canonical's current capture (triage path)")
    p.add_argument("--research", action="store_true", help="research variant: a published advisory, every technical issue")
    p.add_argument("--analysis-records", help="report-records.json of an earlier analysis at the base or an ancestor of it")
    p.add_argument("--out", required=True)
    p = sub.add_parser("plan"); p.add_argument("--issues", required=True)
    p.add_argument("--dispositions", help="the advisory's dispositions.json (triage and draft advisories)")
    p.add_argument("--research", action="store_true", help="research-only path for a published advisory: every technical issue")
    p.add_argument("--intake", help="the advisory's intake record (required with --research)")
    p.add_argument("--records", required=True, help="report-records.json of the analysis at the pin")
    p.add_argument("--revision", required=True, help="revision.json; the records must describe its pin"); p.add_argument("--out", required=True)
    p = sub.add_parser("flags"); p.add_argument("--repo-dir", required=True); p.add_argument("--revision", required=True)
    p.add_argument("--issues", required=True)
    p.add_argument("--records", action="append", help="report-records.json whose verified control sites add anchors; repeatable")
    p.add_argument("--out", required=True)
    p = sub.add_parser("outcome"); p.add_argument("--revision", required=True); p.add_argument("--plan", required=True)
    p.add_argument("--report-records", help="report-records.json of the analysis at the report revision, once it has run")
    p.add_argument("--test", action="append", help="currency-check.py test-result output for a planned issue; repeatable")
    p.add_argument("--out", required=True)
    p = sub.add_parser("brief"); p.add_argument("--outcome", required=True); p.add_argument("--flags")
    p.add_argument("--fix-terms", help="the saved output of intake-check.py render --fix-blind"); p.add_argument("--out", required=True)
    p = sub.add_parser("sandbox-profile"); p.add_argument("--sandbox-dir", required=True, help="outside the home directory")
    p.add_argument("--run-root", required=True); p.add_argument("--repo-dir", required=True)
    p.add_argument("--out", required=True, help="profile file for sandbox-exec -f")
    p = sub.add_parser("checkout"); p.add_argument("--repo-dir", required=True); p.add_argument("--revision", required=True)
    p.add_argument("--which", required=True, choices=["report", "pin", "base", "target"]); p.add_argument("--sandbox-dir", required=True)
    p.add_argument("--test-file", action="append",
                   help="<relative path>=<source>: copy a frozen integration-test file (a new .rs file in a crate's tests/); repeat")
    p = sub.add_parser("registry"); p.add_argument("--spec", required=True); p.add_argument("--out-dir", required=True)
    p = sub.add_parser("coverage-outcome"); p.add_argument("--revision", required=True, help="coverage pair record (fix-revision)")
    p.add_argument("--records", required=True, help="records at the pair's analysis revision"); p.add_argument("--test", action="append")
    p.add_argument("--out", required=True)
    p = sub.add_parser("coverage-brief"); p.add_argument("--outcome", required=True); p.add_argument("--out", required=True)
    p = sub.add_parser("test-result"); p.add_argument("--revision", required=True, help="currency revision.json or coverage pair record")
    p.add_argument("--plan", help="the currency plan (currency kind only)")
    p.add_argument("--issue-id", required=True)
    p.add_argument("--registry", required=True, help="the frozen-test registry holding every <name>@report / <name>@pin pair")
    p.add_argument("--profile", required=True, help="the Phase 2 profile every entry runs under (sandbox-exec -f <profile>)")
    p.add_argument("--candidate-id", required=True, help="the verified candidate at the report revision the tests were written for")
    p.add_argument("--adversarial", action="append", required=True, help="pair name of an adversarial-input test; repeat")
    p.add_argument("--benign", action="append", required=True, help="pair name of a benign control; repeat")
    p.add_argument("--build", required=True, help="pair name of the build entry (cargo test --no-run under the profile)")
    p.add_argument("--coverage", required=True, help="name of the coverage entries <name>@report (adversarial tests) and <name>@pin (all)")
    p.add_argument("--base-result", action="append", required=True, help="deterministic-check.py result at the report revision; repeat")
    p.add_argument("--pin-result", "--target-result", dest="pin_result", action="append", required=True,
                   help="deterministic-check.py result at the pin (coverage kind: the target); repeat")
    p.add_argument("--base-checkout", required=True); p.add_argument("--pin-checkout", "--target-checkout", dest="pin_checkout", required=True)
    p.add_argument("--base-sink", required=True, help="<relative path>:<line> of the sink at the report revision")
    p.add_argument("--pin-sink", "--target-sink", dest="pin_sink", required=True)
    p.add_argument("--report-records", required=True, help="report-records.json of the analysis at the report revision")
    p.add_argument("--poc-overlap", action="append", required=True, help="intake-check.py poc-overlap output per test file")
    p.add_argument("--out", required=True)
    args = parser.parse_args()
    handlers = {"revision": command_revision, "fix-revision": command_fix_revision, "plan": command_plan, "flags": command_flags, "outcome": command_outcome,
                "brief": command_brief, "sandbox-profile": command_sandbox_profile, "checkout": command_checkout,
                "test-result": command_test_result, "coverage-outcome": command_coverage_outcome, "registry": command_registry,
                "coverage-brief": command_coverage_brief}
    try:
        outcome = handlers[args.command](args)
    except (UsageError, KeyError, TypeError, IndexError, AttributeError, OSError, UnicodeError) as error:  # UnicodeError: a lone surrogate
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    outcome.update({"adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION})
    print(json.dumps(outcome, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
