#!/usr/bin/env python3
"""Read-only GitHub Security Advisory intake for security-vuln-analyzer.

Every GitHub request goes through `gh_get`, which issues `gh api -X GET` and nothing
else. Captured bytes are stored verbatim with SHA-256 digests in a restricted run
directory outside any git work tree. Reporter-supplied severity, CVSS, and CWE values
are stored as labeled reporter claims and never as skill assessments.

Read token: if `SVA_GHSA_READ_TOKEN` is set, it is passed to `gh` as `GH_TOKEN` for that
subprocess only; otherwise `gh` uses its own stored authentication. The write token is
never read here.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import unicodedata
from typing import Any
from urllib.parse import quote

ADAPTER_NAME = "security-vuln-analyzer-ghsa-fetch"
ADAPTER_VERSION = "1.0.0"
API_VERSION = "2022-11-28"
ACCEPT = "application/vnd.github+json"
READ_TOKEN_ENV = "SVA_GHSA_READ_TOKEN"
GHSA_ID = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
GHSA_ID_PATTERN = re.compile(rf"^{GHSA_ID}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
URL_PATTERN = re.compile(
    rf"^https://github\.com/(?P<repo>[A-Za-z0-9](?:[A-Za-z0-9-]{{0,38}})/[A-Za-z0-9._-]{{1,100}})"
    rf"\/security\/advisories\/(?P<ghsa>{GHSA_ID})\/?$"
)
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
STATES = ("triage", "draft", "published", "closed")
REPORTER_CLAIM_LABEL = "REPORTER CLAIM - not a skill assessment; never populates discovery scoring"
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_FETCH = 3


class UsageError(ValueError):
    pass


class FetchError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_text_digest(text: str) -> str:
    normalized = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    return sha256_bytes(normalized.encode("utf-8"))


def parse_target(ghsa: str, repo: str | None) -> tuple[str, str, str]:
    """Return (repository, ghsa_id, source) from a URL, or an ID plus --repo."""
    match = URL_PATTERN.match(ghsa)
    if match:
        url_repo = match.group("repo")
        if repo is not None and repo.lower() != url_repo.lower():
            raise UsageError(f"--repo {repo} does not match the advisory URL repository {url_repo}")
        return url_repo, match.group("ghsa"), "URL"
    if GHSA_ID_PATTERN.match(ghsa):
        if repo is None:
            raise UsageError(
                "a bare GHSA ID needs --repo OWNER/REPO; unpublished advisories are not in the global "
                "database and the skill does not guess the repository from git remotes"
            )
        if not REPOSITORY_PATTERN.match(repo):
            raise UsageError("--repo must be OWNER/REPO")
        return repo, ghsa, "ID_AND_REPO"
    raise UsageError(
        "--ghsa must be https://github.com/OWNER/REPO/security/advisories/GHSA-xxxx-xxxx-xxxx "
        "or a GHSA ID with --repo OWNER/REPO"
    )


class Api:
    """GET-only access to the GitHub REST API through `gh`, or to an offline fixture directory."""

    def __init__(self, fixtures: Path | None) -> None:
        self.fixtures = fixtures

    @staticmethod
    def fixture_name(path: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", path) + ".json"

    def gh_get(self, path: str, *, paginate: bool = False, allow_missing: bool = False) -> bytes | None:
        if self.fixtures is not None:
            candidate = self.fixtures / self.fixture_name(path)
            if not candidate.is_file():
                if allow_missing:
                    return None
                raise FetchError(f"fixture missing for GET {path}")
            return candidate.read_bytes()
        argv = ["gh", "api", "-X", "GET", "-H", f"Accept: {ACCEPT}", "-H", f"X-GitHub-Api-Version: {API_VERSION}"]
        if paginate:
            argv += ["--paginate", "--slurp"]
        argv.append(path)
        environment = dict(os.environ)
        token = environment.pop(READ_TOKEN_ENV, "")
        if token:
            environment["GH_TOKEN"] = token
        try:
            process = subprocess.run(argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, timeout=120)
        except (OSError, subprocess.SubprocessError) as error:
            raise FetchError(f"gh could not be run: {error}") from error
        if process.returncode != 0:
            detail = process.stderr.decode("utf-8", errors="replace").strip()
            if allow_missing and ("404" in detail or "Not Found" in detail):
                return None
            raise FetchError(f"GET {path} failed: {detail[-300:] or 'no error output'}")
        return process.stdout

    def get_json(self, path: str, **options: Any) -> tuple[Any, bytes | None]:
        raw = self.gh_get(path, **options)
        if raw is None:
            return None, None
        try:
            return json.loads(raw.decode("utf-8")), raw
        except (UnicodeError, json.JSONDecodeError) as error:
            raise FetchError(f"GET {path} returned invalid JSON: {error}") from error


def ensure_run_root(run_root: Path) -> Path:
    run_root = run_root.expanduser()
    run_root.mkdir(parents=True, exist_ok=True)
    os.chmod(run_root, 0o700)
    probe = subprocess.run(
        ["git", "-C", str(run_root), "rev-parse", "--is-inside-work-tree"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10,
    )
    if probe.returncode == 0 and probe.stdout.strip() == "true":
        raise UsageError("the run root is inside a git work tree; choose a restricted directory outside any repository")
    return run_root.resolve()


def restricted_dir(path: Path) -> Path:
    # Create every missing level with mode 700, not only the leaf (mkdir(parents=True) uses the umask).
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


def write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def write_json(path: Path, value: Any) -> None:
    write_private(path, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8"))


def repo_dir(run_root: Path, repository: str) -> Path:
    owner, name = repository.split("/", 1)
    return restricted_dir(run_root / f"{owner}__{name}")


def pin_revision(api: Api, repository: str, revision: str | None, tag: str | None) -> dict[str, str]:
    if revision and tag:
        raise UsageError("use at most one of --revision and --tag")
    if revision:
        if not SHA_PATTERN.match(revision):
            raise UsageError("--revision must be a full 40-character lowercase commit SHA")
        commit, _ = api.get_json(f"repos/{repository}/commits/{revision}")
        if not isinstance(commit, dict) or commit.get("sha") != revision:
            raise FetchError("the requested revision does not exist in the repository")
        return {"repository": repository, "revision": revision, "revision_source": "USER_SELECTED", "ref": ""}
    if tag:
        ref, _ = api.get_json("/".join(("repos", repository, "git", "ref", "tags", quote(tag, safe=""))), allow_missing=True)
        if not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{tag}":
            raise UsageError(f"no exact tag {tag!r}; select a revision with --revision instead")
        target = ref.get("object", {})
        for _ in range(5):
            if target.get("type") == "commit":
                break
            if target.get("type") != "tag":
                raise FetchError("tag does not resolve to a commit")
            tag_object, _ = api.get_json("/".join(("repos", repository, "git", "tags", str(target.get("sha")))))
            target = tag_object.get("object", {}) if isinstance(tag_object, dict) else {}
        sha = target.get("sha", "")
        if target.get("type") != "commit" or not SHA_PATTERN.match(sha):
            raise FetchError("tag does not resolve to a commit")
        return {"repository": repository, "revision": sha, "revision_source": "EXACT_TAG", "ref": f"refs/tags/{tag}"}
    repo, _ = api.get_json(f"repos/{repository}")
    branch = repo.get("default_branch") if isinstance(repo, dict) else None
    if not isinstance(branch, str) or not branch:
        raise FetchError("repository default branch is unavailable")
    commit, _ = api.get_json(f"repos/{repository}/commits/{quote(branch, safe='')}")
    sha = commit.get("sha", "") if isinstance(commit, dict) else ""
    if not SHA_PATTERN.match(sha):
        raise FetchError("default-branch HEAD is unavailable")
    return {"repository": repository, "revision": sha, "revision_source": "DEFAULT_BRANCH_HEAD", "ref": f"refs/heads/{branch}"}


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def string_or_empty(value: Any) -> str:
    return value if isinstance(value, str) else ""


def map_advisory(advisory: dict[str, Any], comments: list[Any] | None) -> dict[str, Any]:
    severities = as_dict(advisory.get("cvss_severities"))
    cvss_v3 = as_dict(severities.get("cvss_v3"))
    cvss_v4 = as_dict(severities.get("cvss_v4"))
    vulnerabilities = []
    for item in advisory.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        package = as_dict(item.get("package"))
        vulnerabilities.append({
            "ecosystem": string_or_empty(package.get("ecosystem")),
            "package": string_or_empty(package.get("name")),
            "vulnerable_version_range": string_or_empty(item.get("vulnerable_version_range")),
            "patched_versions": string_or_empty(item.get("patched_versions")),
            "vulnerable_functions": [f for f in item.get("vulnerable_functions") or [] if isinstance(f, str)],
        })
    author = as_dict(advisory.get("author"))
    private_fork = as_dict(advisory.get("private_fork"))
    submission = as_dict(advisory.get("submission"))
    comment_texts = []
    for comment in comments or []:
        if isinstance(comment, dict):
            comment_texts.append({
                "comment_id": str(comment.get("id", "")),
                "author_login": string_or_empty(as_dict(comment.get("user")).get("login")),
                "created_at": string_or_empty(comment.get("created_at")),
                "body": string_or_empty(comment.get("body")),
            })
    description = string_or_empty(advisory.get("description"))
    return {
        "ghsa_id": string_or_empty(advisory.get("ghsa_id")),
        "cve_id": string_or_empty(advisory.get("cve_id")),
        "html_url": string_or_empty(advisory.get("html_url")),
        "state": string_or_empty(advisory.get("state")),
        "created_at": string_or_empty(advisory.get("created_at")),
        "updated_at": string_or_empty(advisory.get("updated_at")),
        "submission_accepted": submission.get("accepted") if isinstance(submission.get("accepted"), bool) else None,
        "author_login": string_or_empty(author.get("login")),
        "summary": string_or_empty(advisory.get("summary")),
        "description": description,
        "body_sha256": normalized_text_digest(description),
        "comments": comment_texts,
        "reporter_claims": {
            "label": REPORTER_CLAIM_LABEL,
            "severity": string_or_empty(advisory.get("severity")),
            "cvss_v3_vector": string_or_empty(cvss_v3.get("vector_string")),
            "cvss_v4_vector": string_or_empty(cvss_v4.get("vector_string")),
            "cwe_ids": [c for c in advisory.get("cwe_ids") or [] if isinstance(c, str)],
            "vulnerabilities": vulnerabilities,
        },
        "private_fork": {
            "present": bool(private_fork),
            "full_name": string_or_empty(private_fork.get("full_name")),
        },
    }


def capture_advisory(api: Api, repository: str, ghsa_id: str) -> tuple[dict[str, Any], bytes, list[Any] | None, bytes | None]:
    advisory, raw = api.get_json(f"repos/{repository}/security-advisories/{ghsa_id}")
    if not isinstance(advisory, dict) or advisory.get("ghsa_id") != ghsa_id or raw is None:
        raise FetchError("advisory response does not name the requested GHSA ID")
    try:  # comments are optional evidence: any failure is recorded as UNAVAILABLE, not fatal
        comments, comments_raw = api.get_json(
            f"repos/{repository}/security-advisories/{ghsa_id}/comments", paginate=True, allow_missing=True
        )
    except FetchError:
        comments, comments_raw = None, None
    if isinstance(comments, list) and comments and all(isinstance(page, list) for page in comments):
        comments = [item for page in comments for item in page]
    if comments is not None and not isinstance(comments, list):
        comments, comments_raw = None, None
    return advisory, raw, comments, comments_raw


def comments_status(advisory: dict[str, Any], comments: list[Any] | None, raw: bytes | None) -> str:
    """CAPTURED_INCOMPLETE when the advisory's comment count exceeds what the endpoint returned."""
    if raw is None:
        return "UNAVAILABLE"
    count = advisory.get("comments")
    if isinstance(count, int) and count > len(comments or []):
        return "CAPTURED_INCOMPLETE"
    return "CAPTURED"


def command_advisory(args: argparse.Namespace, api: Api) -> dict[str, Any]:
    repository, ghsa_id, source = parse_target(args.ghsa, args.repo)
    run_root = ensure_run_root(Path(args.run_root))
    retrieved = utc_now()
    advisory, raw, comments, comments_raw = capture_advisory(api, repository, ghsa_id)
    pinned = pin_revision(api, repository, args.revision, args.tag)
    run_id = retrieved.replace(":", "").replace("-", "") + "-" + secrets.token_hex(4)  # unique per capture
    intake_dir = restricted_dir(repo_dir(run_root, repository) / ghsa_id / run_id / "intake")
    write_private(intake_dir / "advisory.raw.json", raw)
    if comments_raw is not None:
        write_private(intake_dir / "comments.raw.json", comments_raw)
    record = {
        "record_type": "ghsa_intake",
        "schema_version": "1",
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "repository": repository,
        "input_form": source,
        "run_id": run_id,
        "retrieved_at_utc": retrieved,
        "api_version": API_VERSION,
        "raw": {
            "advisory_file": "advisory.raw.json",
            "advisory_sha256": sha256_bytes(raw),
            "comments_file": "comments.raw.json" if comments_raw is not None else "",
            "comments_sha256": sha256_bytes(comments_raw) if comments_raw is not None else "",
            "comments_status": comments_status(advisory, comments, comments_raw),
            "comments_count_field": advisory.get("comments") if isinstance(advisory.get("comments"), int) else -1,
        },
        "advisory": map_advisory(advisory, comments),
        "pinned_target": pinned,
    }
    write_json(intake_dir / "intake-record.json", record)
    return {"status": "COMPLETE", "intake_dir": str(intake_dir), "record": record}


def command_queue(args: argparse.Namespace, api: Api) -> dict[str, Any]:
    repository = args.repo
    if not REPOSITORY_PATTERN.match(repository or ""):
        raise UsageError("--repo must be OWNER/REPO")
    run_root = ensure_run_root(Path(args.run_root))
    retrieved = utc_now()
    states = STATES if args.state == "all" else (args.state,)
    listing_id = retrieved.replace(":", "").replace("-", "") + "-" + secrets.token_hex(4)  # unique per listing
    listing_dir = restricted_dir(repo_dir(run_root, repository) / "index" / listing_id)
    entries = []
    listing_digests: dict[str, str] = {}
    for state in states:
        pages, raw = api.get_json(
            f"repos/{repository}/security-advisories?state={state}&per_page=100", paginate=True
        )
        if raw is None or not isinstance(pages, list):
            raise FetchError(f"advisory listing for state {state} is unavailable")
        # Listing bytes contain every report's text; keep only their digest. Each advisory is
        # captured verbatim in its own directory by the advisory command.
        listing_digests[state] = sha256_bytes(raw)
        items = [item for page in pages for item in (page if isinstance(page, list) else [page])]
        for item in items:
            if not isinstance(item, dict) or not GHSA_ID_PATTERN.match(str(item.get("ghsa_id", ""))):
                continue
            description = string_or_empty(item.get("description"))
            entries.append({
                "ghsa_id": item["ghsa_id"],
                "state": string_or_empty(item.get("state")),
                "created_at": string_or_empty(item.get("created_at")),
                "updated_at": string_or_empty(item.get("updated_at")),
                "body_sha256": normalized_text_digest(description),
            })
    entries.sort(key=lambda entry: (entry["created_at"], entry["ghsa_id"]))
    listing = {
        "record_type": "ghsa_queue_listing",
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "repository": repository,
        "retrieved_at_utc": retrieved,
        "states": list(states),
        "listing_sha256": {state: digest for state, digest in sorted(listing_digests.items())},
        "advisories": entries,
    }
    write_json(listing_dir / "listing.json", listing)
    return {"status": "COMPLETE", "listing_dir": str(listing_dir), "listing": listing}


def command_compare(args: argparse.Namespace, api: Api) -> dict[str, Any]:
    record = json.loads(Path(args.record).read_text(encoding="utf-8"))
    repository = record["repository"]
    ghsa_id = record["advisory"]["ghsa_id"]
    advisory, _ = api.get_json(f"repos/{repository}/security-advisories/{ghsa_id}")
    if not isinstance(advisory, dict):
        raise FetchError("advisory re-fetch failed")
    changed = []
    if string_or_empty(advisory.get("updated_at")) != record["advisory"]["updated_at"]:
        changed.append("updated_at")
    if normalized_text_digest(string_or_empty(advisory.get("description"))) != record["advisory"]["body_sha256"]:
        changed.append("description")
    return {"status": "CHANGED" if changed else "UNCHANGED", "changed_fields": changed, "ghsa_id": ghsa_id}


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    parser.add_argument("--api-fixtures", type=Path, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    advisory = sub.add_parser("advisory", help="capture one advisory")
    advisory.add_argument("--ghsa", required=True, help="advisory URL, or GHSA ID with --repo")
    advisory.add_argument("--repo", help="OWNER/REPO (required with a bare GHSA ID)")
    advisory.add_argument("--run-root", required=True)
    advisory.add_argument("--revision", help="pin this full commit SHA instead of default-branch HEAD")
    advisory.add_argument("--tag", help="pin this exact tag instead of default-branch HEAD")
    queue_parser = sub.add_parser("queue", help="list advisories for a queue indexing pass")
    queue_parser.add_argument("--repo", required=True)
    queue_parser.add_argument("--run-root", required=True)
    queue_parser.add_argument("--state", choices=(*STATES, "all"), default="all")
    compare = sub.add_parser("compare", help="re-fetch and compare against a captured intake record")
    compare.add_argument("--record", required=True)
    args = parser.parse_args()
    api = Api(args.api_fixtures)
    try:
        if args.command == "advisory":
            outcome = command_advisory(args, api)
        elif args.command == "queue":
            outcome = command_queue(args, api)
        else:
            outcome = command_compare(args, api)
    except UsageError as error:
        print(json.dumps({"status": "USAGE_ERROR", "error": str(error)}), file=sys.stderr)
        return EXIT_USAGE
    except (FetchError, OSError, KeyError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}), file=sys.stderr)
        return EXIT_FETCH
    summary = {key: value for key, value in outcome.items() if key not in ("record", "listing")}
    print(json.dumps(summary, sort_keys=True))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
