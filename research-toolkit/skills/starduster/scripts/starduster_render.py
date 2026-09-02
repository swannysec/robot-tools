"""Deterministic, filesystem-safe rendering for the portable Starduster controller."""

from __future__ import annotations

import datetime as _datetime
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


YAML_ERROR = yaml.YAMLError if yaml is not None else ValueError


class SynthesisValidationError(Exception):
    """Raised when a synthesis response cannot safely be associated with its input."""


_CATEGORIES = {
    "AI & Machine Learning",
    "CLI & Terminal Tools",
    "Cloud & Infrastructure",
    "Cybersecurity",
    "Data & Databases",
    "Developer Tools",
    "Documentation & Writing",
    "Frontend & UI",
    "Game Development",
    "Mobile Development",
    "Networking & Protocols",
    "Operating Systems & Low-Level",
    "Programming Languages & Runtimes",
    "Web Backend & APIs",
    "Uncategorized",
}
_MATURITIES = {"experimental", "active", "mature", "unmaintained"}
_TAG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SLUG = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
_DANGEROUS = re.compile(
    r"<%[\s\S]*?%>|\[[^\]\n]{1,100}::[^\]\n]*\]|```(?:dataview|dataviewjs)[\s\S]*?```|"
    r"<\s*(?:script|iframe|object|embed|form|input)\b[^>]*>|<\s*img\b[^>]*>|"
    r"<\s*a\b[^>]*javascript:[^>]*>|\son[a-z]+\s*=",
    re.IGNORECASE,
)
_CREDENTIAL = re.compile(r"-----BEGIN|\b(?:gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|AKIA[A-Z0-9]{12,}|token\s*:)", re.IGNORECASE)
_PROMPT_INJECTION = re.compile(r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\.?", re.IGNORECASE)
_MARKDOWN_IMAGE = re.compile(
    r"!\[[^\]\n]{0,200}\]\([^\)\n]{0,2000}\)|!\[\[[^\]\n]{1,500}\]\]|!\[[^\]\n]{0,200}\]\[[^\]\n]{1,200}\]",
    re.IGNORECASE,
)
_UNSAFE_MARKDOWN_LINK = re.compile(
    r"\[([^\]\n]{0,500})\]\(\s*(?:javascript|data|file|obsidian|command|vscode):[^\)\n]*\)",
    re.IGNORECASE,
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_AUTO_FIELDS = {
    "title", "source", "full_name", "owner", "language", "license", "stars", "forks",
    "archived", "is_fork", "parent", "has_readme", "readme_oversized", "date_starred",
    "date_created", "last_pushed", "date_updated", "category", "maturity", "use_case",
    "similar_to", "topics", "summary",
}
_SET_ONCE_FIELDS = {"date_cataloged", "status", "reviewed", "date_unstarred"}


def validate_synthesis_payload(payload: object, expected_full_names: list[str]) -> list[dict[str, Any]]:
    """Validate the exact output envelope before any model-generated data is rendered.

    Value sanitization intentionally happens after this structural boundary so a malformed
    topic or category cannot turn into a different object or escape its assigned repository.
    """
    if not isinstance(payload, list) or len(payload) != len(expected_full_names):
        raise SynthesisValidationError("synthesis response must be an array matching the input batch")
    required = {
        "full_name", "html_url", "category", "normalized_topics", "summary", "key_features",
        "similar_to", "use_case", "maturity", "author_display",
    }
    records: list[dict[str, Any]] = []
    for expected, item in zip(expected_full_names, payload):
        if not isinstance(item, dict) or set(item) != required:
            raise SynthesisValidationError("synthesis record has missing or unexpected fields")
        if item.get("full_name") != expected or not _SLUG.fullmatch(expected):
            raise SynthesisValidationError("synthesis record identity does not match its input")
        if item.get("html_url") != "https://github.com/{}".format(expected):
            raise SynthesisValidationError("synthesis record URL does not match its identity")
        for field in ("category", "summary", "use_case", "maturity", "author_display"):
            if not isinstance(item[field], str):
                raise SynthesisValidationError("synthesis scalar fields must be strings")
        if len(item["summary"]) > 500 or len(item["use_case"]) > 150 or len(item["author_display"]) > 100:
            raise SynthesisValidationError("synthesis scalar field exceeds its limit")
        for field, minimum, maximum, item_limit in (
            ("normalized_topics", 0, 20, 100),
            ("key_features", 3, 8, 100),
            ("similar_to", 0, 3, 200),
        ):
            values = item[field]
            if not isinstance(values, list) or len(values) < minimum or (maximum is not None and len(values) > maximum):
                raise SynthesisValidationError("{} has invalid cardinality".format(field))
            if any(not isinstance(value, str) or len(value) > item_limit for value in values):
                raise SynthesisValidationError("{} has invalid values".format(field))
            if field in {"normalized_topics", "similar_to"} and len(set(values)) != len(values):
                raise SynthesisValidationError("{} must contain unique values".format(field))
        records.append(dict(item))
    return records


def load_existing_identities(output_dir: Path) -> dict[str, Path]:
    """Return safe repository identity-to-note mappings without following symlinks."""
    repos = output_dir / "repos"
    if not repos.is_dir() or repos.is_symlink():
        return {}
    identities: dict[str, Path] = {}
    for path in sorted(repos.glob("*.md")):
        if path.is_symlink() or not path.is_file():
            continue
        frontmatter, _ = _read_note(path)
        full_name = frontmatter.get("full_name")
        if isinstance(full_name, str) and _SLUG.fullmatch(full_name) and full_name not in identities:
            identities[full_name] = path
    return identities


def render_catalog(
    output_dir: Path,
    subfolder: str,
    all_stars: list[dict[str, Any]],
    processed_stars: list[dict[str, Any]],
    synthesis_records: list[dict[str, Any]],
) -> dict[str, int]:
    """Render repository notes, graph hubs, and Bases from validated deterministic data."""
    _ensure_directory(output_dir)
    directories = {name: _safe_child(output_dir, name) for name in ("repos", "indexes", "categories", "topics", "authors")}
    for directory in directories.values():
        _ensure_directory(directory)

    all_by_name = {_full_name(star): star for star in all_stars if _full_name(star)}
    existing = load_existing_identities(output_dir)
    unstarred = 0
    for full_name, path in existing.items():
        if full_name in all_by_name:
            continue
        frontmatter, body = _read_note(path)
        if frontmatter.get("status") != "unstarred":
            frontmatter["status"] = "unstarred"
            frontmatter.setdefault("date_unstarred", _today())
            _write_note(path, frontmatter, body)
            unstarred += 1

    synthesis_by_name = {record.get("full_name"): record for record in synthesis_records if isinstance(record, dict)}
    processed_by_name = {_full_name(star): star for star in processed_stars if _full_name(star)}
    repo_notes = 0
    skipped = 0
    for full_name in sorted(processed_by_name, key=lambda name: _sort_star(processed_by_name[name])):
        record = synthesis_by_name.get(full_name)
        if record is None:
            skipped += 1
            continue
        try:
            sanitized = _sanitize_record(record)
            path = existing.get(full_name) or _note_path(directories["repos"], full_name, existing.values())
            old_frontmatter, old_body = _read_note(path) if path.exists() and not path.is_symlink() else ({}, "")
            frontmatter = _merge_frontmatter(old_frontmatter, processed_by_name[full_name], sanitized)
            body = _render_repo_body(frontmatter, sanitized, old_body, all_by_name)
            _write_note(path, frontmatter, body)
            existing[full_name] = path
            repo_notes += 1
        except (OSError, ValueError, YAML_ERROR):
            skipped += 1

    rows = _catalog_rows(load_existing_identities(output_dir))
    active_rows = [row for row in rows if row["frontmatter"].get("status", "active") != "unstarred"]
    category_hubs = _render_category_hubs(directories["categories"], active_rows)
    topic_hubs = _render_topic_hubs(directories["topics"], active_rows)
    author_hubs = _render_author_hubs(directories["authors"], active_rows)
    base_indexes = _render_bases(directories["indexes"], subfolder)
    return {
        "repo_notes": repo_notes,
        "skipped": skipped,
        "category_hubs": category_hubs,
        "topic_hubs": topic_hubs,
        "author_hubs": author_hubs,
        "base_indexes": base_indexes,
        "unstarred": unstarred,
    }


def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
    category = _clean_text(record["category"])
    if category not in _CATEGORIES:
        category = "Uncategorized"
    maturity = _clean_text(record["maturity"])
    if maturity not in _MATURITIES:
        maturity = "active"
    topics = [_clean_text(topic).lower() for topic in record["normalized_topics"]]
    topics = list(dict.fromkeys(topic for topic in topics if _TAG.fullmatch(topic)))
    similar = [_clean_text(value) for value in record["similar_to"]]
    similar = list(dict.fromkeys(value for value in similar if _SLUG.fullmatch(value)))
    features = [_clean_text(value) for value in record["key_features"]]
    features = [value for value in features if value]
    return {
        "full_name": record["full_name"],
        "html_url": record["html_url"],
        "category": category,
        "normalized_topics": topics,
        "summary": _clean_text(record["summary"]),
        "key_features": features,
        "similar_to": similar,
        "use_case": _clean_text(record["use_case"]),
        "maturity": maturity,
        "author_display": _wikilink_text(record["author_display"]),
    }


def _clean_text(value: str) -> str:
    value = _CONTROL.sub("", value).replace("\r", " ").replace("\n", " ")
    value = _MARKDOWN_IMAGE.sub("", value)
    value = _UNSAFE_MARKDOWN_LINK.sub(r"\1", value)
    value = _DANGEROUS.sub("", value)
    value = _PROMPT_INJECTION.sub("", value)
    if _CREDENTIAL.search(value):
        return ""
    return re.sub(r"\s+", " ", value).strip().replace("---", "")


def _wikilink_text(value: str) -> str:
    return _clean_text(value).translate(str.maketrans("", "", "[]|#"))


def _merge_frontmatter(existing: dict[str, Any], star: dict[str, Any], synthesis: dict[str, Any]) -> dict[str, Any]:
    full_name = synthesis["full_name"]
    data = _star_data(star)
    owner = data.get("owner_login") or full_name.split("/", 1)[0]
    auto = {
        "title": full_name,
        "source": synthesis["html_url"],
        "full_name": full_name,
        "owner": _clean_text(str(owner)),
        "language": _optional_text(data.get("language")),
        "license": _optional_text(data.get("license_spdx")),
        "stars": _integer(data.get("stargazers_count")),
        "forks": _integer(data.get("forks_count")),
        "archived": bool(data.get("archived", False)),
        "is_fork": bool(data.get("is_fork", data.get("fork", False))),
        "parent": _optional_text(data.get("parent_full_name")),
        "has_readme": bool(data.get("has_readme", True)),
        "readme_oversized": bool(data.get("readme_oversized", False)),
        "date_starred": _date(data.get("starred_at")),
        "date_created": _date(data.get("created_at")),
        "last_pushed": _date(data.get("pushed_at")),
        "date_updated": _today(),
        "category": synthesis["category"],
        "maturity": synthesis["maturity"],
        "use_case": synthesis["use_case"],
        "similar_to": synthesis["similar_to"],
        "topics": synthesis["normalized_topics"],
        "summary": synthesis["summary"],
    }
    set_once = {
        "date_cataloged": existing.get("date_cataloged", _today()),
        "status": existing.get("status", "active"),
        "reviewed": existing.get("reviewed", False),
    }
    if "date_unstarred" in existing:
        set_once["date_unstarred"] = existing["date_unstarred"]
    custom = {key: value for key, value in existing.items() if key not in _AUTO_FIELDS | _SET_ONCE_FIELDS}
    return {**auto, **set_once, **custom}


def _render_repo_body(frontmatter: dict[str, Any], synthesis: dict[str, Any], old_body: str, all_stars: dict[str, dict[str, Any]]) -> str:
    user_notes = _user_notes(old_body)
    language = frontmatter["language"] or "Not specified"
    license_name = frontmatter["license"] or "Not specified"
    lines = [
        "# {}".format(frontmatter["full_name"]), "", "## Summary", "", synthesis["summary"], "", "## Overview", "",
        "| | |", "|---|---|",
        "| **Category** | [[Category - {}]] |".format(_wikilink_text(synthesis["category"])),
        "| **Language** | {} |".format(language),
        "| **License** | {} |".format(license_name),
        "| **Stars** | {} |".format(frontmatter["stars"]),
        "| **Forks** | {} |".format(frontmatter["forks"]),
        "| **Maturity** | {} |".format(synthesis["maturity"]),
        "| **Author** | [[Author - {}]] |".format(_wikilink_text(str(frontmatter["owner"]))),
    ]
    if synthesis["use_case"]:
        lines.extend(["", "**Use case:** {}".format(synthesis["use_case"])])
    lines.extend(["", "## Topics", ""])
    lines.extend("[[Topic - {}]]".format(topic) for topic in synthesis["normalized_topics"])
    lines.extend(["", "## Key Features", ""])
    lines.extend("- {}".format(feature) for feature in synthesis["key_features"])
    if synthesis["similar_to"]:
        lines.extend(["", "## Similar Projects", ""])
        for similar in synthesis["similar_to"]:
            if similar in all_stars:
                lines.append("- [[{}]]".format(_filename_stem(similar)))
            else:
                lines.append("- [{}](https://github.com/{})".format(similar, similar))
    lines.extend(["", "## Links", "", "- [GitHub Repository]({})".format(synthesis["html_url"])])
    if frontmatter["is_fork"]:
        parent = frontmatter.get("parent")
        lines.append("- Fork of [[{}]]".format(_filename_stem(str(parent))) if parent else "- Fork (parent unknown)")
    lines.extend(["", "## Notes", "", "<!-- USER-NOTES-START -->"])
    if user_notes:
        lines.extend(user_notes.rstrip("\n").splitlines())
    lines.extend(["<!-- USER-NOTES-END -->", "", "---", "*Cataloged by starduster on {}. Last updated {}.*".format(frontmatter["date_cataloged"], frontmatter["date_updated"]), ""])
    return "\n".join(lines)


def _catalog_rows(identities: dict[str, Path]) -> list[dict[str, Any]]:
    rows = []
    for full_name, path in identities.items():
        frontmatter, _ = _read_note(path)
        rows.append({"full_name": full_name, "path": path, "frontmatter": frontmatter})
    return sorted(rows, key=lambda row: (-_integer(row["frontmatter"].get("stars")), _filename_stem(row["full_name"])))


def _render_category_hubs(directory: Path, rows: list[dict[str, Any]]) -> int:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        category = row["frontmatter"].get("category")
        if category in _CATEGORIES:
            groups.setdefault(category, []).append(row)
    for category, entries in sorted(groups.items()):
        lines = ["---", "type: category-hub", 'category: "{}"'.format(_yaml_text(category)), "date_updated: {}".format(_today()), "---", "", "# Category: {}".format(category), "", "## Repositories ({})".format(len(entries)), ""]
        lines.extend("- [[{}]] — {}".format(_filename_stem(row["full_name"]), _snippet(row["frontmatter"].get("summary"))) for row in entries)
        _write_text(_safe_child(directory, "Category - {}.md".format(category)), "\n".join(lines) + "\n")
    return len(groups)


def _render_topic_hubs(directory: Path, rows: list[dict[str, Any]]) -> int:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        for topic in row["frontmatter"].get("topics") or []:
            if isinstance(topic, str) and _TAG.fullmatch(topic):
                groups.setdefault(topic, []).append(row)
    count = 0
    for topic, entries in sorted(groups.items()):
        if len(entries) < 3:
            continue
        lines = ["---", "type: topic-hub", 'topic: "{}"'.format(topic), "date_updated: {}".format(_today()), "---", "", "# Topic: {}".format(topic), "", "## Repositories ({})".format(len(entries)), ""]
        lines.extend("- [[{}]] — {}".format(_filename_stem(row["full_name"]), _snippet(row["frontmatter"].get("summary"))) for row in entries)
        _write_text(_safe_child(directory, "Topic - {}.md".format(topic)), "\n".join(lines) + "\n")
        count += 1
    return count


def _render_author_hubs(directory: Path, rows: list[dict[str, Any]]) -> int:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        owner = row["frontmatter"].get("owner")
        if isinstance(owner, str) and owner:
            groups.setdefault(owner, []).append(row)
    count = 0
    for owner, entries in sorted(groups.items(), key=lambda item: item[0].lower()):
        if len(entries) < 2:
            continue
        lines = ["---", "type: author-hub", 'author: "{}"'.format(_yaml_text(owner)), 'github_url: "https://github.com/{}"'.format(_yaml_text(owner)), "date_updated: {}".format(_today()), "---", "", "# Author: {}".format(owner), "", "[GitHub Profile](https://github.com/{})".format(owner), "", "## Starred Repositories ({})".format(len(entries)), ""]
        lines.extend("- [[{}]] — {}".format(_filename_stem(row["full_name"]), _snippet(row["frontmatter"].get("summary"))) for row in entries)
        _write_text(_safe_child(directory, "Author - {}.md".format(owner)), "\n".join(lines) + "\n")
        count += 1
    return count


def _render_bases(directory: Path, subfolder: str) -> int:
    folder = "{}/repos".format(subfolder.strip("/"))
    common = 'file.inFolder("{}")'.format(folder)
    bases = {
        "master-index.base": _base([common], {"category": "Category", "language": "Language", "stars": "Stars", "maturity": "Maturity", "status": "Status", "date_starred": "Starred"}, "All Repositories", {"column": "stars", "direction": "DESC"}),
        "by-language.base": _base([common, 'status == "active"'], {"language": "Language", "category": "Category", "stars": "Stars", "license": "License", "maturity": "Maturity"}, "By Language", {"column": "stars", "direction": "DESC"}, "language"),
        "by-category.base": _base([common, 'status == "active"'], {"category": "Category", "language": "Language", "stars": "Stars", "use_case": "Use Case", "maturity": "Maturity"}, "By Category", {"column": "stars", "direction": "DESC"}, "category"),
        "recently-starred.base": _base([common, 'status == "active"'], {"category": "Category", "language": "Language", "stars": "Stars", "maturity": "Maturity", "use_case": "Use Case", "date_starred": "Starred"}, "Recently Starred", {"column": "date_starred", "direction": "DESC"}, limit=50),
        "review-queue.base": _base(['reviewed == false', 'status == "active"', common], {"category": "Category", "language": "Language", "stars": "Stars", "use_case": "Use Case", "maturity": "Maturity", "date_starred": "Starred"}, "Review Queue", {"column": "stars", "direction": "DESC"}),
        "stale-repos.base": _base([common, 'status == "active"', 'last_pushed < now() - "365d"'], {"category": "Category", "language": "Language", "stars": "Stars", "forks": "Forks", "archived": "Archived", "last_pushed": "Last Pushed"}, "Stale Repos (>1 year)", {"column": "last_pushed", "direction": "ASC"}),
        "unstarred.base": _base([common, 'status == "unstarred"'], {"category": "Category", "language": "Language", "stars": "Stars", "owner": "Owner", "date_starred": "Starred", "date_unstarred": "Unstarred"}, "Unstarred Repos", {"column": "date_unstarred", "direction": "DESC"}),
    }
    for name, value in bases.items():
        _write_text(_safe_child(directory, name), yaml.safe_dump(value, sort_keys=False, allow_unicode=True))
    return len(bases)


def _base(filters: list[str], properties: dict[str, str], name: str, sort: dict[str, str], group_by: str | None = None, limit: int | None = None) -> dict[str, Any]:
    view: dict[str, Any] = {"type": "table", "name": name, "sort": [sort]}
    if group_by:
        view["group_by"] = group_by
    if limit is not None:
        view["limit"] = limit
    return {"filters": {"and": filters}, "properties": {key: {"displayName": value} for key, value in properties.items()}, "views": [view]}


def _read_note(path: Path) -> tuple[dict[str, Any], str]:
    if not path.exists() or path.is_symlink():
        return {}, ""
    text = path.read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n?(.*)$", text, flags=re.DOTALL)
    if not match:
        return {}, text
    parsed = yaml.safe_load(match.group(1)) or {}
    return (parsed if isinstance(parsed, dict) else {}), match.group(2)


def _write_note(path: Path, frontmatter: dict[str, Any], body: str) -> None:
    payload = "---\n{}---\n{}".format(yaml.safe_dump(frontmatter, sort_keys=False, allow_unicode=True), body)
    _write_text(path, payload)


def _write_text(path: Path, content: str) -> None:
    _ensure_directory(path.parent)
    if path.exists() and path.is_symlink():
        raise ValueError("refusing to replace symlinked output")
    descriptor, temporary = tempfile.mkstemp(prefix=".starduster-", dir=str(path.parent), text=True)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _ensure_directory(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        raise ValueError("output directory is not a real directory")
    path.mkdir(parents=True, exist_ok=True)


def _safe_child(parent: Path, name: str) -> Path:
    if "/" in name or "\\" in name or name in {"", ".", ".."}:
        raise ValueError("invalid output filename")
    path = parent / name
    if path.parent != parent:
        raise ValueError("output path escaped its parent")
    return path


def _note_path(directory: Path, full_name: str, occupied: Iterable[Path]) -> Path:
    stem = _filename_stem(full_name)
    if not stem:
        raise ValueError("empty repository filename")
    used = {path.name for path in occupied}
    used.update(path.name for path in directory.iterdir())
    candidate = "{}.md".format(stem)
    number = 2
    while candidate in used:
        candidate = "{}-{}.md".format(stem, number)
        number += 1
    return _safe_child(directory, candidate)


def _filename_stem(full_name: str) -> str:
    value = full_name.replace("/", "-").lower()
    value = re.sub(r"[^a-z0-9-]", "", value)
    value = re.sub(r"-+", "-", value).strip("-")
    if ".." in value:
        return ""
    return value[:100].rstrip("-")


def _star_data(star: dict[str, Any]) -> dict[str, Any]:
    repo = star.get("repo")
    if isinstance(repo, dict):
        data = dict(repo)
        data["starred_at"] = star.get("starred_at")
        owner = data.get("owner")
        if isinstance(owner, dict):
            data["owner_login"] = owner.get("login")
        license_value = data.get("license")
        if isinstance(license_value, dict):
            data["license_spdx"] = license_value.get("spdx_id")
        data["is_fork"] = data.get("fork", False)
        parent = data.get("parent")
        if isinstance(parent, dict):
            data["parent_full_name"] = parent.get("full_name")
        return data
    return star


def _full_name(star: dict[str, Any]) -> str:
    value = _star_data(star).get("full_name")
    return value if isinstance(value, str) and _SLUG.fullmatch(value) else ""


def _sort_star(star: dict[str, Any]) -> tuple[str, str]:
    data = _star_data(star)
    return ("".join(chr(255 - ord(char)) for char in str(data.get("starred_at") or "")), _full_name(star))


def _integer(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _optional_text(value: object) -> str | None:
    return _clean_text(value) if isinstance(value, str) and value else None


def _date(value: object) -> str | None:
    return str(value).split("T", 1)[0] if value else None


def _today() -> str:
    return _datetime.date.today().isoformat()


def _user_notes(body: str) -> str:
    match = re.search(r"<!-- USER-NOTES-START -->\n?(.*?)<!-- USER-NOTES-END -->", body, flags=re.DOTALL)
    return match.group(1) if match else ""


def _snippet(value: object) -> str:
    return _clean_text(value)[:80] if isinstance(value, str) else ""


def _yaml_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")
