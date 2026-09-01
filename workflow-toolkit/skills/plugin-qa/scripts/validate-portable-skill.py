#!/usr/bin/env python3
"""Validate a skill directory against Portable Skill Profile v1."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by invoking without the declared dependency
    yaml = None


PROFILE = "portable-skill-v1"
SCHEMA_VERSION = 1
ALLOWED_FRONTMATTER = {"name", "description", "license", "allowed-tools", "metadata"}
NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MARKDOWN_LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))")
PACKAGE_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./-])(?:\./)?"
    r"(?:agents|assets|references|schemas|scripts)/[A-Za-z0-9_.%+@/-]+"
)
HARD_CODED_INSTALL_PATTERN = re.compile(
    r"(?:/Users/[^\s`'\"<>]+|/home/[^\s`'\"<>]+|"
    r"(?:~|\$HOME|\$\{HOME\})/\.(?:claude|agents|codex)/skills/[^\s`'\"<>]+)"
)
ESCAPING_RELATIVE_PATTERN = re.compile(r"(?<!\.)\.\./[A-Za-z0-9_.%+@/-]+")
ABSOLUTE_RUNTIME_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_./:\\~\-])(?:"
    r"/(?!/)[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)+"
    r"|[A-Za-z]:[\\/][A-Za-z0-9][A-Za-z0-9._-]*(?:[\\/][A-Za-z0-9][A-Za-z0-9._-]*)+"
    r"|\\\\[A-Za-z0-9][A-Za-z0-9._-]*(?:\\[A-Za-z0-9][A-Za-z0-9._-]*)+"
    r")"
)
RUNTIME_ASSET_DIRECTORIES = {"agents", "assets", "references", "schemas", "scripts"}
TEXT_RUNTIME_SUFFIXES = {".md", ".py", ".sh", ".json", ".yaml", ".yml", ".toml", ".txt"}
ALLOWED_EXTERNAL_HOST_EXECUTABLES = {
    "/Applications/ChatGPT.app/Contents/Resources/codex",
}


@dataclass(frozen=True)
class Check:
    id: str
    status: str
    message: str


@dataclass(frozen=True)
class LocalReference:
    source: Path
    raw: str
    resolved: Path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a skill directory against Portable Skill Profile v1."
    )
    parser.add_argument("skill_dir", type=Path, help="path to the skill directory")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit JSON")
    return parser.parse_args(argv)


def load_yaml_mapping(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        return None, str(error)
    if not isinstance(loaded, dict):
        return None, "document must be a YAML mapping"
    return loaded, None


def load_skill_frontmatter(path: Path) -> tuple[dict[str, Any] | None, str | None, str]:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return None, str(error), ""
    lines = content.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, "SKILL.md must begin with YAML frontmatter", content
    try:
        closing = next(index for index in range(1, len(lines)) if lines[index].strip() == "---")
    except StopIteration:
        return None, "SKILL.md frontmatter is not terminated with ---", content
    try:
        loaded = yaml.safe_load("\n".join(lines[1:closing]))
    except yaml.YAMLError as error:
        return None, str(error), content
    if not isinstance(loaded, dict):
        return None, "SKILL.md frontmatter must be a YAML mapping", content
    return loaded, None, content


def add_check(checks: list[Check], check_id: str, passed: bool, message: str) -> None:
    checks.append(Check(check_id, "pass" if passed else "fail", message))


def is_external_reference(raw: str) -> bool:
    if raw.startswith("#"):
        return True
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    return bool(parsed.scheme or parsed.netloc)


def normalized_local_target(raw: str) -> str:
    target = unquote(raw.strip())
    return target.split("#", 1)[0].split("?", 1)[0]


def markdown_references(source: Path, content: str, skill_root: Path) -> Iterable[LocalReference]:
    seen: set[tuple[str, str]] = set()
    for match in MARKDOWN_LINK_PATTERN.finditer(content):
        raw = match.group(1) or match.group(2)
        if not raw or is_external_reference(raw):
            continue
        target = normalized_local_target(raw)
        if not target:
            continue
        key = (str(source), target)
        if key not in seen:
            seen.add(key)
            yield LocalReference(source, target, (source.parent / target).resolve(strict=False))

    for match in PACKAGE_PATH_PATTERN.finditer(content):
        raw = match.group(0).rstrip(".,:;)")
        key = (str(source), raw)
        if key not in seen:
            seen.add(key)
            resolved = (skill_root / raw.removeprefix("./")).resolve(strict=False)
            yield LocalReference(source, raw, resolved)


def relative_to_root(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validate(skill_root: Path) -> dict[str, Any]:
    checks: list[Check] = []
    skill_file = skill_root / "SKILL.md"
    frontmatter: dict[str, Any] | None = None
    skill_content = ""

    if skill_file.is_file():
        frontmatter, error, skill_content = load_skill_frontmatter(skill_file)
        add_check(
            checks,
            "frontmatter.parse",
            error is None,
            "SKILL.md frontmatter is valid YAML"
            if error is None
            else f"invalid frontmatter: {error}",
        )
    else:
        add_check(checks, "frontmatter.parse", False, "SKILL.md does not exist")

    keys = set(frontmatter) if frontmatter is not None else set()
    unknown_keys = keys - ALLOWED_FRONTMATTER
    unknown = sorted(str(key) for key in unknown_keys)
    field_type_errors: list[str] = []
    if frontmatter is not None:
        license_value = frontmatter.get("license")
        if "license" in frontmatter and (
            not isinstance(license_value, str) or not license_value.strip()
        ):
            field_type_errors.append("license must be a non-empty string")
        allowed_tools = frontmatter.get("allowed-tools")
        allowed_tools_valid = (
            isinstance(allowed_tools, str) and bool(allowed_tools.strip())
        ) or (
            isinstance(allowed_tools, list)
            and bool(allowed_tools)
            and all(isinstance(tool, str) and bool(tool.strip()) for tool in allowed_tools)
        )
        if "allowed-tools" in frontmatter and not allowed_tools_valid:
            field_type_errors.append(
                "allowed-tools must be a non-empty string or list of non-empty strings"
            )
        if "metadata" in frontmatter and not isinstance(frontmatter.get("metadata"), dict):
            field_type_errors.append("metadata must be a mapping")
    shared_fields_ok = frontmatter is not None and not unknown and not field_type_errors
    shared_field_problems = [
        *(f"unsupported field {field}" for field in unknown),
        *field_type_errors,
    ]
    add_check(
        checks,
        "frontmatter.shared-fields",
        shared_fields_ok,
        "frontmatter uses only shared fields"
        if shared_fields_ok
        else (
            "invalid shared fields: "
            f"{', '.join(shared_field_problems) or 'frontmatter unavailable'}"
        ),
    )
    add_check(
        checks,
        "frontmatter.no-triggers",
        frontmatter is not None and "triggers" not in keys,
        "triggers is absent"
        if frontmatter is not None and "triggers" not in keys
        else "triggers is forbidden by Portable Skill Profile v1",
    )

    name = frontmatter.get("name") if frontmatter is not None else None
    valid_name = (
        isinstance(name, str)
        and len(name) <= 64
        and bool(NAME_PATTERN.fullmatch(name))
    )
    add_check(
        checks,
        "frontmatter.name",
        valid_name,
        f"name is valid: {name}"
        if valid_name
        else "name must be at most 64 characters in lower-case hyphenated form",
    )
    description = frontmatter.get("description") if frontmatter is not None else None
    valid_description = isinstance(description, str) and bool(description.strip())
    add_check(
        checks,
        "frontmatter.description",
        valid_description,
        "description is non-empty"
        if valid_description
        else "description must be a non-empty string",
    )
    directory_matches = valid_name and name == skill_root.name
    add_check(
        checks,
        "frontmatter.directory-name",
        directory_matches,
        "name matches the skill directory"
        if directory_matches
        else f"name {name!r} does not match directory {skill_root.name!r}",
    )

    openai_file = skill_root / "agents" / "openai.yaml"
    openai_data: dict[str, Any] | None = None
    openai_error: str | None = None
    if openai_file.is_file():
        openai_data, openai_error = load_yaml_mapping(openai_file)
    else:
        openai_error = "agents/openai.yaml does not exist"

    interface = openai_data.get("interface") if openai_data is not None else None
    required_interface = ("display_name", "short_description", "default_prompt")
    missing_interface = [
        field
        for field in required_interface
        if not isinstance(interface, dict)
        or not isinstance(interface.get(field), str)
        or not interface[field].strip()
    ]
    expected_prompt_token = f"${name}" if valid_name else None
    prompt = interface.get("default_prompt") if isinstance(interface, dict) else None
    prompt_names_skill = bool(
        valid_name
        and isinstance(prompt, str)
        and re.search(rf"\${re.escape(name)}(?![a-z0-9-])", prompt)
    )
    stale_prompt = bool(
        expected_prompt_token and isinstance(prompt, str) and not prompt_names_skill
    )
    short_description = (
        interface.get("short_description") if isinstance(interface, dict) else None
    )
    short_description_length_ok = (
        isinstance(short_description, str) and 25 <= len(short_description) <= 64
    )
    metadata_ok = (
        openai_error is None
        and not missing_interface
        and not stale_prompt
        and short_description_length_ok
    )
    if openai_error is not None:
        metadata_message = f"invalid OpenAI metadata: {openai_error}"
    elif missing_interface:
        metadata_message = f"missing OpenAI interface fields: {', '.join(missing_interface)}"
    elif stale_prompt:
        metadata_message = f"default_prompt must mention {expected_prompt_token}"
    elif not short_description_length_ok:
        metadata_message = "short_description must contain 25 to 64 characters"
    else:
        metadata_message = "OpenAI interface metadata is complete and names the skill"
    add_check(checks, "openai.metadata", metadata_ok, metadata_message)

    runtime_paths = {
        "runtime.claude": skill_root / "references" / "runtime-claude.md",
        "runtime.codex": skill_root / "references" / "runtime-codex.md",
    }
    for check_id, path in runtime_paths.items():
        relative = path.relative_to(skill_root).as_posix()
        exists = path.is_file()
        linked = relative in skill_content
        add_check(
            checks,
            check_id,
            exists and linked,
            f"{relative} exists and is referenced by SKILL.md"
            if exists and linked
            else f"{relative} must exist and be referenced by SKILL.md",
        )

    markdown_files = [skill_file]
    references_dir = skill_root / "references"
    if references_dir.is_dir():
        markdown_files.extend(sorted(references_dir.rglob("*.md")))
    local_references: list[LocalReference] = []
    hard_coded_locations: list[str] = []
    for source in markdown_files:
        if not source.is_file():
            continue
        try:
            content = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        local_references.extend(markdown_references(source, content, skill_root))
        for match in HARD_CODED_INSTALL_PATTERN.finditer(content):
            hard_coded_locations.append(f"{source.relative_to(skill_root)}:{match.group(0)}")

    escaping_runtime_paths: list[str] = []
    absolute_runtime_paths: list[str] = []
    escaping_runtime_symlinks: list[str] = []
    for source in sorted(skill_root.rglob("*")):
        relative_source = source.relative_to(skill_root)
        if source.is_symlink() and relative_source.parts and relative_source.parts[0] in RUNTIME_ASSET_DIRECTORIES:
            resolved_source = source.resolve(strict=False)
            if not relative_to_root(resolved_source, skill_root):
                escaping_runtime_symlinks.append(f"{relative_source.as_posix()} -> {resolved_source}")
        if not source.is_file() or source.suffix.lower() not in TEXT_RUNTIME_SUFFIXES:
            continue
        try:
            content = source.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        if source not in markdown_files:
            for match in HARD_CODED_INSTALL_PATTERN.finditer(content):
                hard_coded_locations.append(f"{source.relative_to(skill_root)}:{match.group(0)}")
        for match in ESCAPING_RELATIVE_PATTERN.finditer(content):
            escaping_runtime_paths.append(f"{source.relative_to(skill_root)}:{match.group(0)}")
        path_content = (
            content.partition("\n")[2]
            if content.startswith("#!/usr/bin/env")
            else content
        )
        for match in ABSOLUTE_RUNTIME_PATH_PATTERN.finditer(path_content):
            if match.group(0) not in ALLOWED_EXTERNAL_HOST_EXECUTABLES:
                absolute_runtime_paths.append(f"{source.relative_to(skill_root)}:{match.group(0)}")

    if isinstance(interface, dict):
        for field in ("icon_small", "icon_large"):
            raw = interface.get(field)
            if isinstance(raw, str) and raw.strip():
                local_references.append(
                    LocalReference(
                        openai_file,
                        raw,
                        (skill_root / raw.removeprefix("./")).resolve(strict=False),
                    )
                )

    absolute_refs = sorted(
        f"{reference.source.relative_to(skill_root)}:{reference.raw}"
        for reference in local_references
        if Path(reference.raw).is_absolute() or reference.raw.startswith("~")
    )
    add_check(
        checks,
        "references.package-relative",
        not absolute_refs,
        "all local references are package-relative"
        if not absolute_refs
        else f"non-relative local references: {', '.join(absolute_refs)}",
    )

    missing_refs = sorted(
        f"{reference.source.relative_to(skill_root)}:{reference.raw}"
        for reference in local_references
        if not reference.resolved.exists()
    )
    add_check(
        checks,
        "references.exist",
        not missing_refs,
        "all detected local references exist"
        if not missing_refs
        else f"missing local references: {', '.join(missing_refs)}",
    )

    escaping_refs = sorted(
        f"{reference.source.relative_to(skill_root)}:{reference.raw}"
        for reference in local_references
        if not relative_to_root(reference.resolved, skill_root)
    )
    dependency_problems = (
        escaping_refs
        + sorted(set(hard_coded_locations))
        + sorted(set(escaping_runtime_paths))
        + sorted(set(absolute_runtime_paths))
        + sorted(set(escaping_runtime_symlinks))
    )
    add_check(
        checks,
        "dependencies.package-boundary",
        not dependency_problems,
        "no detected runtime dependency escapes the skill package"
        if not dependency_problems
        else f"dependencies outside the package: {', '.join(dependency_problems)}",
    )

    status = "pass" if all(check.status == "pass" for check in checks) else "fail"
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE,
        "skill_path": str(skill_root),
        "status": status,
        "checks": [asdict(check) for check in checks],
    }


def print_text(report: dict[str, Any]) -> None:
    print(f"Portable Skill Profile v1: {report['skill_path']}")
    for check in report["checks"]:
        print(f"{check['status'].upper():4}  {check['id']}: {check['message']}")
    print(f"Overall: {report['status'].upper()}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if yaml is None:
        print("error: PyYAML is required; run with `uv run --with pyyaml`", file=sys.stderr)
        return 2

    skill_root = args.skill_dir.expanduser()
    try:
        skill_root = skill_root.resolve(strict=True)
    except OSError as error:
        print(f"error: cannot resolve skill directory: {error}", file=sys.stderr)
        return 2
    if not skill_root.is_dir():
        print(f"error: skill path is not a directory: {skill_root}", file=sys.stderr)
        return 2

    try:
        report = validate(skill_root)
    except Exception as error:  # unexpected validator faults are invocation/internal errors
        print(f"error: portable skill validation failed unexpectedly: {error}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(report, indent=2, sort_keys=False))
    else:
        print_text(report)
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
