#!/usr/bin/env python3
"""Noninteractive acceptance runner for portable research-toolkit skills."""

from __future__ import annotations

import argparse
import concurrent.futures
import io
import json
import os
import re
import selectors
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
KCAP_DIR = ROOT / "research-toolkit" / "skills" / "kcap"
KCAP_CLI = KCAP_DIR / "scripts" / "kcap.py"
STARDUSTER_DIR = ROOT / "research-toolkit" / "skills" / "starduster"
STARDUSTER_CLI = STARDUSTER_DIR / "scripts" / "starduster.py"
PORTABLE_VALIDATOR = (
    ROOT
    / "workflow-toolkit"
    / "skills"
    / "plugin-qa"
    / "scripts"
    / "validate-portable-skill.py"
)
YOUTUBE_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
BUNDLED_CODEX_BINARY = Path("/Applications/ChatGPT.app/Contents/Resources/codex")
CODEX_BINARY_OVERRIDE_ENV = "KCAP_CODEX_BIN"
HOST_RUNTIME_ENV = (
    "CLAUDECODE",
    "CLAUDE_CODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_SESSION_ID",
    "CODEX_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SANDBOX",
    "CODEX_CI",
    "RESEARCH_TOOLKIT_RUNTIME",
)


@dataclass
class Result:
    test_id: str
    status: str
    duration_ms: int
    message: str
    details: dict[str, Any]


class SkipCase(Exception):
    """A requested check cannot run safely in the current environment."""


class Harness:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.results: list[Result] = []
        self._result_lock = threading.Lock()

    def case(self, test_id: str, action: Callable[[], dict[str, Any] | None]) -> None:
        started = time.monotonic()
        status = "PASS"
        message = "passed"
        details: dict[str, Any] = {}
        try:
            details = action() or {}
        except SkipCase as error:
            status = "SKIP"
            message = str(error)
        except Exception as error:  # The report must retain every failed acceptance case.
            status = "FAIL"
            message = str(error)
        with self._result_lock:
            self.results.append(
                Result(
                    test_id=test_id,
                    status=status,
                    duration_ms=round((time.monotonic() - started) * 1000),
                    message=message,
                    details=details,
                )
            )


def run(
    command: list[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
    unset_env: tuple[str, ...] = (),
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    for name in unset_env:
        merged_env.pop(name, None)
    if env:
        merged_env.update(env)
    return subprocess.run(
        command,
        cwd=cwd,
        env=merged_env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def abbreviated(value: str, limit: int = 2000) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[:limit] + "...[truncated]"


def parse_json(value: str, source: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise AssertionError(f"{source} was not one JSON object: {error}") from error
    if not isinstance(parsed, dict):
        raise AssertionError(f"{source} must be a JSON object")
    return parsed


def parse_jsonl(value: str, source: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(value.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise AssertionError(f"{source} line {line_number} was invalid JSON") from error
        if not isinstance(event, dict):
            raise AssertionError(f"{source} line {line_number} was not a JSON object")
        events.append(event)
    if not events:
        raise AssertionError(f"{source} contained no events")
    return events


def command_values(value: Any) -> list[str]:
    commands: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "command" and isinstance(nested, str):
                commands.append(nested)
            else:
                commands.extend(command_values(nested))
    elif isinstance(value, list):
        for nested in value:
            commands.extend(command_values(nested))
    return commands


def verify_host_skill_provenance(events: list[dict[str, Any]], skill_dir: Path) -> dict[str, Any]:
    commands = [command for event in events for command in command_values(event)]
    kcap_commands = [command for command in commands if "scripts/kcap.py" in command]
    expected_roots = {str(skill_dir), str(skill_dir.absolute()), str(skill_dir.resolve())}
    if not kcap_commands or not any(
        expected_root in command for command in kcap_commands for expected_root in expected_roots
    ):
        raise AssertionError("host events do not prove execution from the temporary kcap copy")
    for command in kcap_commands:
        if "/skills/kcap/scripts/kcap.py" in command and not any(
            expected_root in command for expected_root in expected_roots
        ):
            raise AssertionError("host events show execution from a different kcap installation")
    raw_reader = re.compile(
        r"(?:^|[;&|]\s*|\s)(?:cat|head|tail|sed|awk|grep|rg|less|more)\s+"
        r"[^;&|]*(?:content\.txt|metadata\.json|synthesis\.json)"
    )
    if any(raw_reader.search(command) for command in commands):
        raise AssertionError("host events show a raw extraction or synthesis file read")
    return {"event_count": len(events), "kcap_command_count": len(kcap_commands)}


def canonical_live_path(path: str | Path) -> Path:
    """Resolve a live-test path, including the macOS /var compatibility spelling."""
    text = str(path)
    if text == "/var" or text.startswith("/var/"):
        text = "/private" + text
    return Path(text).resolve()


def preferred_codex_binary(
    override: str | Path | None = None,
    *,
    bundled_path: Path = BUNDLED_CODEX_BINARY,
    path_lookup: Callable[[str], str | None] = shutil.which,
    is_executable: Callable[[Path], bool] | None = None,
) -> Path | None:
    """Select an explicit Codex binary, then the Desktop runtime, then PATH."""
    executable = is_executable or (lambda path: path.is_file() and os.access(path, os.X_OK))
    if override is not None:
        selected = Path(override)
        if not executable(selected):
            raise AssertionError(f"explicit Codex binary is not executable: {selected}")
        return selected
    if executable(bundled_path):
        return bundled_path
    fallback = path_lookup("codex")
    return Path(fallback) if fallback is not None else None


def tree_byte_manifest(root: Path) -> dict[Path, bytes]:
    """Return the relative source-file byte manifest for a copied tree."""
    if not root.is_dir():
        raise AssertionError(f"tree root is not a directory: {root}")
    return {
        path.relative_to(root): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and path.name != ".DS_Store"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


def verify_tree_byte_manifest(
    expected: Mapping[Path, bytes],
    actual_root: Path,
    *,
    allow_extra: bool = False,
    label: str,
) -> None:
    """Require source file inclusion and byte identity in a copied tree."""
    actual = tree_byte_manifest(actual_root)
    expected_paths = set(expected)
    actual_paths = set(actual)
    missing = sorted(str(path) for path in expected_paths - actual_paths)
    changed = sorted(
        str(path) for path in expected_paths & actual_paths if expected[path] != actual[path]
    )
    extras = sorted(str(path) for path in actual_paths - expected_paths)
    problems: list[str] = []
    if missing:
        problems.append("missing " + ", ".join(missing))
    if changed:
        problems.append("changed bytes " + ", ".join(changed))
    if extras and not allow_extra:
        problems.append("extra " + ", ".join(extras))
    if problems:
        raise AssertionError(f"{label} manifest mismatch: {'; '.join(problems)}")


def validate_claude_isolation_command(command: Sequence[str]) -> None:
    """Require the Claude child process to have the full no-tool boundary."""
    values = list(command)
    required_flags = ("--safe-mode", "--no-session-persistence", "--no-chrome", "--disable-slash-commands")
    missing = [flag for flag in required_flags if values.count(flag) != 1]
    if missing:
        raise AssertionError("Claude isolation command lacks required flags: " + ", ".join(missing))

    def require_option(flag: str, expected: str) -> None:
        indexes = [index for index, value in enumerate(values) if value == flag]
        if len(indexes) != 1 or indexes[0] + 1 >= len(values) or values[indexes[0] + 1] != expected:
            raise AssertionError(f"Claude isolation command requires {flag} {expected!r}")

    require_option("--mcp-config", '{"mcpServers":{}}')
    if values.count("--strict-mcp-config") != 1:
        raise AssertionError("Claude isolation command requires one --strict-mcp-config flag")
    strict_index = values.index("--strict-mcp-config")
    if strict_index + 1 < len(values) and values[strict_index + 1] == '{"mcpServers":{}}':
        raise AssertionError("Claude isolation command passed MCP JSON as a positional prompt")
    require_option("--permission-mode", "dontAsk")
    require_option("--tools", "")
    forbidden_session_flags = {"--resume", "--continue", "--session-id"}
    present_session_flags = sorted(forbidden_session_flags & set(values))
    if present_session_flags:
        raise AssertionError("Claude isolation command permits a session: " + ", ".join(present_session_flags))


def live_command_events(events: Sequence[Mapping[str, Any]]) -> list[str]:
    """Return commands from command-execution event shapes, never host prose."""
    commands: list[str] = []
    lifecycle_commands: dict[str, dict[str, str]] = {}
    for event in events:
        if event.get("type") == "command_execution":
            command = event.get("command")
            if isinstance(command, str):
                commands.append(command)
            continue
        item = event.get("item")
        if (
            event.get("type") in {"item.started", "item.completed"}
            and isinstance(item, Mapping)
            and item.get("type") == "command_execution"
            and isinstance(item.get("command"), str)
        ):
            item_id = item.get("id")
            if not isinstance(item_id, str) or not item_id:
                raise AssertionError("live provenance command lifecycle lacks a stable item id")
            state = str(event["type"]).split(".", 1)[1]
            states = lifecycle_commands.setdefault(item_id, {})
            if state in states:
                raise AssertionError("live provenance command lifecycle has duplicate item state")
            states[state] = item["command"]
            continue
        message = event.get("message")
        if event.get("type") != "assistant" or not isinstance(message, Mapping):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, Mapping) or part.get("type") != "tool_use" or part.get("name") != "Bash":
                continue
            tool_input = part.get("input")
            if isinstance(tool_input, Mapping) and isinstance(tool_input.get("command"), str):
                commands.append(tool_input["command"])
    for item_id, states in lifecycle_commands.items():
        if set(states) != {"started", "completed"}:
            raise AssertionError(f"live provenance command lifecycle is incomplete for {item_id}")
        if states["started"] != states["completed"]:
            raise AssertionError(f"live provenance command lifecycle is ambiguous for {item_id}")
        commands.append(states["started"])
    return commands


def starduster_claude_bash_evidence(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Require one exact Claude Bash call with enough time for five synthesis batches."""
    calls: list[dict[str, Any]] = []
    for event in events:
        message = event.get("message")
        if event.get("type") != "assistant" or not isinstance(message, Mapping):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, Mapping) or part.get("type") != "tool_use" or part.get("name") != "Bash":
                continue
            tool_input = part.get("input")
            if not isinstance(tool_input, Mapping) or not isinstance(tool_input.get("command"), str):
                raise AssertionError("Claude Starduster Bash event lacks a command")
            timeout = tool_input.get("timeout")
            if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 600000:
                raise AssertionError("Claude Starduster Bash event lacks the required 600000 ms timeout")
            calls.append({"command": tool_input["command"], "timeout_ms": timeout})
    if len(calls) != 1:
        raise AssertionError("Claude live Starduster run did not execute exactly one Bash command")
    return calls[0]


def safe_live_event_shape_summary(events: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Count only event/item/tool type names; never retain payload text."""
    summary: dict[str, int] = {}
    for event in events:
        event_type = event.get("type")
        if isinstance(event_type, str):
            key = "event:{}".format(event_type)
            summary[key] = summary.get(key, 0) + 1
        item = event.get("item")
        if isinstance(item, Mapping) and isinstance(item.get("type"), str):
            key = "item:{}".format(item["type"])
            summary[key] = summary.get(key, 0) + 1
        message = event.get("message")
        content = message.get("content") if isinstance(message, Mapping) else None
        if isinstance(content, list):
            for part in content:
                if isinstance(part, Mapping) and isinstance(part.get("name"), str):
                    key = "tool:{}".format(part["name"])
                    summary[key] = summary.get(key, 0) + 1
    return dict(sorted(summary.items()))


def parse_live_capture_command(
    command: str,
    skill_dir: Path,
    source_url: str,
    *,
    expected_project_dir: Path,
) -> None:
    """Fail closed unless *command* is the copied public capture controller."""
    if re.search(r"(?:`|\$\(|;|&&|\|\||(?<!\|)\|(?!\|)|[<>])", command):
        raise AssertionError("live provenance rejected a shell compound or raw-reader command")
    try:
        arguments = shlex.split(command, posix=True)
    except ValueError as error:
        raise AssertionError("live provenance could not parse command safely") from error
    script_indexes = [
        index for index, value in enumerate(arguments)
        if value.endswith("/scripts/kcap.py") or value == "scripts/kcap.py"
    ]
    if len(script_indexes) != 1:
        raise AssertionError("live provenance requires one explicit kcap capture command")
    script_index = script_indexes[0]
    if script_index != 1 or arguments[0] != "python3":
        raise AssertionError("live provenance requires direct Python execution of kcap capture")
    expected_script = canonical_live_path(skill_dir / "scripts" / "kcap.py")
    actual_script = canonical_live_path(arguments[script_index])
    if actual_script != expected_script:
        raise AssertionError("live provenance found a different kcap install, not the temporary copy")
    expected_project = canonical_live_path(expected_project_dir)
    if len(arguments) != 6:
        raise AssertionError("live provenance requires the exact public kcap.py capture command")
    if arguments[2:5] != ["capture", source_url, "--project-dir"]:
        raise AssertionError("live provenance capture command differs from the requested command")
    if canonical_live_path(arguments[5]) != expected_project:
        raise AssertionError("live provenance capture command used the wrong temporary project directory")


def resolve_live_catalog_path(value: str | Path, aliases: Mapping[str, Path]) -> Path:
    """Resolve an emitted catalog path without accepting an unrecognized alias."""
    text = str(value)
    match = re.fullmatch(r"(r\d+)/(.*)", text)
    if match:
        alias, relative = match.groups()
        if alias not in aliases:
            raise AssertionError("live provenance catalog uses an unknown alias")
        return canonical_live_path(canonical_live_path(aliases[alias]) / relative)
    return canonical_live_path(text)


def verify_live_host_acceptance(
    events: Sequence[Mapping[str, Any]],
    *,
    skill_dir: Path,
    output_root: Path,
    source_url: str,
    catalog_aliases: Mapping[str, Path],
    catalog_paths: Sequence[str | Path],
    source_auth_before: Mapping[str, Any],
    source_auth_after: Mapping[str, Any],
    expected_project_dir: Path,
    final_host_message: object = None,
) -> dict[str, Any]:
    """Verify a live host from execution evidence and the resulting note only.

    The host's final prose is intentionally not inspected: it is untrusted and
    must not be able to choose either the note or the reported source identity.
    """
    del final_host_message
    commands = live_command_events(events)
    if len(commands) != 1:
        raise AssertionError(
            "live provenance requires exactly one command-execution capture operation; observed {}; event shapes {}".format(
                len(commands), safe_live_event_shape_summary(events)
            )
        )
    expected_skill = canonical_live_path(skill_dir)
    parse_live_capture_command(
        commands[0],
        expected_skill,
        source_url,
        expected_project_dir=expected_project_dir,
    )

    expected_catalog = canonical_live_path(expected_skill / "SKILL.md")
    resolved_catalog_paths = [resolve_live_catalog_path(path, catalog_aliases) for path in catalog_paths]
    for catalog_path in resolved_catalog_paths:
        if catalog_path != expected_catalog:
            raise AssertionError("live provenance catalog points to a different temporary skill source")

    if dict(source_auth_before) != dict(source_auth_after):
        raise AssertionError("live provenance source authentication metadata changed")

    root = canonical_live_path(output_root)
    note_files = sorted(path.resolve() for path in root.rglob("*.md"))
    if len(note_files) != 1:
        raise AssertionError("live provenance could not derive one output file from the filesystem")
    details = verify_live_output(note_files[0], root, source_url=source_url)
    details.update(
        {
            "capture_command_count": 1,
            "catalog_source_verified": bool(resolved_catalog_paths),
            "catalog_source_count": len(resolved_catalog_paths),
            "source_auth_metadata_unchanged": True,
        }
    )
    return details


def _report_has_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {"prompt", "token", "api_key", "secret", "raw_output", "raw_event"}:
                return True
            if _report_has_sensitive_key(nested):
                return True
    elif isinstance(value, list):
        return any(_report_has_sensitive_key(nested) for nested in value)
    return False


def verify_codex_app_server_provenance_report(
    report: Mapping[str, Any],
    *,
    expected_binary: Path,
    expected_capture_command: str,
    expected_catalog_path: Path,
    expected_output_root: Path,
    expected_auth_mode: str = "oauth",
    expected_synthesis_batches: int | None = None,
) -> dict[str, Any]:
    """Validate the small, redacted evidence record from the signed App Server proof."""
    if _report_has_sensitive_key(report):
        raise AssertionError("App Server provenance report contains sensitive prompt or credential fields")
    if report.get("runtime") != "codex-app-server" or report.get("transport") != "stdio":
        raise AssertionError("App Server provenance requires the ephemeral stdio runtime")
    binary = report.get("binary")
    if not isinstance(binary, Mapping):
        raise AssertionError("App Server provenance lacks binary evidence")
    if canonical_live_path(str(binary.get("path", ""))) != canonical_live_path(expected_binary):
        raise AssertionError("App Server provenance used a different bundled binary")
    version = binary.get("version")
    if not isinstance(version, str) or not version.strip() or binary.get("source") != "bundled-desktop":
        raise AssertionError("App Server provenance lacks the signed bundled-build evidence")
    if not isinstance(report.get("session"), Mapping) or report["session"].get("ephemeral") is not True:
        raise AssertionError("App Server provenance requires an ephemeral thread")
    code_mode = report.get("code_mode")
    if not isinstance(code_mode, Mapping):
        raise AssertionError("App Server provenance lacks Code Mode evidence")
    synthesis_batches = report.get("synthesis_batches", 1)
    if isinstance(synthesis_batches, bool) or not isinstance(synthesis_batches, int) or synthesis_batches < 0:
        raise AssertionError("App Server provenance has an invalid synthesis batch count")
    if expected_synthesis_batches is not None and synthesis_batches != expected_synthesis_batches:
        raise AssertionError("App Server provenance has an unexpected synthesis batch count")
    if synthesis_batches == 0:
        if code_mode.get("allowed_operations") != []:
            raise AssertionError("zero-work App Server provenance must not allow Code Mode operations")
        if code_mode.get("lifecycle") != ["thread.start"]:
            raise AssertionError("zero-work App Server provenance must contain only thread.start")
    else:
        if code_mode.get("allowed_operations") != ["exec", "wait"]:
            raise AssertionError("App Server provenance permits operations beyond Code Mode exec and wait")
        if code_mode.get("lifecycle") != ["thread.start", "turn.start", "turn.complete"]:
            raise AssertionError("App Server provenance has an incomplete Code Mode lifecycle")
    environment = report.get("environment")
    if not isinstance(environment, Mapping) or environment.get("mode") != "empty" or environment.get("allowed") != []:
        raise AssertionError("App Server provenance requires an empty model environment")
    sandbox = report.get("sandbox")
    filesystem = sandbox.get("filesystem") if isinstance(sandbox, Mapping) else None
    if not isinstance(filesystem, Mapping) or sandbox.get("network") != "deny":
        raise AssertionError("App Server provenance requires a network-deny sandbox")
    if any(filesystem.get(root) != "deny" for root in ("root", "tmp", "slash_tmp")):
        raise AssertionError("App Server provenance requires root and temporary filesystem denies")
    auth = report.get("auth")
    expected_auth: Mapping[str, Any]
    if expected_auth_mode == "oauth":
        expected_auth = {"mode": "oauth", "source_unchanged": True, "private_copy_removed": True}
    elif expected_auth_mode == "api_key":
        expected_auth = {"mode": "api_key", "ephemeral_login": True, "persistent_credentials": False}
    else:
        raise AssertionError("App Server provenance has an unsupported authentication mode")
    if not isinstance(auth, Mapping) or auth != expected_auth:
        if expected_auth_mode == "api_key":
            raise AssertionError("App Server provenance requires API-key ephemeral-login evidence")
        raise AssertionError("App Server provenance requires OAuth source and cleanup evidence")
    if report.get("prohibited_event_count") != 0:
        raise AssertionError("App Server provenance recorded prohibited activity")
    provenance = report.get("provenance")
    if not isinstance(provenance, Mapping):
        raise AssertionError("App Server provenance lacks capture evidence")
    if provenance.get("capture_command") != expected_capture_command or provenance.get("public_host_command_count") != 1:
        raise AssertionError("App Server provenance requires one exact capture command")
    if canonical_live_path(str(provenance.get("catalog_source", ""))) != canonical_live_path(expected_catalog_path):
        raise AssertionError("App Server provenance used a different temporary catalog source")
    if canonical_live_path(str(provenance.get("output_root", ""))) != canonical_live_path(expected_output_root):
        raise AssertionError("App Server provenance used a different temporary output root")
    return {
        "runtime": "codex-app-server",
        "transport": "stdio",
        "binary": str(canonical_live_path(expected_binary)),
        "version": version,
        "capture_command": expected_capture_command,
        "prohibited_event_count": 0,
        "synthesis_batches": synthesis_batches,
    }


def requested_codex_live_auth_legs(environment: Mapping[str, str] | None = None) -> list[str]:
    """Always request OAuth; request the billed API-key leg only by explicit opt-in."""
    values = os.environ if environment is None else environment
    return ["oauth", "api-key"] if values.get("RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY") else ["oauth"]


def requested_codex_live_result(auth_leg: str, availability: str) -> dict[str, Any]:
    """Classify requested live evidence without retaining CLI or authentication diagnostics."""
    if auth_leg not in {"oauth", "api-key"}:
        raise AssertionError("unknown requested Codex authentication leg")
    if auth_leg == "api-key" and availability == "not_requested":
        return {"status": "not_requested", "exit_code": 0, "auth_leg": auth_leg}
    if availability == "available":
        return {"status": "PASS", "exit_code": 0, "auth_leg": auth_leg}
    return {"status": "INCOMPLETE", "exit_code": 1, "auth_leg": auth_leg}


def validated_live_github_token(result: subprocess.CompletedProcess[str]) -> str:
    """Return one bounded token without retaining authentication diagnostics."""
    if result.returncode != 0:
        raise SkipCase("authenticated GitHub CLI access is unavailable")
    token = result.stdout.strip()
    if not token or len(token) > 4096 or any(character.isspace() for character in token):
        raise AssertionError("GitHub CLI returned invalid authentication material")
    return token


def live_github_token() -> str:
    binary = shutil.which("gh")
    if binary is None:
        raise SkipCase("GitHub CLI is unavailable")
    result = run(
        [binary, "auth", "token"],
        unset_env=("GH_TOKEN", "GITHUB_TOKEN"),
        timeout=30,
    )
    return validated_live_github_token(result)


def codex_prompt_input_catalog_text(value: str) -> str:
    """Extract the developer catalog text from current Desktop prompt-input JSON."""
    try:
        envelope = json.loads(value)
    except json.JSONDecodeError:
        return value
    if not isinstance(envelope, list):
        raise AssertionError("Codex prompt-input JSON must be a message array")
    catalog_texts: list[str] = []
    for message in envelope:
        if not isinstance(message, Mapping) or message.get("role") != "developer":
            continue
        content = message.get("content")
        if not isinstance(content, list):
            raise AssertionError("Codex developer prompt-input content is not an array")
        for part in content:
            if not isinstance(part, Mapping) or part.get("type") != "input_text":
                continue
            text = part.get("text")
            if not isinstance(text, str):
                raise AssertionError("Codex developer input_text is not text")
            if "<skills_instructions>" in text:
                catalog_texts.append(text)
    if len(catalog_texts) != 1:
        raise AssertionError("Codex prompt-input JSON must have exactly one skills_instructions catalog block")
    return catalog_texts[0]


def codex_catalog_skill_paths(value: str, skill_name: str) -> list[Path]:
    value = codex_prompt_input_catalog_text(value)
    roots = dict(re.findall(r"`(r\d+)` = `([^`]+)`", value))
    paths: list[Path] = []
    prefix = f"- {skill_name}:"
    pattern = re.compile(
        rf"- {re.escape(skill_name)}: (?:(?:.+) )?\(file: (?P<source>[^()]+)\)"
    )
    for line in value.splitlines():
        if not line.startswith(prefix):
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise AssertionError(f"Codex catalog has an ambiguous {skill_name} entry: {line!r}")
        source = match.group("source")
        alias_match = re.fullmatch(rf"(r\d+)/{re.escape(skill_name)}/SKILL\.md", source)
        if alias_match:
            alias = alias_match.group(1)
            if alias not in roots:
                raise AssertionError(f"Codex catalog uses an unknown source alias: {alias}")
            paths.append(Path(roots[alias]) / skill_name / "SKILL.md")
            continue
        direct = Path(source)
        if not direct.is_absolute() or direct.name != "SKILL.md" or direct.parent.name != skill_name:
            raise AssertionError(f"Codex catalog has an ambiguous direct {skill_name} source: {source!r}")
        paths.append(direct)
    return paths


def tool_versions() -> dict[str, dict[str, Any]]:
    versions: dict[str, dict[str, Any]] = {}
    for name, arguments in {
        "python": [sys.executable, "--version"],
        "uv": ["uv", "--version"],
        "claude": ["claude", "--version"],
        "codex": ["codex", "--version"],
        "hplumb": ["hplumb", "--version"],
        "yt-dlp": ["yt-dlp", "--version"],
    }.items():
        executable = (
            preferred_codex_binary(os.environ.get(CODEX_BINARY_OVERRIDE_ENV))
            if name == "codex"
            else shutil.which(arguments[0])
        )
        if executable is None:
            versions[name] = {"status": "missing", "version": None, "path": None}
            continue
        process = run([str(executable), *arguments[1:]], timeout=10)
        version = abbreviated(process.stdout or process.stderr, 300).splitlines()
        versions[name] = {
            "status": "available" if process.returncode == 0 else "error",
            "version": version[0] if version else None,
            "path": str(executable),
        }
    return versions


def validator_case(
    fixture_name: str,
    expected_returncode: int,
    expected_failed_check: str | None = None,
) -> Callable[[], dict[str, Any]]:
    def action() -> dict[str, Any]:
        if not PORTABLE_VALIDATOR.is_file():
            raise AssertionError(f"portable validator is missing: {PORTABLE_VALIDATOR}")
        fixture = FIXTURES / "portable-skills" / fixture_name
        process = run([sys.executable, str(PORTABLE_VALIDATOR), str(fixture), "--json"])
        if process.returncode != expected_returncode:
            raise AssertionError(
                f"validator exited {process.returncode}, expected {expected_returncode}: "
                f"{abbreviated(process.stderr or process.stdout)}"
            )
        payload = parse_json(process.stdout, "validator stdout")
        required = {"schema_version", "profile", "skill_path", "status", "checks"}
        missing = sorted(required - payload.keys())
        if missing:
            raise AssertionError(f"validator report lacks fields: {', '.join(missing)}")
        if not isinstance(payload["checks"], list) or not payload["checks"]:
            raise AssertionError("validator report must contain ordered checks")
        expected_status = "pass" if expected_returncode == 0 else "fail"
        if str(payload["status"]).lower() != expected_status:
            raise AssertionError(
                f"validator status was {payload['status']!r}, expected {expected_status!r}"
            )
        check_statuses = {
            check.get("id"): check.get("status")
            for check in payload["checks"]
            if isinstance(check, dict)
        }
        if expected_failed_check and check_statuses.get(expected_failed_check) != "fail":
            raise AssertionError(
                f"fixture did not fail expected check {expected_failed_check!r}: {check_statuses}"
            )
        return {
            "fixture": str(fixture.relative_to(ROOT)),
            "validator_status": payload["status"],
            "check_ids": [check.get("id") for check in payload["checks"]],
        }

    return action


def unittest_acceptance_case(module: str) -> Callable[[], dict[str, Any]]:
    """Run a deterministic unittest module in a child process.

    The child process keeps a module that imports this runner from recursively
    invoking the fixture aggregation currently in progress.
    """
    def action() -> dict[str, Any]:
        process = run([sys.executable, "-m", "unittest", module], timeout=180)
        if process.returncode != 0:
            raise AssertionError(
                "deterministic acceptance module failed: " + abbreviated(process.stderr or process.stdout)
            )
        match = re.search(r"Ran (\d+) tests?", process.stderr + process.stdout)
        return {"module": module, "test_count": int(match.group(1)) if match else None}

    return action


def kcap_command(
    arguments: list[str],
    *,
    env: dict[str, str] | None = None,
    unset_env: tuple[str, ...] = (),
    expected_returncode: int = 0,
    timeout: int = 60,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
    if not KCAP_CLI.is_file():
        raise AssertionError(f"kcap CLI is missing: {KCAP_CLI}")
    process = run(
        [sys.executable, str(KCAP_CLI), *arguments],
        env=env,
        unset_env=unset_env,
        timeout=timeout,
    )
    if process.returncode != expected_returncode:
        raise AssertionError(
            f"kcap {' '.join(arguments)} exited {process.returncode}, expected "
            f"{expected_returncode}: {abbreviated(process.stderr or process.stdout)}"
        )
    stream = process.stdout if expected_returncode == 0 else process.stderr
    payload = parse_json(stream, "kcap output")
    if payload.get("ok") is (expected_returncode != 0):
        raise AssertionError("kcap ok field conflicts with its exit status")
    return process, payload


def add_portable_cases(harness: Harness) -> None:
    harness.case("portable.valid", validator_case("valid", 0))
    harness.case(
        "portable.triggers-forbidden",
        validator_case("triggers-forbidden", 1, "frontmatter.no-triggers"),
    )
    harness.case(
        "portable.openai-missing",
        validator_case("openai-missing", 1, "openai.metadata"),
    )
    harness.case(
        "portable.openai-stale",
        validator_case("openai-stale", 1, "openai.metadata"),
    )
    harness.case(
        "portable.runtime-path-escape",
        validator_case("runtime-path-escape", 1, "dependencies.package-boundary"),
    )
    harness.case(
        "portable.runtime-script-escape",
        validator_case("runtime-script-escape", 1, "dependencies.package-boundary"),
    )
    harness.case(
        "portable.runtime-absolute-paths",
        validator_case("runtime-absolute-paths", 1, "dependencies.package-boundary"),
    )
    harness.case("portable.starduster.source", lambda: portable_source_copy_case(harness.workspace, STARDUSTER_DIR))


def portable_source_copy_case(workspace: Path, skill_dir: Path) -> dict[str, Any]:
    """Validate the source package and unchanged direct copies for both hosts."""
    if not skill_dir.is_dir():
        raise AssertionError(f"portable source package is missing: {skill_dir}")
    source_validation = run([sys.executable, str(PORTABLE_VALIDATOR), str(skill_dir), "--json"], cwd=workspace)
    if source_validation.returncode != 0:
        raise AssertionError("portable source validation failed: " + abbreviated(source_validation.stderr or source_validation.stdout))
    source_manifest = tree_byte_manifest(skill_dir)
    destinations = {
        "claude": workspace / "direct-copy-claude" / ".claude" / "skills" / skill_dir.name,
        "codex": workspace / "direct-copy-codex" / "codex-home" / "skills" / skill_dir.name,
    }
    for host, destination in destinations.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(skill_dir, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        verify_tree_byte_manifest(source_manifest, destination, label=f"direct {host} {skill_dir.name} copy")
        validation = run([sys.executable, str(PORTABLE_VALIDATOR), str(destination), "--json"], cwd=workspace)
        if validation.returncode != 0:
            raise AssertionError(
                f"direct {host} {skill_dir.name} copy failed portable validation: "
                + abbreviated(validation.stderr or validation.stdout)
            )
    return {
        "skill": skill_dir.name,
        "copied_file_count": len(source_manifest),
        "destinations": {host: str(path) for host, path in destinations.items()},
    }


def add_deterministic_acceptance_cases(harness: Harness) -> None:
    modules = [
        "tests.acceptance.test_codex_app_server",
        "tests.acceptance.test_kcap_controller",
        "tests.acceptance.test_kcap_network_process",
        "tests.acceptance.test_kcap_policy",
        "tests.acceptance.test_live_provenance",
        "tests.acceptance.test_portable_validator",
        "tests.acceptance.test_starduster_sync",
        "tests.acceptance.test_starduster_rendering",
        "tests.acceptance.test_starduster_policy",
    ]
    app_server_module = "tests.acceptance.test_starduster_app_server"
    if (ROOT / "tests/acceptance/test_starduster_app_server.py").is_file():
        modules.append(app_server_module)
    for module in modules:
        harness.case("acceptance.{}".format(module.rsplit(".", 1)[-1]), unittest_acceptance_case(module))


def add_fixture_cases(harness: Harness) -> None:
    add_portable_cases(harness)
    add_kcap_cases(harness)
    add_deterministic_acceptance_cases(harness)


def add_kcap_cases(harness: Harness) -> None:
    config_path = harness.workspace / "research-toolkit.json"
    output_path = harness.workspace / "notes"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kcap": {
                    "output_path": str(output_path),
                    "subfolder": "captures",
                    "vault_name": None,
                    "default_tags": ["fixture"],
                    "default_mode": "standard",
                    "synthesis_profile": "fast",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    base_env = {
        "RESEARCH_TOOLKIT_CONFIG": str(config_path),
        "RESEARCH_TOOLKIT_NONINTERACTIVE": "1",
        "TMPDIR": str(harness.workspace),
    }

    def config_case() -> dict[str, Any]:
        _, payload = kcap_command(
            ["config", "--project-dir", str(harness.workspace)], env=base_env
        )
        if payload.get("source") != "environment":
            raise AssertionError(f"explicit config source was {payload.get('source')!r}")
        if payload.get("effective", {}).get("synthesis_profile") != "fast":
            raise AssertionError("fast synthesis profile was not retained")
        if payload.get("effective", {}).get("codex_reasoning") != "low":
            raise AssertionError("fast profile did not map to low Codex reasoning")
        expected_output = str((output_path / "captures").resolve())
        actual_output = payload.get("effective", {}).get("output_dir")
        if not isinstance(actual_output, str) or canonical_live_path(actual_output) != canonical_live_path(expected_output):
            raise AssertionError("config did not resolve output_path plus subfolder")
        return {"source": payload["source"], "effective": payload["effective"]}

    harness.case("kcap.config.explicit", config_case)

    def missing_config_case() -> dict[str, Any]:
        missing = harness.workspace / "missing-config.json"
        _, payload = kcap_command(
            ["config", "--project-dir", str(harness.workspace)],
            env={**base_env, "RESEARCH_TOOLKIT_CONFIG": str(missing)},
            expected_returncode=1,
        )
        code = payload.get("error", {}).get("code")
        if not code:
            raise AssertionError("missing explicit config did not return a diagnostic code")
        return {"error_code": code}

    harness.case("kcap.config.missing-explicit", missing_config_case)

    def defaults_config_case() -> dict[str, Any]:
        empty_home = harness.workspace / "empty-home"
        empty_home.mkdir()
        _, payload = kcap_command(
            ["config", "--project-dir", str(harness.workspace)],
            env={"HOME": str(empty_home), "RESEARCH_TOOLKIT_CONFIG": ""},
        )
        if payload.get("source") != "defaults":
            raise AssertionError(f"default config source was {payload.get('source')!r}")
        return {"source": payload["source"], "effective": payload["effective"]}

    harness.case("kcap.config.defaults", defaults_config_case)

    def legacy_config_case() -> dict[str, Any]:
        legacy_project = harness.workspace / "legacy-project"
        legacy_home = harness.workspace / "legacy-home"
        (legacy_project / ".claude").mkdir(parents=True)
        legacy_home.mkdir()
        (legacy_project / ".claude" / "research-toolkit.local.md").write_text(
            "---\n"
            "kcap:\n"
            f"  output_path: {harness.workspace / 'legacy-output'}\n"
            "  subfolder: captures\n"
            "  vault_name: null\n"
            "  default_tags: ['legacy']\n"
            "  default_mode: standard\n"
            "  synthesis_model: haiku\n"
            "---\n",
            encoding="utf-8",
        )
        _, payload = kcap_command(
            ["config", "--project-dir", str(legacy_project)],
            env={"HOME": str(legacy_home), "RESEARCH_TOOLKIT_CONFIG": ""},
        )
        if payload.get("source") != "legacy":
            raise AssertionError("legacy configuration was not selected")
        if payload.get("config", {}).get("synthesis_profile") != "fast":
            raise AssertionError("legacy haiku model did not map to fast")
        if not payload.get("warnings"):
            raise AssertionError("legacy configuration did not emit a deprecation warning")
        return {"source": payload["source"], "warnings": payload["warnings"]}

    harness.case("kcap.config.legacy-migration", legacy_config_case)

    def partial_legacy_case() -> dict[str, Any]:
        partial_project = harness.workspace / "partial-legacy-project"
        partial_home = harness.workspace / "partial-legacy-home"
        (partial_project / ".claude").mkdir(parents=True)
        partial_home.mkdir()
        partial_output = harness.workspace / "partial-legacy-output"
        (partial_project / ".claude" / "research-toolkit.local.md").write_text(
            "---\n"
            "kcap:\n"
            f"  output_path: {partial_output}\n"
            "  default_tags:\n"
            "    - legacy-one\n"
            "    - legacy-two\n"
            "---\n",
            encoding="utf-8",
        )
        _, payload = kcap_command(
            ["config", "--project-dir", str(partial_project)],
            env={"HOME": str(partial_home), "RESEARCH_TOOLKIT_CONFIG": ""},
        )
        config = payload.get("config", {})
        expected = {
            "output_path": str(partial_output),
            "subfolder": "captures",
            "vault_name": None,
            "default_tags": ["legacy-one", "legacy-two"],
            "default_mode": "standard",
            "synthesis_profile": "fast",
        }
        if payload.get("source") != "legacy" or config != expected:
            raise AssertionError(f"partial legacy defaults were not preserved: {config!r}")
        if not any("0.6.x" in warning for warning in payload.get("warnings", [])):
            raise AssertionError("partial legacy config did not emit the migration warning")
        return {"source": payload["source"], "config": config}

    harness.case("kcap.config.partial-legacy-defaults", partial_legacy_case)

    def invalid_subfolder_case() -> dict[str, Any]:
        invalid_path = harness.workspace / "invalid-subfolder.json"
        document = json.loads(config_path.read_text(encoding="utf-8"))
        document["kcap"]["subfolder"] = "../escape"
        invalid_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        _, payload = kcap_command(
            ["config", "--project-dir", str(harness.workspace)],
            env={**base_env, "RESEARCH_TOOLKIT_CONFIG": str(invalid_path)},
            expected_returncode=1,
        )
        code = payload.get("error", {}).get("code")
        if code != "invalid_config":
            raise AssertionError(f"path escape returned {code!r}")
        return {"error_code": code}

    harness.case("kcap.config.reject-path-escape", invalid_subfolder_case)

    def profile_mapping_case() -> dict[str, Any]:
        mappings: dict[str, Any] = {}
        for mode, content_type in (("deep", "article"), ("full", "tweet"), ("full", "video")):
            _, payload = kcap_command(
                ["config", "--project-dir", str(harness.workspace), "--mode", mode, "--content-type", content_type],
                env=base_env,
            )
            mappings[f"{mode}-{content_type}"] = payload["effective"]
        if mappings["deep-article"]["synthesis_profile"] != "balanced":
            raise AssertionError("deep mode did not force balanced")
        if mappings["full-tweet"]["synthesis_profile"] != "balanced":
            raise AssertionError("full mode did not force balanced")
        if mappings["full-video"]["mode"] != "standard":
            raise AssertionError("full YouTube mode did not fall back to standard")
        return mappings

    harness.case("kcap.config.profile-mapping", profile_mapping_case)

    def runtime_case() -> dict[str, Any]:
        runtimes: list[str] = []
        for runtime in ("claude", "codex"):
            _, payload = kcap_command(
                ["detect-runtime"],
                env={**base_env, "RESEARCH_TOOLKIT_RUNTIME": runtime},
            )
            if payload.get("runtime") != runtime or payload.get("source") != "override":
                raise AssertionError(f"runtime override did not select {runtime}")
            runtimes.append(runtime)
        return {"runtimes": runtimes}

    harness.case("kcap.detect-runtime.override", runtime_case)

    def runtime_fail_closed_case() -> dict[str, Any]:
        _, unknown = kcap_command(
            ["detect-runtime"],
            env={"RESEARCH_TOOLKIT_RUNTIME": ""},
            unset_env=HOST_RUNTIME_ENV,
            expected_returncode=1,
        )
        _, ambiguous = kcap_command(
            ["detect-runtime"],
            env={"RESEARCH_TOOLKIT_RUNTIME": "", "CLAUDECODE": "1", "CODEX_CI": "1"},
            unset_env=HOST_RUNTIME_ENV,
            expected_returncode=1,
        )
        codes = [unknown.get("error", {}).get("code"), ambiguous.get("error", {}).get("code")]
        if codes != ["unknown_runtime", "ambiguous_runtime"]:
            raise AssertionError(f"runtime fail-closed codes were {codes!r}")
        return {"error_codes": codes}

    harness.case("kcap.detect-runtime.fail-closed", runtime_fail_closed_case)

    def validate_url_case() -> dict[str, Any]:
        _, payload = kcap_command(["validate-url", YOUTUBE_URL, "--no-resolve"], env=base_env)
        if payload.get("content_type") != "video":
            raise AssertionError("YouTube URL was not classified as video")
        if payload.get("normalized") != "youtube:dQw4w9WgXcQ":
            raise AssertionError(f"unexpected normalized URL: {payload.get('normalized')}")
        if payload.get("resolved_addresses") != []:
            raise AssertionError("--no-resolve must not resolve addresses")
        return {"content_type": payload["content_type"], "normalized": payload["normalized"]}

    harness.case("kcap.validate-url.youtube", validate_url_case)

    def reject_url_case() -> dict[str, Any]:
        _, payload = kcap_command(
            ["validate-url", "http://example.com", "--no-resolve"],
            env=base_env,
            expected_returncode=1,
        )
        return {"error_code": payload.get("error", {}).get("code")}

    harness.case("kcap.validate-url.reject-http", reject_url_case)

    def reject_private_url_case() -> dict[str, Any]:
        _, payload = kcap_command(
            ["validate-url", "https://127.0.0.1/private", "--no-resolve"],
            env=base_env,
            expected_returncode=1,
        )
        code = payload.get("error", {}).get("code")
        if code != "ssrf_blocked":
            raise AssertionError(f"private URL returned {code!r}")
        return {"error_code": code}

    harness.case("kcap.validate-url.reject-private", reject_private_url_case)

    def reject_private_redirect_case() -> dict[str, Any]:
        fake_bin = harness.workspace / "redirect-bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        curl_arguments = harness.workspace / "curl-arguments"
        fake_curl.write_text(
            "#!/bin/sh\n"
            f"arguments={shlex.quote(str(curl_arguments))}\n"
            "printf '%s\\n' \"$@\" > \"$arguments\"\n"
            "headers=''\n"
            "body=''\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    -D) shift; headers=$1 ;;\n"
            "    -o) shift; body=$1 ;;\n"
            "  esac\n"
            "  shift\n"
            "done\n"
            "printf 'HTTP/1.1 302 Found\\r\\nLocation: https://127.0.0.1/private\\r\\n\\r\\n' > \"$headers\"\n"
            "printf 'redirect body' > \"$body\"\n"
            "printf '302'\n",
            encoding="utf-8",
        )
        fake_curl.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        _, extraction_payload = kcap_command(["create-workdir"], env=base_env)
        extraction_dir = Path(extraction_payload["work_dir"])
        _, payload = kcap_command(
            ["extract", "https://8.8.8.8/article", "--output-dir", str(extraction_dir)],
            env={**base_env, "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")},
            expected_returncode=1,
        )
        code = payload.get("error", {}).get("code")
        if code != "ssrf_blocked":
            raise AssertionError(f"private redirect returned {code!r}")
        arguments = curl_arguments.read_text(encoding="utf-8").splitlines()
        if "--noproxy" not in arguments or "*" not in arguments or "--max-filesize" not in arguments:
            raise AssertionError("secure curl invocation lacks proxy or size controls")
        return {"error_code": code, "proxy_disabled": True, "size_limited": True}

    harness.case("kcap.extract.reject-private-redirect", reject_private_redirect_case)

    def normalize_case() -> dict[str, Any]:
        dirty = "https://youtu.be/dQw4w9WgXcQ?si=tracking&t=42"
        _, payload = kcap_command(["normalize-url", dirty], env=base_env)
        if payload.get("normalized") != "youtube:dQw4w9WgXcQ":
            raise AssertionError(f"tracking parameters survived: {payload.get('normalized')}")
        return {"normalized": payload["normalized"]}

    harness.case("kcap.normalize-url.youtube", normalize_case)

    _, synthesis_workspace_payload = kcap_command(["create-workdir"], env=base_env)
    synthesis_workspace = Path(synthesis_workspace_payload["work_dir"])
    raw_synthesis_path = synthesis_workspace / "model-response.json"
    synthesis_path = synthesis_workspace / "synthesis.json"
    synthesis = {
        "title": "Fixture Video",
        "author": "Fixture Channel",
        "published": "2026-08-28",
        "tldr": "A concise fixture summary.",
        "summary": "The fixture explains deterministic portable-skill testing.",
        "takeaways": ["Validate structured output", "Keep runtime boundaries explicit"],
        "detailed_notes": "The portable package keeps deterministic behavior in its helper.",
        "quotes": [],
        "references": [],
        "tags": ["testing", "portable-skills"],
        "chapters": [],
        "thread": [],
    }
    raw_synthesis_path.write_text(json.dumps(synthesis) + "\n", encoding="utf-8")

    def synthesis_case() -> dict[str, Any]:
        _, payload = kcap_command(
            [
                "validate-synthesis", "--mode", "standard", "--input", str(raw_synthesis_path),
                "--output-file", str(synthesis_path),
            ],
            env=base_env,
        )
        validated = json.loads(synthesis_path.read_text(encoding="utf-8"))
        if validated.get("title") != synthesis["title"]:
            raise AssertionError("validated synthesis changed the title")
        if payload.get("synthesis_file") != str(synthesis_path):
            raise AssertionError("validator did not return the private synthesis path")
        if "synthesis" in payload:
            raise AssertionError("validator exposed synthesis prose on stdout")
        return {"fields": sorted(validated.keys()), "file_only": True}

    harness.case("kcap.validate-synthesis.standard", synthesis_case)

    def strict_synthesis_case() -> dict[str, Any]:
        _, invalid_workspace_payload = kcap_command(["create-workdir"], env=base_env)
        invalid_workspace = Path(invalid_workspace_payload["work_dir"])
        invalid_path = invalid_workspace / "model-response.json"
        output_path = invalid_workspace / "synthesis.json"
        invalid = dict(synthesis)
        invalid["unexpected"] = "must fail"
        invalid_path.write_text(json.dumps(invalid) + "\n", encoding="utf-8")
        _, payload = kcap_command(
            [
                "validate-synthesis", "--mode", "standard", "--input", str(invalid_path),
                "--output-file", str(output_path),
            ],
            env=base_env,
            expected_returncode=1,
        )
        code = payload.get("error", {}).get("code")
        if code != "invalid_synthesis":
            raise AssertionError(f"schema mismatch returned {code!r}")
        return {"error_code": code}

    harness.case("kcap.validate-synthesis.reject-extra-field", strict_synthesis_case)

    def sanitization_case() -> dict[str, Any]:
        _, malicious_workspace_payload = kcap_command(["create-workdir"], env=base_env)
        malicious_workspace = Path(malicious_workspace_payload["work_dir"])
        malicious_path = malicious_workspace / "model-response.json"
        sanitized_path = malicious_workspace / "synthesis.json"
        malicious = dict(synthesis)
        malicious["summary"] = (
            "<script>alert(1)</script><iframe>active</iframe> Safe summary <% system %> "
            "[run:: command] ![[secret-note]] ![pixel](https://tracker.example/pixel) "
            "[run](javascript:alert(1))"
        )
        malicious["references"] = [
            {
                "name": "No DNS fixture",
                "type": "project",
                "url": "https://must-not-resolve.invalid/resource",
            }
        ]
        malicious_path.write_text(json.dumps(malicious) + "\n", encoding="utf-8")
        _, payload = kcap_command(
            [
                "validate-synthesis", "--mode", "standard", "--input", str(malicious_path),
                "--output-file", str(sanitized_path),
            ],
            env=base_env,
        )
        if "synthesis" in payload:
            raise AssertionError("sanitizer exposed synthesis prose on stdout")
        sanitized = json.loads(sanitized_path.read_text(encoding="utf-8"))
        cleaned = sanitized.get("summary", "")
        for marker in ("<script", "<iframe", "<%", "[run::", "![[", "![", "javascript:"):
            if marker in cleaned:
                raise AssertionError(f"sanitizer retained {marker!r}")
        if sanitized["references"][0]["url"] != "https://must-not-resolve.invalid/resource":
            raise AssertionError("syntax-valid reference URL was dropped or resolved")
        return {"sanitized_summary": cleaned, "dns_free_reference": True}

    harness.case("kcap.validate-synthesis.sanitize-active-markup", sanitization_case)

    def reject_chapter_injection_case() -> dict[str, Any]:
        _, chapter_workspace_payload = kcap_command(["create-workdir"], env=base_env)
        chapter_workspace = Path(chapter_workspace_payload["work_dir"])
        chapter_input = chapter_workspace / "model-response.json"
        chapter_output = chapter_workspace / "synthesis.json"
        malicious_chapter = dict(synthesis)
        malicious_chapter["chapters"] = [{"time": "![pixel](https://tracker.example)", "title": "Injected"}]
        chapter_input.write_text(json.dumps(malicious_chapter) + "\n", encoding="utf-8")
        _, payload = kcap_command(
            [
                "validate-synthesis", "--mode", "standard", "--input", str(chapter_input),
                "--output-file", str(chapter_output),
            ],
            env=base_env,
            expected_returncode=1,
        )
        code = payload.get("error", {}).get("code")
        if code != "invalid_synthesis":
            raise AssertionError(f"malicious chapter timestamp returned {code!r}")
        return {"error_code": code}

    harness.case("kcap.validate-synthesis.reject-chapter-injection", reject_chapter_injection_case)

    def render_case() -> dict[str, Any]:
        render_output = harness.workspace / "render-video"
        _, payload = kcap_command(
            [
                "render",
                "--synthesis",
                str(synthesis_path),
                "--url",
                YOUTUBE_URL,
                "--content-type",
                "video",
                "--mode",
                "standard",
                "--captured-at",
                "2026-08-28T12:00:00Z",
                "--output-dir",
                str(render_output),
            ],
            env=base_env,
        )
        if "markdown" in payload:
            raise AssertionError("render exposed note prose on stdout")
        output_file = Path(payload["output_file"])
        markdown = output_file.read_text(encoding="utf-8")
        for expected in ("Fixture Video", YOUTUBE_URL, "Validate structured output"):
            if expected not in markdown:
                raise AssertionError(f"rendered Markdown lacks {expected!r}")
        filename = payload.get("filename", "")
        if not filename.endswith(".md"):
            raise AssertionError("render did not return a Markdown filename")
        return {"filename": filename, "markdown_bytes": len(markdown.encode("utf-8")), "file_only": True}

    harness.case("kcap.render.video", render_case)

    def duplicate_case() -> dict[str, Any]:
        duplicate_output = harness.workspace / "duplicate-output"
        duplicate_url = "https://example.com/article?a=1&b=2"
        _, rendered = kcap_command(
            [
                "render", "--synthesis", str(synthesis_path), "--url", duplicate_url,
                "--content-type", "article", "--mode", "standard",
                "--captured-at", "2026-08-28T12:00:00Z", "--output-dir", str(duplicate_output),
            ],
            env=base_env,
        )
        _, found = kcap_command(
            ["find-duplicate", "--output-dir", str(duplicate_output), "--url", duplicate_url],
            env=base_env,
        )
        found_matches = found.get("matches")
        expected_match = rendered.get("output_file")
        if (
            found.get("count") != 1
            or not isinstance(found_matches, list)
            or not isinstance(expected_match, str)
            or [canonical_live_path(path) for path in found_matches] != [canonical_live_path(expected_match)]
        ):
            raise AssertionError(f"deterministic duplicate search returned {found!r}")
        return {"count": 1, "shell_free": True}

    harness.case("kcap.duplicate.deterministic", duplicate_case)

    def render_modes_case() -> dict[str, Any]:
        _, deep_workspace_payload = kcap_command(["create-workdir"], env=base_env)
        deep_workspace = Path(deep_workspace_payload["work_dir"])
        deep_raw = deep_workspace / "model-response.json"
        deep_path = deep_workspace / "synthesis.json"
        deep = dict(synthesis)
        deep.update(
            {
                "title": "Deep Article",
                "critical_analysis": "The design makes runtime boundaries explicit.",
                "counterarguments": ["Local command surfaces can change."],
                "open_questions": ["How should later profile versions evolve?"],
                "connections": ["This resembles portable package profiles."],
                "action_items": ["Run both host acceptances."],
            }
        )
        deep_raw.write_text(json.dumps(deep) + "\n", encoding="utf-8")
        kcap_command(
            [
                "validate-synthesis", "--mode", "deep", "--input", str(deep_raw),
                "--output-file", str(deep_path),
            ],
            env=base_env,
        )
        _, full_workspace_payload = kcap_command(["create-workdir"], env=base_env)
        full_workspace = Path(full_workspace_payload["work_dir"])
        full_raw = full_workspace / "model-response.json"
        full_path = full_workspace / "synthesis.json"
        full = {
            "title": "Full Thread",
            "author": "Fixture Author",
            "published": "2026-08-28",
            "tags": ["full-capture"],
            "cleaned_content": " ".join(["Preserved substantive fixture content"] * 20),
        }
        full_raw.write_text(json.dumps(full) + "\n", encoding="utf-8")
        kcap_command(
            [
                "validate-synthesis", "--mode", "full", "--input", str(full_raw),
                "--output-file", str(full_path),
            ],
            env=base_env,
        )
        cases = (
            (synthesis_path, "https://example.com/article", "article", "standard", "## Summary"),
            (deep_path, "https://example.com/deep", "article", "deep", "## Critical Analysis"),
            (synthesis_path, "https://x.com/example/status/123456789", "tweet", "standard", "content_type: tweet"),
            (full_path, "https://x.com/example/status/987654321", "tweet", "full", "## Source"),
        )
        rendered: list[str] = []
        for index, (source, url, content_type, mode, expected) in enumerate(cases):
            render_output = harness.workspace / f"render-mode-{index}"
            _, payload = kcap_command(
                [
                    "render", "--synthesis", str(source), "--url", url,
                    "--content-type", content_type, "--mode", mode,
                    "--captured-at", "2026-08-28T12:00:00Z",
                    "--output-dir", str(render_output),
                ],
                env=base_env,
            )
            markdown = Path(payload["output_file"]).read_text(encoding="utf-8")
            if expected not in markdown:
                raise AssertionError(f"{mode} {content_type} render lacks {expected!r}")
            rendered.append(f"{mode}-{content_type}")
        return {"rendered": rendered}

    harness.case("kcap.render.article-tweet-modes", render_modes_case)

    def atomic_write_case() -> dict[str, Any]:
        output_dir = harness.workspace / "atomic-output"
        arguments = [
            "render", "--synthesis", str(synthesis_path), "--url", YOUTUBE_URL,
            "--content-type", "video", "--mode", "standard",
            "--captured-at", "2026-08-28T12:00:00Z", "--output-dir", str(output_dir),
            "--collision", "suffix",
        ]
        _, first = kcap_command(arguments, env=base_env)
        _, second = kcap_command(arguments, env=base_env)
        first_path = Path(first["output_file"])
        second_path = Path(second["output_file"])
        if first_path == second_path or not first_path.is_file() or not second_path.is_file():
            raise AssertionError("atomic writer did not suffix a title collision")
        if first_path.read_bytes() != second_path.read_bytes():
            raise AssertionError("repeat render produced different bytes")
        if list(output_dir.glob(".kcap-*.tmp")):
            raise AssertionError("atomic writer left temporary files")
        return {"files": [first_path.name, second_path.name], "idempotent_bytes": True}

    harness.case("kcap.render.atomic-repeat", atomic_write_case)

    def symlink_collision_case() -> dict[str, Any]:
        output_dir = harness.workspace / "symlink-output"
        output_dir.mkdir()
        outside = harness.workspace / "outside-note.md"
        outside.write_text("must remain unchanged\n", encoding="utf-8")
        destination = output_dir / "2026-08-28-fixture-video.md"
        destination.symlink_to(outside)
        _, payload = kcap_command(
            [
                "render", "--synthesis", str(synthesis_path), "--url", YOUTUBE_URL,
                "--content-type", "video", "--mode", "standard",
                "--captured-at", "2026-08-28T12:00:00Z", "--output-dir", str(output_dir),
                "--collision", "skip",
            ],
            env=base_env,
            expected_returncode=1,
        )
        if payload.get("error", {}).get("code") != "output_error":
            raise AssertionError("symlinked collision did not fail closed")
        if outside.read_text(encoding="utf-8") != "must remain unchanged\n":
            raise AssertionError("symlink target was modified")
        return {"error_code": "output_error", "target_unchanged": True}

    harness.case("kcap.render.reject-symlink-collision", symlink_collision_case)

    def workspace_cleanup_case() -> dict[str, Any]:
        _, created = kcap_command(["create-workdir"], env=base_env)
        work_dir = Path(created["work_dir"])
        if not work_dir.is_dir() or stat.S_IMODE(work_dir.stat().st_mode) != 0o700:
            raise AssertionError("work directory is missing or has the wrong mode")
        _, cleaned = kcap_command(["cleanup-workdir", "--path", str(work_dir)], env=base_env)
        if cleaned.get("removed") is not True or work_dir.exists():
            raise AssertionError("work directory cleanup failed")
        _, again = kcap_command(["cleanup-workdir", "--path", str(work_dir)], env=base_env)
        if again.get("removed") is not False:
            raise AssertionError("work directory cleanup is not idempotent")
        return {"removed": True, "repeat_removed": False}

    harness.case("kcap.workspace.cleanup", workspace_cleanup_case)

    _, content_workspace_payload = kcap_command(["create-workdir"], env=base_env)
    content_workspace = Path(content_workspace_payload["work_dir"])
    content_path = content_workspace / "content.txt"
    synthesis_output_path = content_workspace / "synthesis.json"
    content_path.write_text(
        "Portable skills keep shared behavior host-neutral. " * 20,
        encoding="utf-8",
    )

    def adapter_profile_case() -> dict[str, Any]:
        _, claude_payload = kcap_command(
            [
                "claude-synthesize", "--content-file", str(content_path),
                "--mode", "deep", "--content-type", "video", "--url", YOUTUBE_URL,
                "--profile", "deep", "--output-file", str(synthesis_output_path), "--dry-run",
            ],
            env=base_env,
        )
        claude_command = claude_payload.get("command", [])
        if claude_payload.get("model") != "sonnet":
            raise AssertionError("deep Claude adapter did not force Sonnet-equivalent balanced")
        if not isinstance(claude_command, list) or not all(isinstance(value, str) for value in claude_command):
            raise AssertionError("Claude adapter did not return its child command")
        validate_claude_isolation_command(claude_command)
        cleared = set(claude_payload.get("cleared_host_indicators", []))
        expected_cleared = {"CLAUDECODE", "CLAUDE_CODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_SESSION_ID"}
        if cleared != expected_cleared:
            raise AssertionError(f"Claude adapter did not report the expected scrubbed host indicators: {cleared}")
        return {
            "claude_model": "sonnet",
            "claude_tools": [],
            "claude_host_indicators_cleared": sorted(cleared),
        }

    harness.case("kcap.adapters.force-balanced-and-isolate", adapter_profile_case)

    def claude_host_environment_case() -> dict[str, Any]:
        fake_claude = harness.workspace / "fake-claude"
        claude_output_path = synthesis_output_path
        valid_envelope = json.dumps({"structured_output": synthesis}, separators=(",", ":"))
        fake_claude.write_text(
            "#!/bin/sh\n"
            "if [ \"${CLAUDECODE+x}\" = x ] || [ \"${CLAUDE_CODE+x}\" = x ] || "
            "[ \"${CLAUDE_CODE_ENTRYPOINT+x}\" = x ] || [ \"${CLAUDE_SESSION_ID+x}\" = x ]; then\n"
            "  exit 97\n"
            "fi\n"
            "if [ \"$1\" = \"--help\" ]; then\n"
            "  printf '%s\\n' '--safe-mode --no-session-persistence --no-chrome --tools --mcp-config --strict-mcp-config --json-schema --permission-mode'\n"
            "  exit 0\n"
            "fi\n"
            f"printf '%s\\n' {shlex.quote(valid_envelope)}\n",
            encoding="utf-8",
        )
        fake_claude.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        host_env = {
            **base_env,
            "CLAUDECODE": "1",
            "CLAUDE_CODE": "1",
            "CLAUDE_CODE_ENTRYPOINT": "acceptance",
            "CLAUDE_SESSION_ID": "acceptance",
        }
        _, payload = kcap_command(
            [
                "claude-synthesize", "--content-file", str(content_path),
                "--mode", "standard", "--content-type", "video", "--url", YOUTUBE_URL,
                "--output-file", str(claude_output_path), "--claude-bin", str(fake_claude),
            ],
            env=host_env,
        )
        if "synthesis" in payload:
            raise AssertionError("Claude adapter exposed synthesis prose on stdout")
        saved = json.loads(claude_output_path.read_text(encoding="utf-8"))
        if saved.get("title") != synthesis["title"]:
            raise AssertionError("Claude adapter did not save the fake child's structured output")
        return {"host_indicators_cleared": True, "file_only": True}

    harness.case("kcap.claude-child.scrub-host-environment", claude_host_environment_case)

    def codex_catalog_alias_case() -> dict[str, Any]:
        temporary_root = harness.workspace / "catalog-home" / "skills"
        catalog_text = (
            f"- `r0` = `{temporary_root}`\n"
            "- `r1` = `/Users/example/.agents/skills`\n"
            "- kcap: (file: r1/kcap/SKILL.md)\n"
            "- kcap: (file: r0/kcap/SKILL.md)\n"
        )
        paths = codex_catalog_skill_paths(catalog_text, "kcap")
        expected = (temporary_root / "kcap" / "SKILL.md").resolve()
        if expected not in {path.resolve() for path in paths}:
            raise AssertionError("Codex catalog aliases did not resolve to the temporary skill")
        if len(paths) != 2:
            raise AssertionError("Codex catalog parser did not retain duplicate skill sources")
        return {"resolved_temporary_source": True, "source_count": len(paths)}

    harness.case("kcap.codex-host.catalog-alias-provenance", codex_catalog_alias_case)


def verify_live_output(
    output_file: Path,
    output_root: Path,
    *,
    source_url: str = YOUTUBE_URL,
) -> dict[str, Any]:
    resolved = output_file.resolve()
    try:
        resolved.relative_to(output_root.resolve())
    except ValueError as error:
        raise AssertionError(f"live output escaped its temporary root: {resolved}") from error
    if not resolved.is_file():
        raise AssertionError(f"live output file does not exist: {resolved}")
    markdown = resolved.read_text(encoding="utf-8")
    for expected in ("---", source_url, "## TL;DR", "## Summary", "## Key Takeaways"):
        if expected not in markdown:
            raise AssertionError(f"live output lacks {expected!r}")
    parts = markdown.split("---", 2)
    if len(parts) < 3:
        raise AssertionError("live output has malformed YAML frontmatter delimiters")
    try:
        frontmatter = yaml.safe_load(parts[1])
    except yaml.YAMLError as error:
        raise AssertionError(f"live output frontmatter is invalid YAML: {error}") from error
    if not isinstance(frontmatter, dict) or frontmatter.get("source") != source_url:
        raise AssertionError("live output frontmatter does not preserve source identity")
    for marker in ("<script", "<iframe", "<%", "[run::", "javascript:"):
        if marker.lower() in markdown.lower():
            raise AssertionError(f"live output contains active-content marker {marker!r}")
    note_files = list(output_root.rglob("*.md"))
    if note_files != [resolved]:
        raise AssertionError(f"live capture wrote unexpected Markdown files: {note_files}")
    return {
        "output_file": str(resolved),
        "markdown_bytes": len(markdown.encode("utf-8")),
        "frontmatter_keys": sorted(frontmatter),
        "markdown_file_count": len(note_files),
    }


def live_capture_command(config_path: Path, skill_dir: Path) -> str:
    return " ".join(
        (
            "python3",
            shlex.quote(str((skill_dir / "scripts" / "kcap.py").resolve())),
            "capture",
            shlex.quote(YOUTUBE_URL),
            "--project-dir",
            shlex.quote(str(config_path.parent.resolve())),
        )
    )


def live_prompt(config_path: Path, output_root: Path, skill_dir: Path) -> str:
    controller = live_capture_command(config_path, skill_dir)
    return (
        f"Use the $kcap skill whose catalog source is {(skill_dir / 'SKILL.md').resolve()}. "
        "This is a noninteractive acceptance test. Execute exactly one shell command as the sole required "
        "action, with no preliminary config, validation, extraction, reader, or application-launch commands. "
        "Do not use Task or delegate work. The command must be:\n"
        f"{controller}\n"
        "Do not open Obsidian. The controller must write only below "
        f"{output_root}. Configuration is supplied through {config_path}. Do not claim completion unless "
        "the command completed."
    )


def source_auth_metadata(path: Path) -> dict[str, int]:
    status = path.stat()
    return {
        "device": status.st_dev,
        "inode": status.st_ino,
        "mode": status.st_mode,
        "size": status.st_size,
        "mtime_ns": status.st_mtime_ns,
        "ctime_ns": status.st_ctime_ns,
    }


def source_auth_snapshot(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise AssertionError(f"source authentication file is missing: {path}")
    return {"bytes": path.read_bytes(), "metadata": source_auth_metadata(path)}


def verify_source_auth_unchanged(path: Path, snapshot: Mapping[str, Any]) -> None:
    if path.read_bytes() != snapshot.get("bytes"):
        raise AssertionError("source authentication bytes changed")
    if source_auth_metadata(path) != snapshot.get("metadata"):
        raise AssertionError("source authentication metadata changed")


def create_private_auth_copy(source: Path, destination: Path) -> dict[str, Any]:
    """Copy source authentication into an isolated, regular 0600 file."""
    snapshot = source_auth_snapshot(source)
    if destination.exists() or destination.is_symlink():
        raise AssertionError(f"private Codex authentication destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(destination, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(snapshot["bytes"])
    except Exception:
        if descriptor != -1:
            os.close(descriptor)
        raise
    if destination.is_symlink() or not stat.S_ISREG(destination.stat().st_mode):
        raise AssertionError("private Codex authentication copy must be a regular file")
    if stat.S_IMODE(destination.stat().st_mode) != 0o600:
        raise AssertionError("private Codex authentication copy must have mode 0600")
    if destination.read_bytes() != snapshot["bytes"]:
        raise AssertionError("private Codex authentication copy bytes differ from source")
    verify_source_auth_unchanged(source, snapshot)
    return snapshot


def codex_live_environment(
    project: Path,
    config_path: Path,
    codex_home: Path,
    sqlite_home: Path,
) -> dict[str, str]:
    return {
        "RESEARCH_TOOLKIT_CONFIG": str(config_path),
        "RESEARCH_TOOLKIT_RUNTIME": "codex",
        "RESEARCH_TOOLKIT_NONINTERACTIVE": "1",
        "CODEX_HOME": str(codex_home),
        "CODEX_SQLITE_HOME": str(sqlite_home),
        "HOME": str(project / "home"),
        "TMPDIR": str(project),
    }


def run_codex_app_server_capture(
    *,
    codex_bin: Path,
    argv: Sequence[str],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = 900.0,
    output_bytes_cap: int = 65536,
    forbidden_values: Sequence[str] = (),
) -> dict[str, Any]:
    """Run one exact controller argv through buffered App Server command/exec."""
    if timeout_seconds <= 0 or output_bytes_cap <= 0:
        raise AssertionError("Codex App Server command limits must be positive")
    command = [str(value) for value in argv]
    if not command or any(not value for value in command):
        raise AssertionError("Codex App Server capture command must be a nonempty argv vector")
    resolved_cwd = cwd.resolve()
    if not resolved_cwd.is_dir():
        raise AssertionError("Codex App Server capture working directory is unavailable")
    process = subprocess.Popen(
        [str(codex_bin), "app-server", "--stdio", "--strict-config"],
        cwd=resolved_cwd,
        env=dict(environment),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    selector = selectors.DefaultSelector()
    pending = bytearray()
    deadline = time.monotonic() + timeout_seconds
    response_limit = output_bytes_cap * 2 + 65536

    def write_message(message: Mapping[str, Any]) -> None:
        if process.stdin is None:
            raise AssertionError("Codex App Server command transport is unavailable")
        try:
            process.stdin.write(json.dumps(dict(message), separators=(",", ":")).encode("utf-8") + b"\n")
            process.stdin.flush()
        except OSError as error:
            raise AssertionError("Codex App Server command transport closed unexpectedly") from error

    def read_message() -> dict[str, Any]:
        while True:
            newline = pending.find(b"\n")
            if newline >= 0:
                raw = bytes(pending[:newline])
                del pending[: newline + 1]
                if len(raw) > response_limit:
                    raise AssertionError("Codex App Server command response exceeded the output limit")
                try:
                    value = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise AssertionError("Codex App Server command protocol emitted invalid JSON") from error
                if not isinstance(value, dict):
                    raise AssertionError("Codex App Server command protocol emitted a non-object response")
                return value
            if len(pending) > response_limit:
                raise AssertionError("Codex App Server command response exceeded the output limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("Codex App Server command timed out")
            ready = selector.select(remaining)
            if not ready:
                if process.poll() is not None:
                    raise AssertionError("Codex App Server exited before returning the command response")
                continue
            if process.stdout is None:
                raise AssertionError("Codex App Server command transport is unavailable")
            try:
                chunk = os.read(process.stdout.fileno(), 8192)
            except OSError as error:
                raise AssertionError("Codex App Server command transport failed") from error
            if not chunk:
                raise AssertionError("Codex App Server exited before returning the command response")
            pending.extend(chunk)

    passive_notification_count = 0

    def require_response(request_id: int) -> dict[str, Any]:
        nonlocal passive_notification_count
        while True:
            message = read_message()
            if message.get("method") == "remoteControl/status/changed" and "id" not in message:
                if not isinstance(message.get("params"), dict):
                    raise AssertionError("Codex App Server command protocol emitted an invalid passive notification")
                passive_notification_count += 1
                continue
            break
        if "method" in message:
            raise AssertionError("Codex App Server command protocol emitted an unexpected request or notification")
        if message.get("id") != request_id:
            raise AssertionError("Codex App Server command response ID did not match the request")
        if "error" in message:
            raise AssertionError("Codex App Server rejected the command request")
        result = message.get("result")
        if not isinstance(result, dict):
            raise AssertionError("Codex App Server command response lacked an object result")
        return result

    try:
        if process.stdout is None:
            raise AssertionError("Codex App Server command transport is unavailable")
        selector.register(process.stdout, selectors.EVENT_READ)
        write_message(
            {
                "id": 1,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "robot-tools-acceptance", "version": "1"},
                    "capabilities": {},
                },
            }
        )
        require_response(1)
        write_message({"method": "initialized", "params": {}})
        write_message(
            {
                "id": 2,
                "method": "command/exec",
                "params": {
                    "command": command,
                    "cwd": str(resolved_cwd),
                    "sandboxPolicy": {
                        "type": "workspaceWrite",
                        "writableRoots": [str(resolved_cwd)],
                        "networkAccess": True,
                        "excludeTmpdirEnvVar": True,
                        "excludeSlashTmp": True,
                    },
                    "timeoutMs": max(1, round(timeout_seconds * 1000)),
                    "outputBytesCap": output_bytes_cap,
                },
            }
        )
        result = require_response(2)
        exit_code = result.get("exitCode")
        stdout = result.get("stdout")
        stderr = result.get("stderr")
        if not isinstance(exit_code, int) or not isinstance(stdout, str) or not isinstance(stderr, str):
            raise AssertionError("Codex App Server command response had an invalid result shape")
        stdout_bytes = len(stdout.encode("utf-8"))
        stderr_bytes = len(stderr.encode("utf-8"))
        if stdout_bytes > output_bytes_cap or stderr_bytes > output_bytes_cap:
            raise AssertionError("Codex App Server command response exceeded the output limit")
        if any(value and (value in stdout or value in stderr) for value in forbidden_values):
            raise AssertionError("Codex App Server command response exposed authentication material")
        if exit_code != 0:
            error_code = safe_controller_error_code(stderr)
            suffix = " ({})".format(error_code) if error_code else ""
            raise AssertionError("Codex App Server capture command exited unsuccessfully" + suffix)
        return {
            "event": {
                "type": "command_execution",
                "command": shlex.join(command),
                "argv": command,
                "status": "completed",
            },
            "exit_code": exit_code,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "passive_notification_count": passive_notification_count,
            "transport": "app-server-command-exec",
        }
    finally:
        selector.close()
        if process.stdin is not None:
            process.stdin.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if process.stdout is not None:
            process.stdout.close()


def prepare_live_project(workspace: Path, host: str) -> tuple[Path, Path, Path, Path, dict[Path, bytes]]:
    project = workspace / f"live-{host}"
    skill_root = project / ".claude/skills" if host == "claude" else workspace / "live-codex-home/skills"
    skill_root.mkdir(parents=True)
    skill_dir = skill_root / "kcap"
    source_manifest = tree_byte_manifest(KCAP_DIR)
    shutil.copytree(KCAP_DIR, skill_dir)
    verify_tree_byte_manifest(source_manifest, skill_dir, label="temporary kcap copy before host execution")
    output_root = project / "output"
    output_root.mkdir(parents=True)
    config_path = project / "research-toolkit.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kcap": {
                    "output_path": str(output_root),
                    "subfolder": "captures",
                    "vault_name": None,
                    "default_tags": ["acceptance"],
                    "default_mode": "standard",
                    "synthesis_profile": "fast",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return project, output_root, config_path, skill_dir, source_manifest


def prepare_live_starduster_project(
    workspace: Path, host: str
) -> tuple[Path, Path, Path, Path, dict[Path, bytes]]:
    project = workspace / f"live-starduster-{host}"
    skill_root = project / ".claude/skills" if host == "claude" else workspace / "live-starduster-codex-home/skills"
    skill_root.mkdir(parents=True)
    for state_dir in (project / "home", project / "state"):
        state_dir.mkdir(parents=True, mode=0o700)
        state_dir.chmod(0o700)
    skill_dir = skill_root / "starduster"
    source_manifest = tree_byte_manifest(STARDUSTER_DIR)
    shutil.copytree(STARDUSTER_DIR, skill_dir)
    verify_tree_byte_manifest(source_manifest, skill_dir, label="temporary starduster copy before host execution")
    output_root = project / "output"
    output_root.mkdir(parents=True)
    config_path = project / "research-toolkit.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "starduster": {
                    "output_path": str(output_root),
                    "subfolder": "catalog",
                    "vault_name": None,
                    "synthesis_profile": "fast",
                    "synthesis_batch_size": 1,
                },
            }
        ) + "\n",
        encoding="utf-8",
    )
    return project, output_root, config_path, skill_dir, source_manifest


def starduster_live_command(config_path: Path, skill_dir: Path) -> list[str]:
    return [
        "python3", str((skill_dir / "scripts" / "starduster.py").resolve()), "sync",
        "--limit", "5", "--project-dir", str(config_path.parent.resolve()),
    ]


def starduster_claude_live_environment(
    project: Path,
    config_path: Path,
    github_token: str,
) -> dict[str, str]:
    """Keep Desktop-managed Claude login while isolating outputs and GitHub access."""
    return {
        "RESEARCH_TOOLKIT_CONFIG": str(config_path),
        "RESEARCH_TOOLKIT_RUNTIME": "claude",
        "RESEARCH_TOOLKIT_NONINTERACTIVE": "1",
        "TMPDIR": str(project),
        "GH_TOKEN": github_token,
    }


def starduster_controller_path(python_executable: Path, gh_executable: Path) -> str:
    """Build the deterministic executable path used by the outer controller only."""
    executables = (python_executable, gh_executable)
    if any(not path.is_absolute() for path in executables):
        raise AssertionError("Starduster controller executables must use absolute paths")
    directories: list[str] = []
    for directory in (python_executable.parent, gh_executable.parent, Path("/usr/bin"), Path("/bin")):
        value = str(directory)
        if value not in directories:
            directories.append(value)
    return os.pathsep.join(directories)


def safe_controller_error_code(stderr: str) -> str | None:
    """Extract only a bounded public controller code from an exact error envelope."""
    if len(stderr.encode("utf-8")) > 4096:
        return None
    try:
        value = json.loads(stderr)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or value.get("ok") is not False or set(value) != {"ok", "error"}:
        return None
    error = value.get("error")
    if not isinstance(error, dict) or not {"code", "message"}.issubset(error):
        return None
    code, message = error.get("code"), error.get("message")
    if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code):
        return None
    if not isinstance(message, str) or len(message) > 512:
        return None
    return code


def require_bundled_desktop_codex_for_live(binary: Path) -> Path:
    """The release live proof is valid only for the signed Desktop binary."""
    if canonical_live_path(binary) != canonical_live_path(BUNDLED_CODEX_BINARY):
        raise SkipCase("Codex Starduster live proof requires the bundled Desktop binary")
    return binary


def verify_starduster_live_success(output_root: Path) -> dict[str, Any]:
    """Use paths and bounded counts only; never inspect live GitHub or model text."""
    root = output_root.resolve()
    repo_root = root / "catalog" / "repos"
    notes = sorted(path.resolve() for path in repo_root.glob("*.md")) if repo_root.is_dir() else []
    if len(notes) != 5:
        raise AssertionError("live Starduster run did not derive exactly five repository notes from its filesystem")
    bases = sorted(path.resolve() for path in root.rglob("*.base"))
    if len(bases) != 7:
        raise AssertionError("live Starduster run did not derive exactly seven Bases indexes from its filesystem")
    for note in notes:
        try:
            note.relative_to(root)
        except ValueError as error:
            raise AssertionError("live Starduster note escaped its temporary output root") from error
        if not note.is_file():
            raise AssertionError("live Starduster repository note is not a regular file")
    return {
        "repo_note_count": len(notes), "base_index_count": len(bases),
        "output_root": str(root), "filesystem_derived": True,
    }


def verify_starduster_live_command(event: Mapping[str, Any], skill_dir: Path, project: Path) -> None:
    command = event.get("command")
    if not isinstance(command, str):
        raise AssertionError("live Starduster provenance lacks one command")
    values = shlex.split(command)
    expected = starduster_live_command(project / "research-toolkit.json", skill_dir)
    if values != expected:
        raise AssertionError("live Starduster provenance differs from the exact temporary sync command")


def starduster_codex_live_case(
    workspace: Path,
    *,
    auth_leg: str = "oauth",
    api_key: str | None = None,
) -> dict[str, Any]:
    if auth_leg not in {"oauth", "api-key"}:
        raise AssertionError("unknown Starduster Codex authentication leg")
    if auth_leg == "api-key" and not api_key:
        raise AssertionError("requested Starduster API-key live leg lacks its dedicated test credential")
    codex = preferred_codex_binary(os.environ.get(CODEX_BINARY_OVERRIDE_ENV))
    if codex is None:
        raise SkipCase("Codex CLI is not installed")
    codex = require_bundled_desktop_codex_for_live(codex)
    gh_binary = shutil.which("gh")
    python_binary = Path(sys.executable).parent / "python3"
    if not STARDUSTER_CLI.is_file() or gh_binary is None or not python_binary.is_file():
        raise SkipCase("Starduster controller or authenticated gh dependency is unavailable")
    project, output_root, config_path, skill_dir, manifest = prepare_live_starduster_project(workspace, "codex")
    codex_home = skill_dir.parent.parent
    codex_home.chmod(0o700)
    sqlite_home = project / "codex-sqlite"
    sqlite_home.mkdir(mode=0o700)
    sqlite_home.chmod(0o700)
    auth_source = Path.home() / ".codex" / "auth.json"
    auth_snapshot: Mapping[str, Any] | None = None
    if auth_leg == "oauth":
        if not auth_source.is_file():
            raise SkipCase("Codex authentication file is not installed")
        auth_snapshot = create_private_auth_copy(auth_source, codex_home / "auth.json")
    report_path = project / "starduster-codex-app-server-report.json"
    host_env = {
        "RESEARCH_TOOLKIT_CONFIG": str(config_path), "RESEARCH_TOOLKIT_RUNTIME": "codex",
        "RESEARCH_TOOLKIT_NONINTERACTIVE": "1", "RESEARCH_TOOLKIT_CODEX_AUTH": auth_leg.replace("-", "_"),
        "RESEARCH_TOOLKIT_ACCEPTANCE_REPORT": str(report_path),
        "CODEX_HOME": str(codex_home), "CODEX_SQLITE_HOME": str(sqlite_home),
        "HOME": str(project / "home"), "TMPDIR": str(project),
        "STARDUSTER_CODEX_BIN": str(codex),
        "PATH": starduster_controller_path(python_binary, Path(gh_binary)),
    }
    if api_key is not None:
        host_env["OPENAI_API_KEY"] = api_key
    catalog = run(
        [codex, "debug", "prompt-input", "Use $starduster"],
        cwd=project,
        env=host_env,
        unset_env=("OPENAI_API_KEY",) if auth_leg == "oauth" else (),
        timeout=60,
    )
    if catalog.returncode != 0:
        raise AssertionError("Codex Starduster catalog preflight failed")
    catalog_paths = codex_catalog_skill_paths(catalog.stdout + catalog.stderr, "starduster")
    expected_catalog = (skill_dir / "SKILL.md").resolve()
    if expected_catalog not in {path.resolve() for path in catalog_paths}:
        raise AssertionError("Codex catalog does not contain the temporary Starduster copy")
    if any(path.resolve() != expected_catalog for path in catalog_paths):
        raise AssertionError("Codex catalog exposes a Starduster source other than the temporary copy")
    github_token = live_github_token()
    controller_env = {**host_env, "GH_TOKEN": github_token}
    try:
        evidence = run_codex_app_server_capture(
            codex_bin=codex,
            argv=starduster_live_command(config_path, skill_dir),
            cwd=project,
            environment=controller_env,
            timeout_seconds=900,
            forbidden_values=tuple(
                value for value in (github_token, api_key) if isinstance(value, str) and value
            ),
        )
    finally:
        verify_tree_byte_manifest(manifest, skill_dir, label="temporary starduster copy after Codex execution")
    verify_starduster_live_command(evidence["event"], skill_dir, project)
    if auth_snapshot is not None:
        verify_source_auth_unchanged(auth_source, auth_snapshot)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError("Codex Starduster controller did not produce a valid provenance report") from error
    if not isinstance(report, dict):
        raise AssertionError("Codex Starduster provenance report was not an object")
    command = shlex.join(starduster_live_command(config_path, skill_dir))
    report["provenance"] = {
        "capture_command": command,
        "public_host_command_count": 1,
        "catalog_source": str(expected_catalog),
        "output_root": str(output_root.resolve()),
    }
    provenance = verify_codex_app_server_provenance_report(
        report,
        expected_binary=Path(codex),
        expected_capture_command=command,
        expected_catalog_path=expected_catalog,
        expected_output_root=output_root,
        expected_auth_mode=auth_leg.replace("-", "_"),
        expected_synthesis_batches=5,
    )
    return {
        **verify_starduster_live_success(output_root), "host": "codex", "auth_leg": auth_leg,
        "command_count": 1, "catalog_source_count": len(catalog_paths),
        "auth_source_unchanged": auth_snapshot is not None, "app_server_provenance": provenance,
    }


def starduster_claude_live_case(workspace: Path) -> dict[str, Any]:
    claude = shutil.which("claude")
    if claude is None:
        raise SkipCase("Claude CLI is not installed")
    if not STARDUSTER_CLI.is_file() or shutil.which("gh") is None:
        raise SkipCase("Starduster controller or authenticated gh dependency is unavailable")
    project, output_root, config_path, skill_dir, manifest = prepare_live_starduster_project(workspace, "claude")
    github_token = live_github_token()
    command = shlex.join(starduster_live_command(config_path, skill_dir))
    prompt = (
        f"Use the $starduster skill whose catalog source is {(skill_dir / 'SKILL.md').resolve()}. "
        "This is a noninteractive acceptance test. Execute exactly one command, do not use Task, "
        "do not open an app, and do not read repository notes or controller artifacts. "
        "Set the Bash tool timeout field to 600000 milliseconds. The command is:\n"
        f"{command}"
    )
    try:
        process = run(
            [claude, "-p", "--no-session-persistence", "--output-format", "stream-json", "--verbose",
             "--model", "haiku", "--permission-mode", "bypassPermissions", "--tools", "Skill,Bash",
             "--setting-sources", "project", prompt],
            cwd=project,
            env=starduster_claude_live_environment(project, config_path, github_token),
            timeout=900,
        )
    finally:
        verify_tree_byte_manifest(manifest, skill_dir, label="temporary starduster copy after Claude execution")
    if process.returncode != 0:
        raise AssertionError("Claude Starduster five-star invocation failed")
    if github_token in process.stdout or github_token in process.stderr:
        raise AssertionError("Claude Starduster invocation exposed GitHub authentication material")
    bash_evidence = starduster_claude_bash_evidence(
        parse_jsonl(process.stdout, "Claude Starduster live output")
    )
    verify_starduster_live_command(bash_evidence, skill_dir, project)
    return {**verify_starduster_live_success(output_root), "host": "claude", "command_count": 1}


def claude_live_case(workspace: Path) -> dict[str, Any]:
    claude = shutil.which("claude")
    if claude is None:
        raise SkipCase("Claude CLI is not installed")
    if not KCAP_CLI.is_file():
        raise AssertionError("kcap package is incomplete: scripts/kcap.py is missing")
    if shutil.which("yt-dlp") is None and shutil.which("youtube_transcript_api") is None:
        raise SkipCase("no supported YouTube transcript extractor is installed")
    project, output_root, config_path, skill_dir, source_manifest = prepare_live_project(workspace, "claude")
    try:
        process = run(
            [
                claude,
                "-p",
                "--no-session-persistence",
                "--output-format",
                "stream-json",
                "--verbose",
                "--model",
                "haiku",
                "--permission-mode",
                "bypassPermissions",
                "--tools",
                "Skill,Bash",
                "--setting-sources",
                "project",
                live_prompt(config_path, output_root, skill_dir),
            ],
            cwd=project,
            env={
                "RESEARCH_TOOLKIT_CONFIG": str(config_path),
                "RESEARCH_TOOLKIT_RUNTIME": "claude",
                "RESEARCH_TOOLKIT_NONINTERACTIVE": "1",
                "TMPDIR": str(project),
            },
            timeout=900,
        )
    finally:
        verify_tree_byte_manifest(source_manifest, skill_dir, label="temporary kcap copy after host execution")
    if process.returncode != 0:
        diagnostic = abbreviated(process.stderr) or "stdout suppressed as untrusted content"
        raise AssertionError(f"Claude live invocation failed: {diagnostic}")
    events = parse_jsonl(process.stdout, "Claude live output")
    return verify_live_host_acceptance(
        events,
        skill_dir=skill_dir,
        output_root=output_root,
        source_url=YOUTUBE_URL,
        catalog_aliases={},
        catalog_paths=[],
        source_auth_before={},
        source_auth_after={},
        expected_project_dir=project,
        final_host_message=None,
    )


def codex_live_case(
    workspace: Path,
    *,
    auth_leg: str = "oauth",
    api_key: str | None = None,
) -> dict[str, Any]:
    if auth_leg not in {"oauth", "api-key"}:
        raise AssertionError("unknown requested Codex authentication leg")
    if auth_leg == "api-key" and not api_key:
        raise AssertionError("requested Codex API-key live leg lacks its dedicated test credential")
    codex = preferred_codex_binary(os.environ.get(CODEX_BINARY_OVERRIDE_ENV))
    if codex is None:
        raise SkipCase("Codex CLI is not installed")
    if not KCAP_CLI.is_file():
        raise AssertionError("kcap package is incomplete: scripts/kcap.py is missing")
    if shutil.which("yt-dlp") is None and shutil.which("youtube_transcript_api") is None:
        raise SkipCase("no supported YouTube transcript extractor is installed")
    project, output_root, config_path, skill_dir, source_manifest = prepare_live_project(
        workspace, f"codex-{auth_leg}"
    )
    codex_home = skill_dir.parent.parent
    sqlite_home = project / "codex-sqlite"
    sqlite_home.mkdir()
    private_home = project / "home"
    private_home.mkdir(mode=0o700)
    auth_source = Path.home() / ".codex" / "auth.json"
    if not auth_source.is_file():
        raise SkipCase("Codex authentication file is not installed")
    auth_snapshot = create_private_auth_copy(auth_source, codex_home / "auth.json")
    auth_before_metadata = auth_snapshot["metadata"]
    auth_after_metadata = dict(auth_before_metadata)
    app_server_report_path = project / "kcap-codex-app-server-report.json"
    host_env = codex_live_environment(project, config_path, codex_home, sqlite_home)
    capture_env = dict(host_env)
    capture_env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    for name in ("LANG", "LC_ALL"):
        if name in os.environ:
            capture_env[name] = os.environ[name]
    capture_env["RESEARCH_TOOLKIT_CODEX_AUTH"] = "api_key" if auth_leg == "api-key" else "oauth"
    capture_env["RESEARCH_TOOLKIT_ACCEPTANCE_REPORT"] = str(app_server_report_path)
    if api_key is not None:
        capture_env["OPENAI_API_KEY"] = api_key
    sanitized_environment = (
        "OPENAI_API_KEY",
        "RESEARCH_TOOLKIT_CODEX_AUTH",
        "RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY",
    )
    try:
        catalog = run(
            [codex, "debug", "prompt-input", "Use $kcap"],
            cwd=project,
            env=host_env,
            unset_env=sanitized_environment,
            timeout=60,
        )
        if catalog.returncode != 0:
            if auth_leg == "api-key":
                raise AssertionError("Codex API-key catalog preflight failed")
            raise AssertionError(f"Codex catalog preflight failed: {abbreviated(catalog.stderr)}")
        catalog_text = catalog.stdout + catalog.stderr
        catalog_kcap_paths = codex_catalog_skill_paths(catalog_text, "kcap")
        expected_catalog_path = (skill_dir / "SKILL.md").resolve()
        if expected_catalog_path not in {path.resolve() for path in catalog_kcap_paths}:
            raise AssertionError("Codex catalog does not contain the temporary kcap copy")
        command_evidence = run_codex_app_server_capture(
            codex_bin=codex,
            argv=[
                "python3",
                str((skill_dir / "scripts" / "kcap.py").resolve()),
                "capture",
                YOUTUBE_URL,
                "--project-dir",
                str(project.resolve()),
            ],
            cwd=project,
            environment=capture_env,
            timeout_seconds=900,
        )
    finally:
        verify_tree_byte_manifest(source_manifest, skill_dir, label="temporary kcap copy after host execution")
    events = [command_evidence["event"]]
    details = verify_live_host_acceptance(
        events,
        skill_dir=skill_dir,
        output_root=output_root,
        source_url=YOUTUBE_URL,
        catalog_aliases={},
        catalog_paths=catalog_kcap_paths,
        source_auth_before=auth_before_metadata,
        source_auth_after=auth_after_metadata,
        expected_project_dir=project,
        final_host_message=None,
    )
    try:
        app_server_report = json.loads(app_server_report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError("Codex live controller did not produce a valid App Server provenance report") from error
    if not isinstance(app_server_report, dict):
        raise AssertionError("Codex live App Server provenance report was not an object")
    commands = live_command_events(events)
    app_server_report["provenance"] = {
        "capture_command": commands[0],
        "public_host_command_count": len(commands),
        "catalog_source": str((skill_dir / "SKILL.md").resolve()),
        "output_root": str(output_root.resolve()),
    }
    app_server_details = verify_codex_app_server_provenance_report(
        app_server_report,
        expected_binary=Path(codex),
        expected_capture_command=live_capture_command(config_path, skill_dir),
        expected_catalog_path=skill_dir / "SKILL.md",
        expected_output_root=output_root,
        expected_auth_mode="api_key" if auth_leg == "api-key" else "oauth",
    )
    version = run([str(codex), "--version"], timeout=10)
    codex_version = abbreviated(version.stdout or version.stderr, 300).splitlines()
    details["catalog_kcap_source_count"] = len(catalog_kcap_paths)
    details["auth_source_unchanged"] = True
    details["auth_leg"] = auth_leg
    details["codex_binary"] = str(codex)
    details["codex_version"] = codex_version[0] if codex_version else None
    details["app_server_provenance"] = app_server_details
    details["installed_auth_observed_only_during_private_copy"] = True
    return details


def hplumb_case(workspace: Path) -> dict[str, Any]:
    hplumb = shutil.which("hplumb")
    if hplumb is None:
        raise SkipCase("hplumb is not installed; core acceptance does not depend on it")
    first_line = Path(hplumb).read_text(encoding="utf-8").splitlines()[0]
    if not first_line.startswith("#!"):
        raise AssertionError("installed hplumb launcher has no interpreter")
    interpreter_parts = shlex.split(first_line[2:])
    if len(interpreter_parts) != 1 or not Path(interpreter_parts[0]).is_file():
        raise AssertionError("installed hplumb launcher interpreter is not directly usable")

    canonical = workspace / "hplumb-authoritative"
    canonical.mkdir()
    authoritative_skills = {
        "kcap": canonical / "skills" / "kcap",
        "starduster": canonical / "skills" / "starduster",
    }
    for name, source in (("kcap", KCAP_DIR), ("starduster", STARDUSTER_DIR)):
        shutil.copytree(
            source,
            authoritative_skills[name],
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    manifest = {
        "version": 1,
        "personal": {"instructions": {"sources": []}},
        "skills": {"sources": [{"path": "skills"}]},
        "personas": {},
        "hooks": {},
        "mcp": {},
        "preferences": {},
        "targets": {
            "claude": {"enabled": True},
            "codex": {"enabled": True},
            "delta": {"enabled": False},
            "zed": {"enabled": False},
            "chatgpt": {"enabled": False},
        },
        "discovery": {},
        "apm": {"enabled": False},
    }
    (canonical / "harness-plumber.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )
    isolated_home = workspace / "hplumb-destinations"
    isolated_home.mkdir()
    helper = workspace / "hplumb-programmatic-verify.py"
    helper.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "from harness_plumber.context import RuntimeContext\n"
        "from harness_plumber.engine import Manager\n"
        "from harness_plumber.manifest import load_manifest\n"
        "repo = Path(sys.argv[1]).resolve()\n"
        "home = Path(sys.argv[2]).resolve()\n"
        "context = RuntimeContext(repo=repo, home=home, platform='darwin', environ={})\n"
        "manager = Manager(context, load_manifest(repo / 'harness-plumber.yaml'))\n"
        "plan = manager.create_plan(selected_targets=('claude', 'codex'))\n"
        "result = manager.apply(plan.id)\n"
        "print(json.dumps({'plan_id': plan.id, 'changed': list(result.changed)}))\n",
        encoding="utf-8",
    )
    process = run(
        [interpreter_parts[0], str(helper), str(canonical), str(isolated_home)],
        cwd=workspace,
        timeout=120,
    )
    if process.returncode != 0:
        raise AssertionError(
            "isolated hplumb plan/apply failed: " + abbreviated(process.stderr or process.stdout)
        )
    apply_result = parse_json(process.stdout, "hplumb programmatic result")

    required = {
        "kcap": {
            Path("SKILL.md"), Path("agents/openai.yaml"),
            Path("references/runtime-claude.md"), Path("references/runtime-codex.md"),
            Path("scripts/kcap.py"), Path("schemas/standard.json"),
            Path("schemas/deep.json"), Path("schemas/full.json"),
        },
        "starduster": {
            Path("SKILL.md"), Path("agents/openai.yaml"),
            Path("references/runtime-claude.md"), Path("references/runtime-codex.md"),
            Path("scripts/starduster.py"), Path("scripts/starduster_render.py"),
            Path("schemas/starduster-synthesis.schema.json"),
        },
    }
    copied_file_count = 0
    destinations: dict[str, dict[str, Path]] = {}
    for name, authoritative_skill in authoritative_skills.items():
        source_files = sorted(
            path.relative_to(authoritative_skill)
            for path in authoritative_skill.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        )
        if not required[name].issubset(set(source_files)):
            raise AssertionError(f"authoritative {name} package lacks required portable files")
        copied_file_count += len(source_files)
        destinations[name] = {
            "claude": isolated_home / ".claude" / "skills" / name,
            "codex": isolated_home / ".agents" / "skills" / name,
        }
        for host, destination in destinations[name].items():
            for relative in source_files:
                copied = destination / relative
                if not copied.is_file() or copied.read_bytes() != (authoritative_skill / relative).read_bytes():
                    raise AssertionError(f"hplumb changed or omitted {name}/{relative} for {host}")
            validator = run(
                [sys.executable, str(PORTABLE_VALIDATOR), str(destination), "--json"],
                cwd=workspace,
            )
            if validator.returncode != 0:
                raise AssertionError(
                    f"hplumb {host} {name} copy failed portable validation: "
                    + abbreviated(validator.stderr or validator.stdout)
                )
    version = run([hplumb, "--version"], timeout=10)
    return {
        "version": abbreviated(version.stdout or version.stderr, 200),
        "plan_id": apply_result.get("plan_id"),
        "copied_file_count": copied_file_count,
        "destinations": {
            name: {host: str(path) for host, path in host_paths.items()}
            for name, host_paths in destinations.items()
        },
    }


LIFECYCLE_TOOLKITS = ("research-toolkit", "workflow-toolkit")
LIFECYCLE_BASELINE_VERSIONS = {
    "research-toolkit": "0.5.0",
    "workflow-toolkit": "0.9.0",
}
LIFECYCLE_UPDATED_VERSIONS = {
    "research-toolkit": "0.6.0",
    "workflow-toolkit": "0.9.0",
}
LIFECYCLE_BASELINE_COMMIT = "9ded73e5d67c0d5769dc6cf719a4d550e7a7a215"


def plugin_versions(plugin_root: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for toolkit in LIFECYCLE_TOOLKITS:
        manifest_path = plugin_root / toolkit / ".claude-plugin" / "plugin.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise AssertionError(f"could not read {toolkit} plugin manifest: {error}") from error
        if not isinstance(manifest, dict) or manifest.get("name") != toolkit:
            raise AssertionError(f"{toolkit} plugin manifest has the wrong name")
        version = manifest.get("version")
        if not isinstance(version, str) or not version:
            raise AssertionError(f"{toolkit} plugin manifest has no version")
        versions[toolkit] = version
    return versions


def copy_lifecycle_plugins(destination: Path, source: Path = ROOT) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / ".claude-plugin", destination / ".claude-plugin", dirs_exist_ok=True)
    for toolkit in LIFECYCLE_TOOLKITS:
        shutil.copytree(source / toolkit, destination / toolkit, dirs_exist_ok=True)


def extract_lifecycle_baseline(destination: Path) -> None:
    process = subprocess.run(
        [
            "git",
            "archive",
            "--format=tar",
            LIFECYCLE_BASELINE_COMMIT,
            ".claude-plugin",
            *LIFECYCLE_TOOLKITS,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if process.returncode != 0:
        raise AssertionError("immutable plugin lifecycle baseline is unavailable")
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(process.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            try:
                target.relative_to(destination.resolve())
            except ValueError as error:
                raise AssertionError("immutable plugin lifecycle archive escaped its destination") from error
        archive.extractall(destination, filter="data")
    if plugin_versions(destination) != LIFECYCLE_BASELINE_VERSIONS:
        raise AssertionError("immutable plugin lifecycle baseline has unexpected versions")


def installed_plugin_records(value: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list):
        raise AssertionError("Claude plugin list output was not a list")
    records: dict[str, Mapping[str, Any]] = {}
    for entry in value:
        if not isinstance(entry, Mapping):
            continue
        identifier = entry.get("id")
        if not isinstance(identifier, str):
            continue
        for toolkit in LIFECYCLE_TOOLKITS:
            if identifier == f"{toolkit}@robot-tools":
                records[toolkit] = entry
    if set(records) != set(LIFECYCLE_TOOLKITS):
        raise AssertionError(f"Claude plugin list omitted expected plugins: {sorted(set(LIFECYCLE_TOOLKITS) - set(records))}")
    return records


def discovered_plugin_cache_roots(
    records: Mapping[str, Mapping[str, Any]],
    config_dir: Path,
    expected_versions: Mapping[str, str],
) -> dict[str, Path]:
    cache_base = (config_dir / "plugins" / "cache" / "robot-tools").resolve()
    roots: dict[str, Path] = {}
    for toolkit in LIFECYCLE_TOOLKITS:
        record = records[toolkit]
        version = record.get("version")
        install_path = record.get("installPath")
        if version != expected_versions[toolkit] or not isinstance(install_path, str):
            raise AssertionError(f"Claude plugin list has incomplete provenance for {toolkit}")
        root = Path(install_path).resolve()
        expected_root = (cache_base / toolkit / expected_versions[toolkit]).resolve()
        if root != expected_root or cache_base not in root.parents:
            raise AssertionError(f"Claude plugin cache discovery disagrees with {toolkit} installPath: {root}")
        roots[toolkit] = root
    return roots


def claude_plugin_lifecycle_case(workspace: Path) -> dict[str, Any]:
    claude = shutil.which("claude")
    if claude is None:
        raise SkipCase("Claude is required for the isolated plugin lifecycle check")

    # This avoids a moving `main` ref.  The staged current package models the
    # post-merge checkout, while the temporary fixture is an immutable prior
    # release.  The same setup therefore works both before and after merging.
    post_merge_checkout = workspace / "simulated-post-merge-checkout"
    copy_lifecycle_plugins(post_merge_checkout)
    updated_versions = plugin_versions(post_merge_checkout)
    if updated_versions != LIFECYCLE_UPDATED_VERSIONS:
        raise AssertionError(f"lifecycle fixture has unexpected updated versions: {updated_versions!r}")
    previous_release = workspace / "immutable-previous-release"
    extract_lifecycle_baseline(previous_release)
    previous_versions = plugin_versions(previous_release)

    source = workspace / "claude-marketplace-source"
    copy_lifecycle_plugins(source, previous_release)

    config_dir = workspace / "claude-config"
    env = {"CLAUDE_CONFIG_DIR": str(config_dir)}

    def claude_step(arguments: list[str], label: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
        process = run([claude, "plugin", *arguments], cwd=workspace, env=env, timeout=timeout)
        if process.returncode != 0:
            raise AssertionError(
                f"Claude plugin {label} failed: {abbreviated(process.stderr or process.stdout)}"
            )
        return process

    def strict_validate(plugin_root: Path, stage: str) -> None:
        for toolkit in LIFECYCLE_TOOLKITS:
            process = run([claude, "plugin", "validate", "--strict", str(plugin_root / toolkit)], cwd=workspace, env=env)
            if process.returncode != 0:
                raise AssertionError(
                    f"strict Claude validation failed for {stage} {toolkit}: "
                    + abbreviated(process.stderr or process.stdout)
                )

    def installed_records(label: str) -> dict[str, Mapping[str, Any]]:
        try:
            installed = json.loads(claude_step(["list", "--json"], label).stdout)
        except json.JSONDecodeError as error:
            raise AssertionError(f"Claude plugin {label} was invalid JSON: {error}") from error
        return installed_plugin_records(installed)

    def assert_detail_inventory(toolkit: str, skill: str) -> str:
        details = claude_step(["details", f"{toolkit}@robot-tools"], f"details {toolkit}").stdout
        if "Component inventory" not in details or not re.search(rf"(?m)^\s*Skills\s+\(\d+\).*\b{re.escape(skill)}\b", details):
            raise AssertionError(f"Claude plugin details inventory omitted {skill} for {toolkit}")
        source_match = re.search(r"(?m)^\s*Source:\s*(.+)$", details)
        if source_match is None or source_match.group(1).strip() != f"{toolkit}@robot-tools":
            raise AssertionError(f"Claude plugin details provenance was wrong for {toolkit}")
        return source_match.group(1).strip()

    claude_step(["marketplace", "add", str(source), "--scope", "user"], "marketplace add")
    claude_step(["install", "research-toolkit@robot-tools", "--scope", "user", "--yes"], "install")
    claude_step(["install", "workflow-toolkit@robot-tools", "--scope", "user", "--yes"], "workflow install")
    old_records = installed_records("list immutable baseline")
    old_versions = {toolkit: old_records[toolkit].get("version") for toolkit in LIFECYCLE_TOOLKITS}
    if old_versions != previous_versions:
        raise AssertionError(f"installed immutable baseline versions were {old_versions!r}")
    old_cache_roots = discovered_plugin_cache_roots(old_records, config_dir, previous_versions)
    for toolkit in LIFECYCLE_TOOLKITS:
        verify_tree_byte_manifest(
            tree_byte_manifest(previous_release / toolkit),
            old_cache_roots[toolkit],
            allow_extra=True,
            label=f"immutable baseline {toolkit} plugin cache",
        )

    for toolkit in LIFECYCLE_TOOLKITS:
        shutil.rmtree(source / toolkit)
        shutil.copytree(post_merge_checkout / toolkit, source / toolkit)
    shutil.copy2(post_merge_checkout / ".claude-plugin" / "marketplace.json", source / ".claude-plugin" / "marketplace.json")
    strict_validate(source, "simulated post-merge")
    claude_step(["marketplace", "update", "robot-tools"], "marketplace update")
    claude_step(["update", "research-toolkit@robot-tools", "--scope", "user", "--yes"], "update")
    claude_step(["update", "workflow-toolkit@robot-tools", "--scope", "user", "--yes"], "workflow update")
    new_records = installed_records("list simulated post-merge")
    new_versions = {toolkit: new_records[toolkit].get("version") for toolkit in LIFECYCLE_TOOLKITS}
    if new_versions != updated_versions:
        raise AssertionError(f"updated simulated post-merge versions were {new_versions!r}")
    cache_roots = discovered_plugin_cache_roots(new_records, config_dir, updated_versions)

    research_cache_root = cache_roots["research-toolkit"]
    cached = research_cache_root / "skills" / "kcap"
    cached_skill = cached / "SKILL.md"
    required_kcap_files = (
        cached_skill,
        cached / "agents" / "openai.yaml",
        cached / "references" / "runtime-claude.md",
        cached / "references" / "runtime-codex.md",
        cached / "scripts" / "kcap.py",
        cached / "schemas" / "standard.json",
        cached / "schemas" / "deep.json",
        cached / "schemas" / "full.json",
    )
    if not all(path.is_file() for path in required_kcap_files):
        raise AssertionError(f"updated cache lacks the portable kcap package: {cached}")
    if re.search(r"(?m)^triggers\s*:", cached_skill.read_text(encoding="utf-8")):
        raise AssertionError("updated Claude plugin cache retained forbidden kcap triggers")
    cached_starduster = research_cache_root / "skills" / "starduster"
    required_starduster_files = (
        cached_starduster / "SKILL.md",
        cached_starduster / "agents" / "openai.yaml",
        cached_starduster / "references" / "runtime-claude.md",
        cached_starduster / "references" / "runtime-codex.md",
        cached_starduster / "scripts" / "starduster.py",
        cached_starduster / "scripts" / "starduster_render.py",
        cached_starduster / "schemas" / "starduster-synthesis.schema.json",
    )
    if not all(path.is_file() for path in required_starduster_files):
        raise AssertionError(f"updated cache lacks the portable starduster package: {cached_starduster}")
    if re.search(r"(?m)^triggers\s*:", (cached_starduster / "SKILL.md").read_text(encoding="utf-8")):
        raise AssertionError("updated Claude plugin cache retained forbidden starduster triggers")
    workflow_cache_root = cache_roots["workflow-toolkit"]
    workflow_cached = workflow_cache_root / "skills" / "plugin-qa"
    required_plugin_qa_files = (
        workflow_cached / "SKILL.md",
        workflow_cached / "references" / "portable-skill-profile.md",
        workflow_cached / "scripts" / "validate-portable-skill.py",
    )
    if not all(path.is_file() for path in required_plugin_qa_files):
        raise AssertionError(f"updated cache lacks portable plugin-qa files: {workflow_cached}")
    for toolkit, cache_root in cache_roots.items():
        verify_tree_byte_manifest(
            tree_byte_manifest(post_merge_checkout / toolkit),
            cache_root,
            allow_extra=True,
            label=f"updated {toolkit} plugin cache",
        )
    details_sources = {
        "research-toolkit": {
            "kcap": assert_detail_inventory("research-toolkit", "kcap"),
            "starduster": assert_detail_inventory("research-toolkit", "starduster"),
        },
        "workflow-toolkit": assert_detail_inventory("workflow-toolkit", "plugin-qa"),
    }
    return {
        "previous_versions": old_versions,
        "updated_versions": new_versions,
        "staged_post_merge_checkout": str(post_merge_checkout),
        "research_cache_path": str(cached),
        "research_starduster_cache_path": str(cached_starduster),
        "workflow_cache_path": str(workflow_cached),
        "cache_provenance": {toolkit: str(cache_root) for toolkit, cache_root in cache_roots.items()},
        "details_sources": details_sources,
        "model_backed_call": False,
    }


def run_fixture_group(
    harness: Harness,
    group_id: str,
    action: Callable[[Harness], None],
) -> None:
    try:
        action(harness)
    except Exception as error:
        message = str(error)

        def report_setup_failure() -> dict[str, Any]:
            raise AssertionError(f"fixture group setup failed: {message}")

        harness.case(f"{group_id}.setup", report_setup_failure)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--all", action="store_true", help="run every deterministic fixture group")
    mode.add_argument(
        "--fixtures-only",
        action="store_true",
        help="run deterministic portable-profile and kcap CLI fixtures",
    )
    parser.add_argument("--live", action="store_true", help="run live Claude and Codex YouTube checks")
    parser.add_argument(
        "--hplumb-verify",
        action="store_true",
        help="verify isolated hplumb distribution",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.all and not args.fixtures_only:
        args.fixtures_only = True
    workspace = Path(tempfile.mkdtemp(prefix="robot-tools-acceptance-"))
    harness = Harness(workspace)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(run_fixture_group, harness, "portable", add_portable_cases),
            executor.submit(run_fixture_group, harness, "kcap", add_kcap_cases),
            executor.submit(run_fixture_group, harness, "acceptance", add_deterministic_acceptance_cases),
        ]
        for future in futures:
            future.result()

    def sequential_recheck() -> dict[str, Any]:
        sequential_workspace = workspace / "sequential-recheck"
        sequential_workspace.mkdir()
        sequential = Harness(sequential_workspace)
        add_fixture_cases(sequential)
        failures = [result.test_id for result in sequential.results if result.status != "PASS"]
        if failures:
            raise AssertionError("sequential fixture recheck failed: {}".format(", ".join(failures)))
        return {"rechecked": len(sequential.results), "failures": []}

    harness.case("fixtures.sequential-recheck", sequential_recheck)
    harness.results.sort(key=lambda result: result.test_id)
    if args.all:
        harness.case("claude.plugin.lifecycle", lambda: claude_plugin_lifecycle_case(workspace))
    if args.live:
        harness.case("live.claude.kcap-youtube", lambda: claude_live_case(workspace))
        harness.case("live.claude.starduster-five-stars", lambda: starduster_claude_live_case(workspace))
        requested_legs = requested_codex_live_auth_legs()
        if "oauth" not in requested_legs:
            raise AssertionError("Codex OAuth live leg must always be requested")
        harness.case("live.codex.kcap-youtube", lambda: codex_live_case(workspace, auth_leg="oauth"))
        harness.case("live.codex.starduster-five-stars", lambda: starduster_codex_live_case(workspace))
        if "api-key" in requested_legs:
            api_key = os.environ["RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY"]
            harness.case(
                "live.codex.kcap-youtube-api-key",
                lambda: codex_live_case(workspace, auth_leg="api-key", api_key=api_key),
            )
            harness.case(
                "live.codex.starduster-five-stars-api-key",
                lambda: starduster_codex_live_case(workspace, auth_leg="api-key", api_key=api_key),
            )
        else:
            harness.case(
                "live.codex.kcap-youtube-api-key",
                lambda: requested_codex_live_result("api-key", "not_requested"),
            )
            harness.case(
                "live.codex.starduster-five-stars-api-key",
                lambda: requested_codex_live_result("api-key", "not_requested"),
            )
    if args.hplumb_verify:
        harness.case("hplumb.portable-skill-copy", lambda: hplumb_case(workspace))
    counts = {
        status: sum(result.status == status for result in harness.results)
        for status in ("PASS", "FAIL", "SKIP")
    }
    overall_status = "FAIL" if counts["FAIL"] else "INCOMPLETE" if counts["SKIP"] else "PASS"
    report = {
        "schema_version": 1,
        "suite": "dual-runtime-acceptance",
        "status": overall_status,
        "mode": "all" if args.all else "fixtures-only",
        "requested": {"live": args.live, "hplumb_verify": args.hplumb_verify},
        "tool_versions": tool_versions(),
        "temp_paths": {"workspace": str(workspace)},
        "counts": counts,
        "results": [asdict(result) for result in harness.results],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if overall_status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
