#!/usr/bin/env python3
"""Run a predeclared, computation-only security-analyzer check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from typing import Any
import unicodedata


ADAPTER_NAME = "security-vuln-analyzer-deterministic-check"
ADAPTER_VERSION = "1.0.0"
MAX_OUTPUT_BYTES = 65_536
FINAL_STATUSES = {
    "CROSS-MODEL VERIFIED",
    "REFUTED",
    "DISPUTED",
    "NOT VERIFIED",
    "INCOMPLETE",
}


class RequestError(ValueError):
    pass


def load_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RequestError(f"cannot read JSON object: {path}: {error}") from error
    return parse_object(raw, str(path))


def parse_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RequestError(f"cannot parse JSON object: {label}: {error}") from error
    if not isinstance(value, dict):
        raise RequestError(f"JSON root must be an object: {label}")
    return value


def required_string(value: dict[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise RequestError(f"{key} must be a non-empty string")
    return item


def canonical_relative_path(raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in raw.split("/")):
        raise RequestError("relative_path must be a canonical relative path")
    return path


def contained_path(root: Path, relative: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved_path = (resolved_root / relative).resolve(strict=True)
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise RequestError("path escapes checkout root")
    return resolved_path


def checkout_revision(checkout: Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    if process.returncode != 0:
        raise RequestError("checkout revision could not be read")
    return process.stdout.strip()


def normalized_line_slice(path: Path, start_line: int, end_line: int) -> bytes:
    if start_line < 1 or end_line < start_line:
        raise RequestError("line range must be positive and ordered")
    try:
        raw = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise RequestError(f"source slice is not readable UTF-8: {error}") from error
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.splitlines(keepends=True)
    if end_line > len(lines):
        raise RequestError("line range exceeds source file")
    return "".join(lines[start_line - 1 : end_line]).encode("utf-8")


def normalized_proposition_digest(proposition: str) -> str:
    normalized = unicodedata.normalize("NFC", proposition).replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def validate_routing_table(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise RequestError("routing_table must be an array")
    table: list[dict[str, str]] = []
    seen_results: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"literal_result", "final_status"}:
            raise RequestError("routing_table entries must contain only literal_result and final_status")
        literal_result = entry.get("literal_result")
        final_status = entry.get("final_status")
        if not isinstance(literal_result, str) or final_status not in FINAL_STATUSES:
            raise RequestError("routing_table entry is invalid")
        if literal_result in seen_results:
            raise RequestError("routing_table literal_result keys must be unique")
        seen_results.add(literal_result)
        table.append({"literal_result": literal_result, "final_status": final_status})
    return table


def base_result(request: dict[str, Any], routing_table: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "role_type": "computation",
        "status": "COMPLETE",
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "packet_revision": required_string(request, "packet_revision"),
        "candidate_id": required_string(request, "candidate_id"),
        "proposition": required_string(request, "proposition"),
        "check_id": required_string(request, "check_id"),
        "check_kind": required_string(request, "check_kind"),
        "repository": required_string(request, "repository"),
        "target_revision": required_string(request, "target_revision"),
        "relative_path": "",
        "start_line": 0,
        "end_line": 0,
        "expected_sha256": "",
        "registry_sha256": "",
        "frozen_test_id": "",
        "executed_argv": [],
        "tool_version": sys.version.split()[0],
        "bounded_output": "",
        "exit_status": 0,
        "literal_check_result": "NOT_RUN",
        "routing_table": routing_table,
    }


def run_source_slice(request: dict[str, Any], checkout: Path, result: dict[str, Any]) -> None:
    if any(entry["final_status"] != "DISPUTED" for entry in result["routing_table"]):
        raise RequestError("SOURCE_SLICE_SHA256 routing may only preserve DISPUTED")
    relative_path = canonical_relative_path(required_string(request, "relative_path"))
    start_line = request.get("start_line")
    end_line = request.get("end_line")
    expected = required_string(request, "expected_sha256")
    if not isinstance(start_line, int) or not isinstance(end_line, int):
        raise RequestError("start_line and end_line must be integers")
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise RequestError("expected_sha256 must be 64 lowercase hexadecimal characters")
    actual = hashlib.sha256(normalized_line_slice(contained_path(checkout, relative_path), start_line, end_line)).hexdigest()
    result.update(
        {
            "relative_path": relative_path.as_posix(),
            "start_line": start_line,
            "end_line": end_line,
            "expected_sha256": expected,
            "bounded_output": actual,
            "literal_check_result": "MATCHED" if actual == expected else "NOT_MATCHED",
        }
    )


def run_frozen_test(
    request: dict[str, Any], checkout: Path, registry: dict[str, Any], registry_sha256: str, result: dict[str, Any]
) -> None:
    if required_string(request, "registry_sha256") != registry_sha256:
        result.update({"status": "FAILED", "literal_check_result": "NOT_RUN"})
        return
    result["registry_sha256"] = registry_sha256
    frozen_test_id = required_string(request, "frozen_test_id")
    tests = registry.get("tests")
    if not isinstance(tests, dict) or not isinstance(tests.get(frozen_test_id), dict):
        result.update({"status": "FAILED", "frozen_test_id": frozen_test_id, "literal_check_result": "NOT_RUN"})
        return
    frozen = tests[frozen_test_id]
    if frozen.get("repository") != result["repository"] or frozen.get("revision") != result["target_revision"]:
        result.update({"status": "FAILED", "frozen_test_id": frozen_test_id, "literal_check_result": "NOT_RUN"})
        return
    if frozen.get("proposition_sha256") != normalized_proposition_digest(result["proposition"]):
        result.update({"status": "FAILED", "frozen_test_id": frozen_test_id, "literal_check_result": "NOT_RUN"})
        return
    registered_routing_table = validate_routing_table(frozen.get("routing_table"))
    if registered_routing_table != result["routing_table"]:
        result.update({"status": "FAILED", "frozen_test_id": frozen_test_id, "literal_check_result": "NOT_RUN"})
        return
    argv = frozen.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) and item for item in argv):
        raise RequestError("frozen test argv must be a non-empty string array")
    raw_working_directory = frozen.get("working_directory")
    if raw_working_directory == ".":
        cwd = checkout
    elif isinstance(raw_working_directory, str):
        cwd = contained_path(checkout, canonical_relative_path(raw_working_directory))
    else:
        raise RequestError("frozen test working_directory must be a string")
    if not cwd.is_dir():
        raise RequestError("frozen test working_directory must be a directory")
    timeout_seconds = frozen.get("timeout_seconds")
    expected_exit_status = frozen.get("expected_exit_status")
    expected_stdout_sha256 = frozen.get("expected_stdout_sha256", "")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 600:
        raise RequestError("frozen test timeout_seconds must be between 1 and 600")
    if not isinstance(expected_exit_status, int):
        raise RequestError("frozen test expected_exit_status must be an integer")
    if expected_stdout_sha256 and (
        not isinstance(expected_stdout_sha256, str)
        or len(expected_stdout_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_stdout_sha256)
    ):
        raise RequestError("frozen test expected_stdout_sha256 is invalid")
    environment = frozen.get("environment", {})
    if not isinstance(environment, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
    ):
        raise RequestError("frozen test environment must be a string map")
    process = None
    selector = None
    group_terminated = False
    try:
        popen_options: dict[str, Any] = {}
        if os.name == "posix":
            popen_options["start_new_session"] = True
        elif os.name == "nt":
            popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            result.update(
                {
                    "status": "FAILED",
                    "frozen_test_id": frozen_test_id,
                    "bounded_output": "process-group isolation is unavailable",
                    "exit_status": -1,
                    "literal_check_result": "NOT_RUN",
                }
            )
            return
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **popen_options,
        )
        if process.stdout is None or process.stderr is None:
            raise RequestError("frozen test output pipe is unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        captured = {"stdout": bytearray(), "stderr": bytearray()}
        output_bytes = 0
        deadline = time.monotonic() + timeout_seconds
        limit_exceeded = False
        timed_out = False
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                terminate_process_group(process)
                group_terminated = True
                break
            events = selector.select(min(remaining, 0.25))
            for key, _ in events:
                chunk = os.read(key.fd, min(65_536, MAX_OUTPUT_BYTES - output_bytes + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(chunk)
                output_bytes += len(chunk)
                if output_bytes > MAX_OUTPUT_BYTES:
                    limit_exceeded = True
                    terminate_process_group(process)
                    group_terminated = True
                    break
            if limit_exceeded:
                break
        if not timed_out and not limit_exceeded:
            remaining = deadline - time.monotonic()
            try:
                process.wait(timeout=max(0.0, remaining))
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process_group(process)
                group_terminated = True
        process.wait(timeout=5)
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if timed_out or limit_exceeded:
            reason = "timeout exceeded" if timed_out else "output limit exceeded"
            result.update(
                {
                    "status": "FAILED",
                    "frozen_test_id": frozen_test_id,
                    "executed_argv": argv,
                    "bounded_output": reason,
                    "exit_status": process.returncode if process.returncode is not None else -1,
                    "literal_check_result": "NOT_RUN",
                }
            )
            return
        stdout = bytes(captured["stdout"])
        stderr = bytes(captured["stderr"])
        output_digest = hashlib.sha256(stdout).hexdigest()
        bounded = stdout if not stderr else b"[stdout]\n" + stdout + b"\n[stderr]\n" + stderr
        passed = process.returncode == expected_exit_status and (
            not expected_stdout_sha256 or output_digest == expected_stdout_sha256
        )
        result.update(
            {
                "frozen_test_id": frozen_test_id,
                "executed_argv": argv,
                "tool_version": str(frozen.get("tool_version", "unrecorded")),
                "bounded_output": bounded.decode("utf-8", errors="replace"),
                "exit_status": process.returncode,
                "literal_check_result": "PASSED" if passed else "FAILED",
            }
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        result.update(
            {
                "status": "FAILED",
                "frozen_test_id": frozen_test_id,
                "executed_argv": argv,
                "bounded_output": str(error)[:MAX_OUTPUT_BYTES],
                "exit_status": -1,
                "literal_check_result": "NOT_RUN",
            }
        )
    finally:
        if process is not None:
            if not group_terminated:
                terminate_process_group(process)
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
        if selector is not None:
            selector.close()


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    else:
        process.kill()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--registry", type=Path)
    args = parser.parse_args()

    try:
        request = load_object(args.request)
        routing_table = validate_routing_table(request.get("routing_table"))
        result = base_result(request, routing_table)
        checkout = args.checkout.resolve(strict=True)
        if checkout_revision(checkout) != result["target_revision"]:
            raise RequestError("checkout HEAD does not equal target_revision")
        if result["check_kind"] == "SOURCE_SLICE_SHA256":
            run_source_slice(request, checkout, result)
        elif result["check_kind"] == "FROZEN_TEST_REFERENCE":
            if args.registry is None:
                raise RequestError("--registry is required for FROZEN_TEST_REFERENCE")
            try:
                registry_bytes = args.registry.read_bytes()
            except OSError as error:
                raise RequestError(f"cannot read registry: {error}") from error
            run_frozen_test(
                request,
                checkout,
                parse_object(registry_bytes, str(args.registry)),
                hashlib.sha256(registry_bytes).hexdigest(),
                result,
            )
        else:
            raise RequestError("unsupported check_kind")
    except (RequestError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "FAILED", "adapter": ADAPTER_NAME, "adapter_version": ADAPTER_VERSION, "error": str(error)}, sort_keys=True))
        return 2

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "COMPLETE" else 3


if __name__ == "__main__":
    raise SystemExit(main())
