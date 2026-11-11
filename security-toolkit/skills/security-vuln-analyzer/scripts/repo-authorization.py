#!/usr/bin/env python3
"""Check the repository permission that authorizes a security-vuln-analyzer run.

The check is deterministic: it reads the caller's permission for OWNER/REPO from
`gh api repos/OWNER/REPO` (or from a captured copy of that response) and authorizes the
run only for admin, maintain, or push. Advisory collaboration alone is not enough,
because reporters are automatically advisory collaborators. There is no verbal or
interactive override.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

ADAPTER_NAME = "security-vuln-analyzer-repo-authorization"
ADAPTER_VERSION = "1.0.0"
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
AUTHORIZING_PERMISSIONS = ("admin", "maintain", "push")
EXIT_AUTHORIZED = 0
EXIT_USAGE = 2
EXIT_NOT_AUTHORIZED = 4


def result(repository: str, authorized: bool, basis: str, check: str, reason: str) -> dict[str, Any]:
    return {
        "adapter": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "repository": repository,
        "authorized": authorized,
        "basis": basis,
        "failed_check": "" if authorized else check,
        "reason": reason,
    }


def evaluate(repository: str, response: Any) -> dict[str, Any]:
    if not isinstance(response, dict):
        return result(repository, False, "", "response_shape", "the repository API response is not a JSON object")
    full_name = response.get("full_name")
    if not isinstance(full_name, str) or full_name.lower() != repository.lower():
        return result(
            repository, False, "", "repository_identity",
            f"the API response names {full_name!r}, not the requested repository",
        )
    permissions = response.get("permissions")
    if not isinstance(permissions, dict):
        return result(
            repository, False, "", "permissions_present",
            "the API response has no permissions object; the credential cannot show repository permission",
        )
    for name in AUTHORIZING_PERMISSIONS:
        if permissions.get(name) is True:
            return result(repository, True, name, "", f"the credential has {name} permission on the repository")
    held = sorted(key for key, value in permissions.items() if value is True)
    return result(
        repository, False, "", "repository_permission",
        "admin, maintain, or push permission is required; the credential holds "
        + (", ".join(held) if held else "no repository permission"),
    )


def fetch(repository: str) -> tuple[Any, str]:
    try:
        process = subprocess.run(
            ["gh", "api", f"repos/{repository}"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return None, f"gh could not be run: {error}"
    if process.returncode != 0:
        detail = process.stderr.strip().splitlines()[-1:] or ["no error output"]
        return None, f"gh api exited {process.returncode}: {detail[0][:300]}"
    try:
        return json.loads(process.stdout), ""
    except json.JSONDecodeError as error:
        return None, f"gh api returned invalid JSON: {error}"


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or ADAPTER_NAME).splitlines()[0])
    parser.add_argument("--repo", required=True, help="OWNER/REPO")
    parser.add_argument(
        "--response-json",
        type=Path,
        help="captured `gh api repos/OWNER/REPO` response to evaluate instead of calling gh",
    )
    args = parser.parse_args()

    repository = args.repo
    if not REPOSITORY_PATTERN.match(repository):
        print(json.dumps(result(repository, False, "", "repository_format", "repository must be OWNER/REPO"), sort_keys=True))
        return EXIT_USAGE

    if args.response_json is not None:
        try:
            response = json.loads(args.response_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            print(json.dumps(result(repository, False, "", "response_read", f"cannot read captured response: {error}"), sort_keys=True))
            return EXIT_USAGE
    else:
        response, error = fetch(repository)
        if response is None:
            print(json.dumps(result(repository, False, "", "repository_lookup", error), sort_keys=True))
            return EXIT_NOT_AUTHORIZED

    outcome = evaluate(repository, response)
    print(json.dumps(outcome, sort_keys=True))
    return EXIT_AUTHORIZED if outcome["authorized"] else EXIT_NOT_AUTHORIZED


if __name__ == "__main__":
    sys.exit(main())
