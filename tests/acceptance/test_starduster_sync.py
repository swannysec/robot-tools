"""Acceptance coverage for the noninteractive starduster sync controller."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STARDUSTER_CLI = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster.py"
RAW_DESCRIPTION_MARKER = "RAW_DESCRIPTION_MUST_NOT_REACH_RESULT"
RAW_README_MARKER = "RAW_README_MUST_NOT_REACH_RESULT"
MODEL_OUTPUT_MARKER = "RAW_MODEL_OUTPUT_MUST_NOT_REACH_RESULT"
INJECTION_CANARY = "GRAPHQL_INJECTION_CANARY"
SYNTHESIS_SCHEMA = ROOT / "research-toolkit" / "skills" / "starduster" / "schemas" / "starduster-synthesis.schema.json"

VALID_STARS = (
    {
        "starred_at": "2026-08-30T10:00:00Z",
        "repo": {
            "full_name": "fixture/newest",
            "description": RAW_DESCRIPTION_MARKER,
            "language": "Python",
            "topics": ["testing"],
            "license": {"spdx_id": "MIT"},
            "stargazers_count": 100,
            "forks_count": 10,
            "archived": False,
            "fork": False,
            "owner": {"login": "fixture"},
            "pushed_at": "2026-08-29T00:00:00Z",
            "created_at": "2020-01-01T00:00:00Z",
            "html_url": "https://github.com/fixture/newest",
        },
    },
    {
        "starred_at": "2026-08-20T10:00:00Z",
        "repo": {
            "full_name": "fixture/existing",
            "description": "An existing fixture note.",
            "language": "Rust",
            "topics": ["tooling"],
            "license": {"spdx_id": "Apache-2.0"},
            "stargazers_count": 200,
            "forks_count": 20,
            "archived": False,
            "fork": False,
            "owner": {"login": "fixture"},
            "pushed_at": "2026-08-19T00:00:00Z",
            "created_at": "2021-01-01T00:00:00Z",
            "html_url": "https://github.com/fixture/existing",
        },
    },
    {
        "starred_at": "2026-08-10T10:00:00Z",
        "repo": {
            "full_name": "fixture/older",
            "description": "An older fixture repo.",
            "language": "Go",
            "topics": ["automation"],
            "license": {"spdx_id": "BSD-3-Clause"},
            "stargazers_count": 50,
            "forks_count": 5,
            "archived": False,
            "fork": False,
            "owner": {"login": "fixture"},
            "pushed_at": "2026-08-09T00:00:00Z",
            "created_at": "2022-01-01T00:00:00Z",
            "html_url": "https://github.com/fixture/older",
        },
    },
)

MALFORMED_STAR = {
    "starred_at": "2026-08-31T10:00:00Z",
    "repo": {
        "full_name": 'fixture/valid" } ' + INJECTION_CANARY,
        "description": "This name must never be interpolated into GraphQL.",
        "language": None,
        "topics": [],
        "license": {"spdx_id": None},
        "stargazers_count": 0,
        "forks_count": 0,
        "archived": False,
        "fork": False,
        "owner": {"login": "fixture"},
        "pushed_at": "2026-08-31T00:00:00Z",
        "created_at": "2026-08-31T00:00:00Z",
        "html_url": "https://github.com/fixture/invalid",
    },
}


class StardusterSyncAcceptanceTests(unittest.TestCase):
    """Hermetic sync tests with an argv-recording, read-only GitHub CLI fixture."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starduster-sync-test-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.project = self.root / "project"
        self.vault = self.root / "vault"
        self.catalog = self.vault / "github-stars"
        self.bin_dir = self.root / "bin"
        self.work_root = self.root / "work"
        self.gh_log = self.root / "gh-argv.jsonl"
        self.config = self.root / "research-toolkit.json"
        for directory in (self.home, self.project, self.catalog / "repos", self.bin_dir, self.work_root):
            directory.mkdir(parents=True, exist_ok=True)
        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "starduster": {
                        "output_path": str(self.vault),
                        "subfolder": "github-stars",
                        "vault_name": None,
                        "synthesis_profile": "fast",
                        "synthesis_batch_size": 25,
                    },
                }
            ),
            encoding="utf-8",
        )
        self._write_existing_note("existing.md", "fixture/existing")
        self._write_existing_note("unstarred.md", "fixture/no-longer-starred")
        self._write_fixtures()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_existing_note(self, filename: str, full_name: str) -> None:
        (self.catalog / "repos" / filename).write_text(
            "---\n"
            + 'full_name: "{}"\n'.format(full_name)
            + "reviewed: true\n"
            + "---\n"
            + "<!-- USER-NOTES-START -->\n"
            + "fixture user note\n"
            + "<!-- USER-NOTES-END -->\n",
            encoding="utf-8",
        )

    def _write_executable(self, name: str, source: str) -> None:
        path = self.bin_dir / name
        path.write_text(source, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def _write_fixtures(self) -> None:
        portable_schema = json.loads(SYNTHESIS_SCHEMA.read_text(encoding="utf-8"))
        claude_array_schema = dict(portable_schema)
        dialect = claude_array_schema.pop("$schema")
        claude_schema = {
            "$schema": dialect,
            "type": "object",
            "additionalProperties": False,
            "properties": {"synthesis": claude_array_schema},
            "required": ["synthesis"],
        }
        star_pages = [list(VALID_STARS[:2]), [VALID_STARS[2], MALFORMED_STAR]]
        fixture = """#!/usr/bin/env python3
import json
import re
import sys

args = sys.argv[1:]
with open({log_path!r}, "a", encoding="utf-8") as handle:
    handle.write(json.dumps({{"argv": args}}, separators=(",", ":")) + "\\n")

if args[:2] == ["auth", "status"]:
    print("Logged in to github.com as fixture")
elif args and args[0] == "api" and "/rate_limit" in args:
    print(json.dumps({{"resources": {{"core": {{"remaining": 4900, "limit": 5000}}, "graphql": {{"remaining": 4900, "limit": 5000}}}}}}))
elif args and args[0] == "api" and "/user/starred" in args:
    for page in {star_pages!r}:
        print(json.dumps(page, separators=(",", ":")))
elif args[:2] == ["api", "graphql"]:
    query = next((part.split("=", 1)[1] for part in args if part.startswith("query=")), "")
    if "totalCount" in query:
        print(json.dumps({{"data": {{"viewer": {{"starredRepositories": {{"totalCount": 4}}}}}}}}))
    else:
        aliases = re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\\s*:\\s*repository\\s*\\(", query)
        data = {{}}
        for alias in aliases:
            data[alias] = {{"readme_md": {{"text": {readme_marker!r}, "byteSize": 45}}, "readme_lower": None, "readme_rst": None, "readme_plain": None}}
        print(json.dumps({{"data": data}}))
else:
    print("unexpected gh invocation: " + json.dumps(args), file=sys.stderr)
    sys.exit(64)
""".format(log_path=str(self.gh_log), star_pages=star_pages, readme_marker=RAW_README_MARKER)
        self._write_executable("gh", fixture)

        synthesis = """#!/usr/bin/env python3
import json
import os
import sys

if "--help" in sys.argv[1:]:
    print("--safe-mode --no-session-persistence --no-chrome --tools --mcp-config --strict-mcp-config --json-schema --permission-mode")
    sys.exit(0)

arguments = sys.argv[1:]
schema_index = arguments.index("--json-schema") + 1
if json.loads(arguments[schema_index]) != {schema!r}:
    sys.exit(65)

targets = [value for value in os.environ.get("STARDUSTER_FIXTURE_TARGETS", "").split(",") if value]
result = []
for full_name in targets:
    result.append({{
        "full_name": full_name,
        "html_url": "https://github.com/" + full_name,
        "category": "Developer Tools",
        "normalized_topics": ["testing"],
        "summary": "Fixture summary.",
        "key_features": ["Deterministic fixture", "Portable execution", "Safe rendering"],
        "similar_to": [],
        "use_case": "Fixture use case.",
        "maturity": "active",
        "author_display": "Fixture",
    }})
print({model_marker!r}, file=sys.stderr)
print(json.dumps({{"structured_output": {{"synthesis": result}}}}))
""".format(model_marker=MODEL_OUTPUT_MARKER, schema=claude_schema)
        self._write_executable("claude", synthesis)

    def _environment(self, targets: tuple[str, ...]) -> dict[str, str]:
        environment = os.environ.copy()
        for name in ("CLAUDECODE", "CLAUDE_CODE", "CODEX_SESSION_ID", "CODEX_THREAD_ID"):
            environment.pop(name, None)
        environment.update(
            {
                "HOME": str(self.home),
                "TMPDIR": str(self.work_root),
                "PATH": "{}:{}".format(self.bin_dir, environment.get("PATH", "")),
                "RESEARCH_TOOLKIT_RUNTIME": "claude",
                "RESEARCH_TOOLKIT_CONFIG": str(self.config),
                "STARDUSTER_FIXTURE_TARGETS": ",".join(targets),
            }
        )
        return environment

    def _sync(
        self,
        *arguments: str,
        targets: tuple[str, ...] = ("fixture/newest",),
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        process = subprocess.run(
            [sys.executable, str(STARDUSTER_CLI), "sync", "--project-dir", str(self.project), *arguments],
            cwd=ROOT,
            env=self._environment(targets),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(
            process.returncode,
            0,
            "sync stderr:\n{}\nstdout:\n{}".format(process.stderr, process.stdout),
        )
        payload = json.loads(process.stdout)
        self.assertIsInstance(payload, dict)
        return process, payload

    def _gh_commands(self) -> list[list[str]]:
        return [json.loads(line)["argv"] for line in self.gh_log.read_text(encoding="utf-8").splitlines()]

    def _graphql_queries(self) -> list[str]:
        queries = []
        for command in self._gh_commands():
            if command[:2] == ["api", "graphql"]:
                queries.extend(part.split("=", 1)[1] for part in command if part.startswith("query="))
        return queries

    def _assert_counts(self, payload: dict[str, Any], **expected: int) -> None:
        counts = payload["counts"]
        self.assertIsInstance(counts, dict)
        for name, value in expected.items():
            self.assertEqual(counts[name], value, name)

    def test_full_star_pagination_runs_even_when_limit_is_one(self) -> None:
        _, payload = self._sync("--limit", "1")

        starred_commands = [command for command in self._gh_commands() if "/user/starred" in command]
        self.assertEqual(len(starred_commands), 1)
        self.assertEqual(starred_commands[0][0:4], ["api", "/user/starred", "--method", "GET"])
        self.assertIn("--paginate", starred_commands[0])
        self.assertIn("per_page=100", starred_commands[0])
        self._assert_counts(payload, total_stars=3, new=2, existing=1, unstarred=1, processed=1)

    def test_gh_calls_are_read_only_and_invalid_names_never_reach_graphql(self) -> None:
        self._sync("--limit", "1")

        commands = self._gh_commands()
        self.assertIn(["auth", "status"], commands)
        for command in commands:
            self.assertIn(command[0], {"auth", "api"}, command)
            if command[0] == "auth":
                self.assertEqual(command, ["auth", "status"])
            self.assertNotIn("POST", command)
            self.assertNotIn("PUT", command)
            self.assertNotIn("PATCH", command)
            self.assertNotIn("DELETE", command)

        queries = self._graphql_queries()
        self.assertTrue(any("totalCount" in query for query in queries))
        readme_queries = [query for query in queries if "repository(" in query]
        self.assertTrue(readme_queries)
        joined = "\n".join(readme_queries)
        self.assertNotIn(INJECTION_CANARY, joined)
        self.assertNotIn('fixture/valid"', joined)
        identifiers = re.findall(r'repository\s*\(\s*owner:\s*"([^"]+)"\s*,\s*name:\s*"([^"]+)"', joined)
        self.assertTrue(identifiers)
        for owner, name in identifiers:
            self.assertRegex(owner + "/" + name, r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

    def test_frontmatter_identity_partitions_new_existing_and_unstarred(self) -> None:
        _, payload = self._sync("--limit", "2", targets=("fixture/newest", "fixture/older"))

        self._assert_counts(payload, total_stars=3, new=2, existing=1, unstarred=1, processed=2)
        unstarred = self.catalog / "repos" / "unstarred.md"
        self.assertTrue(unstarred.is_file())
        self.assertRegex(unstarred.read_text(encoding="utf-8"), r'(?m)^status:\s*"?unstarred"?$')

    def test_limit_only_gates_new_repo_synthesis_and_note_generation(self) -> None:
        _, payload = self._sync("--limit", "1", targets=("fixture/newest",))

        self._assert_counts(payload, new=2, existing=1, unstarred=1, processed=1, repo_notes=1)
        readme_queries = [query for query in self._graphql_queries() if "repository(" in query]
        self.assertEqual(len(readme_queries), 1)
        self.assertIn('owner: "fixture", name: "newest"', readme_queries[0])
        self.assertNotIn('owner: "fixture", name: "older"', readme_queries[0])
        self.assertNotIn('owner: "fixture", name: "existing"', readme_queries[0])

    def test_full_refresh_includes_existing_without_changing_diff_counts(self) -> None:
        _, payload = self._sync(
            "--limit", "1",
            "--full",
            targets=("fixture/newest", "fixture/existing"),
        )

        self._assert_counts(payload, total_stars=3, new=2, existing=1, unstarred=1, processed=2, repo_notes=2)
        readme_queries = [query for query in self._graphql_queries() if "repository(" in query]
        self.assertEqual(len(readme_queries), 1)
        self.assertIn('owner: "fixture", name: "newest"', readme_queries[0])
        self.assertIn('owner: "fixture", name: "existing"', readme_queries[0])
        self.assertNotIn('owner: "fixture", name: "older"', readme_queries[0])

    def test_success_result_uses_only_safe_summary_fields(self) -> None:
        process, payload = self._sync("--limit", "1")

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(Path(payload["output_dir"]), self.catalog)
        self.assertIsInstance(payload["warnings"], list)
        self.assertIn("obsidian_uri", payload)
        self.assertIsNone(payload["obsidian_uri"])
        self._assert_counts(
            payload,
            total_stars=3,
            new=2,
            existing=1,
            unstarred=1,
            processed=1,
            skipped=0,
            repo_notes=1,
            category_hubs=1,
            topic_hubs=0,
            author_hubs=0,
            base_indexes=7,
        )
        rendered = process.stdout + process.stderr
        for marker in (RAW_DESCRIPTION_MARKER, RAW_README_MARKER, MODEL_OUTPUT_MARKER, INJECTION_CANARY):
            self.assertNotIn(marker, rendered)

    def test_repeat_run_uses_vault_identities_for_idempotent_recovery(self) -> None:
        self._sync("--limit", "2", targets=("fixture/newest", "fixture/older"))
        _, repeated = self._sync("--limit", "2", targets=())

        self._assert_counts(repeated, total_stars=3, new=0, existing=3, unstarred=1, processed=0, repo_notes=0)
        self.assertTrue((self.catalog / "repos" / "unstarred.md").is_file())
        self.assertEqual(len(list((self.catalog / "indexes").glob("*.base"))), 7)


if __name__ == "__main__":
    unittest.main()
