"""RED acceptance coverage for deterministic Starduster vault rendering."""

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

import yaml


ROOT = Path(__file__).resolve().parents[2]
STARDUSTER_CLI = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster.py"
SYNTHESIS_SCHEMA = ROOT / "research-toolkit" / "skills" / "starduster" / "schemas" / "starduster-synthesis.schema.json"
FIXTURES = ROOT / "tests" / "fixtures" / "starduster"
RAW_DESCRIPTION_MARKER = "RAW_STARDUSTER_DESCRIPTION_MUST_NOT_ESCAPE"
RAW_README_MARKER = "RAW_STARDUSTER_README_MUST_NOT_ESCAPE"


class StardusterRenderingAcceptanceTests(unittest.TestCase):
    """Exercise the public controller with hermetic GitHub and synthesis adapters."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starduster-rendering-test-")
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.home = self.root / "home"
        self.bin_dir = self.root / "bin"
        self.work_root = self.root / "work"
        self.vault = self.root / "vault"
        self.config = self.root / "research-toolkit.json"
        self.stars = self.root / "stars.json"
        self.synthesis = self.root / "synthesis.json"
        self.calls = self.root / "synthesis-calls.jsonl"
        for directory in (self.project, self.home, self.bin_dir, self.work_root):
            directory.mkdir()
        self.stars.write_bytes((FIXTURES / "stars.json").read_bytes())
        self.synthesis.write_bytes((FIXTURES / "synthesis.json").read_bytes())
        self._write_config(batch_size=25)
        self._write_fixtures()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def output_dir(self) -> Path:
        return self.vault / "tools" / "github"

    def _write_config(self, batch_size: int) -> None:
        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "starduster": {
                        "output_path": str(self.vault),
                        "vault_name": None,
                        "subfolder": "tools/github",
                        "synthesis_profile": "fast",
                        "synthesis_batch_size": batch_size,
                    },
                }
            ),
            encoding="utf-8",
        )

    def _write_executable(self, name: str, source: str) -> None:
        path = self.bin_dir / name
        path.write_text(source, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def _write_fixtures(self) -> None:
        self._write_executable(
            "gh",
            "#!/usr/bin/env python3\n"
            "import json, os, re, sys\n"
            "arguments = sys.argv[1:]\n"
            "if arguments[:2] == ['auth', 'status']:\n"
            "    print('Logged in to github.com as fixture')\n"
            "    raise SystemExit(0)\n"
            "if arguments[:2] != ['api', 'graphql'] and arguments[:2] != ['api', '/rate_limit'] and arguments[:2] != ['api', '/user/starred']:\n"
            "    if arguments[:1] == ['api'] and len(arguments) > 1 and arguments[1].startswith('repos/'):\n"
            "        print('{}')\n"
            "        raise SystemExit(0)\n"
            "    raise SystemExit('unexpected gh invocation: {!r}'.format(arguments))\n"
            "if arguments[:2] == ['api', '/rate_limit']:\n"
            "    print(json.dumps({'resources': {'graphql': {'remaining': 5000, 'limit': 5000, 'reset': 0}, 'core': {'remaining': 5000, 'limit': 5000, 'reset': 0}}}))\n"
            "    raise SystemExit(0)\n"
            "if arguments[:2] == ['api', '/user/starred']:\n"
            "    print(open(os.environ['STARDUSTER_FIXTURE_STARS'], encoding='utf-8').read())\n"
            "    raise SystemExit(0)\n"
            "query = next((item.split('=', 1)[1] for item in arguments if item.startswith('query=')), '')\n"
            "stars = json.load(open(os.environ['STARDUSTER_FIXTURE_STARS'], encoding='utf-8'))\n"
            "data = {'rateLimit': {'cost': 1, 'remaining': 4999, 'resetAt': '2026-09-02T00:00:00Z'}}\n"
            "if 'starredRepositories' in query:\n"
            "    data['viewer'] = {'starredRepositories': {'totalCount': len(stars)}}\n"
            "for alias in re.findall(r'([A-Za-z0-9_]+):\\s*repository\\s*\\(', query):\n"
            "    blob = {'text': '# Fixture README\\n' + os.environ.get('STARDUSTER_FIXTURE_README_MARKER', ''), 'byteSize': 42}\n"
            "    data[alias] = {'readme_md': blob, 'readme_lower': None, 'readme_rst': None, 'readme_plain': None}\n"
            "print(json.dumps({'data': data}))\n",
        )
        self._write_executable(
            "claude",
            "#!/usr/bin/env python3\n"
            "import json, os, re, sys\n"
            "from pathlib import Path\n"
            "if '--help' in sys.argv:\n"
            "    print('--print --safe-mode --no-session-persistence --no-chrome --disable-slash-commands --permission-mode --tools --mcp-config --strict-mcp-config --output-format --json-schema --model')\n"
            "    raise SystemExit(0)\n"
            "stdin = sys.stdin.read()\n"
            "match = re.search(r'<repositories_json>\\s*(\\[.*?\\])\\s*</repositories_json>', stdin, flags=re.DOTALL)\n"
            "repositories = json.loads(match.group(1)) if match else []\n"
            "call_log = Path(os.environ['STARDUSTER_FIXTURE_CALLS'])\n"
            "call_index = len(call_log.read_text(encoding='utf-8').splitlines()) if call_log.exists() else 0\n"
            "with call_log.open('a', encoding='utf-8') as handle:\n"
            "    handle.write(json.dumps({'repositories': repositories, 'argv': sys.argv[1:]}) + '\\n')\n"
            "invalid_calls = {int(value) for value in os.environ.get('STARDUSTER_FIXTURE_INVALID_CALLS', '').split(',') if value}\n"
            "if call_index in invalid_calls:\n"
            "    print('this is not valid synthesis JSON')\n"
            "    raise SystemExit(0)\n"
            "override = os.environ.get('STARDUSTER_FIXTURE_SYNTHESIS_OVERRIDE')\n"
            "if override:\n"
            "    print(Path(override).read_text(encoding='utf-8'))\n"
            "    raise SystemExit(0)\n"
            "records = json.load(open(os.environ['STARDUSTER_FIXTURE_SYNTHESIS'], encoding='utf-8'))\n"
            "by_name = {record['full_name']: record for record in records}\n"
            "print(json.dumps([by_name[item['full_name']] for item in repositories]))\n",
        )

    def _environment(self, **extra: str) -> dict[str, str]:
        environment = os.environ.copy()
        for name in ("CLAUDECODE", "CLAUDE_CODE", "CLAUDE_SESSION_ID", "CODEX_SESSION_ID"):
            environment.pop(name, None)
        environment.update(
            {
                "HOME": str(self.home),
                "RESEARCH_TOOLKIT_CONFIG": str(self.config),
                "RESEARCH_TOOLKIT_RUNTIME": "claude",
                "STARDUSTER_FIXTURE_STARS": str(self.stars),
                "STARDUSTER_FIXTURE_SYNTHESIS": str(self.synthesis),
                "STARDUSTER_FIXTURE_CALLS": str(self.calls),
                "STARDUSTER_FIXTURE_README_MARKER": RAW_README_MARKER,
                "TMPDIR": str(self.work_root),
                "PATH": "{}:{}".format(self.bin_dir, environment.get("PATH", "")),
            }
        )
        environment.update(extra)
        return environment

    def _sync(self, *arguments: str, expected_returncode: int = 0, **environment: str) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        process = subprocess.run(
            [sys.executable, str(STARDUSTER_CLI), "sync", "--project-dir", str(self.project), *arguments],
            cwd=ROOT,
            env=self._environment(**environment),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(process.returncode, expected_returncode, process.stderr)
        payload = json.loads(process.stdout if expected_returncode == 0 else process.stderr)
        self.assertIsInstance(payload, dict)
        if expected_returncode == 0:
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["status"], "completed")
            self.assertEqual(Path(payload["output_dir"]), self.output_dir)
        self.assertNotIn(RAW_DESCRIPTION_MARKER, process.stdout + process.stderr)
        self.assertNotIn(RAW_README_MARKER, process.stdout + process.stderr)
        return process, payload

    def _calls(self) -> list[dict[str, Any]]:
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines()]

    def _frontmatter(self, path: Path) -> dict[str, Any]:
        match = re.match(r"^---\n(.*?)\n---\n", path.read_text(encoding="utf-8"), flags=re.DOTALL)
        self.assertIsNotNone(match, "missing YAML frontmatter in {}".format(path))
        parsed = yaml.safe_load(match.group(1))
        self.assertIsInstance(parsed, dict)
        return parsed

    def _repo(self, full_name: str) -> Path:
        return self.output_dir / "repos" / (full_name.replace("/", "-") + ".md")

    def _snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.output_dir)): path.read_bytes()
            for path in sorted(self.output_dir.rglob("*"))
            if path.is_file()
        }

    def test_synthesis_batches_retry_and_fall_back_to_individual_repositories(self) -> None:
        self._write_config(batch_size=2)
        _, payload = self._sync(STARDUSTER_FIXTURE_INVALID_CALLS="0,1")

        calls = self._calls()
        self.assertEqual([len(call["repositories"]) for call in calls], [2, 2, 1, 1, 2, 1])
        self.assertEqual(
            [[item["full_name"] for item in call["repositories"]] for call in calls],
            [
                ["acme/alpha", "acme/beta"],
                ["acme/alpha", "acme/beta"],
                ["acme/alpha"],
                ["acme/beta"],
                ["dev/gamma", "dev/delta"],
                ["solo/epsilon"],
            ],
        )
        isolation_arguments = calls[0]["argv"]
        for argument in (
            "--safe-mode",
            "--no-session-persistence",
            "--no-chrome",
            "--disable-slash-commands",
            "--permission-mode",
            "--tools",
            "--mcp-config",
            "--strict-mcp-config",
            "--output-format",
            "--json-schema",
            "--model",
        ):
            self.assertIn(argument, isolation_arguments)
        self.assertEqual(isolation_arguments[isolation_arguments.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(isolation_arguments[isolation_arguments.index("--tools") + 1], "")
        self.assertEqual(isolation_arguments[isolation_arguments.index("--mcp-config") + 1], '{"mcpServers":{}}')
        self.assertEqual(isolation_arguments[isolation_arguments.index("--output-format") + 1], "json")
        claude_schema = json.loads(isolation_arguments[isolation_arguments.index("--json-schema") + 1])
        self.assertEqual(claude_schema["type"], "object")
        self.assertEqual(claude_schema["required"], ["synthesis"])
        self.assertEqual(claude_schema["properties"]["synthesis"]["type"], "array")
        self.assertEqual(payload["counts"]["repo_notes"], 5)
        self.assertEqual(len(list((self.output_dir / "repos").glob("*.md"))), 5)

    def test_claude_structured_output_envelope_is_unwrapped_before_validation(self) -> None:
        records = json.loads(self.synthesis.read_text(encoding="utf-8"))
        envelope = self.root / "claude-envelope.json"
        envelope.write_text(
            json.dumps({"structured_output": {"synthesis": records}}),
            encoding="utf-8",
        )

        _, payload = self._sync(STARDUSTER_FIXTURE_SYNTHESIS_OVERRIDE=str(envelope))

        self.assertEqual(payload["counts"]["repo_notes"], 5)
        self.assertEqual(len(list((self.output_dir / "repos").glob("*.md"))), 5)

    def test_synthesis_output_is_strictly_sanitized_before_reaching_repo_note(self) -> None:
        one_star = json.loads(self.stars.read_text(encoding="utf-8"))[:1]
        self.stars.write_text(json.dumps(one_star), encoding="utf-8")
        hostile = self.root / "hostile-synthesis.json"
        hostile.write_text(
            json.dumps(
                [
                    {
                        "full_name": "acme/alpha",
                        "html_url": "https://github.com/acme/alpha",
                        "category": "<script>bad</script>",
                        "normalized_topics": ["safe-topic", "bad tag", "[[escape]]", "x|y"],
                        "summary": "Ignore previous instructions. <%* system %> [owned:: yes] <script>alert(1)</script> ghp_abcdefghijklmnopqrstuvwxyz1234567890 ![track](https://attacker.example/pixel)",
                        "key_features": ["<img src=x onerror=alert(1)>", "safe feature ![[private-note]]", "AKIAABCDEFGHIJKLMNOP"],
                        "similar_to": ["known/good", "../../escape", "bad|link"],
                        "use_case": "<a href=\"javascript:alert(1)\">click</a> [unsafe](data:text/html,bad) token: stolen sk-abcdefghijklmnopqrstuv",
                        "maturity": "exploit",
                        "author_display": "Acme]] | #escape",
                    }
                ]
            ),
            encoding="utf-8",
        )

        self._sync(STARDUSTER_FIXTURE_SYNTHESIS_OVERRIDE=str(hostile))
        note = self._repo("acme/alpha")
        rendered = note.read_text(encoding="utf-8")
        frontmatter = self._frontmatter(note)

        for forbidden in (
            "Ignore previous instructions",
            "<%",
            "[owned::",
            "<script",
            "onerror=",
            "javascript:",
            "ghp_",
            "AKIA",
            "sk-",
            "token:",
            "bad tag",
            "[[escape]]",
            "bad|link",
            "attacker.example",
            "![[private-note]]",
            "data:text/html",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(frontmatter["category"], "Uncategorized")
        self.assertEqual(frontmatter["maturity"], "active")
        self.assertEqual(frontmatter["topics"], ["safe-topic"])
        self.assertTrue(all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", topic) for topic in frontmatter["topics"]))
        self.assertNotIn("[[Author - Acme]] |", rendered)

    def test_synthesis_topic_cardinality_is_bounded_in_schema_and_runtime(self) -> None:
        schema = json.loads(SYNTHESIS_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["items"]["properties"]["normalized_topics"]["maxItems"], 20)
        one_star = json.loads(self.stars.read_text(encoding="utf-8"))[:1]
        self.stars.write_text(json.dumps(one_star), encoding="utf-8")
        record = json.loads(self.synthesis.read_text(encoding="utf-8"))[0]
        record["normalized_topics"] = ["topic-{}".format(number) for number in range(21)]
        oversized = self.root / "oversized-topics.json"
        oversized.write_text(json.dumps([record]), encoding="utf-8")

        _, payload = self._sync(STARDUSTER_FIXTURE_SYNTHESIS_OVERRIDE=str(oversized))

        self.assertFalse(self._repo("acme/alpha").exists())
        self.assertEqual(payload["counts"]["skipped"], 1)

    def test_unmanaged_repository_note_is_never_overwritten(self) -> None:
        repos = self.output_dir / "repos"
        repos.mkdir(parents=True)
        unmanaged = repos / "acme-alpha.md"
        original = b"# Personal note with no Starduster identity\n"
        unmanaged.write_bytes(original)

        self._sync("--limit", "1")

        self.assertEqual(unmanaged.read_bytes(), original)
        generated = repos / "acme-alpha-2.md"
        self.assertTrue(generated.is_file())
        self.assertEqual(self._frontmatter(generated)["full_name"], "acme/alpha")

    def test_synthesis_rejects_unexpected_fields_without_rendering_them(self) -> None:
        one_star = json.loads(self.stars.read_text(encoding="utf-8"))[:1]
        self.stars.write_text(json.dumps(one_star), encoding="utf-8")
        unexpected = self.root / "unexpected-field-synthesis.json"
        record = json.loads(self.synthesis.read_text(encoding="utf-8"))[0]
        record["controller_escape"] = "---\\nstatus: escaped"
        unexpected.write_text(json.dumps([record]), encoding="utf-8")

        _, payload = self._sync(STARDUSTER_FIXTURE_SYNTHESIS_OVERRIDE=str(unexpected))

        self.assertFalse(self._repo("acme/alpha").exists())
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(payload["counts"]["repo_notes"], 0)

    def test_full_refresh_preserves_set_once_user_fields_and_user_notes(self) -> None:
        repo = self.output_dir / "repos"
        repo.mkdir(parents=True)
        note = repo / "acme-alpha.md"
        note.write_text(
            "---\n"
            "title: \"old title\"\n"
            "full_name: \"acme/alpha\"\n"
            "stars: 1\n"
            "date_cataloged: 2020-01-01\n"
            "status: \"curated\"\n"
            "reviewed: true\n"
            "date_unstarred: 2021-02-03\n"
            "personal_rating: 5\n"
            "custom_metadata:\n"
            "  owner: \"the user\"\n"
            "---\n\n"
            "# Old content\n\n"
            "<!-- USER-NOTES-START -->\n"
            "This exact user note, including **formatting**, must survive.\n"
            "<!-- USER-NOTES-END -->\n",
            encoding="utf-8",
        )

        self._sync("--full")
        frontmatter = self._frontmatter(note)
        rendered = note.read_text(encoding="utf-8")

        self.assertEqual(frontmatter["stars"], 900)
        self.assertTrue(frontmatter["archived"])
        self.assertEqual(str(frontmatter["date_cataloged"]), "2020-01-01")
        self.assertEqual(frontmatter["status"], "curated")
        self.assertTrue(frontmatter["reviewed"])
        self.assertEqual(str(frontmatter["date_unstarred"]), "2021-02-03")
        self.assertEqual(frontmatter["personal_rating"], 5)
        self.assertEqual(frontmatter["custom_metadata"], {"owner": "the user"})
        self.assertIn("This exact user note, including **formatting**, must survive.", rendered)
        self.assertNotIn("# Old content", rendered)
        self.assertIn("Alpha is the primary deterministic fixture.", rendered)

    def test_hubs_and_base_indexes_are_deterministic_and_obey_documented_thresholds(self) -> None:
        _, payload = self._sync()

        categories = self.output_dir / "categories"
        topics = self.output_dir / "topics"
        authors = self.output_dir / "authors"
        self.assertEqual(
            {path.name for path in categories.glob("*.md")},
            {
                "Category - AI & Machine Learning.md",
                "Category - CLI & Terminal Tools.md",
                "Category - Developer Tools.md",
            },
        )
        self.assertEqual({path.name for path in topics.glob("*.md")}, {"Topic - shared-topic.md"})
        self.assertEqual(
            {path.name for path in authors.glob("*.md")},
            {"Author - acme.md", "Author - dev.md"},
        )
        shared = (topics / "Topic - shared-topic.md").read_text(encoding="utf-8")
        self.assertLess(shared.index("[[acme-alpha]]"), shared.index("[[acme-beta]]"))
        self.assertLess(shared.index("[[acme-beta]]"), shared.index("[[dev-gamma]]"))
        acme = (authors / "Author - acme.md").read_text(encoding="utf-8")
        self.assertLess(acme.index("[[acme-alpha]]"), acme.index("[[acme-beta]]"))
        self.assertEqual(payload["counts"]["category_hubs"], 3)
        self.assertEqual(payload["counts"]["topic_hubs"], 1)
        self.assertEqual(payload["counts"]["author_hubs"], 2)

        indexes = self.output_dir / "indexes"
        expected = {
            "master-index.base": (["file.inFolder(\"tools/github/repos\")"], "All Repositories", None, {"column": "stars", "direction": "DESC"}),
            "by-language.base": (["status == \"active\""], "By Language", "language", {"column": "stars", "direction": "DESC"}),
            "by-category.base": (["status == \"active\""], "By Category", "category", {"column": "stars", "direction": "DESC"}),
            "recently-starred.base": (["status == \"active\""], "Recently Starred", None, {"column": "date_starred", "direction": "DESC"}),
            "review-queue.base": (["reviewed == false", "status == \"active\""], "Review Queue", None, {"column": "stars", "direction": "DESC"}),
            "stale-repos.base": (["last_pushed < now() - \"365d\""], "Stale Repos (>1 year)", None, {"column": "last_pushed", "direction": "ASC"}),
            "unstarred.base": (["status == \"unstarred\""], "Unstarred Repos", None, {"column": "date_unstarred", "direction": "DESC"}),
        }
        self.assertEqual({path.name for path in indexes.glob("*.base")}, set(expected))
        for filename, (required_filters, view_name, group_by, sort) in expected.items():
            with self.subTest(index=filename):
                base = yaml.safe_load((indexes / filename).read_text(encoding="utf-8"))
                filters = base["filters"]["and"]
                self.assertIn('file.inFolder("tools/github/repos")', filters)
                for expression in required_filters:
                    self.assertIn(expression, filters)
                view = base["views"][0]
                self.assertEqual(view["type"], "table")
                self.assertEqual(view["name"], view_name)
                self.assertEqual(view.get("group_by"), group_by)
                self.assertEqual(view["sort"][0], sort)
                if filename == "recently-starred.base":
                    self.assertEqual(view["limit"], 50)
        self.assertEqual(payload["counts"]["base_indexes"], 7)

    def test_reruns_are_idempotent_and_recover_from_vault_state_without_checkpoint(self) -> None:
        self._sync("--limit", "2")
        self.assertEqual(len(list((self.output_dir / "repos").glob("*.md"))), 2)
        self.assertFalse(any("checkpoint" in path.name.lower() for path in self.output_dir.rglob("*")))

        self._sync()
        first_complete = self._snapshot()
        self.assertEqual(len(list((self.output_dir / "repos").glob("*.md"))), 5)
        self.assertFalse(any("checkpoint" in path.name.lower() for path in self.output_dir.rglob("*")))

        self._sync()
        self.assertEqual(self._snapshot(), first_complete)
        self.assertFalse(any("checkpoint" in path.name.lower() for path in self.output_dir.rglob("*")))

    def test_archived_and_unstarred_notes_preserve_existing_semantics(self) -> None:
        repo = self.output_dir / "repos"
        repo.mkdir(parents=True)
        removed = repo / "retired-tool.md"
        removed.write_text(
            "---\n"
            "title: \"retired/tool\"\n"
            "full_name: \"retired/tool\"\n"
            "status: \"curated\"\n"
            "date_cataloged: 2021-01-01\n"
            "date_unstarred: 2022-02-02\n"
            "personal_notes: \"Keep this historical record\"\n"
            "---\n\n"
            "<!-- USER-NOTES-START -->\nHistorical user note\n<!-- USER-NOTES-END -->\n",
            encoding="utf-8",
        )

        _, payload = self._sync()
        archived = self._frontmatter(self._repo("acme/alpha"))
        unstarred = self._frontmatter(removed)
        rendered = removed.read_text(encoding="utf-8")

        self.assertTrue(archived["archived"])
        self.assertEqual(archived["status"], "active")
        self.assertEqual(unstarred["status"], "unstarred")
        self.assertEqual(str(unstarred["date_unstarred"]), "2022-02-02")
        self.assertEqual(str(unstarred["date_cataloged"]), "2021-01-01")
        self.assertEqual(unstarred["personal_notes"], "Keep this historical record")
        self.assertIn("Historical user note", rendered)
        self.assertEqual(payload["counts"]["unstarred"], 1)


if __name__ == "__main__":
    unittest.main()
