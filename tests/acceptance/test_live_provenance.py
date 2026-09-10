"""Deterministic simulated-host coverage for live kcap provenance checks.

The runner API exercised here deliberately treats a host's final prose as
untrusted.  `verify_live_host_acceptance` must establish success from command
events, catalog provenance, source-auth metadata snapshots, and files beneath
the temporary output root.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any, Callable

import tests.run_dual_runtime_acceptance as acceptance_runner
from tests.run_dual_runtime_acceptance import (
    BUNDLED_CODEX_BINARY,
    codex_catalog_skill_paths,
    codex_live_environment,
    create_private_auth_copy,
    live_prompt,
    preferred_codex_binary,
    verify_source_auth_unchanged,
    tree_byte_manifest,
    validate_claude_isolation_command,
    verify_live_host_acceptance,
    verify_tree_byte_manifest,
)


ROOT = Path(__file__).resolve().parents[2]
SOURCE_SKILL = ROOT / "research-toolkit" / "skills" / "kcap"
STARDUSTER_SKILL = ROOT / "research-toolkit" / "skills" / "starduster"
SOURCE_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"


def runner_seam_available(name: str) -> bool:
    return callable(getattr(acceptance_runner, name, None))


class LiveHostProvenanceTests(unittest.TestCase):
    """The intended support API is pure simulated-event acceptance support."""

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="kcap-live-provenance-")
        self.workspace = Path(self._temporary_directory.name)
        self.skill_dir = self.workspace / "isolated" / "skills" / "kcap"
        self.skill_dir.parent.mkdir(parents=True)
        shutil.copytree(SOURCE_SKILL, self.skill_dir)
        self.output_root = self.workspace / "output"
        self.output_root.mkdir()
        self.auth_file = self.workspace / "source-auth.json"
        self.auth_file.write_text("{}\n", encoding="utf-8")
        self.auth_metadata = self._metadata(self.auth_file)

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    @staticmethod
    def _metadata(path: Path) -> dict[str, int]:
        status = path.stat()
        return {
            "inode": status.st_ino,
            "mode": status.st_mode,
            "size": status.st_size,
            "mtime_ns": status.st_mtime_ns,
        }

    def _capture_command(self, skill_dir: Path | None = None) -> str:
        script = (skill_dir or self.skill_dir) / "scripts" / "kcap.py"
        return (
            f"python3 {script} capture {SOURCE_URL} "
            f"--project-dir {self.workspace / 'project'}"
        )

    def _capture_event(self, skill_dir: Path | None = None) -> dict[str, object]:
        capture = self.output_root / "captures" / "video.md"
        return {
            "type": "command_execution",
            "command": self._capture_command(skill_dir),
            "status": "completed",
            "exit_code": 0,
            "stdout": json.dumps(
                {"ok": True, "status": "created", "output_file": str(capture.resolve())},
                sort_keys=True,
            ),
            "output_files_before": [],
            "output_files_after": [str(capture.resolve())],
        }

    def _write_valid_capture(self) -> Path:
        capture = self.output_root / "captures" / "video.md"
        capture.parent.mkdir(exist_ok=True)
        capture.write_text(
            "---\n"
            f"source: {SOURCE_URL}\n"
            "---\n\n"
            "## TL;DR\n\nA deterministic capture.\n\n"
            "## Summary\n\nVerified from the simulated filesystem.\n\n"
            "## Key Takeaways\n\n- The output exists.\n",
            encoding="utf-8",
        )
        return capture

    def _verify(
        self,
        events: list[dict[str, str]],
        *,
        catalog_aliases: dict[str, Path] | None = None,
        catalog_paths: list[str | Path] | None = None,
        auth_after: dict[str, int] | None = None,
        final_host_message: object = None,
    ) -> dict[str, object]:
        """Minimal intended runner interface for deterministic host simulation."""
        return verify_live_host_acceptance(
            events,
            skill_dir=self.skill_dir,
            output_root=self.output_root,
            source_url=SOURCE_URL,
            catalog_aliases=catalog_aliases or {},
            catalog_paths=catalog_paths or [],
            source_auth_before=self.auth_metadata,
            source_auth_after=auth_after or self._metadata(self.auth_file),
            expected_project_dir=self.workspace / "project",
            final_host_message=final_host_message,
        )

    def test_prefers_bundled_desktop_codex_before_path_fallback(self) -> None:
        bundled = self.workspace / "ChatGPT.app" / "Contents" / "Resources" / "codex"
        path_fallback = self.workspace / "homebrew" / "bin" / "codex"
        selected = preferred_codex_binary(
            bundled_path=bundled,
            path_lookup=lambda _: str(path_fallback),
            is_executable=lambda path: path == bundled,
        )

        self.assertEqual(selected, bundled)

    def test_accepts_explicit_codex_override_before_bundled_runtime(self) -> None:
        override = self.workspace / "explicit-codex"
        bundled = self.workspace / "ChatGPT.app" / "Contents" / "Resources" / "codex"
        self.assertEqual(
            preferred_codex_binary(
                str(override),
                bundled_path=bundled,
                path_lookup=lambda _: None,
                is_executable=lambda _: True,
            ),
            override,
        )

    def test_live_release_proof_rejects_a_non_bundled_codex_binary(self) -> None:
        require_bundled = getattr(acceptance_runner, "require_bundled_desktop_codex_for_live", None)
        self.assertTrue(callable(require_bundled), "missing signed Desktop live-proof seam")
        with self.assertRaises(acceptance_runner.SkipCase):
            require_bundled(self.workspace / "external-codex")

    def test_live_release_proof_accepts_the_bundled_codex_binary(self) -> None:
        require_bundled = getattr(acceptance_runner, "require_bundled_desktop_codex_for_live", None)
        self.assertTrue(callable(require_bundled), "missing signed Desktop live-proof seam")
        bundled = self.workspace / "ChatGPT.app" / "Contents" / "Resources" / "codex"
        bundled.parent.mkdir(parents=True)
        bundled.write_text("fixture", encoding="utf-8")
        with patch.object(acceptance_runner, "BUNDLED_CODEX_BINARY", bundled):
            self.assertEqual(require_bundled(bundled), bundled)

    def test_live_github_token_validation_keeps_authentication_out_of_reports(self) -> None:
        validate = getattr(acceptance_runner, "validated_live_github_token", None)
        self.assertTrue(callable(validate), "missing live GitHub authentication seam")
        token = "gho_fixture_live_token"

        self.assertEqual(
            validate(subprocess.CompletedProcess(["gh", "auth", "token"], 0, token + "\n", "")),
            token,
        )
        with self.assertRaises(acceptance_runner.SkipCase):
            validate(subprocess.CompletedProcess(["gh", "auth", "token"], 1, "", "not authenticated"))
        for invalid in ("", "token with spaces", "x" * 4097):
            with self.subTest(invalid_length=len(invalid)):
                with self.assertRaises(AssertionError):
                    validate(subprocess.CompletedProcess(["gh", "auth", "token"], 0, invalid, ""))

    def test_parses_described_and_description_free_codex_catalog_entries(self) -> None:
        catalog_root = self.workspace / "catalog" / "skills"
        direct = self.workspace / "direct" / "kcap" / "SKILL.md"
        catalog = "\n".join(
            (
                f"- `r0` = `{catalog_root}`",
                "- kcap: Description (file: r0/kcap/SKILL.md)",
                "- kcap: (file: r0/kcap/SKILL.md)",
                f"- kcap: direct source (file: {direct})",
            )
        )

        self.assertEqual(
            codex_catalog_skill_paths(catalog, "kcap"),
            [
                catalog_root / "kcap" / "SKILL.md",
                catalog_root / "kcap" / "SKILL.md",
                direct,
            ],
        )

    def test_rejects_ambiguous_codex_catalog_entry(self) -> None:
        with self.assertRaisesRegex(AssertionError, "ambiguous|catalog"):
            codex_catalog_skill_paths(
                "- `r0` = `/tmp/skills`\n- kcap: (file: r0/kcap/SKILL.md) trailing",
                "kcap",
            )

    def test_requires_the_exact_live_capture_argv(self) -> None:
        self._write_valid_capture()
        expected = self._capture_command()
        self._verify([self._capture_event()])

        invalid_commands = (
            expected + " --mode standard",
            expected.replace("--project-dir", "--project"),
            expected.rsplit(" --project-dir", 1)[0],
            expected.replace(str(self.workspace / "project"), str(self.workspace / "other-project")),
        )
        for command in invalid_commands:
            with self.subTest(command=command):
                with self.assertRaisesRegex(AssertionError, "exact|project|capture"):
                    self._verify([{"type": "command_execution", "command": command}])

    def test_accepts_only_the_exact_codex_zsh_lc_wrapper(self) -> None:
        self._write_valid_capture()
        event = self._capture_event()
        event["command"] = "/bin/zsh -lc {}".format(shlex.quote(self._capture_command()))

        details = self._verify([event])

        self.assertEqual(details["capture_command_count"], 1)
        for inner in (
            self._capture_command() + "; ls",
            self._capture_command() + " && true",
            self._capture_command() + " | cat",
        ):
            with self.subTest(inner=inner):
                bad = dict(event)
                bad["command"] = "/bin/zsh -lc {}".format(shlex.quote(inner))
                with self.assertRaisesRegex(AssertionError, "compound|exact|capture"):
                    self._verify([bad])

    def test_rejects_nonexact_or_unneeded_pending_output_commit(self) -> None:
        self._write_valid_capture()
        pending = Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-fixture"
        expected = "python3 {} commit-output {}".format(self.skill_dir / "scripts" / "kcap.py", pending)
        cases = (
            expected + " --project-dir {}".format(self.workspace / "project"),
            expected.replace("commit-output", "capture"),
            expected.replace(str(pending), str(self.workspace / "not-a-pending-directory")),
        )
        for command in cases:
            with self.subTest(command=command):
                with self.assertRaisesRegex(AssertionError, "commit-output|pending|capture"):
                    self._verify([self._capture_event(), {"type": "command_execution", "command": command}])

    def test_rejects_nested_claude_bash_capture_without_completion_evidence(self) -> None:
        self._write_valid_capture()
        event = {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Bash",
                        "input": {"command": self._capture_command()},
                    }
                ]
            },
        }

        with self.assertRaisesRegex(AssertionError, "completed|exit|controller|provenance"):
            self._verify([event])

    def test_accepts_nested_claude_bash_capture_only_with_matching_tool_result(self) -> None:
        capture = self._write_valid_capture()
        tool_id = "toolu_kcap_capture"
        events = [
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": tool_id,
                            "name": "Bash",
                            "input": {"command": self._capture_command()},
                        }
                    ]
                },
            },
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": json.dumps(
                                {"ok": True, "status": "created", "output_file": str(capture.resolve())}
                            ),
                        }
                    ]
                },
            },
        ]

        details = self._verify(events)

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())

    def test_rejects_duplicate_claude_tool_result_for_completed_bash_use(self) -> None:
        """A second result must not be silently ignored after command completion."""
        capture = self._write_valid_capture()
        tool_id = "toolu_kcap_capture"
        result = {
            "type": "tool_result",
            "tool_use_id": tool_id,
            "content": json.dumps({"ok": True, "status": "created", "output_file": str(capture.resolve())}),
        }
        events = [
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": tool_id,
                            "name": "Bash",
                            "input": {"command": self._capture_command()},
                        }
                    ]
                },
            },
            {"type": "user", "message": {"content": [result]}},
            {"type": "user", "message": {"content": [result]}},
        ]

        with self.assertRaisesRegex(AssertionError, "duplicate|completed|result"):
            self._verify(events)

    def test_live_prompt_requires_a_public_capture_and_conditional_pending_commit(self) -> None:
        config = self.workspace / "project" / "research-toolkit.json"
        prompt = live_prompt(config, self.output_root, self.skill_dir)

        self.assertIn("public capture command", prompt)
        self.assertIn("If and only if", prompt)
        self.assertIn('commit-output "PENDING_DIRECTORY"', prompt)
        self.assertIn("Do not use Task", prompt)
        self.assertIn("Do not run any other command", prompt)
        self.assertNotIn('{"status": "passed"}', prompt)

    def test_deduplicates_matching_codex_started_and_completed_command_events(self) -> None:
        self._write_valid_capture()
        command = self._capture_command()
        details = self._verify(
            [
                {
                    "type": "item.started",
                    "item": {"id": "capture-1", "type": "command_execution", "command": command},
                },
                {
                    "type": "item.completed",
                    "item": {
                        "id": "capture-1",
                        "type": "command_execution",
                        "command": command,
                        "status": "completed",
                        "exit_code": 0,
                        "aggregated_output": json.dumps(
                            {
                                "ok": True,
                                "status": "created",
                                "output_file": str(
                                    (self.output_root / "captures" / "video.md").resolve()
                                ),
                            }
                        ),
                    },
                },
            ]
        )

        self.assertEqual(details["capture_command_count"], 1)

    def test_rejects_distinct_or_ambiguous_codex_command_lifecycle_events(self) -> None:
        self._write_valid_capture()
        command = self._capture_command()
        cases = (
            [
                {
                    "type": "item.started",
                    "item": {"id": "capture-1", "type": "command_execution", "command": command},
                },
                {
                    "type": "item.completed",
                    "item": {"id": "capture-1", "type": "command_execution", "command": command},
                },
                {
                    "type": "item.started",
                    "item": {"id": "capture-2", "type": "command_execution", "command": command},
                },
                {
                    "type": "item.completed",
                    "item": {"id": "capture-2", "type": "command_execution", "command": command},
                },
            ],
            [
                {
                    "type": "item.started",
                    "item": {"id": "capture-1", "type": "command_execution", "command": command},
                },
                {
                    "type": "item.completed",
                    "item": {
                        "id": "capture-1",
                        "type": "command_execution",
                        "command": command + " --mode standard",
                    },
                },
            ],
        )
        for events in cases:
            with self.subTest(events=events):
                with self.assertRaisesRegex(AssertionError, "exactly one|lifecycle|ambiguous|command"):
                    self._verify(events)

    def test_rejects_task_and_non_bash_nested_command_carriers(self) -> None:
        self._write_valid_capture()
        events = (
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "name": "Task", "input": {}}]},
            },
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "Read",
                            "input": {"command": self._capture_command()},
                        }
                    ]
                },
            },
        )
        for event in events:
            with self.subTest(event=event):
                with self.assertRaisesRegex(AssertionError, "command-execution|capture|provenance"):
                    self._verify([event])

    def test_unwraps_desktop_codex_json_catalog_and_retains_legacy_text(self) -> None:
        catalog_root = self.workspace / "catalog" / "skills"
        catalog = (
            "<skills_instructions>\n"
            f"- `r0` = `{catalog_root}`\n"
            "- kcap: Description (file: r0/kcap/SKILL.md)"
        )
        desktop_envelope = json.dumps(
            [{"role": "developer", "content": [{"type": "input_text", "text": catalog}]}]
        )
        expected = [catalog_root / "kcap" / "SKILL.md"]

        self.assertEqual(codex_catalog_skill_paths(desktop_envelope, "kcap"), expected)
        self.assertEqual(codex_catalog_skill_paths(catalog, "kcap"), expected)

    def test_selects_only_the_marker_bearing_desktop_developer_catalog(self) -> None:
        catalog_root = self.workspace / "catalog" / "skills"
        catalog = (
            "<skills_instructions>\n"
            f"- `r0` = `{catalog_root}`\n"
            "- kcap: Description (file: r0/kcap/SKILL.md)"
        )
        desktop_envelope = json.dumps(
            [
                {"role": "developer", "content": [{"type": "input_text", "text": "runtime policy"}]},
                {"role": "developer", "content": [{"type": "input_text", "text": catalog}]},
                {"role": "developer", "content": [{"type": "input_text", "text": "additional context"}]},
            ]
        )

        self.assertEqual(
            codex_catalog_skill_paths(desktop_envelope, "kcap"),
            [catalog_root / "kcap" / "SKILL.md"],
        )

    def test_rejects_desktop_catalog_envelopes_without_one_marker_block(self) -> None:
        catalog_root = self.workspace / "catalog" / "skills"
        marker_catalog = (
            "<skills_instructions>\n"
            f"- `r0` = `{catalog_root}`\n"
            "- kcap: Description (file: r0/kcap/SKILL.md)"
        )
        envelopes = (
            json.dumps(
                [{"role": "developer", "content": [{"type": "input_text", "text": "runtime policy"}]}]
            ),
            json.dumps(
                [
                    {"role": "developer", "content": [{"type": "input_text", "text": marker_catalog}]},
                    {"role": "developer", "content": [{"type": "input_text", "text": marker_catalog}]},
                ]
            ),
        )
        for envelope in envelopes:
            with self.subTest(envelope=envelope):
                with self.assertRaisesRegex(AssertionError, "marker|catalog|ambiguous"):
                    codex_catalog_skill_paths(envelope, "kcap")

    def test_full_direct_copy_manifest_rejects_missing_changed_and_extra_files(self) -> None:
        source = self.workspace / "source"
        copied = self.workspace / "copied"
        source.mkdir()
        copied.mkdir()
        (source / "controller.py").write_text("source\n", encoding="utf-8")
        (copied / "controller.py").write_text("source\n", encoding="utf-8")
        manifest = tree_byte_manifest(source)
        verify_tree_byte_manifest(manifest, copied, label="direct copy")

        (copied / "controller.py").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "byte|changed|direct copy"):
            verify_tree_byte_manifest(manifest, copied, label="direct copy")
        (copied / "controller.py").write_text("source\n", encoding="utf-8")
        (copied / "extra.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "extra|direct copy"):
            verify_tree_byte_manifest(manifest, copied, label="direct copy")
        (copied / "extra.txt").unlink()
        (copied / "controller.py").unlink()
        with self.assertRaisesRegex(AssertionError, "missing|direct copy"):
            verify_tree_byte_manifest(manifest, copied, label="direct copy")

    def test_cache_manifest_requires_every_source_plugin_file_but_allows_metadata(self) -> None:
        source = self.workspace / "workflow-source"
        cache = self.workspace / "workflow-cache"
        (source / "commands").mkdir(parents=True)
        (cache / "commands").mkdir(parents=True)
        (source / "commands" / "workflow.md").write_text("workflow\n", encoding="utf-8")
        (source / ".DS_Store").write_bytes(b"ignored macOS metadata")
        (cache / "commands" / "workflow.md").write_text("workflow\n", encoding="utf-8")
        (cache / "metadata.json").write_text("{}\n", encoding="utf-8")
        manifest = tree_byte_manifest(source)
        verify_tree_byte_manifest(manifest, cache, allow_extra=True, label="workflow cache")

        (cache / "commands" / "workflow.md").unlink()
        with self.assertRaisesRegex(AssertionError, "missing|workflow cache"):
            verify_tree_byte_manifest(manifest, cache, allow_extra=True, label="workflow cache")

    def test_claude_isolation_requires_the_full_child_boundary(self) -> None:
        command = [
            "claude", "-p", "--safe-mode", "--no-session-persistence", "--no-chrome",
            "--mcp-config", '{"mcpServers":{}}', "--strict-mcp-config", "--permission-mode", "dontAsk",
            "--disable-slash-commands", "--tools", "",
        ]
        validate_claude_isolation_command(command)

        for required in (
            "--safe-mode", "--no-session-persistence", "--no-chrome", "--mcp-config",
            "--strict-mcp-config", "--permission-mode", "--disable-slash-commands", "--tools",
        ):
            with self.subTest(required=required):
                invalid = list(command)
                invalid.remove(required)
                with self.assertRaisesRegex(AssertionError, "Claude|isolation|MCP|tools|permission"):
                    validate_claude_isolation_command(invalid)
        invalid_tools = list(command)
        invalid_tools[-1] = "Read,Write"
        with self.assertRaisesRegex(AssertionError, "tools"):
            validate_claude_isolation_command(invalid_tools)

    def test_private_auth_copy_is_regular_mode_0600_and_preserves_source(self) -> None:
        source = self.workspace / "source-auth.json"
        destination = self.workspace / "isolated-codex-home" / "auth.json"
        source.write_bytes(b'{"tokens":{"access_token":"fixture"}}\n')

        snapshot = create_private_auth_copy(source, destination)

        self.assertTrue(destination.is_file())
        self.assertFalse(destination.is_symlink())
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        verify_source_auth_unchanged(source, snapshot)

        source.write_bytes(b'{"tokens":{"access_token":"changed"}}\n')
        with self.assertRaisesRegex(AssertionError, "source authentication|bytes|metadata"):
            verify_source_auth_unchanged(source, snapshot)

    def test_codex_live_environment_uses_only_a_private_temp_home(self) -> None:
        project = self.workspace / "live-codex"
        config = project / "research-toolkit.json"
        codex_home = self.workspace / "codex-home"
        sqlite_home = project / "codex-sqlite"

        environment = codex_live_environment(project, config, codex_home, sqlite_home)

        self.assertEqual(environment["HOME"], str(project / "home"))
        self.assertNotEqual(environment["HOME"], str(Path.home()))
        self.assertEqual(environment["CODEX_HOME"], str(codex_home))
        self.assertEqual(environment["CODEX_SQLITE_HOME"], str(sqlite_home))
        self.assertEqual(environment["TMPDIR"], str(project))

    def test_starduster_claude_live_environment_preserves_managed_login_home(self) -> None:
        build_environment = getattr(acceptance_runner, "starduster_claude_live_environment", None)
        self.assertTrue(callable(build_environment), "missing Starduster Claude live environment seam")
        project = self.workspace / "live-starduster-claude"
        config = project / "research-toolkit.json"

        environment = build_environment(project, config, "fixture-github-token")

        self.assertNotIn("HOME", environment)
        self.assertEqual(environment["TMPDIR"], str(project))
        self.assertEqual(environment["GH_TOKEN"], "fixture-github-token")
        self.assertEqual(environment["RESEARCH_TOOLKIT_RUNTIME"], "claude")

    def test_starduster_claude_bash_event_requires_an_explicit_long_timeout(self) -> None:
        extract = getattr(acceptance_runner, "starduster_claude_bash_evidence", None)
        self.assertTrue(callable(extract), "missing Starduster Claude Bash evidence seam")
        command = "python3 /temporary/starduster/scripts/starduster.py sync --limit 5"
        event = {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Bash",
                        "input": {"command": command, "timeout": 600000},
                    }
                ]
            },
        }

        self.assertEqual(extract([event]), {"command": command, "timeout_ms": 600000})

        event["message"]["content"][0]["input"].pop("timeout")
        with self.assertRaisesRegex(AssertionError, "timeout"):
            extract([event])

    def test_starduster_controller_path_is_narrow_and_deterministic(self) -> None:
        build_path = getattr(acceptance_runner, "starduster_controller_path", None)
        self.assertTrue(callable(build_path), "missing Starduster controller PATH seam")

        value = build_path(
            Path("/trusted/python/bin/python3"),
            Path("/trusted/github/bin/gh"),
        )

        self.assertEqual(
            value.split(os.pathsep),
            ["/trusted/python/bin", "/trusted/github/bin", "/usr/bin", "/bin"],
        )
        self.assertNotIn("/attacker/bin", value)

    def test_safe_controller_error_code_rejects_non_contract_stderr(self) -> None:
        extract = getattr(acceptance_runner, "safe_controller_error_code", None)
        self.assertTrue(callable(extract), "missing safe controller error parser")

        self.assertEqual(
            extract('{"error":{"code":"missing_dependency","message":"Required dependency is unavailable"},"ok":false}\n'),
            "missing_dependency",
        )
        self.assertIsNone(extract("raw model output"))
        self.assertIsNone(
            extract('{"error":{"code":"bad code","message":"unsafe"},"ok":false}\n')
        )

    def test_accepts_exact_command_event_for_the_temporary_capture(self) -> None:
        capture = self._write_valid_capture()

        details = self._verify(
            [self._capture_event()],
            final_host_message="I captured the video, trust me.",
        )

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())
        self.assertEqual(details["capture_command_count"], 1)

    def test_rejects_non_command_events_and_non_capture_invocations(self) -> None:
        self._write_valid_capture()
        non_command_event = {"type": "agent_message", "command": self._capture_command()}
        manual_invocation = {
            "type": "command_execution",
            "command": f"python3 {self.skill_dir / 'scripts' / 'kcap.py'} extract {SOURCE_URL}",
        }

        for event in (non_command_event, manual_invocation):
            with self.subTest(event=event):
                with self.assertRaisesRegex(AssertionError, "command|capture|provenance"):
                    self._verify([event])

    def test_rejects_another_installed_kcap_copy_even_when_the_temporary_copy_ran(self) -> None:
        self._write_valid_capture()
        installed_copy = self.workspace / "installed" / "skills" / "kcap"
        installed_copy.parent.mkdir(parents=True)
        shutil.copytree(SOURCE_SKILL, installed_copy)

        with self.assertRaisesRegex(AssertionError, "different|temporary|provenance"):
            self._verify([self._capture_event(), self._capture_event(installed_copy)])

    def test_rejects_low_level_and_raw_content_reader_commands(self) -> None:
        self._write_valid_capture()
        forbidden_commands = (
            f"yt-dlp --skip-download {SOURCE_URL}",
            f"python3 -c \"print('manual extraction')\" > {self.output_root / 'content.txt'}",
            f"cat {self.output_root / 'content.txt'}",
            f"rg summary {self.output_root / 'synthesis.json'}",
        )

        for command in forbidden_commands:
            with self.subTest(command=command):
                events = [self._capture_event(), {"type": "command_execution", "command": command}]
                with self.assertRaisesRegex(AssertionError, "manual|raw|reader|command|provenance"):
                    self._verify(events)

    def test_resolves_catalog_aliases_symlinks_and_reported_paths_to_temporary_package(self) -> None:
        self._write_valid_capture()
        catalog_root = self.workspace / "codex-catalog" / "skills"
        catalog_root.parent.mkdir()
        catalog_root.symlink_to(self.skill_dir.parent)
        reported_skill = catalog_root / "kcap" / "SKILL.md"

        details = self._verify(
            [self._capture_event()],
            catalog_aliases={"r0": catalog_root},
            catalog_paths=["r0/kcap/SKILL.md", reported_skill],
        )

        self.assertTrue(details["catalog_source_verified"])

    def test_treats_var_and_private_var_spellings_as_the_same_physical_path(self) -> None:
        self._write_valid_capture()
        private_skill = Path("/private/var/folders/kcap-live/skills/kcap")
        var_skill = Path("/var/folders/kcap-live/skills/kcap")
        private_command = (
            f"python3 {private_skill / 'scripts' / 'kcap.py'} capture {SOURCE_URL} "
            "--project-dir /private/var/folders/kcap-live/project"
        )

        event = self._capture_event()
        event["command"] = private_command
        details = verify_live_host_acceptance(
            [event],
            skill_dir=var_skill,
            output_root=self.output_root,
            source_url=SOURCE_URL,
            catalog_aliases={},
            catalog_paths=[],
            source_auth_before=self.auth_metadata,
            source_auth_after=self._metadata(self.auth_file),
            expected_project_dir=Path("/var/folders/kcap-live/project"),
            final_host_message="untrusted final prose",
        )

        self.assertEqual(details["capture_command_count"], 1)

    def test_uses_verified_filesystem_effects_not_final_host_prose(self) -> None:
        lying_response = {
            "source_url": SOURCE_URL,
            "output_file": str(self.output_root / "captures" / "claimed.md"),
            "status": "success",
        }
        with self.assertRaisesRegex(AssertionError, "output|file|filesystem"):
            self._verify([self._capture_event()], final_host_message=lying_response)

        wrong_capture = self._write_valid_capture()
        wrong_capture.write_text("---\nsource: https://example.test/wrong\n---\n", encoding="utf-8")
        with self.assertRaisesRegex(AssertionError, "source|output|filesystem"):
            self._verify([self._capture_event()], final_host_message=lying_response)

        self._write_valid_capture()
        details = self._verify([self._capture_event()], final_host_message="I cannot provide a useful summary.")
        self.assertEqual(Path(str(details["output_file"])).resolve(), wrong_capture.resolve())

    def test_rejects_direct_controller_output_file_that_differs_from_sole_note(self) -> None:
        capture = self._write_valid_capture()
        claimed = self.output_root / "captures" / "claimed.md"
        event = self._capture_event()
        event["stdout"] = json.dumps({"ok": True, "status": "created", "output_file": str(claimed)})
        event["output_files_after"] = [str(claimed)]

        with self.assertRaisesRegex(AssertionError, "output|filesystem|result"):
            self._verify([event])

        self.assertTrue(capture.is_file())

    def test_controller_json_failure_reports_only_safe_output_shape(self) -> None:
        event = self._capture_event()
        event["stdout"] = "credential-like-canary\nsecond line"

        with self.assertRaises(AssertionError) as failure:
            self._verify([event])

        message = str(failure.exception)
        self.assertIn("output shape", message)
        self.assertIn("byte_length", message)
        self.assertNotIn("credential-like-canary", message)
        self.assertNotIn("second line", message)

    def test_accepts_one_macos_xcrun_cache_warning_before_controller_json(self) -> None:
        capture = self._write_valid_capture()
        event = self._capture_event()
        controller_json = event["stdout"]
        event["stdout"] = (
            "python3: error: couldn't create cache file "
            "'/var/folders/r9/fixture/T/xcrun_db-Ab12Cd34' "
            "(errno=Operation not permitted)\n{}".format(controller_json)
        )

        details = self._verify([event])

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())

    def test_rejects_multiple_macos_xcrun_cache_warnings(self) -> None:
        event = self._capture_event()
        warning = (
            "python3: error: couldn't create cache file "
            "'/var/folders/r9/fixture/T/xcrun_db-Ab12Cd34' "
            "(errno=Operation not permitted)"
        )
        event["stdout"] = "{}\n{}\n{}".format(warning, warning, event["stdout"])

        with self.assertRaisesRegex(AssertionError, "controller JSON|output shape"):
            self._verify([event])

    def test_does_not_claim_whole_run_oauth_source_immutability(self) -> None:
        self._write_valid_capture()
        details = self._verify([self._capture_event()])
        self.assertEqual(self._metadata(self.auth_file), self.auth_metadata)
        self.assertNotIn("source_auth_metadata_unchanged", details)

        changed_metadata = dict(self.auth_metadata)
        changed_metadata["mtime_ns"] += 1
        details = self._verify([self._capture_event()], auth_after=changed_metadata)
        self.assertEqual(details["capture_command_count"], 1)


    # RED contract for controller-result-bound pending output commits.
    def _command_event(
        self,
        command: str,
        result: dict[str, object],
        *,
        exit_code: int = 0,
        execution_status: str = "completed",
        output_before: list[Path] | None = None,
        output_after: list[Path] | None = None,
    ) -> dict[str, object]:
        """Synthetic trusted command evidence, not model-authored final prose."""
        return {
            "type": "command_execution",
            "command": command,
            "status": execution_status,
            "exit_code": exit_code,
            "stdout": json.dumps({"ok": exit_code == 0, **result}, sort_keys=True),
            "output_files_before": [str(path.resolve()) for path in output_before or []],
            "output_files_after": [str(path.resolve()) for path in output_after or []],
        }

    def _pending_authority(self, capsule: Path, capture: Path) -> dict[str, object]:
        return {
            "status": "write_pending",
            "pending_directory": str(capsule.resolve()),
            "output_root": str(self.output_root.resolve()),
            "output_dir": str(capture.parent.resolve()),
            "filename": capture.name,
            "collision": "suffix",
            "capsule_digest": "a" * 64,
        }

    def _commit_command(self, authority: dict[str, object]) -> str:
        return "python3 {} commit-output {} --output-root {} --output-dir {} --filename {} --collision {} --capsule-digest {}".format(
            self.skill_dir / "scripts" / "kcap.py",
            authority["pending_directory"],
            authority["output_root"],
            authority["output_dir"],
            authority["filename"],
            authority["collision"],
            authority["capsule_digest"],
        )

    def test_accepts_a_completed_write_pending_capture_and_exact_successful_commit(self) -> None:
        capture = self._write_valid_capture()
        capsule = Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-authority"
        authority = self._pending_authority(capsule, capture)
        details = self._verify(
            [
                self._command_event(
                    self._capture_command(), authority, output_after=[],
                ),
                self._command_event(
                    self._commit_command(authority),
                    {"status": "created", "output_file": str(capture.resolve())},
                    output_after=[capture],
                ),
            ]
        )

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())
        self.assertEqual(Path(str(details["pending_directory"])), capsule.resolve())

    def test_rejects_a_commit_without_a_successful_write_pending_capture(self) -> None:
        capture = self._write_valid_capture()
        capsule = Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-invented"
        authority = self._pending_authority(capsule, capture)
        capture_results = (
            {"status": "created", "output_file": str(capture.resolve())},
            {"status": "skipped_duplicate", "existing_paths": [str(capture.resolve())]},
            {"status": "write_pending", "pending_directory": str(capsule.resolve())},
        )
        for result in capture_results:
            with self.subTest(result=result):
                with self.assertRaisesRegex(AssertionError, "write_pending|commit|authority"):
                    self._verify(
                        [
                            self._command_event(self._capture_command(), result),
                            self._command_event(
                                self._commit_command(authority),
                                {"status": "created", "output_file": str(capture.resolve())},
                                output_after=[capture],
                            ),
                        ]
                    )

    def test_rejects_incomplete_or_unsuccessful_capture_execution_even_with_write_pending_json(self) -> None:
        capture = self._write_valid_capture()
        authority = self._pending_authority(
            Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-failed-capture", capture
        )
        for exit_code, status in ((1, "completed"), (0, "started")):
            with self.subTest(exit_code=exit_code, status=status):
                with self.assertRaises(AssertionError):
                    self._verify(
                        [
                            self._command_event(
                                self._capture_command(), authority,
                                exit_code=exit_code, execution_status=status,
                            ),
                            self._command_event(
                                self._commit_command(authority),
                                {"status": "created", "output_file": str(capture.resolve())},
                                output_after=[capture],
                            ),
                        ]
                    )

    def test_requires_bounded_success_controller_json_for_a_capture(self) -> None:
        capture = self._write_valid_capture()
        event = self._command_event(
            self._capture_command(), {"status": "created", "output_file": str(capture.resolve())},
            output_after=[capture],
        )
        malformed = dict(event)
        malformed["stdout"] = "not controller JSON"
        oversized = dict(event)
        oversized["stdout"] = "{" + "x" * 65536 + "}"
        for evidence in (malformed, oversized):
            with self.subTest(stdout_bytes=len(str(evidence["stdout"]).encode("utf-8"))):
                with self.assertRaisesRegex(AssertionError, "controller|JSON|bounded|output"):
                    self._verify([evidence])

        with self.assertRaisesRegex(AssertionError, "controller|JSON|bounded|output"):
            self._verify([{"type": "command_execution", "command": self._capture_command()}])

    def test_rejects_each_commit_argument_or_digest_that_differs_from_capture_authority(self) -> None:
        capture = self._write_valid_capture()
        authority = self._pending_authority(
            Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-mismatch", capture
        )
        command = self._commit_command(authority)
        replacements = {
            "capsule": (str(authority["pending_directory"]), str(Path(tempfile.gettempdir()) / "kcap-pending-other")),
            "output root": (str(authority["output_root"]), str(self.workspace / "other-root")),
            "output directory": (str(authority["output_dir"]), str(self.workspace / "other-directory")),
            "filename": (str(authority["filename"]), "other.md"),
            "collision": (str(authority["collision"]), "replace"),
            "digest": (str(authority["capsule_digest"]), "b" * 64),
        }
        for name, (expected, replacement) in replacements.items():
            with self.subTest(authority=name):
                with self.assertRaisesRegex(AssertionError, "commit|authority|pending|digest"):
                    self._verify(
                        [
                            self._command_event(self._capture_command(), authority),
                            self._command_event(
                                command.replace(expected, replacement, 1),
                                {"status": "created", "output_file": str(capture.resolve())},
                                output_after=[capture],
                            ),
                        ]
                    )

    def test_rejects_unsuccessful_or_nonterminal_commit_results_and_missing_output_evidence(self) -> None:
        capture = self._write_valid_capture()
        authority = self._pending_authority(
            Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-commit-result", capture
        )
        cases = (
            (1, "completed", {"status": "created", "output_file": str(capture.resolve())}, [capture]),
            (0, "started", {"status": "created", "output_file": str(capture.resolve())}, [capture]),
            (0, "completed", {"status": "write_pending"}, [capture]),
            (0, "completed", {"status": "created", "output_file": str(capture.resolve())}, []),
        )
        for exit_code, execution_status, result, output_after in cases:
            with self.subTest(result=result, execution_status=execution_status, exit_code=exit_code):
                with self.assertRaisesRegex(AssertionError, "completed|exit|created|replaced|skipped_duplicate|output"):
                    self._verify(
                        [
                            self._command_event(self._capture_command(), authority),
                            self._command_event(
                                self._commit_command(authority), result,
                                exit_code=exit_code, execution_status=execution_status,
                                output_after=output_after,
                            ),
                        ]
                    )

    def test_rejects_preexisting_or_mismatched_output_claimed_as_commit_success(self) -> None:
        capture = self._write_valid_capture()
        other = self.output_root / "captures" / "other.md"
        other.write_text(capture.read_text(encoding="utf-8"), encoding="utf-8")
        authority = self._pending_authority(
            Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-output", capture
        )
        cases = (
            ([capture], [capture], str(capture.resolve())),
            ([], [capture], str(other.resolve())),
        )
        for output_before, output_after, output_file in cases:
            with self.subTest(output_before=output_before, output_file=output_file):
                with self.assertRaisesRegex(AssertionError, "preexisting|output|filesystem"):
                    self._verify(
                        [
                            self._command_event(self._capture_command(), authority),
                            self._command_event(
                                self._commit_command(authority),
                                {"status": "created", "output_file": output_file},
                                output_before=output_before, output_after=output_after,
                            ),
                        ]
                    )

    def test_accepts_a_completed_skipped_duplicate_commit_only_with_matching_existing_file_evidence(self) -> None:
        capture = self._write_valid_capture()
        authority = self._pending_authority(
            Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-skipped", capture
        )
        details = self._verify(
            [
                self._command_event(self._capture_command(), authority),
                self._command_event(
                    self._commit_command(authority),
                    {"status": "skipped_duplicate", "existing_paths": [str(capture.resolve())]},
                    output_before=[capture], output_after=[capture],
                ),
            ]
        )

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())

    def test_accepts_a_completed_replaced_commit_only_with_matching_output_file(self) -> None:
        capture = self._write_valid_capture()
        authority = self._pending_authority(
            Path(tempfile.gettempdir()) / "kcap-pending-live-provenance-replaced", capture
        )
        details = self._verify(
            [
                self._command_event(self._capture_command(), authority),
                self._command_event(
                    self._commit_command(authority),
                    {"status": "replaced", "output_file": str(capture.resolve())},
                    output_before=[capture], output_after=[capture],
                ),
            ]
        )

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())


class CodexLivePathIsolationTests(unittest.TestCase):
    def test_codex_live_case_does_not_manufacture_a_command_event_via_app_server_command_exec(self) -> None:
        """Keep the live path tied to host events, not a controller shortcut."""
        tree = ast.parse(textwrap.dedent(inspect.getsource(acceptance_runner.codex_live_case)))
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

        self.assertNotIn("run_codex_app_server_capture", called_names)

    def test_kcap_codex_live_case_requires_the_bundled_desktop_binary(self) -> None:
        tree = ast.parse(textwrap.dedent(inspect.getsource(acceptance_runner.codex_live_case)))
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }

        self.assertIn("require_bundled_desktop_codex_for_live", called_names)

    def test_codex_host_task_is_ephemeral_ignores_user_state_and_enables_only_workspace_network(self) -> None:
        command = "python3 /tmp/kcap/scripts/kcap.py capture https://example.com --project-dir /tmp/project"
        stream = "\n".join(
            (
                json.dumps(
                    {
                        "type": "item.started",
                        "item": {"id": "cmd-1", "type": "command_execution", "command": command},
                    }
                ),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {
                            "id": "cmd-1",
                            "type": "command_execution",
                            "command": command,
                            "status": "completed",
                            "exit_code": 0,
                            "aggregated_output": json.dumps(
                                {"ok": True, "status": "created", "output_file": "/tmp/project/note.md"}
                            ),
                        },
                    }
                ),
            )
        )
        with patch.object(
            acceptance_runner,
            "run",
            return_value=subprocess.CompletedProcess(["codex"], 0, stream, ""),
        ) as run:
            acceptance_runner.run_codex_exec_host_task(
                codex_bin=Path("/Applications/ChatGPT.app/Contents/Resources/codex"),
                prompt="Use $kcap",
                cwd=Path(tempfile.gettempdir()),
                environment={"CODEX_HOME": str(Path(tempfile.gettempdir()) / "codex-home")},
            )

        arguments = run.call_args.args[0]
        self.assertEqual(arguments.count("--ephemeral"), 1)
        for flag in ("--ignore-user-config", "--ignore-rules", "--skip-git-repo-check"):
            self.assertIn(flag, arguments)
        self.assertIn('approval_policy="never"', arguments)
        self.assertIn("sandbox_workspace_write.network_access=true", arguments)


class CodexAppServerProvenanceTests(unittest.TestCase):
    """RED contract for the isolated Codex App Server live-runtime replacement.

    These tests deliberately name the small runner seams that the replacement
    must provide.  They do not invoke a model, read an installed Codex config,
    or depend on an ambient API key.
    """

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="kcap-app-server-provenance-")
        self.workspace = Path(self._temporary_directory.name)
        self.skill_dir = self.workspace / "isolated" / "skills" / "kcap"
        self.skill_dir.parent.mkdir(parents=True)
        shutil.copytree(SOURCE_SKILL, self.skill_dir)
        self.output_root = self.workspace / "output"
        self.output_root.mkdir()
        self.capture_command = (
            f"python3 {self.skill_dir / 'scripts' / 'kcap.py'} capture {SOURCE_URL} "
            f"--project-dir {self.workspace / 'project'}"
        )

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def _seam(self, name: str) -> Callable[..., Any]:
        seam = getattr(acceptance_runner, name, None)
        if not callable(seam):
            self.fail(f"missing required Codex App Server acceptance seam: {name}")
        return seam

    def test_app_server_acceptance_seams_exist(self) -> None:
        required = (
            "verify_codex_app_server_provenance_report",
            "requested_codex_live_auth_legs",
            "requested_codex_live_result",
        )
        missing = [name for name in required if not runner_seam_available(name)]
        self.assertEqual(missing, [], "missing required Codex App Server acceptance seams")

    def _valid_report(self) -> dict[str, object]:
        """Minimal safe report; raw prompts, auth, and tool payloads are absent."""
        return {
            "runtime": "codex-app-server",
            "transport": "stdio",
            "binary": {
                "path": str(BUNDLED_CODEX_BINARY),
                "version": "codex fixture-bundled-build",
                "source": "bundled-desktop",
            },
            "session": {"ephemeral": True},
            "code_mode": {
                "allowed_operations": ["exec", "wait"],
                "lifecycle": ["thread.start", "turn.start", "turn.complete"],
            },
            "provenance": {
                "capture_command": self.capture_command,
                "public_host_command_count": 1,
                "catalog_source": str(self.skill_dir / "SKILL.md"),
                "output_root": str(self.output_root),
            },
            "sandbox": {
                "network": "deny",
                "filesystem": {"root": "deny", "tmp": "deny", "slash_tmp": "deny"},
            },
            "environment": {"mode": "empty", "allowed": []},
            "auth": {
                "mode": "oauth",
                "source_unchanged": True,
                "auth_copy_boundary_verified": True,
                "private_copy_removed": True,
            },
            "prohibited_event_count": 0,
        }

    def _verify_report(
        self,
        report: dict[str, object],
        *,
        expected_auth_mode: str = "oauth",
        expected_synthesis_batches: int | None = None,
    ) -> dict[str, object]:
        verify = self._seam("verify_codex_app_server_provenance_report")
        kwargs: dict[str, object] = {
            "expected_binary": BUNDLED_CODEX_BINARY,
            "expected_capture_command": self.capture_command,
            "expected_catalog_path": self.skill_dir / "SKILL.md",
            "expected_output_root": self.output_root,
            "expected_auth_mode": expected_auth_mode,
        }
        if expected_synthesis_batches is not None:
            kwargs["expected_synthesis_batches"] = expected_synthesis_batches
        return verify(report, **kwargs)


    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_requires_a_sanitized_ephemeral_stdio_app_server_provenance_report(self) -> None:
        details = self._verify_report(self._valid_report())

        self.assertEqual(details["runtime"], "codex-app-server")
        self.assertEqual(details["transport"], "stdio")
        self.assertEqual(details["binary"], str(BUNDLED_CODEX_BINARY))
        self.assertEqual(details["version"], "codex fixture-bundled-build")
        self.assertEqual(details["capture_command"], self.capture_command)
        self.assertEqual(details["prohibited_event_count"], 0)
        self.assertNotIn("prompt", json.dumps(details, sort_keys=True).lower())
        self.assertNotIn("token", json.dumps(details, sort_keys=True).lower())

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_records_any_nonempty_bundled_codex_version(self) -> None:
        report = self._valid_report()
        report["binary"]["version"] = "codex fixture-signed-build"

        details = self._verify_report(report)

        self.assertEqual(details["version"], "codex fixture-signed-build")

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_rejects_non_code_mode_or_prohibited_app_server_activity(self) -> None:
        invalid_reports = (
            {**self._valid_report(), "prohibited_event_count": 1},
            {
                **self._valid_report(),
                "code_mode": {
                    "allowed_operations": ["exec", "wait", "read_file"],
                    "lifecycle": ["thread.start", "turn.start", "turn.complete"],
                },
            },
            {
                **self._valid_report(),
                "code_mode": {
                    "allowed_operations": ["exec", "wait"],
                    "lifecycle": ["thread.start", "turn.start"],
                },
            },
        )
        for report in invalid_reports:
            with self.subTest(report=report):
                with self.assertRaisesRegex(AssertionError, "prohibited|Code Mode|lifecycle|exec|wait"):
                    self._verify_report(report)

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_requires_empty_environment_and_deny_root_tmp_network_sandbox_evidence(self) -> None:
        invalid_reports = (
            {**self._valid_report(), "environment": {"mode": "inherited", "allowed": ["PATH"]}},
            {
                **self._valid_report(),
                "sandbox": {
                    "network": "allow",
                    "filesystem": {"root": "deny", "tmp": "deny", "slash_tmp": "deny"},
                },
            },
            {
                **self._valid_report(),
                "sandbox": {
                    "network": "deny",
                    "filesystem": {"root": "allow", "tmp": "deny", "slash_tmp": "deny"},
                },
            },
            {
                **self._valid_report(),
                "sandbox": {
                    "network": "deny",
                    "filesystem": {"root": "deny", "tmp": "allow", "slash_tmp": "deny"},
                },
            },
            {
                **self._valid_report(),
                "sandbox": {
                    "network": "deny",
                    "filesystem": {"root": "deny", "tmp": "deny", "slash_tmp": "allow"},
                },
            },
        )
        for report in invalid_reports:
            with self.subTest(report=report):
                with self.assertRaisesRegex(AssertionError, "environment|sandbox|network|root|tmp"):
                    self._verify_report(report)

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_requires_exact_temporary_capture_and_private_oauth_copy_cleanup_evidence(self) -> None:
        invalid_reports = (
            {
                **self._valid_report(),
                "provenance": {
                    **self._valid_report()["provenance"],
                    "capture_command": self.capture_command + " --mode standard",
                },
            },
            {
                **self._valid_report(),
                "provenance": {
                    **self._valid_report()["provenance"],
                    "public_host_command_count": 2,
                },
            },
            {
                **self._valid_report(),
                "auth": {
                    "mode": "oauth",
                    "auth_copy_boundary_verified": True,
                    "private_copy_removed": False,
                },
            },
        )
        for report in invalid_reports:
            with self.subTest(report=report):
                with self.assertRaisesRegex(AssertionError, "capture|command|OAuth|authentication|cleanup"):
                    self._verify_report(report)

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_accepts_api_key_evidence_without_oauth_claims(self) -> None:
        report = self._valid_report()
        report["auth"] = {
            "mode": "api_key",
            "ephemeral_login": True,
            "persistent_credentials": False,
        }

        details = self._verify_report(report, expected_auth_mode="api_key")

        self.assertEqual(details["runtime"], "codex-app-server")

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_rejects_unrecognized_report_fields_including_raw_or_credential_shaped_data(self) -> None:
        for field, value in (
            ("unreviewed", True),
            ("credential_hint", "not-a-secret"),
            ("raw_content", "fixture-only"),
        ):
            with self.subTest(field=field):
                report = self._valid_report()
                report[field] = value
                with self.assertRaisesRegex(AssertionError, "schema|field|report|sensitive"):
                    self._verify_report(report)

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_rejects_unrecognized_nested_report_fields(self) -> None:
        report = self._valid_report()
        report["binary"]["unexpected"] = "fixture"

        with self.assertRaisesRegex(AssertionError, "schema|binary|field"):
            self._verify_report(report)

    def test_codex_live_auth_copy_is_oauth_only_and_removed_after_each_attempt(self) -> None:
        """The live harness must not create OAuth state for an API-key leg."""
        for function_name in ("codex_live_case", "starduster_codex_live_case"):
            source = inspect.getsource(getattr(acceptance_runner, function_name))
            with self.subTest(function=function_name):
                self.assertIn('if auth_leg == "oauth"', source)
                self.assertIn("remove_private_auth_copy", source)

    def test_private_oauth_copy_removal_verifies_the_path_is_gone(self) -> None:
        remove = getattr(acceptance_runner, "remove_private_auth_copy", None)
        self.assertTrue(callable(remove), "missing private OAuth cleanup seam")
        destination = self.workspace / "private" / "auth.json"
        destination.parent.mkdir()
        destination.write_text("fixture", encoding="utf-8")
        destination.chmod(0o600)

        remove(destination)

        self.assertFalse(destination.exists())

    def test_starduster_oauth_copy_is_removed_when_catalog_invocation_raises(self) -> None:
        """An exception before controller startup must still clear the private OAuth copy."""
        workspace = self.workspace / "starduster-live"
        source_home = workspace / "source-home"
        source_auth = source_home / ".codex" / "auth.json"
        source_auth.parent.mkdir(parents=True)
        source_auth.write_text("{}\n", encoding="utf-8")
        source_auth.chmod(0o600)
        project = workspace / "live-starduster-codex"
        project.mkdir(parents=True)
        output_root = project / "output"
        output_root.mkdir()
        config = project / "research-toolkit.json"
        config.write_text("{}\n", encoding="utf-8")
        skill_dir = workspace / "live-starduster-codex-home" / "skills" / "starduster"
        skill_dir.mkdir(parents=True)
        auth_copy = workspace / "live-starduster-codex-home" / "auth.json"

        with (
            patch.object(acceptance_runner.Path, "home", return_value=source_home),
            patch.object(acceptance_runner, "preferred_codex_binary", return_value=Path("/bin/echo")),
            patch.object(acceptance_runner, "require_bundled_desktop_codex_for_live", side_effect=lambda value: value),
            patch.object(acceptance_runner.shutil, "which", return_value="/bin/echo"),
            patch.object(
                acceptance_runner,
                "prepare_live_starduster_project",
                return_value=(project, output_root, config, skill_dir, {}),
            ),
            patch.object(acceptance_runner, "run", side_effect=RuntimeError("catalog boom")),
        ):
            with self.assertRaisesRegex(RuntimeError, "catalog boom"):
                acceptance_runner.starduster_codex_live_case(workspace, auth_leg="oauth")

        self.assertFalse(auth_copy.exists(), "outer cleanup must remove the OAuth copy after catalog errors")

    def test_live_starduster_uses_one_five_repository_synthesis_batch(self) -> None:
        """The host must not time out and retry the complete sync between batches."""
        project, _output, config_path, _skill, _manifest = (
            acceptance_runner.prepare_live_starduster_project(self.workspace, "claude")
        )

        config = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertEqual(project, self.workspace / "live-starduster-claude")
        self.assertEqual(config["starduster"]["synthesis_batch_size"], 5)

    def test_kcap_live_path_records_and_verifies_signed_app_server_evidence(self) -> None:
        source = inspect.getsource(acceptance_runner.codex_live_case)
        self.assertIn("RESEARCH_TOOLKIT_ACCEPTANCE_REPORT", source)
        self.assertIn("verify_codex_app_server_provenance_report", source)
        self.assertIn('details["app_server_provenance"]', source)

    def test_live_prompt_requires_same_session_polling_until_controller_completion(self) -> None:
        prompt = acceptance_runner.live_prompt(
            self.workspace / "config.json",
            self.workspace / "output",
            self.workspace / "skill",
        ).lower()

        self.assertIn("same running session", prompt)
        self.assertIn("poll", prompt)
        self.assertIn("terminal controller json", prompt)

    def test_kcap_skill_requires_same_session_polling_for_yielded_commands(self) -> None:
        skill = (ROOT / "research-toolkit" / "skills" / "kcap" / "SKILL.md").read_text(
            encoding="utf-8"
        ).lower()

        self.assertIn("same running session", skill)
        self.assertIn("poll", skill)
        self.assertIn("terminal json", skill)

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_rejects_oauth_claims_in_api_key_evidence(self) -> None:
        report = self._valid_report()
        report["auth"] = {
            "mode": "api_key",
            "source_unchanged": True,
            "private_copy_removed": True,
        }

        with self.assertRaisesRegex(AssertionError, "API-key|authentication"):
            self._verify_report(report, expected_auth_mode="api_key")

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_accepts_zero_work_preflight_with_no_code_operations(self) -> None:
        report = self._valid_report()
        report["synthesis_batches"] = 0
        report["code_mode"] = {
            "allowed_operations": [],
            "lifecycle": ["thread.start"],
        }

        details = self._verify_report(report, expected_synthesis_batches=0)

        self.assertEqual(details["runtime"], "codex-app-server")

    @unittest.skipUnless(
        runner_seam_available("verify_codex_app_server_provenance_report"),
        "requires Codex App Server provenance report verifier",
    )
    def test_rejects_zero_work_report_with_turn_operations_or_wrong_batch_count(self) -> None:
        invalid_reports = (
            {
                **self._valid_report(),
                "synthesis_batches": 0,
            },
            {
                **self._valid_report(),
                "synthesis_batches": 2,
            },
        )
        with self.assertRaisesRegex(AssertionError, "zero-work|batch"):
            self._verify_report(invalid_reports[0], expected_synthesis_batches=0)
        with self.assertRaisesRegex(AssertionError, "batch"):
            self._verify_report(invalid_reports[1], expected_synthesis_batches=1)

    @unittest.skipUnless(
        runner_seam_available("requested_codex_live_auth_legs"),
        "requires Codex live authentication-leg selector",
    )
    def test_requests_api_key_live_leg_only_with_the_dedicated_test_variable(self) -> None:
        select_legs = self._seam("requested_codex_live_auth_legs")

        self.assertEqual(select_legs({}), ["oauth"])
        self.assertEqual(select_legs({"OPENAI_API_KEY": "ambient-must-not-request"}), ["oauth"])
        self.assertEqual(
            select_legs({"RESEARCH_TOOLKIT_TEST_OPENAI_API_KEY": "explicit-test-key"}),
            ["oauth", "api-key"],
        )

    @unittest.skipUnless(
        runner_seam_available("requested_codex_live_result"),
        "requires Codex requested-live result classifier",
    )
    def test_requested_live_oauth_unavailability_is_incomplete_and_nonzero(self) -> None:
        result_for = self._seam("requested_codex_live_result")

        result = result_for("oauth", "not available")
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertNotEqual(result["exit_code"], 0)
        self.assertEqual(result["auth_leg"], "oauth")

    @unittest.skipUnless(
        runner_seam_available("requested_codex_live_result"),
        "requires Codex requested-live result classifier",
    )
    def test_unrequested_api_key_live_leg_is_a_passing_not_requested_case(self) -> None:
        result_for = self._seam("requested_codex_live_result")

        result = result_for("api-key", "not_requested")

        self.assertEqual(result["status"], "not_requested")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["auth_leg"], "api-key")

    def test_direct_copy_and_hplumb_manifests_keep_required_kcap_package_assets(self) -> None:
        manifest = tree_byte_manifest(SOURCE_SKILL)
        required = {
            Path("scripts/kcap.py"),
            Path("schemas/deep.json"),
            Path("schemas/full.json"),
            Path("schemas/standard.json"),
            Path("references/runtime-claude.md"),
            Path("references/runtime-codex.md"),
            Path("agents/openai.yaml"),
            Path("SKILL.md"),
        }
        self.assertTrue(required <= set(manifest), f"missing package assets: {sorted(required - set(manifest))}")

        direct_copy = self.workspace / "direct-copy"
        hplumb_copy = self.workspace / "hplumb-copy"
        shutil.copytree(SOURCE_SKILL, direct_copy)
        shutil.copytree(SOURCE_SKILL, hplumb_copy)
        verify_tree_byte_manifest(manifest, direct_copy, label="direct kcap copy")
        verify_tree_byte_manifest(manifest, hplumb_copy, label="hplumb kcap copy")


class StardusterHostProvenanceRedTests(unittest.TestCase):
    """RED contract for Starduster's public host-controller flow.

    A host may use its own slash-command UI, but evidence is deliberately
    limited to public package-local controller commands and safe JSON. Final
    prose is not evidence of a successful sync.
    """

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="starduster-host-provenance-")
        self.workspace = Path(self._temporary_directory.name)
        self.project = self.workspace / "project with spaces"
        self.project.mkdir()
        self.skill_dir = self.workspace / "isolated skills" / "starduster"
        self.skill_dir.parent.mkdir(parents=True)
        shutil.copytree(STARDUSTER_SKILL, self.skill_dir)
        self.output_root = self.workspace / "output root"
        self.output_root.mkdir()
        self.destination = self.output_root / "github stars"

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def _sync_command(self) -> str:
        return shlex.join([
            "python3", str(self.skill_dir / "scripts" / "starduster.py"), "sync",
            "--limit", "5", "--project-dir", str(self.project),
        ])

    def _configure_command(self) -> str:
        return shlex.join([
            "python3", str(self.skill_dir / "scripts" / "starduster.py"), "configure",
            "--output-dir", str(self.destination), "--project-dir", str(self.project),
        ])

    @staticmethod
    def _event(command: str, result: dict[str, object], *, output_after: list[Path] | None = None) -> dict[str, object]:
        return {
            "type": "command_execution", "command": command, "status": "completed", "exit_code": 0,
            "stdout": json.dumps({"ok": True, **result}, sort_keys=True),
            "output_files_after": [str(path.resolve()) for path in output_after or []],
        }

    @staticmethod
    def _error_event(command: str, code: str, *, details: dict[str, object] | None = None) -> dict[str, object]:
        error: dict[str, object] = {"code": code, "message": "safe controller error"}
        if details:
            error["details"] = details
        return {
            "type": "command_execution", "command": command, "status": "completed", "exit_code": 1,
            "stdout": "", "stderr": json.dumps({"ok": False, "error": error}, sort_keys=True),
            "output_files_after": [],
        }

    def _write_successful_catalog(self) -> list[Path]:
        repo_root = self.destination / "repos"
        repo_root.mkdir(parents=True)
        paths = []
        for number in range(5):
            path = repo_root / "owner-{}.md".format(number)
            path.write_text("---\nrepo: owner/{}\n---\n".format(number), encoding="utf-8")
            paths.append(path)
        for number in range(7):
            path = self.destination / "indexes" / "index-{}.base".format(number)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("views: []\n", encoding="utf-8")
            paths.append(path)
        return paths

    def _verify(self, events: list[dict[str, object]], *, final_host_message: object = None) -> dict[str, object]:
        verify = getattr(acceptance_runner, "verify_starduster_host_acceptance", None)
        self.assertTrue(callable(verify), "missing Starduster host provenance verifier")
        return verify(
            events, skill_dir=self.skill_dir, output_root=self.output_root,
            expected_project_dir=self.project, expected_limit=5, final_host_message=final_host_message,
        )

    def test_raw_limit_invocation_maps_to_one_public_sync_and_filesystem_success(self) -> None:
        output_files = self._write_successful_catalog()
        details = self._verify(
            [self._event(self._sync_command(), {"status": "completed"}, output_after=output_files)],
            final_host_message="Five repositories were captured.",
        )
        self.assertEqual(details["sync_command_count"], 1)
        self.assertTrue(details["filesystem_derived"])
        self.assertEqual(details["repo_note_count"], 5)
        self.assertEqual(details["base_index_count"], 7)

    def test_missing_destination_uses_the_exact_four_command_first_run_flow(self) -> None:
        output_files = self._write_successful_catalog()
        pending = Path(tempfile.gettempdir()) / "starduster-pending-host-provenance"
        authority = {
            "status": "write_pending", "pending_directory": str(pending.resolve()),
            "output_root": str(self.output_root.resolve()), "output_dir": str(self.destination.resolve()),
            "capsule_digest": "b" * 64,
        }
        commit = shlex.join([
            "python3", str(self.skill_dir / "scripts" / "starduster.py"), "commit-output",
            authority["pending_directory"], "--output-root", authority["output_root"],
            "--output-dir", authority["output_dir"], "--capsule-digest", authority["capsule_digest"],
        ])
        details = self._verify([
            self._error_event(
                self._sync_command(), "output_path_required",
                details={"suggested_path": "~/Documents/starduster"},
            ),
            self._event(self._configure_command(), {"status": "configured", "output_dir": str(self.destination.resolve())}),
            self._event(self._sync_command(), authority),
            self._event(commit, {"status": "completed"}, output_after=output_files),
        ])
        self.assertEqual(details["configure_command_count"], 1)
        self.assertEqual(details["sync_command_count"], 2)
        self.assertEqual(details["commit_output_command_count"], 1)
        self.assertEqual(Path(str(details["configured_output_dir"])), self.destination.resolve())
        self.assertEqual(Path(str(details["pending_directory"])), pending.resolve())

    def test_output_path_required_is_an_exit_one_safe_stderr_error(self) -> None:
        event = self._error_event(self._sync_command(), "output_path_required")
        self.assertEqual(event["exit_code"], 1)
        self.assertEqual(event["stdout"], "")
        self.assertIn('"ok": false', str(event["stderr"]))
        parse_error = getattr(acceptance_runner, "bounded_safe_controller_error", None)
        self.assertTrue(callable(parse_error), "missing bounded safe controller error parser")
        parsed = parse_error(event, operation="Starduster sync", expected_code="output_path_required")
        self.assertEqual(parsed["error"]["code"], "output_path_required")

    def test_write_pending_allows_only_a_controller_bound_narrow_commit(self) -> None:
        output_files = self._write_successful_catalog()
        pending = Path(tempfile.gettempdir()) / "starduster-pending-host-provenance-pending"
        authority = {
            "status": "write_pending", "pending_directory": str(pending.resolve()),
            "output_root": str(self.output_root.resolve()), "output_dir": str(self.destination.resolve()),
            "capsule_digest": "b" * 64,
        }
        commit = shlex.join([
            "python3", str(self.skill_dir / "scripts" / "starduster.py"), "commit-output",
            str(authority["pending_directory"]), "--output-root", str(authority["output_root"]),
            "--output-dir", str(authority["output_dir"]), "--capsule-digest", str(authority["capsule_digest"]),
        ])
        details = self._verify([
            self._event(self._sync_command(), authority),
            self._event(commit, {"status": "completed"}, output_after=output_files),
        ])
        self.assertEqual(details["commit_output_command_count"], 1)
        self.assertEqual(Path(str(details["pending_directory"])), pending.resolve())

        raw_reader = {"type": "command_execution", "command": "cat {}/manifest.json".format(pending)}
        with self.assertRaisesRegex(AssertionError, "raw|reader|commit-output|provenance"):
            self._verify([
                self._event(self._sync_command(), authority), raw_reader,
                self._event(commit, {"status": "completed"}, output_after=output_files),
            ])


class CodexAppServerCommandExecTests(unittest.TestCase):
    """Contract for deterministic live-host invocation through command/exec."""

    def setUp(self) -> None:
        self._temporary_directory = tempfile.TemporaryDirectory(prefix="kcap-command-exec-")
        self.workspace = Path(self._temporary_directory.name)
        self.project = self.workspace / "project"
        self.project.mkdir()
        self.skill_dir = self.workspace / "codex-home" / "skills" / "kcap"
        self.skill_dir.parent.mkdir(parents=True)
        shutil.copytree(SOURCE_SKILL, self.skill_dir)
        self.request_log = self.workspace / "request.json"
        self.fake_codex = self.workspace / "fake-codex"
        self.fake_codex.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
import time

mode = os.environ.get("FAKE_APP_SERVER_MODE", "ok")
initialize = json.loads(sys.stdin.readline())
print(json.dumps({"id": initialize["id"], "result": {"userAgent": "fake"}}), flush=True)
json.loads(sys.stdin.readline())
request = json.loads(sys.stdin.readline())
with open(os.environ["FAKE_REQUEST_LOG"], "w", encoding="utf-8") as handle:
    json.dump(request, handle)
if mode == "malformed":
    print("{broken", flush=True)
elif mode == "mismatched":
    print(json.dumps({"id": request["id"] + 1, "result": {"exitCode": 0, "stdout": "", "stderr": ""}}), flush=True)
elif mode == "server_request":
    print(json.dumps({"id": 99, "method": "item/commandExecution/requestApproval", "params": {}}), flush=True)
elif mode == "unknown_notification":
    print(json.dumps({"method": "unexpected/changed", "params": {}}), flush=True)
elif mode == "passive_notification":
    print(json.dumps({"method": "remoteControl/status/changed", "params": {}}), flush=True)
    print(json.dumps({"id": request["id"], "result": {"exitCode": 0, "stdout": "", "stderr": ""}}), flush=True)
elif mode == "nonzero":
    print(json.dumps({"id": request["id"], "result": {"exitCode": 7, "stdout": "RAW_STDOUT", "stderr": "RAW_STDERR"}}), flush=True)
elif mode == "oversized":
    print(json.dumps({"id": request["id"], "result": {"exitCode": 0, "stdout": "X" * 4096, "stderr": ""}}), flush=True)
elif mode == "timeout":
    time.sleep(2)
elif mode == "premature_exit":
    sys.exit(0)
else:
    print(json.dumps({"id": request["id"], "result": {"exitCode": 0, "stdout": '{"status":"created"}', "stderr": ""}}), flush=True)
""",
            encoding="utf-8",
        )
        self.fake_codex.chmod(0o700)
        self.argv = [
            "python3",
            str((self.skill_dir / "scripts" / "kcap.py").resolve()),
            "capture",
            SOURCE_URL,
            "--project-dir",
            str(self.project.resolve()),
        ]

    def tearDown(self) -> None:
        self._temporary_directory.cleanup()

    def _run(self, mode: str = "ok", **overrides: object) -> dict[str, object]:
        helper = getattr(acceptance_runner, "run_codex_app_server_capture", None)
        if not callable(helper):
            self.fail("missing deterministic Codex App Server command/exec helper")
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "FAKE_APP_SERVER_MODE": mode,
            "FAKE_REQUEST_LOG": str(self.request_log),
        }
        arguments: dict[str, object] = {
            "codex_bin": self.fake_codex,
            "argv": self.argv,
            "cwd": self.project,
            "environment": environment,
            "timeout_seconds": 1.0,
            "output_bytes_cap": 1024,
        }
        arguments.update(overrides)
        return helper(**arguments)

    def test_issues_one_exact_sandboxed_command_exec_and_returns_only_safe_evidence(self) -> None:
        evidence = self._run()
        request = json.loads(self.request_log.read_text(encoding="utf-8"))

        self.assertEqual(request["method"], "command/exec")
        self.assertEqual(request["params"]["command"], self.argv)
        self.assertEqual(request["params"]["cwd"], str(self.project.resolve()))
        self.assertEqual(
            request["params"]["sandboxPolicy"],
            {
                "type": "workspaceWrite",
                "writableRoots": [str(self.project.resolve())],
                "networkAccess": True,
                "excludeTmpdirEnvVar": True,
                "excludeSlashTmp": True,
            },
        )
        self.assertEqual(request["params"]["timeoutMs"], 1000)
        self.assertEqual(request["params"]["outputBytesCap"], 1024)
        self.assertEqual(evidence["event"]["type"], "command_execution")
        self.assertEqual(evidence["event"]["argv"], self.argv)
        serialized = json.dumps(evidence, sort_keys=True)
        self.assertNotIn("RAW_STDOUT", serialized)
        self.assertNotIn('{"status":"created"}', serialized)
        self.assertEqual(evidence["exit_code"], 0)

    def test_accepts_only_the_signed_build_passive_status_notification(self) -> None:
        self.assertEqual(self._run("passive_notification")["exit_code"], 0)

    def test_rejects_protocol_and_process_failures_without_returning_raw_output(self) -> None:
        cases = (
            ("malformed", "JSON|protocol"),
            ("mismatched", "ID|response"),
            ("server_request", "request|notification|protocol"),
            ("unknown_notification", "request|notification|protocol"),
            ("nonzero", "exit|command"),
            ("oversized", "output|limit"),
            ("timeout", "timeout|timed out"),
            ("premature_exit", "exit|response"),
        )
        for mode, pattern in cases:
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(AssertionError, pattern) as raised:
                    self._run(mode, timeout_seconds=0.1 if mode == "timeout" else 1.0)
                self.assertNotIn("RAW_STDOUT", str(raised.exception))
                self.assertNotIn("RAW_STDERR", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
