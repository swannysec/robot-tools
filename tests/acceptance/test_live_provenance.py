"""Deterministic simulated-host coverage for live kcap provenance checks.

The runner API exercised here deliberately treats a host's final prose as
untrusted.  `verify_live_host_acceptance` must establish success from command
events, catalog provenance, source-auth metadata snapshots, and files beneath
the temporary output root.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
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

    def _capture_event(self, skill_dir: Path | None = None) -> dict[str, str]:
        return {"type": "command_execution", "command": self._capture_command(skill_dir)}

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
        self._verify([{"type": "command_execution", "command": expected}])

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

    def test_accepts_exact_nested_claude_bash_capture_event(self) -> None:
        capture = self._write_valid_capture()
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

        details = self._verify([event])

        self.assertEqual(Path(str(details["output_file"])), capture.resolve())

    def test_live_prompt_requires_one_shell_action_without_inviting_unverified_success(self) -> None:
        config = self.workspace / "project" / "research-toolkit.json"
        prompt = live_prompt(config, self.output_root, self.skill_dir)

        self.assertIn("sole required action", prompt)
        self.assertIn("shell command", prompt)
        self.assertIn("Do not use Task", prompt)
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
                    "item": {"id": "capture-1", "type": "command_execution", "command": command},
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

        details = verify_live_host_acceptance(
            [{"type": "command_execution", "command": private_command}],
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

    def test_preserves_source_auth_metadata_and_rejects_changed_snapshots(self) -> None:
        self._write_valid_capture()
        details = self._verify([self._capture_event()])
        self.assertEqual(self._metadata(self.auth_file), self.auth_metadata)
        self.assertTrue(details["source_auth_metadata_unchanged"])

        changed_metadata = dict(self.auth_metadata)
        changed_metadata["mtime_ns"] += 1
        with self.assertRaisesRegex(AssertionError, "auth|metadata|source"):
            self._verify([self._capture_event()], auth_after=changed_metadata)


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
                "private_copy_removed": True,
            },
            "prohibited_event_count": 0,
        }

    def _verify_report(self, report: dict[str, object]) -> dict[str, object]:
        verify = self._seam("verify_codex_app_server_provenance_report")
        return verify(
            report,
            expected_binary=BUNDLED_CODEX_BINARY,
            expected_capture_command=self.capture_command,
            expected_catalog_path=self.skill_dir / "SKILL.md",
            expected_output_root=self.output_root,
        )


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
                "auth": {"mode": "oauth", "source_unchanged": True, "private_copy_removed": False},
            },
        )
        for report in invalid_reports:
            with self.subTest(report=report):
                with self.assertRaisesRegex(AssertionError, "capture|command|OAuth|authentication|cleanup"):
                    self._verify_report(report)

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
