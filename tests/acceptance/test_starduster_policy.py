"""Acceptance coverage for Starduster's portable policy boundary.

The controller is intentionally exercised only through its public ``sync``
command.  Every external dependency is a local executable fixture so these
tests neither read the user's GitHub state nor launch Obsidian.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
STARDUSTER_CLI = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster.py"
FAKE_CODEX_APP_SERVER = ROOT / "tests" / "fixtures" / "codex-app-server" / "fake_codex_app_server.py"
RAW_DESCRIPTION = "RAW_STARDUSTER_DESCRIPTION_MUST_NOT_REACH_RESULT"
RAW_README = "RAW_STARDUSTER_README_MUST_NOT_REACH_RESULT"
RAW_MODEL = "RAW_STARDUSTER_MODEL_OUTPUT_MUST_NOT_REACH_RESULT"
SECRET = "STARDUSTER_AMBIENT_SECRET_MUST_NOT_REACH_ADAPTER"
SYNTHETIC_OAUTH = (
    b'{"auth_mode":"chatgpt","tokens":{"access_token":"fixture-access",'
    b'"id_token":"fixture-identity","refresh_token":"fixture-refresh"}}\n'
)


class StardusterPolicyAcceptanceTests(unittest.TestCase):
    """Hermetic process-level tests for the Starduster controller contract."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starduster-policy-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.project = self.root / "project"
        self.bin_dir = self.root / "bin"
        self.work_root = self.root / "work"
        self.output = self.root / "vault"
        for directory in (self.home, self.project, self.bin_dir, self.work_root):
            directory.mkdir()
        self.config = self.root / "research-toolkit.json"
        self.write_config(self.config, self.output)
        self._write_fixtures()

    def write_config(self, path: Path, output: Path, **starduster: object) -> None:
        value: dict[str, object] = {
            "output_path": str(output),
            "subfolder": "catalog",
            "vault_name": None,
            "synthesis_profile": "fast",
            "synthesis_batch_size": 1,
        }
        value.update(starduster)
        path.write_text(
            json.dumps({"schema_version": 1, "starduster": value}), encoding="utf-8"
        )

    def write_legacy(self, body: str) -> None:
        self.write_legacy_document("---\nstarduster:\n" + body + "---\n")

    def write_legacy_document(self, document: str) -> None:
        legacy = self.project / ".claude" / "research-toolkit.local.md"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        legacy.write_text(document, encoding="utf-8")

    def write_executable(self, name: str, source: str) -> Path:
        path = self.bin_dir / name
        path.write_text(source, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return path

    def _write_fixtures(self) -> None:
        self.write_executable(
            "gh",
            "#!/bin/sh\n"
            "if [ -n \"${STARDUSTER_FIXTURE_GH_LOG:-}\" ]; then printf '%s\\n' \"$*\" >> \"$STARDUSTER_FIXTURE_GH_LOG\"; fi\n"
            "if [ \"$1\" = auth ] && [ \"${STARDUSTER_FIXTURE_GH_AUTH:-ok}\" != ok ]; then exit 1; fi\n"
            "if [ \"$1\" = auth ]; then printf '%s\\n' 'github.com: logged in'; exit 0; fi\n"
            "if [ \"$1\" = api ] && [ \"$2\" = /rate_limit ]; then\n"
            "  if [ \"${STARDUSTER_FIXTURE_RATE:-normal}\" = high ]; then\n"
            "    printf '%s\\n' '{\"resources\":{\"core\":{\"remaining\":4},\"graphql\":{\"remaining\":4}}}'\n"
            "  else\n"
            "    printf '%s\\n' '{\"resources\":{\"core\":{\"remaining\":5000},\"graphql\":{\"remaining\":5000}}}'\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$1\" = api ] && [ \"$2\" = /user/starred ]; then\n"
            "  if [ \"${STARDUSTER_FIXTURE_STARS:-one}\" = empty ]; then printf '%s\\n' '[]'; else\n"
            "    printf '%s\\n' '[{\"starred_at\":\"2026-01-01T00:00:00Z\",\"repo\":{\"full_name\":\"fixture/repository\",\"description\":\"" + RAW_DESCRIPTION + "\",\"language\":\"Python\",\"topics\":[\"fixture\"],\"html_url\":\"https://github.com/fixture/repository\",\"owner\":{\"login\":\"fixture\"},\"stargazers_count\":1,\"forks_count\":0,\"archived\":false,\"fork\":false,\"created_at\":\"2026-01-01T00:00:00Z\",\"pushed_at\":\"2026-01-01T00:00:00Z\"}}]'\n"
            "    if [ \"${STARDUSTER_FIXTURE_STARS:-one}\" = duplicates ]; then printf '%s\\n' '[{\"starred_at\":\"2026-01-01T00:00:00Z\",\"repo\":{\"full_name\":\"fixture/repository\",\"description\":\"" + RAW_DESCRIPTION + "\",\"language\":\"Python\",\"topics\":[\"fixture\"],\"html_url\":\"https://github.com/fixture/repository\",\"owner\":{\"login\":\"fixture\"},\"stargazers_count\":1,\"forks_count\":0,\"archived\":false,\"fork\":false,\"created_at\":\"2026-01-01T00:00:00Z\",\"pushed_at\":\"2026-01-01T00:00:00Z\"}}]'; fi\n"
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"$1\" = api ] && [ \"$2\" = graphql ]; then\n"
            "  printf '%s\\n' '{\"data\":{\"viewer\":{\"starredRepositories\":{\"totalCount\":1}},\"repository\":{\"object\":{\"text\":\"" + RAW_README + "\"}},\"rateLimit\":{\"remaining\":4999}}}'\n"
            "  exit 0\n"
            "fi\n"
            "exit 64\n",
        )
        claude_adapter = (
            "#!/bin/sh\n"
            "if [ -n \"${STARDUSTER_FIXTURE_RUNTIME_LOG:-}\" ]; then printf '%s|%s|%s|%s|%s|%s|%s\\n' \"$0\" \"${OPENAI_API_KEY-unset}\" \"${ANTHROPIC_API_KEY-unset}\" \"${AWS_SECRET_ACCESS_KEY-unset}\" \"${GITHUB_TOKEN-unset}\" \"${GH_TOKEN-unset}\" \"$*\" >> \"$STARDUSTER_FIXTURE_RUNTIME_LOG\"; fi\n"
            "if [ \"${STARDUSTER_FIXTURE_INTERRUPT:-}\" = 1 ]; then kill -INT \"$PPID\"; exit 130; fi\n"
            "if [ \"$1\" = --help ]; then printf '%s\\n' '--safe-mode --no-session-persistence --no-chrome --tools --mcp-config --strict-mcp-config --json-schema --permission-mode'; exit 0; fi\n"
            "if [ \"${STARDUSTER_FIXTURE_FAILURE:-}\" = synthesis ]; then exit 42; fi\n"
            "if [ \"${STARDUSTER_FIXTURE_FAILURE:-}\" = validation ]; then printf '%s\\n' '{\"not\":\"a valid synthesis array\"}'; exit 0; fi\n"
            "result='[{\"full_name\":\"fixture/repository\",\"html_url\":\"https://github.com/fixture/repository\",\"category\":\"Developer Tools\",\"normalized_topics\":[\"fixture\"],\"summary\":\"" + RAW_MODEL + "\",\"key_features\":[\"fixture\",\"portable\",\"safe\"],\"similar_to\":[],\"use_case\":\"Fixture use case.\",\"maturity\":\"active\",\"author_display\":\"Fixture\"}]'\n"
            "output=''\n"
            "while [ \"$#\" -gt 0 ]; do if [ \"$1\" = --output-last-message ]; then shift; output=$1; fi; shift; done\n"
            "if [ -n \"$output\" ]; then printf '%s\\n' \"$result\" > \"$output\"; fi\n"
            "printf '%s\\n' \"$result\"\n"
        )
        self.write_executable("claude", claude_adapter)
        codex_result = json.dumps(
            {"synthesis": [{
                "full_name": "fixture/repository",
                "html_url": "https://github.com/fixture/repository",
                "category": "Developer Tools",
                "normalized_topics": ["fixture"],
                "summary": RAW_MODEL,
                "key_features": ["fixture", "portable", "safe"],
                "similar_to": [],
                "use_case": "Fixture use case.",
                "maturity": "active",
                "author_display": "Fixture",
            }]},
            separators=(",", ":"),
        )
        self.write_executable(
            "codex",
            "#!/bin/sh\n"
            "if [ -n \"${STARDUSTER_FIXTURE_RUNTIME_LOG:-}\" ]; then printf '%s|%s|%s|%s|%s|%s|%s\\n' \"$0\" \"${OPENAI_API_KEY-unset}\" \"${ANTHROPIC_API_KEY-unset}\" \"${AWS_SECRET_ACCESS_KEY-unset}\" \"${GITHUB_TOKEN-unset}\" \"${GH_TOKEN-unset}\" \"$*\" >> \"$STARDUSTER_FIXTURE_RUNTIME_LOG\"; fi\n"
            "if [ \"$1\" = --version ]; then printf '%s\\n' 'codex fixture-signed-build'; exit 0; fi\n"
            "if { [ \"$1\" = features ] && [ \"$2\" = list ]; } || [ \"$1\" = app-server ]; then\n"
            "  export KCAP_APP_SERVER_FIXTURE_LOG='" + str(self.root / "codex-rpc.log") + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_CLEANUP='" + str(self.root / "codex-server-cleanup.log") + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_RESULT='" + codex_result + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_PERMISSION_PROFILE='starduster_synthesis'\n"
            "  exec python3 '" + str(FAKE_CODEX_APP_SERVER) + "' \"$@\"\n"
            "fi\n"
            "exit 64\n",
        )
        self.write_executable(
            "open",
            "#!/bin/sh\n"
            "if [ -n \"${STARDUSTER_FIXTURE_OPEN_LOG:-}\" ]; then printf '%s\\n' \"$*\" >> \"$STARDUSTER_FIXTURE_OPEN_LOG\"; fi\n"
            "exit 0\n",
        )

    def environment(self, runtime: str = "claude", **extra: str) -> dict[str, str]:
        environment = os.environ.copy()
        for name in (
            "CLAUDECODE", "CLAUDE_CODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_SESSION_ID",
            "CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SANDBOX", "CODEX_CI",
        ):
            environment.pop(name, None)
        environment.update(
            {
                "HOME": str(self.home),
                "TMPDIR": str(self.work_root),
                "RESEARCH_TOOLKIT_CONFIG": str(self.config),
                "RESEARCH_TOOLKIT_RUNTIME": runtime,
                "PATH": "{}:{}".format(self.bin_dir, os.defpath),
            }
        )
        environment.update(extra)
        return environment

    def sync(
        self,
        *arguments: str,
        runtime: str | None = "claude",
        expected_returncode: int = 0,
        **environment: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        if not STARDUSTER_CLI.is_file():
            self.fail("missing Starduster controller: {}".format(STARDUSTER_CLI))
        selected_environment = self.environment(runtime or "")
        if runtime is None:
            selected_environment.pop("RESEARCH_TOOLKIT_RUNTIME", None)
        selected_environment.update(environment)
        process = subprocess.run(
            [sys.executable, str(STARDUSTER_CLI), "sync", "--project-dir", str(self.project), *arguments],
            cwd=ROOT,
            env=selected_environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(
            process.returncode,
            expected_returncode,
            "sync stderr:\n{}\nstdout:\n{}".format(process.stderr, process.stdout),
        )
        stream = process.stdout if expected_returncode == 0 else process.stderr
        try:
            payload = json.loads(stream)
        except json.JSONDecodeError as exc:
            self.fail("controller must emit one JSON envelope: {}\n{}".format(exc, stream))
        self.assertIsInstance(payload, dict)
        return process, payload

    def workspaces(self) -> list[Path]:
        return sorted(self.work_root.glob("starduster-*"))

    def assert_safe(self, process: subprocess.CompletedProcess[str], payload: object) -> None:
        visible = process.stdout + process.stderr + json.dumps(payload, sort_keys=True)
        for value in (RAW_DESCRIPTION, RAW_README, RAW_MODEL, SECRET):
            self.assertNotIn(value, visible)

    def assert_success(
        self,
        process: subprocess.CompletedProcess[str],
        payload: dict[str, Any],
        output_dir: Path | None = None,
    ) -> None:
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(Path(payload["output_dir"]), output_dir or self.output / "catalog")
        self.assertIsInstance(payload["warnings"], list)
        self.assertIn("counts", payload)
        self.assertIsInstance(payload["counts"], dict)
        for name, value in payload["counts"].items():
            self.assertIsInstance(name, str)
            self.assertIsInstance(value, int)
            self.assertGreaterEqual(value, 0)
        self.assertIsNone(payload["obsidian_uri"])
        self.assert_safe(process, payload)

    def assert_error(self, process: subprocess.CompletedProcess[str], payload: dict[str, Any]) -> None:
        self.assertFalse(payload["ok"])
        self.assertIsInstance(payload.get("error"), dict)
        self.assertIsInstance(payload["error"].get("code"), str)
        self.assertTrue(payload["error"]["code"])
        self.assertIsInstance(payload["error"].get("message"), str)
        if "details" in payload["error"]:
            self.assertIsInstance(payload["error"]["details"], dict)
        self.assert_safe(process, payload)

    def test_gh_preflight_auth_and_dependency_failure_stop_before_fetch_or_synthesis(self) -> None:
        for label, environment in (
            ("auth", {"STARDUSTER_FIXTURE_GH_AUTH": "failed"}),
            ("missing", {"PATH": os.defpath}),
        ):
            with self.subTest(label=label):
                gh_log = self.root / "{}.gh.log".format(label)
                runtime_log = self.root / "{}.runtime.log".format(label)
                process, payload = self.sync(
                    expected_returncode=1,
                    STARDUSTER_FIXTURE_GH_LOG=str(gh_log),
                    STARDUSTER_FIXTURE_RUNTIME_LOG=str(runtime_log),
                    **environment,
                )
                self.assert_error(process, payload)
                if gh_log.exists():
                    self.assertNotIn("api /user/starred", gh_log.read_text(encoding="utf-8"))
                self.assertFalse(runtime_log.exists())
                self.assertEqual(self.workspaces(), [])

    def test_missing_pyyaml_is_a_safe_startup_failure(self) -> None:
        """A direct installation without PyYAML must not leak an import traceback."""
        gh_log = self.root / "missing-yaml.gh.log"
        environment = self.environment(STARDUSTER_FIXTURE_GH_LOG=str(gh_log))
        process = subprocess.run(
            [sys.executable, "-S", str(STARDUSTER_CLI), "sync", "--project-dir", str(self.project)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(process.returncode, 1, process.stderr)
        self.assertEqual(process.stdout, "")
        self.assertNotIn("Traceback", process.stderr)
        self.assertEqual(len(process.stderr.splitlines()), 1)
        payload = json.loads(process.stderr)
        self.assertEqual(payload["error"]["code"], "missing_dependency")
        self.assertIn("PyYAML", payload["error"]["message"])
        self.assertFalse(gh_log.exists())
        self.assertEqual(self.workspaces(), [])

    def test_rate_confirmation_is_structured_rerunnable_and_noninteractive_never_prompts(self) -> None:
        runtime_log = self.root / "rate.runtime.log"
        gh_log = self.root / "rate.gh.log"
        process, payload = self.sync(
            expected_returncode=1,
            STARDUSTER_FIXTURE_RATE="high",
            STARDUSTER_FIXTURE_RUNTIME_LOG=str(runtime_log),
            STARDUSTER_FIXTURE_GH_LOG=str(gh_log),
        )
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "confirmation_required")
        self.assertIn("--confirm-rate", json.dumps(payload["error"].get("details", {})))
        self.assertEqual(payload["error"]["details"]["threshold_percent"], 25)
        self.assertGreater(payload["error"]["details"]["estimated_percent"], 25)
        self.assertGreaterEqual(payload["error"]["details"]["estimated_core_calls"], 1)
        self.assertGreaterEqual(payload["error"]["details"]["estimated_graphql_calls"], 1)
        self.assertFalse(runtime_log.exists())
        self.assertNotIn("api /user/starred", gh_log.read_text(encoding="utf-8"))
        self.assertEqual(self.workspaces(), [])
        self.assertFalse((self.output / "catalog").exists())

        process, payload = self.sync(
            "--confirm-rate",
            STARDUSTER_FIXTURE_RATE="high",
            STARDUSTER_FIXTURE_STARS="empty",
        )
        self.assert_success(process, payload)

        open_log = self.root / "noninteractive.open.log"
        process, payload = self.sync(
            expected_returncode=1,
            STARDUSTER_FIXTURE_RATE="high",
            STARDUSTER_FIXTURE_RUNTIME_LOG=str(runtime_log),
            STARDUSTER_FIXTURE_OPEN_LOG=str(open_log),
            RESEARCH_TOOLKIT_NONINTERACTIVE="1",
        )
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "confirmation_required")
        self.assertTrue(payload["error"]["details"]["noninteractive"])
        self.assertFalse(open_log.exists())
        self.assertEqual(self.workspaces(), [])

    def test_workspace_cleanup_and_preservation_boundaries(self) -> None:
        process, payload = self.sync(STARDUSTER_FIXTURE_STARS="empty")
        self.assert_success(process, payload)
        self.assertEqual(self.workspaces(), [])

        for failure in ("synthesis",):
            with self.subTest(failure=failure):
                process, payload = self.sync(
                    expected_returncode=1, STARDUSTER_FIXTURE_FAILURE=failure
                )
                self.assert_error(process, payload)
                self.assertEqual(self.workspaces(), [])

                process, payload = self.sync(
                    "--preserve-on-failure",
                    expected_returncode=1,
                    STARDUSTER_FIXTURE_FAILURE=failure,
                )
                self.assert_error(process, payload)
                paths = self.workspaces()
                try:
                    self.assertEqual(len(paths), 1)
                    self.assertEqual(stat.S_IMODE(paths[0].stat().st_mode), 0o700)
                    self.assertEqual(
                        Path(payload["error"]["details"]["recovery_path"]).resolve(), paths[0].resolve()
                    )
                finally:
                    for path in paths:
                        shutil.rmtree(path)

        process, payload = self.sync(STARDUSTER_FIXTURE_FAILURE="validation")
        self.assert_success(process, payload)
        self.assertEqual(payload["counts"]["skipped"], 1)
        self.assertEqual(self.workspaces(), [])

        blocked_note = self.output / "catalog" / "repos" / "fixture-repository.md"
        blocked_note.mkdir(parents=True)
        render_log = self.root / "render.runtime.log"
        process, payload = self.sync(
            "--preserve-on-failure",
            STARDUSTER_FIXTURE_RUNTIME_LOG=str(render_log),
        )
        self.assert_success(process, payload)
        self.assertTrue(render_log.exists(), "the collision check must occur after synthesis")
        self.assertTrue((blocked_note.parent / "fixture-repository-2.md").is_file())
        self.assertEqual(self.workspaces(), [])

        process, payload = self.sync(
            "--preserve-on-failure",
            expected_returncode=1,
            STARDUSTER_FIXTURE_RATE="high",
        )
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "confirmation_required")
        self.assertNotIn("recovery_path", payload["error"].get("details", {}))
        self.assertEqual(self.workspaces(), [])

    def test_renderer_exception_cleans_or_returns_a_recovery_path(self) -> None:
        """An ordinary renderer failure must not bypass private-workspace cleanup."""
        blocked_repos = self.output / "catalog" / "repos"
        blocked_repos.parent.mkdir(parents=True)
        blocked_repos.write_text("not a directory", encoding="utf-8")

        process, payload = self.sync(expected_returncode=1)
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "internal_error")
        self.assertEqual(self.workspaces(), [])

        process, payload = self.sync("--preserve-on-failure", expected_returncode=1)
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "internal_error")
        paths = self.workspaces()
        try:
            self.assertEqual(len(paths), 1)
            self.assertEqual(Path(payload["error"]["details"]["recovery_path"]).resolve(), paths[0].resolve())
            self.assertEqual(stat.S_IMODE(paths[0].stat().st_mode), 0o700)
        finally:
            for path in paths:
                shutil.rmtree(path)

    def test_keyboard_interrupt_cleans_the_private_workspace(self) -> None:
        process, payload = self.sync(
            "--preserve-on-failure",
            expected_returncode=1,
            STARDUSTER_FIXTURE_INTERRUPT="1",
        )
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "interrupted")
        self.assertNotIn("recovery_path", payload["error"].get("details", {}))
        self.assertEqual(self.workspaces(), [])

    def test_codex_auth_failures_are_never_eligible_for_workspace_preservation(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("starduster_auth_cleanup", STARDUSTER_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        script_dir = str(STARDUSTER_CLI.parent)
        sys.path.insert(0, script_dir)
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path.remove(script_dir)

        preserved: Path | None = None
        with self.assertRaises(module.StardusterError) as failure:
            with module.workspace(True) as work_dir:
                preserved = work_dir
                private_auth = work_dir / "codex-operation-fixture" / "codex-home" / "auth.json"
                private_auth.parent.mkdir(parents=True)
                private_auth.write_bytes(SYNTHETIC_OAUTH)
                raise module.StardusterError("codex_auth_error", "Could not remove private Codex state")

        self.assertEqual(failure.exception.code, "codex_auth_error")
        self.assertNotIn("recovery_path", failure.exception.details or {})
        assert preserved is not None
        self.assertFalse(preserved.exists())

    def test_neutral_config_precedence_and_legacy_migration_rules(self) -> None:
        env_output = self.root / "env-vault"
        home_output = self.root / "home-vault"
        home_config = self.home / ".config" / "robot-tools" / "research-toolkit.json"
        home_config.parent.mkdir(parents=True)
        self.write_config(home_config, home_output)
        legacy_output = self.root / "legacy-vault"
        self.write_legacy(
            "  output_path: {}\n"
            "  subfolder: catalog\n"
            "  vault_name: null\n"
            "  synthesis_model: sonnet\n"
            "  main_model: opus\n"
            "  synthesis_batch_size: 1\n".format(legacy_output)
        )
        env_config = self.root / "environment.json"
        self.write_config(env_config, env_output)

        process, payload = self.sync(
            STARDUSTER_FIXTURE_STARS="empty", RESEARCH_TOOLKIT_CONFIG=str(env_config)
        )
        self.assert_success(process, payload, env_output / "catalog")
        self.assertEqual(Path(payload["output_dir"]), env_output / "catalog")

        process, payload = self.sync(
            STARDUSTER_FIXTURE_STARS="empty", RESEARCH_TOOLKIT_CONFIG=""
        )
        self.assert_success(process, payload, home_output / "catalog")
        self.assertEqual(Path(payload["output_dir"]), home_output / "catalog")

        home_config.unlink()
        inherited_output = self.root / "legacy-inherited-defaults"
        self.write_legacy("  output_path: {}\n".format(inherited_output))
        process, payload = self.sync(RESEARCH_TOOLKIT_CONFIG="")
        self.assert_success(process, payload, inherited_output / "tools" / "github")
        self.assertTrue(str(payload["output_dir"]).startswith(str(inherited_output)))

        for legacy_model, expected_model in (
            ("haiku", "haiku"),
            ("sonnet", "sonnet"),
            ("opus", "opus"),
        ):
            with self.subTest(legacy_model=legacy_model):
                selected_output = self.root / "legacy-{}-vault".format(legacy_model)
                self.write_legacy(
                    "  output_path: {}\n"
                    "  subfolder: catalog\n"
                    "  vault_name: null\n"
                    "  synthesis_model: {}\n"
                    "  main_model: opus\n"
                    "  synthesis_batch_size: 1\n".format(selected_output, legacy_model)
                )
                runtime_log = self.root / "legacy-{}.runtime.log".format(legacy_model)
                process, payload = self.sync(
                    STARDUSTER_FIXTURE_RUNTIME_LOG=str(runtime_log), RESEARCH_TOOLKIT_CONFIG=""
                )
                self.assert_success(process, payload, selected_output / "catalog")
                self.assertEqual(Path(payload["output_dir"]), selected_output / "catalog")
                self.assertTrue(any("0.6.x" in warning for warning in payload["warnings"]))
                self.assertTrue(any("main_model" in warning for warning in payload["warnings"]))
                self.assertIn(expected_model, runtime_log.read_text(encoding="utf-8"))

        self.config.write_text("{not json", encoding="utf-8")
        process, payload = self.sync(expected_returncode=1)
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "invalid_config")

        self.config.write_text(json.dumps({"schema_version": 2, "starduster": {}}), encoding="utf-8")
        process, payload = self.sync(expected_returncode=1)
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "unsupported_schema")

        self.write_legacy_document("---\nother_skill:\n  enabled: true\n---\n")
        process, payload = self.sync(expected_returncode=1, RESEARCH_TOOLKIT_CONFIG="")
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "missing_legacy_section")

    def test_runtime_is_fail_closed_uses_only_selected_adapter_and_scrubs_ambient_secrets(self) -> None:
        for runtime in ("claude", "codex"):
            with self.subTest(runtime=runtime):
                log = self.root / "{}.adapter.log".format(runtime)
                decoy_log = self.root / "decoy.log"
                self.write_executable(
                    "starduster",
                    "#!/bin/sh\nprintf '%s\\n' invoked >> '{}'\n".format(decoy_log),
                )
                oauth_home = self.root / "{}-oauth".format(runtime)
                oauth_home.mkdir()
                oauth = oauth_home / "auth.json"
                descriptor = os.open(oauth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(SYNTHETIC_OAUTH)
                auth = {
                    "RESEARCH_TOOLKIT_CODEX_AUTH": "oauth",
                    "CODEX_HOME": str(oauth_home),
                    "STARDUSTER_CODEX_BIN": str(self.bin_dir / "codex"),
                } if runtime == "codex" else {}
                process, payload = self.sync(
                    runtime=runtime,
                    STARDUSTER_FIXTURE_RUNTIME_LOG=str(log),
                    OPENAI_API_KEY=SECRET,
                    ANTHROPIC_API_KEY=SECRET,
                    AWS_SECRET_ACCESS_KEY=SECRET,
                    GITHUB_TOKEN=SECRET,
                    GH_TOKEN=SECRET,
                    **auth,
                )
                self.assert_success(process, payload)
                records = log.read_text(encoding="utf-8").splitlines()
                self.assertGreaterEqual(len(records), 1)
                for record in records:
                    self.assertTrue(record.startswith(str(self.bin_dir / runtime) + "|"))
                    self.assertNotIn(SECRET, record)
                self.assertFalse(decoy_log.exists())
                if runtime == "codex":
                    command_log = (self.root / "codex-rpc.log").read_text(encoding="utf-8")
                    self.assertIn('"argv": ["features", "list"]', command_log)
                    self.assertIn('"argv": ["app-server", "--stdio"', command_log)

        process, payload = self.sync(runtime="neither", expected_returncode=1)
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "invalid_runtime")

        process, payload = self.sync(
            runtime="", expected_returncode=1, RESEARCH_TOOLKIT_RUNTIME=""
        )
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "unknown_runtime")

        process, payload = self.sync(
            runtime=None,
            STARDUSTER_FIXTURE_STARS="empty",
            CLAUDECODE="1",
        )
        self.assert_success(process, payload)

        process, payload = self.sync(
            runtime=None,
            expected_returncode=1,
            CLAUDECODE="1",
            CODEX_SESSION_ID="fixture-session",
        )
        self.assert_error(process, payload)
        self.assertEqual(payload["error"]["code"], "ambiguous_runtime")

    def test_claude_child_keeps_only_login_identity_and_scrubs_ambient_secrets(self) -> None:
        import importlib.util

        sys.path.insert(0, str(STARDUSTER_CLI.parent))
        spec = importlib.util.spec_from_file_location("starduster_child_environment", STARDUSTER_CLI)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = {
            "PATH": "/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
            "HOME": str(self.home),
            "USER": "fixture-user",
            "LOGNAME": "fixture-user",
            "SHELL": "/bin/zsh",
            "GH_TOKEN": SECRET,
            "OPENAI_API_KEY": SECRET,
            "ANTHROPIC_API_KEY": SECRET,
            "SSH_AUTH_SOCK": SECRET,
            "CLAUDECODE": "1",
            "CODEX_SESSION_ID": "outer-session",
        }

        with patch.dict(os.environ, source, clear=True):
            environment = module.child_environment()

        self.assertEqual(
            environment,
            {
                "PATH": "/usr/bin:/bin",
                "LANG": "en_US.UTF-8",
                "HOME": str(self.home),
                "USER": "fixture-user",
                "LOGNAME": "fixture-user",
                "SHELL": "/bin/zsh",
            },
        )

    def test_codex_acceptance_report_is_written_once_after_all_synthesis_batches(self) -> None:
        oauth_home = self.root / "report-oauth"
        oauth_home.mkdir()
        oauth = oauth_home / "auth.json"
        descriptor = os.open(oauth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(SYNTHETIC_OAUTH)
        report = self.project / "starduster-codex-app-server-report.json"

        process, payload = self.sync(
            runtime="codex",
            STARDUSTER_FIXTURE_STARS="duplicates",
            RESEARCH_TOOLKIT_CODEX_AUTH="oauth",
            CODEX_HOME=str(oauth_home),
            STARDUSTER_CODEX_BIN=str(self.bin_dir / "codex"),
            RESEARCH_TOOLKIT_ACCEPTANCE_REPORT=str(report),
        )

        self.assert_success(process, payload)
        evidence = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(evidence["synthesis_batches"], 2)

    def test_zero_work_codex_sync_uses_isolated_auth_and_writes_a_report(self) -> None:
        oauth_home = self.root / "zero-work-oauth"
        oauth_home.mkdir()
        oauth = oauth_home / "auth.json"
        descriptor = os.open(oauth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(SYNTHETIC_OAUTH)
        report = self.project / "starduster-codex-app-server-report.json"

        process, payload = self.sync(
            runtime="codex",
            STARDUSTER_FIXTURE_STARS="empty",
            RESEARCH_TOOLKIT_CODEX_AUTH="oauth",
            CODEX_HOME=str(oauth_home),
            STARDUSTER_CODEX_BIN=str(self.bin_dir / "codex"),
            RESEARCH_TOOLKIT_ACCEPTANCE_REPORT=str(report),
        )

        self.assert_success(process, payload)
        evidence = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(evidence["synthesis_batches"], 0)
        self.assertEqual(evidence["auth"], {
            "mode": "oauth", "source_unchanged": True, "private_copy_removed": True,
        })
        self.assertEqual(list(self.work_root.rglob("auth.json")), [])

    def test_api_key_report_attests_ephemeral_login_without_oauth_claims(self) -> None:
        report = self.project / "starduster-codex-app-server-report.json"

        process, payload = self.sync(
            runtime="codex",
            RESEARCH_TOOLKIT_CODEX_AUTH="api_key",
            OPENAI_API_KEY="fixture-api-key",
            STARDUSTER_CODEX_BIN=str(self.bin_dir / "codex"),
            RESEARCH_TOOLKIT_ACCEPTANCE_REPORT=str(report),
        )

        self.assert_success(process, payload)
        evidence = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(evidence["auth"], {
            "mode": "api_key", "ephemeral_login": True, "persistent_credentials": False,
        })

    def test_configured_vault_returns_encoded_uri_without_opening_an_application(self) -> None:
        self.write_config(self.config, self.output, vault_name="Team Vault & Notes")
        open_log = self.root / "open.log"
        process, payload = self.sync(
            STARDUSTER_FIXTURE_STARS="empty", STARDUSTER_FIXTURE_OPEN_LOG=str(open_log)
        )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "completed")
        uri = payload["obsidian_uri"]
        self.assertIsInstance(uri, str)
        self.assertNotIn(" ", uri)
        self.assertNotIn("& Notes", uri)
        parsed = parse_qs(urlparse(uri).query)
        self.assertEqual(parsed["vault"], ["Team Vault & Notes"])
        self.assertEqual(parsed["file"], ["catalog"])
        self.assertFalse(open_log.exists())
        self.assert_safe(process, payload)

    def test_safe_result_and_error_schemas_exclude_untrusted_content(self) -> None:
        process, payload = self.sync()
        self.assert_success(process, payload)
        counts = payload["counts"]
        self.assertEqual(counts["total_stars"], 1)
        self.assertEqual(counts["new"], 1)
        self.assertEqual(counts["processed"], 1)

        process, payload = self.sync("--full", STARDUSTER_FIXTURE_FAILURE="validation")
        self.assert_success(process, payload)
        self.assertEqual(payload["counts"]["skipped"], 1)


if __name__ == "__main__":
    unittest.main()
