"""Acceptance coverage for the public, noninteractive kcap capture controller."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
KCAP_CLI = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"
FAKE_CODEX_APP_SERVER = ROOT / "tests" / "fixtures" / "codex-app-server" / "fake_codex_app_server.py"
YOUTUBE_URL = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
RAW_MARKER = "RAW_EXTRACTION_MUST_NEVER_REACH_CONTROLLER_JSON"
CHILD_MARKER = "RAW_CHILD_SYNTHESIS_MUST_NEVER_REACH_CONTROLLER_JSON"

STANDARD_SYNTHESIS = {
    "title": "Fixture Video Capture",
    "author": "Fixture Channel",
    "published": "2026-08-31",
    "tldr": "A safe fixture summary.",
    "summary": "The fixture child produced this structured summary.",
    "takeaways": ["Capture uses the selected isolated runtime."],
    "detailed_notes": "The fake child has no access to host tools.",
    "quotes": [],
    "references": [],
    "tags": ["fixture"],
    "chapters": [],
    "thread": [],
}
SYNTHETIC_ACCOUNT_DOCUMENT = (
    b'{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-access",'
    b'"id_token":"synthetic-identity","refresh_token":"synthetic-refresh"}}\n'
)


class KcapControllerAcceptanceTests(unittest.TestCase):
    """Controller tests use only subprocesses and hermetic executable fixtures."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kcap-controller-test-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.project = self.root / "project"
        self.output = self.root / "output"
        self.work_root = self.root / "work"
        self.bin_dir = self.root / "bin"
        self.site_dir = self.root / "site"
        for directory in (self.home, self.project, self.work_root, self.bin_dir, self.site_dir):
            directory.mkdir()
        self.config = self.root / "research-toolkit.json"
        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kcap": {
                        "output_path": str(self.output),
                        "subfolder": "captures",
                        "vault_name": None,
                        "default_tags": ["controller-fixture"],
                        "default_mode": "standard",
                        "synthesis_profile": "fast",
                    },
                }
            ),
            encoding="utf-8",
        )
        self._write_fixtures()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_executable(self, name: str, source: str) -> None:
        path = self.bin_dir / name
        path.write_text(source, encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    def _write_private_fixture(self, path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)

    def _write_fixtures(self) -> None:
        # This prevents URL validation from asking the host resolver.  8.8.8.8 is
        # deliberately public, so it exercises the same address validation path.
        (self.site_dir / "sitecustomize.py").write_text(
            "import socket\n"
            "def fixture_getaddrinfo(host, port, *args, **kwargs):\n"
            "    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', port))]\n"
            "socket.getaddrinfo = fixture_getaddrinfo\n",
            encoding="utf-8",
        )
        self._write_executable(
            "youtube_transcript_api",
            "#!/bin/sh\n"
            "if [ \"${KCAP_FIXTURE_LARGE:-0}\" = 1 ]; then\n"
            "  i=0\n"
            "  while [ \"$i\" -lt 15001 ]; do printf 'large '; i=$((i + 1)); done\n"
            "else\n"
            "  i=0\n"
            "  while [ \"$i\" -lt 80 ]; do printf 'transcript '; i=$((i + 1)); done\n"
            f"  printf '%s' ' {RAW_MARKER}'\n"
            "fi\n",
        )
        self._write_executable(
            "yt-dlp",
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--dump-single-json\" ]; then\n"
            "  printf '%s\\n' '{\"title\":\"Fixture Video\",\"channel\":\"Fixture Channel\",\"duration_string\":\"10:00\",\"upload_date\":\"20260831\",\"chapters\":[]}'\n"
            "fi\n",
        )
        envelope = json.dumps({"structured_output": STANDARD_SYNTHESIS}, separators=(",", ":"))
        self._write_executable(
            "claude",
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--help\" ]; then\n"
            "  printf '%s\\n' '--safe-mode --no-session-persistence --no-chrome --tools --mcp-config --strict-mcp-config --json-schema --permission-mode'\n"
            "  exit 0\n"
            "fi\n"
            "if [ \"${KCAP_FIXTURE_FAILURE:-}\" = \"synthesis\" ]; then exit 42; fi\n"
            "if [ \"${KCAP_FIXTURE_FAILURE:-}\" = \"validation\" ]; then\n"
            "  printf '%s\\n' '{\"structured_output\":{\"title\":\"bad\"}}'\n"
            "  exit 0\n"
            "fi\n"
            "if [ -n \"${KCAP_FIXTURE_CLAUDE_ARGV:-}\" ]; then\n"
            "  : > \"$KCAP_FIXTURE_CLAUDE_ARGV\"\n"
            "  for argument in \"$@\"; do printf '%s\\n' \"$argument\" >> \"$KCAP_FIXTURE_CLAUDE_ARGV\"; done\n"
            "fi\n"
            "if [ -n \"${KCAP_FIXTURE_CLAUDE_STDIN:-}\" ]; then cat > \"$KCAP_FIXTURE_CLAUDE_STDIN\"; fi\n"
            "if [ -n \"${KCAP_FIXTURE_LOG:-}\" ]; then printf '%s\\n' claude >> \"$KCAP_FIXTURE_LOG\"; fi\n"
            f"printf '%s\\n' '{envelope}'\n"
            f"# {CHILD_MARKER}\n",
        )
        self._write_executable(
            "codex",
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> '" + str(self.root / "codex-command.log") + "'\n"
            "if [ \"$1\" = \"features\" ] && [ -f '" + str(self.root / "codex-auth-mutation.flag") + "' ]; then\n"
            "  printf '%s\\n' 'mutated-during-synthesis' > '" + str(self.root / "codex-auth-mutation" / "auth.json") + "'\n"
            "fi\n"
            "if true; then\n"
            "  auth_type=none\n"
            "  if [ -L \"${CODEX_HOME:-}/auth.json\" ]; then auth_type=link; fi\n"
            "  if [ \"$auth_type\" = none ] && [ -f \"${CODEX_HOME:-}/auth.json\" ]; then auth_type=file; fi\n"
            "  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\\n' \\\n"
            "    \"${CODEX_SESSION_ID-unset}\" \"${CODEX_THREAD_ID-unset}\" \"${CODEX_SANDBOX-unset}\" \"${CODEX_CI-unset}\" \\\n"
            "    \"${CODEX_HOME-unset}\" \"${CODEX_SQLITE_HOME-unset}\" \"${TMPDIR-unset}\" \"$auth_type\" \\\n"
            "    \"$(stat -f '%Lp' \"${CODEX_HOME:-/nonexistent}\" 2>/dev/null || printf missing)\" \\\n"
            "    \"$(stat -f '%Lp' \"${CODEX_SQLITE_HOME:-/nonexistent}\" 2>/dev/null || printf missing)\" \\\n"
            "    \"$(stat -f '%Lp' \"${TMPDIR:-/nonexistent}\" 2>/dev/null || printf missing)\" \\\n"
            "    \"${HOME-unset}\" \"${OPENAI_API_KEY-unset}\" \"${ANTHROPIC_API_KEY-unset}\" \\\n"
            "    \"${AWS_SECRET_ACCESS_KEY-unset}\" \"${GITHUB_TOKEN-unset}\" \"${HTTPS_PROXY-unset}\" \\\n"
            "    \"$(stat -f '%Lp' \"${CODEX_HOME:-/nonexistent}/auth.json\" 2>/dev/null || printf missing)\" \\\n"
            "    \"${KCAP_FIXTURE_AUTH_WRITE-unset}\" >> '" + str(self.root / "codex-environment.log") + "'\n"
            "fi\n"
            "if [ \"$1\" = \"features\" ] && [ \"$2\" = \"list\" ]; then\n"
            "  export KCAP_APP_SERVER_FIXTURE_LOG='" + str(self.root / "codex-rpc.log") + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_CLEANUP='" + str(self.root / "codex-server-cleanup.log") + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_RESULT='" + json.dumps(STANDARD_SYNTHESIS, separators=(",", ":")) + "'\n"
            "  exec python3 '" + str(FAKE_CODEX_APP_SERVER) + "' \"$@\"\n"
            "fi\n"
            "if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'codex fixture-signed-build'; exit 0; fi\n"
            "if [ \"$1\" = \"app-server\" ]; then\n"
            "  export KCAP_APP_SERVER_FIXTURE_LOG='" + str(self.root / "codex-rpc.log") + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_CLEANUP='" + str(self.root / "codex-server-cleanup.log") + "'\n"
            "  export KCAP_APP_SERVER_FIXTURE_RESULT='" + json.dumps(STANDARD_SYNTHESIS, separators=(",", ":")) + "'\n"
            "  exec python3 '" + str(FAKE_CODEX_APP_SERVER) + "' \"$@\"\n"
            "fi\n"
            "result_path=''\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = \"--output-last-message\" ]; then shift; result_path=$1; fi\n"
            "  shift\n"
            "done\n"
            "if [ -f \"${CODEX_HOME:-}/auth.json\" ]; then printf '%s' child-write > \"$CODEX_HOME/auth.json\"; fi\n"
            "printf '%s\\n' codex >> '" + str(self.root / "codex-child.log") + "'\n"
            f"printf '%s\\n' '{json.dumps(STANDARD_SYNTHESIS, separators=(',', ':'))}' > \"$result_path\"\n"
            "printf '%s\\n' '{\"type\":\"thread.started\"}'\n"
            f"# {CHILD_MARKER}\n",
        )

    def _environment(self, runtime: str, **extra: str) -> dict[str, str]:
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
                "PATH": "{}:{}".format(self.bin_dir, environment.get("PATH", "")),
                "PYTHONPATH": "{}:{}".format(self.site_dir, environment.get("PYTHONPATH", "")),
            }
        )
        environment.update(extra)
        return environment

    def _capture(
        self,
        runtime: str = "claude",
        *arguments: str,
        expected_returncode: int = 0,
        **environment: str,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        if runtime == "codex":
            arguments = (*arguments, "--codex-bin", str(self.bin_dir / "codex"))
        process = subprocess.run(
            [sys.executable, str(KCAP_CLI), "capture", YOUTUBE_URL, "--project-dir", str(self.project), *arguments],
            cwd=ROOT,
            env=self._environment(runtime, **environment),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(
            process.returncode,
            expected_returncode,
            "capture stderr:\n{}\nstdout:\n{}".format(process.stderr, process.stdout),
        )
        stream = process.stdout if expected_returncode == 0 else process.stderr
        payload = json.loads(stream)
        self.assertIsInstance(payload, dict)
        return process, payload

    def _workspaces(self) -> list[Path]:
        return sorted(self.work_root.glob("kcap-*"))

    def _codex_environment_records(self, path: Path) -> list[dict[str, str]]:
        fields = (
            "session", "thread", "sandbox", "ci", "home", "sqlite_home", "tmpdir",
            "auth_type", "home_mode", "sqlite_home_mode", "tmpdir_mode", "platform_home",
            "openai", "anthropic", "aws", "github", "https_proxy", "auth_mode", "write_auth",
        )
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            values = line.split("|")
            self.assertEqual(len(values), len(fields))
            records.append(dict(zip(fields, values)))
        return records

    def _codex_command_records(self, path: Path) -> list[list[str]]:
        return [line.split() for line in path.read_text(encoding="utf-8").splitlines() if line]

    def _assert_success(self, payload: dict[str, Any], effective_mode: str = "standard") -> Path:
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], "created")
        self.assertEqual(payload["effective_mode"], effective_mode)
        self.assertEqual(payload["content_type"], "video")
        output_file = Path(payload["output_file"])
        self.assertEqual(payload["filename"], output_file.name)
        self.assertTrue(output_file.is_file())
        self.assertGreater(payload["bytes"], 0)
        return output_file

    def test_capture_standard_youtube_uses_fake_claude_child(self) -> None:
        child_log = self.root / "claude-child.log"
        process, payload = self._capture(
            "claude", "--focus", "How is isolation enforced?", KCAP_FIXTURE_LOG=str(child_log)
        )
        output_file = self._assert_success(payload)
        self.assertEqual(child_log.read_text(encoding="utf-8"), "claude\n")
        self.assertIn("Fixture Video Capture", output_file.read_text(encoding="utf-8"))
        self.assertNotIn(RAW_MARKER, process.stdout + process.stderr)
        self.assertNotIn(CHILD_MARKER, process.stdout + process.stderr)

    def test_claude_mcp_config_is_explicit_and_prompt_uses_stdin(self) -> None:
        argv_log = self.root / "claude-argv.log"
        stdin_log = self.root / "claude-stdin.log"
        _, payload = self._capture(
            "claude",
            "--focus",
            "stdin transport canary",
            KCAP_FIXTURE_CLAUDE_ARGV=str(argv_log),
            KCAP_FIXTURE_CLAUDE_STDIN=str(stdin_log),
        )
        self._assert_success(payload)
        arguments = argv_log.read_text(encoding="utf-8").splitlines()
        self.assertIn("--mcp-config", arguments)
        mcp_index = arguments.index("--mcp-config")
        self.assertEqual(arguments[mcp_index + 1], '{"mcpServers":{}}')
        strict_index = arguments.index("--strict-mcp-config")
        self.assertNotEqual(arguments[strict_index + 1], '{"mcpServers":{}}')
        prompt = stdin_log.read_text(encoding="utf-8")
        self.assertIn("stdin transport canary", prompt)
        self.assertNotIn("stdin transport canary", "\n".join(arguments))

    def test_partial_legacy_config_uses_0_4_4_defaults_and_block_tags(self) -> None:
        legacy_project = self.root / "legacy-project"
        (legacy_project / ".claude").mkdir(parents=True)
        (legacy_project / ".claude" / "research-toolkit.local.md").write_text(
            "---\n"
            "kcap:\n"
            "  output_path: {}\n"
            "  default_tags:\n"
            "    - legacy-one\n"
            "    - legacy-two\n"
            "---\n".format(self.output),
            encoding="utf-8",
        )
        process = subprocess.run(
            [sys.executable, str(KCAP_CLI), "config", "--project-dir", str(legacy_project)],
            cwd=ROOT,
            env=self._environment("claude", RESEARCH_TOOLKIT_CONFIG=""),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertEqual(payload["source"], "legacy")
        self.assertEqual(payload["config"]["output_path"], str(self.output))
        self.assertEqual(payload["config"]["subfolder"], "captures")
        self.assertIsNone(payload["config"]["vault_name"])
        self.assertEqual(payload["config"]["default_tags"], ["legacy-one", "legacy-two"])
        self.assertEqual(payload["config"]["default_mode"], "standard")
        self.assertEqual(payload["config"]["synthesis_profile"], "fast")
        self.assertTrue(any("0.6.x" in warning for warning in payload["warnings"]))

    def test_all_mode_schemas_use_the_claude_compatible_draft(self) -> None:
        """The exact documents passed through Claude's --json-schema boundary stay portable."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_schema_boundary", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        for mode in ("standard", "deep", "full"):
            with self.subTest(mode=mode):
                schema = json.loads(module.schema_for_mode(mode).read_text(encoding="utf-8"))
                self.assertEqual(schema.get("$schema"), "http://json-schema.org/draft-07/schema#")
                self.assertNotIn("2020-12", json.dumps(schema, sort_keys=True))

    def test_codex_auto_auth_fails_closed_without_credentials(self) -> None:
        child_log = self.root / "codex-child.log"
        environment_log = self.root / "codex-environment.log"
        process, payload = self._capture(
            "codex",
            expected_returncode=1,
            KCAP_FIXTURE_LOG=str(child_log),
            KCAP_FIXTURE_CODEX_ENV_LOG=str(environment_log),
            CODEX_HOME=str(self.root / "missing-codex-home"),
            OPENAI_API_KEY="",
            RESEARCH_TOOLKIT_CODEX_AUTH="auto",
        )
        self.assertFalse(payload["ok"])
        self.assertIn(payload["error"]["code"], {"codex_auth_error", "codex_auth_unsupported"})
        self.assertFalse(child_log.exists())
        self.assertFalse(environment_log.exists())
        self.assertNotIn(RAW_MARKER, process.stdout + process.stderr)
        self.assertNotIn(CHILD_MARKER, process.stdout + process.stderr)

    def test_codex_app_server_oauth_copy_is_private_and_source_is_immutable(self) -> None:
        outer_home = self.root / "outer-codex-home"
        outer_sqlite_home = self.root / "outer-codex-sqlite-home"
        outer_tmpdir = self.root / "outer-tmpdir"
        for directory in (outer_home, outer_sqlite_home, outer_tmpdir):
            directory.mkdir()
        auth = outer_home / "auth.json"
        self._write_private_fixture(auth, SYNTHETIC_ACCOUNT_DOCUMENT)
        before = (auth.read_bytes(), auth.stat())
        environment_log = self.root / "codex-environment.log"
        command_log = self.root / "codex-command.log"

        _, payload = self._capture(
            "codex",
            KCAP_FIXTURE_CODEX_ENV_LOG=str(environment_log),
            CODEX_SESSION_ID="outer-session",
            CODEX_THREAD_ID="outer-thread",
            CODEX_SANDBOX="outer-sandbox",
            CODEX_CI="outer-ci",
            CODEX_HOME=str(outer_home),
            CODEX_SQLITE_HOME=str(outer_sqlite_home),
            TMPDIR=str(outer_tmpdir),
            HOME="OUTER_HOME_SENTINEL",
            OPENAI_API_KEY="OPENAI_SENTINEL",
            ANTHROPIC_API_KEY="ANTHROPIC_SENTINEL",
            AWS_SECRET_ACCESS_KEY="AWS_SENTINEL",
            GITHUB_TOKEN="GITHUB_SENTINEL",
            HTTPS_PROXY="https://proxy.invalid",
            KCAP_FIXTURE_AUTH_WRITE="1",
            KCAP_FIXTURE_COMMAND_LOG=str(command_log),
            RESEARCH_TOOLKIT_CODEX_AUTH="auto",
        )

        self._assert_success(payload)
        records = self._codex_environment_records(environment_log)
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertEqual(
                [record[name] for name in ("session", "thread", "sandbox", "ci")],
                ["unset", "unset", "unset", "unset"],
            )
            child_paths = {name: Path(record[name]) for name in ("home", "sqlite_home", "tmpdir")}
            self.assertNotEqual(child_paths["home"], outer_home)
            self.assertNotEqual(child_paths["sqlite_home"], outer_sqlite_home)
            self.assertNotEqual(child_paths["tmpdir"], outer_tmpdir)
            self.assertEqual(
                [record[name] for name in ("home_mode", "sqlite_home_mode", "tmpdir_mode")],
                ["700", "700", "700"],
            )
            self.assertEqual(record["auth_type"], "file")
            self.assertEqual(record["auth_mode"], "600")
            self.assertEqual(
                [record[name] for name in ("openai", "anthropic", "aws", "github", "https_proxy")],
                ["unset", "unset", "unset", "unset", "unset"],
            )

        commands = self._codex_command_records(command_log)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0], ["features", "list"])
        self.assertEqual(commands[1][0], "app-server")
        self.assertIn("--stdio", commands[1])
        self.assertIn("--strict-config", commands[1])

        after = auth.stat()
        self.assertEqual(auth.read_bytes(), before[0])
        self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_mtime_ns), (before[1].st_dev, before[1].st_ino, before[1].st_mode, before[1].st_mtime_ns))

    def test_codex_oauth_source_change_during_synthesis_fails_without_attestation(self) -> None:
        source_home = self.root / "codex-auth-mutation"
        source_home.mkdir()
        source = source_home / "auth.json"
        self._write_private_fixture(source, SYNTHETIC_ACCOUNT_DOCUMENT)
        (self.root / "codex-auth-mutation.flag").write_text("mutate\n", encoding="utf-8")
        report_path = self.project / "kcap-codex-app-server-report.json"

        process, payload = self._capture(
            "codex",
            expected_returncode=1,
            RESEARCH_TOOLKIT_CODEX_AUTH="oauth",
            CODEX_HOME=str(source_home),
            RESEARCH_TOOLKIT_ACCEPTANCE_REPORT=str(report_path),
        )

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "codex_auth_error")
        self.assertFalse(report_path.exists())
        self.assertNotIn(SYNTHETIC_ACCOUNT_DOCUMENT.decode("utf-8").strip(), process.stdout + process.stderr)

    def test_codex_oauth_source_change_does_not_replace_direct_synthesis_output(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_auth_publish_order", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        work_dir = Path(tempfile.mkdtemp(prefix="kcap-")).resolve()
        self.addCleanup(shutil.rmtree, work_dir, True)
        content_file = work_dir / "content.txt"
        content_file.write_text(" ".join(["transcript"] * 80), encoding="utf-8")
        output_file = work_dir / "synthesis.json"
        sentinel = b"preexisting-synthesis-must-survive\n"
        output_file.write_bytes(sentinel)
        source_home = self.root / "codex-auth-mutation"
        source_home.mkdir()
        self._write_private_fixture(source_home / "auth.json", SYNTHETIC_ACCOUNT_DOCUMENT)
        (self.root / "codex-auth-mutation.flag").write_text("mutate\n", encoding="utf-8")
        args = module.argparse.Namespace(
            content_file=str(content_file),
            metadata_file=None,
            mode="standard",
            profile="fast",
            codex_bin=str(self.bin_dir / "codex"),
            dry_run=False,
            timeout=30,
            content_type="video",
            url=YOUTUBE_URL,
            focus=None,
            output_file=str(output_file),
        )

        with patch.dict(
            os.environ,
            {
                "CODEX_HOME": str(source_home),
                "RESEARCH_TOOLKIT_CODEX_AUTH": "oauth",
                "PATH": os.environ.get("PATH", os.defpath),
            },
            clear=True,
        ):
            with self.assertRaises(module.KcapError) as failure:
                module.codex_synthesize(args)

        self.assertEqual(failure.exception.code, "codex_auth_error")
        self.assertEqual(output_file.read_bytes(), sentinel)

    def test_codex_capture_writes_only_bounded_acceptance_provenance_when_requested(self) -> None:
        oauth_home = self.root / "provenance-oauth-home"
        oauth_home.mkdir()
        self._write_private_fixture(oauth_home / "auth.json", SYNTHETIC_ACCOUNT_DOCUMENT)
        report_path = self.project / "kcap-codex-app-server-report.json"

        process, payload = self._capture(
            "codex",
            RESEARCH_TOOLKIT_CODEX_AUTH="oauth",
            CODEX_HOME=str(oauth_home),
            RESEARCH_TOOLKIT_ACCEPTANCE_REPORT=str(report_path),
        )

        self._assert_success(payload)
        self.assertTrue(report_path.is_file())
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["runtime"], "codex-app-server")
        self.assertEqual(report["transport"], "stdio")
        self.assertEqual(Path(report["binary"]["path"]).resolve(), (self.bin_dir / "codex").resolve())
        self.assertEqual(report["binary"]["version"], "codex fixture-signed-build")
        self.assertEqual(report["session"], {"ephemeral": True})
        self.assertEqual(report["code_mode"]["allowed_operations"], ["exec", "wait"])
        self.assertEqual(report["code_mode"]["lifecycle"], ["thread.start", "turn.start", "turn.complete"])
        self.assertEqual(report["sandbox"]["network"], "deny")
        self.assertEqual(
            report["sandbox"]["filesystem"],
            {"root": "deny", "tmp": "deny", "slash_tmp": "deny"},
        )
        self.assertEqual(report["environment"], {"mode": "empty", "allowed": []})
        self.assertEqual(
            report["auth"],
            {"mode": "oauth", "source_unchanged": True, "private_copy_removed": True},
        )
        self.assertEqual(report["prohibited_event_count"], 0)
        rendered = json.dumps(report, sort_keys=True)
        for forbidden in (
            "prompt",
            "token",
            "api_key",
            "secret",
            RAW_MARKER,
            CHILD_MARKER,
            "structured_output",
        ):
            self.assertNotIn(forbidden.lower(), rendered.lower())
        self.assertNotIn(rendered, process.stdout + process.stderr)

    def test_codex_auth_selection_is_explicit_and_fails_closed(self) -> None:
        oauth_home = self.root / "oauth-home"
        oauth_home.mkdir()
        self._write_private_fixture(oauth_home / "auth.json", SYNTHETIC_ACCOUNT_DOCUMENT)

        cases = (
            ("auto", str(self.root / "missing-oauth-home"), None, 1),
            ("oauth", str(self.root / "missing-oauth-home"), "API_KEY_MUST_NOT_BE_USED", 1),
            ("api_key", str(oauth_home), None, 1),
            ("invalid-mode", str(oauth_home), "API_KEY_MUST_NOT_BE_USED", 1),
        )
        for mode, codex_home, api_key, expected_returncode in cases:
            with self.subTest(mode=mode):
                environment: dict[str, str] = {
                    "RESEARCH_TOOLKIT_CODEX_AUTH": mode,
                    "CODEX_HOME": codex_home,
                }
                if api_key is not None:
                    environment["OPENAI_API_KEY"] = api_key
                process, payload = self._capture(
                    "codex", "--collision", "suffix", expected_returncode=expected_returncode, **environment
                )
                self.assertFalse(payload["ok"])
                self.assertIn(payload["error"]["code"], {"codex_auth_error", "codex_auth_unsupported"})
                rendered = process.stdout + process.stderr + json.dumps(payload, sort_keys=True)
                self.assertNotIn("API_KEY_MUST_NOT_BE_USED", rendered)
                self.assertNotIn(RAW_MARKER, rendered)
                self.assertNotIn(CHILD_MARKER, rendered)

    def test_codex_oauth_symlink_is_rejected_without_reading_or_copying_target(self) -> None:
        source_home = self.root / "symlink-oauth-home"
        source_home.mkdir()
        target = self.root / "oauth-target.json"
        target.write_bytes(b'{"fixture":"oauth-target"}\n')
        source = source_home / "auth.json"
        source.symlink_to(target)
        target_before = (target.read_bytes(), target.stat())

        process, payload = self._capture(
            "codex",
            expected_returncode=1,
            RESEARCH_TOOLKIT_CODEX_AUTH="oauth",
            CODEX_HOME=str(source_home),
        )

        self.assertFalse(payload["ok"])
        self.assertIn(payload["error"]["code"], {"codex_auth_error", "codex_auth_unsupported"})
        self.assertNotIn(str(target), process.stdout + process.stderr + json.dumps(payload, sort_keys=True))
        target_after = target.stat()
        self.assertEqual(target.read_bytes(), target_before[0])
        self.assertEqual(
            (target_after.st_dev, target_after.st_ino, target_after.st_mode, target_after.st_mtime_ns),
            (target_before[1].st_dev, target_before[1].st_ino, target_before[1].st_mode, target_before[1].st_mtime_ns),
        )

    def test_codex_oauth_snapshot_rejects_a_path_swap_at_open(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_auth_source_swap", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = self.root / "oauth-source-swap.json"
        target = self.root / "oauth-source-swap-target.json"
        self._write_private_fixture(source, b"original-source\n")
        self._write_private_fixture(target, b"replacement-target\n")
        real_open = os.open
        swapped = False

        def swap_before_open(path: object, flags: int, mode: int = 0o777, **kwargs: object) -> int:
            nonlocal swapped
            if Path(path) == source and not swapped:
                source.unlink()
                source.symlink_to(target)
                swapped = True
            return real_open(path, flags, mode, **kwargs)

        with patch.object(module.os, "open", side_effect=swap_before_open):
            with self.assertRaises(module.KcapError) as failure:
                module.codex_auth_snapshot(source)

        self.assertTrue(swapped)
        self.assertEqual(failure.exception.code, "codex_auth_error")

    def test_codex_child_auth_file_is_created_private_without_post_creation_chmod(self) -> None:
        """A permissive caller umask must never briefly expose the OAuth copy."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_auth_create_mode", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        work_dir = self.root / "auth-create-mode"
        work_dir.mkdir()
        original_chmod = Path.chmod
        observed_modes: list[int] = []

        def observe_auth_chmod(path: Path, mode: int, *, follow_symlinks: bool = True) -> None:
            if path.name == "auth.json":
                observed_modes.append(stat.S_IMODE(path.stat().st_mode))
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            original_chmod(path, mode, follow_symlinks=follow_symlinks)

        prior_umask = os.umask(0)
        try:
            with patch.object(Path, "chmod", new=observe_auth_chmod):
                environment = module.codex_child_environment(work_dir, auth_content=b"opaque-auth-snapshot\n")
        finally:
            os.umask(prior_umask)

        self.assertEqual(observed_modes, [])
        self.assertEqual(stat.S_IMODE((Path(environment["CODEX_HOME"]) / "auth.json").stat().st_mode), 0o600)

    def test_codex_child_auth_copy_rejects_a_symlink_before_copying_target(self) -> None:
        """Direct callers cannot bypass the source validation performed by auth selection."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_auth_copy_source", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        work_dir = self.root / "auth-copy-source"
        work_dir.mkdir()
        target = self.root / "child-copy-target.json"
        target.write_bytes(b"opaque-symlink-target\n")
        source = self.root / "child-copy-source.json"
        source.symlink_to(target)

        with patch.object(module.shutil, "copyfile", side_effect=AssertionError("unsafe source was copied")) as copyfile:
            with self.assertRaises(module.KcapError) as failure:
                module.codex_child_environment(work_dir, auth_source=source)

        self.assertEqual(failure.exception.code, "codex_auth_error")
        copyfile.assert_not_called()

    def test_private_writer_never_removes_a_preexisting_destination(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_private_writer_collision", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        destination = self.root / "preexisting-private-file"
        destination.write_bytes(b"preexisting-content\n")

        with self.assertRaises(FileExistsError):
            module.write_private_bytes(destination, b"replacement-content\n")

        self.assertEqual(destination.read_bytes(), b"preexisting-content\n")

    def test_codex_child_environment_rejects_api_credentials(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_child_api_credential", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        work_dir = self.root / "api-credential-child-environment"
        work_dir.mkdir()

        with patch.dict(os.environ, {"OPENAI_API_KEY": "must-not-enter-child"}, clear=True):
            with self.assertRaises(module.KcapError) as failure:
                module.codex_child_environment(work_dir, include_api_credential=True)

        self.assertEqual(failure.exception.code, "codex_auth_error")

    def test_codex_oauth_rejects_api_key_shaped_auth_file(self) -> None:
        oauth_home = self.root / "api-key-shaped-oauth-home"
        oauth_home.mkdir()
        sentinel = "AUTH_FILE_API_KEY_MUST_NOT_LEAK"
        (oauth_home / "auth.json").write_text(
            json.dumps({"auth_mode": "apikey", "OPENAI_API_KEY": sentinel}) + "\n",
            encoding="utf-8",
        )

        process, payload = self._capture(
            "codex",
            expected_returncode=1,
            RESEARCH_TOOLKIT_CODEX_AUTH="oauth",
            CODEX_HOME=str(oauth_home),
        )

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "codex_auth_error")
        self.assertNotIn(sentinel, process.stdout + process.stderr + json.dumps(payload, sort_keys=True))

    def test_codex_api_key_auth_stays_ephemeral_and_uses_app_server(self) -> None:
        api_key = "API_KEY_MUST_NOT_PERSIST"
        oauth_home = self.root / "oauth-present-for-api-key-mode"
        oauth_home.mkdir()
        self._write_private_fixture(oauth_home / "auth.json", SYNTHETIC_ACCOUNT_DOCUMENT)
        environment_log = self.root / "codex-environment.log"
        command_log = self.root / "codex-command.log"

        process, payload = self._capture(
            "codex",
            RESEARCH_TOOLKIT_CODEX_AUTH="api_key",
            CODEX_HOME=str(oauth_home),
            OPENAI_API_KEY=api_key,
            KCAP_FIXTURE_COMMAND_LOG=str(command_log),
        )

        self._assert_success(payload)
        commands = self._codex_command_records(command_log)
        self.assertEqual(len(commands), 2)
        self.assertEqual(commands[0], ["features", "list"])
        self.assertEqual(commands[1][0], "app-server")
        self.assertIn("--stdio", commands[1])
        self.assertIn("--strict-config", commands[1])
        records = self._codex_environment_records(environment_log)
        self.assertEqual(len(records), 2)
        self.assertTrue(all(record["auth_type"] == "none" for record in records))
        self.assertTrue(all(record["openai"] == "unset" for record in records))
        self.assertTrue(all(record["anthropic"] == "unset" for record in records))
        self.assertTrue(all(record["aws"] == "unset" for record in records))
        self.assertTrue(all(record["github"] == "unset" for record in records))
        self.assertTrue(all(record["https_proxy"] == "unset" for record in records))
        self.assertNotIn(api_key, process.stdout + process.stderr + json.dumps(payload, sort_keys=True))
        self.assertEqual(self._workspaces(), [])

    def test_codex_app_server_control_plane_has_only_code_mode_authority(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_app_server_control_plane", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        control_plane = module.codex_app_server_control_plane(
            codex_bin="codex",
            work_dir=self.work_root,
            auth_mode="oauth",
            output_schema={"type": "object"},
            reasoning="low",
            prompt="fixture prompt",
        )

        launch = control_plane["launch"]
        thread = control_plane["thread"]
        turn = control_plane["turn"]

        self.assertEqual(launch[:2], ["codex", "app-server"])
        self.assertIn("--stdio", launch)
        self.assertTrue(thread["ephemeral"])
        self.assertEqual(thread["environments"], [])
        self.assertEqual(turn["environments"], [])
        self.assertTrue(turn["code_mode_only"])
        self.assertEqual(turn["tools"], [])
        self.assertEqual(turn["dynamic_tools"], [])
        self.assertEqual(
            thread["permission_profile"]["filesystem"]["deny"],
            [":root", ":tmpdir", ":slash_tmp"],
        )
        self.assertEqual(thread["permission_profile"]["filesystem"]["allow"], [])
        self.assertFalse(thread["permission_profile"]["network"]["enabled"])
        with self.assertRaises(module.KcapError) as failure:
            module.validate_codex_app_server_capabilities(
                {"code_mode_only": "disabled", "shell_tool": "enabled"}
            )
        self.assertEqual(failure.exception.code, "codex_capability_error")

    def test_codex_binary_selection_prefers_explicit_then_desktop_then_path(self) -> None:
        desktop = self.root / "desktop-codex"
        explicit = self.root / "explicit-codex"
        path_codex = self.root / "path-codex"
        for candidate in (desktop, explicit, path_codex):
            self._write_executable(candidate.name, "#!/bin/sh\nexit 0\n")
            candidate = self.bin_dir / candidate.name
        desktop = self.bin_dir / "desktop-codex"
        explicit = self.bin_dir / "explicit-codex"
        path_codex = self.bin_dir / "path-codex"
        import importlib.util
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location("kcap_binary_selection", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with patch.object(module, "DESKTOP_CODEX_BINARY", desktop), patch.object(module.shutil, "which", return_value=str(path_codex)):
            self.assertEqual(module.select_codex_binary(str(explicit)), str(explicit))
            self.assertEqual(module.select_codex_binary(None), str(desktop))
        desktop.chmod(stat.S_IRUSR | stat.S_IWUSR)
        with patch.object(module, "DESKTOP_CODEX_BINARY", desktop), patch.object(module.shutil, "which", return_value=str(path_codex)):
            self.assertEqual(module.select_codex_binary(None), str(path_codex))

    def test_codex_critical_features_include_action_authority(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_event_controls", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for feature in ("skill_search", "view_image", "memories"):
            self.assertIn(feature, module.DESIRED_DISABLED_FEATURES)
            self.assertIn(feature, module.CRITICAL_DISABLED_FEATURES)

    def test_codex_web_search_is_disabled_without_deprecated_feature_flags(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("kcap_web_search_controls", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        self.assertIn('web_search = "disabled"', module.codex_app_server_config())
        self.assertEqual(
            module.codex_features_to_disable(
                {
                    "shell_tool": "stable",
                    "web_search_cached": "deprecated",
                    "web_search_request": "deprecated",
                    "code_mode": "under development",
                }
            ),
            ["shell_tool"],
        )

    def test_codex_child_environment_omits_api_key_and_ambient_secrets(self) -> None:
        import importlib.util
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location("kcap_child_environment", KCAP_CLI)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        work_dir = self.root / "direct-child-environment"
        work_dir.mkdir()
        with patch.dict(
            os.environ,
            {
                "HOME": str(self.home),
                "CODEX_HOME": str(self.root / "no-auth"),
                "OPENAI_API_KEY": "explicit-api-auth",
                "ANTHROPIC_API_KEY": "ambient-anthropic",
                "AWS_SECRET_ACCESS_KEY": "ambient-aws",
                "GITHUB_TOKEN": "ambient-github",
                "HTTPS_PROXY": "https://proxy.invalid",
            },
            clear=True,
        ):
            environment = module.codex_child_environment(work_dir, include_api_credential=False)

        for name in (
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "HTTPS_PROXY",
        ):
            self.assertNotIn(name, environment)
        self.assertFalse((Path(environment["CODEX_HOME"]) / "auth.json").exists())

    def test_capture_full_youtube_falls_back_to_standard(self) -> None:
        _, payload = self._capture("claude", "--mode", "full")
        output_file = self._assert_success(payload, effective_mode="standard")
        self.assertTrue(
            any("full" in warning.lower() and "standard" in warning.lower() for warning in payload["warnings"])
        )
        self.assertIn("capture_mode: standard", output_file.read_text(encoding="utf-8"))

    def test_capture_success_schema_excludes_raw_extraction_and_child_output(self) -> None:
        process, payload = self._capture("claude")
        self._assert_success(payload)
        encoded = json.dumps(payload, sort_keys=True)
        for forbidden in (RAW_MARKER, CHILD_MARKER, "transcript", "structured_output", "synthesis.json"):
            self.assertNotIn(forbidden, encoded)
        self.assertNotIn(RAW_MARKER, process.stdout + process.stderr)
        self.assertNotIn(CHILD_MARKER, process.stdout + process.stderr)

    def test_default_cleanup_removes_workspace_after_success_and_post_extraction_failure(self) -> None:
        self._capture("claude")
        self.assertEqual(self._workspaces(), [])

        _, failure = self._capture("claude", expected_returncode=1, KCAP_FIXTURE_FAILURE="synthesis")
        self.assertFalse(failure["ok"])
        self.assertEqual(self._workspaces(), [])

    def test_preserve_on_failure_only_retains_post_extraction_workspaces(self) -> None:
        for failure in ("synthesis", "validation"):
            with self.subTest(failure=failure):
                _, payload = self._capture(
                    "claude", "--preserve-on-failure", expected_returncode=1, KCAP_FIXTURE_FAILURE=failure
                )
                self.assertFalse(payload["ok"])
                workspaces = self._workspaces()
                try:
                    self.assertEqual(len(workspaces), 1)
                    self.assertEqual(stat.S_IMODE(workspaces[0].stat().st_mode), 0o700)
                    self.assertEqual(Path(payload["error"]["details"]["recovery_path"]).resolve(), workspaces[0].resolve())
                finally:
                    for workspace in workspaces:
                        shutil.rmtree(workspace)

        blocker = self.root / "not-a-directory"
        blocker.write_text("block rendering", encoding="utf-8")
        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kcap": {
                        "output_path": str(blocker), "subfolder": "captures", "vault_name": None,
                        "default_tags": ["controller-fixture"], "default_mode": "standard", "synthesis_profile": "fast",
                    },
                }
            ),
            encoding="utf-8",
        )
        _, payload = self._capture("claude", "--preserve-on-failure", expected_returncode=1)
        self.assertFalse(payload["ok"])
        workspaces = self._workspaces()
        try:
            self.assertEqual(len(workspaces), 1)
            self.assertEqual(stat.S_IMODE(workspaces[0].stat().st_mode), 0o700)
            self.assertEqual(Path(payload["error"]["details"]["recovery_path"]).resolve(), workspaces[0].resolve())
        finally:
            for workspace in workspaces:
                shutil.rmtree(workspace)

        self.config.write_text("{}", encoding="utf-8")
        _, invalid_config = self._capture("claude", "--preserve-on-failure", expected_returncode=1)
        self.assertFalse(invalid_config["ok"])
        self.assertEqual(self._workspaces(), [])
        self.assertNotIn("recovery_path", invalid_config["error"].get("details", {}))

        self.config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "kcap": {
                        "output_path": str(self.output), "subfolder": "captures", "vault_name": None,
                        "default_tags": ["controller-fixture"], "default_mode": "standard", "synthesis_profile": "fast",
                    },
                }
            ),
            encoding="utf-8",
        )
        _, confirmation = self._capture(
            "claude", "--mode", "deep", "--preserve-on-failure", expected_returncode=1, KCAP_FIXTURE_LARGE="1"
        )
        self.assertFalse(confirmation["ok"])
        self.assertEqual(self._workspaces(), [])
        self.assertNotIn("recovery_path", confirmation["error"].get("details", {}))


if __name__ == "__main__":
    unittest.main()
