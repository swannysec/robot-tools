"""Hardening contract for Starduster's isolated Codex App Server broker."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
STARDUSTER_PATH = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster.py"
SYNTHESIS_SCHEMA = ROOT / "research-toolkit" / "skills" / "starduster" / "schemas" / "starduster-synthesis.schema.json"
FIXTURE = ROOT / "tests" / "fixtures" / "codex-app-server" / "fake_codex_app_server.py"
API_KEY = "starduster-api-key-fixture-not-a-real-secret"
SERVER_SECRET = "APP_SERVER_SECRET_MUST_NOT_LEAK"
SYNTHESIS_RESULT = [
    {
        "full_name": "fixture/repository",
        "html_url": "https://github.com/fixture/repository",
        "category": "Developer Tools",
        "normalized_topics": ["fixture"],
        "summary": "A synthetic structured fixture summary.",
        "key_features": ["One", "Two", "Three"],
        "similar_to": [],
        "use_case": "Exercise the hardened App Server broker.",
        "maturity": "active",
        "author_display": "Fixture",
    }
]


def load_starduster():
    """Import a fresh package-local module and expose its adjacent renderer import."""
    name = "starduster_app_server_{}".format(uuid.uuid4().hex)
    scripts = str(STARDUSTER_PATH.parent)
    sys.path.insert(0, scripts)
    try:
        spec = importlib.util.spec_from_file_location(name, STARDUSTER_PATH)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(scripts)


class StardusterAppServerAcceptanceTests(unittest.TestCase):
    """The no-tools broker must reject unexpected JSON-RPC behavior before output use."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starduster-app-server-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.log_path = self.root / "requests.jsonl"
        self.cleanup_path = self.root / "cleanup.txt"
        FIXTURE.chmod(FIXTURE.stat().st_mode | stat.S_IXUSR)
        self.starduster = load_starduster()

    def environment(self, scenario: str = "success") -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", os.defpath),
            "KCAP_APP_SERVER_FIXTURE_SCENARIO": scenario,
            "KCAP_APP_SERVER_FIXTURE_LOG": str(self.log_path),
            "KCAP_APP_SERVER_FIXTURE_CLEANUP": str(self.cleanup_path),
            "KCAP_APP_SERVER_FIXTURE_RESULT": json.dumps({"synthesis": SYNTHESIS_RESULT}),
            # The shared fixture must attest Starduster's named capability profile.
            "KCAP_APP_SERVER_FIXTURE_PERMISSION_PROFILE": "starduster_synthesis",
        }

    def broker(self, *, scenario: str = "success", api_key: str | None = None, reasoning: str = "low", timeout: float = 0.1):
        return self.starduster.AppServer(
            str(FIXTURE),
            self.workspace,
            self.environment(scenario),
            api_key,
            reasoning,
            ("plugins", "browser_use"),
            timeout=timeout,
        )

    def synthesize(self, **kwargs: object) -> object:
        server = self.broker(**kwargs)
        self.last_server = server
        with server:
            return server.synthesize("Synthetic untrusted input.")

    def records(self) -> list[dict[str, object]]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]

    def requests(self) -> list[dict[str, object]]:
        return [record for record in self.records() if "method" in record]

    def assert_error(self, code: str, **kwargs: object) -> None:
        with self.assertRaises(self.starduster.StardusterError) as failure:
            self.synthesize(**kwargs)
        self.assertEqual(failure.exception.code, code)

    def test_launch_uses_exact_stdio_strict_config_and_supported_disable_flags(self) -> None:
        self.assertEqual(self.synthesize(), SYNTHESIS_RESULT)
        launches = [record for record in self.records() if "argv" in record]
        self.assertEqual(len(launches), 1)
        self.assertEqual(
            launches[0]["argv"],
            ["app-server", "--stdio", "--strict-config", "--disable", "plugins", "--disable", "browser_use"],
        )

    def test_config_denies_named_root_tmp_and_network_access(self) -> None:
        config = self.starduster.codex_config("oauth").decode("utf-8")
        self.assertIn('default_permissions = "starduster_synthesis"', config)
        self.assertIn('":root" = "deny"', config)
        self.assertIn('":tmpdir" = "deny"', config)
        self.assertIn('":slash_tmp" = "deny"', config)
        self.assertIn("enabled = false", config)
        self.assertNotIn("allow = []", config)

    def test_lifecycle_is_correlated_allowlisted_and_uses_exact_schema(self) -> None:
        self.assertEqual(self.synthesize(), SYNTHESIS_RESULT)
        requests = self.requests()
        self.assertEqual([request["method"] for request in requests], ["initialize", "initialized", "thread/start", "turn/start"])
        ids = [request["id"] for request in requests if "id" in request]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all("jsonrpc" not in request for request in requests))
        thread = requests[2]["params"]
        self.assertEqual(thread["cwd"], str(self.workspace))
        self.assertTrue(thread["ephemeral"])
        self.assertEqual(thread["environments"], [])
        self.assertEqual(thread["dynamicTools"], [])
        self.assertEqual(thread["runtimeWorkspaceRoots"], [])
        self.assertEqual(thread["permissions"], "starduster_synthesis")
        self.assertEqual(thread["approvalPolicy"], "never")
        turn = requests[3]["params"]
        self.assertEqual(turn["threadId"], "thread-fixture")
        self.assertEqual(turn["effort"], "low")
        self.assertEqual(turn["outputSchema"], self.starduster.codex_synthesis_schema())
        self.assertEqual(turn["outputSchema"]["type"], "object")
        self.assertEqual(turn["outputSchema"]["required"], ["synthesis"])
        self.assertNotIn("uniqueItems", json.dumps(turn["outputSchema"], sort_keys=True))
        self.assertEqual(self.starduster.synthesis_schema(), json.loads(SYNTHESIS_SCHEMA.read_text(encoding="utf-8")))
        self.assertIn("uniqueItems", json.dumps(self.starduster.synthesis_schema(), sort_keys=True))

    def test_oauth_suppresses_api_login_and_explicit_api_key_is_redacted(self) -> None:
        self.assertEqual(self.synthesize(api_key=None), SYNTHESIS_RESULT)
        self.assertNotIn("account/login/start", [request["method"] for request in self.requests()])
        self.log_path.unlink()
        self.assertEqual(self.synthesize(api_key=API_KEY), SYNTHESIS_RESULT)
        login = self.requests()[2]
        self.assertEqual(login["method"], "account/login/start")
        self.assertEqual(login["params"], {"type": "apiKey", "apiKey": "<redacted>"})
        self.assertNotIn(API_KEY, self.log_path.read_text(encoding="utf-8"))

    def test_missing_or_malformed_authentication_fails_before_thread_start(self) -> None:
        project = self.root / "project"
        project.mkdir()
        isolated_home = self.root / "home"
        isolated_home.mkdir()
        star = {"full_name": "fixture/repository", "repo": {"full_name": "fixture/repository"}}
        with patch.dict(os.environ, {"STARDUSTER_CODEX_BIN": str(FIXTURE), "RESEARCH_TOOLKIT_CODEX_AUTH": "api_key", "OPENAI_API_KEY": "", "HOME": str(isolated_home)}, clear=False):
            with self.assertRaises(self.starduster.StardusterError) as failure:
                self.starduster.codex_synthesize([star], "fast", self.workspace, project)
        self.assertEqual(failure.exception.code, "codex_auth_error")
        self.assertFalse(self.log_path.exists())
        malformed = isolated_home / ".codex"
        malformed.mkdir()
        (malformed / "auth.json").write_text("not json", encoding="utf-8")
        with patch.dict(os.environ, {"STARDUSTER_CODEX_BIN": str(FIXTURE), "RESEARCH_TOOLKIT_CODEX_AUTH": "oauth", "OPENAI_API_KEY": "", "HOME": str(isolated_home), "CODEX_HOME": str(malformed)}, clear=False):
            with self.assertRaises(self.starduster.StardusterError) as failure:
                self.starduster.codex_synthesize([star], "fast", self.workspace, project)
        self.assertEqual(failure.exception.code, "codex_auth_error")

    def test_oauth_mode_rejects_api_key_auth_records_before_child_start(self) -> None:
        project = self.root / "project-oauth-record"
        project.mkdir()
        codex_home = self.root / "api-key-auth-home"
        codex_home.mkdir()
        auth = codex_home / "auth.json"
        auth.write_text(
            json.dumps({
                "auth_mode": "api_key",
                "OPENAI_API_KEY": "fixture-key",
                "tokens": {
                    "access_token": "fixture-access",
                    "id_token": "fixture-id",
                    "refresh_token": "fixture-refresh",
                },
            }),
            encoding="utf-8",
        )
        auth.chmod(0o600)
        star = {"full_name": "fixture/repository", "repo": {"full_name": "fixture/repository"}}
        with patch.dict(os.environ, {
            "STARDUSTER_CODEX_BIN": str(FIXTURE),
            "RESEARCH_TOOLKIT_CODEX_AUTH": "oauth",
            "OPENAI_API_KEY": "",
            "CODEX_HOME": str(codex_home),
        }, clear=False):
            with self.assertRaises(self.starduster.StardusterError) as failure:
                self.starduster.codex_synthesize([star], "fast", self.workspace, project)
        self.assertEqual(failure.exception.code, "codex_auth_error")
        self.assertFalse(self.log_path.exists())

    def test_private_oauth_state_is_removed_on_capability_and_revalidation_failures(self) -> None:
        project = self.root / "cleanup-project"
        project.mkdir()
        codex_home = self.root / "cleanup-auth-home"
        codex_home.mkdir()
        auth = codex_home / "auth.json"
        auth.write_text(json.dumps({
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": "cleanup-access",
                "id_token": "cleanup-id",
                "refresh_token": "cleanup-refresh",
            },
        }), encoding="utf-8")
        auth.chmod(0o600)
        star = {"full_name": "fixture/repository", "repo": {"full_name": "fixture/repository"}}
        base_environment = {
            "RESEARCH_TOOLKIT_CODEX_AUTH": "oauth",
            "OPENAI_API_KEY": "",
            "CODEX_HOME": str(codex_home),
        }

        with patch.dict(os.environ, {**base_environment, "STARDUSTER_CODEX_BIN": "/usr/bin/false"}, clear=False):
            with self.assertRaises(self.starduster.StardusterError):
                self.starduster.codex_synthesize([star], "fast", self.workspace, project)
        self.assertEqual(list(self.workspace.rglob("auth.json")), [])

        wrapper = self.root / "codex-wrapper"
        wrapper.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = --version ]; then printf '%s\\n' 'codex cleanup fixture'; exit 0; fi\n"
            "exec python3 '{}' \"$@\"\n".format(FIXTURE),
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        changed = self.starduster.StardusterError("codex_auth_error", "source changed")
        with patch.dict(os.environ, {**base_environment, "STARDUSTER_CODEX_BIN": str(wrapper)}, clear=False), patch.object(
            self.starduster, "child_environment", return_value=self.environment()
        ), patch.object(
            self.starduster, "verify_auth_snapshot", side_effect=[None, changed]
        ):
            with self.assertRaises(self.starduster.StardusterError) as failure:
                self.starduster.codex_synthesize([star], "fast", self.workspace, project)
        self.assertEqual(failure.exception.code, "codex_auth_error")
        self.assertEqual(list(self.workspace.rglob("auth.json")), [])

    def test_protocol_errors_include_mismatched_ids_unknown_requests_and_unknown_notifications(self) -> None:
        self.assert_error("codex_app_server_protocol_error", scenario="response-id-mismatch")
        self.log_path.unlink(missing_ok=True)
        self.assert_error("codex_app_server_protocol_error", scenario="unknown-server-request")
        server = object.__new__(self.starduster.AppServer)
        server.events = 0
        server.thread_id = "thread-fixture"
        server.turn_id = "turn-fixture"
        server.active_items = {}
        server.completed_text = None
        with self.assertRaises(self.starduster.StardusterError) as failure:
            server._notification({"method": "unknown/notification", "params": {}})
        self.assertEqual(failure.exception.code, "codex_app_server_protocol_error")

    def test_timeout_exit_malformed_json_and_single_deadline_fail_closed(self) -> None:
        for scenario, code in (("premature-exit", "codex_app_server_exit"), ("malformed-json", "codex_app_server_protocol_error"), ("timeout", "codex_app_server_timeout"), ("slow-drip", "codex_app_server_timeout")):
            with self.subTest(scenario=scenario):
                self.assert_error(code, scenario=scenario)
                self.log_path.unlink(missing_ok=True)

    def test_message_event_and_aggregate_limits_are_configurable_and_fail_closed(self) -> None:
        self.assertTrue(hasattr(self.starduster, "AppServerLimits"))
        limits = self.starduster.AppServerLimits(max_message_bytes=128, max_events=3, max_total_bytes=400)
        for scenario in ("oversized-message", "event-flood", "aggregate-output"):
            with self.subTest(scenario=scenario):
                with self.assertRaises(self.starduster.StardusterError) as failure:
                    with self.starduster.AppServer(str(FIXTURE), self.workspace, self.environment(scenario), None, "low", (), limits=limits, timeout=0.1) as server:
                        server.synthesize("Synthetic untrusted input.")
                self.assertEqual(failure.exception.code, "codex_app_server_limit")
                self.log_path.unlink(missing_ok=True)

    def test_passive_items_and_lifecycle_violations_are_handled(self) -> None:
        self.assertEqual(self.synthesize(scenario="passive-items"), SYNTHESIS_RESULT)
        self.log_path.unlink()
        for scenario in ("forbidden-item-started", "forbidden-item", "turn-id-mismatch", "item-thread-mismatch", "item-turn-mismatch", "item-completed-without-start", "item-type-mismatch", "multiple-agent-messages"):
            with self.subTest(scenario=scenario):
                self.assert_error("codex_app_server_protocol_error", scenario=scenario)
                self.log_path.unlink(missing_ok=True)

    def test_incomplete_output_schema_rejection_and_cleanup_after_success_or_failure(self) -> None:
        self.assertEqual(self.synthesize(), SYNTHESIS_RESULT)
        self._assert_cleanup()
        self.log_path.unlink(missing_ok=True)
        self.assert_error("codex_app_server_error", scenario="server-error")
        self._assert_cleanup()
        with self.assertRaises(self.starduster.SynthesisValidationError):
            self.starduster.validate_synthesis_payload([{"full_name": "fixture/repository"}], ["fixture/repository"])
        duplicate_values = json.loads(json.dumps(SYNTHESIS_RESULT))
        duplicate_values[0]["normalized_topics"] = ["fixture", "fixture"]
        with self.assertRaises(self.starduster.SynthesisValidationError):
            self.starduster.validate_synthesis_payload(duplicate_values, ["fixture/repository"])

    def test_profile_effort_mapping_is_low_medium_high(self) -> None:
        self.assertEqual(self.starduster.PROFILE_MODELS["fast"]["codex"], "low")
        self.assertEqual(self.starduster.PROFILE_MODELS["balanced"]["codex"], "medium")
        self.assertEqual(self.starduster.PROFILE_MODELS["deep"]["codex"], "high")

    def _assert_cleanup(self) -> None:
        self.assertTrue(self.last_server.closed, "broker did not finish its close lifecycle")
        self.assertIsNone(self.last_server.process, "broker retained an unreaped child process")


if __name__ == "__main__":
    unittest.main()
