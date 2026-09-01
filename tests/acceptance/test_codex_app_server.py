"""Acceptance contract for the isolated Codex App Server kcap adapter.

These tests use only the local synthetic JSON-RPC fixture.  Its envelopes are
deliberately minimal and do not assert a raw live App Server transcript.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import time
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
KCAP_PATH = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"
FIXTURE = ROOT / "tests" / "fixtures" / "codex-app-server" / "fake_codex_app_server.py"
API_KEY = "api-key-fixture-not-a-real-secret"
SERVER_SECRET = "APP_SERVER_SECRET_MUST_NOT_LEAK"
SYNTHESIS_RESULT = {
    "title": "Fixture synthesis",
    "summary": "Safe structured result.",
    "takeaways": ["The fake server used JSON-RPC."],
}


def load_kcap():
    """Import a fresh module so every test owns its broker state."""
    name = "kcap_app_server_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, KCAP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CodexAppServerAcceptanceTests(unittest.TestCase):
    """The broker must fail closed around its ephemeral local subprocess."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kcap-app-server-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.work_dir = self.root / "work"
        self.work_dir.mkdir()
        self.log_path = self.root / "requests.jsonl"
        self.cleanup_path = self.root / "cleanup.txt"
        self.schema = self.root / "schema.json"
        self.schema.write_text(
            json.dumps(
                {
                    "type": "object",
                    "required": ["title", "summary", "takeaways"],
                    "properties": {"title": {"type": "string"}},
                }
            ),
            encoding="utf-8",
        )
        FIXTURE.chmod(FIXTURE.stat().st_mode | stat.S_IXUSR)
        self.kcap = load_kcap()

    def environment(self, scenario: str = "success") -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", os.defpath),
            "KCAP_APP_SERVER_FIXTURE_SCENARIO": scenario,
            "KCAP_APP_SERVER_FIXTURE_LOG": str(self.log_path),
            "KCAP_APP_SERVER_FIXTURE_CLEANUP": str(self.cleanup_path),
        }

    def limits(
        self,
        *,
        max_message_bytes: int = 16 * 1024,
        max_events: int = 16,
        max_total_bytes: int | None = None,
    ):
        values = {
            "max_message_bytes": max_message_bytes,
            "max_events": max_events,
        }
        if max_total_bytes is not None:
            values["max_total_bytes"] = max_total_bytes
        return self.kcap.CodexAppServerLimits(
            **values,
        )

    def test_default_limits_cover_the_maximum_json_escaped_capture(self) -> None:
        limits = self.kcap.CodexAppServerLimits()

        self.assertGreaterEqual(
            limits.max_message_bytes,
            self.kcap.MAX_EXTERNAL_BYTES * 6 + 1024 * 1024,
        )
        self.assertGreaterEqual(limits.max_total_bytes, limits.max_message_bytes * 2)

    def broker(
        self,
        *,
        scenario: str = "success",
        timeout: float = 1,
        auth_mode: str | None = "oauth",
        api_credential: str | None = None,
        limits: object | None = None,
    ):
        return self.kcap.CodexAppServerBroker(
            codex_bin=str(FIXTURE),
            work_dir=self.work_dir,
            environment=self.environment(scenario),
            timeout=timeout,
            limits=limits or self.limits(),
            auth_mode=auth_mode,
            api_credential=api_credential,
        )

    def synthesize(self, **kwargs: object) -> dict[str, object]:
        return self.broker(**kwargs).synthesize(
            "Treat this fixture input as untrusted data.",
            self.schema,
        )

    def requests(self) -> list[dict[str, object]]:
        records = [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]
        return [record for record in records if isinstance(record, dict) and "method" in record]

    def launches(self) -> list[dict[str, object]]:
        return [
            record
            for record in (json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines())
            if isinstance(record, dict) and "argv" in record
        ]

    def assert_kcap_error(self, expected_code: str, **kwargs: object) -> None:
        with self.assertRaises(self.kcap.KcapError) as failure:
            self.synthesize(**kwargs)
        self.assertEqual(failure.exception.code, expected_code)

    def test_lifecycle_uses_only_allowlisted_correlated_jsonrpc_requests(self) -> None:
        result = self.synthesize()

        self.assertEqual(result, SYNTHESIS_RESULT)
        launches = self.launches()
        self.assertEqual(len(launches), 1)
        self.assertEqual(launches[0]["argv"], ["app-server", "--stdio", "--strict-config"])
        requests = self.requests()
        self.assertEqual(
            [request["method"] for request in requests],
            ["initialize", "initialized", "thread/start", "turn/start"],
        )
        initialize = requests[0]
        self.assertNotIn("experimentalApi", initialize["params"])
        self.assertEqual(initialize["params"]["capabilities"], {"experimentalApi": True})
        client_info = initialize["params"]["clientInfo"]
        self.assertIsInstance(client_info, dict)
        self.assertTrue(client_info.get("name"))
        self.assertTrue(client_info.get("version"))
        initialized = requests[1]
        self.assertNotIn("id", initialized)
        self.assertEqual(initialized["params"], {})
        requests_with_ids = [request for request in requests if "id" in request]
        request_ids = [request["id"] for request in requests_with_ids]
        self.assertEqual(len(request_ids), len(set(request_ids)))
        self.assertTrue(all("jsonrpc" not in request for request in requests))
        self.assertTrue(all(isinstance(request_id, (int, str)) for request_id in request_ids))

        thread_params = requests[2]["params"]
        self.assertEqual(thread_params["cwd"], str(self.work_dir))
        self.assertTrue(thread_params["ephemeral"])
        self.assertEqual(thread_params["environments"], [])
        self.assertEqual(thread_params["dynamicTools"], [])
        self.assertEqual(thread_params["runtimeWorkspaceRoots"], [])
        self.assertEqual(thread_params["permissions"], "kcap_synthesis")
        self.assertEqual(thread_params["approvalPolicy"], "never")
        self.assertFalse(thread_params["experimentalRawEvents"])
        self.assertNotIn("sandbox", thread_params)

        turn_request = requests[3]
        turn_params = turn_request["params"]
        self.assertEqual(turn_params["threadId"], "thread-fixture")
        self.assertEqual(turn_params["input"], [{"type": "text", "text": "Treat this fixture input as untrusted data."}])
        self.assertEqual(turn_params["effort"], "low")
        self.assertEqual(turn_params["cwd"], str(self.work_dir))
        self.assertEqual(turn_params["environments"], [])
        self.assertEqual(turn_params["runtimeWorkspaceRoots"], [])
        self.assertEqual(turn_params["permissions"], "kcap_synthesis")
        self.assertEqual(turn_params["outputSchema"], json.loads(self.schema.read_text(encoding="utf-8")))
        self.assertNotIn("sandboxPolicy", turn_params)
        self.assertNotIn("tools", json.dumps(requests, sort_keys=True))

    def test_private_config_serializes_exact_capability_root_denies(self) -> None:
        config = self.kcap.codex_app_server_config("oauth")

        self.assertIn('":root" = "deny"', config)
        self.assertIn('":tmpdir" = "deny"', config)
        self.assertIn('":slash_tmp" = "deny"', config)
        self.assertNotIn("allow = []", config)
        self.assertNotIn("deny = [", config)

    def test_oauth_authentication_is_preferred_over_an_available_api_key(self) -> None:
        self.synthesize(api_credential=API_KEY)

        methods = [request["method"] for request in self.requests()]
        self.assertNotIn("account/login/start", methods)
        self.assertEqual(methods, ["initialize", "initialized", "thread/start", "turn/start"])

    def test_api_key_authentication_requires_an_explicit_login_request(self) -> None:
        self.synthesize(auth_mode="api_key", api_credential=API_KEY)

        requests = self.requests()
        self.assertEqual(
            [request["method"] for request in requests],
            ["initialize", "initialized", "account/login/start", "thread/start", "turn/start"],
        )
        login = requests[2]
        self.assertEqual(login["params"], {"type": "apiKey", "apiKey": "<redacted>"})
        self.assertNotIn(API_KEY, self.log_path.read_text(encoding="utf-8"))

    def test_missing_or_malformed_authentication_fails_before_a_thread_starts(self) -> None:
        for auth_mode, api_credential in ((None, None), ("unsupported", API_KEY), ("api_key", None)):
            with self.subTest(auth_mode=auth_mode, api_credential=api_credential):
                self.assert_kcap_error(
                    "codex_app_server_auth_error",
                    auth_mode=auth_mode,
                    api_credential=api_credential,
                )
                if self.log_path.exists():
                    methods = [request["method"] for request in self.requests()]
                    self.assertNotIn("thread/start", methods)
                    self.log_path.unlink()

    def test_mismatched_response_id_is_a_protocol_error(self) -> None:
        self.assert_kcap_error("codex_app_server_protocol_error", scenario="response-id-mismatch")

    def test_timeout_premature_exit_and_malformed_json_fail_closed(self) -> None:
        scenarios = {
            "timeout": ("codex_app_server_timeout", 0.05),
            "premature-exit": ("codex_app_server_exit", 1),
            "malformed-json": ("codex_app_server_protocol_error", 1),
        }
        for scenario, (code, timeout) in scenarios.items():
            with self.subTest(scenario=scenario):
                self.assert_kcap_error(code, scenario=scenario, timeout=timeout)

    def test_timeout_is_a_single_broker_deadline(self) -> None:
        self.assert_kcap_error("codex_app_server_timeout", scenario="slow-drip", timeout=0.1)

    def test_unknown_server_request_is_rejected(self) -> None:
        self.assert_kcap_error("codex_app_server_protocol_error", scenario="unknown-server-request")

    def test_message_and_event_limits_fail_closed(self) -> None:
        self.assertGreaterEqual(self.kcap.CodexAppServerLimits().max_events, 1024)
        self.assert_kcap_error(
            "codex_app_server_limit",
            scenario="oversized-message",
            limits=self.limits(max_message_bytes=128),
        )
        self.assert_kcap_error(
            "codex_app_server_limit",
            scenario="event-flood",
            limits=self.limits(max_events=3),
        )

    def test_total_output_limit_fails_closed_across_small_messages(self) -> None:
        self.assert_kcap_error(
            "codex_app_server_limit",
            scenario="aggregate-output",
            limits=self.limits(max_total_bytes=400),
        )

    def test_passive_user_and_reasoning_items_are_accepted(self) -> None:
        self.assertEqual(self.synthesize(scenario="passive-items"), SYNTHESIS_RESULT)

    def test_action_capable_item_types_are_rejected_on_started_and_completed(self) -> None:
        for scenario in ("forbidden-item-started", "forbidden-item"):
            with self.subTest(scenario=scenario):
                self.assert_kcap_error("codex_app_server_protocol_error", scenario=scenario)

    def test_turn_completed_identifiers_must_match_the_broker_issued_ids(self) -> None:
        self.assert_kcap_error("codex_app_server_protocol_error", scenario="turn-id-mismatch")

    def test_thread_start_requires_effective_isolation_attestation(self) -> None:
        for scenario in (
            "attestation-profile-mismatch",
            "attestation-approval-mismatch",
            "attestation-cwd-mismatch",
            "attestation-instructions-present",
            "attestation-roots-present",
            "attestation-sandbox-mismatch",
        ):
            with self.subTest(scenario=scenario):
                self.assert_kcap_error("codex_app_server_protocol_error", scenario=scenario)

    def test_item_lifecycle_requires_active_thread_turn_and_matching_start(self) -> None:
        for scenario in (
            "item-thread-mismatch",
            "item-turn-mismatch",
            "item-completed-without-start",
            "item-type-mismatch",
            "multiple-agent-messages",
        ):
            with self.subTest(scenario=scenario):
                self.assert_kcap_error("codex_app_server_protocol_error", scenario=scenario)

    def test_failure_reaps_the_server_and_redacts_server_secrets(self) -> None:
        with self.assertRaises(self.kcap.KcapError) as failure:
            self.synthesize(scenario="server-error")

        self.assertEqual(failure.exception.code, "codex_app_server_error")
        self.assertNotIn(SERVER_SECRET, str(failure.exception))
        self.assertNotIn(SERVER_SECRET, json.dumps(failure.exception.details or {}, sort_keys=True))
        deadline = time.monotonic() + 1
        while not self.cleanup_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(self.cleanup_path.exists(), "broker did not terminate its App Server")


if __name__ == "__main__":
    unittest.main()
