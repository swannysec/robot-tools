"""Acceptance contract for the kcap OAuth private-copy boundary.

The tests use synthetic OAuth records only.  They exercise the boundary around
the isolated child rather than a live Codex credential or service.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
KCAP_PATH = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"
INITIAL_AUTH = (
    b'{"auth_mode":"chatgpt","tokens":{"access_token":"initial-access",'
    b'"id_token":"initial-identity","refresh_token":"initial-refresh"}}\n'
)
REFRESHED_AUTH = (
    b'{"auth_mode":"chatgpt","tokens":{"access_token":"refreshed-access",'
    b'"id_token":"refreshed-identity","refresh_token":"refreshed-refresh"}}\n'
)
SYNTHESIS = {
    "title": "OAuth boundary fixture",
    "author": "Fixture Author",
    "published": "2026-09-03",
    "tldr": "The private OAuth copy remains isolated.",
    "summary": "The source may refresh after the copy boundary is verified.",
    "takeaways": ["The source authentication file is never given to the child."],
    "detailed_notes": "The fixture does not invoke a live credential or service.",
    "quotes": [],
    "references": [],
    "tags": ["fixture"],
    "chapters": [],
    "thread": [],
}


def load_kcap():
    name = "kcap_oauth_boundary_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, KCAP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KcapOAuthBoundaryAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kcap-oauth-boundary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source_home = self.root / "source-home"
        self.source_home.mkdir()
        self.source = self.source_home / "auth.json"
        self.report = self.root / "kcap-codex-app-server-report.json"
        self.kcap = load_kcap()

    def write_private(self, path: Path, content: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)

    def replace_private(self, path: Path, content: bytes) -> None:
        replacement = path.with_name(path.name + ".replacement")
        self.write_private(replacement, content)
        os.replace(replacement, path)

    def args(self) -> argparse.Namespace:
        return argparse.Namespace(
            mode="standard",
            profile="fast",
            codex_bin="fixture-codex",
            dry_run=False,
            timeout=1,
            content_type="article",
            url="https://example.com/fixture",
            focus=None,
            output_file=str(self.root / "capture.md"),
            acceptance_report=str(self.report),
        )

    def oauth_environment(self, **extra: str) -> dict[str, str]:
        environment = {
            "CODEX_HOME": str(self.source_home),
            "RESEARCH_TOOLKIT_CODEX_AUTH": "oauth",
            "PATH": os.environ.get("PATH", os.defpath),
        }
        environment.update(extra)
        return environment

    def synthesis_patches(self):
        return patch.multiple(
            self.kcap,
            synthesis_inputs=lambda _args: ("synthetic content", {}),
            supported_codex_features=lambda _bin, _environment: {},
            save_sanitized_synthesis_result=lambda _value, _args: {"status": "saved"},
            run_process=lambda _command, **_kwargs: subprocess.CompletedProcess(
                _command, 0, stdout="fixture-codex 1.0\n", stderr=""
            ),
        )

    def test_refresh_after_verified_private_copy_succeeds_and_attests_boundary(self) -> None:
        """A later Codex refresh is outside the source_unchanged copy assertion."""
        self.write_private(self.source, INITIAL_AUTH)
        copies: list[Path] = []
        test = self

        class RefreshingBroker:
            def __init__(self, **kwargs: object) -> None:
                environment = kwargs["environment"]
                assert isinstance(environment, dict)
                copy = Path(environment["CODEX_HOME"]) / "auth.json"
                copies.append(copy)
                self.assert_copy(copy)

            def assert_copy(self, copy: Path) -> None:
                test.assertEqual(copy.read_bytes(), INITIAL_AUTH)
                test.assertEqual(stat.S_IMODE(copy.stat().st_mode), 0o600)

            def synthesize(self, _prompt: str, _schema: Path) -> dict[str, object]:
                test.replace_private(test.source, REFRESHED_AUTH)
                return SYNTHESIS

        with patch.dict(os.environ, self.oauth_environment(), clear=True), self.synthesis_patches(), patch.object(
            self.kcap, "CodexAppServerBroker", RefreshingBroker
        ):
            result = self.kcap.codex_synthesize(self.args())

        self.assertEqual(result, {"status": "saved"})
        self.assertEqual(self.source.read_bytes(), REFRESHED_AUTH)
        self.assertEqual(len(copies), 1)
        self.assertFalse(copies[0].exists(), "the private OAuth copy must be removed with its workspace")
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(
            report["auth"],
            {
                "mode": "oauth",
                "source_unchanged": True,
                "auth_copy_boundary_verified": True,
                "private_copy_removed": True,
            },
        )
        rendered = json.dumps(report, sort_keys=True)
        for credential in (INITIAL_AUTH, REFRESHED_AUTH):
            self.assertNotIn(credential.decode("utf-8").strip(), rendered)

    def test_source_change_during_private_copy_fails_before_synthesis(self) -> None:
        self.write_private(self.source, INITIAL_AUTH)
        original_writer = self.kcap.write_private_bytes
        broker_started = False

        class UnexpectedBroker:
            def __init__(self, **_kwargs: object) -> None:
                nonlocal broker_started
                broker_started = True

        def mutate_during_copy(path: Path, content: bytes) -> None:
            original_writer(path, content)
            if path.name == "auth.json":
                self.replace_private(self.source, REFRESHED_AUTH)

        with patch.dict(os.environ, self.oauth_environment(), clear=True), self.synthesis_patches(), patch.object(
            self.kcap, "write_private_bytes", mutate_during_copy
        ), patch.object(self.kcap, "CodexAppServerBroker", UnexpectedBroker):
            with self.assertRaises(self.kcap.KcapError) as failure:
                self.kcap.codex_synthesize(self.args())

        self.assertEqual(failure.exception.code, "codex_auth_error")
        self.assertFalse(broker_started)
        self.assertNotIn("initial-access", failure.exception.message)
        self.assertNotIn("refreshed-access", failure.exception.message)

    def test_oauth_source_requires_private_regular_owner_owned_well_formed_document(self) -> None:
        cases = {
            "symlink": lambda: self.source.symlink_to(self.root / "target.json"),
            "wrong-mode": lambda: (self.write_private(self.source, INITIAL_AUTH), self.source.chmod(0o644)),
            "malformed": lambda: self.write_private(self.source, b'{"auth_mode":"chatgpt"}\n'),
        }
        (self.root / "target.json").write_bytes(INITIAL_AUTH)

        for name, arrange in cases.items():
            with self.subTest(name=name):
                if self.source.exists() or self.source.is_symlink():
                    self.source.unlink()
                arrange()
                with patch.object(self.kcap.Path, "home", return_value=self.root / "no-home"), patch.dict(
                    os.environ, self.oauth_environment(), clear=True
                ):
                    with self.assertRaises(self.kcap.KcapError) as failure:
                        self.kcap.selected_codex_auth()
                self.assertEqual(failure.exception.code, "codex_auth_error")
                self.assertNotIn("initial-access", failure.exception.message)

        if self.source.exists() or self.source.is_symlink():
            self.source.unlink()
        self.write_private(self.source, INITIAL_AUTH)
        with patch.object(self.kcap.Path, "home", return_value=self.root / "no-home"), patch.object(
            self.kcap.os, "geteuid", return_value=os.geteuid() + 1
        ), patch.dict(os.environ, self.oauth_environment(), clear=True):
            with self.assertRaises(self.kcap.KcapError) as failure:
                self.kcap.selected_codex_auth()
        self.assertEqual(failure.exception.code, "codex_auth_error")

    def test_api_key_selection_remains_explicit_and_does_not_copy_oauth_source(self) -> None:
        self.write_private(self.source, INITIAL_AUTH)
        api_key = "API_KEY_FIXTURE_MUST_NOT_LEAK"
        environment = self.oauth_environment(
            RESEARCH_TOOLKIT_CODEX_AUTH="api_key",
            OPENAI_API_KEY=api_key,
        )

        with patch.dict(os.environ, environment, clear=True):
            mode, source, credential = self.kcap.selected_codex_auth()

        self.assertEqual(mode, "api_key")
        self.assertIsNone(source)
        self.assertEqual(credential, api_key)
        self.assertEqual(self.source.read_bytes(), INITIAL_AUTH)


if __name__ == "__main__":
    unittest.main()
