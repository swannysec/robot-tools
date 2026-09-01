"""Regression tests for kcap network authority and process-error boundaries.

The tests mock the external executables at the subprocess boundary.  They do
not use the host resolver, network, curl, yt-dlp, or the Twitter extractor.
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Optional
from unittest.mock import patch
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
KCAP_PATH = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"


def load_kcap():
    """Import a fresh kcap module for isolated mocks in each test."""
    name = "kcap_network_process_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, KCAP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KcapNetworkProcessAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kcap-")
        self.addCleanup(self.temporary.cleanup)
        self.work_dir = Path(self.temporary.name)
        self.kcap = load_kcap()

    def _validated(self, url: str, content_type: str) -> dict[str, object]:
        hostname = (urlparse(url).hostname or "").lower().rstrip(".")
        return {
            "url": url,
            "hostname": hostname,
            "content_type": content_type,
            "normalized": "fixture",
            "resolved_addresses": ["8.8.8.8"],
        }

    def _write_response(self, command: list[str], status: int, headers: str = "") -> None:
        headers_path = Path(command[command.index("-D") + 1])
        body_path = Path(command[command.index("-o") + 1])
        headers_path.write_text(headers or "HTTP/1.1 {} Fixture\r\n\r\n".format(status), encoding="iso-8859-1")
        body_path.write_text("<html>fixture</html>", encoding="utf-8")

    def _assert_canonical_curl_authority(self, command: list[str], expected_url: str) -> None:
        self.assertEqual(command[-1], expected_url)
        resolve = command[command.index("--resolve") + 1]
        self.assertEqual(resolve, "{}:443:8.8.8.8".format(urlparse(expected_url).hostname))
        self.assertEqual(urlparse(command[-1]).hostname, resolve.split(":", 1)[0])
        self.assertNotIn("example.test.", command[-1])

    def test_initial_trailing_dot_hostname_is_canonicalized_for_curl_authority(self) -> None:
        source_url = "https://example.test./article?case=initial"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            self._write_response(command, 200)
            return subprocess.CompletedProcess(command, 0, "200", "")

        with patch.object(self.kcap.shutil, "which", return_value="/fixture/curl"), patch.object(
            self.kcap, "validate_url", side_effect=lambda url, resolve=True: self._validated(url, "article")
        ), patch.object(self.kcap, "run_process", side_effect=fake_run):
            self.kcap.fetch_article(source_url, self.work_dir)

        self.assertEqual(len(commands), 1)
        self._assert_canonical_curl_authority(
            commands[0], "https://example.test/article?case=initial"
        )

    def test_trailing_dot_redirect_is_canonicalized_before_next_curl_request(self) -> None:
        source_url = "https://origin.test/article"
        redirected_url = "https://redirect.test/next?case=redirect"
        commands: list[list[str]] = []

        def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if len(commands) == 1:
                self._write_response(
                    command,
                    302,
                    "HTTP/1.1 302 Fixture\r\nLocation: https://redirect.test./next?case=redirect\r\n\r\n",
                )
                return subprocess.CompletedProcess(command, 0, "302", "")
            self._write_response(command, 200)
            return subprocess.CompletedProcess(command, 0, "200", "")

        with patch.object(self.kcap.shutil, "which", return_value="/fixture/curl"), patch.object(
            self.kcap, "validate_url", side_effect=lambda url, resolve=True: self._validated(url, "article")
        ), patch.object(self.kcap, "run_process", side_effect=fake_run):
            self.kcap.fetch_article(source_url, self.work_dir)

        self.assertEqual(len(commands), 2)
        self._assert_canonical_curl_authority(commands[1], redirected_url)

    def _assert_timeout_error_is_safe(self, content_type: str, url: str, executable: str) -> None:
        token = "query-token-canary-{}".format(content_type)
        self.assertIn(token, url)

        def fixture_which(name: str) -> Optional[str]:
            return "/fixture/{}".format(name) if name == executable else None

        def timeout(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            raise subprocess.TimeoutExpired(command, 60)

        with patch.object(
            self.kcap, "validate_url", side_effect=lambda value, resolve=True: self._validated(value, content_type)
        ), patch.object(self.kcap.shutil, "which", side_effect=fixture_which), patch.object(
            self.kcap.subprocess, "run", side_effect=timeout
        ):
            with self.assertRaises(self.kcap.KcapError) as caught:
                self.kcap.extract_content(url, self.work_dir, "standard")

        error = caught.exception
        message = error.message
        self.assertEqual(error.code, "process_failed")
        self.assertNotIn(url, message)
        self.assertNotIn(token, message)
        self.assertNotIn("Command ", message)
        self.assertNotIn("timed out after", message)
        self.assertNotIn("--", message)

    def test_article_curl_timeout_error_does_not_expose_argv_or_url(self) -> None:
        self._assert_timeout_error_is_safe(
            "article",
            "https://article.test/read?access=query-token-canary-article",
            "curl",
        )

    def test_video_yt_dlp_timeout_error_does_not_expose_argv_or_url(self) -> None:
        self._assert_timeout_error_is_safe(
            "video",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ&access=query-token-canary-video",
            "yt-dlp",
        )

    def test_tweet_extractor_timeout_error_does_not_expose_argv_or_url(self) -> None:
        self._assert_timeout_error_is_safe(
            "tweet",
            "https://twitter.com/fixture/status/1234567890?access=query-token-canary-tweet",
            "bird",
        )


if __name__ == "__main__":
    unittest.main()
