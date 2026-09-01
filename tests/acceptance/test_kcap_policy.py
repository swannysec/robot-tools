"""Acceptance coverage for the public kcap capture policy controller.

These tests deliberately replace extraction and synthesis with local fakes.  The
controller must make its policy decisions before it can expose untrusted source
or model content in its machine-readable result.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
import uuid
import webbrowser
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[2]
KCAP_PATH = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"
URL = "https://example.com/articles/policy?utm_source=test"
NORMALIZED_URL = "https://example.com/articles/policy"
RAW_SENTINEL = "RAW_EXTERNAL_CONTENT_MUST_NOT_LEAK"
MODEL_SENTINEL = "MODEL_SYNTHESIS_PROSE_MUST_NOT_LEAK"


def load_kcap():
    """Import a fresh module so fakes and environment are isolated per test."""
    name = "kcap_policy_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, KCAP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KcapPolicyAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.output_dir = Path(self.tempdir.name) / "vault" / "captures"
        self.kcap = load_kcap()
        self.extract = Mock(side_effect=self._extract)
        self.synthesize = Mock(side_effect=self._synthesize)
        self.render = Mock(return_value=("# Safe final note\n", "note.md"))

        self.kcap.validate_url = Mock(
            return_value={
                "url": URL,
                "normalized": NORMALIZED_URL,
                "content_type": "article",
                "hostname": "example.com",
            }
        )
        self.kcap.load_config = Mock(
            return_value=(
                {
                    "output_path": str(Path(self.tempdir.name) / "vault"),
                    "subfolder": "captures",
                    "vault_name": None,
                    "default_tags": [],
                    "default_mode": "standard",
                    "synthesis_profile": "fast",
                },
                "test",
                [],
            )
        )
        self.kcap.effective_config = Mock(
            return_value=(
                {
                    "mode": "standard",
                    "synthesis_profile": "fast",
                    "vault_name": None,
                    "default_tags": [],
                },
                [],
            )
        )
        self.kcap.find_duplicate = Mock(return_value=[])
        self.kcap.extract_content = self.extract
        self.kcap.detect_runtime = Mock(return_value=("codex", "test"))
        self.kcap.codex_synthesize = self.synthesize
        self.kcap.claude_synthesize = self.synthesize
        self.kcap.render_markdown = self.render

    def _extract(self, url: str, work_dir: Path, mode: str) -> dict[str, object]:
        content_file = work_dir / "content.txt"
        metadata_file = work_dir / "metadata.json"
        content_file.write_text("{}\n".format(RAW_SENTINEL), encoding="utf-8")
        metadata_file.write_text(json.dumps({"raw": RAW_SENTINEL}), encoding="utf-8")
        return {
            "content_file": str(content_file),
            "metadata_file": str(metadata_file),
            "word_count": 300,
            "original_word_count": 300,
        }

    def _synthesize(self, args: object) -> dict[str, object]:
        output_file = Path(getattr(args, "output_file"))
        output_file.write_text(json.dumps({"unsafe": MODEL_SENTINEL}), encoding="utf-8")
        return {"synthesis_file": str(output_file), "bytes": output_file.stat().st_size}

    def invoke(self, *arguments: str) -> tuple[int, dict[str, object], dict[str, object]]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = self.kcap.main(["capture", URL, *arguments])
        out_payload = json.loads(stdout.getvalue()) if stdout.getvalue() else {}
        err_payload = json.loads(stderr.getvalue()) if stderr.getvalue() else {}
        return result, out_payload, err_payload

    def assert_safe_payload(self, payload: object) -> None:
        serialized = json.dumps(payload, sort_keys=True)
        self.assertNotIn(RAW_SENTINEL, serialized)
        self.assertNotIn(MODEL_SENTINEL, serialized)

    def configure_duplicate(self, *paths: Path) -> None:
        self.kcap.find_duplicate.return_value = [str(path) for path in paths]

    def test_duplicate_without_collision_requires_confirmation_before_extraction(self) -> None:
        existing = self.output_dir / "existing.md"
        self.configure_duplicate(existing)

        status, output, error = self.invoke()

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "confirmation_required")
        details = error["error"]["details"]
        self.assertEqual(details["existing_paths"], [str(existing)])
        self.assertEqual(details["choices"], ["replace", "suffix", "skip"])
        self.extract.assert_not_called()
        self.synthesize.assert_not_called()
        self.assert_safe_payload(error)

    def test_replace_requires_one_normalized_source_match_and_reports_replaced(self) -> None:
        self.output_dir.mkdir(parents=True)
        existing = self.output_dir / "published-source.md"
        existing.write_text("old capture", encoding="utf-8")
        self.configure_duplicate(existing)

        status, output, error = self.invoke("--collision", "replace")

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "replaced")
        self.assertEqual(Path(str(output["output_file"])).resolve(), existing.resolve())
        self.assertEqual(output["filename"], "published-source.md")
        self.assertEqual(existing.read_text(encoding="utf-8"), "# Safe final note\n")
        self.assertFalse((self.output_dir / "note.md").exists())
        self.assertEqual(output["effective_mode"], "standard")
        self.assertEqual(output["content_type"], "article")
        self.assertIn("bytes", output)
        self.assertIn("warnings", output)
        self.assertIsNone(output["obsidian_uri"])
        self.extract.assert_called_once()
        self.synthesize.assert_called_once()
        self.assert_safe_payload(output)

    def test_suffix_creates_the_deterministic_next_filename(self) -> None:
        self.output_dir.mkdir(parents=True)
        (self.output_dir / "note.md").write_text("old", encoding="utf-8")
        (self.output_dir / "note-2.md").write_text("older", encoding="utf-8")
        self.configure_duplicate(self.output_dir / "note.md")

        status, output, error = self.invoke("--collision", "suffix")

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "created")
        self.assertEqual(output["filename"], "note-3.md")
        self.assertEqual(
            Path(str(output["output_file"])).resolve(),
            (self.output_dir / "note-3.md").resolve(),
        )
        self.assertTrue((self.output_dir / "note-3.md").is_file())
        self.assert_safe_payload(output)

    def test_explicit_skip_returns_sorted_existing_paths_without_work(self) -> None:
        paths = (self.output_dir / "z-last.md", self.output_dir / "a-first.md")
        self.configure_duplicate(*paths)

        status, output, error = self.invoke("--collision", "skip")

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "skipped_duplicate")
        self.assertEqual(output["existing_paths"], sorted(map(str, paths)))
        self.assertEqual(output["existing_count"], 2)
        self.extract.assert_not_called()
        self.synthesize.assert_not_called()
        self.assert_safe_payload(output)

    def test_replace_rejects_ambiguous_duplicate_matches_before_extraction(self) -> None:
        self.configure_duplicate(self.output_dir / "one.md", self.output_dir / "two.md")

        status, output, error = self.invoke("--collision", "replace")

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "duplicate_ambiguous")
        self.assertEqual(error["error"]["details"]["existing_paths"], [
            str(self.output_dir / "one.md"),
            str(self.output_dir / "two.md"),
        ])
        self.extract.assert_not_called()
        self.synthesize.assert_not_called()
        self.assert_safe_payload(error)

    def test_noninteractive_duplicate_skips_without_extraction_or_synthesis(self) -> None:
        existing = self.output_dir / "existing.md"
        self.configure_duplicate(existing)

        with patch.dict(os.environ, {"RESEARCH_TOOLKIT_NONINTERACTIVE": "1"}):
            status, output, error = self.invoke()

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "skipped_duplicate")
        self.assertEqual(output["existing_paths"], [str(existing)])
        self.extract.assert_not_called()
        self.synthesize.assert_not_called()
        self.assert_safe_payload(output)

    def test_deep_original_content_over_limit_requires_confirmation_before_synthesis(self) -> None:
        self.extract.side_effect = self._large_extract

        status, output, error = self.invoke("--mode", "deep")

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "confirmation_required")
        details = error["error"]["details"]
        self.assertEqual(details["original_word_count"], 15001)
        self.assertEqual(details["threshold"], 15000)
        self.synthesize.assert_not_called()
        self.assert_safe_payload(error)

    def test_confirm_large_allows_deep_capture_and_reports_effective_mode(self) -> None:
        self.extract.side_effect = self._large_extract

        status, output, error = self.invoke("--mode", "deep", "--confirm-large")

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "created")
        self.assertEqual(output["effective_mode"], "deep")
        self.synthesize.assert_called_once()
        self.assert_safe_payload(output)

    def test_noninteractive_large_deep_capture_aborts_without_synthesis(self) -> None:
        self.extract.side_effect = self._large_extract

        with patch.dict(os.environ, {"RESEARCH_TOOLKIT_NONINTERACTIVE": "1"}):
            status, output, error = self.invoke("--mode", "deep")

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "confirmation_required")
        self.assertTrue(error["error"]["details"]["noninteractive"])
        self.synthesize.assert_not_called()
        self.assert_safe_payload(error)

    def test_configured_vault_returns_encoded_uri_and_never_opens_an_application(self) -> None:
        self.kcap.load_config.return_value[0]["vault_name"] = "Team Vault & Notes"
        self.kcap.effective_config.return_value[0]["vault_name"] = "Team Vault & Notes"

        with patch.object(webbrowser, "open", autospec=True) as launch:
            status, output, error = self.invoke()

        self.assertEqual(status, 0, error)
        uri = output["obsidian_uri"]
        self.assertIsInstance(uri, str)
        self.assertNotIn(" ", uri)
        self.assertNotIn("& Notes", uri)
        query = parse_qs(urlparse(uri).query)
        self.assertEqual(query["vault"], ["Team Vault & Notes"])
        self.assertEqual(query["file"], ["captures/note.md"])
        launch.assert_not_called()
        self.assert_safe_payload(output)

    def test_symlinked_configured_capture_directory_is_rejected_before_external_work(self) -> None:
        vault = Path(self.tempdir.name) / "vault"
        outside = Path(self.tempdir.name) / "outside"
        vault.mkdir()
        outside.mkdir()
        (vault / "captures").symlink_to(outside, target_is_directory=True)
        self.kcap.load_config.return_value[0]["output_path"] = str(vault)

        status, output, error = self.invoke()

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "invalid_output_path")
        self.extract.assert_not_called()
        self.synthesize.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_configured_output_root_is_rejected_before_external_work(self) -> None:
        outside = Path(self.tempdir.name) / "outside-root"
        outside.mkdir()
        configured_root = Path(self.tempdir.name) / "configured-vault"
        configured_root.symlink_to(outside, target_is_directory=True)
        self.kcap.load_config.return_value[0]["output_path"] = str(configured_root)

        status, output, error = self.invoke()

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "invalid_output_path")
        self.extract.assert_not_called()
        self.synthesize.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_markdown_sanitizer_removes_reference_images_and_obfuscated_unsafe_schemes(self) -> None:
        value = (
            "before ![tracker][r] ![collapsed][]\n"
            "[r]: https://attacker.example/pixel\n"
            "[collapsed]: https://attacker.example/collapsed\n"
            "[click](java&#x73;cript:alert(1)) "
            "[again](%256a%2561%2576%2561%2573%2563%2572%2569%2570%2574:alert(1)) "
            "[safe](https://example.com/docs) after"
        )

        cleaned = self.kcap.clean_markdown(value)

        self.assertNotIn("![", cleaned)
        self.assertNotIn("attacker.example", cleaned)
        self.assertNotIn("javascript:", cleaned.lower())
        self.assertIn("[click](#)", cleaned)
        self.assertIn("[again](#)", cleaned)
        self.assertIn("[safe](https://example.com/docs)", cleaned)

    def test_markdown_sanitizer_neutralizes_obfuscated_unsafe_reference_links(self) -> None:
        value = (
            "[click][unsafe] [again][] [safe][docs]\n\n"
            "[unsafe]: java&#x73;cript:alert(1)\n"
            "[again]: %256a%2561%2576%2561%2573%2563%2572%2569%2570%2574:alert(1)\n"
            "[docs]: https://example.com/docs\n"
        )

        cleaned = self.kcap.clean_markdown(value)

        self.assertNotIn("javascript:", cleaned.lower())
        self.assertNotIn("%256a", cleaned.lower())
        self.assertIn("[unsafe]: #", cleaned)
        self.assertIn("[again]: #", cleaned)
        self.assertIn("[safe][docs]", cleaned)
        self.assertIn("[docs]: https://example.com/docs", cleaned)

    def test_safe_error_details_are_optional_and_legacy_errors_keep_their_shape(self) -> None:
        legacy_error = self.kcap.KcapError("invalid_url", "invalid")
        detailed_error = self.kcap.KcapError(
            "confirmation_required",
            "confirmation required",
            details={"choices": ["replace", "suffix", "skip"]},
        )

        with patch.object(self.kcap, "dispatch", side_effect=legacy_error):
            status, output, error = self.invoke()
        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error, {"ok": False, "error": {"code": "invalid_url", "message": "invalid"}})

        with patch.object(self.kcap, "dispatch", side_effect=detailed_error):
            status, output, error = self.invoke()
        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(
            error,
            {
                "ok": False,
                "error": {
                    "code": "confirmation_required",
                    "message": "confirmation required",
                    "details": {"choices": ["replace", "suffix", "skip"]},
                },
            },
        )
        self.assert_safe_payload(error)

    def _large_extract(self, url: str, work_dir: Path, mode: str) -> dict[str, object]:
        result = self._extract(url, work_dir, mode)
        result["original_word_count"] = 15001
        return result


if __name__ == "__main__":
    unittest.main()
