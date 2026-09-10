"""RED acceptance coverage for kcap synthesis length, tag, and host policy."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import subprocess
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
KCAP_PATH = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"
STANDARD_SCHEMA = ROOT / "research-toolkit" / "skills" / "kcap" / "schemas" / "standard.json"
GENERIC_TAGS = {"article", "video", "tweet", "summary", "content"}
REJECTED_TLDR = "REJECTED_TLDR_PROSE_MUST_NOT_LEAK"


def load_kcap():
    name = "kcap_synthesis_policy_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, KCAP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def standard_document(tldr: str, tags: Optional[List[str]] = None) -> Dict[str, object]:
    return {
        "title": "Fixture synthesis",
        "author": None,
        "published": None,
        "tldr": tldr,
        "summary": "A grounded fixture summary.",
        "takeaways": ["A grounded takeaway."],
        "detailed_notes": "A grounded fixture note.",
        "quotes": [],
        "references": [],
        "tags": tags if tags is not None else ["fixture-topic"],
        "chapters": [],
        "thread": [],
    }


def words(count: int, prefix: str = "word") -> str:
    return " ".join("{}{}".format(prefix, index) for index in range(count))


class KcapSynthesisPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kcap = load_kcap()

    def test_standard_and_deep_prompts_aim_for_useful_35_to_50_word_tldrs_without_disclosing_75(self) -> None:
        for mode in ("standard", "deep"):
            with self.subTest(mode=mode):
                prompt = self.kcap.build_synthesis_prompt(
                    "source material", {}, mode, "article", "https://example.com/story", None
                ).lower()
                self.assertIn("35-50", prompt)
                self.assertIn("accuracy", prompt)
                self.assertIn("effectiveness", prompt)
                self.assertIn("exact length", prompt)
                self.assertNotIn("75", prompt)

    def test_full_prompt_has_no_tldr_length_retry_policy(self) -> None:
        prompt = self.kcap.build_synthesis_prompt(
            "source material", {}, "full", "article", "https://example.com/story", None
        ).lower()
        self.assertNotIn("35-50", prompt)
        self.assertNotIn("75", prompt)

    def test_sanitizer_accepts_cleaned_tldrs_through_75_words_and_rejects_76_with_safe_reason(self) -> None:
        for count in (35, 50, 51, 75):
            with self.subTest(count=count):
                result = self.kcap.sanitize_synthesis(standard_document(words(count)), "standard")
                self.assertEqual(len(result["tldr"].split()), count)

        with self.assertRaises(self.kcap.KcapError) as failure:
            self.kcap.sanitize_synthesis(standard_document(words(76)), "standard")
        self.assertEqual(failure.exception.code, "invalid_synthesis")
        self.assertEqual(
            failure.exception.details,
            {"reason": "tldr_too_long", "word_count": 76, "limit": 75},
        )

    def test_tag_sanitizer_filters_only_exact_generic_and_invalid_candidates_then_preserves_order(self) -> None:
        longest_valid = "a" * 48
        result = self.kcap.sanitize_synthesis(
            standard_document(
                words(35),
                [
                    "article",
                    "machine-learning",
                    "machine-learning",
                    "2026",
                    "article-review",
                    longest_valid,
                    "b" * 49,
                    "not_valid",
                    "summary",
                    "content",
                    "video",
                    "tweet",
                ],
            ),
            "standard",
        )
        self.assertEqual(result["tags"], ["machine-learning", "article-review", longest_valid])
        self.assertTrue(all(tag not in GENERIC_TAGS for tag in result["tags"]))
        self.assertTrue(all(not tag.isdigit() and len(tag) <= 48 for tag in result["tags"]))

    def test_tag_sanitizer_rejects_zero_or_more_than_five_retained_tags_with_stable_reasons(self) -> None:
        with self.assertRaises(self.kcap.KcapError) as empty:
            self.kcap.sanitize_synthesis(standard_document(words(35), ["article", "123", "not_valid"]), "standard")
        self.assertEqual(empty.exception.code, "invalid_synthesis")
        self.assertEqual(empty.exception.details, {"reason": "no_valid_tags"})

        with self.assertRaises(self.kcap.KcapError) as too_many:
            self.kcap.sanitize_synthesis(
                standard_document(words(35), ["one", "two", "three", "four", "five", "six"]), "standard"
            )
        self.assertEqual(too_many.exception.code, "invalid_synthesis")
        self.assertEqual(too_many.exception.details, {"reason": "too_many_tags", "count": 6, "limit": 5})

    def test_prompt_requests_one_to_five_grounded_topical_tags(self) -> None:
        prompt = self.kcap.build_synthesis_prompt(
            "source material", {}, "standard", "article", "https://example.com/story", None
        ).lower()
        self.assertIn("1-5", prompt)
        self.assertIn("grounded", prompt)
        self.assertIn("topical", prompt)
        self.assertIn("tags", prompt)

    def test_prompt_prefers_broad_discovery_topics_alongside_specific_tags(self) -> None:
        prompt = self.kcap.build_synthesis_prompt(
            "source material", {}, "standard", "video", "https://www.youtube.com/watch?v=fixture", None
        ).lower()
        self.assertIn("higher-level", prompt)
        self.assertIn("us-civil-war", prompt)
        self.assertIn("battle", prompt)
        self.assertIn("military-history", prompt)

    def test_render_always_prepends_one_kcap_provenance_tag(self) -> None:
        markdown, _ = self.kcap.render_markdown(
            standard_document(words(35), ["us-civil-war", "battle"]),
            "https://example.com/story",
            "article",
            "standard",
            dt.datetime(2026, 9, 4, tzinfo=dt.timezone.utc),
            {"default_tags": ["military-history", "kcap", "kcap"]},
        )
        tag_lines = [line.strip()[2:] for line in markdown.splitlines() if line.startswith("  - ")]
        self.assertEqual(tag_lines, ["kcap", "us-civil-war", "battle", "military-history"])

    def _claude_args(self, work_dir: Path, mode: str = "standard") -> argparse.Namespace:
        return argparse.Namespace(
            content_file=str(work_dir / "content.txt"),
            metadata_file=str(work_dir / "metadata.json"),
            mode=mode,
            content_type="article",
            url="https://example.com/story",
            focus=None,
            profile="fast",
            output_file=str(work_dir / "synthesis.json"),
            claude_bin="claude",
            timeout=30,
            dry_run=False,
        )

    def _run_claude(
        self, responses: List[Dict[str, object]], mode: str = "standard", prompts: Optional[List[str]] = None
    ) -> Tuple[object, List[str]]:
        prompts = prompts if prompts is not None else []
        response_iter = iter(responses)

        def fake_run(command, stdin=None, **_kwargs):
            if command[-1] == "--help":
                return subprocess.CompletedProcess(command, 0, "--safe-mode --no-session-persistence --no-chrome --tools --mcp-config --strict-mcp-config --json-schema --permission-mode", "")
            assert stdin is not None
            prompts.append(stdin)
            return subprocess.CompletedProcess(command, 0, json.dumps({"structured_output": next(response_iter)}), "")

        work_dir = self.kcap.create_work_dir()
        self.addCleanup(self.kcap.cleanup_work_dir, work_dir)
        (work_dir / "content.txt").write_text(words(50), encoding="utf-8")
        (work_dir / "metadata.json").write_text("{}", encoding="utf-8")
        with patch.object(self.kcap, "run_process", side_effect=fake_run):
            result = self.kcap.claude_synthesize(self._claude_args(work_dir, mode))
        return result, prompts

    def _run_codex(self, responses: List[Dict[str, object]]) -> Tuple[object, List[str]]:
        prompts: List[str] = []
        response_iter = iter(responses)
        module = self.kcap

        class FakeBroker:
            def __init__(self, **_kwargs: Any) -> None:
                pass

            def synthesize(self, prompt: str, _schema: Path) -> Dict[str, object]:
                prompts.append(prompt)
                return next(response_iter)

        def child_environment(work_dir: Path, **_kwargs: Any) -> Dict[str, str]:
            home = work_dir / "codex-home"
            home.mkdir()
            return {"CODEX_HOME": str(home)}

        work_dir = module.create_work_dir()
        self.addCleanup(module.cleanup_work_dir, work_dir)
        args = self._claude_args(work_dir)
        args.codex_bin = "codex"
        args.acceptance_report = None
        with patch.object(module, "synthesis_inputs", return_value=(words(50), {})), patch.object(
            module, "select_codex_binary", return_value="codex"
        ), patch.object(module, "selected_codex_auth", return_value=("oauth", None, None)), patch.object(
            module, "codex_child_environment", side_effect=child_environment
        ), patch.object(module, "supported_codex_features", return_value={}), patch.object(
            module, "CodexAppServerBroker", FakeBroker
        ):
            result = module.codex_synthesize(args)
        return result, prompts

    def test_claude_attempts_one_and_two_do_not_disclose_75_then_targeted_third_repair_succeeds(self) -> None:
        invalid = standard_document(words(76, REJECTED_TLDR))
        valid = standard_document(words(50))

        result, prompts = self._run_claude([invalid, invalid, valid])

        self.assertEqual(result["mode"], "standard")
        self.assertEqual(len(prompts), 3)
        self.assertNotIn("75", prompts[0])
        self.assertNotIn("75", prompts[1])
        self.assertIn("35-50", prompts[2])
        self.assertIn("75", prompts[2])
        self.assertIn("<external_content>", prompts[2])
        self.assertIn("word0", prompts[2])
        self.assertNotIn(REJECTED_TLDR, prompts[2])

    def test_claude_tldr_repair_still_fails_without_rejected_prose_leakage(self) -> None:
        invalid = standard_document(words(76, REJECTED_TLDR))

        with self.assertRaises(self.kcap.KcapError) as failure:
            self._run_claude([invalid, invalid, invalid])

        self.assertEqual(failure.exception.code, "invalid_synthesis")
        self.assertNotIn(REJECTED_TLDR, failure.exception.message)
        self.assertNotIn(REJECTED_TLDR, json.dumps(failure.exception.details or {}))

    def test_codex_uses_the_same_targeted_third_tldr_repair_policy_as_claude(self) -> None:
        invalid = standard_document(words(76, REJECTED_TLDR))
        valid = standard_document(words(50))

        result, prompts = self._run_codex([invalid, invalid, valid])

        self.assertEqual(result["mode"], "standard")
        self.assertEqual(len(prompts), 3)
        self.assertNotIn("75", prompts[0])
        self.assertNotIn("75", prompts[1])
        self.assertIn("35-50", prompts[2])
        self.assertIn("75", prompts[2])
        self.assertIn("<external_content>", prompts[2])
        self.assertIn("word0", prompts[2])
        self.assertNotIn(REJECTED_TLDR, prompts[2])

    def test_full_mode_keeps_the_two_attempt_general_validation_behavior_without_tldr_repair(self) -> None:
        invalid_full = {
            "title": "Fixture synthesis",
            "author": None,
            "published": None,
            "tags": ["fixture-topic"],
            "cleaned_content": "too short",
        }
        prompts: List[str] = []
        with self.assertRaises(self.kcap.KcapError):
            self._run_claude([invalid_full, invalid_full], mode="full", prompts=prompts)
        self.assertEqual(len(prompts), 2)
        self.assertTrue(all("35-50" not in prompt and "75" not in prompt for prompt in prompts))

    def test_claude_and_codex_runtime_guides_pass_a_raw_quoted_url_to_the_controller(self) -> None:
        for path in (
            ROOT / "research-toolkit" / "skills" / "kcap" / "SKILL.md",
            ROOT / "research-toolkit" / "skills" / "kcap" / "references" / "runtime-claude.md",
            ROOT / "research-toolkit" / "skills" / "kcap" / "references" / "runtime-codex.md",
        ):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIn('capture "$URL"', text)
                self.assertNotIn("capture [", text)


if __name__ == "__main__":
    unittest.main()
