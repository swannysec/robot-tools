"""RED coverage for Starduster's distinct GitHub-topic and Obsidian-tag fields."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RENDERER = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster_render.py"
CLI = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster.py"
SCHEMA = ROOT / "research-toolkit" / "skills" / "starduster" / "schemas" / "starduster-synthesis.schema.json"
SCRIPTS = RENDERER.parent

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load {}".format(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render = _load_module("starduster_render_tag_semantics", RENDERER)
cli = _load_module("starduster_cli_tag_semantics", CLI)


def _record() -> dict[str, object]:
    return {
        "full_name": "fixture/compliance-toolkit",
        "html_url": "https://github.com/fixture/compliance-toolkit",
        "category": "Cybersecurity",
        "tags": ["compliance", "security-governance", "developer-tools"],
        "summary": "A fixture for testing semantic tag rendering.",
        "key_features": ["Policy automation", "Evidence collection", "Audit reporting"],
        "similar_to": [],
        "use_case": "Use for a compliance automation fixture.",
        "maturity": "active",
        "author_display": "Fixture",
    }


class StardusterTagSemanticsTests(unittest.TestCase):
    def test_synthesis_contract_explicitly_carries_bounded_obsidian_tags(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        properties = schema["items"]["properties"]

        self.assertIn("tags", schema["items"]["required"])
        self.assertNotIn("normalized_topics", properties)
        self.assertEqual(properties["tags"]["type"], "array")
        self.assertEqual(properties["tags"]["minItems"], 1)
        self.assertEqual(properties["tags"]["maxItems"], 5)

    def test_validated_record_keeps_topics_and_semantic_tags_as_separate_fields(self) -> None:
        record = _record()

        validated = render.validate_synthesis_payload([record], ["fixture/compliance-toolkit"])
        sanitized = render._sanitize_record(validated[0])
        frontmatter = render._merge_frontmatter(
            {
                "tags": ["favorite", "old-generated", "starduster"],
                "starduster_tags": ["old-generated"],
            },
            {
                "repo": {
                    "owner": {"login": "fixture"},
                    "topics": ["compliance-as-code", "soc2", "github-actions"],
                }
            },
            sanitized,
        )

        self.assertEqual(frontmatter["topics"], ["compliance-as-code", "soc2", "github-actions"])
        self.assertEqual(frontmatter["starduster_tags"], record["tags"])
        self.assertEqual(frontmatter["tags"][0], "starduster")
        self.assertEqual(set(frontmatter["tags"]), {"starduster", "compliance", "security-governance", "developer-tools", "favorite"})
        self.assertNotIn("old-generated", frontmatter["tags"])
        self.assertNotIn("compliance-as-code", frontmatter["tags"])
        self.assertNotIn("soc2", frontmatter["tags"])

    def test_model_tag_cleanup_drops_generic_and_digit_only_values_without_losing_semantics(self) -> None:
        record = _record()
        record["tags"] = ["video", "1864", "military-history", "summary", "content"]

        validated = render.validate_synthesis_payload([record], ["fixture/compliance-toolkit"])
        sanitized = render._sanitize_record(validated[0])

        self.assertEqual(sanitized["tags"], ["military-history"])

    def test_model_tag_cleanup_rejects_a_record_with_no_usable_discovery_tag(self) -> None:
        record = _record()
        record["tags"] = ["video", "1864", "summary"]

        with self.assertRaisesRegex(
            render.SynthesisValidationError,
            "at least one usable discovery term",
        ):
            render.validate_synthesis_payload([record], ["fixture/compliance-toolkit"])

    def test_prompt_distinguishes_github_topics_from_obsidian_discovery_tags(self) -> None:
        prompt = cli.synthesis_prompt(
            [{"full_name": "fixture/compliance-toolkit", "repo": {}, "readme_text": ""}]
        )

        self.assertIn("GitHub topics", prompt)
        self.assertIn("Obsidian tags", prompt)
        self.assertIn("one to five", prompt.lower())
        self.assertIn("broader", prompt.lower())
        self.assertIn("do not copy the source github topic list wholesale", prompt.lower())
        self.assertIn("may overlap", prompt.lower())
        self.assertIn("repository description and readme content", prompt.lower())


if __name__ == "__main__":
    unittest.main()
