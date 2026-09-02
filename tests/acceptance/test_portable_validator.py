"""Regression coverage for portable-skill package-boundary validation."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = (
    ROOT
    / "workflow-toolkit"
    / "skills"
    / "plugin-qa"
    / "scripts"
    / "validate-portable-skill.py"
)
FIXTURES = ROOT / "tests" / "fixtures" / "portable-skills"


class PortableValidatorAcceptanceTests(unittest.TestCase):
    def validate(self, skill_dir: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        process = subprocess.run(
            [sys.executable, str(VALIDATOR), str(skill_dir), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        return process, json.loads(process.stdout)

    @staticmethod
    def package_boundary(report: dict[str, object]) -> dict[str, str]:
        checks = report["checks"]
        assert isinstance(checks, list)
        for check in checks:
            if isinstance(check, dict) and check.get("id") == "dependencies.package-boundary":
                return {"status": str(check["status"]), "message": str(check["message"])}
        raise AssertionError("portable validator did not report package-boundary validation")

    def test_rejects_posix_windows_and_unc_absolute_runtime_dependencies(self) -> None:
        process, report = self.validate(FIXTURES / "runtime-absolute-paths")

        self.assertEqual(process.returncode, 1, process.stderr)
        boundary = self.package_boundary(report)
        self.assertEqual(boundary["status"], "fail")
        for path in (
            "/opt/portable-fixture/tool.py",
            "/private/tmp/portable-fixture/token.txt",
            "/Applications/Unrelated.app/Contents/Resources/helper",
            r"C:\portable-fixture\tool.py",
            r"\\fileserver\portable-fixture\tool.py",
        ):
            self.assertIn(path, boundary["message"])

    def test_allows_the_documented_bundled_desktop_executable_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="portable-validator-") as temporary:
            skill_dir = Path(temporary) / "valid"
            shutil.copytree(FIXTURES / "valid", skill_dir)
            scripts = skill_dir / "scripts"
            scripts.mkdir()
            (scripts / "host.py").write_text(
                'BUNDLED_HOST = "/Applications/ChatGPT.app/Contents/Resources/codex"\n',
                encoding="utf-8",
            )

            process, report = self.validate(skill_dir)

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.package_boundary(report)["status"], "pass")

    def test_rejects_symlinked_runtime_asset_outside_the_skill_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="portable-validator-") as temporary:
            temporary_root = Path(temporary)
            skill_dir = temporary_root / "symlink-runtime-asset"
            shutil.copytree(FIXTURES / "valid", skill_dir)
            skill_file = skill_dir / "SKILL.md"
            skill_file.write_text(
                skill_file.read_text(encoding="utf-8")
                .replace("name: valid", "name: symlink-runtime-asset")
                .replace("$valid", "$symlink-runtime-asset"),
                encoding="utf-8",
            )
            outside = temporary_root / "outside-runtime.py"
            outside.write_text("print('outside')\n", encoding="utf-8")
            scripts = skill_dir / "scripts"
            scripts.mkdir()
            (scripts / "run.py").symlink_to(outside)

            process, report = self.validate(skill_dir)

        self.assertEqual(process.returncode, 1, process.stderr)
        boundary = self.package_boundary(report)
        self.assertEqual(boundary["status"], "fail")
        self.assertIn("scripts/run.py", boundary["message"])

    def test_valid_fixture_keeps_urls_prose_slashes_and_package_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="portable-validator-") as temporary:
            skill_dir = Path(temporary) / "valid"
            shutil.copytree(FIXTURES / "valid", skill_dir)
            skill_file = skill_dir / "SKILL.md"
            skill_file.write_text(
                skill_file.read_text(encoding="utf-8")
                + "\nSee https://example.com/portable-skill and input/output guidance.\n",
                encoding="utf-8",
            )
            process, report = self.validate(skill_dir)

        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.package_boundary(report)["status"], "pass")


if __name__ == "__main__":
    unittest.main()
