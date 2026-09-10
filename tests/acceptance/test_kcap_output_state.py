"""Acceptance coverage for KCAP's explicit output and pending-capsule state.

These tests deliberately exercise only the public controller commands.  They
keep extraction and synthesis local so an output-state failure cannot cause
network or model activity during the test.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
KCAP_PATH = ROOT / "research-toolkit" / "skills" / "kcap" / "scripts" / "kcap.py"
URL = "https://example.com/explicit-output"


def load_kcap():
    name = "kcap_output_state_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, KCAP_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KcapOutputStateAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="kcap-output-state-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.project = self.root / "project"
        self.home.mkdir()
        self.project.mkdir()
        self.kcap = load_kcap()

    def invoke(self, *argv: str) -> tuple[int, dict[str, object], dict[str, object]]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                status = self.kcap.main(list(argv))
            except SystemExit as exc:
                status = int(exc.code) if isinstance(exc.code, int) else 2
        return (
            status,
            json.loads(stdout.getvalue()) if stdout.getvalue().lstrip().startswith("{") else {},
            json.loads(stderr.getvalue()) if stderr.getvalue().lstrip().startswith("{") else {},
        )

    def user_config_path(self) -> Path:
        return self.home / ".config" / "robot-tools" / "research-toolkit.json"

    def patch_home(self):
        return patch.object(Path, "home", return_value=self.home)

    def fake_capture_dependencies(self, output_root: Path) -> tuple[Mock, Mock]:
        extract = Mock(side_effect=self._extract)
        synthesize = Mock(side_effect=self._synthesize)
        self.kcap.validate_url = Mock(
            return_value={
                "url": URL,
                "normalized": URL,
                "content_type": "article",
                "hostname": "example.com",
            }
        )
        self.kcap.load_config = Mock(
            return_value=(
                {
                    "output_path": str(output_root),
                    "subfolder": ".",
                    "vault_name": None,
                    "default_tags": [],
                    "default_mode": "standard",
                    "synthesis_profile": "fast",
                },
                "user",
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
        self.kcap.extract_content = extract
        self.kcap.detect_runtime = Mock(return_value=("claude", "test"))
        self.kcap.claude_synthesize = synthesize
        self.kcap.render_markdown = Mock(return_value=("# output state fixture\n", "note.md"))
        return extract, synthesize

    @staticmethod
    def _extract(_url: str, work_dir: Path, _mode: str) -> dict[str, object]:
        content = work_dir / "content.txt"
        metadata = work_dir / "metadata.json"
        content.write_text("fixture", encoding="utf-8")
        metadata.write_text("{}", encoding="utf-8")
        return {
            "content_file": str(content),
            "metadata_file": str(metadata),
            "word_count": 1,
            "original_word_count": 1,
        }

    @staticmethod
    def _synthesize(args: object) -> dict[str, object]:
        output = Path(str(getattr(args, "output_file")))
        output.write_text("{}", encoding="utf-8")
        return {"synthesis_file": str(output), "bytes": 2}

    def write_capsule(
        self,
        target: Path,
        *,
        name: str = "note.md",
        collision: str = "suffix",
        created_at: str | None = None,
        expires_at: str | None = None,
    ) -> Path:
        created = dt.datetime.now(dt.timezone.utc)
        created_at = created_at or created.isoformat().replace("+00:00", "Z")
        expires_at = expires_at or (created + dt.timedelta(days=7)).isoformat().replace("+00:00", "Z")
        capsule = Path(tempfile.gettempdir()) / "kcap-pending-{}".format(uuid.uuid4().hex)
        capsule.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(capsule, ignore_errors=True))
        note = capsule / "note.md"
        note_text = "# validated pending note\n"
        note.write_text(note_text, encoding="utf-8")
        note.chmod(0o600)
        (capsule / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "created_at": created_at,
                    "expires_at": expires_at,
                    "source_normalized": self.kcap.source_identity(
                        "https://example.com/normalized-source"
                    ),
                    "target": {
                        "output_root": str(target),
                        "output_dir": str(target),
                        "filename": name,
                        "collision": collision,
                        "vault_name": None,
                    },
                    "note": {
                        "path": "note.md",
                        "bytes": len(note_text.encode("utf-8")),
                        "sha256": hashlib.sha256(note.read_bytes()).hexdigest(),
                    },
                    "result": {
                        "effective_mode": "standard",
                        "content_type": "article",
                        "warnings": [],
                    },
                }
            ),
            encoding="utf-8",
        )
        (capsule / "manifest.json").chmod(0o600)
        return capsule

    @staticmethod
    def commit_arguments(capsule: Path, target: dict[str, object], capsule_digest: str) -> tuple[str, ...]:
        """Render the narrow, user-visible authority for one pending capsule."""
        return (
            "commit-output",
            str(capsule),
            "--output-root",
            str(target["output_root"]),
            "--output-dir",
            str(target["output_dir"]),
            "--filename",
            str(target["filename"]),
            "--collision",
            str(target["collision"]),
            "--capsule-digest",
            capsule_digest,
        )

    def commit_capsule(self, capsule: Path) -> tuple[int, dict[str, object], dict[str, object]]:
        manifest_bytes = (capsule / "manifest.json").read_bytes()
        note_bytes = (capsule / "note.md").read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        digest = self.kcap.capsule_digest(manifest_bytes, note_bytes)
        return self.invoke(*self.commit_arguments(capsule, manifest["target"], digest))

    def test_defaults_without_capture_output_fail_before_extraction_or_synthesis(self) -> None:
        extract, synthesize = self.fake_capture_dependencies(self.root / "default-output")
        self.kcap.load_config.return_value = (
            dict(self.kcap.DEFAULT_CONFIG),
            "defaults",
            [],
        )

        status, output, error = self.invoke("capture", URL, "--project-dir", str(self.project))

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "output_path_required")
        extract.assert_not_called()
        synthesize.assert_not_called()

    def test_configure_writes_private_schema_v1_user_config_with_exact_output_root(self) -> None:
        output_root = self.root / "vault with spaces"
        with self.patch_home():
            status, output, error = self.invoke("configure", "--output-dir", str(output_root))

        self.assertEqual(status, 0, error)
        self.assertTrue(output["ok"])
        path = self.user_config_path()
        self.assertTrue(path.is_file())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["kcap"]["output_path"], str(output_root))
        self.assertEqual(document["kcap"]["subfolder"], ".")

    def test_configure_preserves_existing_starduster_and_unrelated_valid_settings(self) -> None:
        path = self.user_config_path()
        path.parent.mkdir(parents=True)
        original = {
            "schema_version": 1,
            "starduster": {"output_path": "/existing/starduster"},
            "kcap": {
                "output_path": "/old",
                "subfolder": "old",
                "vault_name": "Existing Vault",
                "default_tags": ["existing-tag"],
                "default_mode": "deep",
                "synthesis_profile": "balanced",
            },
        }
        path.write_text(json.dumps(original), encoding="utf-8")
        path.chmod(0o600)

        with self.patch_home():
            status, _output, error = self.invoke("configure", "--output-dir", str(self.root / "new"))

        self.assertEqual(status, 0, error)
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["starduster"], original["starduster"])
        self.assertEqual(document["kcap"]["output_path"], str(self.root / "new"))
        self.assertEqual(document["kcap"]["subfolder"], ".")
        for field in ("vault_name", "default_tags", "default_mode", "synthesis_profile"):
            self.assertEqual(document["kcap"][field], original["kcap"][field])

    def test_configure_refuses_to_modify_an_environment_selected_config(self) -> None:
        selected = self.root / "selected.json"
        selected.write_text(json.dumps({"schema_version": 1, "kcap": {}}), encoding="utf-8")
        before = selected.read_bytes()

        with self.patch_home(), patch.dict(os.environ, {"RESEARCH_TOOLKIT_CONFIG": str(selected)}):
            status, output, error = self.invoke("configure", "--output-dir", str(self.root / "new"))

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "config_selected")
        self.assertEqual(selected.read_bytes(), before)

    def test_capture_output_dir_overrides_config_without_persisting_the_override(self) -> None:
        configured_root = self.root / "configured"
        requested_root = self.root / "requested"
        config_path = self.root / "config.json"
        config_path.write_text(
            json.dumps({"schema_version": 1, "kcap": {"output_path": str(configured_root), "subfolder": "."}}),
            encoding="utf-8",
        )
        before = config_path.read_bytes()
        self.fake_capture_dependencies(configured_root)

        with patch.dict(os.environ, {"RESEARCH_TOOLKIT_CONFIG": str(config_path)}):
            status, output, error = self.invoke(
                "capture", URL, "--project-dir", str(self.project), "--output-dir", str(requested_root)
            )

        self.assertEqual(status, 0, error)
        self.assertEqual(Path(str(output["output_file"])).parent, requested_root)
        self.assertTrue((requested_root / "note.md").is_file())
        self.assertFalse((configured_root / "note.md").exists())
        self.assertEqual(config_path.read_bytes(), before)

    def test_permission_denied_output_becomes_a_sanitized_pending_capsule(self) -> None:
        output_root = self.root / "denied-output"
        extract, synthesize = self.fake_capture_dependencies(output_root)
        events: list[str] = []
        original_extract = extract.side_effect
        extract.side_effect = lambda *args: (events.append("extract"), original_extract(*args))[1]
        with patch.object(
            self.kcap,
            "preflight_output_destination",
            side_effect=lambda _path: (events.append("preflight"), False)[1],
            create=True,
        ):
            status, output, error = self.invoke(
                "capture", URL, "--project-dir", str(self.project), "--output-dir", str(output_root)
            )

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "write_pending")
        capsule = Path(str(output["pending_directory"]))
        self.assertEqual(sorted(entry.name for entry in capsule.iterdir()), ["manifest.json", "note.md"])
        manifest = json.loads((capsule / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(
            set(manifest),
            {"schema_version", "created_at", "expires_at", "source_normalized", "target", "note", "result"},
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["note"]["path"], "note.md")
        self.assertNotIn(URL, (capsule / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(events, ["preflight", "extract"])
        extract.assert_called_once()
        synthesize.assert_called_once()

    def test_write_pending_returns_a_digest_and_commit_requires_exact_visible_authority(self) -> None:
        destination = self.root / "published"
        self.fake_capture_dependencies(destination)
        with patch.object(self.kcap, "preflight_output_destination", return_value=False):
            status, output, error = self.invoke(
                "capture", URL, "--project-dir", str(self.project), "--output-dir", str(destination)
            )

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "write_pending")
        self.assertIn("capsule_digest", output)
        self.assertRegex(str(output["capsule_digest"]), r"^[0-9a-f]{64}$")
        capsule = Path(str(output["pending_directory"]))
        manifest = json.loads((capsule / "manifest.json").read_text(encoding="utf-8"))
        target = manifest["target"]
        arguments = self.commit_arguments(capsule, target, str(output["capsule_digest"]))

        replacements = {
            "output-root": ("--output-root", str(self.root / "other-root")),
            "output-dir": ("--output-dir", str(self.root / "other-directory")),
            "filename": ("--filename", "other.md"),
            "collision": ("--collision", "replace"),
        }
        for name, (flag, replacement) in replacements.items():
            with self.subTest(authority=name):
                mismatched = list(arguments)
                mismatched[mismatched.index(flag) + 1] = replacement
                commit_status, commit_output, commit_error = self.invoke(*mismatched)
                self.assertEqual(commit_status, 1, commit_error)
                self.assertEqual(commit_output, {})
                self.assertTrue(capsule.exists())
                self.assertFalse((destination / "note.md").exists())

        commit_status, commit_output, commit_error = self.invoke(*arguments)
        self.assertEqual(commit_status, 0, commit_error)
        self.assertEqual(commit_output["status"], "created")
        self.assertFalse(capsule.exists())

    def test_write_pending_digest_is_formed_from_written_bytes_without_reopening_capsule(self) -> None:
        destination = self.root / "published"
        self.fake_capture_dependencies(destination)
        with (
            patch.object(self.kcap, "preflight_output_destination", return_value=False),
            patch.object(
                self.kcap,
                "_open_pending_capsule",
                side_effect=AssertionError("capture must not reopen a mutable capsule to form authority"),
            ),
        ):
            status, output, error = self.invoke(
                "capture", URL, "--project-dir", str(self.project), "--output-dir", str(destination)
            )

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "write_pending")
        self.assertRegex(str(output["capsule_digest"]), r"^[0-9a-f]{64}$")

    def test_commit_requires_the_returned_digest_and_rejects_a_replaced_capsule(self) -> None:
        destination = self.root / "published"
        self.fake_capture_dependencies(destination)
        with patch.object(self.kcap, "preflight_output_destination", return_value=False):
            status, output, error = self.invoke(
                "capture", URL, "--project-dir", str(self.project), "--output-dir", str(destination)
            )

        self.assertEqual(status, 0, error)
        capsule = Path(str(output["pending_directory"]))
        manifest_path = capsule / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertIn("capsule_digest", output)
        digest = str(output["capsule_digest"])
        arguments = self.commit_arguments(capsule, manifest["target"], digest)

        missing_digest = list(arguments)
        digest_index = missing_digest.index("--capsule-digest")
        del missing_digest[digest_index : digest_index + 2]
        for case, commit_arguments in (
            ("missing", missing_digest),
            ("mismatched", [*arguments[:-1], "0" * 64]),
        ):
            with self.subTest(digest=case):
                commit_status, commit_output, commit_error = self.invoke(*commit_arguments)
                self.assertEqual(commit_status, 1, commit_error)
                self.assertEqual(commit_output, {})
                self.assertTrue(capsule.exists())
                self.assertFalse((destination / "note.md").exists())

        injected_warning = "attacker-controlled warning"
        replacement_note = b"# attacker replacement\n"
        (capsule / "note.md").write_bytes(replacement_note)
        manifest["note"]["bytes"] = len(replacement_note)
        manifest["note"]["sha256"] = hashlib.sha256(replacement_note).hexdigest()
        manifest["result"]["warnings"] = [injected_warning]
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        commit_status, commit_output, commit_error = self.invoke(*arguments)
        self.assertEqual(commit_status, 1, commit_error)
        self.assertEqual(commit_output, {})
        self.assertNotIn(injected_warning, json.dumps(commit_error))
        self.assertTrue(capsule.exists())
        self.assertFalse((destination / "note.md").exists())

    def test_pending_replace_authority_names_the_exact_existing_file(self) -> None:
        destination = self.root / "published"
        existing = destination / "nested" / "existing-capture.md"
        existing.parent.mkdir(parents=True)
        existing.write_text("# existing\n", encoding="utf-8")
        self.fake_capture_dependencies(destination)
        self.kcap.find_duplicate = Mock(return_value=[str(existing.resolve())])
        with patch.object(self.kcap, "preflight_output_destination", return_value=False):
            status, output, error = self.invoke(
                "capture",
                URL,
                "--project-dir",
                str(self.project),
                "--output-dir",
                str(destination),
                "--collision",
                "replace",
            )

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "write_pending")
        self.assertEqual(Path(str(output["output_dir"])).resolve(), existing.parent.resolve())
        self.assertEqual(output["filename"], existing.name)

    def test_empty_or_whitespace_output_dir_is_rejected_before_configuration_or_capture(self) -> None:
        for value in ("", "   "):
            with self.subTest(command="configure", value=repr(value)):
                with self.patch_home():
                    status, output, error = self.invoke("configure", "--output-dir", value)
                self.assertEqual(status, 1)
                self.assertEqual(output, {})
                self.assertEqual(error["error"]["code"], "invalid_output_path")
                self.assertFalse(self.user_config_path().exists())

            with self.subTest(command="capture", value=repr(value)):
                extract, synthesize = self.fake_capture_dependencies(self.root / "configured")
                status, output, error = self.invoke(
                    "capture", URL, "--project-dir", str(self.project), "--output-dir", value
                )
                self.assertEqual(status, 1)
                self.assertEqual(output, {})
                self.assertEqual(error["error"]["code"], "invalid_output_path")
                extract.assert_not_called()
                synthesize.assert_not_called()

    def test_vault_uri_is_null_for_an_exact_configured_output_dir_but_legacy_subfolder_is_relative(self) -> None:
        exact_output = self.root / "exact-output"
        self.fake_capture_dependencies(exact_output)
        self.kcap.load_config.return_value = (
            {
                "output_path": str(exact_output),
                "subfolder": ".",
                "vault_name": "Retained Vault",
                "default_tags": [],
                "default_mode": "standard",
                "synthesis_profile": "fast",
            },
            "user",
            [],
        )

        status, output, error = self.invoke("capture", URL, "--project-dir", str(self.project))

        self.assertEqual(status, 0, error)
        self.assertIsNone(output["obsidian_uri"])

        legacy_root = self.root / "legacy-root"
        self.fake_capture_dependencies(legacy_root)
        self.kcap.load_config.return_value = (
            {
                "output_path": str(legacy_root),
                "subfolder": "captures",
                "vault_name": "Legacy Vault",
                "default_tags": [],
                "default_mode": "standard",
                "synthesis_profile": "fast",
            },
            "user",
            [],
        )

        status, output, error = self.invoke("capture", URL, "--project-dir", str(self.project))

        self.assertEqual(status, 0, error)
        self.assertEqual(output["obsidian_uri"], "obsidian://open?vault=Legacy+Vault&file=captures%2Fnote.md")

    def test_pending_source_identity_is_exactly_lowercase_sha256(self) -> None:
        identity = self.kcap.source_identity("https://example.com/normalized-source")
        self.assertEqual(len(identity), 64)
        self.assertEqual(identity, identity.lower())
        self.assertTrue(all(character in "0123456789abcdef" for character in identity))
        self.assertEqual(self.kcap.source_identity(identity), identity)

        capsule = self.write_capsule(self.root / "published")
        manifest_path = capsule / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["source_normalized"] = "not-a-sha256-identity"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with self.assertRaises(self.kcap.KcapError) as failure:
            self.kcap.validate_pending_capsule(capsule)
        self.assertEqual(failure.exception.code, "invalid_pending_capsule")

    def test_non_utf8_pending_note_is_rejected_as_an_invalid_capsule(self) -> None:
        capsule = self.write_capsule(self.root / "published")
        note = capsule / "note.md"
        non_utf8 = b"# invalid\n\xff"
        note.write_bytes(non_utf8)
        manifest_path = capsule / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["note"]["bytes"] = len(non_utf8)
        manifest["note"]["sha256"] = hashlib.sha256(non_utf8).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        try:
            self.kcap.validate_pending_capsule(capsule)
        except self.kcap.KcapError as failure:
            self.assertEqual(failure.code, "invalid_pending_capsule")
        except UnicodeDecodeError as exc:
            self.fail("non-UTF-8 pending note leaked {} instead of invalid_pending_capsule".format(exc))
        else:
            self.fail("non-UTF-8 pending note was accepted")

    def test_partial_pending_capsule_creation_is_removed(self) -> None:
        before = set(Path(tempfile.gettempdir()).glob("kcap-pending-*"))
        original = self.kcap.write_private_bytes
        calls = 0

        def fail_manifest(path: Path, content: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic manifest write failure")
            original(path, content)

        with patch.object(self.kcap, "write_private_bytes", side_effect=fail_manifest):
            with self.assertRaises(self.kcap.KcapError) as failure:
                self.kcap.write_pending_capsule(
                    "# sanitized\n", "example.com/source", self.root, self.root, "note.md",
                    "suffix", None, "standard", "article", [],
                )
        self.assertEqual(failure.exception.code, "output_error")
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("kcap-pending-*")), before)

    def test_commit_output_rejects_unsafe_or_expired_capsules_without_publishing(self) -> None:
        destination = self.root / "published"
        cases = {
            "expired": self.write_capsule(destination, expires_at="2026-08-27T12:00:00Z"),
            "bad-hash": self.write_capsule(destination),
        }
        manifest = json.loads((cases["bad-hash"] / "manifest.json").read_text(encoding="utf-8"))
        manifest["note"]["sha256"] = "0" * 64
        (cases["bad-hash"] / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        external = self.write_capsule(self.root / "outside")
        external_manifest = json.loads((external / "manifest.json").read_text(encoding="utf-8"))
        external_manifest["target"]["output_root"] = str(self.root / "declared-root")
        external_manifest["target"]["output_dir"] = "/etc"
        (external / "manifest.json").write_text(json.dumps(external_manifest), encoding="utf-8")
        cases["outside-target"] = external

        for case, capsule in cases.items():
            with self.subTest(case=case):
                status, output, error = self.commit_capsule(capsule)
                self.assertEqual(status, 1)
                self.assertEqual(output, {})
                self.assertIn(error["error"]["code"], {"invalid_pending_capsule", "expired_pending_capsule"})
                self.assertFalse((destination / "note.md").exists())
                self.assertTrue(capsule.exists())

    def test_commit_output_rejects_a_capsule_outside_the_canonical_temp_root(self) -> None:
        capsule = self.write_capsule(self.root / "published")
        noncanonical = self.root / "not-a-kcap-pending-directory"
        shutil.move(str(capsule), str(noncanonical))

        manifest_bytes = (noncanonical / "manifest.json").read_bytes()
        note_bytes = (noncanonical / "note.md").read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        status, output, error = self.invoke(
            *self.commit_arguments(
                noncanonical,
                manifest["target"],
                self.kcap.capsule_digest(manifest_bytes, note_bytes),
            )
        )

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "invalid_pending_capsule")
        self.assertTrue(noncanonical.exists())

    def test_commit_output_rejects_nonprivate_or_nonregular_capsule_entries(self) -> None:
        destination = self.root / "published"
        cases: dict[str, Path] = {}
        public_manifest = self.write_capsule(destination)
        (public_manifest / "manifest.json").chmod(0o644)
        cases["public-manifest"] = public_manifest
        symlinked_note = self.write_capsule(destination)
        note = symlinked_note / "note.md"
        note.unlink()
        note.symlink_to(self.root / "outside-note.md")
        cases["symlink-note"] = symlinked_note

        for case, capsule in cases.items():
            with self.subTest(case=case):
                if case == "symlink-note":
                    manifest = json.loads((capsule / "manifest.json").read_text(encoding="utf-8"))
                    status, output, error = self.invoke(
                        *self.commit_arguments(capsule, manifest["target"], "0" * 64)
                    )
                else:
                    status, output, error = self.commit_capsule(capsule)
                self.assertEqual(status, 1)
                self.assertEqual(output, {})
                self.assertEqual(error["error"]["code"], "invalid_pending_capsule")
                self.assertTrue(capsule.exists())

    def test_commit_output_rejects_an_unsupported_manifest_schema(self) -> None:
        destination = self.root / "published"
        capsule = self.write_capsule(destination)
        manifest_path = capsule / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema_version"] = 2
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        status, output, error = self.commit_capsule(capsule)

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "invalid_pending_capsule")
        self.assertTrue(capsule.exists())

    def test_commit_output_requires_an_exact_seven_day_expiry(self) -> None:
        capsule = self.write_capsule(
            self.root / "published",
            created_at="2026-09-03T12:00:00Z",
            expires_at="2026-09-11T12:00:00Z",
        )

        status, output, error = self.commit_capsule(capsule)

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "invalid_pending_capsule")
        self.assertTrue(capsule.exists())

    def test_commit_output_publishes_atomically_and_removes_only_a_valid_capsule(self) -> None:
        destination = self.root / "published"
        capsule = self.write_capsule(destination)

        status, output, error = self.commit_capsule(capsule)

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "created")
        self.assertEqual((destination / "note.md").read_text(encoding="utf-8"), "# validated pending note\n")
        self.assertFalse(capsule.exists())

    def test_commit_output_rechecks_suffix_collision_without_overwriting_an_existing_note(self) -> None:
        destination = self.root / "published"
        destination.mkdir()
        existing = destination / "note.md"
        existing.write_text("# existing note\n", encoding="utf-8")
        capsule = self.write_capsule(destination)

        status, output, error = self.commit_capsule(capsule)

        self.assertEqual(status, 0, error)
        self.assertEqual(existing.read_text(encoding="utf-8"), "# existing note\n")
        self.assertEqual((destination / "note-2.md").read_text(encoding="utf-8"), "# validated pending note\n")
        self.assertEqual(Path(str(output["output_file"])).name, "note-2.md")
        self.assertFalse(capsule.exists())

    def test_commit_output_replace_refuses_a_duplicate_moved_after_authorization(self) -> None:
        destination = self.root / "published"
        destination.mkdir()
        identity = self.kcap.source_identity("https://example.com/normalized-source")
        authorized = destination / "authorized.md"
        authorized.write_text(
            "---\nsource_normalized: {}\n---\n# approved target\n".format(identity),
            encoding="utf-8",
        )
        capsule = self.write_capsule(destination, name=authorized.name, collision="replace")
        moved = destination / "moved-after-approval.md"
        authorized.rename(moved)

        status, output, error = self.commit_capsule(capsule)

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "invalid_pending_authority")
        self.assertIn("approved target", moved.read_text(encoding="utf-8"))
        self.assertTrue(capsule.exists())

    def test_atomic_write_rolls_back_if_approved_directory_is_renamed_during_publication(self) -> None:
        destination = self.root / "approved"
        destination.mkdir()
        diverted = self.root / "diverted"
        original_link = self.kcap.os.link
        renamed = False

        def rename_then_link(*args: object, **kwargs: object) -> None:
            nonlocal renamed
            if not renamed:
                destination.rename(diverted)
                destination.mkdir()
                renamed = True
            original_link(*args, **kwargs)

        with patch.object(self.kcap.os, "link", side_effect=rename_then_link):
            with self.assertRaises(self.kcap.KcapError) as failure:
                self.kcap.write_markdown_atomically(
                    "# sanitized pending note\n", "note.md", destination, "suffix"
                )

        self.assertEqual(failure.exception.code, "output_error")
        self.assertEqual(list(destination.iterdir()), [])
        self.assertEqual(list(diverted.iterdir()), [])

    def test_atomic_write_removes_hidden_temporary_note_after_publication_failure(self) -> None:
        destination = self.root / "published"
        destination.mkdir()

        with patch.object(self.kcap.os, "link", side_effect=OSError("synthetic link failure")):
            with self.assertRaises(self.kcap.KcapError) as failure:
                self.kcap.write_markdown_atomically(
                    "# sanitized pending note\n", "note.md", destination, "suffix"
                )

        self.assertEqual(failure.exception.code, "output_error")
        self.assertEqual(list(destination.iterdir()), [])

    def test_commit_output_discards_capsule_after_terminal_duplicate_skip(self) -> None:
        destination = self.root / "published"
        destination.mkdir()
        identity = self.kcap.source_identity("https://example.com/normalized-source")
        (destination / "existing.md").write_text(
            "---\nsource_normalized: {}\n---\n# existing\n".format(identity), encoding="utf-8"
        )
        capsule = self.write_capsule(destination, collision="skip")

        status, output, error = self.commit_capsule(capsule)

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "skipped_duplicate")
        self.assertFalse(capsule.exists())

    def test_commit_output_cleanup_removes_capsules_older_than_seven_days_only(self) -> None:
        destination = self.root / "published"
        expired = self.write_capsule(destination, created_at="2026-08-20T12:00:00Z", expires_at="2026-08-27T12:00:00Z")
        current = self.write_capsule(destination)

        status, output, error = self.commit_capsule(current)

        self.assertEqual(status, 0, error)
        self.assertTrue(expired.exists() is False, "commit-output must remove expired pending capsules")


if __name__ == "__main__":
    unittest.main()
