"""RED coverage for Starduster's least-authority catalog publication.

The controller may fetch and synthesize in its private workspace, but it must
not need broad write access to the user's vault.  These tests describe the
small staged-publication handoff used when the destination is unavailable to
the controller sandbox.
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
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
STARDUSTER_PATH = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster.py"
PUBLISH_PATH = ROOT / "research-toolkit" / "skills" / "starduster" / "scripts" / "starduster_publish.py"


def load_starduster():
    name = "starduster_output_state_{}".format(uuid.uuid4().hex)
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


def load_publish():
    name = "starduster_publish_output_state_{}".format(uuid.uuid4().hex)
    spec = importlib.util.spec_from_file_location(name, PUBLISH_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StardusterOutputStateAcceptanceTests(unittest.TestCase):
    """Exercise only public output authority and deliberately small capsules."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="starduster-output-state-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.output_dir = self.root / "vault" / "tools" / "github"
        self.project.mkdir()
        self.starduster = load_starduster()
        self.publish = load_publish()

    def invoke(self, *argv: str) -> tuple[int, dict[str, object], dict[str, object]]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        def capture_emit(value: object, stream: object | None = None) -> None:
            # Starduster's success call omits ``stream``; error paths supply it.
            # This remains correct when redirect_stdout/redirect_stderr swaps the
            # module's live sys streams during an in-process controller test.
            target = stderr if stream is not None else stdout
            json.dump(value, target, ensure_ascii=False, sort_keys=True)
            target.write("\n")

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), patch.object(self.starduster, "emit", side_effect=capture_emit):
            try:
                status = self.starduster.main(list(argv))
            except SystemExit as exc:
                status = int(exc.code) if isinstance(exc.code, int) else 2
        return (
            status,
            json.loads(stdout.getvalue()) if stdout.getvalue().lstrip().startswith("{") else {},
            json.loads(stderr.getvalue()) if stderr.getvalue().lstrip().startswith("{") else {},
        )

    def write_capsule(
        self,
        *,
        created_at: str | None = None,
        expires_at: str | None = None,
        target: Path | None = None,
    ) -> Path:
        """Create the smallest valid future capsule, without raw source inputs."""
        created = dt.datetime.now(dt.timezone.utc)
        created_at = created_at or created.isoformat().replace("+00:00", "Z")
        expires_at = expires_at or (created + dt.timedelta(days=7)).isoformat().replace("+00:00", "Z")
        target = target or self.output_dir
        capsule = Path(tempfile.gettempdir()) / "starduster-pending-{}".format(uuid.uuid4().hex)
        catalog = capsule / "catalog"
        repos = catalog / "repos"
        indexes = catalog / "indexes"
        repos.mkdir(parents=True, mode=0o700)
        indexes.mkdir(mode=0o700)
        for directory in (capsule, catalog, repos, indexes):
            directory.chmod(0o700)
        self.addCleanup(lambda: shutil.rmtree(capsule, ignore_errors=True))
        files = {
            "catalog/repos/fixture-alpha.md": b"---\nfull_name: fixture/alpha\ntags: [starduster]\n---\n# Alpha\n",
            "catalog/indexes/Repositories.base": b"views:\n  - type: table\n",
        }
        entries: list[dict[str, object]] = []
        for relative, content in files.items():
            path = capsule / relative
            path.write_bytes(content)
            path.chmod(0o600)
            entries.append(
                {
                    "path": relative,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "previous_sha256": None,
                }
            )
        manifest = {
            "schema_version": 1,
            "created_at": created_at,
            "expires_at": expires_at,
            "target": {"output_root": str(target), "output_dir": str(target)},
            "catalog": {"root": "catalog", "files": entries, "file_count": len(entries), "total_bytes": sum(item["bytes"] for item in entries)},
            "result": {
                "counts": {"repo_notes": 1, "base_indexes": 1, "category_hubs": 0, "topic_hubs": 0, "author_hubs": 0, "processed": 1, "skipped": 0, "new": 1, "existing": 0, "unstarred": 0, "total_stars": 1},
                "warnings": [],
                "obsidian_uri": None,
            },
        }
        manifest_path = capsule / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest_path.chmod(0o600)
        capsule.chmod(0o700)
        return capsule

    def capsule_digest(self, capsule: Path) -> str:
        manifest_bytes = (capsule / "manifest.json").read_bytes()
        catalog_files = {
            str(path.relative_to(capsule)): path.read_bytes()
            for path in sorted((capsule / "catalog").rglob("*"))
            if path.is_file()
        }
        return self.starduster.catalog_capsule_digest(manifest_bytes, catalog_files)

    def commit_arguments(self, capsule: Path) -> tuple[str, ...]:
        manifest = json.loads((capsule / "manifest.json").read_text(encoding="utf-8"))
        target = manifest["target"]
        return (
            "commit-output",
            str(capsule),
            "--output-root",
            str(target["output_root"]),
            "--output-dir",
            str(target["output_dir"]),
            "--capsule-digest",
            self.capsule_digest(capsule),
        )

    def test_sync_continues_after_destination_denial_and_returns_bounded_pending_authority(self) -> None:
        """A denied vault must not suppress authenticated read-only catalog work."""
        config = {
            "output_path": str(self.root / "vault"),
            "subfolder": "tools/github",
            "vault_name": None,
            "synthesis_profile": "fast",
            "synthesis_batch_size": 25,
        }
        gh = Mock(side_effect=["ok", json.dumps({"resources": {}}), json.dumps({"data": {"viewer": {"starredRepositories": {"totalCount": 0}}}}), "[]"])
        rendered = Mock(return_value={"repo_notes": 0, "skipped": 0, "category_hubs": 0, "topic_hubs": 0, "author_hubs": 0, "base_indexes": 7, "unstarred": 0})
        with (
            patch.object(self.starduster, "load_config", return_value=(config, [])),
            patch.object(self.starduster, "detect_runtime", return_value=("claude", "test")),
            patch.object(self.starduster, "preflight_output_destination", return_value=False, create=True),
            patch.object(self.starduster, "gh", gh),
            patch.object(self.starduster, "rate_preflight"),
            patch.object(self.starduster, "load_existing_identities", return_value={}),
            patch.object(self.starduster, "synthesize", return_value=[]),
            patch.object(self.starduster, "render_catalog", rendered),
        ):
            status, output, error = self.invoke("sync", "--project-dir", str(self.project))

        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "write_pending")
        self.assertEqual(Path(str(output["output_dir"])), self.output_dir)
        self.assertRegex(str(output["capsule_digest"]), r"^[0-9a-f]{64}$")
        self.assertEqual(gh.call_args_list[0].args[0], ["auth", "status"])
        self.assertGreaterEqual(gh.call_count, 4)
        capsule = Path(str(output["pending_directory"]))
        self.assertEqual(sorted(entry.name for entry in capsule.iterdir()), ["catalog", "manifest.json"])

    def test_denied_destination_rejects_unsafe_existing_catalog_before_github_access(self) -> None:
        self.output_dir.mkdir(parents=True)
        (self.output_dir / "raw-readme.txt").write_text("untrusted", encoding="utf-8")
        config = {
            "output_path": str(self.root / "vault"),
            "subfolder": "tools/github",
            "vault_name": None,
            "synthesis_profile": "fast",
            "synthesis_batch_size": 25,
        }
        gh = Mock()
        with (
            patch.object(self.starduster, "load_config", return_value=(config, [])),
            patch.object(self.starduster, "preflight_output_destination", return_value=False),
            patch.object(self.starduster, "gh", gh),
        ):
            status, output, error = self.invoke("sync", "--project-dir", str(self.project))

        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "output_error")
        gh.assert_not_called()

    def test_pending_capsule_contains_only_rendered_catalog_artifacts_and_bounded_manifest(self) -> None:
        capsule = self.write_capsule()
        manifest = json.loads((capsule / "manifest.json").read_text(encoding="utf-8"))
        descendants = sorted(str(path.relative_to(capsule)) for path in capsule.rglob("*") if path.is_file())

        self.assertEqual(descendants, ["catalog/indexes/Repositories.base", "catalog/repos/fixture-alpha.md", "manifest.json"])
        self.assertEqual(set(manifest), {"schema_version", "created_at", "expires_at", "target", "catalog", "result"})
        serialized = json.dumps(manifest)
        # Use unambiguous field names: e.g. ``author_hubs`` is legitimate output
        # metadata and must not be mistaken for an authentication artifact.
        for forbidden in ("raw_readme", "raw_prompt", "auth.json", "access_token", "raw_star", "model_output"):
            self.assertNotIn(forbidden, serialized.lower())
        self.assertEqual(manifest["catalog"]["file_count"], 2)
        self.assertLessEqual(manifest["catalog"]["total_bytes"], 1024 * 1024)

    def test_seed_catalog_snapshot_copies_only_allowed_final_artifacts_without_symlinks(self) -> None:
        source = self.root / "existing-catalog"
        (source / "repos").mkdir(parents=True)
        note = source / "repos" / "fixture-alpha.md"
        note.write_text("# preserved note\n", encoding="utf-8")
        destination = self.root / "private-stage"

        copied = self.publish.seed_catalog_snapshot(source, destination)

        self.assertEqual(copied, {"catalog/repos/fixture-alpha.md": hashlib.sha256(b"# preserved note\n").hexdigest()})
        copied_note = destination / "repos" / "fixture-alpha.md"
        self.assertEqual(copied_note.read_text(encoding="utf-8"), "# preserved note\n")
        self.assertEqual(stat.S_IMODE(copied_note.stat().st_mode), 0o600)
        (source / "raw-synthesis.json").write_text("must not copy", encoding="utf-8")
        with self.assertRaises(self.publish.PublicationError) as failure:
            self.publish.seed_catalog_snapshot(source, self.root / "other-stage")
        self.assertEqual(failure.exception.code, "output_error")

    def test_seed_catalog_snapshot_reads_from_pinned_directories_during_a_path_swap(self) -> None:
        source = self.root / "existing-catalog"
        (source / "repos").mkdir(parents=True)
        (source / "repos" / "fixture.md").write_text("# approved snapshot\n", encoding="utf-8")
        moved = self.root / "moved-approved-catalog"
        original_listdir = self.publish.os.listdir
        calls = 0

        def swap_after_child_listing(path: object):
            nonlocal calls
            names = original_listdir(path)
            calls += 1
            if calls == 2:
                source.rename(moved)
                (source / "repos").mkdir(parents=True)
                (source / "repos" / "fixture.md").write_text("# replacement path\n", encoding="utf-8")
            return names

        destination = self.root / "private-stage"
        with patch.object(self.publish.os, "listdir", side_effect=swap_after_child_listing):
            self.publish.seed_catalog_snapshot(source, destination)

        self.assertEqual(
            (destination / "repos" / "fixture.md").read_text(encoding="utf-8"),
            "# approved snapshot\n",
        )

    def test_pending_catalog_rejects_an_unbounded_result_envelope_before_writing(self) -> None:
        source = self.root / "rendered"
        (source / "repos").mkdir(parents=True)
        (source / "repos" / "fixture-alpha.md").write_text("# rendered\n", encoding="utf-8")
        unsafe_result = {"counts": {}, "warnings": ["safe"], "obsidian_uri": None, "raw_model_output": "must not persist"}

        with self.assertRaises(self.publish.PublicationError) as failure:
            self.publish.write_pending_catalog_capsule(source, self.root, self.output_dir, unsafe_result, {})
        self.assertEqual(failure.exception.code, "output_error")

    def test_commit_output_requires_exact_visible_authority_and_publishes_every_catalog_file(self) -> None:
        capsule = self.write_capsule()
        arguments = self.commit_arguments(capsule)

        mismatch = list(arguments)
        mismatch[mismatch.index("--output-dir") + 1] = str(self.root / "other")
        status, output, error = self.invoke(*mismatch)
        self.assertEqual(status, 1, error)
        self.assertEqual(output, {})
        self.assertTrue(capsule.exists())

        status, output, error = self.invoke(*arguments)
        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "completed")
        self.assertTrue((self.output_dir / "repos" / "fixture-alpha.md").is_file())
        self.assertTrue((self.output_dir / "indexes" / "Repositories.base").is_file())
        self.assertFalse(capsule.exists())

    def test_commit_rejects_tampering_traversal_symlinks_permissions_and_expiry_without_publishing(self) -> None:
        cases: list[tuple[str, Path]] = []
        traversal = self.write_capsule()
        document = json.loads((traversal / "manifest.json").read_text(encoding="utf-8"))
        document["catalog"]["files"][0]["path"] = "catalog/../escape.md"
        (traversal / "manifest.json").write_text(json.dumps(document), encoding="utf-8")
        cases.append(("traversal", traversal))
        symlinked = self.write_capsule()
        note = symlinked / "catalog" / "repos" / "fixture-alpha.md"
        note.unlink()
        note.symlink_to(self.root / "outside.md")
        cases.append(("symlink", symlinked))
        public = self.write_capsule()
        (public / "manifest.json").chmod(0o644)
        cases.append(("public-manifest", public))
        tampered = self.write_capsule()
        (tampered / "catalog" / "repos" / "fixture-alpha.md").write_text("# altered\n", encoding="utf-8")
        cases.append(("tampered", tampered))

        for name, capsule in cases:
            with self.subTest(case=name):
                # A stale digest is intentional for tampering; validation must still be fail-closed.
                args = self.commit_arguments(capsule) if name not in {"symlink", "public-manifest"} else (
                    "commit-output", str(capsule), "--output-root", str(self.output_dir), "--output-dir", str(self.output_dir), "--capsule-digest", "0" * 64,
                )
                status, output, error = self.invoke(*args)
                self.assertEqual(status, 1, error)
                self.assertEqual(output, {})
                self.assertIn(error["error"]["code"], {"invalid_pending_capsule", "expired_pending_capsule"})
                self.assertTrue(capsule.exists())
                self.assertFalse((self.output_dir / "repos" / "fixture-alpha.md").exists())

    def test_commit_rechecks_destination_structure_retains_failed_capsule_and_eventually_allows_retry(self) -> None:
        capsule = self.write_capsule()
        self.output_dir.parent.mkdir(parents=True)
        self.output_dir.symlink_to(self.root / "redirected")

        status, output, error = self.invoke(*self.commit_arguments(capsule))
        self.assertEqual(status, 1, error)
        self.assertEqual(output, {})
        self.assertTrue(capsule.exists())
        self.assertEqual(error["error"]["code"], "output_error")

        self.output_dir.unlink()
        status, output, error = self.invoke(*self.commit_arguments(capsule))
        self.assertEqual(status, 0, error)
        self.assertEqual(output["status"], "completed")
        self.assertFalse(capsule.exists())

    def test_successful_retry_is_idempotent_and_expired_capsules_are_cleaned(self) -> None:
        capsule = self.write_capsule()
        arguments = self.commit_arguments(capsule)
        first_status, first_output, first_error = self.invoke(*arguments)
        self.assertEqual(first_status, 0, first_error)
        self.assertEqual(first_output["status"], "completed")
        self.assertFalse(capsule.exists())

        # Replaying a deleted authority cannot republish or overwrite catalog state.
        second_status, second_output, second_error = self.invoke(*arguments)
        self.assertEqual(second_status, 1, second_error)
        self.assertEqual(second_output, {})
        self.assertEqual((self.output_dir / "repos" / "fixture-alpha.md").read_text(encoding="utf-8"), "---\nfull_name: fixture/alpha\ntags: [starduster]\n---\n# Alpha\n")

        expired_created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=8)
        expired = self.write_capsule(
            created_at=expired_created.isoformat().replace("+00:00", "Z"),
            expires_at=(expired_created + dt.timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        )
        current = self.write_capsule()
        status, _output, error = self.invoke(*self.commit_arguments(current))
        self.assertEqual(status, 0, error)
        self.assertTrue(expired.exists(), "commit-output must not sweep unrelated same-prefix paths")
        self.publish.sweep_expired_pending_catalogs()
        self.assertFalse(expired.exists(), "an explicit sweep removes only fully validated expired capsules")

    def test_pending_commit_preserves_files_created_or_edited_after_snapshot(self) -> None:
        self.output_dir.mkdir(parents=True)
        existing = self.output_dir / "repos" / "fixture-alpha.md"
        existing.parent.mkdir()
        existing.write_text("# original user state\n", encoding="utf-8")
        stage = self.root / "stage"
        prior_state = self.publish.seed_catalog_snapshot(self.output_dir, stage)
        (stage / "repos" / "fixture-alpha.md").write_text("# rendered update\n", encoding="utf-8")
        (stage / "topics").mkdir()
        (stage / "topics" / "new-topic.md").write_text("# desired topic\n", encoding="utf-8")
        result = {
            "counts": {key: 0 for key in self.publish._COUNT_KEYS},
            "warnings": [],
            "obsidian_uri": None,
        }
        capsule, digest = self.publish.write_pending_catalog_capsule(
            stage, self.root / "vault", self.output_dir, result, prior_state
        )
        existing.write_text("# user edited during synthesis\n", encoding="utf-8")
        created = self.output_dir / "topics" / "new-topic.md"
        created.parent.mkdir()
        created.write_text("# user-created topic\n", encoding="utf-8")

        with self.assertRaises(self.publish.PublicationError) as failure:
            self.publish.commit_catalog_output(
                str(capsule), str(self.root / "vault"), str(self.output_dir), digest
            )

        self.assertEqual(failure.exception.code, "output_conflict")
        self.assertEqual(existing.read_text(encoding="utf-8"), "# user edited during synthesis\n")
        self.assertEqual(created.read_text(encoding="utf-8"), "# user-created topic\n")
        self.assertTrue(capsule.exists())

    def test_partial_publication_retry_accepts_desired_bytes_without_overwriting_new_state(self) -> None:
        stage = self.root / "stage"
        prior_state = self.publish.seed_catalog_snapshot(self.output_dir, stage)
        for directory, filename in (("repos", "fixture-alpha.md"), ("topics", "fixture.md")):
            (stage / directory).mkdir(exist_ok=True)
            (stage / directory / filename).write_text("# desired {}\n".format(directory), encoding="utf-8")
        result = {
            "counts": {key: 0 for key in self.publish._COUNT_KEYS},
            "warnings": [],
            "obsidian_uri": None,
        }
        capsule, digest = self.publish.write_pending_catalog_capsule(
            stage, self.root / "vault", self.output_dir, result, prior_state
        )
        original = self.publish._write_atomic
        calls = 0

        def fail_second(*args: object, **kwargs: object):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise self.publish.PublicationError("output_error", "synthetic second-file failure")
            return original(*args, **kwargs)

        with patch.object(self.publish, "_write_atomic", side_effect=fail_second):
            with self.assertRaises(self.publish.PublicationError):
                self.publish.commit_catalog_output(
                    str(capsule), str(self.root / "vault"), str(self.output_dir), digest
                )
        self.assertTrue(capsule.exists())

        result = self.publish.commit_catalog_output(
            str(capsule), str(self.root / "vault"), str(self.output_dir), digest
        )
        self.assertEqual(result["status"], "completed")
        self.assertFalse(capsule.exists())
        self.assertEqual((self.output_dir / "repos" / "fixture-alpha.md").read_text(encoding="utf-8"), "# desired repos\n")
        self.assertEqual((self.output_dir / "topics" / "fixture.md").read_text(encoding="utf-8"), "# desired topics\n")

    def test_expired_sweep_preserves_decoys_and_selected_valid_expired_capsule_is_removed(self) -> None:
        decoy = Path(tempfile.gettempdir()) / "starduster-pending-decoy-{}".format(uuid.uuid4().hex)
        decoy.mkdir(mode=0o700)
        decoy.chmod(0o700)
        self.addCleanup(lambda: shutil.rmtree(decoy, ignore_errors=True))
        (decoy / "manifest.json").write_text(json.dumps({"expires_at": "2020-01-01T00:00:00Z"}), encoding="utf-8")
        (decoy / "manifest.json").chmod(0o600)
        self.publish.sweep_expired_pending_catalogs()
        self.assertTrue(decoy.exists(), "same-prefix directories are not deletion authority")

        created = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=8)
        capsule = self.write_capsule(
            created_at=created.isoformat().replace("+00:00", "Z"),
            expires_at=(created + dt.timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        )
        arguments = self.commit_arguments(capsule)
        status, output, error = self.invoke(*arguments)
        self.assertEqual(status, 1)
        self.assertEqual(output, {})
        self.assertEqual(error["error"]["code"], "expired_pending_capsule")
        self.assertFalse(capsule.exists(), "a fully validated selected expired capsule is safely removed")

    def test_interrupted_pending_capsule_creation_removes_partial_private_state(self) -> None:
        stage = self.root / "stage"
        prior_state = self.publish.seed_catalog_snapshot(self.output_dir, stage)
        (stage / "repos").mkdir()
        (stage / "repos" / "fixture.md").write_text("# rendered\n", encoding="utf-8")
        result = {
            "counts": {key: 0 for key in self.publish._COUNT_KEYS},
            "warnings": [],
            "obsidian_uri": None,
        }
        before = set(self.publish.pending_root().glob("starduster-pending-*"))
        original = self.publish._write_private
        calls = 0

        def interrupt_manifest(path: Path, content: bytes) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise KeyboardInterrupt
            original(path, content)

        with patch.object(self.publish, "_write_private", side_effect=interrupt_manifest):
            with self.assertRaises(KeyboardInterrupt):
                self.publish.write_pending_catalog_capsule(
                    stage, self.root / "vault", self.output_dir, result, prior_state
                )
        self.assertEqual(set(self.publish.pending_root().glob("starduster-pending-*")), before)

    def test_manifest_limit_can_represent_the_maximum_allowed_catalog(self) -> None:
        minimum_worst_case = self.publish.MAX_FILES * (self.publish.MAX_PATH_BYTES + 160)
        self.assertGreaterEqual(self.publish.MAX_MANIFEST_BYTES, minimum_worst_case)


if __name__ == "__main__":
    unittest.main()
