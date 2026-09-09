"""Least-authority publication for a rendered Starduster catalog.

This module deliberately has no GitHub, model, subprocess, or network code.
It moves a small, validated tree of already-rendered Markdown and Base files
from a private temporary capsule into a user-approved catalog directory.
"""

from __future__ import annotations

import datetime as dt
import errno
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence


PENDING_PREFIX = "starduster-pending-"
MANIFEST_KEYS = {"schema_version", "created_at", "expires_at", "target", "catalog", "result"}
CATALOG_DIRECTORIES = {"repos", "indexes", "categories", "topics", "authors"}
MAX_FILES = 10_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 240
MAX_WARNINGS = 100
MAX_WARNING_BYTES = 512
MAX_URI_BYTES = 2048
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COUNT_KEYS = {
    "total_stars", "new", "existing", "unstarred", "processed", "skipped",
    "repo_notes", "category_hubs", "topic_hubs", "author_hubs", "base_indexes",
}


class PublicationError(Exception):
    """A safe, controller-ready error without source or rendered content."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _fail(code: str, message: str) -> None:
    raise PublicationError(code, message)


def pending_root() -> Path:
    return Path(tempfile.gettempdir()).resolve()


def _canonical_absolute(path: Path) -> Path:
    """Use macOS's real root spelling before descriptor-by-component traversal."""
    if not path.is_absolute():
        _fail("output_error", "Output directory must be absolute")
    parts = path.parts
    if len(parts) > 1 and parts[1] == "var":
        return Path("/private").joinpath(*parts[1:])
    return path


def _utc(value: str, code: str = "invalid_pending_capsule") -> dt.datetime:
    if not isinstance(value, str):
        _fail(code, "Pending capsule timestamps must be UTC strings")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail(code, "Pending capsule timestamp is invalid")
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        _fail(code, "Pending capsule timestamps must be UTC")
    return parsed.astimezone(dt.timezone.utc)


def _read_private_at(directory_fd: int, name: str, max_bytes: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            _fail("invalid_pending_capsule", "Pending capsule contains an unsafe file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(content) > max_bytes or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            _fail("invalid_pending_capsule", "Pending capsule file changed during validation")
        return content
    except PublicationError:
        raise
    except OSError:
        _fail("invalid_pending_capsule", "Pending capsule file could not be opened safely")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_private_directory_at(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            _fail("invalid_pending_capsule", "Pending capsule directory is not private")
        return descriptor
    except PublicationError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        _fail("invalid_pending_capsule", "Pending capsule directory could not be opened safely")


def _normal_catalog_relative(value: object) -> tuple[str, str, str]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_PATH_BYTES:
        _fail("invalid_pending_capsule", "Pending catalog path is invalid")
    path = Path(value)
    parts = path.parts
    if len(parts) != 3 or parts[0] != "catalog" or parts[1] not in CATALOG_DIRECTORIES:
        _fail("invalid_pending_capsule", "Pending catalog path is outside the catalog tree")
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        _fail("invalid_pending_capsule", "Pending catalog path contains unsafe components")
    filename = parts[2]
    if Path(filename).name != filename:
        _fail("invalid_pending_capsule", "Pending catalog filename is unsafe")
    if parts[1] == "indexes":
        allowed = filename.endswith(".base")
    else:
        allowed = filename.endswith(".md")
    if not allowed:
        _fail("invalid_pending_capsule", "Pending catalog file type is not allowed")
    return parts[0], parts[1], filename


def _open_existing_directory(path: Path, error_code: str = "output_error") -> int:
    """Traverse an existing absolute directory one pinned component at a time."""
    absolute = _canonical_absolute(path.absolute())
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if not directory_flag or not nofollow_flag:
        _fail(error_code, "The platform cannot safely open catalog directories")
    flags = os.O_RDONLY | directory_flag | nofollow_flag
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for component in absolute.parts[1:]:
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        _fail(error_code, "Catalog directory could not be opened safely")


def _read_source_at(directory_fd: int, filename: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(filename, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
            _fail("output_error", "Rendered catalog contains an unsafe file")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if len(content) > MAX_FILE_BYTES or (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
            _fail("output_error", "Rendered catalog file changed while it was being staged")
        return content
    except PublicationError:
        raise
    except OSError:
        _fail("output_error", "Rendered catalog file could not be read safely")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _catalog_files(source: Path) -> list[tuple[str, bytes]]:
    source_fd = _open_existing_directory(source)
    child_fd = -1
    files: list[tuple[str, bytes]] = []
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        for directory in sorted(os.listdir(source_fd)):
            if directory not in CATALOG_DIRECTORIES:
                _fail("output_error", "Rendered catalog has an unexpected directory")
            try:
                child_fd = os.open(directory, flags, dir_fd=source_fd)
            except OSError:
                _fail("output_error", "Rendered catalog contains an unsafe directory")
            for filename in sorted(os.listdir(child_fd)):
                relative = "catalog/{}/{}".format(directory, filename)
                _normal_catalog_relative(relative)
                files.append((relative, _read_source_at(child_fd, filename)))
                if len(files) > MAX_FILES:
                    _fail("output_error", "Rendered catalog has too many files")
            os.close(child_fd)
            child_fd = -1
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        os.close(source_fd)
    total = sum(len(content) for _relative, content in files)
    if total > MAX_TOTAL_BYTES:
        _fail("output_error", "Rendered catalog exceeds the publication size limit")
    return files


def seed_catalog_snapshot(source: Path, destination: Path) -> dict[str, str]:
    """Safely seed a private render directory from an existing catalog.

    An absent source is an empty catalog.  A present source must contain only
    Starduster's five direct directories and allowed regular final artifacts.
    The destination must be absent or an empty private directory; the function
    never follows a source symlink or copies hidden/raw workspace artifacts.
    """
    source = Path(source)
    destination = Path(destination)
    try:
        if source.is_symlink():
            _fail("output_error", "Rendered catalog directory is unsafe")
        if source.exists():
            files = _catalog_files(source)
        else:
            files = []
        if destination.exists():
            metadata = destination.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or any(destination.iterdir()):
                _fail("output_error", "Private catalog staging directory is unsafe")
        else:
            destination.mkdir(mode=0o700, parents=True)
        destination.chmod(0o700)
        copied: dict[str, str] = {}
        for relative, content in files:
            _prefix, directory, filename = _normal_catalog_relative(relative)
            child = destination / directory
            if not child.exists():
                child.mkdir(mode=0o700)
            child.chmod(0o700)
            _write_private(child / filename, content)
            copied[relative] = hashlib.sha256(content).hexdigest()
        return copied
    except PublicationError:
        raise
    except OSError:
        _fail("output_error", "Could not seed the private catalog staging directory")


def validate_catalog_snapshot(source: Path) -> None:
    """Validate an existing catalog before retrieval without retaining its contents."""
    source = Path(source)
    try:
        if source.is_symlink():
            _fail("output_error", "Rendered catalog directory is unsafe")
        if source.exists():
            _catalog_files(source)
    except PublicationError:
        raise
    except OSError:
        _fail("output_error", "Rendered catalog could not be inspected safely")


def catalog_capsule_digest(manifest_bytes: bytes, catalog_files: Mapping[str, bytes]) -> str:
    """Bind exact manifest and catalog bytes to a narrow one-time authority."""
    if not isinstance(manifest_bytes, bytes) or not isinstance(catalog_files, Mapping):
        _fail("invalid_pending_capsule", "Pending catalog digest input is invalid")
    digest = hashlib.sha256()
    digest.update(b"starduster.pending-catalog.digest.v1\x00")
    digest.update(len(manifest_bytes).to_bytes(8, "big"))
    digest.update(manifest_bytes)
    for relative in sorted(catalog_files):
        _normal_catalog_relative(relative)
        content = catalog_files[relative]
        if not isinstance(content, bytes):
            _fail("invalid_pending_capsule", "Pending catalog digest input is invalid")
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _write_private(path: Path, content: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        _fail("output_error", "Could not create the pending output capsule")


def write_pending_catalog_capsule(
    rendered_catalog: Path,
    output_root: Path,
    output_dir: Path,
    result: Mapping[str, Any],
    prior_state: Mapping[str, str],
) -> tuple[Path, str]:
    """Copy only validated final artifacts into a private seven-day capsule."""
    if not output_root.is_absolute() or not output_dir.is_absolute():
        _fail("output_error", "Pending catalog targets must be absolute")
    try:
        output_dir.resolve(strict=False).relative_to(output_root.resolve(strict=False))
    except ValueError:
        _fail("output_error", "Pending catalog output directory is outside its root")
    files = _catalog_files(Path(rendered_catalog))
    if not isinstance(result, Mapping):
        _fail("output_error", "Pending catalog result is invalid")
    try:
        _validate_result(result)
    except PublicationError:
        _fail("output_error", "Pending catalog result is invalid")
    if not isinstance(prior_state, Mapping):
        _fail("output_error", "Pending catalog prior state is invalid")
    for relative, digest in prior_state.items():
        try:
            _normal_catalog_relative(relative)
        except PublicationError:
            _fail("output_error", "Pending catalog prior state is invalid")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            _fail("output_error", "Pending catalog prior state is invalid")
    now = dt.datetime.now(dt.timezone.utc)
    capsule = Path(tempfile.mkdtemp(prefix=PENDING_PREFIX)).resolve()
    try:
        os.chmod(str(capsule), 0o700)
        catalog = capsule / "catalog"
        catalog.mkdir(mode=0o700)
        entries: list[dict[str, Any]] = []
        for relative, content in files:
            _prefix, directory, filename = _normal_catalog_relative(relative)
            target_directory = catalog / directory
            if not target_directory.exists():
                target_directory.mkdir(mode=0o700)
                target_directory.chmod(0o700)
            target = target_directory / filename
            _write_private(target, content)
            entries.append(
                {
                    "path": relative,
                    "bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "previous_sha256": prior_state.get(relative),
                }
            )
        manifest = {
            "schema_version": 1,
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + dt.timedelta(days=7)).isoformat().replace("+00:00", "Z"),
            "target": {"output_root": str(output_root), "output_dir": str(output_dir)},
            "catalog": {
                "root": "catalog", "files": entries, "file_count": len(entries),
                "total_bytes": sum(len(content) for _relative, content in files),
            },
            "result": dict(result),
        }
        manifest_bytes = (json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            _fail("output_error", "Pending catalog manifest exceeds the publication limit")
        _write_private(capsule / "manifest.json", manifest_bytes)
        return capsule, catalog_capsule_digest(manifest_bytes, {relative: content for relative, content in files})
    except (KeyboardInterrupt, SystemExit):
        shutil.rmtree(str(capsule), ignore_errors=True)
        raise
    except PublicationError:
        shutil.rmtree(str(capsule), ignore_errors=True)
        raise
    except BaseException:
        shutil.rmtree(str(capsule), ignore_errors=True)
        _fail("output_error", "Could not create the pending output capsule")


def _catalog_manifest_entries(catalog: Mapping[str, Any]) -> list[dict[str, Any]]:
    if set(catalog) != {"root", "files", "file_count", "total_bytes"} or catalog.get("root") != "catalog":
        _fail("invalid_pending_capsule", "Pending catalog manifest fields are invalid")
    entries = catalog.get("files")
    if not isinstance(entries, list) or not isinstance(catalog.get("file_count"), int) or not isinstance(catalog.get("total_bytes"), int):
        _fail("invalid_pending_capsule", "Pending catalog manifest fields are invalid")
    if len(entries) > MAX_FILES or catalog["file_count"] != len(entries) or catalog["total_bytes"] < 0 or catalog["total_bytes"] > MAX_TOTAL_BYTES:
        _fail("invalid_pending_capsule", "Pending catalog manifest exceeds publication limits")
    validated: list[dict[str, Any]] = []
    paths: set[str] = set()
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256", "previous_sha256"}:
            _fail("invalid_pending_capsule", "Pending catalog entry is invalid")
        relative = entry.get("path")
        _normal_catalog_relative(relative)
        previous = entry.get("previous_sha256")
        if relative in paths or not isinstance(entry.get("bytes"), int) or entry["bytes"] < 0 or entry["bytes"] > MAX_FILE_BYTES or not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"]) or (previous is not None and (not isinstance(previous, str) or not _SHA256.fullmatch(previous))):
            _fail("invalid_pending_capsule", "Pending catalog entry is invalid")
        paths.add(relative)
        total += entry["bytes"]
        validated.append(dict(entry))
    if total != catalog["total_bytes"] or total > MAX_TOTAL_BYTES:
        _fail("invalid_pending_capsule", "Pending catalog total does not match")
    return validated


def _validate_result(result: Mapping[str, Any]) -> None:
    if set(result) != {"counts", "warnings", "obsidian_uri"}:
        _fail("invalid_pending_capsule", "Pending catalog result fields are invalid")
    counts, warnings, uri = result.get("counts"), result.get("warnings"), result.get("obsidian_uri")
    if not isinstance(counts, dict) or set(counts) != _COUNT_KEYS:
        _fail("invalid_pending_capsule", "Pending catalog result counts are invalid")
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_FILES for value in counts.values()):
        _fail("invalid_pending_capsule", "Pending catalog result counts are invalid")
    if not isinstance(warnings, list) or len(warnings) > MAX_WARNINGS or any(not isinstance(item, str) or len(item.encode("utf-8")) > MAX_WARNING_BYTES for item in warnings):
        _fail("invalid_pending_capsule", "Pending catalog warnings are invalid")
    if uri is not None and (not isinstance(uri, str) or len(uri.encode("utf-8")) > MAX_URI_BYTES):
        _fail("invalid_pending_capsule", "Pending catalog URI is invalid")


def _read_validated_catalog(capsule_fd: int, entries: Sequence[Mapping[str, Any]]) -> dict[str, bytes]:
    expected = {str(entry["path"]) for entry in entries}
    actual: set[str] = set()
    contents: dict[str, bytes] = {}
    catalog_fd = _open_private_directory_at(capsule_fd, "catalog")
    child_fd = -1
    try:
        directories = sorted(os.listdir(catalog_fd))
        if any(directory not in CATALOG_DIRECTORIES for directory in directories):
            _fail("invalid_pending_capsule", "Pending catalog contains an unexpected directory")
        for directory in directories:
            child_fd = _open_private_directory_at(catalog_fd, directory)
            for filename in sorted(os.listdir(child_fd)):
                relative = "catalog/{}/{}".format(directory, filename)
                _normal_catalog_relative(relative)
                content = _read_private_at(child_fd, filename, MAX_FILE_BYTES)
                actual.add(relative)
                contents[relative] = content
            os.close(child_fd)
            child_fd = -1
        if actual != expected:
            _fail("invalid_pending_capsule", "Pending catalog files do not match its manifest")
        for entry in entries:
            content = contents[str(entry["path"])]
            if len(content) != entry["bytes"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
                _fail("invalid_pending_capsule", "Pending catalog file hash does not match")
        return contents
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        os.close(catalog_fd)


def _open_pending_capsule(path: Path) -> tuple[Path, int, int]:
    raw = Path(path)
    if not raw.is_absolute() or not raw.name.startswith(PENDING_PREFIX):
        _fail("invalid_pending_capsule", "Pending capsule is outside the canonical temporary directory")
    try:
        parent = raw.parent.resolve(strict=False)
    except OSError:
        _fail("invalid_pending_capsule", "Pending capsule path is invalid")
    if parent != pending_root():
        _fail("invalid_pending_capsule", "Pending capsule is outside the canonical temporary directory")
    root_fd = _open_existing_directory(pending_root(), "invalid_pending_capsule")
    capsule_fd = -1
    try:
        capsule_fd = _open_private_directory_at(root_fd, raw.name)
        named = os.stat(raw.name, dir_fd=root_fd, follow_symlinks=False)
        pinned = os.fstat(capsule_fd)
        if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
            _fail("invalid_pending_capsule", "Pending capsule changed while it was opened")
        return parent / raw.name, root_fd, capsule_fd
    except BaseException:
        if capsule_fd >= 0:
            os.close(capsule_fd)
        os.close(root_fd)
        raise


def _validate_opened_capsule(
    capsule_fd: int, *, allow_expired: bool
) -> tuple[dict[str, Any], dict[str, bytes], str, bool]:
    try:
        names = sorted(os.listdir(capsule_fd))
    except OSError:
        _fail("invalid_pending_capsule", "Pending capsule could not be listed")
    if names != ["catalog", "manifest.json"]:
        _fail("invalid_pending_capsule", "Pending capsule must contain only catalog and manifest")
    try:
        manifest_bytes = _read_private_at(capsule_fd, "manifest.json", MAX_MANIFEST_BYTES)
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (PublicationError, OSError, UnicodeError, json.JSONDecodeError):
        _fail("invalid_pending_capsule", "Pending capsule manifest is unreadable")
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS or manifest.get("schema_version") != 1:
        _fail("invalid_pending_capsule", "Pending capsule manifest has an unsupported schema")
    created, expires = _utc(manifest.get("created_at")), _utc(manifest.get("expires_at"))
    if expires - created != dt.timedelta(days=7):
        _fail("invalid_pending_capsule", "Pending capsule expiry is invalid")
    target, catalog, result = manifest.get("target"), manifest.get("catalog"), manifest.get("result")
    if not isinstance(target, dict) or set(target) != {"output_root", "output_dir"} or not isinstance(catalog, dict) or not isinstance(result, dict):
        _fail("invalid_pending_capsule", "Pending capsule manifest fields are invalid")
    root_value, output_value = target.get("output_root"), target.get("output_dir")
    if not isinstance(root_value, str) or not isinstance(output_value, str) or not Path(root_value).is_absolute() or not Path(output_value).is_absolute():
        _fail("invalid_pending_capsule", "Pending capsule targets must be absolute")
    try:
        _canonical_absolute(Path(output_value)).resolve(strict=False).relative_to(
            _canonical_absolute(Path(root_value)).resolve(strict=False)
        )
    except ValueError:
        _fail("invalid_pending_capsule", "Pending capsule output directory is outside its root")
    entries = _catalog_manifest_entries(catalog)
    _validate_result(result)
    contents = _read_validated_catalog(capsule_fd, entries)
    digest = catalog_capsule_digest(manifest_bytes, contents)
    expired = dt.datetime.now(dt.timezone.utc) >= expires
    if expired and not allow_expired:
        _fail("expired_pending_capsule", "Pending capsule has expired")
    return manifest, contents, digest, expired


def validate_catalog_capsule(path: Path, *, allow_expired: bool = False) -> tuple[Path, dict[str, Any], dict[str, bytes], str]:
    """Validate a pinned-shape capsule before a privileged publication step."""
    capsule, root_fd, capsule_fd = _open_pending_capsule(Path(path))
    try:
        manifest, contents, digest, _expired = _validate_opened_capsule(
            capsule_fd, allow_expired=allow_expired
        )
        return capsule, manifest, contents, digest
    finally:
        os.close(capsule_fd)
        os.close(root_fd)


def _secure_directory(path: Path) -> int:
    path = _canonical_absolute(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if not getattr(os, "O_DIRECTORY", 0) or not getattr(os, "O_NOFOLLOW", 0):
        _fail("output_error", "The platform cannot safely open output directories")
    descriptor = -1
    try:
        descriptor = os.open("/", flags)
        for component in path.parts[1:]:
            try:
                os.mkdir(component, 0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        if exc.errno in {errno.EACCES, errno.EPERM}:
            raise
        _fail("output_error", "Could not safely prepare the output directory")


def preflight_output_destination(output_dir: Path) -> bool:
    """Probe a destination. Permission denial is the only pending-state signal."""
    descriptor = -1
    probe = ".starduster-probe-{}".format(uuid.uuid4().hex)
    try:
        descriptor = _secure_directory(Path(output_dir))
        handle = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=descriptor)
        os.close(handle)
        os.unlink(probe, dir_fd=descriptor)
        return True
    except OSError as exc:
        if exc.errno in {errno.EACCES, errno.EPERM}:
            return False
        _fail("output_error", "Could not safely prepare the output directory")
    finally:
        if descriptor >= 0:
            try:
                os.unlink(probe, dir_fd=descriptor)
            except OSError:
                pass
            os.close(descriptor)


def _output_matches(descriptor: int, path: Path) -> bool:
    try:
        pinned = os.fstat(descriptor)
        named = os.stat(str(_canonical_absolute(path)), follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(named.st_mode) and (pinned.st_dev, pinned.st_ino) == (named.st_dev, named.st_ino)


def _target_hash(directory_fd: int, filename: str) -> str | None:
    descriptor = -1
    try:
        descriptor = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        _fail("output_conflict", "Catalog destination changed after rendering")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
            _fail("output_conflict", "Catalog destination changed after rendering")
        digest = hashlib.sha256()
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if remaining == 0 or (metadata.st_dev, metadata.st_ino, metadata.st_size) != (after.st_dev, after.st_ino, after.st_size):
            _fail("output_conflict", "Catalog destination changed after rendering")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _target_action(directory_fd: int, filename: str, desired_sha256: str, previous_sha256: str | None) -> bool:
    """Return True to write, False when a partial retry already published it."""
    current = _target_hash(directory_fd, filename)
    if current == desired_sha256:
        return False
    if previous_sha256 is None:
        if current is None:
            return True
    elif current == previous_sha256:
        return True
    _fail("output_conflict", "Catalog destination changed after rendering")


def _write_atomic(
    directory_fd: int,
    output_dir: Path,
    filename: str,
    content: bytes,
    previous_sha256: str | None,
) -> bool:
    desired_sha256 = hashlib.sha256(content).hexdigest()
    if not _target_action(directory_fd, filename, desired_sha256, previous_sha256):
        return False
    temporary = ".starduster-{}.tmp".format(uuid.uuid4().hex)
    try:
        handle = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if not _output_matches(directory_fd, output_dir):
            _fail("output_error", "Approved output directory changed before publication")
        # Recheck the bound prior state immediately before atomic replacement.
        # A partial retry may find the already-desired bytes and skip safely.
        if not _target_action(directory_fd, filename, desired_sha256, previous_sha256):
            os.unlink(temporary, dir_fd=directory_fd)
            return False
        os.replace(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        if not _output_matches(directory_fd, output_dir):
            _fail("output_error", "Approved output directory changed during publication")
    except PublicationError:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    except OSError:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        _fail("output_error", "Could not publish rendered catalog file")
    return True


def _publish_catalog(
    output_dir: Path,
    contents: Mapping[str, bytes],
    entries: Sequence[Mapping[str, Any]],
) -> list[str]:
    root_fd = _secure_directory(output_dir)
    created: list[str] = []
    child_fds: dict[str, int] = {}
    by_path = {str(entry["path"]): entry for entry in entries}
    try:
        # Resolve and pin every destination directory, then validate every file
        # state before making the first content write.
        for directory in sorted({_normal_catalog_relative(relative)[1] for relative in contents}):
            try:
                os.mkdir(directory, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                child_fds[directory] = os.open(directory, flags, dir_fd=root_fd)
            except OSError:
                _fail("output_error", "Could not safely open catalog destination")
            if not _output_matches(child_fds[directory], output_dir / directory):
                _fail("output_error", "Catalog directory changed before publication")
        for relative in sorted(contents):
            _prefix, directory, filename = _normal_catalog_relative(relative)
            entry = by_path[relative]
            _target_action(child_fds[directory], filename, str(entry["sha256"]), entry.get("previous_sha256"))
        for relative in sorted(contents):
            _prefix, directory, filename = _normal_catalog_relative(relative)
            entry = by_path[relative]
            if _write_atomic(
                child_fds[directory], output_dir / directory, filename,
                contents[relative], entry.get("previous_sha256"),
            ):
                created.append("{}/{}".format(directory, filename))
        return created
    finally:
        for descriptor in child_fds.values():
            os.close(descriptor)
        os.close(root_fd)


def _remove_capsule(capsule: Path, expected_digest: str) -> None:
    """Revalidate and remove the exact pinned capsule, never a path replacement."""
    capsule, root_fd, capsule_fd = _open_pending_capsule(capsule)
    catalog_fd = child_fd = -1
    try:
        _manifest, _contents, digest, _expired = _validate_opened_capsule(
            capsule_fd, allow_expired=True
        )
        if not hmac.compare_digest(digest, expected_digest):
            _fail("invalid_pending_capsule", "Pending capsule changed before cleanup")
        catalog_fd = _open_private_directory_at(capsule_fd, "catalog")
        for directory in sorted(os.listdir(catalog_fd)):
            child_fd = _open_private_directory_at(catalog_fd, directory)
            for filename in sorted(os.listdir(child_fd)):
                os.unlink(filename, dir_fd=child_fd)
            os.close(child_fd)
            child_fd = -1
            os.rmdir(directory, dir_fd=catalog_fd)
        os.close(catalog_fd)
        catalog_fd = -1
        os.unlink("manifest.json", dir_fd=capsule_fd)
        os.rmdir("catalog", dir_fd=capsule_fd)
        named = os.stat(capsule.name, dir_fd=root_fd, follow_symlinks=False)
        pinned = os.fstat(capsule_fd)
        if (named.st_dev, named.st_ino) != (pinned.st_dev, pinned.st_ino):
            _fail("invalid_pending_capsule", "Pending capsule changed before cleanup")
        os.rmdir(capsule.name, dir_fd=root_fd)
    except PublicationError:
        raise
    except OSError:
        _fail("output_error", "Could not remove pending output capsule")
    finally:
        if child_fd >= 0:
            os.close(child_fd)
        if catalog_fd >= 0:
            os.close(catalog_fd)
        os.close(capsule_fd)
        os.close(root_fd)


def sweep_expired_pending_catalogs(exclude: Path | None = None) -> None:
    root = pending_root()
    try:
        candidates = list(root.glob(PENDING_PREFIX + "*"))
    except OSError:
        return
    for candidate in candidates:
        try:
            if exclude is not None and candidate.resolve(strict=False) == exclude.resolve(strict=False):
                continue
            capsule, manifest, _contents, digest = validate_catalog_capsule(
                candidate, allow_expired=True
            )
            if dt.datetime.now(dt.timezone.utc) < _utc(manifest.get("expires_at")):
                continue
            _remove_capsule(capsule, digest)
        except (PublicationError, OSError, UnicodeError, json.JSONDecodeError):
            continue


def commit_catalog_output(path: str, output_root: str, output_dir: str, expected_digest: str) -> dict[str, Any]:
    """Publish an exactly authorized capsule; retain it whenever publication fails."""
    capsule_path = Path(path)
    capsule, manifest, contents, actual_digest = validate_catalog_capsule(
        capsule_path, allow_expired=True
    )
    if dt.datetime.now(dt.timezone.utc) >= _utc(manifest["expires_at"]):
        _remove_capsule(capsule, actual_digest)
        _fail("expired_pending_capsule", "Pending capsule has expired")
    target = manifest["target"]
    if (
        output_root != target["output_root"]
        or output_dir != target["output_dir"]
        or not isinstance(expected_digest, str)
        or not _SHA256.fullmatch(expected_digest)
        or not hmac.compare_digest(expected_digest, actual_digest)
    ):
        _fail("invalid_pending_authority", "Commit authority does not match the pending capsule")
    published = _publish_catalog(Path(output_dir), contents, manifest["catalog"]["files"])
    _remove_capsule(capsule, actual_digest)
    result = manifest["result"]
    return {
        "status": "completed",
        "output_dir": output_dir,
        "published_files": len(published),
        "counts": result.get("counts", {}),
        "warnings": result.get("warnings", []),
        "obsidian_uri": result.get("obsidian_uri"),
    }
