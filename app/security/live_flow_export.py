"""Offline-safe validation and atomic export for supplied live_flow_v1 records.

This module has no packet-capture, database, GUI, or IDS-service dependency.
It writes only to an explicit caller-provided directory.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import uuid
from contextlib import nullcontext
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from app.security.windows_handle_fs import (
    HeldSessionLock,
    VerifiedDirectoryChain,
    WindowsHandleFilesystemError,
    is_available as windows_handle_backend_available,
)

from app.security.live_flow_schema import LIVE_FLOW_V1_FEATURE_NAMES, LiveFlowV1Record
from app.security.live_flow_validation import (
    ExportSummary,
    SessionManifest,
    ValidationError,
    ValidationReport,
    _SESSION_ID,
    _parse_timestamp,
    validate_export,
)

_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class LiveFlowExportError(RuntimeError):
    """Base error for an offline live-flow export."""

    def __init__(
        self,
        message: str,
        *,
        primary_error: Exception | None = None,
        cleanup_error: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.primary_error = primary_error
        self.cleanup_error = cleanup_error


class _PathFilesystemBackend:
    """Compatibility backend: pathname operations with documented limitations."""

    def hold_root(self, _root: Path):
        return nullcontext()

    def create_session_lock(self, _path: Path, _owner_token: str) -> None:
        return None


class _WindowsHandleFilesystemBackend:
    """Use retained Windows handles only for operations implemented safely here.

    Publication, receipts, and deletion remain pathname-based in this increment;
    they are not represented as handle-bound guarantees.
    """

    def hold_root(self, root: Path) -> VerifiedDirectoryChain:
        return VerifiedDirectoryChain.open(root)

    def create_session_lock(self, path: Path, owner_token: str) -> HeldSessionLock:
        return HeldSessionLock.create(path, owner_token)


def _default_filesystem_backend() -> _PathFilesystemBackend | _WindowsHandleFilesystemBackend:
    if windows_handle_backend_available():
        return _WindowsHandleFilesystemBackend()
    return _PathFilesystemBackend()


class ExportValidationError(LiveFlowExportError):
    """Raised before writing when a manifest or supplied record is invalid."""

    def __init__(self, report: ValidationReport) -> None:
        super().__init__(f"Export validation failed with {report.rejected_records} rejected record(s).")
        self.report = report


class _SessionLock:
    """Exclusive per-session lock using create-new semantics in the output root."""

    def __init__(self, root: Path, session_id: str, filesystem_backend: object) -> None:
        self.path = root / f".{session_id}.live-flow.lock"
        self._descriptor: int | None = None
        self._owner_token = uuid.uuid4().hex
        self._identity: tuple[int, int] | None = None
        self._filesystem_backend = filesystem_backend
        self._held_windows_lock: HeldSessionLock | None = None

    def __enter__(self) -> "_SessionLock":
        try:
            held_lock = self._filesystem_backend.create_session_lock(self.path, self._owner_token)
        except FileExistsError as exc:
            raise LiveFlowExportError("Another export or deletion is active for this session_id.") from exc
        except WindowsHandleFilesystemError as exc:
            raise LiveFlowExportError("Session lock could not be created safely.") from exc
        if held_lock is not None:
            self._held_windows_lock = held_lock
            return self
        try:
            self._descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise LiveFlowExportError("Another export or deletion is active for this session_id.") from exc
        except OSError as exc:
            raise LiveFlowExportError("Session lock could not be created.") from exc
        try:
            os.write(self._descriptor, self._owner_token.encode("ascii"))
            self._identity = _path_identity(self.path)
        except OSError as exc:
            os.close(self._descriptor)
            self._descriptor = None
            raise LiveFlowExportError(
                "Session lock could not be initialized safely; it was preserved for manual review."
            ) from exc
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._held_windows_lock is not None:
            try:
                self._held_windows_lock.release()
            except WindowsHandleFilesystemError as exc:
                raise LiveFlowExportError("Session lock could not be removed safely; it was preserved for manual review.") from exc
            return
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None
        if self._identity is not None:
            _remove_owned_file(self.path, self._identity, self._owner_token, "Session lock")


def _validated_output_root(output_root: str | Path) -> Path:
    raw_root = Path(output_root).absolute()
    _assert_no_reparse_ancestors(raw_root, "output_root")
    try:
        root = raw_root.resolve(strict=True)
    except OSError as exc:
        raise LiveFlowExportError("output_root could not be canonicalized safely.") from exc
    _assert_no_reparse_ancestors(root, "output_root")
    if not root.is_dir() or _is_reparse_point(root):
        raise LiveFlowExportError("output_root must be an existing non-reparse-point directory.")
    return root


def _is_regular_export_file(path: Path) -> bool:
    """Return whether a required export file is present without following a link."""
    return path.is_file() and not _is_reparse_point(path)


def _is_reparse_point(path: Path) -> bool:
    """Detect links and Windows reparse points without following the final path."""
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise LiveFlowExportError(f"Path metadata could not be read safely: {path}") from exc
    return path.is_symlink() or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _assert_no_reparse_ancestors(path: Path, label: str) -> None:
    """Fail closed when any existing component is a link or Windows reparse point."""
    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise LiveFlowExportError(f"{label} must be an absolute path.")
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        if _is_reparse_point(current):
            raise LiveFlowExportError(f"{label} must not include a reparse-point ancestor.")


def _path_identity(path: Path) -> tuple[int, int]:
    if _is_reparse_point(path):
        raise LiveFlowExportError("Expected a regular path, not a reparse point.")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise LiveFlowExportError("Path identity could not be read safely.") from exc
    return metadata.st_dev, metadata.st_ino


def _assert_directory_identity(path: Path, expected: tuple[int, int], label: str) -> None:
    if not path.is_dir() or _path_identity(path) != expected:
        raise LiveFlowExportError(f"{label} changed during the operation.")


def _remove_owned_file(path: Path, expected: tuple[int, int], owner_token: str, label: str) -> None:
    """Remove only the file whose identity and opaque owner token still match.

    Windows pathname replacement between the final check and unlink remains an OS
    race; callers preserve the path when any observed ownership check fails.
    """
    try:
        if _path_identity(path) != expected or path.read_text(encoding="ascii") != owner_token:
            raise LiveFlowExportError(f"{label} ownership changed; it was preserved for manual review.")
        if _path_identity(path) != expected:
            raise LiveFlowExportError(f"{label} ownership changed; it was preserved for manual review.")
        path.unlink()
    except LiveFlowExportError:
        raise
    except OSError as exc:
        raise LiveFlowExportError(f"{label} could not be removed safely.") from exc


class LiveFlowExportStore:
    """Write explicitly supplied records atomically; never starts collection."""

    def __init__(
        self,
        directory_replace: Callable[[str, str], Any] = os.replace,
        filesystem_backend: _PathFilesystemBackend | _WindowsHandleFilesystemBackend | None = None,
    ) -> None:
        self._directory_replace = directory_replace
        self._filesystem_backend = filesystem_backend or _default_filesystem_backend()

    def export(
        self,
        output_root: str | Path,
        manifest: SessionManifest,
        records: Iterable[object],
    ) -> tuple[Path, ExportSummary]:
        """Validate then atomically create one new session export directory."""
        root = _validated_output_root(output_root)
        accepted, report = validate_export(manifest, records)
        if not report.valid:
            raise ExportValidationError(report)

        destination = root / manifest.session_id
        try:
            root_guard = self._filesystem_backend.hold_root(root)
        except WindowsHandleFilesystemError as exc:
            raise LiveFlowExportError("Output root could not be retained safely.") from exc
        with root_guard:
            root_identity = _path_identity(root)
            with _SessionLock(root, manifest.session_id, self._filesystem_backend):
                _assert_directory_identity(root, root_identity, "output_root")
                if destination.exists() or destination.is_symlink():
                    raise LiveFlowExportError("A session export already exists for this session_id.")
                try:
                    staging = Path(tempfile.mkdtemp(prefix=f".{manifest.session_id}.staging-", dir=root))
                except OSError as exc:
                    raise LiveFlowExportError("Session staging directory could not be created.") from exc
                try:
                    _assert_directory_identity(root, root_identity, "output_root")
                    summary = ExportSummary(
                    session_id=manifest.session_id,
                    record_count=len(accepted),
                    rejected_record_count=report.rejected_records,
                    validation_error_count=len(report.errors),
                    schema_version=manifest.schema_version,
                    collector_version=manifest.collector_version,
                    feature_names=LIVE_FLOW_V1_FEATURE_NAMES,
                    )
                    self._write_json(staging / "manifest.json", asdict(manifest))
                    self._write_records(staging / "flow_records.ndjson", accepted)
                    self._write_json(staging / "export_summary.json", {
                    **asdict(summary),
                    "feature_names": list(summary.feature_names),
                    "validation_errors": [],
                    })
                    _assert_directory_identity(root, root_identity, "output_root")
                    self._directory_replace(str(staging), str(destination))
                except Exception as exc:
                    try:
                        shutil.rmtree(staging)
                    except Exception as cleanup_error:
                        raise LiveFlowExportError(
                            f"Atomic session export failed: {exc}. Staging cleanup also failed; "
                            f"manual recovery may be required for session_id {manifest.session_id!r}.",
                            primary_error=exc,
                            cleanup_error=cleanup_error,
                        ) from exc
                    if isinstance(exc, LiveFlowExportError):
                        raise
                    raise LiveFlowExportError(f"Atomic session export failed: {exc}") from exc
        return destination, summary

    @staticmethod
    def _write_json(path: Path, value: Mapping[str, Any]) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def _write_records(path: Path, records: Iterable[LiveFlowV1Record]) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            for record in records:
                json.dump(record.as_dict(), handle, sort_keys=False)
                handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    @staticmethod
    def delete_export(
        output_root: str | Path,
        session_id: str,
        deleted_at: str,
    ) -> Path:
        """Remove a completed export and atomically record verifiable deletion."""
        root = _validated_output_root(output_root)
        if not _SESSION_ID.fullmatch(session_id):
            raise LiveFlowExportError("session_id must be a safe opaque identifier.")
        directory = root / session_id
        receipt_directory = root / "deletion_receipts"
        receipt = receipt_directory / f"{session_id}.json"
        if _is_reparse_point(directory) or not directory.is_dir():
            raise LiveFlowExportError("Session export is missing or is not a regular directory.")
        if not _is_regular_export_file(directory / "manifest.json") or not _is_regular_export_file(directory / "export_summary.json"):
            raise LiveFlowExportError("session_directory is not a completed live_flow_v1 export.")
        errors: list[ValidationError] = []
        if _parse_timestamp(deleted_at, "deleted_at", errors) is None:
            raise LiveFlowExportError(errors[0].message)
        filesystem_backend = _default_filesystem_backend()
        try:
            root_guard = filesystem_backend.hold_root(root)
        except WindowsHandleFilesystemError as exc:
            raise LiveFlowExportError("Output root could not be retained safely.") from exc
        with root_guard:
            root_identity = _path_identity(root)
            with _SessionLock(root, session_id, filesystem_backend):
                _assert_directory_identity(root, root_identity, "output_root")
                if _is_reparse_point(directory) or not directory.is_dir():
                    raise LiveFlowExportError("Session export changed while deletion was being prepared.")
                try:
                    receipt_directory.mkdir(exist_ok=True)
                except OSError as exc:
                    raise LiveFlowExportError("deletion_receipts directory could not be created.") from exc
                if _is_reparse_point(receipt_directory) or not receipt_directory.is_dir():
                    raise LiveFlowExportError("deletion_receipts must not be a reparse-point directory.")
                if receipt.exists() or _is_reparse_point(receipt):
                    raise LiveFlowExportError("A deletion receipt already exists for this session_id.")
                if not _is_regular_export_file(directory / "manifest.json") or not _is_regular_export_file(directory / "export_summary.json"):
                    raise LiveFlowExportError("Session export changed while deletion was being prepared.")
                try:
                    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise LiveFlowExportError("Session manifest cannot be read as valid JSON.") from exc
                if manifest.get("session_id") != session_id:
                    raise LiveFlowExportError("Manifest session_id does not match deletion target.")
                try:
                    _assert_directory_identity(root, root_identity, "output_root")
                    shutil.rmtree(directory)
                except OSError as exc:
                    raise LiveFlowExportError("Session export could not be deleted.") from exc
                if directory.exists():
                    raise LiveFlowExportError("Session export could not be deleted.")
                payload = {
                    "session_id": session_id,
                    "deleted_at": deleted_at,
                    "verification": "session_directory_absent",
                }
                temporary: Path | None = None
                try:
                    _assert_directory_identity(root, root_identity, "output_root")
                    descriptor, temporary_name = tempfile.mkstemp(
                        prefix=f".{receipt.name}.", suffix=".tmp", dir=receipt_directory,
                    )
                    os.close(descriptor)
                    temporary = Path(temporary_name)
                    LiveFlowExportStore._write_json(temporary, payload)
                    os.replace(temporary, receipt)
                except Exception as exc:
                    if temporary is not None:
                        temporary.unlink(missing_ok=True)
                    raise LiveFlowExportError(
                        "Export was deleted, but the deletion receipt could not be written."
                    ) from exc
        return receipt
