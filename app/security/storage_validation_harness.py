"""Opt-in disposable temporary-directory validation using synthetic records.

This module is intentionally disconnected from packet capture, the dashboard,
SQLite, IDS, and model code. It has no default target path. Operators must
provide an existing, empty, disposable child directory explicitly. It must not
be run against selected, pilot, or production storage.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from app.security.live_flow_export import LiveFlowExportError, LiveFlowExportStore, SessionManifest
from app.security.live_flow_schema import CollectorMetadata, LIVE_FLOW_V1_FEATURE_NAMES, LiveFlowV1Record, MissingReason

PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DISPOSABLE_DIRECTORY = re.compile(r"^\.securework-storage-validation-[0-9a-f]{32}$")
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_ROOT_LOCK_NAME = ".securework-storage-validation.run.lock"


class StorageValidationError(RuntimeError):
    """The explicit target is unsafe or a storage validation check failed."""


@dataclass(frozen=True)
class StorageValidationResult:
    """Non-sensitive result of one synthetic disposable-directory validation run."""

    run_id: str
    validation_directory: str
    verified_checks: tuple[str, ...]
    simulated_checks: tuple[str, ...]
    limitations: tuple[str, ...]


def run_storage_validation(validation_directory: str | Path, *, confirm_disposable: bool = False) -> StorageValidationResult:
    """Run synthetic exporter checks in one explicitly supplied empty directory."""
    root = _validate_target(validation_directory, confirm_disposable=confirm_disposable)
    root_lock = _HarnessRootLock(root)
    try:
        root_lock.acquire()
        return _run_storage_validation(root, root_lock.root_identity)
    finally:
        if root_lock.identity is not None:
            root_lock.release()


def _run_storage_validation(root: Path, root_identity: tuple[int, int]) -> StorageValidationResult:
    """Run checks while the harness-owned root lock remains present."""
    run_id = uuid.uuid4().hex
    session_id = f"storage-validation-{run_id}"
    lock_session_id = f"storage-lock-{run_id}"
    failure_session_id = f"storage-failure-{run_id}"

    try:
        store = LiveFlowExportStore()
        manifest = _manifest(session_id)
        record = _synthetic_record(session_id, run_id)
        _assert_root_unchanged(root, root_identity)
        destination, summary = store.export(root, manifest, [record])
        if not destination.is_dir() or summary.record_count != 1:
            raise StorageValidationError("Synthetic export did not publish the expected session directory.")

        try:
            _assert_root_unchanged(root, root_identity)
            store.export(root, manifest, [record])
        except LiveFlowExportError:
            pass
        else:
            raise StorageValidationError("Existing-session collision was not rejected.")

        lock_path = root / f".{lock_session_id}.live-flow.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, run_id.encode("ascii"))
        finally:
            os.close(descriptor)
        lock_identity = _path_identity(lock_path)
        try:
            try:
                _assert_root_unchanged(root, root_identity)
                store.export(root, _manifest(lock_session_id), [_synthetic_record(lock_session_id, run_id)])
            except LiveFlowExportError:
                pass
            else:
                raise StorageValidationError("Active lock contention was not rejected.")
        finally:
            _remove_harness_lock(lock_path, lock_identity, run_id)

        failing_store = LiveFlowExportStore(
            directory_replace=lambda _source, _target: (_ for _ in ()).throw(OSError("synthetic publish interruption"))
        )
        try:
            _assert_root_unchanged(root, root_identity)
            failing_store.export(root, _manifest(failure_session_id), [_synthetic_record(failure_session_id, run_id)])
        except LiveFlowExportError:
            pass
        else:
            raise StorageValidationError("Synthetic publish interruption did not fail.")
        _assert_no_failed_publish_artifacts(root, failure_session_id)

        _assert_root_unchanged(root, root_identity)
        receipt = store.delete_export(root, session_id, "2026-10-27T09:05:00+05:30")
        if not receipt.is_file():
            raise StorageValidationError("Synthetic deletion receipt was not created.")
        receipt_identity = _path_identity(receipt)
        _remove_harness_receipt(receipt, receipt_identity, session_id)
        if receipt.parent.exists() and not any(receipt.parent.iterdir()):
            receipt.parent.rmdir()
        _assert_directory_empty(root, allowed_names={_ROOT_LOCK_NAME})
    except StorageValidationError:
        raise
    except LiveFlowExportError as exc:
        raise StorageValidationError(f"Synthetic exporter validation failed: {exc}") from exc
    except OSError as exc:
        raise StorageValidationError(f"Disposable-directory validation encountered a filesystem error: {exc}") from exc

    return StorageValidationResult(
        run_id=run_id,
        validation_directory=str(root),
        verified_checks=(
            "synthetic export and deletion receipt",
            "existing-session collision rejection",
            "create-new lock-file contention rejection",
            "synthetic publish-failure staging and lock cleanup",
            "cleanup of harness-created artifacts",
        ),
        simulated_checks=("publish interruption via injected directory rename failure",),
        limitations=(
            "This does not test real ACL denial, process crash, power loss, antivirus locking, or other reparse-point types.",
            "This does not create or test symbolic links, junctions, packet capture, SQLite, IDS, or model inference.",
        ),
    )


def _validate_target(value: str | Path, *, confirm_disposable: bool) -> Path:
    if not confirm_disposable:
        raise StorageValidationError("Refusing to run without explicit disposable-target confirmation.")
    if not isinstance(value, (str, Path)):
        raise StorageValidationError("validation_directory must be an explicit absolute path.")
    supplied_path = Path(value)
    if not supplied_path.is_absolute():
        raise StorageValidationError("validation_directory must be an explicit absolute path.")
    root = supplied_path.absolute()
    if not root.exists() or not root.is_dir():
        raise StorageValidationError("validation_directory must be an existing absolute directory.")
    _assert_no_reparse_ancestors(root)
    try:
        canonical_root = root.resolve(strict=True)
        canonical_project_root = PROJECT_ROOT.resolve(strict=True)
    except OSError as exc:
        raise StorageValidationError("validation_directory could not be canonicalized safely.") from exc
    _assert_no_reparse_ancestors(canonical_root)
    if not canonical_root.is_dir() or _is_reparse_point(canonical_root):
        raise StorageValidationError("validation_directory must be an existing non-reparse-point directory.")
    if not _DISPOSABLE_DIRECTORY.fullmatch(root.name):
        raise StorageValidationError("validation_directory name must use the disposable SecureWork validation format.")
    try:
        canonical_root.relative_to(canonical_project_root)
    except ValueError:
        pass
    else:
        raise StorageValidationError("validation_directory must not be inside the SecureWork project.")
    try:
        if any(canonical_root.iterdir()):
            raise StorageValidationError("validation_directory must be empty before the harness starts.")
    except OSError as exc:
        raise StorageValidationError("validation_directory cannot be inspected safely.") from exc
    return canonical_root


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise StorageValidationError(f"Path metadata could not be read safely: {path}") from exc
    return path.is_symlink() or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _assert_no_reparse_ancestors(path: Path) -> None:
    """Inspect every path component before accepting an explicit disposable target."""
    absolute = path.absolute()
    parts = absolute.parts
    if not parts:
        raise StorageValidationError("validation_directory must be an absolute path.")
    current = Path(parts[0])
    for part in parts[1:]:
        current /= part
        if _is_reparse_point(current):
            raise StorageValidationError("validation_directory must not include a reparse-point ancestor.")


def _path_identity(path: Path) -> tuple[int, int]:
    if _is_reparse_point(path):
        raise StorageValidationError("Expected a regular path, not a reparse point.")
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise StorageValidationError("Path identity could not be read safely.") from exc
    return metadata.st_dev, metadata.st_ino


def _assert_root_unchanged(root: Path, expected: tuple[int, int]) -> None:
    _assert_no_reparse_ancestors(root)
    if not root.is_dir() or _path_identity(root) != expected:
        raise StorageValidationError("validation_directory changed during the operation; artifacts were preserved for manual review.")


class _HarnessRootLock:
    """Serialize cooperating harness runs and detect root replacement.

    The lock cannot prevent a privileged external process from changing a
    pathname. Every subsequent operation therefore also checks root identity.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.path = root / _ROOT_LOCK_NAME
        self.owner_token = uuid.uuid4().hex
        self.descriptor: int | None = None
        self.identity: tuple[int, int] | None = None
        self.root_identity = _path_identity(root)

    def acquire(self) -> None:
        _assert_root_unchanged(self.root, self.root_identity)
        try:
            self.descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(self.descriptor, self.owner_token.encode("ascii"))
            self.identity = _path_identity(self.path)
        except FileExistsError as exc:
            raise StorageValidationError("Another storage-validation harness run is active or needs manual review.") from exc
        except OSError as exc:
            raise StorageValidationError("Harness root lock could not be created safely.") from exc
        _assert_root_unchanged(self.root, self.root_identity)
        if {entry.name for entry in self.root.iterdir()} != {_ROOT_LOCK_NAME}:
            raise StorageValidationError("validation_directory changed after validation; artifacts were preserved for manual review.")

    def release(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None
        if self.identity is not None:
            _remove_owned_file(
                self.path,
                self.identity,
                self.owner_token,
                "Harness root lock",
                encoding="ascii",
            )


def _manifest(session_id: str) -> SessionManifest:
    return SessionManifest(
        session_id=session_id, scenario_id="STORAGE-VALIDATION", scenario_definition_version="1",
        actual_start="2026-10-20T09:00:00+05:30", actual_end="2026-10-20T09:05:00+05:30",
        retention_delete_after="2026-10-27T09:05:00+05:30", interface_category="approved_external_usb_wifi",
        collector_configuration={"idle_timeout_seconds": 30, "finalization_policy": "existing_aggregator"},
    )


def _synthetic_record(session_id: str, run_id: str) -> LiveFlowV1Record:
    values: dict[str, Any] = {
        "protocol": "tcp", "packet_count": 1, "captured_bytes": 128, "observed_duration_seconds": 0.0,
        "packet_rate_pps": None, "captured_byte_rate_bps": None, "source_packet_count": 1,
        "destination_packet_count": 0, "source_captured_bytes": 128, "destination_captured_bytes": 0,
        "source_packet_fraction": 1.0, "destination_packet_fraction": 0.0,
        "source_mean_captured_packet_bytes": 128.0, "destination_mean_captured_packet_bytes": None,
        "source_interpacket_ms": None, "destination_interpacket_ms": None, "source_jitter_ms": None,
        "destination_jitter_ms": None, "source_ipv4_ttl": None, "destination_ipv4_ttl": None,
        "source_tcp_window": None, "destination_tcp_window": None, "source_initial_tcp_sequence": None,
        "destination_initial_tcp_sequence": None, "observed_tcp_state": None, "synack_seconds": None,
        "ackdat_seconds": None, "tcp_handshake_seconds": None, "is_sm_ips_ports": None,
    }
    if tuple(values) != LIVE_FLOW_V1_FEATURE_NAMES:
        raise StorageValidationError("Synthetic record no longer matches the live_flow_v1 schema.")
    missingness = {name: MissingReason.NOT_OBSERVED for name, value in values.items() if value is None}
    return LiveFlowV1Record(
        metadata=CollectorMetadata(session_id, idle_timeout_seconds=30), flow_id=run_id,
        finalization_reason="monitor_stopped", values=values, missingness=missingness,
    )


def _assert_no_failed_publish_artifacts(root: Path, session_id: str) -> None:
    paths = [root / session_id, root / f".{session_id}.live-flow.lock", *root.glob(f".{session_id}.staging-*")]
    if any(path.exists() for path in paths):
        raise StorageValidationError("Unexpected failed-publish artifacts were preserved for manual review; do not rerun until reviewed.")


def _remove_owned_file(
    path: Path,
    expected: tuple[int, int],
    expected_contents: str,
    label: str,
    *,
    encoding: str,
) -> None:
    try:
        if _path_identity(path) != expected or path.read_text(encoding=encoding) != expected_contents:
            raise StorageValidationError(f"{label} ownership changed; it was preserved for manual review.")
        if _path_identity(path) != expected:
            raise StorageValidationError(f"{label} ownership changed; it was preserved for manual review.")
        path.unlink()
    except OSError as exc:
        raise StorageValidationError(f"{label} could not be removed safely.") from exc


def _remove_harness_lock(path: Path, identity: tuple[int, int], run_id: str) -> None:
    _remove_owned_file(path, identity, run_id, "Harness-created lock", encoding="ascii")


def _remove_harness_receipt(path: Path, identity: tuple[int, int], session_id: str) -> None:
    try:
        receipt_contents = path.read_text(encoding="utf-8")
        payload = json.loads(receipt_contents)
    except (OSError, json.JSONDecodeError) as exc:
        raise StorageValidationError("Deletion receipt could not be verified; it was preserved for manual review.") from exc
    if payload.get("session_id") != session_id or payload.get("verification") != "session_directory_absent":
        raise StorageValidationError("Deletion receipt ownership changed; it was preserved for manual review.")
    _remove_owned_file(path, identity, receipt_contents, "Harness-created deletion receipt", encoding="utf-8")


def _assert_directory_empty(root: Path, *, allowed_names: set[str] | None = None) -> None:
    allowed_names = allowed_names or set()
    if {entry.name for entry in root.iterdir()} - allowed_names:
        raise StorageValidationError("Unexpected validation artifacts were preserved for manual review; do not reuse this directory.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run synthetic SecureWork live_flow_v1 storage validation.")
    parser.add_argument("--validation-dir", type=Path, required=True, help="Existing empty disposable validation child directory.")
    parser.add_argument("--confirm-disposable", action="store_true", help="Confirm the explicit directory is disposable and approved for synthetic writes.")
    arguments = parser.parse_args()
    try:
        result = run_storage_validation(arguments.validation_dir, confirm_disposable=arguments.confirm_disposable)
    except StorageValidationError as exc:
        print(f"Storage validation refused or failed: {exc}")
        return 1
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
