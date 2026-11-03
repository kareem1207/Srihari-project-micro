"""Tests for offline-safe live_flow_v1 batch validation and export."""
import json
import math
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.security.flow_aggregator import LiveFlowAggregator
from app.security.live_flow_export import (
    ExportValidationError,
    LiveFlowExportError,
    LiveFlowExportStore,
    SessionManifest,
    _PathFilesystemBackend,
)
from app.security.live_flow_schema import CollectorMetadata, export_live_flow_v1
from app.security.network_monitor import PacketRecord


def record(session_id: str, flow_number: int = 1):
    aggregator = LiveFlowAggregator()
    aggregator.process_packet(PacketRecord(
        timestamp=1, source_ip="192.0.2.1", destination_ip="198.51.100.4",
        protocol="TCP", source_port=1234, destination_port=443, packet_length=100,
    ))
    flow = aggregator.finalize_all()[0]
    object.__setattr__(flow, "flow_id", f"{flow_number:032x}")
    return export_live_flow_v1(flow, CollectorMetadata(session_id, idle_timeout_seconds=30))


def manifest(session_id: str = "session-001") -> SessionManifest:
    return SessionManifest(
        session_id=session_id,
        scenario_id="IDLE-01",
        scenario_definition_version="1",
        actual_start="2026-10-20T09:00:00+05:30",
        actual_end="2026-10-20T09:05:00+05:30",
        retention_delete_after="2026-10-27T09:05:00+05:30",
        interface_category="approved_external_usb_wifi",
        collector_configuration={"idle_timeout_seconds": 30, "finalization_policy": "existing_aggregator"},
    )


class LiveFlowExportStoreTests(unittest.TestCase):
    def test_valid_batch_writes_separate_atomic_session_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, summary = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            self.assertEqual(destination, root / "session-001")
            self.assertEqual(summary.record_count, 1)
            self.assertTrue((destination / "manifest.json").is_file())
            self.assertTrue((destination / "flow_records.ndjson").is_file())
            payload = json.loads((destination / "flow_records.ndjson").read_text(encoding="utf-8"))
            self.assertNotIn("source_ip", payload)
            self.assertNotIn("destination_port", payload)
            self.assertEqual(payload["capture_session_id"], "session-001")

    def test_invalid_metadata_or_duplicate_flow_rejects_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = record("session-001")
            with self.assertRaises(ExportValidationError) as raised:
                LiveFlowExportStore().export(root, manifest(), [duplicate, duplicate])
            self.assertEqual(raised.exception.report.rejected_records, 1)
            self.assertFalse((root / "session-001").exists())

            bad_manifest = manifest()
            object.__setattr__(bad_manifest, "actual_end", "2026-10-20T09:05:00")
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, bad_manifest, [record("session-001")])
            self.assertFalse((root / "session-001").exists())

            incomplete_configuration = manifest()
            object.__setattr__(incomplete_configuration, "collector_configuration", {})
            with self.assertRaises(ExportValidationError) as raised:
                LiveFlowExportStore().export(root, incomplete_configuration, [record("session-001")])
            self.assertGreaterEqual(raised.exception.report.rejected_records, 2)
            self.assertFalse((root / "session-001").exists())

            private_configuration = manifest()
            object.__setattr__(
                private_configuration,
                "collector_configuration",
                {"idle_timeout_seconds": 30, "finalization_policy": "existing_aggregator", "source_ip": "192.0.2.1"},
            )
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, private_configuration, [record("session-001")])
            self.assertFalse((root / "session-001").exists())

    def test_path_traversal_and_non_finite_feature_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unsafe_manifest = manifest("../outside")
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, unsafe_manifest, [record("../outside")])

            invalid = record("session-001")
            values = dict(invalid.values)
            values["observed_duration_seconds"] = math.nan
            object.__setattr__(invalid, "values", values)
            with self.assertRaises(ExportValidationError) as raised:
                LiveFlowExportStore().export(root, manifest(), [invalid])
            self.assertEqual(raised.exception.report.accepted_records, 0)
            self.assertFalse((root / "session-001").exists())

            invalid_timeout = manifest()
            object.__setattr__(
                invalid_timeout,
                "collector_configuration",
                {"idle_timeout_seconds": math.nan, "finalization_policy": "existing_aggregator"},
            )
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, invalid_timeout, [record("session-001")])

    def test_existing_session_collision_and_active_lock_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = LiveFlowExportStore()
            store.export(root, manifest(), [record("session-001")])
            with self.assertRaises(LiveFlowExportError):
                store.export(root, manifest(), [record("session-001")])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / ".session-001.live-flow.lock"
            lock.write_text("active", encoding="utf-8")
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore(filesystem_backend=_PathFilesystemBackend()).export(root, manifest(), [record("session-001")])

            # A stale lock needs an explicit, reviewed recovery action.
            lock.unlink()
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            lock.write_text("active", encoding="utf-8")
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")
            self.assertTrue(destination.is_dir())

    def test_permission_failures_fail_closed_and_release_no_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("app.security.live_flow_export.os.open", side_effect=PermissionError("denied")):
                with self.assertRaises(LiveFlowExportError) as raised:
                    LiveFlowExportStore(filesystem_backend=_PathFilesystemBackend()).export(root, manifest(), [record("session-001")])
            self.assertIn("lock", str(raised.exception).casefold())
            self.assertFalse((root / ".session-001.live-flow.lock").exists())
            self.assertFalse((root / "session-001").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("app.security.live_flow_export.tempfile.mkdtemp", side_effect=PermissionError("denied")):
                with self.assertRaises(LiveFlowExportError) as raised:
                    LiveFlowExportStore(filesystem_backend=_PathFilesystemBackend()).export(root, manifest(), [record("session-001")])
            self.assertIn("staging", str(raised.exception).casefold())
            self.assertFalse((root / ".session-001.live-flow.lock").exists())
            self.assertFalse((root / "session-001").exists())

    @unittest.skipUnless(os.name == "nt", "Windows junctions are platform-specific")
    def test_junction_output_or_deletion_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            junction = root / "junction-root"
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"junction creation unavailable: {result.stderr or result.stdout}")
            self.addCleanup(lambda: junction.exists() and junction.rmdir())

            self.assertFalse(junction.is_symlink())
            self.assertTrue(junction.is_dir())
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore().export(junction, manifest(), [record("session-001")])

            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            shutil.rmtree(destination)
            subprocess.run(
                ["cmd", "/c", "rmdir", str(junction)],
                capture_output=True,
                text=True,
                check=False,
            )
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(destination), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"junction target creation unavailable: {result.stderr or result.stdout}")
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")

    @unittest.skipUnless(os.name == "nt", "junctions are a Windows-only test")
    def test_ancestor_junction_output_root_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backing = root / "backing"
            backing.mkdir()
            junction = root / "junction"
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction), str(backing)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"junction creation unavailable: {result.stderr or result.stdout}")
            try:
                target = junction / "ordinary-child"
                target.mkdir()
                with self.assertRaises(LiveFlowExportError):
                    LiveFlowExportStore().export(target, manifest(), [record("session-001")])
            finally:
                subprocess.run(["cmd", "/c", "rmdir", str(junction)], capture_output=True, text=True, check=False)

    def test_atomic_publish_failure_leaves_no_completed_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = LiveFlowExportStore(
                directory_replace=lambda _source, _target: (_ for _ in ()).throw(OSError("simulated"))
            )
            with self.assertRaises(LiveFlowExportError):
                store.export(root, manifest(), [record("session-001")])
            self.assertFalse((root / "session-001").exists())
            self.assertFalse(list(root.glob(".session-001.staging-*")))
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            self.assertTrue(destination.is_dir())

    def test_export_failure_with_successful_cleanup_preserves_primary_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(
                LiveFlowExportStore,
                "_write_records",
                side_effect=OSError("simulated primary write failure"),
            ):
                with self.assertRaises(LiveFlowExportError) as raised:
                    LiveFlowExportStore().export(root, manifest(), [record("session-001")])

            self.assertEqual(
                str(raised.exception),
                "Atomic session export failed: simulated primary write failure",
            )
            self.assertIsInstance(raised.exception.__cause__, OSError)
            self.assertFalse((root / "session-001").exists())
            self.assertFalse(list(root.glob(".session-001.staging-*")))

    def test_export_failure_with_cleanup_failure_requires_manual_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary_error = OSError("simulated primary write failure")
            cleanup_error = OSError("simulated cleanup failure")
            with patch.object(
                LiveFlowExportStore,
                "_write_records",
                side_effect=primary_error,
            ), patch(
                "app.security.live_flow_export.shutil.rmtree",
                side_effect=cleanup_error,
            ):
                with self.assertRaises(LiveFlowExportError) as raised:
                    LiveFlowExportStore().export(root, manifest(), [record("session-001")])

            self.assertIn("simulated primary write failure", str(raised.exception))
            self.assertIn("Staging cleanup also failed", str(raised.exception))
            self.assertIn("manual recovery may be required", str(raised.exception))
            self.assertIn("session-001", str(raised.exception))
            self.assertIs(raised.exception.__cause__, primary_error)
            self.assertIs(raised.exception.primary_error, primary_error)
            self.assertIs(raised.exception.cleanup_error, cleanup_error)
            self.assertFalse((root / "session-001").exists())
            self.assertTrue(list(root.glob(".session-001.staging-*")))

    def test_explicit_deletion_writes_verifiable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            receipt = LiveFlowExportStore.delete_export(
                root, "session-001", "2026-10-27T09:05:00+05:30"
            )
            self.assertFalse(destination.exists())
            self.assertEqual(json.loads(receipt.read_text(encoding="utf-8"))["verification"], "session_directory_absent")

    def test_deletion_refuses_existing_receipt_and_preserves_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, _ = LiveFlowExportStore().export(root, manifest("session-002"), [record("session-002")])
            receipts = root / "deletion_receipts"
            receipts.mkdir()
            (receipts / "session-002.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore.delete_export(root, "session-002", "2026-10-27T09:05:00+05:30")
            self.assertTrue(destination.is_dir())

    def test_deletion_does_not_overwrite_abandoned_temporary_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            receipts = root / "deletion_receipts"
            receipts.mkdir()
            abandoned = receipts / ".session-001.json.tmp"
            abandoned.write_text("preserve", encoding="utf-8")
            receipt = LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")
            self.assertFalse(destination.exists())
            self.assertEqual(abandoned.read_text(encoding="utf-8"), "preserve")
            self.assertTrue(receipt.is_file())

    def test_free_form_manifest_and_feature_values_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            free_form_manifest = manifest()
            object.__setattr__(free_form_manifest, "scenario_definition_version", "192.0.2.1")
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, free_form_manifest, [record("session-001")])

            free_form_configuration = manifest()
            object.__setattr__(
                free_form_configuration,
                "collector_configuration",
                {"idle_timeout_seconds": 30, "finalization_policy": "192.0.2.1", "application_version": "endpoint-192.0.2.1"},
            )
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, free_form_configuration, [record("session-001")])

            invalid_protocol = record("session-001")
            values = dict(invalid_protocol.values)
            values["protocol"] = "192.0.2.1"
            object.__setattr__(invalid_protocol, "values", values)
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, manifest(), [invalid_protocol])

    def test_nested_or_unsupported_input_values_are_rejected_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested_configuration = manifest()
            object.__setattr__(
                nested_configuration,
                "collector_configuration",
                {"idle_timeout_seconds": {"seconds": 30}, "finalization_policy": "existing_aggregator"},
            )
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, nested_configuration, [record("session-001")])

            nested_feature = record("session-001")
            values = dict(nested_feature.values)
            values["protocol"] = {"value": "tcp"}
            object.__setattr__(nested_feature, "values", values)
            with self.assertRaises(ExportValidationError):
                LiveFlowExportStore().export(root, manifest(), [nested_feature])

            self.assertFalse((root / "session-001").exists())
            self.assertFalse(list(root.glob(".session-001.staging-*")))
            self.assertFalse((root / ".session-001.live-flow.lock").exists())

    def test_each_export_write_failure_cleans_current_staging_lock_and_allows_retry(self) -> None:
        failure_cases = (
            ("manifest", "_write_json", lambda path, _value: path.name == "manifest.json"),
            ("records", "_write_records", lambda _path, _value: True),
            ("summary", "_write_json", lambda path, _value: path.name == "export_summary.json"),
        )
        for name, method_name, should_fail in failure_cases:
            with self.subTest(write=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                original = getattr(LiveFlowExportStore, method_name)

                def failing_write(*args, _original=original, _should_fail=should_fail, **kwargs):
                    if _should_fail(*args, **kwargs):
                        raise TypeError("simulated JSON serialization failure")
                    return _original(*args, **kwargs)

                with patch.object(LiveFlowExportStore, method_name, side_effect=failing_write):
                    with self.assertRaises(LiveFlowExportError):
                        LiveFlowExportStore().export(root, manifest(), [record("session-001")])
                self.assertFalse((root / "session-001").exists())
                self.assertFalse(list(root.glob(".session-001.staging-*")))
                self.assertFalse((root / ".session-001.live-flow.lock").exists())

                destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
                self.assertTrue(destination.is_dir())

    def test_deletion_failure_does_not_create_a_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            with patch("app.security.live_flow_export.shutil.rmtree", side_effect=OSError("simulated")):
                with self.assertRaises(LiveFlowExportError):
                    LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")
            self.assertTrue(destination.is_dir())
            self.assertFalse((root / "deletion_receipts" / "session-001.json").exists())

    def test_receipt_write_failure_never_claims_a_completed_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            with patch("app.security.live_flow_export.os.replace", side_effect=OSError("simulated")):
                with self.assertRaises(LiveFlowExportError):
                    LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")
            self.assertFalse(destination.exists())
            self.assertFalse((root / "deletion_receipts" / "session-001.json").exists())
            self.assertFalse(list((root / "deletion_receipts").glob(".session-001.json.*.tmp")))
            self.assertFalse((root / ".session-001.live-flow.lock").exists())

    def test_malformed_manifest_refuses_deletion_and_preserves_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination, _ = LiveFlowExportStore().export(root, manifest(), [record("session-001")])
            (destination / "manifest.json").write_text("not-json", encoding="utf-8")
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")
            self.assertTrue(destination.is_dir())
            self.assertFalse((root / "deletion_receipts" / "session-001.json").exists())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unsupported")
    def test_symlinked_output_or_deletion_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linked_root = root / "linked-root"
            try:
                os.symlink(root, linked_root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore().export(linked_root, manifest(), [record("session-001")])

            target = root / "target"
            target.mkdir()
            os.symlink(target, root / "session-001", target_is_directory=True)
            with self.assertRaises(LiveFlowExportError):
                LiveFlowExportStore.delete_export(root, "session-001", "2026-10-27T09:05:00+05:30")


if __name__ == "__main__":
    unittest.main()
