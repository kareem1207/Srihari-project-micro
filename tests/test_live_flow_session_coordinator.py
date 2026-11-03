"""Unit tests for the capture-independent offline session coordinator."""
from __future__ import annotations

import math
import sys
import tempfile
import unittest
from pathlib import Path

from app.security.flow_aggregator import LiveFlowAggregator
from app.security.live_flow_export import LiveFlowExportStore, SessionManifest
from app.security.live_flow_schema import CollectorMetadata
from app.security.live_flow_session_coordinator import (
    LiveFlowSessionCoordinator,
    LiveFlowSessionCoordinatorError,
    SessionState,
)
from app.security.network_monitor import PacketRecord


def metadata() -> CollectorMetadata:
    return CollectorMetadata("coordinator-session-001", idle_timeout_seconds=30)


def manifest() -> SessionManifest:
    return SessionManifest(
        session_id="coordinator-session-001",
        scenario_id="IDLE-01",
        scenario_definition_version="1",
        actual_start="2026-10-20T09:00:00+05:30",
        actual_end="2026-10-20T09:05:00+05:30",
        retention_delete_after="2026-10-27T09:05:00+05:30",
        interface_category="approved_external_usb_wifi",
        collector_configuration={"idle_timeout_seconds": 30, "finalization_policy": "existing_aggregator"},
    )


def completed_flow(number: int = 1, reason: str = "monitor_stopped"):
    aggregator = LiveFlowAggregator()
    aggregator.process_packet(PacketRecord(
        timestamp=1, source_ip="192.0.2.1", destination_ip="198.51.100.4",
        source_port=10000 + number, destination_port=443, protocol="TCP", packet_length=100,
    ))
    flow = aggregator.finalize_all(reason)[0]
    object.__setattr__(flow, "flow_id", f"{number:032x}")
    return flow


class LiveFlowSessionCoordinatorTests(unittest.TestCase):
    def make_coordinator(self, root: Path, **kwargs) -> LiveFlowSessionCoordinator:
        return LiveFlowSessionCoordinator(metadata(), manifest(), root, **kwargs)

    def test_valid_lifecycle_requires_authorization_then_exports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = self.make_coordinator(Path(temporary))
            self.assertEqual(coordinator.status.state, SessionState.PREPARED)
            self.assertEqual(coordinator.authorize().state, SessionState.AUTHORIZED)
            self.assertEqual(coordinator.finalize([completed_flow(1), completed_flow(2)]).state, SessionState.VALIDATED)
            status = coordinator.export()
            self.assertEqual(status.state, SessionState.EXPORTED)
            self.assertEqual(status.result.summary.record_count, 2)
            self.assertTrue(status.result.destination.is_dir())

    def test_invalid_transitions_and_missing_authorization_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = self.make_coordinator(Path(temporary))
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.finalize([completed_flow()])
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.export()
            coordinator.authorize()
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.authorize()
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.finalize([])

    def test_invalid_metadata_or_malformed_flow_fails_without_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad_metadata = metadata()
            object.__setattr__(bad_metadata, "idle_timeout_seconds", math.nan)
            coordinator = LiveFlowSessionCoordinator(bad_metadata, manifest(), root)
            coordinator.authorize()
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.finalize([completed_flow()])
            self.assertEqual(coordinator.status.state, SessionState.FAILED)
            self.assertFalse((root / "coordinator-session-001").exists())

            malformed = self.make_coordinator(root)
            malformed.authorize()
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                malformed.finalize([object()])
            self.assertEqual(malformed.status.state, SessionState.FAILED)

    def test_unsupported_finalization_reason_is_held_without_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            coordinator = self.make_coordinator(root)
            coordinator.authorize()
            status = coordinator.finalize([completed_flow(reason="dashboard_closed")])
            self.assertEqual(status.state, SessionState.HELD_FOR_REVIEW)
            self.assertIn("unsupported", status.message)
            self.assertFalse((root / "coordinator-session-001").exists())
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.export()

    def test_duplicate_flow_ids_fail_validation_without_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flow = completed_flow()
            coordinator = self.make_coordinator(root)
            coordinator.authorize()
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.finalize([flow, flow])
            self.assertEqual(coordinator.status.state, SessionState.FAILED)
            self.assertFalse((root / "coordinator-session-001").exists())

    def test_export_failure_is_reported_and_safe_retry_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failing = LiveFlowExportStore(
                directory_replace=lambda _source, _target: (_ for _ in ()).throw(OSError("simulated"))
            )
            coordinator = self.make_coordinator(root, exporter=failing)
            coordinator.authorize()
            coordinator.finalize([completed_flow()])
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                coordinator.export()
            self.assertEqual(coordinator.status.state, SessionState.FAILED)
            self.assertFalse((root / "coordinator-session-001").exists())
            self.assertFalse(list(root.glob(".coordinator-session-001.staging-*")))

            # Replace the injected failing store only in this test fixture.
            object.__setattr__(coordinator, "_exporter", None)
            self.assertEqual(coordinator.retry_export().state, SessionState.EXPORTED)

    def test_explicit_hold_separates_review_from_feature_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            coordinator = self.make_coordinator(root)
            coordinator.authorize()
            status = coordinator.hold_for_review("Session boundaries require human review.")
            self.assertEqual(status.state, SessionState.HELD_FOR_REVIEW)
            self.assertFalse((root / "coordinator-session-001").exists())

    def test_constructor_requires_explicit_existing_directory_and_no_side_effect_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(LiveFlowSessionCoordinatorError):
                self.make_coordinator(missing)

        before = set(sys.modules)
        with tempfile.TemporaryDirectory() as temporary:
            coordinator = self.make_coordinator(Path(temporary))
            coordinator.authorize()
            coordinator.finalize([completed_flow()])
        imported = set(sys.modules) - before
        prohibited = {
            "app.security.event_store", "app.security.ids_service", "app.security.feature_compatibility",
            "app.ui.dashboard_window", "app.ml.predict", "scapy.all",
        }
        self.assertFalse(prohibited & imported)


if __name__ == "__main__":
    unittest.main()
