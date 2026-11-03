"""Tests for the explicit in-memory CompletedFlow-to-offline-export workflow.

All fixtures are constructed unit-test data.  They are never captured traffic
and tests write only to TemporaryDirectory instances.
"""
from __future__ import annotations

import json
import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.security.flow_aggregator import LiveFlowAggregator
from app.security.live_flow_adapter import CompletedFlowAdapterError
from app.security.live_flow_export import LiveFlowExportError, LiveFlowExportStore, SessionManifest
from app.security.live_flow_schema import CollectorMetadata
from app.security.network_monitor import PacketRecord
from app.security.offline_flow_export_workflow import (
    OfflineFlowExportWorkflowError,
    export_completed_flows_offline,
)


def metadata(session_id: str = "workflow-session-001") -> CollectorMetadata:
    return CollectorMetadata(session_id, idle_timeout_seconds=30)


def manifest(session_id: str = "workflow-session-001") -> SessionManifest:
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


def completed_flow(flow_number: int, reason: str = "monitor_stopped"):
    aggregator = LiveFlowAggregator()
    aggregator.process_packet(PacketRecord(
        timestamp=1, source_ip="192.0.2.1", destination_ip="198.51.100.4",
        source_port=12000 + flow_number, destination_port=443, protocol="TCP",
        packet_length=100,
    ))
    aggregator.process_packet(PacketRecord(
        timestamp=2, source_ip="198.51.100.4", destination_ip="192.0.2.1",
        source_port=443, destination_port=12000 + flow_number, protocol="TCP",
        packet_length=120,
    ))
    flow = aggregator.finalize_all(reason)[0]
    object.__setattr__(flow, "flow_id", f"{flow_number:032x}")
    return flow


class OfflineFlowExportWorkflowTests(unittest.TestCase):
    def test_successful_multi_flow_export_is_payload_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = export_completed_flows_offline(
                [completed_flow(1), completed_flow(2)], metadata(), manifest(), root,
            )
            self.assertEqual(result.destination, root / "workflow-session-001")
            self.assertEqual(result.summary.record_count, 2)
            records = [json.loads(line) for line in (result.destination / "flow_records.ndjson").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 2)
            for record in records:
                self.assertNotIn("source_ip", record)
                self.assertNotIn("destination_ip", record)
                self.assertNotIn("source_port", record)
                self.assertNotIn("destination_port", record)
                self.assertNotIn("label", record)
                self.assertNotIn("disposition", record)

    def test_invalid_adapter_inputs_leave_no_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bad = completed_flow(1)
            object.__setattr__(bad, "packet_count", True)
            with self.assertRaises(CompletedFlowAdapterError):
                export_completed_flows_offline([bad], metadata(), manifest(), root)
            self.assertFalse((root / "workflow-session-001").exists())

            with self.assertRaises(OfflineFlowExportWorkflowError):
                export_completed_flows_offline([], metadata(), manifest(), root)
            self.assertFalse((root / "workflow-session-001").exists())

            malformed_metadata = metadata()
            object.__setattr__(malformed_metadata, "idle_timeout_seconds", math.nan)
            with self.assertRaises(CompletedFlowAdapterError):
                export_completed_flows_offline(
                    [completed_flow(1)], malformed_metadata, manifest(), root,
                )
            self.assertFalse((root / "workflow-session-001").exists())

    def test_duplicate_flow_ids_reject_whole_batch_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = completed_flow(1)
            with self.assertRaises(LiveFlowExportError):
                export_completed_flows_offline([duplicate, duplicate], metadata(), manifest(), root)
            self.assertFalse((root / "workflow-session-001").exists())

    def test_existing_session_collision_and_safe_retry_after_publish_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            export_completed_flows_offline([completed_flow(1)], metadata(), manifest(), root)
            with self.assertRaises(LiveFlowExportError):
                export_completed_flows_offline([completed_flow(2)], metadata(), manifest(), root)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = LiveFlowExportStore(directory_replace=lambda _source, _target: (_ for _ in ()).throw(OSError("simulated")))
            with self.assertRaises(LiveFlowExportError):
                export_completed_flows_offline([completed_flow(1)], metadata(), manifest(), root, exporter=store)
            self.assertFalse((root / "workflow-session-001").exists())
            self.assertFalse(list(root.glob(".workflow-session-001.staging-*")))
            retry = export_completed_flows_offline([completed_flow(1)], metadata(), manifest(), root)
            self.assertTrue(retry.destination.is_dir())

    def test_write_failure_cleans_staging_and_allows_safe_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(LiveFlowExportStore, "_write_records", side_effect=OSError("simulated write failure")):
                with self.assertRaises(LiveFlowExportError):
                    export_completed_flows_offline([completed_flow(1)], metadata(), manifest(), root)
            self.assertFalse((root / "workflow-session-001").exists())
            self.assertFalse(list(root.glob(".workflow-session-001.staging-*")))
            retry = export_completed_flows_offline([completed_flow(1)], metadata(), manifest(), root)
            self.assertTrue(retry.destination.is_dir())

    def test_unsupported_finalization_reason_is_rejected_without_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            flow = completed_flow(1, "dashboard_closed")
            with self.assertRaises(CompletedFlowAdapterError):
                export_completed_flows_offline([flow], metadata(), manifest(), root)
            self.assertFalse((root / "workflow-session-001").exists())

    def test_workflow_has_no_capture_database_ids_model_or_ui_imports(self) -> None:
        before = set(sys.modules)
        with tempfile.TemporaryDirectory() as temporary:
            export_completed_flows_offline([completed_flow(1)], metadata(), manifest(), Path(temporary))
        imported = set(sys.modules) - before
        prohibited = {
            "app.security.event_store", "app.security.ids_service", "app.security.feature_compatibility",
            "app.ui.dashboard_window", "app.ml.predict", "scapy.all",
        }
        self.assertFalse(prohibited & imported)


if __name__ == "__main__":
    unittest.main()
