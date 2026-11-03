"""Unit tests for the pure CompletedFlow-to-live_flow_v1 adapter.

All flows here are constructed fixtures, not captured observations.
"""
import math
import sys
import unittest

from app.security.flow_aggregator import LiveFlowAggregator
from app.security.live_flow_adapter import (
    CompletedFlowAdapterError,
    completed_flow_to_live_flow_v1,
)
from app.security.live_flow_schema import CollectorMetadata, LIVE_FLOW_V1_FEATURE_NAMES, MissingReason
from app.security.network_monitor import PacketRecord


def fixture_packet(
    timestamp: float,
    protocol: str = "TCP",
    source_ip: str = "192.0.2.1",
    destination_ip: str = "198.51.100.4",
    source_port: int | None = 1234,
    destination_port: int | None = 443,
    size: int = 100,
    **kwargs,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp, source_ip=source_ip, destination_ip=destination_ip,
        source_port=source_port, destination_port=destination_port,
        protocol=protocol, packet_length=size, **kwargs,
    )


def completed_flow(protocol: str = "TCP"):
    aggregator = LiveFlowAggregator()
    if protocol == "TCP":
        aggregator.process_packet(fixture_packet(1, tcp_flags="S", ip_ttl=64, tcp_window=1000, tcp_sequence=5))
        aggregator.process_packet(fixture_packet(2, source_ip="198.51.100.4", destination_ip="192.0.2.1", source_port=443, destination_port=1234, size=200, tcp_flags="SA", ip_ttl=63, tcp_window=2000, tcp_sequence=7))
        aggregator.process_packet(fixture_packet(3, tcp_flags="A", ip_ttl=64, tcp_window=1000, tcp_sequence=6))
    else:
        aggregator.process_packet(fixture_packet(1, protocol=protocol, tcp_window=None, tcp_sequence=None))
        aggregator.process_packet(fixture_packet(2, protocol=protocol, tcp_window=None, tcp_sequence=None))
    return aggregator.finalize_all()[0]


def metadata() -> CollectorMetadata:
    return CollectorMetadata("adapter-session-001", idle_timeout_seconds=30)


class CompletedFlowAdapterTests(unittest.TestCase):
    def test_valid_tcp_flow_preserves_schema_direction_units_and_missingness(self) -> None:
        record = completed_flow_to_live_flow_v1(completed_flow(), metadata())
        self.assertEqual(tuple(record.values), LIVE_FLOW_V1_FEATURE_NAMES)
        self.assertEqual(record.values["protocol"], "tcp")
        self.assertEqual(record.values["source_packet_count"], 2)
        self.assertEqual(record.values["destination_packet_count"], 1)
        self.assertEqual(record.values["captured_bytes"], 400)
        self.assertEqual(record.values["captured_byte_rate_bps"], 1600)
        self.assertNotIn("synack_seconds", record.missingness)
        exported = record.as_dict()
        self.assertNotIn("source_ip", exported)
        self.assertNotIn("destination_ip", exported)
        self.assertNotIn("source_port", exported)
        self.assertNotIn("destination_port", exported)

    def test_non_tcp_values_are_not_applicable_without_fabrication(self) -> None:
        record = completed_flow_to_live_flow_v1(completed_flow("UDP"), metadata())
        self.assertEqual(record.values["protocol"], "udp")
        self.assertIsNone(record.values["source_tcp_window"])
        self.assertEqual(record.missingness["source_tcp_window"], MissingReason.NOT_APPLICABLE)
        self.assertIsNone(record.values["synack_seconds"])
        self.assertEqual(record.missingness["synack_seconds"], MissingReason.NOT_APPLICABLE)

    def test_rejects_malformed_metadata_and_flow_values(self) -> None:
        flow = completed_flow()
        bad_metadata = CollectorMetadata("adapter-session-001", idle_timeout_seconds=30)
        object.__setattr__(bad_metadata, "idle_timeout_seconds", math.nan)
        with self.assertRaises(CompletedFlowAdapterError):
            completed_flow_to_live_flow_v1(flow, bad_metadata)

        object.__setattr__(flow, "packet_count", True)
        with self.assertRaises(CompletedFlowAdapterError):
            completed_flow_to_live_flow_v1(flow, metadata())

    def test_rejects_nonfinite_inconsistent_and_non_tcp_tcp_values(self) -> None:
        flow = completed_flow()
        object.__setattr__(flow, "source_interpacket_ms", math.inf)
        with self.assertRaises(CompletedFlowAdapterError):
            completed_flow_to_live_flow_v1(flow, metadata())

    def test_rejects_unrepresentable_numeric_values_with_adapter_error(self) -> None:
        flow = completed_flow()
        object.__setattr__(flow, "first_seen", 10 ** 10000)
        with self.assertRaises(CompletedFlowAdapterError):
            completed_flow_to_live_flow_v1(flow, metadata())

        flow = completed_flow()
        object.__setattr__(flow, "source_packets", flow.source_packets + 1)
        with self.assertRaises(CompletedFlowAdapterError):
            completed_flow_to_live_flow_v1(flow, metadata())

        flow = completed_flow("UDP")
        object.__setattr__(flow, "source_tcp_window", 1)
        with self.assertRaises(CompletedFlowAdapterError):
            completed_flow_to_live_flow_v1(flow, metadata())

    def test_adapter_has_no_exporter_database_capture_or_ids_side_effects(self) -> None:
        before_modules = set(sys.modules)
        record = completed_flow_to_live_flow_v1(completed_flow(), metadata())
        self.assertEqual(record.metadata.capture_session_id, "adapter-session-001")
        imported = set(sys.modules) - before_modules
        self.assertFalse({"app.security.live_flow_export", "app.security.event_store", "app.security.ids_service"} & imported)


if __name__ == "__main__":
    unittest.main()
