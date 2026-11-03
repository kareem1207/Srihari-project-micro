"""Tests for the versioned payload-free live_flow_v1 export contract."""
import unittest

from app.security.flow_aggregator import LiveFlowAggregator
from app.security.live_flow_schema import (
    COLLECTOR_VERSION,
    LIVE_FLOW_V1_FEATURE_NAMES,
    SCHEMA_VERSION,
    CollectorMetadata,
    MissingReason,
    export_live_flow_v1,
)
from app.security.network_monitor import PacketRecord


def packet(
    timestamp: float,
    source_ip: str = "192.0.2.1",
    destination_ip: str = "198.51.100.4",
    source_port: int | None = 1234,
    destination_port: int | None = 443,
    size: int = 100,
    protocol: str = "TCP",
    tcp_flags: str | None = None,
    ip_ttl: int | None = None,
    tcp_window: int | None = None,
    tcp_sequence: int | None = None,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp, source_ip=source_ip, destination_ip=destination_ip,
        protocol=protocol, source_port=source_port, destination_port=destination_port,
        packet_length=size, tcp_flags=tcp_flags, ip_ttl=ip_ttl,
        tcp_window=tcp_window, tcp_sequence=tcp_sequence,
    )


def metadata() -> CollectorMetadata:
    return CollectorMetadata("test-session-001", idle_timeout_seconds=30)


class LiveFlowV1SchemaTests(unittest.TestCase):
    def test_schema_order_version_and_metadata_are_stable(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "live_flow_v1")
        self.assertEqual(COLLECTOR_VERSION, "securework_flow_aggregator_v1")
        self.assertEqual(LIVE_FLOW_V1_FEATURE_NAMES[:6], (
            "protocol", "packet_count", "captured_bytes", "observed_duration_seconds",
            "packet_rate_pps", "captured_byte_rate_bps",
        ))
        self.assertEqual(len(LIVE_FLOW_V1_FEATURE_NAMES), len(set(LIVE_FLOW_V1_FEATURE_NAMES)))
        with self.assertRaises(ValueError):
            CollectorMetadata("", idle_timeout_seconds=30)

    def test_calculations_units_orientation_and_real_zero_are_preserved(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, size=100, ip_ttl=64, tcp_window=1000, tcp_sequence=10))
        aggregator.process_packet(packet(2, "198.51.100.4", "192.0.2.1", 443, 1234, 200,
                                          ip_ttl=63, tcp_window=2000, tcp_sequence=20))
        aggregator.process_packet(packet(4, size=300, ip_ttl=62, tcp_window=1100, tcp_sequence=11))
        flow = aggregator.finalize_all()[0]
        record = export_live_flow_v1(flow, metadata())

        self.assertEqual(tuple(record.values), LIVE_FLOW_V1_FEATURE_NAMES)
        self.assertEqual(record.values["observed_duration_seconds"], 3)
        self.assertAlmostEqual(record.values["packet_rate_pps"], 1)
        self.assertAlmostEqual(record.values["captured_byte_rate_bps"], 1600)
        self.assertEqual(record.values["source_packet_count"], 2)
        self.assertEqual(record.values["destination_packet_count"], 1)
        self.assertAlmostEqual(record.values["source_packet_fraction"], 2 / 3)
        self.assertAlmostEqual(record.values["destination_packet_fraction"], 1 / 3)
        self.assertEqual(record.values["source_ipv4_ttl"], 62)
        self.assertEqual(record.values["destination_ipv4_ttl"], 63)
        self.assertEqual(record.values["is_sm_ips_ports"], 0)
        self.assertNotIn("observed_duration_seconds", record.missingness)

    def test_zero_duration_and_insufficient_observations_are_null_not_zero(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, size=0))
        record = export_live_flow_v1(aggregator.finalize_all()[0], metadata())

        self.assertEqual(record.values["captured_bytes"], 0)
        self.assertEqual(record.values["observed_duration_seconds"], 0)
        self.assertIsNone(record.values["packet_rate_pps"])
        self.assertEqual(record.missingness["packet_rate_pps"], MissingReason.INSUFFICIENT_OBSERVATIONS)
        self.assertIsNone(record.values["destination_mean_captured_packet_bytes"])
        self.assertEqual(
            record.missingness["destination_mean_captured_packet_bytes"],
            MissingReason.INSUFFICIENT_OBSERVATIONS,
        )

    def test_non_tcp_fields_are_explicitly_not_applicable(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, protocol="UDP", tcp_window=None, tcp_sequence=None))
        aggregator.process_packet(packet(2, protocol="UDP", tcp_window=None, tcp_sequence=None))
        record = export_live_flow_v1(aggregator.finalize_all()[0], metadata())

        self.assertEqual(record.values["protocol"], "udp")
        self.assertIsNone(record.values["source_tcp_window"])
        self.assertEqual(record.missingness["source_tcp_window"], MissingReason.NOT_APPLICABLE)
        self.assertIsNone(record.values["synack_seconds"])
        self.assertEqual(record.missingness["synack_seconds"], MissingReason.NOT_APPLICABLE)

    def test_portless_flow_does_not_fabricate_endpoint_equality(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, source_port=None, destination_port=None, protocol="ICMP"))
        record = export_live_flow_v1(aggregator.finalize_all()[0], metadata())

        self.assertIsNone(record.values["is_sm_ips_ports"])
        self.assertEqual(record.missingness["is_sm_ips_ports"], MissingReason.NOT_APPLICABLE)
        exported = record.as_dict()
        self.assertNotIn("source_ip", exported)
        self.assertNotIn("destination_ip", exported)

    def test_serialized_export_retains_schema_and_collector_metadata(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1))
        collector_metadata = CollectorMetadata("review-session-42", idle_timeout_seconds=45)
        record = export_live_flow_v1(aggregator.finalize_all()[0], collector_metadata)
        exported = record.as_dict()

        self.assertEqual(exported["schema_version"], SCHEMA_VERSION)
        self.assertEqual(exported["collector_version"], COLLECTOR_VERSION)
        self.assertEqual(exported["capture_session_id"], "review-session-42")
        self.assertEqual(exported["idle_timeout_seconds"], 45)
        self.assertEqual(exported["finalization_reason"], "monitor_stopped")
        self.assertEqual(tuple(exported["features"]), LIVE_FLOW_V1_FEATURE_NAMES)
        self.assertEqual(
            set(exported["missingness"]),
            {name for name, value in exported["features"].items() if value is None},
        )


if __name__ == "__main__":
    unittest.main()
