"""Unit tests for payload-free flow aggregation and the fail-closed IDS gate."""
import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP

from app.security.feature_compatibility import (
    MODEL_FEATURES,
    FeatureAvailability,
    FeatureCompatibilityReport,
    FeatureMapping,
)
from app.security.flow_aggregator import LiveFlowAggregator
from app.security.ids_service import (
    FeatureCompatibilityError,
    IDSResult,
    IDSService,
    MalformedFeatureError,
    MissingFeatureError,
    SecurityEvent,
    validate_feature_record,
)
from app.security.network_monitor import NetworkMonitor, PacketRecord
from app.security.usb_checker import STATUS_APPROVED, USBAdapterStatus


def packet(
    timestamp: float = 1.0,
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
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_length=size,
        tcp_flags=tcp_flags,
        ip_ttl=ip_ttl,
        tcp_window=tcp_window,
        tcp_sequence=tcp_sequence,
    )


def complete_test_features(spkts: int) -> dict[str, object]:
    numeric = {name: 1.0 for name in MODEL_FEATURES if name not in {"proto", "service", "state"}}
    numeric["spkts"] = spkts
    return {**numeric, "proto": "tcp", "service": "-", "state": "CON"}


class FakeModel:
    feature_names_in_ = MODEL_FEATURES
    classes_ = (0, 1)

    def predict(self, frame):
        return [int(value > 1) for value in frame["spkts"]]

    def predict_proba(self, frame):
        return [[0.9, 0.1] if value <= 1 else [0.2, 0.8] for value in frame["spkts"]]


class FakeSniffer:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.running = False
        self.thread = None
        self.exception = None

    def start(self) -> None:
        self.running = True
        self.kwargs["started_callback"]()

    def stop(self, join=True) -> None:
        self.running = False


class LiveFlowAggregatorTests(unittest.TestCase):
    def test_bidirectional_flow_aggregates_counts_bytes_and_times(self) -> None:
        aggregator = LiveFlowAggregator(idle_timeout_seconds=30)
        aggregator.process_packet(packet(10, size=100))
        aggregator.process_packet(packet(11, "198.51.100.4", "192.0.2.1", 443, 1234, 200))
        aggregator.process_packet(packet(12, size=120))

        flow = aggregator.finalize_all()[0]
        self.assertEqual(flow.packet_count, 3)
        self.assertEqual(flow.source_packets, 2)
        self.assertEqual(flow.destination_packets, 1)
        self.assertEqual(flow.total_bytes, 420)
        self.assertEqual(flow.source_bytes, 220)
        self.assertEqual(flow.destination_bytes, 200)
        self.assertEqual(flow.first_seen, 10)
        self.assertEqual(flow.last_seen, 12)
        self.assertEqual(flow.duration, 2)
        self.assertEqual(flow.average_packet_size, 140)
        self.assertEqual(flow.source_interpacket_ms, 2000)

    def test_timeout_finalizes_idle_flow_and_callback_receives_snapshot(self) -> None:
        completed = []
        aggregator = LiveFlowAggregator(idle_timeout_seconds=5, on_flow_completed=completed.append)
        aggregator.process_packet(packet(1))
        expired = aggregator.process_packet(packet(7, "203.0.113.9", "203.0.113.10", 1, 2))
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].finalized_reason, "idle_timeout")
        self.assertEqual(completed, list(expired))
        self.assertEqual(aggregator.active_flow_count, 1)
        self.assertEqual(aggregator.completed_flow_count, 1)

    def test_stop_finalizes_flows_and_empty_feature_values_are_omitted(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, source_port=None, destination_port=None))
        flow = aggregator.finalize_all()[0]
        features = flow.candidate_features()
        self.assertEqual(flow.finalized_reason, "monitor_stopped")
        self.assertNotIn("rate", features)  # Zero duration is undefined, not a made-up zero.
        self.assertNotIn("is_sm_ips_ports", features)

    def test_feature_candidates_contain_only_measured_or_derived_values(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, size=100))
        aggregator.process_packet(packet(3, size=120))
        features = aggregator.finalize_all()[0].candidate_features()
        self.assertEqual(features["dur"], 2)
        self.assertEqual(features["proto"], "tcp")
        self.assertEqual(features["spkts"], 2)
        self.assertEqual(features["sbytes"], 220)
        self.assertEqual(features["rate"], 1)
        self.assertEqual(features["smean"], 110)
        self.assertFalse(any("payload" in name for name in features))
        self.assertNotIn("service", features)

    def test_candidate_transformations_keep_local_units_and_omit_unknowns(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, size=100))
        aggregator.process_packet(packet(2, "198.51.100.4", "192.0.2.1", 443, 1234, 200))
        aggregator.process_packet(packet(4, size=300))
        aggregator.process_packet(packet(6, size=200))
        features = aggregator.finalize_all()[0].candidate_features()

        self.assertEqual(features["dur"], 5)  # seconds
        self.assertAlmostEqual(features["rate"], 0.8)  # packets per second
        self.assertAlmostEqual(features["sload"], 960)  # captured bits per second
        self.assertAlmostEqual(features["dload"], 320)  # captured bits per second
        self.assertAlmostEqual(features["sinpkt"], 2500)  # milliseconds
        self.assertAlmostEqual(features["sjit"], 1000)  # milliseconds
        self.assertEqual(features["smean"], 200)  # captured bytes per packet
        self.assertEqual(features["dmean"], 200)  # captured bytes per packet
        self.assertNotIn("dinpkt", features)
        self.assertNotIn("djit", features)
        self.assertNotIn("service", features)
        self.assertNotIn("sloss", features)
        self.assertNotIn("ct_src_ltm", features)

    def test_malformed_packet_record_is_ignored(self) -> None:
        aggregator = LiveFlowAggregator()
        malformed = packet(timestamp=float("nan"))
        self.assertEqual(aggregator.process_packet(malformed), ())
        malformed_header = packet(ip_ttl=999)
        self.assertEqual(aggregator.process_packet(malformed_header), ())
        self.assertEqual(aggregator.malformed_packet_count, 2)
        self.assertEqual(aggregator.active_flow_count, 0)

    def test_tcp_handshake_metrics_require_all_observed_packets(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1.0, tcp_flags="S", ip_ttl=64, tcp_window=1000, tcp_sequence=10))
        aggregator.process_packet(packet(1.1, "198.51.100.4", "192.0.2.1", 443, 1234, 90, tcp_flags="SA", ip_ttl=63, tcp_window=2000, tcp_sequence=20))
        aggregator.process_packet(packet(1.3, tcp_flags="A", ip_ttl=64, tcp_window=1200, tcp_sequence=11))
        flow = aggregator.finalize_all()[0]
        self.assertEqual(flow.observed_tcp_state, "ESTABLISHED_OBSERVED")
        self.assertAlmostEqual(flow.synack_seconds, 0.1)
        self.assertAlmostEqual(flow.ackdat_seconds, 0.2)
        self.assertAlmostEqual(flow.tcp_handshake_seconds, 0.3)
        self.assertEqual(flow.candidate_features()["sttl"], 64)
        self.assertEqual(flow.candidate_features()["dwin"], 2000)

    def test_partial_or_retransmitted_handshake_is_not_completed(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, tcp_flags="S", tcp_sequence=10))
        aggregator.process_packet(packet(1.1, tcp_flags="S", tcp_sequence=10))  # retransmitted SYN remains counted
        flow = aggregator.finalize_all()[0]
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.observed_tcp_state, "SYN_OBSERVED")
        self.assertIsNone(flow.synack_seconds)
        self.assertNotIn("tcprtt", flow.candidate_features())

    def test_monitor_callback_reuses_existing_capture_lifecycle(self) -> None:
        adapter = USBAdapterStatus(
            status=STATUS_APPROVED,
            detected=True,
            approved=True,
            interface_name="USB Wi-Fi",
            interface_description="USB Wi-Fi Adapter",
            adapter_name="USB Wi-Fi Adapter",
            reason="approved test adapter",
        )
        monitor = NetworkMonitor(
            usb_checker=type("Checker", (), {"check": lambda self: adapter})(),
            interface_provider=lambda: [{
                "name": "USB Wi-Fi",
                "capture_name": r"\Device\NPF_TEST",
                "description": "USB Wi-Fi Adapter",
            }],
            sniffer_factory=lambda **kwargs: FakeSniffer(**kwargs),
        )
        aggregator = LiveFlowAggregator()
        callback = aggregator.process_packet
        monitor.add_packet_callback(callback)
        monitor.start_capture("USB Wi-Fi")
        captured = IP(src="192.0.2.1", dst="198.51.100.4") / TCP(sport=1234, dport=443)
        captured.time = 1.0
        monitor.process_packet(captured)
        self.assertEqual(aggregator.active_flow_count, 1)
        monitor.stop_capture()
        finalized = aggregator.finalize_all()
        self.assertEqual(len(finalized), 1)
        monitor.remove_packet_callback(callback)
        monitor.process_packet(packet(2, "203.0.113.1", "203.0.113.2", 8, 9))
        self.assertEqual(aggregator.active_flow_count, 0)


class IDSCompatibilityAndServiceTests(unittest.TestCase):
    def test_current_feature_mapping_blocks_live_predictions(self) -> None:
        report = FeatureCompatibilityReport()
        self.assertEqual(set(report.feature_mapping), set(MODEL_FEATURES))
        self.assertFalse(report.live_prediction_enabled)
        self.assertEqual(set(report.compatible_feature_names), {"proto", "is_sm_ips_ports"})
        self.assertEqual(len(report.partially_derivable_feature_names), 24)
        self.assertEqual(len(report.blocked_feature_names), 40)
        assessment = report.assess({"dur": 1.0, "proto": "tcp"})
        self.assertFalse(assessment.compatible)
        self.assertIn("service", assessment.missing_features)

    def test_semantic_requirements_block_numeric_lookalikes(self) -> None:
        report = FeatureCompatibilityReport()
        self.assertFalse(report.feature_mapping["spkts"].semantics_reproducible)
        self.assertTrue(report.feature_mapping["spkts"].requires_directional_state)
        self.assertTrue(report.feature_mapping["tcprtt"].requires_tcp_state)
        self.assertTrue(report.feature_mapping["ct_src_ltm"].requires_historical_statistics)
        self.assertTrue(report.feature_mapping["service"].requires_application_inspection)
        self.assertFalse(report.assess(complete_test_features(1)).compatible)

    def test_only_verified_mapping_entries_can_be_compatible(self) -> None:
        report = FeatureCompatibilityReport()
        compatible = {
            name for name, mapping in report.feature_mapping.items()
            if mapping.semantics_reproducible
        }
        self.assertEqual(compatible, {"proto", "is_sm_ips_ports"})
        self.assertTrue(all(
            report.feature_mapping[name].availability in {
                FeatureAvailability.DIRECT,
                FeatureAvailability.EQUIVALENT,
            }
            for name in compatible
        ))
        self.assertFalse(report.live_prediction_enabled)

    def test_feature_validation_rejects_missing_malformed_and_extra_fields(self) -> None:
        with self.assertRaises(MissingFeatureError):
            validate_feature_record({"dur": 1.0})
        complete = complete_test_features(1)
        complete["dur"] = "fast"
        with self.assertRaises(MalformedFeatureError):
            validate_feature_record(complete)
        extra = complete_test_features(1)
        extra["payload"] = "must not enter the model"
        with self.assertRaises(MalformedFeatureError):
            validate_feature_record(extra)

    def test_missing_and_corrupt_models_are_reported_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            missing = IDSService(Path(temporary) / "missing.joblib")
            self.assertFalse(missing.load_model())
            self.assertEqual(missing.model_status, "MISSING")
            corrupt_path = Path(temporary) / "corrupt.joblib"
            corrupt_path.write_bytes(b"not a model")
            corrupt = IDSService(corrupt_path)
            self.assertFalse(corrupt.load_model())
            self.assertEqual(corrupt.model_status, "ERROR")

    def test_candidate_live_flow_is_reviewed_but_never_predicted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = IDSService(Path(temporary) / "not-present.joblib")
            flow_builder = LiveFlowAggregator()
            flow_builder.process_packet(packet(1))
            flow = flow_builder.finalize_all()[0]
            review = service.inspect_completed_flow(flow)
        self.assertEqual(review.status, "COMPATIBILITY_INCOMPLETE")
        self.assertIsNone(review.prediction)
        self.assertGreater(len(review.missing_features), 0)
        self.assertEqual(service.flows_checked, 1)
        self.assertEqual(service.detections, 0)
        self.assertEqual(service.events, ())

    def test_prediction_paths_only_run_with_explicit_full_compatible_schema(self) -> None:
        compatible_mapping = {
            name: FeatureMapping(
                FeatureAvailability.DIRECT,
                "Test-only complete adapter",
                semantics_reproducible=True,
            )
            for name in MODEL_FEATURES
        }
        test_compatibility = FeatureCompatibilityReport(compatible_mapping)
        with tempfile.TemporaryDirectory() as temporary:
            model_path = Path(temporary) / "fake.joblib"
            model_path.touch()
            service = IDSService(
                model_path,
                compatibility=test_compatibility,
                model_loader=lambda _path: FakeModel(),
            )
            self.assertTrue(service.load_model())
            normal = service.predict_features(complete_test_features(1), "normal-flow")
            attack = service.predict_features(complete_test_features(2), "attack-flow")
        self.assertEqual(normal.prediction, "Normal")
        self.assertFalse(normal.is_attack)
        self.assertEqual(attack.prediction, "Attack")
        self.assertTrue(attack.is_attack)
        self.assertEqual(attack.attack_probability, 0.8)

    def test_default_service_refuses_complete_values_when_semantics_are_not_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = IDSService(Path(temporary) / "model.joblib")
            with self.assertRaises(FeatureCompatibilityError):
                service.predict_features(complete_test_features(2))

    def test_security_event_contains_flow_metadata_and_signal_severity(self) -> None:
        aggregator = LiveFlowAggregator()
        aggregator.process_packet(packet(1, size=150))
        flow = aggregator.finalize_all()[0]
        result = IDSResult(flow.flow_id, "Attack", True, 0.8, "2026-01-01T00:00:00+00:00")
        event = SecurityEvent.from_prediction(flow, result)
        self.assertEqual(event.severity, "SUSPICIOUS")
        self.assertEqual(event.prediction, "Attack")
        self.assertEqual(event.byte_count, 150)
        self.assertIn("not confirmation", event.message)
        self.assertFalse(hasattr(event, "payload"))

    def test_analysis_start_stop_refuses_incompatible_live_service(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            service = IDSService(Path(temporary) / "model.joblib")
            with self.assertRaises(FeatureCompatibilityError):
                service.start_analysis()
            service.stop_analysis()
            self.assertFalse(service.analysis_active)


if __name__ == "__main__":
    unittest.main()
