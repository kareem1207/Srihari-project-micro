"""Deterministic packet, flow, and capture-state tests without live capture."""
import unittest
from types import SimpleNamespace

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from app.security.network_monitor import (
    ERROR,
    RUNNING,
    STOPPED,
    FlowRecord,
    NetworkMonitor,
    NetworkMonitorError,
    PacketRecord,
    extract_packet_features,
)
from app.security.usb_checker import STATUS_APPROVED, USBAdapterStatus


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


class NetworkMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.approved = USBAdapterStatus(
            status=STATUS_APPROVED,
            detected=True,
            approved=True,
            adapter_name="Generic USB Wi-Fi Adapter",
            interface_name="Wi-Fi USB",
            interface_description="Generic USB Wi-Fi Adapter",
            device_id=r"USB\VID_TEST\DEVICE",
            connection_type="USB",
            reason="Matches test policy",
        )
        self.interface = {
            "name": "Wi-Fi USB",
            "capture_name": r"\Device\NPF_{TEST-GUID}",
            "description": "Generic USB Wi-Fi Adapter",
            "ip_address": "192.0.2.10",
            "mac_address": "00:11:22:33:44:55",
            "status": "Available",
            "interface_id": "{TEST-GUID}",
        }
        self.checker = SimpleNamespace(check=lambda: self.approved)

    def make_monitor(self, records=None, sniffer_factory=None, checker=None) -> NetworkMonitor:
        return NetworkMonitor(
            usb_checker=checker or self.checker,
            interface_provider=lambda: [self.interface] if records is None else records,
            sniffer_factory=sniffer_factory,
        )

    def test_ipv4_tcp_feature_extraction(self) -> None:
        packet = Ether(dst="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=4321, dport=443, flags="S")
        packet.time = 100.0
        record = extract_packet_features(packet)
        self.assertIsInstance(record, PacketRecord)
        self.assertEqual(record.source_ip, "192.0.2.1")
        self.assertEqual(record.destination_ip, "198.51.100.2")
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual(record.source_port, 4321)
        self.assertEqual(record.destination_port, 443)
        self.assertEqual(record.tcp_flags, "S")
        self.assertEqual(record.ip_ttl, 64)
        self.assertEqual(record.tcp_window, 8192)
        self.assertEqual(record.tcp_sequence, 0)
        self.assertEqual(record.tcp_acknowledgement, 0)
        self.assertEqual(record.timestamp, 100.0)

    def test_ipv4_udp_feature_extraction(self) -> None:
        packet = Ether(dst="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=5353, dport=53)
        record = extract_packet_features(packet)
        self.assertEqual(record.protocol, "UDP")
        self.assertEqual(record.source_port, 5353)
        self.assertEqual(record.destination_port, 53)
        self.assertIsNone(record.tcp_flags)

    def test_icmp_feature_extraction_has_no_ports(self) -> None:
        packet = Ether(dst="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2") / ICMP()
        record = extract_packet_features(packet)
        self.assertEqual(record.protocol, "ICMP")
        self.assertIsNone(record.source_port)
        self.assertIsNone(record.destination_port)

    def test_packet_length_is_extracted_without_payload_content(self) -> None:
        packet = Ether(dst="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2") / UDP() / b"private payload"
        record = extract_packet_features(packet)
        self.assertEqual(record.packet_length, len(packet))
        self.assertFalse(hasattr(record, "payload"))

    def test_flow_creation_and_statistics_update(self) -> None:
        monitor = self.make_monitor()
        first = Ether(dst="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=1000, dport=2000)
        second = Ether(dst="00:11:22:33:44:55") / IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=1000, dport=2000)
        first.time = 10.0
        second.time = 13.0
        first_length = len(first)
        second_length = len(second)

        self.assertIsNotNone(monitor.process_packet(first))
        self.assertIsNotNone(monitor.process_packet(second))
        flow = monitor.flows[0]
        self.assertIsInstance(flow, FlowRecord)
        self.assertEqual(flow.packet_count, 2)
        self.assertEqual(flow.total_bytes, first_length + second_length)
        self.assertEqual(flow.first_seen, 10.0)
        self.assertEqual(flow.last_seen, 13.0)
        self.assertEqual(flow.duration, 3.0)
        self.assertEqual(flow.average_packet_size, (first_length + second_length) / 2)
        self.assertEqual(monitor.packet_count, 2)
        self.assertEqual(monitor.flow_count, 1)

    def test_multiple_packets_in_same_directional_flow_share_key(self) -> None:
        monitor = self.make_monitor()
        for timestamp in (1.0, 2.0, 3.0):
            packet = IP(src="192.0.2.3", dst="198.51.100.8") / TCP(sport=123, dport=80)
            packet.time = timestamp
            monitor.process_packet(packet)
        self.assertEqual(monitor.flow_count, 1)
        self.assertEqual(monitor.flows[0].packet_count, 3)

    def test_multiple_flows_are_tracked_separately(self) -> None:
        monitor = self.make_monitor()
        packets = [
            IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1000, dport=80),
            IP(src="192.0.2.1", dst="198.51.100.2") / TCP(sport=1001, dport=80),
            IP(src="192.0.2.1", dst="198.51.100.3") / UDP(sport=1000, dport=80),
        ]
        for packet in packets:
            monitor.process_packet(packet)
        self.assertEqual(monitor.flow_count, 3)

    def test_malformed_and_non_ipv4_packets_are_ignored(self) -> None:
        self.assertIsNone(extract_packet_features(object()))
        self.assertIsNone(extract_packet_features(Ether() / b"not an IPv4 packet"))

    def test_capture_start_and_stop_state(self) -> None:
        fake_sniffer = FakeSniffer()
        monitor = self.make_monitor(sniffer_factory=lambda **kwargs: self._sniffer_with_kwargs(fake_sniffer, kwargs))
        self.assertEqual(monitor.status, STOPPED)
        selected = monitor.start_capture("Wi-Fi USB")
        self.assertEqual(selected.capture_name, self.interface["capture_name"])
        self.assertEqual(fake_sniffer.kwargs["iface"], self.interface["capture_name"])
        self.assertFalse(fake_sniffer.kwargs["store"])
        self.assertEqual(monitor.status, RUNNING)
        self.assertTrue(monitor.is_running())
        monitor.stop_capture()
        self.assertEqual(monitor.status, STOPPED)
        self.assertFalse(monitor.is_running())

    @staticmethod
    def _sniffer_with_kwargs(sniffer: FakeSniffer, kwargs: dict) -> FakeSniffer:
        sniffer.kwargs = kwargs
        return sniffer

    def test_interface_unavailable_or_unapproved_is_rejected(self) -> None:
        monitor = self.make_monitor()
        with self.assertRaisesRegex(NetworkMonitorError, "unavailable or is not approved"):
            monitor.start_capture("Other interface")
        self.assertEqual(monitor.status, ERROR)
        self.assertIsNotNone(monitor.last_error)

    def test_no_approved_interface_is_never_used_as_fallback(self) -> None:
        unapproved = USBAdapterStatus(
            status="not_approved",
            detected=True,
            approved=False,
            reason="Adapter is not approved",
        )
        monitor = self.make_monitor(checker=SimpleNamespace(check=lambda: unapproved))
        with self.assertRaisesRegex(NetworkMonitorError, "Adapter is not approved"):
            monitor.start_capture()
        self.assertEqual(monitor.status, ERROR)

    def test_interface_description_matches_approved_adapter_when_names_differ(self) -> None:
        scapy_named_differently = {
            **self.interface,
            "name": "Wi-Fi 2",
            "description": self.approved.interface_description,
        }
        monitor = self.make_monitor(records=[scapy_named_differently])
        interfaces = monitor.discover_interfaces()
        self.assertEqual(len(interfaces), 1)
        self.assertTrue(interfaces[0].approved)
        self.assertEqual(interfaces[0].name, "Wi-Fi 2")

    def test_capture_identity_matches_approved_usb_interface_name(self) -> None:
        scapy_identity_differs = {
            **self.interface,
            "name": "Local Area Connection* 10",
            "description": "WAN Miniport (Network Monitor)",
            "capture_name": self.approved.interface_name,
        }
        monitor = self.make_monitor(records=[scapy_identity_differs])

        interfaces = monitor.discover_interfaces()

        self.assertEqual(len(interfaces), 1)
        self.assertTrue(interfaces[0].approved)
        self.assertEqual(interfaces[0].capture_name, "Wi-Fi USB")


if __name__ == "__main__":
    unittest.main()
