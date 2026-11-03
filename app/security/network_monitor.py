"""Safe packet-metadata collection and basic directional flow tracking."""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, TypeAlias

from app.security.usb_checker import STATUS_APPROVED, USBAdapterChecker

logger = logging.getLogger(__name__)

STOPPED = "STOPPED"
STARTING = "STARTING"
RUNNING = "RUNNING"
STOPPING = "STOPPING"
ERROR = "ERROR"

FlowKey: TypeAlias = tuple[str, str, int | None, int | None, str]


class NetworkMonitorError(RuntimeError):
    """Raised when interface selection or network capture cannot proceed."""


@dataclass(frozen=True)
class NetworkInterface:
    """Interface metadata separated from Scapy's runtime interface objects."""

    name: str
    capture_name: str
    description: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    status: str | None = None
    interface_id: str | None = None
    approved: bool = False

    @property
    def display_name(self) -> str:
        return self.name or self.description or self.capture_name


@dataclass(frozen=True)
class PacketRecord:
    """Payload-free packet metadata suitable for later ML feature engineering."""

    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    packet_length: int
    tcp_flags: str | None = None
    ip_ttl: int | None = None
    tcp_window: int | None = None
    tcp_sequence: int | None = None
    tcp_acknowledgement: int | None = None

    @property
    def flow_key(self) -> FlowKey:
        return (
            self.source_ip,
            self.destination_ip,
            self.source_port,
            self.destination_port,
            self.protocol,
        )


@dataclass(frozen=True)
class FlowRecord:
    """Statistics for one directional five-tuple flow."""

    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    packet_count: int
    total_bytes: int
    first_seen: float
    last_seen: float

    @property
    def key(self) -> FlowKey:
        return (
            self.source_ip,
            self.destination_ip,
            self.source_port,
            self.destination_port,
            self.protocol,
        )

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def average_packet_size(self) -> float:
        return self.total_bytes / self.packet_count if self.packet_count else 0.0


def extract_packet_features(packet: Any) -> PacketRecord | None:
    """Extract only IPv4/TCP/UDP/ICMP metadata; never retain packet payloads."""
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP

        if not packet.haslayer(IP):
            return None
        ip_layer = packet[IP]
        source_ip = str(ip_layer.src)
        destination_ip = str(ip_layer.dst)
        source_port: int | None = None
        destination_port: int | None = None
        tcp_flags: str | None = None
        tcp_window: int | None = None
        tcp_sequence: int | None = None
        tcp_acknowledgement: int | None = None

        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "TCP"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
            tcp_flags = str(transport.flags)
            tcp_window = int(transport.window)
            tcp_sequence = int(transport.seq)
            tcp_acknowledgement = int(transport.ack)
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "UDP"
            source_port = int(transport.sport)
            destination_port = int(transport.dport)
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = f"IP-{int(ip_layer.proto)}"

        packet_time = getattr(packet, "time", None)
        timestamp = float(packet_time) if packet_time is not None else time.time()
        return PacketRecord(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            packet_length=int(len(packet)),
            tcp_flags=tcp_flags,
            ip_ttl=int(ip_layer.ttl),
            tcp_window=tcp_window,
            tcp_sequence=tcp_sequence,
            tcp_acknowledgement=tcp_acknowledgement,
        )
    except Exception as exc:
        logger.debug("Ignoring malformed or unsupported packet: %s", exc)
        return None


class NetworkMonitor:
    """Discover approved interfaces, capture metadata, and maintain flow counts.

    Capture is opt-in through :meth:`start_capture`. Interfaces are only marked
    approved when they match the existing USB adapter check; the monitor never
    falls back to another interface.
    """

    def __init__(
        self,
        usb_checker: USBAdapterChecker | None = None,
        interface_provider: Callable[[], Iterable[Any]] | None = None,
        sniffer_factory: Callable[..., Any] | None = None,
        packet_callback: Callable[[PacketRecord], None] | None = None,
        startup_timeout: float = 5.0,
    ) -> None:
        self.usb_checker = usb_checker or USBAdapterChecker()
        self._interface_provider = interface_provider or self._scapy_interface_provider
        self._sniffer_factory = sniffer_factory
        self._startup_timeout = startup_timeout
        self._lock = threading.RLock()
        self._flows: dict[FlowKey, FlowRecord] = {}
        self._packet_count = 0
        self._packet_callbacks: list[Callable[[PacketRecord], None]] = []
        if packet_callback is not None:
            self._packet_callbacks.append(packet_callback)
        self._interfaces: list[NetworkInterface] = []
        self._selected_interface: NetworkInterface | None = None
        self._sniffer: Any = None
        self._state = STOPPED
        self._last_error: str | None = None
        self._selection_error: str | None = None
        logger.info("Network monitor initialized; packet capture is stopped")

    def add_packet_callback(self, callback: Callable[[PacketRecord], None]) -> None:
        """Subscribe to parsed metadata without creating another capture loop."""
        with self._lock:
            if callback not in self._packet_callbacks:
                self._packet_callbacks.append(callback)

    def remove_packet_callback(self, callback: Callable[[PacketRecord], None]) -> None:
        """Remove a packet metadata observer."""
        with self._lock:
            try:
                self._packet_callbacks.remove(callback)
            except ValueError:
                pass

    @property
    def status(self) -> str:
        self._refresh_capture_state()
        with self._lock:
            return self._state

    @property
    def last_error(self) -> str | None:
        self._refresh_capture_state()
        with self._lock:
            return self._last_error

    @property
    def selection_error(self) -> str | None:
        with self._lock:
            return self._selection_error

    @property
    def selected_interface(self) -> NetworkInterface | None:
        with self._lock:
            return self._selected_interface

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def flow_count(self) -> int:
        with self._lock:
            return len(self._flows)

    @property
    def flows(self) -> tuple[FlowRecord, ...]:
        with self._lock:
            return tuple(self._flows.values())

    def is_running(self) -> bool:
        return self.status == RUNNING

    def is_active(self) -> bool:
        status = self.status
        if status in (STARTING, RUNNING, STOPPING):
            return True
        with self._lock:
            sniffer = self._sniffer
        thread = getattr(sniffer, "thread", None) if sniffer is not None else None
        return bool(thread is not None and thread.is_alive())

    def discover_interfaces(self) -> list[NetworkInterface]:
        """List interfaces and mark only the USB-checker-matched interface approved."""
        logger.info("Discovering network interfaces")
        try:
            raw_interfaces = list(self._interface_provider())
            interfaces = [self._normalize_interface(raw) for raw in raw_interfaces]
        except Exception as exc:
            message = f"Unable to discover network interfaces: {exc}"
            logger.error(message)
            with self._lock:
                self._interfaces = []
                self._selection_error = message
            raise NetworkMonitorError(message) from exc

        try:
            approval = self.usb_checker.check()
        except Exception as exc:
            approval = None
            approval_reason = f"Unable to verify the approved USB adapter: {exc}"
        else:
            approval_reason = approval.reason if approval else "USB adapter status is unavailable."

        approved_names: set[str] = set()
        if approval and approval.status == STATUS_APPROVED:
            approved_names = {
                str(value).strip().casefold()
                for value in (
                    approval.interface_name,
                    approval.interface_description,
                    approval.adapter_name,
                )
                if value
            }

        marked = [
            NetworkInterface(
                name=item.name,
                capture_name=item.capture_name,
                description=item.description,
                ip_address=item.ip_address,
                mac_address=item.mac_address,
                status=item.status,
                interface_id=item.interface_id,
                approved=self._matches_approved_interface(item, approved_names),
            )
            for item in interfaces
        ]
        approved_count = sum(interface.approved for interface in marked)
        with self._lock:
            self._interfaces = marked
            if approved_count:
                self._selection_error = None
            elif not marked:
                self._selection_error = "No network interfaces were found."
            elif approval and approval.status == STATUS_APPROVED:
                self._selection_error = (
                    "The approved USB adapter was found, but its Scapy interface could not be matched."
                )
            else:
                self._selection_error = approval_reason or "No approved USB Wi-Fi interface is available."

        logger.info(
            "Discovered %d network interface(s); %d match the approved USB Wi-Fi adapter",
            len(marked), approved_count,
        )
        return list(marked)

    def start_capture(self, interface: NetworkInterface | str | None = None) -> NetworkInterface:
        """Start asynchronous metadata capture on an explicitly approved interface."""
        with self._lock:
            if self._state in (STARTING, RUNNING, STOPPING):
                raise NetworkMonitorError("Network capture is already active or changing state.")

        interfaces = self.discover_interfaces()
        approved_interfaces = [item for item in interfaces if item.approved]
        selected = self._resolve_interface(interface, approved_interfaces)
        if selected is None:
            message = self.selection_error or "No approved USB Wi-Fi interface is available."
            self._set_error(message)
            raise NetworkMonitorError(message)

        started = threading.Event()

        def on_started() -> None:
            with self._lock:
                if self._state == STARTING:
                    self._state = RUNNING
                    self._last_error = None
                    logger.info("Packet capture started on interface %s", selected.name)
            started.set()

        try:
            sniffer_factory = self._sniffer_factory or self._create_scapy_sniffer
            sniffer = sniffer_factory(
                iface=selected.capture_name,
                prn=self.process_packet,
                store=False,
                started_callback=on_started,
            )
            with self._lock:
                self._selected_interface = selected
                self._sniffer = sniffer
                self._state = STARTING
                self._last_error = None
            sniffer.start()
        except Exception as exc:
            message = self._capture_error_message(exc)
            self._set_error(message)
            raise NetworkMonitorError(message) from exc

        if not started.wait(self._startup_timeout):
            exception = getattr(sniffer, "exception", None)
            if exception is not None:
                message = self._capture_error_message(exception)
            else:
                message = "Timed out while initializing packet capture."
            try:
                if getattr(sniffer, "running", False):
                    sniffer.stop(join=True)
            except Exception:
                logger.exception("Failed to clean up a capture that did not initialize")
            self._set_error(message)
            raise NetworkMonitorError(message)

        return selected

    def stop_capture(self) -> None:
        """Stop and join the Scapy capture thread before returning."""
        with self._lock:
            sniffer = self._sniffer
            if sniffer is None:
                self._state = STOPPED
                self._last_error = None
                return
            if self._state == STOPPING:
                return
            self._state = STOPPING

        try:
            if getattr(sniffer, "running", False):
                sniffer.stop(join=True)
            else:
                thread = getattr(sniffer, "thread", None)
                if thread is not None and thread.is_alive():
                    thread.join(timeout=self._startup_timeout)
                    if thread.is_alive():
                        raise TimeoutError("Capture thread did not stop before the timeout.")
        except Exception as exc:
            message = f"Unable to stop packet capture cleanly: {exc}"
            self._set_error(message)
            logger.error(message)
            raise NetworkMonitorError(message) from exc

        with self._lock:
            thread = getattr(sniffer, "thread", None)
            if thread is not None and thread.is_alive():
                message = "Capture thread is still running after stop was requested."
                self._state = ERROR
                self._last_error = message
                logger.error(message)
                raise NetworkMonitorError(message)
            self._sniffer = None
            self._state = STOPPED
            self._last_error = None
        logger.info("Packet capture stopped")

    def process_packet(self, packet: Any) -> PacketRecord | None:
        """Convert a Scapy packet to metadata and update its directional flow."""
        record = extract_packet_features(packet)
        if record is None:
            return None

        with self._lock:
            previous = self._flows.get(record.flow_key)
            if previous is None:
                flow = FlowRecord(
                    source_ip=record.source_ip,
                    destination_ip=record.destination_ip,
                    source_port=record.source_port,
                    destination_port=record.destination_port,
                    protocol=record.protocol,
                    packet_count=1,
                    total_bytes=record.packet_length,
                    first_seen=record.timestamp,
                    last_seen=record.timestamp,
                )
            else:
                flow = FlowRecord(
                    source_ip=previous.source_ip,
                    destination_ip=previous.destination_ip,
                    source_port=previous.source_port,
                    destination_port=previous.destination_port,
                    protocol=previous.protocol,
                    packet_count=previous.packet_count + 1,
                    total_bytes=previous.total_bytes + record.packet_length,
                    first_seen=previous.first_seen,
                    last_seen=max(previous.last_seen, record.timestamp),
                )
            self._flows[record.flow_key] = flow
            self._packet_count += 1

            packet_callbacks = tuple(self._packet_callbacks)
        for callback in packet_callbacks:
            try:
                callback(record)
            except Exception:
                logger.exception("Network packet metadata callback failed")
        return record

    def _refresh_capture_state(self) -> None:
        with self._lock:
            sniffer = self._sniffer
            state = self._state
        if sniffer is None or state not in (STARTING, RUNNING):
            return

        thread = getattr(sniffer, "thread", None)
        if thread is None or thread.is_alive():
            return
        exception = getattr(sniffer, "exception", None)
        with self._lock:
            if self._sniffer is not sniffer or self._state not in (STARTING, RUNNING):
                return
            if exception is not None:
                self._state = ERROR
                self._last_error = self._capture_error_message(exception)
                logger.error("Packet capture failed: %s", self._last_error)
            elif self._state == STARTING:
                self._state = ERROR
                self._last_error = "Packet capture stopped before initialization completed."
                logger.error(self._last_error)
            else:
                self._state = STOPPED
                logger.info("Packet capture ended")

    def _resolve_interface(
        self,
        requested: NetworkInterface | str | None,
        approved_interfaces: list[NetworkInterface],
    ) -> NetworkInterface | None:
        if not approved_interfaces:
            return None
        if requested is None:
            if len(approved_interfaces) == 1:
                return approved_interfaces[0]
            self._selection_error = "Select an approved USB Wi-Fi interface before starting capture."
            return None

        identity = (
            requested.capture_name if isinstance(requested, NetworkInterface) else str(requested)
        ).strip().casefold()
        for item in approved_interfaces:
            if identity in {
                item.name.casefold(),
                item.capture_name.casefold(),
                (item.description or "").casefold(),
                (item.interface_id or "").casefold(),
            }:
                return item
        self._selection_error = "The selected interface is unavailable or is not approved."
        return None

    @staticmethod
    def _matches_approved_interface(
        interface: NetworkInterface,
        approved_names: set[str],
    ) -> bool:
        candidates = {
            interface.name.strip().casefold(),
            interface.capture_name.strip().casefold(),
            (interface.description or "").strip().casefold(),
            (interface.interface_id or "").strip().casefold(),
        }
        return bool(candidates & approved_names)

    @staticmethod
    def _normalize_interface(raw: Any) -> NetworkInterface:
        if isinstance(raw, NetworkInterface):
            return raw
        if isinstance(raw, Mapping):
            get = raw.get
        else:
            get = lambda key, default=None: getattr(raw, key, default)

        name = str(get("name", "") or "").strip()
        capture_name = str(get("capture_name", "") or "").strip()
        description = get("description")
        interface_id = get("interface_id") or get("guid")
        if not name or not capture_name:
            raise ValueError("Interface data must include a friendly name and capture name.")
        return NetworkInterface(
            name=name,
            capture_name=capture_name,
            description=str(description) if description else None,
            ip_address=str(get("ip_address") or "") or None,
            mac_address=str(get("mac_address") or "") or None,
            status=str(get("status") or "") or None,
            interface_id=str(interface_id) if interface_id else None,
            approved=bool(get("approved", False)),
        )

    @staticmethod
    def _scapy_interface_provider() -> list[dict[str, str | None]]:
        from scapy.all import conf

        interfaces: list[dict[str, str | None]] = []
        for interface in conf.ifaces.values():
            name = str(getattr(interface, "name", "") or "").strip()
            # Scapy also lists WFP/NDIS filter endpoints as separate interfaces.
            if not name or re.search(r"-\d{4}$", name):
                continue
            capture_name = str(getattr(interface, "network_name", "") or "").strip()
            if not capture_name:
                continue
            is_valid = getattr(interface, "is_valid", None)
            status = "Available" if is_valid is not False else "Unavailable"
            interfaces.append(
                {
                    "name": name,
                    "capture_name": capture_name,
                    "description": getattr(interface, "description", None),
                    "ip_address": getattr(interface, "ip", None),
                    "mac_address": getattr(interface, "mac", None),
                    "status": status,
                    "interface_id": getattr(interface, "guid", None),
                }
            )
        return interfaces

    @staticmethod
    def _create_scapy_sniffer(**kwargs: Any) -> Any:
        from scapy.all import AsyncSniffer, conf

        if os.name == "nt" and not bool(getattr(conf, "use_pcap", False)):
            raise NetworkMonitorError(
                "Scapy has no libpcap provider. Install Npcap in WinPcap API-compatible mode "
                "before starting capture."
            )
        return AsyncSniffer(**kwargs)

    @staticmethod
    def _capture_error_message(exc: Exception) -> str:
        message = str(exc).strip() or exc.__class__.__name__
        lowered = message.casefold()
        if "npcap" in lowered or "libpcap" in lowered or "pcap" in lowered:
            return f"Npcap/libpcap capture is unavailable: {message}"
        if "access is denied" in lowered or "permission" in lowered:
            return f"Packet capture permission was denied: {message}"
        return f"Packet capture failed: {message}"

    def _set_error(self, message: str) -> None:
        with self._lock:
            self._state = ERROR
            self._last_error = message
        logger.error(message)
