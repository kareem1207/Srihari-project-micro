"""Payload-free, bidirectional flow aggregation for live monitoring."""
from __future__ import annotations

import logging
import math
import numbers
import threading
import uuid
from dataclasses import dataclass, field
from typing import Callable

from app.security.network_monitor import PacketRecord

logger = logging.getLogger(__name__)
Endpoint = tuple[str, int | None]
BidirectionalFlowKey = tuple[Endpoint, Endpoint, str]


@dataclass(frozen=True)
class CompletedFlow:
    """Metadata and aggregates for one completed bidirectional flow.

    The source/destination orientation is the first packet observed, not a claim
    about client/server roles or equivalence with the UNSW-NB15 exporter.
    """

    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int
    total_bytes: int
    source_packets: int
    destination_packets: int
    source_bytes: int
    destination_bytes: int
    source_interpacket_ms: float | None
    destination_interpacket_ms: float | None
    source_jitter_ms: float | None
    destination_jitter_ms: float | None
    source_ttl: int | None
    destination_ttl: int | None
    source_tcp_window: int | None
    destination_tcp_window: int | None
    source_initial_tcp_sequence: int | None
    destination_initial_tcp_sequence: int | None
    observed_tcp_state: str | None
    synack_seconds: float | None
    ackdat_seconds: float | None
    tcp_handshake_seconds: float | None
    finalized_reason: str

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def average_packet_size(self) -> float:
        return self.total_bytes / self.packet_count if self.packet_count else 0.0

    @property
    def packet_rate(self) -> float | None:
        return self.packet_count / self.duration if self.duration > 0 else None

    @property
    def source_load_bps(self) -> float | None:
        return self.source_bytes * 8 / self.duration if self.duration > 0 else None

    @property
    def destination_load_bps(self) -> float | None:
        return self.destination_bytes * 8 / self.duration if self.duration > 0 else None

    @property
    def source_mean_packet_size(self) -> float | None:
        return self.source_bytes / self.source_packets if self.source_packets else None

    @property
    def destination_mean_packet_size(self) -> float | None:
        return self.destination_bytes / self.destination_packets if self.destination_packets else None

    def candidate_features(self) -> dict[str, int | float | str]:
        """Return only observed/derived candidates, never placeholders for gaps.

        Candidate values are useful for review and tests. They are not asserted
        to use the same exporter semantics as UNSW-NB15 and are not sent to the
        trained model by the current compatibility gate.
        """
        result: dict[str, int | float | str] = {
            "dur": self.duration,
            "proto": self.protocol.casefold(),
            "spkts": self.source_packets,
            "dpkts": self.destination_packets,
            "sbytes": self.source_bytes,
            "dbytes": self.destination_bytes,
        }
        if self.packet_rate is not None:
            result["rate"] = self.packet_rate
        if self.source_load_bps is not None:
            result["sload"] = self.source_load_bps
        if self.destination_load_bps is not None:
            result["dload"] = self.destination_load_bps
        if self.source_interpacket_ms is not None:
            result["sinpkt"] = self.source_interpacket_ms
        if self.destination_interpacket_ms is not None:
            result["dinpkt"] = self.destination_interpacket_ms
        if self.source_jitter_ms is not None:
            result["sjit"] = self.source_jitter_ms
        if self.destination_jitter_ms is not None:
            result["djit"] = self.destination_jitter_ms
        if self.source_mean_packet_size is not None:
            result["smean"] = self.source_mean_packet_size
        if self.destination_mean_packet_size is not None:
            result["dmean"] = self.destination_mean_packet_size
        # These TCP/IP values are observed from headers only. They are useful
        # diagnostics, but remain blocked by the compatibility report because
        # their orientation and UNSW-NB15 exporter semantics are unverified.
        if self.source_ttl is not None:
            result["sttl"] = self.source_ttl
        if self.destination_ttl is not None:
            result["dttl"] = self.destination_ttl
        if self.source_tcp_window is not None:
            result["swin"] = self.source_tcp_window
        if self.destination_tcp_window is not None:
            result["dwin"] = self.destination_tcp_window
        if self.source_initial_tcp_sequence is not None:
            result["stcpb"] = self.source_initial_tcp_sequence
        if self.destination_initial_tcp_sequence is not None:
            result["dtcpb"] = self.destination_initial_tcp_sequence
        if self.observed_tcp_state is not None:
            result["state"] = self.observed_tcp_state
        if self.synack_seconds is not None:
            result["synack"] = self.synack_seconds
        if self.ackdat_seconds is not None:
            result["ackdat"] = self.ackdat_seconds
        if self.tcp_handshake_seconds is not None:
            result["tcprtt"] = self.tcp_handshake_seconds
        if self.source_port is not None and self.destination_port is not None:
            result["is_sm_ips_ports"] = int(
                self.source_ip == self.destination_ip
                and self.source_port == self.destination_port
            )
        return result


@dataclass
class _DirectionStats:
    packets: int = 0
    byte_count: int = 0
    last_timestamp: float | None = None
    interval_total: float = 0.0
    interval_count: int = 0
    previous_interval: float | None = None
    jitter_total: float = 0.0
    jitter_count: int = 0
    ttl: int | None = None
    tcp_window: int | None = None
    initial_tcp_sequence: int | None = None

    def add(self, packet: PacketRecord) -> None:
        timestamp = float(packet.timestamp)
        byte_count = int(packet.packet_length)
        self.packets += 1
        self.byte_count += byte_count
        if self.last_timestamp is not None and timestamp > self.last_timestamp:
            interval = timestamp - self.last_timestamp
            self.interval_total += interval
            self.interval_count += 1
            if self.previous_interval is not None:
                self.jitter_total += abs(interval - self.previous_interval)
                self.jitter_count += 1
            self.previous_interval = interval
        if self.last_timestamp is None or timestamp > self.last_timestamp:
            self.last_timestamp = timestamp
        if packet.ip_ttl is not None:
            self.ttl = int(packet.ip_ttl)
        if packet.tcp_window is not None:
            self.tcp_window = int(packet.tcp_window)
        if self.initial_tcp_sequence is None and packet.tcp_sequence is not None:
            self.initial_tcp_sequence = int(packet.tcp_sequence)

    @property
    def mean_interpacket_ms(self) -> float | None:
        if not self.interval_count:
            return None
        return self.interval_total * 1000 / self.interval_count

    @property
    def mean_jitter_ms(self) -> float | None:
        if not self.jitter_count:
            return None
        return self.jitter_total * 1000 / self.jitter_count


@dataclass
class _ActiveFlow:
    flow_id: str
    source_endpoint: Endpoint
    destination_endpoint: Endpoint
    protocol: str
    first_seen: float
    last_seen: float
    source: _DirectionStats = field(default_factory=_DirectionStats)
    destination: _DirectionStats = field(default_factory=_DirectionStats)
    syn_timestamp: float | None = None
    syn_source_endpoint: Endpoint | None = None
    synack_timestamp: float | None = None
    final_ack_timestamp: float | None = None
    observed_tcp_state: str | None = None

    def add(self, packet: PacketRecord) -> None:
        observed_source = (packet.source_ip, packet.source_port)
        stats = self.source if observed_source == self.source_endpoint else self.destination
        stats.add(packet)
        timestamp = float(packet.timestamp)
        self.first_seen = min(self.first_seen, timestamp)
        self.last_seen = max(self.last_seen, timestamp)
        self._observe_tcp(packet, observed_source)

    def _observe_tcp(self, packet: PacketRecord, observed_source: Endpoint) -> None:
        """Track only a fully observed TCP handshake; partial capture stays explicit."""
        if self.protocol.casefold() != "tcp" or not packet.tcp_flags:
            return
        flags = set(str(packet.tcp_flags).upper())
        timestamp = float(packet.timestamp)
        if "R" in flags:
            self.observed_tcp_state = "RESET_OBSERVED"
            return
        if "F" in flags:
            self.observed_tcp_state = "CLOSED_OBSERVED"
            return
        if "S" in flags and "A" not in flags:
            if self.syn_timestamp is None:
                self.syn_timestamp = timestamp
                self.syn_source_endpoint = observed_source
            self.observed_tcp_state = "SYN_OBSERVED"
            return
        if (
            "S" in flags and "A" in flags
            and self.syn_timestamp is not None
            and self.syn_source_endpoint is not None
            and observed_source != self.syn_source_endpoint
            and timestamp >= self.syn_timestamp
        ):
            if self.synack_timestamp is None:
                self.synack_timestamp = timestamp
            self.observed_tcp_state = "SYN_ACK_OBSERVED"
            return
        if (
            "A" in flags and "S" not in flags
            and self.synack_timestamp is not None
            and self.syn_source_endpoint == observed_source
            and timestamp >= self.synack_timestamp
        ):
            if self.final_ack_timestamp is None:
                self.final_ack_timestamp = timestamp
            self.observed_tcp_state = "ESTABLISHED_OBSERVED"
            return
        if self.observed_tcp_state is None:
            self.observed_tcp_state = "PARTIAL_OBSERVED"

    def complete(self, reason: str) -> CompletedFlow:
        synack_seconds = self._elapsed(self.syn_timestamp, self.synack_timestamp)
        ackdat_seconds = self._elapsed(self.synack_timestamp, self.final_ack_timestamp)
        handshake_seconds = self._elapsed(self.syn_timestamp, self.final_ack_timestamp)
        return CompletedFlow(
            flow_id=self.flow_id,
            source_ip=self.source_endpoint[0],
            destination_ip=self.destination_endpoint[0],
            source_port=self.source_endpoint[1],
            destination_port=self.destination_endpoint[1],
            protocol=self.protocol,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            packet_count=self.source.packets + self.destination.packets,
            total_bytes=self.source.byte_count + self.destination.byte_count,
            source_packets=self.source.packets,
            destination_packets=self.destination.packets,
            source_bytes=self.source.byte_count,
            destination_bytes=self.destination.byte_count,
            source_interpacket_ms=self.source.mean_interpacket_ms,
            destination_interpacket_ms=self.destination.mean_interpacket_ms,
            source_jitter_ms=self.source.mean_jitter_ms,
            destination_jitter_ms=self.destination.mean_jitter_ms,
            source_ttl=self.source.ttl,
            destination_ttl=self.destination.ttl,
            source_tcp_window=self.source.tcp_window,
            destination_tcp_window=self.destination.tcp_window,
            source_initial_tcp_sequence=self.source.initial_tcp_sequence,
            destination_initial_tcp_sequence=self.destination.initial_tcp_sequence,
            observed_tcp_state=self.observed_tcp_state,
            synack_seconds=synack_seconds,
            ackdat_seconds=ackdat_seconds,
            tcp_handshake_seconds=handshake_seconds,
            finalized_reason=reason,
        )

    @staticmethod
    def _elapsed(start: float | None, end: float | None) -> float | None:
        if start is None or end is None or end < start:
            return None
        return end - start


class LiveFlowAggregator:
    """Aggregate parsed packets once; expire idle flows and flush on stop."""

    def __init__(
        self,
        idle_timeout_seconds: float = 30.0,
        on_flow_completed: Callable[[CompletedFlow], None] | None = None,
    ) -> None:
        if idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive.")
        self.idle_timeout_seconds = float(idle_timeout_seconds)
        self.on_flow_completed = on_flow_completed
        self._lock = threading.RLock()
        self._active: dict[BidirectionalFlowKey, _ActiveFlow] = {}
        self._completed_count = 0
        self._malformed_count = 0

    @property
    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._active)

    @property
    def completed_flow_count(self) -> int:
        with self._lock:
            return self._completed_count

    @property
    def malformed_packet_count(self) -> int:
        with self._lock:
            return self._malformed_count

    def reset(self) -> None:
        """Start a clean per-monitoring-session aggregate."""
        with self._lock:
            self._active.clear()
            self._completed_count = 0
            self._malformed_count = 0

    def process_packet(self, packet: PacketRecord) -> tuple[CompletedFlow, ...]:
        """Add one metadata record and emit any flows expired by this packet."""
        if not self._valid_packet(packet):
            with self._lock:
                self._malformed_count += 1
            return ()

        emitted: list[CompletedFlow] = []
        source = (packet.source_ip, packet.source_port)
        destination = (packet.destination_ip, packet.destination_port)
        first, second = sorted((source, destination), key=lambda endpoint: (endpoint[0], endpoint[1] or -1))
        key: BidirectionalFlowKey = (first, second, packet.protocol.casefold())
        timestamp = float(packet.timestamp)

        with self._lock:
            expired = [
                flow_key for flow_key, flow in self._active.items()
                if timestamp >= flow.last_seen
                and timestamp - flow.last_seen >= self.idle_timeout_seconds
            ]
            for flow_key in expired:
                emitted.append(self._finish_locked(flow_key, "idle_timeout"))

            flow = self._active.get(key)
            if flow is None:
                flow = _ActiveFlow(
                    flow_id=uuid.uuid4().hex,
                    source_endpoint=source,
                    destination_endpoint=destination,
                    protocol=packet.protocol,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
                self._active[key] = flow
            flow.add(packet)

        self._notify(emitted)
        return tuple(emitted)

    def finalize_all(self, reason: str = "monitor_stopped") -> tuple[CompletedFlow, ...]:
        """Finalize all open flows on an explicit stop/close boundary."""
        with self._lock:
            emitted = [self._finish_locked(key, reason) for key in tuple(self._active)]
        self._notify(emitted)
        return tuple(emitted)

    def _finish_locked(self, key: BidirectionalFlowKey, reason: str) -> CompletedFlow:
        flow = self._active.pop(key)
        completed = flow.complete(reason)
        self._completed_count += 1
        return completed

    def _notify(self, flows: list[CompletedFlow]) -> None:
        if self.on_flow_completed is None:
            return
        for flow in flows:
            try:
                self.on_flow_completed(flow)
            except Exception:
                logger.exception("Completed-flow callback failed")

    @staticmethod
    def _valid_packet(packet: PacketRecord) -> bool:
        if not isinstance(packet, PacketRecord):
            return False
        if not all(isinstance(value, str) and value for value in (
            packet.source_ip, packet.destination_ip, packet.protocol
        )):
            return False
        if isinstance(packet.timestamp, bool) or not isinstance(packet.timestamp, numbers.Real):
            return False
        if isinstance(packet.packet_length, bool) or not isinstance(packet.packet_length, numbers.Integral):
            return False
        timestamp = float(packet.timestamp)
        packet_length = int(packet.packet_length)
        if not math.isfinite(timestamp) or packet_length < 0:
            return False
        if packet.source_port is not None and (
            isinstance(packet.source_port, bool)
            or not isinstance(packet.source_port, numbers.Integral)
            or not 0 <= packet.source_port <= 65535
        ):
            return False
        if packet.destination_port is not None and (
            isinstance(packet.destination_port, bool)
            or not isinstance(packet.destination_port, numbers.Integral)
            or not 0 <= packet.destination_port <= 65535
        ):
            return False
        if packet.ip_ttl is not None and (
            isinstance(packet.ip_ttl, bool)
            or not isinstance(packet.ip_ttl, numbers.Integral)
            or not 0 <= packet.ip_ttl <= 255
        ):
            return False
        if packet.tcp_window is not None and (
            isinstance(packet.tcp_window, bool)
            or not isinstance(packet.tcp_window, numbers.Integral)
            or not 0 <= packet.tcp_window <= 65535
        ):
            return False
        for value in (packet.tcp_sequence, packet.tcp_acknowledgement):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, numbers.Integral)
                or not 0 <= value <= 0xFFFFFFFF
            ):
                return False
        return True
