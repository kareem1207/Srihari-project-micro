"""Versioned, payload-free feature contract for future live-flow studies.

This module is instrumentation only. It does not load a model, create an IDS
event, or alter the Phase 4 UNSW-NB15 compatibility gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from app.security.flow_aggregator import CompletedFlow

SCHEMA_VERSION = "live_flow_v1"
COLLECTOR_VERSION = "securework_flow_aggregator_v1"
ORIENTATION_CONVENTION = "first_observed_packet"


class MissingReason(str, Enum):
    """Why a schema value is absent; absence is never converted to zero."""

    NOT_APPLICABLE = "not_applicable"
    INSUFFICIENT_OBSERVATIONS = "insufficient_observations"
    NOT_OBSERVED = "not_observed"


@dataclass(frozen=True)
class FeatureSpec:
    """One ordered feature in the live_flow_v1 contract."""

    name: str
    value_type: str
    units: str
    source: str
    minimum_observations: str


LIVE_FLOW_V1_FEATURES: tuple[FeatureSpec, ...] = (
    FeatureSpec("protocol", "string", "categorical", "PacketRecord.protocol", "one IPv4 packet"),
    FeatureSpec("packet_count", "integer", "packets", "CompletedFlow.packet_count", "one packet"),
    FeatureSpec("captured_bytes", "integer", "bytes", "CompletedFlow.total_bytes", "one packet"),
    FeatureSpec("observed_duration_seconds", "number", "seconds", "last_seen - first_seen", "one packet; may be zero"),
    FeatureSpec("packet_rate_pps", "number|null", "packets/second", "packet_count / observed_duration_seconds", "positive duration"),
    FeatureSpec("captured_byte_rate_bps", "number|null", "bits/second", "captured_bytes * 8 / observed_duration_seconds", "positive duration"),
    FeatureSpec("source_packet_count", "integer", "packets", "CompletedFlow.source_packets", "one packet"),
    FeatureSpec("destination_packet_count", "integer", "packets", "CompletedFlow.destination_packets", "zero allowed"),
    FeatureSpec("source_captured_bytes", "integer", "bytes", "CompletedFlow.source_bytes", "one packet"),
    FeatureSpec("destination_captured_bytes", "integer", "bytes", "CompletedFlow.destination_bytes", "zero allowed"),
    FeatureSpec("source_packet_fraction", "number", "fraction", "source_packet_count / packet_count", "one packet"),
    FeatureSpec("destination_packet_fraction", "number", "fraction", "destination_packet_count / packet_count", "one packet"),
    FeatureSpec("source_mean_captured_packet_bytes", "number", "bytes/packet", "source_captured_bytes / source_packet_count", "one source packet"),
    FeatureSpec("destination_mean_captured_packet_bytes", "number|null", "bytes/packet", "destination_captured_bytes / destination_packet_count", "one destination packet"),
    FeatureSpec("source_interpacket_ms", "number|null", "milliseconds", "CompletedFlow.source_interpacket_ms", "two source packets with increasing timestamps"),
    FeatureSpec("destination_interpacket_ms", "number|null", "milliseconds", "CompletedFlow.destination_interpacket_ms", "two destination packets with increasing timestamps"),
    FeatureSpec("source_jitter_ms", "number|null", "milliseconds", "CompletedFlow.source_jitter_ms", "three source packets with increasing timestamps"),
    FeatureSpec("destination_jitter_ms", "number|null", "milliseconds", "CompletedFlow.destination_jitter_ms", "three destination packets with increasing timestamps"),
    FeatureSpec("source_ipv4_ttl", "integer|null", "IPv4 TTL", "latest source-direction PacketRecord.ip_ttl", "observed IPv4 TTL"),
    FeatureSpec("destination_ipv4_ttl", "integer|null", "IPv4 TTL", "latest destination-direction PacketRecord.ip_ttl", "observed IPv4 TTL"),
    FeatureSpec("source_tcp_window", "integer|null", "TCP window units", "latest source-direction PacketRecord.tcp_window", "TCP packet with window"),
    FeatureSpec("destination_tcp_window", "integer|null", "TCP window units", "latest destination-direction PacketRecord.tcp_window", "TCP packet with window"),
    FeatureSpec("source_initial_tcp_sequence", "integer|null", "TCP sequence number", "first source-direction PacketRecord.tcp_sequence", "TCP packet with sequence"),
    FeatureSpec("destination_initial_tcp_sequence", "integer|null", "TCP sequence number", "first destination-direction PacketRecord.tcp_sequence", "TCP packet with sequence"),
    FeatureSpec("observed_tcp_state", "string|null", "categorical diagnostic", "CompletedFlow.observed_tcp_state", "TCP flag observation"),
    FeatureSpec("synack_seconds", "number|null", "seconds", "observed SYN to SYN/ACK elapsed time", "complete observed SYN and SYN/ACK"),
    FeatureSpec("ackdat_seconds", "number|null", "seconds", "observed SYN/ACK to final ACK elapsed time", "complete observed SYN/ACK and final ACK"),
    FeatureSpec("tcp_handshake_seconds", "number|null", "seconds", "observed SYN to final ACK elapsed time", "complete three-packet handshake"),
    FeatureSpec("is_sm_ips_ports", "integer|null", "binary", "equal endpoint IP and port check", "both transport ports present"),
)
LIVE_FLOW_V1_FEATURE_NAMES = tuple(spec.name for spec in LIVE_FLOW_V1_FEATURES)


@dataclass(frozen=True)
class CollectorMetadata:
    """Configuration needed to interpret a collected flow without storing endpoints."""

    capture_session_id: str
    idle_timeout_seconds: float
    collector_version: str = COLLECTOR_VERSION
    schema_version: str = SCHEMA_VERSION
    orientation_convention: str = ORIENTATION_CONVENTION

    def __post_init__(self) -> None:
        if not self.capture_session_id.strip():
            raise ValueError("capture_session_id must be non-empty.")
        if self.idle_timeout_seconds <= 0:
            raise ValueError("idle_timeout_seconds must be positive.")
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"Expected schema version {SCHEMA_VERSION!r}.")
        if self.orientation_convention != ORIENTATION_CONVENTION:
            raise ValueError(f"Expected orientation {ORIENTATION_CONVENTION!r}.")


@dataclass(frozen=True)
class LiveFlowV1Record:
    """One schema-complete record; absent values have an explicit reason."""

    metadata: CollectorMetadata
    flow_id: str
    finalization_reason: str
    values: Mapping[str, Any]
    missingness: Mapping[str, MissingReason]

    def __post_init__(self) -> None:
        if tuple(self.values) != LIVE_FLOW_V1_FEATURE_NAMES:
            raise ValueError("live_flow_v1 values must use the schema's exact order.")
        absent = {name for name, value in self.values.items() if value is None}
        if set(self.missingness) != absent:
            raise ValueError("Every null value, and only null values, needs a missingness reason.")
        if not self.flow_id or not self.finalization_reason:
            raise ValueError("flow_id and finalization_reason must be non-empty.")

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable record without endpoint IP addresses or ports."""
        return {
            "schema_version": self.metadata.schema_version,
            "collector_version": self.metadata.collector_version,
            "capture_session_id": self.metadata.capture_session_id,
            "idle_timeout_seconds": self.metadata.idle_timeout_seconds,
            "orientation_convention": self.metadata.orientation_convention,
            "flow_id": self.flow_id,
            "finalization_reason": self.finalization_reason,
            "features": dict(self.values),
            "missingness": {name: reason.value for name, reason in self.missingness.items()},
        }


def export_live_flow_v1(flow: CompletedFlow, metadata: CollectorMetadata) -> LiveFlowV1Record:
    """Export one completed flow under the fixed live_flow_v1 contract."""
    is_tcp = flow.protocol.casefold() == "tcp"
    duration = flow.duration
    values: dict[str, Any] = {
        "protocol": flow.protocol.casefold(),
        "packet_count": flow.packet_count,
        "captured_bytes": flow.total_bytes,
        "observed_duration_seconds": duration,
        "packet_rate_pps": flow.packet_rate,
        "captured_byte_rate_bps": flow.total_bytes * 8 / duration if duration > 0 else None,
        "source_packet_count": flow.source_packets,
        "destination_packet_count": flow.destination_packets,
        "source_captured_bytes": flow.source_bytes,
        "destination_captured_bytes": flow.destination_bytes,
        "source_packet_fraction": flow.source_packets / flow.packet_count,
        "destination_packet_fraction": flow.destination_packets / flow.packet_count,
        "source_mean_captured_packet_bytes": flow.source_mean_packet_size,
        "destination_mean_captured_packet_bytes": flow.destination_mean_packet_size,
        "source_interpacket_ms": flow.source_interpacket_ms,
        "destination_interpacket_ms": flow.destination_interpacket_ms,
        "source_jitter_ms": flow.source_jitter_ms,
        "destination_jitter_ms": flow.destination_jitter_ms,
        "source_ipv4_ttl": flow.source_ttl,
        "destination_ipv4_ttl": flow.destination_ttl,
        "source_tcp_window": flow.source_tcp_window,
        "destination_tcp_window": flow.destination_tcp_window,
        "source_initial_tcp_sequence": flow.source_initial_tcp_sequence,
        "destination_initial_tcp_sequence": flow.destination_initial_tcp_sequence,
        "observed_tcp_state": flow.observed_tcp_state,
        "synack_seconds": flow.synack_seconds,
        "ackdat_seconds": flow.ackdat_seconds,
        "tcp_handshake_seconds": flow.tcp_handshake_seconds,
        "is_sm_ips_ports": (
            int(flow.source_ip == flow.destination_ip and flow.source_port == flow.destination_port)
            if flow.source_port is not None and flow.destination_port is not None else None
        ),
    }
    missingness: dict[str, MissingReason] = {}
    tcp_features = {
        "source_tcp_window", "destination_tcp_window", "source_initial_tcp_sequence",
        "destination_initial_tcp_sequence", "observed_tcp_state", "synack_seconds",
        "ackdat_seconds", "tcp_handshake_seconds",
    }
    for name, value in values.items():
        if value is not None:
            continue
        if name in {"packet_rate_pps", "captured_byte_rate_bps", "source_interpacket_ms",
                    "destination_interpacket_ms", "source_jitter_ms", "destination_jitter_ms",
                    "destination_mean_captured_packet_bytes"}:
            missingness[name] = MissingReason.INSUFFICIENT_OBSERVATIONS
        elif name == "is_sm_ips_ports":
            missingness[name] = MissingReason.NOT_APPLICABLE
        elif name in tcp_features:
            missingness[name] = MissingReason.NOT_APPLICABLE if not is_tcp else MissingReason.NOT_OBSERVED
        else:
            missingness[name] = MissingReason.NOT_OBSERVED
    return LiveFlowV1Record(metadata, flow.flow_id, flow.finalized_reason, values, missingness)
