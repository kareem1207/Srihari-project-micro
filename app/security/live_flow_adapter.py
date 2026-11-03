"""Pure validated boundary from CompletedFlow to a live_flow_v1 record.

This module intentionally has no capture, exporter, database, GUI, model, or
IDS-service dependency. It only validates explicit in-memory inputs and calls
the schema conversion contract.
"""
from __future__ import annotations

import math
import numbers
import re
from typing import Any

from app.security.flow_aggregator import CompletedFlow
from app.security.live_flow_schema import (
    COLLECTOR_VERSION,
    ORIENTATION_CONVENTION,
    SCHEMA_VERSION,
    CollectorMetadata,
    LiveFlowV1Record,
    export_live_flow_v1,
)

_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$")
_FLOW_ID = re.compile(r"^[0-9a-f]{32}$")
_IP_PROTOCOL = re.compile(r"^ip-([0-9]{1,3})$")
_FINALIZATION_REASONS = frozenset({"idle_timeout", "monitor_stopped"})


class CompletedFlowAdapterError(ValueError):
    """The supplied completed flow or explicit collector metadata is invalid."""


def completed_flow_to_live_flow_v1(
    flow: CompletedFlow,
    metadata: CollectorMetadata,
) -> LiveFlowV1Record:
    """Validate explicit in-memory inputs and create one payload-free record.

    This performs no I/O and does not infer session metadata, labels, or output
    paths. The returned record follows the schema converter's direction,
    units, missingness, and finalization conventions.
    """
    _validate_metadata(metadata)
    _validate_flow(flow)
    return export_live_flow_v1(flow, metadata)


def _validate_metadata(metadata: CollectorMetadata) -> None:
    if not isinstance(metadata, CollectorMetadata):
        raise CompletedFlowAdapterError("metadata must be CollectorMetadata.")
    if not isinstance(metadata.capture_session_id, str) or not _SESSION_ID.fullmatch(metadata.capture_session_id):
        raise CompletedFlowAdapterError("capture_session_id must be a safe opaque identifier.")
    _positive_finite_number(metadata.idle_timeout_seconds, "idle_timeout_seconds")
    if metadata.schema_version != SCHEMA_VERSION:
        raise CompletedFlowAdapterError("metadata schema_version does not match live_flow_v1.")
    if metadata.collector_version != COLLECTOR_VERSION:
        raise CompletedFlowAdapterError("metadata collector_version does not match the supported collector.")
    if metadata.orientation_convention != ORIENTATION_CONVENTION:
        raise CompletedFlowAdapterError("metadata orientation_convention does not match the schema.")


def _validate_flow(flow: CompletedFlow) -> None:
    if not isinstance(flow, CompletedFlow):
        raise CompletedFlowAdapterError("flow must be CompletedFlow.")
    if not isinstance(flow.flow_id, str) or not _FLOW_ID.fullmatch(flow.flow_id):
        raise CompletedFlowAdapterError("flow_id must be a generated 32-character lowercase hexadecimal identifier.")
    if not isinstance(flow.protocol, str) or not _supported_protocol(flow.protocol.casefold()):
        raise CompletedFlowAdapterError("protocol must be tcp, udp, icmp, or ip-0 through ip-255.")
    if flow.finalized_reason not in _FINALIZATION_REASONS:
        raise CompletedFlowAdapterError("finalized_reason must be idle_timeout or monitor_stopped.")
    for field in ("source_ip", "destination_ip"):
        if not isinstance(getattr(flow, field), str) or not getattr(flow, field):
            raise CompletedFlowAdapterError(f"{field} must be a non-empty source value.")
    for field in ("source_port", "destination_port"):
        _optional_port(getattr(flow, field), field)
    for field in ("first_seen", "last_seen"):
        _finite_number(getattr(flow, field), field)
    if flow.last_seen < flow.first_seen:
        raise CompletedFlowAdapterError("last_seen cannot be earlier than first_seen.")
    for field in (
        "packet_count", "total_bytes", "source_packets", "destination_packets",
        "source_bytes", "destination_bytes",
    ):
        _nonnegative_integer(getattr(flow, field), field)
    if flow.packet_count <= 0:
        raise CompletedFlowAdapterError("packet_count must be positive for a completed flow.")
    if flow.source_packets + flow.destination_packets != flow.packet_count:
        raise CompletedFlowAdapterError("directional packet counts must equal packet_count.")
    if flow.source_bytes + flow.destination_bytes != flow.total_bytes:
        raise CompletedFlowAdapterError("directional byte counts must equal total_bytes.")
    for field in (
        "source_interpacket_ms", "destination_interpacket_ms", "source_jitter_ms",
        "destination_jitter_ms", "synack_seconds", "ackdat_seconds",
        "tcp_handshake_seconds",
    ):
        _optional_nonnegative_finite_number(getattr(flow, field), field)
    for field in (
        "source_ttl", "destination_ttl", "source_tcp_window", "destination_tcp_window",
        "source_initial_tcp_sequence", "destination_initial_tcp_sequence",
    ):
        _optional_nonnegative_integer(getattr(flow, field), field)
    for field in ("source_ttl", "destination_ttl"):
        value = getattr(flow, field)
        if value is not None and value > 255:
            raise CompletedFlowAdapterError(f"{field} must be at most 255.")
    if flow.observed_tcp_state is not None and (
        not isinstance(flow.observed_tcp_state, str) or not flow.observed_tcp_state
    ):
        raise CompletedFlowAdapterError("observed_tcp_state must be a non-empty string when present.")
    if flow.protocol.casefold() != "tcp":
        _reject_non_tcp_values(flow)


def _reject_non_tcp_values(flow: CompletedFlow) -> None:
    tcp_only = (
        "source_tcp_window", "destination_tcp_window", "source_initial_tcp_sequence",
        "destination_initial_tcp_sequence", "observed_tcp_state", "synack_seconds",
        "ackdat_seconds", "tcp_handshake_seconds",
    )
    if any(getattr(flow, field) is not None for field in tcp_only):
        raise CompletedFlowAdapterError("non-TCP flow contains TCP-only observations.")


def _supported_protocol(value: str) -> bool:
    if value in {"tcp", "udp", "icmp"}:
        return True
    match = _IP_PROTOCOL.fullmatch(value)
    return match is not None and int(match.group(1)) <= 255


def _finite_number(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise CompletedFlowAdapterError(f"{field} must be a finite number.")
    try:
        finite = math.isfinite(float(value))
    except OverflowError:
        finite = False
    if not finite:
        raise CompletedFlowAdapterError(f"{field} must be a finite number.")


def _positive_finite_number(value: Any, field: str) -> None:
    _finite_number(value, field)
    if value <= 0:
        raise CompletedFlowAdapterError(f"{field} must be positive.")


def _optional_nonnegative_finite_number(value: Any, field: str) -> None:
    if value is None:
        return
    _finite_number(value, field)
    if value < 0:
        raise CompletedFlowAdapterError(f"{field} cannot be negative.")


def _nonnegative_integer(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, numbers.Integral) or value < 0:
        raise CompletedFlowAdapterError(f"{field} must be a non-negative integer.")


def _optional_nonnegative_integer(value: Any, field: str) -> None:
    if value is None:
        return
    _nonnegative_integer(value, field)


def _optional_port(value: Any, field: str) -> None:
    if value is None:
        return
    _nonnegative_integer(value, field)
    if value > 65535:
        raise CompletedFlowAdapterError(f"{field} must be at most 65535.")
