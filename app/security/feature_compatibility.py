"""Semantic compatibility audit for the fixed Phase 4 UNSW-NB15 model."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


class FeatureAvailability(str, Enum):
    """Whether a live value has the model's required meaning, not just a name."""

    DIRECT = "Directly compatible"
    EQUIVALENT = "Derivable with equivalent semantics"
    NOT_EQUIVALENT = "Derivable but not equivalent"
    REQUIRES_IMPLEMENTATION = "Requires additional implementation"
    REQUIRES_APPLICATION = "Requires application-layer inspection"
    UNAVAILABLE = "Unavailable"
    UNKNOWN = "Unknown; requires verification"


@dataclass(frozen=True)
class FeatureMapping:
    availability: FeatureAvailability
    explanation: str
    available_from_monitor: bool = False
    derivable_from_packets: bool = False
    requires_directional_state: bool = False
    requires_tcp_state: bool = False
    requires_application_inspection: bool = False
    requires_historical_statistics: bool = False
    semantics_reproducible: bool = False


@dataclass(frozen=True)
class CompatibilityAssessment:
    compatible: bool
    missing_features: tuple[str, ...]
    blocked_features: tuple[str, ...]
    reason: str


MODEL_FEATURES: tuple[str, ...] = (
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt",
    "dinpkt", "sjit", "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
)


def _mapping(availability: FeatureAvailability, explanation: str, **requirements: bool) -> FeatureMapping:
    return FeatureMapping(availability, explanation, **requirements)


# Similar field names are deliberately insufficient. The saved pipeline may only
# receive a value when its UNSW-NB15 exporter semantics are reproducible.
FEATURE_MAPPING: dict[str, FeatureMapping] = {
    "dur": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed first-to-last packet duration; timeout and partial capture can truncate the exporter flow.", available_from_monitor=True, derivable_from_packets=True),
    "proto": _mapping(FeatureAvailability.DIRECT, "Protocol is captured and normalized, subject to the model's trained category vocabulary.", available_from_monitor=True, derivable_from_packets=True, semantics_reproducible=True),
    "service": _mapping(FeatureAvailability.REQUIRES_APPLICATION, "No service classifier or payload/application inspection is used.", requires_application_inspection=True),
    "state": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed TCP handshake/reset/close summaries are not verified UNSW connection-state labels.", available_from_monitor=True, derivable_from_packets=True, requires_tcp_state=True),
    "spkts": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Directional count uses first-observed orientation, not verified exporter source/destination roles.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "dpkts": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Directional count uses first-observed orientation, not verified exporter source/destination roles.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "sbytes": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Directional captured-frame byte count may use a different layer from the exporter.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "dbytes": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Directional captured-frame byte count may use a different layer from the exporter.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "rate": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed packets per first-to-last duration; exporter window semantics are unverified.", available_from_monitor=True, derivable_from_packets=True),
    "sttl": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Latest observed source IPv4 TTL is retained; role and exporter aggregation are unverified.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "dttl": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Latest observed destination IPv4 TTL is retained; role and exporter aggregation are unverified.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "sload": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed source captured bits per second, not verified exporter load semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "dload": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed destination captured bits per second, not verified exporter load semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "sloss": _mapping(FeatureAvailability.UNAVAILABLE, "Packet loss cannot be inferred reliably from passive partial capture."),
    "dloss": _mapping(FeatureAvailability.UNAVAILABLE, "Packet loss cannot be inferred reliably from passive partial capture."),
    "sinpkt": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Mean observed source-direction interval; capture timing and exporter convention are unverified.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "dinpkt": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Mean observed destination-direction interval; capture timing and exporter convention are unverified.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "sjit": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Mean absolute change in observed source intervals; not verified UNSW jitter semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "djit": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Mean absolute change in observed destination intervals; not verified UNSW jitter semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "swin": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Latest observed source TCP window, not verified exporter field semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True, requires_tcp_state=True),
    "stcpb": _mapping(FeatureAvailability.NOT_EQUIVALENT, "First observed source TCP sequence value; not verified exporter base sequence semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True, requires_tcp_state=True),
    "dtcpb": _mapping(FeatureAvailability.NOT_EQUIVALENT, "First observed destination TCP sequence value; not verified exporter base sequence semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True, requires_tcp_state=True),
    "dwin": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Latest observed destination TCP window, not verified exporter field semantics.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True, requires_tcp_state=True),
    "tcprtt": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed SYN-to-final-ACK duration only when the complete handshake is captured.", available_from_monitor=True, derivable_from_packets=True, requires_tcp_state=True),
    "synack": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed SYN-to-SYN/ACK duration only when both packets are captured.", available_from_monitor=True, derivable_from_packets=True, requires_tcp_state=True),
    "ackdat": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed SYN/ACK-to-final-ACK duration only when both packets are captured.", available_from_monitor=True, derivable_from_packets=True, requires_tcp_state=True),
    "smean": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed source captured-frame mean size; byte layer and direction are unverified.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "dmean": _mapping(FeatureAvailability.NOT_EQUIVALENT, "Observed destination captured-frame mean size; byte layer and direction are unverified.", available_from_monitor=True, derivable_from_packets=True, requires_directional_state=True),
    "trans_depth": _mapping(FeatureAvailability.REQUIRES_APPLICATION, "HTTP transaction depth requires application-layer inspection.", requires_application_inspection=True),
    "response_body_len": _mapping(FeatureAvailability.REQUIRES_APPLICATION, "HTTP response body length requires application-layer inspection; payloads are deliberately not retained.", requires_application_inspection=True),
    "ct_srv_src": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical service/source flow window.", requires_historical_statistics=True),
    "ct_state_ttl": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires historical flow state/TTL counts with exporter-equivalent state labels.", requires_tcp_state=True, requires_historical_statistics=True),
    "ct_dst_ltm": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical destination flow window.", requires_historical_statistics=True),
    "ct_src_dport_ltm": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical source/destination-port flow window.", requires_historical_statistics=True),
    "ct_dst_sport_ltm": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical destination/source-port flow window.", requires_historical_statistics=True),
    "ct_dst_src_ltm": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical address-pair flow window.", requires_historical_statistics=True),
    "is_ftp_login": _mapping(FeatureAvailability.REQUIRES_APPLICATION, "FTP login state requires application-layer inspection.", requires_application_inspection=True),
    "ct_ftp_cmd": _mapping(FeatureAvailability.REQUIRES_APPLICATION, "FTP command count requires application-layer inspection.", requires_application_inspection=True),
    "ct_flw_http_mthd": _mapping(FeatureAvailability.REQUIRES_APPLICATION, "HTTP method count requires application-layer inspection.", requires_application_inspection=True),
    "ct_src_ltm": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical source flow window.", requires_historical_statistics=True),
    "ct_srv_dst": _mapping(FeatureAvailability.REQUIRES_IMPLEMENTATION, "Requires a validated historical service/destination flow window.", requires_historical_statistics=True),
    "is_sm_ips_ports": _mapping(FeatureAvailability.EQUIVALENT, "Exactly checks equal endpoint IP and transport port values when both ports are present.", available_from_monitor=True, derivable_from_packets=True, semantics_reproducible=True),
}


@dataclass(frozen=True)
class FeatureCompatibilityReport:
    """Assess complete schema and per-field semantic certification."""

    feature_mapping: Mapping[str, FeatureMapping] = field(default_factory=lambda: FEATURE_MAPPING)
    required_features: tuple[str, ...] = MODEL_FEATURES
    allow_compatible_predictions: bool = True

    def __post_init__(self) -> None:
        missing = set(self.required_features) - set(self.feature_mapping)
        extra = set(self.feature_mapping) - set(self.required_features)
        if missing or extra:
            raise ValueError(f"Feature mapping schema mismatch; missing={sorted(missing)}, extra={sorted(extra)}")

    @property
    def live_prediction_enabled(self) -> bool:
        return self.allow_compatible_predictions and all(
            self.feature_mapping[name].availability in (FeatureAvailability.DIRECT, FeatureAvailability.EQUIVALENT)
            and self.feature_mapping[name].semantics_reproducible
            for name in self.required_features
        )

    @property
    def compatible_feature_names(self) -> tuple[str, ...]:
        return tuple(name for name in self.required_features if self.feature_mapping[name].availability in (FeatureAvailability.DIRECT, FeatureAvailability.EQUIVALENT) and self.feature_mapping[name].semantics_reproducible)

    @property
    def partially_derivable_feature_names(self) -> tuple[str, ...]:
        return tuple(name for name in self.required_features if self.feature_mapping[name].availability == FeatureAvailability.NOT_EQUIVALENT)

    @property
    def blocked_feature_names(self) -> tuple[str, ...]:
        return tuple(name for name in self.required_features if name not in self.compatible_feature_names)

    def assess(self, candidate_features: Mapping[str, object]) -> CompatibilityAssessment:
        missing = tuple(name for name in self.required_features if name not in candidate_features)
        blocked = self.blocked_feature_names
        compatible = self.live_prediction_enabled and not missing
        reason = "All required features have verified live semantics." if compatible else "Live IDS inference unavailable: the saved model requires feature semantics the current extractor cannot reproduce."
        return CompatibilityAssessment(compatible, missing, blocked, reason)
