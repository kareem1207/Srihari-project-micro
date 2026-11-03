"""Pure validation and data contracts for supplied live_flow_v1 records.

This module deliberately has no filesystem, packet-capture, database, GUI, IDS,
or model dependency.  The filesystem exporter re-exports these public data
types for backward compatibility.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping

from app.security.live_flow_schema import (
    COLLECTOR_VERSION,
    LIVE_FLOW_V1_FEATURES,
    LIVE_FLOW_V1_FEATURE_NAMES,
    MissingReason,
    ORIENTATION_CONVENTION,
    SCHEMA_VERSION,
    LiveFlowV1Record,
)

_SESSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$")
_SCENARIO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_FLOW_ID = re.compile(r"^[0-9a-f]{32}$")
_SCENARIO_DEFINITION_VERSION = re.compile(r"^[0-9]{1,9}$")
_APPLICATION_VERSION = re.compile(r"^v[0-9]+(?:\.[0-9]+){0,3}(?:-[A-Za-z0-9]+)?$")
_IP_PROTOCOL = re.compile(r"^ip-([0-9]{1,3})$")
_FEATURE_SPECS = {spec.name: spec for spec in LIVE_FLOW_V1_FEATURES}
_ALLOWED_CONFIGURATION_FIELDS = frozenset({
    "idle_timeout_seconds", "finalization_policy", "application_version",
})
_ALLOWED_FINALIZATION_POLICIES = frozenset({"existing_aggregator"})


@dataclass(frozen=True)
class SessionManifest:
    """Non-feature metadata required to interpret one export session."""

    session_id: str
    scenario_id: str
    scenario_definition_version: str
    actual_start: str
    actual_end: str
    interface_category: str
    collector_configuration: Mapping[str, Any]
    retention_delete_after: str
    schema_version: str = SCHEMA_VERSION
    collector_version: str = COLLECTOR_VERSION
    orientation_convention: str = ORIENTATION_CONVENTION
    operator_notes_reference: str = ""
    uncertainty_flag: bool = False


@dataclass(frozen=True)
class ValidationError:
    record_index: int | None
    field: str
    message: str


@dataclass(frozen=True)
class ValidationReport:
    accepted_records: int
    rejected_records: int
    errors: tuple[ValidationError, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class ExportSummary:
    session_id: str
    record_count: int
    rejected_record_count: int
    validation_error_count: int
    schema_version: str
    collector_version: str
    feature_names: tuple[str, ...]


def _parse_timestamp(value: str, field: str, errors: list[ValidationError]) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        errors.append(ValidationError(None, field, "must be an ISO 8601 timestamp with numeric UTC offset."))
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(ValidationError(None, field, "must include a numeric UTC offset."))
        return None
    return parsed


def _is_supported_protocol(value: str) -> bool:
    if value in {"tcp", "udp", "icmp"}:
        return True
    match = _IP_PROTOCOL.fullmatch(value)
    return match is not None and int(match.group(1)) <= 255


def _validate_feature_value(
    name: str,
    value: Any,
    missingness: Mapping[str, MissingReason],
    index: int,
    errors: list[ValidationError],
) -> None:
    spec = _FEATURE_SPECS[name]
    nullable = spec.value_type.endswith("|null")
    if value is None:
        if not nullable:
            errors.append(ValidationError(index, name, "cannot be null."))
        if not isinstance(missingness.get(name), MissingReason):
            errors.append(ValidationError(index, f"missingness.{name}", "must be a MissingReason."))
        return
    if name in missingness:
        errors.append(ValidationError(index, f"missingness.{name}", "is present for a measured value."))
    base_type = spec.value_type.removesuffix("|null")
    if base_type == "string":
        if not isinstance(value, str) or not value:
            errors.append(ValidationError(index, name, "must be a non-empty string."))
        elif name == "protocol" and not _is_supported_protocol(value):
            errors.append(ValidationError(index, name, "must be tcp, udp, icmp, or ip-0 through ip-255."))
    elif base_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            errors.append(ValidationError(index, name, "must be an integer."))
    elif base_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            errors.append(ValidationError(index, name, "must be a finite number."))


def validate_export(
    manifest: SessionManifest,
    records: Iterable[object],
) -> tuple[tuple[LiveFlowV1Record, ...], ValidationReport]:
    """Validate supplied in-memory inputs without writing or changing them."""
    errors: list[ValidationError] = []
    if not _SESSION_ID.fullmatch(manifest.session_id):
        errors.append(ValidationError(None, "session_id", "must be a 3-128 character opaque identifier."))
    for field in ("scenario_id", "scenario_definition_version", "interface_category"):
        if not isinstance(getattr(manifest, field), str) or not getattr(manifest, field).strip():
            errors.append(ValidationError(None, field, "must be non-empty."))
    if isinstance(manifest.scenario_id, str) and not _SCENARIO_ID.fullmatch(manifest.scenario_id):
        errors.append(ValidationError(None, "scenario_id", "must be an opaque scenario identifier."))
    if not isinstance(manifest.scenario_definition_version, str) or not _SCENARIO_DEFINITION_VERSION.fullmatch(manifest.scenario_definition_version):
        errors.append(ValidationError(None, "scenario_definition_version", "must be a numeric catalogue version."))
    if manifest.interface_category != "approved_external_usb_wifi":
        errors.append(ValidationError(None, "interface_category", "must be 'approved_external_usb_wifi'."))
    if not isinstance(manifest.operator_notes_reference, str):
        errors.append(ValidationError(None, "operator_notes_reference", "must be a string when supplied."))
    elif manifest.operator_notes_reference and not _SESSION_ID.fullmatch(manifest.operator_notes_reference):
        errors.append(ValidationError(None, "operator_notes_reference", "must be an opaque identifier when supplied."))
    if not isinstance(manifest.uncertainty_flag, bool):
        errors.append(ValidationError(None, "uncertainty_flag", "must be a boolean."))
    if manifest.schema_version != SCHEMA_VERSION:
        errors.append(ValidationError(None, "schema_version", f"must be {SCHEMA_VERSION!r}."))
    if manifest.collector_version != COLLECTOR_VERSION:
        errors.append(ValidationError(None, "collector_version", f"must be {COLLECTOR_VERSION!r}."))
    if manifest.orientation_convention != ORIENTATION_CONVENTION:
        errors.append(ValidationError(None, "orientation_convention", f"must be {ORIENTATION_CONVENTION!r}."))
    if not isinstance(manifest.collector_configuration, Mapping):
        errors.append(ValidationError(None, "collector_configuration", "must be a mapping."))
    else:
        unexpected = set(manifest.collector_configuration) - _ALLOWED_CONFIGURATION_FIELDS
        if unexpected:
            errors.append(ValidationError(None, "collector_configuration", f"contains unsupported fields: {sorted(unexpected)!r}."))
        idle_timeout = manifest.collector_configuration.get("idle_timeout_seconds")
        if isinstance(idle_timeout, bool) or not isinstance(idle_timeout, (int, float)) or not math.isfinite(idle_timeout) or idle_timeout <= 0:
            errors.append(ValidationError(None, "collector_configuration.idle_timeout_seconds", "must be a positive number."))
        finalization_policy = manifest.collector_configuration.get("finalization_policy")
        if finalization_policy not in _ALLOWED_FINALIZATION_POLICIES:
            errors.append(ValidationError(None, "collector_configuration.finalization_policy", "must be an approved collector finalization policy."))
        application_version = manifest.collector_configuration.get("application_version")
        if application_version is not None and (not isinstance(application_version, str) or not _APPLICATION_VERSION.fullmatch(application_version)):
            errors.append(ValidationError(None, "collector_configuration.application_version", "must use the approved version format when supplied."))

    actual_start = _parse_timestamp(manifest.actual_start, "actual_start", errors)
    actual_end = _parse_timestamp(manifest.actual_end, "actual_end", errors)
    delete_after = _parse_timestamp(manifest.retention_delete_after, "retention_delete_after", errors)
    if actual_start and actual_end and actual_end < actual_start:
        errors.append(ValidationError(None, "actual_end", "must not be earlier than actual_start."))
    if actual_end and delete_after and delete_after != actual_end + timedelta(days=7):
        errors.append(ValidationError(None, "retention_delete_after", "must be exactly seven days after actual_end."))

    accepted: list[LiveFlowV1Record] = []
    seen_flow_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, LiveFlowV1Record):
            errors.append(ValidationError(index, "record", "must be a LiveFlowV1Record."))
            continue
        if record.metadata.capture_session_id != manifest.session_id:
            errors.append(ValidationError(index, "capture_session_id", "does not match manifest session_id."))
            continue
        if record.metadata.schema_version != manifest.schema_version:
            errors.append(ValidationError(index, "schema_version", "does not match manifest."))
            continue
        if record.metadata.collector_version != manifest.collector_version:
            errors.append(ValidationError(index, "collector_version", "does not match manifest."))
            continue
        if record.metadata.orientation_convention != manifest.orientation_convention:
            errors.append(ValidationError(index, "orientation_convention", "does not match manifest."))
            continue
        if record.metadata.idle_timeout_seconds != manifest.collector_configuration.get("idle_timeout_seconds"):
            errors.append(ValidationError(index, "idle_timeout_seconds", "does not match collector_configuration.idle_timeout_seconds."))
            continue
        if not isinstance(record.flow_id, str) or not _FLOW_ID.fullmatch(record.flow_id):
            errors.append(ValidationError(index, "flow_id", "must be a generated 32-character lowercase hexadecimal identifier."))
            continue
        if record.finalization_reason not in {"idle_timeout", "monitor_stopped"}:
            errors.append(ValidationError(index, "finalization_reason", "must be an approved collector finalization reason."))
            continue
        if tuple(record.values) != LIVE_FLOW_V1_FEATURE_NAMES:
            errors.append(ValidationError(index, "features", "does not use the required ordered feature names."))
            continue
        absent = {name for name, value in record.values.items() if value is None}
        if set(record.missingness) != absent:
            errors.append(ValidationError(index, "missingness", "must describe every null feature and no measured feature."))
            continue
        errors_before_feature_validation = len(errors)
        for name, value in record.values.items():
            _validate_feature_value(name, value, record.missingness, index, errors)
        if len(errors) != errors_before_feature_validation:
            continue
        if record.flow_id in seen_flow_ids:
            errors.append(ValidationError(index, "flow_id", "duplicates another record in this export."))
            continue
        seen_flow_ids.add(record.flow_id)
        accepted.append(record)

    report = ValidationReport(len(accepted), len(errors), tuple(errors))
    return tuple(accepted), report
