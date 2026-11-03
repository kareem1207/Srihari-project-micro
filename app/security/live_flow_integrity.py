"""Pure in-memory integrity contract for immutable live_flow_v1 exports.

This module neither reads nor writes files.  SHA-256 checks internal byte
consistency only; it does not establish authenticity, authorization, or safe
filesystem publication.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from app.security.live_flow_validation import (
    ExportSummary,
    SessionManifest,
    validate_export,
)
from app.security.live_flow_schema import (
    COLLECTOR_VERSION,
    LIVE_FLOW_V1_FEATURE_NAMES,
    ORIENTATION_CONVENTION,
    SCHEMA_VERSION,
    CollectorMetadata,
    LiveFlowV1Record,
    MissingReason,
)


INTEGRITY_CONTRACT_VERSION = "live_flow_integrity_v1"
PROTECTED_FILENAMES = (
    "manifest.json",
    "flow_records.ndjson",
    "export_summary.json",
)
INTEGRITY_FILENAME = "integrity.json"
COMPLETION_FILENAME = "completion.json"
COMPLETE_FILENAMES = PROTECTED_FILENAMES + (INTEGRITY_FILENAME, COMPLETION_FILENAME)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FLOW_ID = re.compile(r"^[0-9a-f]{32}$")


class IntegrityContractError(ValueError):
    """The supplied in-memory candidate cannot be constructed safely."""


class IntegrityValidationError(IntegrityContractError):
    """Existing live_flow_v1 validation rejected candidate inputs."""

    def __init__(self, report: object) -> None:
        super().__init__("Integrity candidate validation failed.")
        self.report = report


class ExportClassification(str, Enum):
    UNSUPPORTED_CONTRACT_VERSION = "unsupported_contract_version"
    UNSUPPORTED_SCHEMA_VERSION = "unsupported_schema_version"
    INCOMPLETE = "incomplete"
    INVALID_COMPLETE_CLAIM = "invalid_complete_claim"
    INTEGRITY_INVALID = "integrity_invalid"
    INTEGRITY_VALID_AUTHENTICITY_UNKNOWN = "integrity_valid_authenticity_unknown"


@dataclass(frozen=True)
class IntegrityEntry:
    filename: str
    byte_count: int
    sha256_hex: str


@dataclass(frozen=True)
class IntegrityManifest:
    contract_version: str
    session_id: str
    schema_version: str
    collector_version: str
    feature_names: tuple[str, ...]
    record_count: int
    files: tuple[IntegrityEntry, ...]


@dataclass(frozen=True)
class CompletionMarker:
    contract_version: str
    session_id: str
    integrity_sha256_hex: str


@dataclass(frozen=True)
class InMemoryFile:
    """One named byte sequence; duplicate names are retained for verification."""

    filename: str
    content: bytes


@dataclass(frozen=True)
class InMemoryExportCandidate:
    """An immutable candidate representation with no filesystem behavior."""

    files: tuple[InMemoryFile, ...]

    def content_for(self, filename: str) -> bytes:
        matches = [item.content for item in self.files if item.filename == filename]
        if len(matches) != 1:
            raise IntegrityContractError(f"Expected exactly one {filename!r} entry.")
        return matches[0]


@dataclass(frozen=True)
class VerificationResult:
    classification: ExportClassification
    reason: str

    @property
    def valid(self) -> bool:
        return self.classification is ExportClassification.INTEGRITY_VALID_AUTHENTICITY_UNKNOWN


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize JSON deterministically for this contract version only."""
    try:
        payload = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise IntegrityContractError("Value is not canonical JSON for the integrity contract.") from exc
    return (payload + "\n").encode("utf-8")


def canonical_ndjson_bytes(records: Iterable[LiveFlowV1Record]) -> bytes:
    """Serialize already validated records in lexical flow_id order.

    ``sort_keys=True`` makes JSON object keys alphabetical on the wire.  The
    semantic feature order remains ``LIVE_FLOW_V1_FEATURE_NAMES`` and is
    validated before serialization and carried explicitly in metadata.
    """
    return b"".join(canonical_json_bytes(record.as_dict()) for record in records)


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def build_candidate(
    manifest: SessionManifest,
    records: Iterable[LiveFlowV1Record],
) -> InMemoryExportCandidate:
    """Build a complete candidate after reusing the existing export validator."""
    accepted, report = validate_export(manifest, records)
    if not report.valid:
        raise IntegrityValidationError(report)
    if not accepted:
        raise IntegrityContractError("Integrity candidates must contain at least one validated record.")
    if any(tuple(record.values) != LIVE_FLOW_V1_FEATURE_NAMES for record in accepted):
        raise IntegrityContractError("Record features do not use the required semantic schema order.")
    ordered = tuple(sorted(accepted, key=lambda record: record.flow_id))
    protected = (
        InMemoryFile("manifest.json", canonical_json_bytes(asdict(manifest))),
        InMemoryFile("flow_records.ndjson", canonical_ndjson_bytes(ordered)),
        InMemoryFile(
            "export_summary.json",
            canonical_json_bytes(_summary_dict(manifest, len(ordered))),
        ),
    )
    integrity = IntegrityManifest(
        contract_version=INTEGRITY_CONTRACT_VERSION,
        session_id=manifest.session_id,
        schema_version=manifest.schema_version,
        collector_version=manifest.collector_version,
        feature_names=LIVE_FLOW_V1_FEATURE_NAMES,
        record_count=len(ordered),
        files=tuple(
            IntegrityEntry(item.filename, len(item.content), sha256_hex(item.content))
            for item in protected
        ),
    )
    integrity_file = InMemoryFile(INTEGRITY_FILENAME, canonical_json_bytes(_integrity_dict(integrity)))
    completion = CompletionMarker(
        contract_version=INTEGRITY_CONTRACT_VERSION,
        session_id=manifest.session_id,
        integrity_sha256_hex=sha256_hex(integrity_file.content),
    )
    return InMemoryExportCandidate(protected + (
        integrity_file,
        InMemoryFile(COMPLETION_FILENAME, canonical_json_bytes(_completion_dict(completion))),
    ))


def verify_candidate(candidate: InMemoryExportCandidate) -> VerificationResult:
    """Classify bytes using the approved precedence without filesystem access."""
    if not isinstance(candidate, InMemoryExportCandidate):
        return _result(ExportClassification.INTEGRITY_INVALID, "Candidate must be an InMemoryExportCandidate.")
    malformed_entries = any(not _is_well_formed_file(item) for item in candidate.files)
    by_name = _unique_files(candidate)

    # Version precedence is evaluated from independently parsed declarations.
    integrity_object = _json_object(by_name.get(INTEGRITY_FILENAME))
    completion_object = _json_object(by_name.get(COMPLETION_FILENAME))
    for declared in (integrity_object, completion_object):
        if isinstance(declared, dict) and declared.get("contract_version") != INTEGRITY_CONTRACT_VERSION:
            return _result(ExportClassification.UNSUPPORTED_CONTRACT_VERSION, "Unsupported integrity contract version.")
    manifest_object = _json_object(by_name.get("manifest.json"))
    for declared in (integrity_object, manifest_object):
        if isinstance(declared, dict) and declared.get("schema_version") != SCHEMA_VERSION:
            return _result(ExportClassification.UNSUPPORTED_SCHEMA_VERSION, "Unsupported live-flow schema version.")

    if malformed_entries:
        return _result(ExportClassification.INTEGRITY_INVALID, "Candidate contains malformed file entries.")

    names = [item.filename for item in candidate.files]
    has_completion = COMPLETION_FILENAME in names
    if not has_completion:
        return _result(ExportClassification.INCOMPLETE, "No completion marker is present.")
    if completion_object is None or not _completion_is_well_formed(completion_object):
        return _result(ExportClassification.INVALID_COMPLETE_CLAIM, "Completion marker is malformed.")
    if any(name not in COMPLETE_FILENAMES for name in names) or len(set(names)) != len(names):
        return _result(ExportClassification.INTEGRITY_INVALID, "Candidate filenames are not the exact allowlist.")
    if set(names) != set(COMPLETE_FILENAMES):
        return _result(ExportClassification.INVALID_COMPLETE_CLAIM, "Completion marker is present but required content is missing.")
    if integrity_object is None:
        return _result(ExportClassification.INVALID_COMPLETE_CLAIM, "Completion marker lacks valid integrity metadata.")
    if not _integrity_is_well_formed(integrity_object):
        return _result(ExportClassification.INTEGRITY_INVALID, "Integrity manifest is malformed.")
    if sha256_hex(by_name[INTEGRITY_FILENAME]) != completion_object["integrity_sha256_hex"]:
        return _result(ExportClassification.INVALID_COMPLETE_CLAIM, "Completion marker does not match integrity metadata.")
    if completion_object["session_id"] != integrity_object["session_id"]:
        return _result(ExportClassification.INTEGRITY_INVALID, "Completion and integrity session IDs differ.")
    decoded = _decode_protected_content(by_name)
    if decoded is None:
        return _result(ExportClassification.INTEGRITY_INVALID, "Protected content is malformed or violates validation rules.")
    manifest, records, summary = decoded
    if integrity_object["session_id"] != manifest.session_id:
        return _result(ExportClassification.INTEGRITY_INVALID, "Integrity and manifest session IDs differ.")
    expected_summary = _summary_dict(manifest, len(records))
    if summary != expected_summary:
        return _result(ExportClassification.INTEGRITY_INVALID, "Export summary is inconsistent with protected content.")
    expected_integrity = _integrity_dict(IntegrityManifest(
        contract_version=INTEGRITY_CONTRACT_VERSION,
        session_id=manifest.session_id,
        schema_version=manifest.schema_version,
        collector_version=manifest.collector_version,
        feature_names=LIVE_FLOW_V1_FEATURE_NAMES,
        record_count=len(records),
        files=tuple(
            IntegrityEntry(name, len(by_name[name]), sha256_hex(by_name[name]))
            for name in PROTECTED_FILENAMES
        ),
    ))
    if integrity_object != expected_integrity:
        return _result(ExportClassification.INTEGRITY_INVALID, "Integrity metadata does not match protected bytes.")
    return _result(
        ExportClassification.INTEGRITY_VALID_AUTHENTICITY_UNKNOWN,
        "Protected content is hash-consistent; authenticity is not established.",
    )


def _result(classification: ExportClassification, reason: str) -> VerificationResult:
    return VerificationResult(classification, reason)


def _summary_dict(manifest: SessionManifest, record_count: int) -> dict[str, Any]:
    summary = ExportSummary(
        session_id=manifest.session_id,
        record_count=record_count,
        rejected_record_count=0,
        validation_error_count=0,
        schema_version=manifest.schema_version,
        collector_version=manifest.collector_version,
        feature_names=LIVE_FLOW_V1_FEATURE_NAMES,
    )
    result = asdict(summary)
    result["feature_names"] = list(summary.feature_names)
    result["validation_errors"] = []
    return result


def _integrity_dict(value: IntegrityManifest) -> dict[str, Any]:
    return {
        "contract_version": value.contract_version,
        "session_id": value.session_id,
        "schema_version": value.schema_version,
        "collector_version": value.collector_version,
        "feature_names": list(value.feature_names),
        "record_count": value.record_count,
        "files": [asdict(entry) for entry in value.files],
    }


def _completion_dict(value: CompletionMarker) -> dict[str, str]:
    return {
        "contract_version": value.contract_version,
        "session_id": value.session_id,
        "integrity_sha256_hex": value.integrity_sha256_hex,
    }


def _unique_files(candidate: InMemoryExportCandidate) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for item in candidate.files:
        if _is_well_formed_file(item):
            result.setdefault(item.filename, item.content)
    return result


def _is_well_formed_file(item: object) -> bool:
    return (
        isinstance(item, InMemoryFile)
        and isinstance(item.filename, str)
        and isinstance(item.content, bytes)
    )


def _json_object(content: bytes | None) -> dict[str, Any] | None:
    if content is None:
        return None
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _completion_is_well_formed(value: Mapping[str, Any]) -> bool:
    return set(value) == {"contract_version", "session_id", "integrity_sha256_hex"} and (
        value.get("contract_version") == INTEGRITY_CONTRACT_VERSION
        and isinstance(value.get("session_id"), str)
        and isinstance(value.get("integrity_sha256_hex"), str)
        and bool(_SHA256.fullmatch(value["integrity_sha256_hex"]))
    )


def _integrity_is_well_formed(value: Mapping[str, Any]) -> bool:
    expected = {"contract_version", "session_id", "schema_version", "collector_version", "feature_names", "record_count", "files"}
    if set(value) != expected or value.get("contract_version") != INTEGRITY_CONTRACT_VERSION:
        return False
    if value.get("schema_version") != SCHEMA_VERSION or value.get("collector_version") != COLLECTOR_VERSION:
        return False
    if value.get("feature_names") != list(LIVE_FLOW_V1_FEATURE_NAMES) or not isinstance(value.get("record_count"), int):
        return False
    entries = value.get("files")
    if not isinstance(entries, list) or len(entries) != len(PROTECTED_FILENAMES):
        return False
    for filename, entry in zip(PROTECTED_FILENAMES, entries):
        if not isinstance(entry, dict) or set(entry) != {"filename", "byte_count", "sha256_hex"}:
            return False
        if entry.get("filename") != filename or isinstance(entry.get("byte_count"), bool) or not isinstance(entry.get("byte_count"), int):
            return False
        if entry["byte_count"] < 0 or not isinstance(entry.get("sha256_hex"), str) or not _SHA256.fullmatch(entry["sha256_hex"]):
            return False
    return True


def _decode_protected_content(files: Mapping[str, bytes]) -> tuple[SessionManifest, tuple[LiveFlowV1Record, ...], dict[str, Any]] | None:
    manifest_value = _json_object(files.get("manifest.json"))
    summary_value = _json_object(files.get("export_summary.json"))
    records_content = files.get("flow_records.ndjson")
    if manifest_value is None or summary_value is None or records_content is None:
        return None
    try:
        manifest = _manifest_from_dict(manifest_value)
        records = _records_from_ndjson(records_content)
        accepted, report = validate_export(manifest, records)
    except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not report.valid or tuple(sorted(accepted, key=lambda record: record.flow_id)) != tuple(records):
        return None
    return manifest, tuple(records), summary_value


def _manifest_from_dict(value: Mapping[str, Any]) -> SessionManifest:
    fields = {
        "session_id", "scenario_id", "scenario_definition_version", "actual_start", "actual_end",
        "interface_category", "collector_configuration", "retention_delete_after", "schema_version",
        "collector_version", "orientation_convention", "operator_notes_reference", "uncertainty_flag",
    }
    if set(value) != fields:
        raise ValueError("Manifest keys do not match the allowlist.")
    return SessionManifest(**dict(value))


def _records_from_ndjson(content: bytes) -> tuple[LiveFlowV1Record, ...]:
    text = content.decode("utf-8")
    if not text.endswith("\n") or not text or "\n\n" in text:
        raise ValueError("NDJSON must have one trailing newline and no blank lines.")
    records = []
    expected = {
        "schema_version", "collector_version", "capture_session_id", "idle_timeout_seconds",
        "orientation_convention", "flow_id", "finalization_reason", "features", "missingness",
    }
    for line in text[:-1].split("\n"):
        value = json.loads(line)
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("Record contains unexpected fields.")
        features = value["features"]
        missingness = value["missingness"]
        if not isinstance(features, dict) or tuple(features) != tuple(sorted(features)):
            raise ValueError("Features are not canonical JSON keys.")
        # Restore schema order after canonical JSON key ordering before reusing validation.
        if set(features) != set(LIVE_FLOW_V1_FEATURE_NAMES) or not isinstance(missingness, dict):
            raise ValueError("Record schema is invalid.")
        restored = {name: features[name] for name in LIVE_FLOW_V1_FEATURE_NAMES}
        restored_missingness = {name: MissingReason(reason) for name, reason in missingness.items()}
        metadata = CollectorMetadata(
            capture_session_id=value["capture_session_id"],
            idle_timeout_seconds=value["idle_timeout_seconds"],
            collector_version=value["collector_version"],
            schema_version=value["schema_version"],
            orientation_convention=value["orientation_convention"],
        )
        records.append(LiveFlowV1Record(metadata, value["flow_id"], value["finalization_reason"], restored, restored_missingness))
    return tuple(records)
