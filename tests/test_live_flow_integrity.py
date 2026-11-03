"""Pure unit tests for the immutable in-memory live-flow integrity contract."""
from __future__ import annotations

import json
import math
import unittest
from hashlib import sha256
from dataclasses import replace

from app.security.live_flow_integrity import (
    COMPLETION_FILENAME,
    INTEGRITY_CONTRACT_VERSION,
    INTEGRITY_FILENAME,
    PROTECTED_FILENAMES,
    ExportClassification,
    IntegrityContractError,
    InMemoryExportCandidate,
    InMemoryFile,
    build_candidate,
    canonical_json_bytes,
    verify_candidate,
)
from app.security.live_flow_schema import (
    LIVE_FLOW_V1_FEATURE_NAMES,
    LIVE_FLOW_V1_FEATURES,
    CollectorMetadata,
    LiveFlowV1Record,
)
from app.security.live_flow_validation import _ALLOWED_CONFIGURATION_FIELDS, SessionManifest


def manifest() -> SessionManifest:
    return SessionManifest(
        session_id="session-001",
        scenario_id="IDLE-01",
        scenario_definition_version="1",
        actual_start="2026-10-20T09:00:00+05:30",
        actual_end="2026-10-20T09:05:00+05:30",
        retention_delete_after="2026-10-27T09:05:00+05:30",
        interface_category="approved_external_usb_wifi",
        collector_configuration={"idle_timeout_seconds": 30, "finalization_policy": "existing_aggregator"},
    )


def record(flow_number: int):
    values = {
        spec.name: ("tcp" if spec.name == "protocol" else "observed")
        if spec.value_type.startswith("string")
        else (1 if spec.value_type.startswith("integer") else 1.0)
        for spec in LIVE_FLOW_V1_FEATURES
    }
    return LiveFlowV1Record(
        CollectorMetadata("session-001", idle_timeout_seconds=30),
        f"{flow_number:032x}",
        "monitor_stopped",
        values,
        {},
    )


def replace_file(candidate: InMemoryExportCandidate, filename: str, content: bytes) -> InMemoryExportCandidate:
    return replace(candidate, files=tuple(
        InMemoryFile(item.filename, content if item.filename == filename else item.content)
        for item in candidate.files
    ))


class LiveFlowIntegrityTests(unittest.TestCase):
    def test_deterministic_output_sorts_validated_records_by_flow_id(self) -> None:
        first = build_candidate(manifest(), [record(2), record(1)])
        second = build_candidate(manifest(), [record(1), record(2)])
        self.assertEqual(first, second)
        self.assertEqual(verify_candidate(first).classification, ExportClassification.INTEGRITY_VALID_AUTHENTICITY_UNKNOWN)

    def test_canonical_bytes_use_utf8_lf_and_one_trailing_newline(self) -> None:
        candidate = build_candidate(manifest(), [record(2), record(1)])
        for filename in (*PROTECTED_FILENAMES[:1], PROTECTED_FILENAMES[2], INTEGRITY_FILENAME, COMPLETION_FILENAME):
            with self.subTest(filename=filename):
                content = candidate.content_for(filename)
                self.assertFalse(content.startswith(b"\xef\xbb\xbf"))
                self.assertNotIn(b"\r", content)
                self.assertTrue(content.endswith(b"\n"))
                self.assertFalse(content.endswith(b"\n\n"))

        ndjson = candidate.content_for("flow_records.ndjson")
        self.assertFalse(ndjson.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", ndjson)
        self.assertTrue(ndjson.endswith(b"\n"))
        self.assertFalse(ndjson.endswith(b"\n\n"))
        self.assertEqual(len(ndjson.splitlines()), 2)
        self.assertEqual(
            ndjson,
            build_candidate(manifest(), [record(1), record(2)]).content_for("flow_records.ndjson"),
        )

    def test_integrity_entries_and_completion_hash_match_exact_bytes(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        integrity_bytes = candidate.content_for(INTEGRITY_FILENAME)
        integrity = json.loads(integrity_bytes)
        self.assertEqual([entry["filename"] for entry in integrity["files"]], list(PROTECTED_FILENAMES))
        for entry in integrity["files"]:
            content = candidate.content_for(entry["filename"])
            self.assertEqual(entry["byte_count"], len(content))
            self.assertEqual(entry["sha256_hex"], sha256(content).hexdigest())
        completion = json.loads(candidate.content_for(COMPLETION_FILENAME))
        self.assertEqual(completion["integrity_sha256_hex"], sha256(integrity_bytes).hexdigest())
        self.assertNotIn("completion_timestamp", completion)

    def test_invalid_flow_id_is_rejected_before_sorting(self) -> None:
        invalid = record(1)
        object.__setattr__(invalid, "flow_id", "not-a-generated-id")
        with self.assertRaises(IntegrityContractError):
            build_candidate(manifest(), [invalid])

    def test_duplicate_flow_id_is_rejected_before_sorting(self) -> None:
        duplicate = record(1)
        with self.assertRaises(IntegrityContractError):
            build_candidate(manifest(), [duplicate, duplicate])

    def test_empty_batch_is_rejected_before_serialization(self) -> None:
        with self.assertRaisesRegex(IntegrityContractError, "at least one validated record"):
            build_candidate(manifest(), [])

    def test_feature_schema_order_is_validated_before_canonical_serialization(self) -> None:
        invalid = record(1)
        object.__setattr__(invalid, "values", dict(reversed(tuple(invalid.values.items()))))
        with self.assertRaises(IntegrityContractError):
            build_candidate(manifest(), [invalid])

        candidate = build_candidate(manifest(), [record(1)])
        serialized = json.loads(candidate.content_for("flow_records.ndjson"))
        self.assertEqual(list(serialized["features"]), sorted(LIVE_FLOW_V1_FEATURE_NAMES))
        integrity = json.loads(candidate.content_for(INTEGRITY_FILENAME))
        self.assertEqual(integrity["feature_names"], list(LIVE_FLOW_V1_FEATURE_NAMES))

    def test_one_byte_protected_file_tampering_is_integrity_invalid(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        tampered = replace_file(candidate, "flow_records.ndjson", candidate.content_for("flow_records.ndjson") + b" ")
        self.assertEqual(verify_candidate(tampered).classification, ExportClassification.INTEGRITY_INVALID)

    def test_incorrect_completion_hash_is_invalid_complete_claim(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        marker = json.loads(candidate.content_for(COMPLETION_FILENAME))
        marker["integrity_sha256_hex"] = "0" * 64
        altered = replace_file(candidate, COMPLETION_FILENAME, canonical_json_bytes(marker))
        self.assertEqual(verify_candidate(altered).classification, ExportClassification.INVALID_COMPLETE_CLAIM)

    def test_missing_completion_marker_is_incomplete(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        incomplete = replace(candidate, files=tuple(item for item in candidate.files if item.filename != COMPLETION_FILENAME))
        self.assertEqual(verify_candidate(incomplete).classification, ExportClassification.INCOMPLETE)

    def test_completion_with_missing_protected_content_is_invalid_claim(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        incomplete = replace(candidate, files=tuple(item for item in candidate.files if item.filename != "manifest.json"))
        self.assertEqual(verify_candidate(incomplete).classification, ExportClassification.INVALID_COMPLETE_CLAIM)

    def test_unknown_or_missing_contract_versions_take_precedence(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        integrity = json.loads(candidate.content_for(INTEGRITY_FILENAME))
        integrity["contract_version"] = "future-contract"
        unsupported_contract = replace_file(candidate, INTEGRITY_FILENAME, canonical_json_bytes(integrity))
        self.assertEqual(verify_candidate(unsupported_contract).classification, ExportClassification.UNSUPPORTED_CONTRACT_VERSION)

        missing_contract = json.loads(candidate.content_for(INTEGRITY_FILENAME))
        del missing_contract["contract_version"]
        invalid_complete_candidate = replace_file(candidate, INTEGRITY_FILENAME, canonical_json_bytes(missing_contract))
        invalid_complete_candidate = replace(
            invalid_complete_candidate,
            files=tuple(item for item in invalid_complete_candidate.files if item.filename != "manifest.json"),
        )
        self.assertEqual(verify_candidate(invalid_complete_candidate).classification, ExportClassification.UNSUPPORTED_CONTRACT_VERSION)

    def test_completion_missing_contract_version_precedes_malformed_content(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        completion = json.loads(candidate.content_for(COMPLETION_FILENAME))
        del completion["contract_version"]
        malformed_content = replace_file(candidate, COMPLETION_FILENAME, canonical_json_bytes(completion))
        malformed_content = replace(
            malformed_content,
            files=tuple(item for item in malformed_content.files if item.filename != "manifest.json"),
        )
        self.assertEqual(
            verify_candidate(malformed_content).classification,
            ExportClassification.UNSUPPORTED_CONTRACT_VERSION,
        )

    def test_integrity_and_manifest_schema_versions_take_precedence(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        integrity = json.loads(candidate.content_for(INTEGRITY_FILENAME))
        integrity["schema_version"] = "future-schema"
        malformed_content = replace_file(candidate, INTEGRITY_FILENAME, canonical_json_bytes(integrity))
        malformed_content = replace(
            malformed_content,
            files=tuple(item for item in malformed_content.files if item.filename != "manifest.json"),
        )
        self.assertEqual(verify_candidate(malformed_content).classification, ExportClassification.UNSUPPORTED_SCHEMA_VERSION)

        manifest_value = json.loads(candidate.content_for("manifest.json"))
        manifest_value["schema_version"] = "future-schema"
        unsupported_schema = replace_file(candidate, "manifest.json", canonical_json_bytes(manifest_value))
        self.assertEqual(verify_candidate(unsupported_schema).classification, ExportClassification.UNSUPPORTED_SCHEMA_VERSION)

        missing_schema = json.loads(candidate.content_for("manifest.json"))
        del missing_schema["schema_version"]
        self.assertEqual(
            verify_candidate(replace_file(candidate, "manifest.json", canonical_json_bytes(missing_schema))).classification,
            ExportClassification.UNSUPPORTED_SCHEMA_VERSION,
        )

    def test_integrity_missing_schema_version_precedes_malformed_content(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        integrity = json.loads(candidate.content_for(INTEGRITY_FILENAME))
        del integrity["schema_version"]
        malformed_content = replace_file(candidate, INTEGRITY_FILENAME, canonical_json_bytes(integrity))
        malformed_content = replace(
            malformed_content,
            files=tuple(item for item in malformed_content.files if item.filename != "manifest.json"),
        )
        self.assertEqual(
            verify_candidate(malformed_content).classification,
            ExportClassification.UNSUPPORTED_SCHEMA_VERSION,
        )

    def test_extra_duplicate_nested_and_path_like_filenames_are_rejected(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        for filename in ("extra.json", "nested/extra.json", "..\\extra.json"):
            with self.subTest(filename=filename):
                altered = replace(candidate, files=candidate.files + (InMemoryFile(filename, b"{}\n"),))
                self.assertEqual(verify_candidate(altered).classification, ExportClassification.INTEGRITY_INVALID)
        duplicate = replace(candidate, files=candidate.files + (candidate.files[0],))
        self.assertEqual(verify_candidate(duplicate).classification, ExportClassification.INTEGRITY_INVALID)

    def test_malformed_file_entries_are_integrity_invalid(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        malformed_entries = (
            object(),
            InMemoryFile("extra.json", "not-byte-content"),
            InMemoryFile(123, b"{}\n"),
        )
        for entry in malformed_entries:
            with self.subTest(entry_type=type(entry).__name__):
                altered = replace(candidate, files=candidate.files + (entry,))
                self.assertEqual(
                    verify_candidate(altered).classification,
                    ExportClassification.INTEGRITY_INVALID,
                )

    def test_unsupported_versions_precede_malformed_file_entry_rejection(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        integrity = json.loads(candidate.content_for(INTEGRITY_FILENAME))
        integrity["contract_version"] = "future-contract"
        altered = replace_file(candidate, INTEGRITY_FILENAME, canonical_json_bytes(integrity))
        altered = replace(altered, files=altered.files + (object(),))
        self.assertEqual(
            verify_candidate(altered).classification,
            ExportClassification.UNSUPPORTED_CONTRACT_VERSION,
        )

    def test_builder_serializes_only_allowlisted_payload_free_content(self) -> None:
        candidate = build_candidate(manifest(), [record(1)])
        payloads = {
            item.filename: json.loads(item.content)
            for item in candidate.files
            if item.filename != "flow_records.ndjson"
        }
        records = [json.loads(line) for line in candidate.content_for("flow_records.ndjson").decode("utf-8").splitlines()]
        approved_record_keys = {
            "schema_version", "collector_version", "capture_session_id", "idle_timeout_seconds",
            "orientation_convention", "flow_id", "finalization_reason", "features", "missingness",
        }
        self.assertEqual(len(records), 1)
        self.assertEqual(set(records[0]), approved_record_keys)
        self.assertEqual(set(records[0]["features"]), set(LIVE_FLOW_V1_FEATURE_NAMES))
        self.assertEqual(payloads["export_summary.json"]["feature_names"], list(LIVE_FLOW_V1_FEATURE_NAMES))
        self.assertEqual(payloads["integrity.json"]["feature_names"], list(LIVE_FLOW_V1_FEATURE_NAMES))
        self.assertIn("source_ipv4_ttl", records[0]["features"])
        self.assertIn("source_interpacket_ms", records[0]["features"])
        self.assertTrue(
            set(payloads["manifest.json"]["collector_configuration"]).issubset(
                _ALLOWED_CONFIGURATION_FIELDS
            )
        )
        prohibited = {
            "source_ip", "destination_ip", "source_port", "destination_port",
            "payload", "credentials", "label", "disposition",
        }
        for payload in (*payloads.values(), *records):
            self.assertFalse(_contains_prohibited_key(payload, prohibited))

    def test_hash_consistent_candidate_is_authenticity_unknown(self) -> None:
        result = verify_candidate(build_candidate(manifest(), [record(1)]))
        self.assertTrue(result.valid)
        self.assertEqual(result.classification, ExportClassification.INTEGRITY_VALID_AUTHENTICITY_UNKNOWN)
        self.assertIn("authenticity is not established", result.reason)

    def test_nonfinite_values_and_malformed_completion_are_rejected(self) -> None:
        invalid = record(1)
        values = dict(invalid.values)
        values["observed_duration_seconds"] = math.nan
        object.__setattr__(invalid, "values", values)
        with self.assertRaises(IntegrityContractError):
            build_candidate(manifest(), [invalid])

        candidate = build_candidate(manifest(), [record(1)])
        malformed = replace_file(candidate, COMPLETION_FILENAME, canonical_json_bytes({"contract_version": INTEGRITY_CONTRACT_VERSION}))
        self.assertEqual(verify_candidate(malformed).classification, ExportClassification.INVALID_COMPLETE_CLAIM)


if __name__ == "__main__":
    unittest.main()


def _contains_prohibited_key(value: object, prohibited: set[str]) -> bool:
    if isinstance(value, dict):
        return any(
            key in prohibited or _contains_prohibited_key(nested, prohibited)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(_contains_prohibited_key(item, prohibited) for item in value)
    return False
