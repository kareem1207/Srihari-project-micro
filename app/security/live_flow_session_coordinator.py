"""Capture-independent lifecycle for an explicit offline flow-export session.

The coordinator accepts only already-completed in-memory flows.  It has no
packet capture, interface, USB policy, GUI, IDS/model, or database dependency.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable

from app.security.flow_aggregator import CompletedFlow
from app.security.live_flow_adapter import (
    CompletedFlowAdapterError,
    completed_flow_to_live_flow_v1,
)
from app.security.live_flow_export import (
    ExportValidationError,
    LiveFlowExportError,
    LiveFlowExportStore,
    SessionManifest,
    validate_export,
)
from app.security.live_flow_schema import CollectorMetadata
from app.security.offline_flow_export_workflow import (
    OfflineFlowExportResult,
    export_completed_flows_offline,
)


class SessionState(str, Enum):
    PREPARED = "prepared"
    AUTHORIZED = "authorized"
    FINALIZED = "finalized"
    VALIDATED = "validated"
    EXPORTED = "exported"
    FAILED = "failed"
    HELD_FOR_REVIEW = "held_for_review"


class LiveFlowSessionCoordinatorError(RuntimeError):
    """An explicit session lifecycle action could not be completed."""


@dataclass(frozen=True)
class SessionStatus:
    """Observable state without labels or human review content."""

    state: SessionState
    message: str | None
    result: OfflineFlowExportResult | None


class LiveFlowSessionCoordinator:
    """Manage one supplied completed-flow batch before offline export.

    Calling :meth:`authorize` is an explicit software action only. It does not
    assert that a pilot, network, device, or person has received human approval.
    """

    def __init__(
        self,
        collector_metadata: CollectorMetadata,
        session_manifest: SessionManifest,
        output_root: str | Path,
        *,
        exporter: LiveFlowExportStore | None = None,
    ) -> None:
        if not isinstance(collector_metadata, CollectorMetadata):
            raise LiveFlowSessionCoordinatorError("collector_metadata must be CollectorMetadata.")
        if not isinstance(session_manifest, SessionManifest):
            raise LiveFlowSessionCoordinatorError("session_manifest must be SessionManifest.")
        if not isinstance(output_root, (str, Path)):
            raise LiveFlowSessionCoordinatorError("output_root must be an explicit path.")
        root = Path(output_root)
        if not root.exists() or not root.is_dir():
            raise LiveFlowSessionCoordinatorError("output_root must be an existing directory.")
        if exporter is not None and not isinstance(exporter, LiveFlowExportStore):
            raise LiveFlowSessionCoordinatorError("exporter must be LiveFlowExportStore when supplied.")

        self._collector_metadata = collector_metadata
        self._session_manifest = session_manifest
        self._output_root = root
        self._exporter = exporter
        self._flows: tuple[CompletedFlow, ...] = ()
        self._state = SessionState.PREPARED
        self._message: str | None = None
        self._result: OfflineFlowExportResult | None = None
        self._export_attempted = False

    @property
    def status(self) -> SessionStatus:
        return SessionStatus(self._state, self._message, self._result)

    def authorize(self) -> SessionStatus:
        """Allow a caller to submit an already-completed batch for validation."""
        self._require_state(SessionState.PREPARED)
        self._state = SessionState.AUTHORIZED
        self._message = None
        return self.status

    def finalize(self, completed_flows: Iterable[CompletedFlow]) -> SessionStatus:
        """Validate an explicit complete batch without writing an export."""
        self._require_state(SessionState.AUTHORIZED)
        flows = self._materialize_flows(completed_flows)
        self._flows = flows
        self._state = SessionState.FINALIZED

        if any(
            isinstance(flow, CompletedFlow)
            and flow.finalized_reason not in {"idle_timeout", "monitor_stopped"}
            for flow in flows
        ):
            return self.hold_for_review(
                "Batch contains a completion reason unsupported by the offline export contract."
            )

        try:
            records = tuple(
                completed_flow_to_live_flow_v1(flow, self._collector_metadata)
                for flow in flows
            )
            _accepted, report = validate_export(self._session_manifest, records)
            if not report.valid:
                raise ExportValidationError(report)
        except (CompletedFlowAdapterError, LiveFlowExportError) as exc:
            self._state = SessionState.FAILED
            self._message = str(exc)
            raise LiveFlowSessionCoordinatorError("Session validation failed.") from exc

        self._state = SessionState.VALIDATED
        self._message = None
        return self.status

    def export(self) -> SessionStatus:
        """Publish a validated batch through the existing offline workflow."""
        self._require_state(SessionState.VALIDATED)
        return self._export_current_batch()

    def retry_export(self) -> SessionStatus:
        """Retry only a prior failed export; never bypass review or validation."""
        if self._state is not SessionState.FAILED or not self._export_attempted:
            raise LiveFlowSessionCoordinatorError("retry_export requires a prior failed export attempt.")
        return self._export_current_batch()

    def hold_for_review(self, reason: str) -> SessionStatus:
        """Prevent export while preserving only the caller-supplied in-memory batch."""
        if self._state in {SessionState.EXPORTED, SessionState.HELD_FOR_REVIEW}:
            raise LiveFlowSessionCoordinatorError(f"Cannot hold a session in state {self._state.value!r}.")
        if not isinstance(reason, str) or not reason.strip():
            raise LiveFlowSessionCoordinatorError("A non-empty review reason is required.")
        self._state = SessionState.HELD_FOR_REVIEW
        self._message = reason.strip()
        return self.status

    def _export_current_batch(self) -> SessionStatus:
        self._export_attempted = True
        try:
            self._result = export_completed_flows_offline(
                self._flows,
                self._collector_metadata,
                self._session_manifest,
                self._output_root,
                exporter=self._exporter,
            )
        except (CompletedFlowAdapterError, LiveFlowExportError, ValueError) as exc:
            self._state = SessionState.FAILED
            self._message = str(exc)
            raise LiveFlowSessionCoordinatorError("Offline export failed.") from exc
        self._state = SessionState.EXPORTED
        self._message = None
        return self.status

    def _materialize_flows(self, completed_flows: Iterable[CompletedFlow]) -> tuple[CompletedFlow, ...]:
        if isinstance(completed_flows, (str, bytes)):
            raise LiveFlowSessionCoordinatorError("completed_flows must be an iterable of CompletedFlow objects.")
        try:
            flows = tuple(completed_flows)
        except TypeError as exc:
            raise LiveFlowSessionCoordinatorError(
                "completed_flows must be an iterable of CompletedFlow objects."
            ) from exc
        if not flows:
            raise LiveFlowSessionCoordinatorError("completed_flows must contain at least one completed flow.")
        return flows

    def _require_state(self, expected: SessionState) -> None:
        if self._state is not expected:
            raise LiveFlowSessionCoordinatorError(
                f"Action requires session state {expected.value!r}; current state is {self._state.value!r}."
            )
