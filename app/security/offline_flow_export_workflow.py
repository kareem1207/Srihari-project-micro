"""Caller-controlled, offline-only CompletedFlow export workflow.

This module composes the existing pure adapter with the existing atomic
exporter.  It never starts capture, selects an interface, invokes IDS/model
code, writes SQLite data, or supplies implicit session metadata or paths.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app.security.flow_aggregator import CompletedFlow
from app.security.live_flow_adapter import completed_flow_to_live_flow_v1
from app.security.live_flow_export import ExportSummary, LiveFlowExportStore, SessionManifest
from app.security.live_flow_schema import CollectorMetadata


class OfflineFlowExportWorkflowError(ValueError):
    """The caller did not supply a valid, explicit offline export batch."""


@dataclass(frozen=True)
class OfflineFlowExportResult:
    """A successfully published export; no result is returned on failure."""

    destination: Path
    summary: ExportSummary


def export_completed_flows_offline(
    completed_flows: Iterable[CompletedFlow],
    collector_metadata: CollectorMetadata,
    session_manifest: SessionManifest,
    output_root: str | Path,
    *,
    exporter: LiveFlowExportStore | None = None,
) -> OfflineFlowExportResult:
    """Convert an explicit completed-flow batch and publish it once offline.

    All flows are converted before the exporter is called.  Consequently an
    adapter rejection, including an unsupported finalization reason, creates no
    session export.  The existing exporter then validates the full converted
    batch and publishes it atomically, or raises without reporting success.

    Human review, dispositions, and labels are intentionally absent from this
    interface and must remain outside feature exports.
    """
    if not isinstance(session_manifest, SessionManifest):
        raise OfflineFlowExportWorkflowError("session_manifest must be SessionManifest.")
    if isinstance(completed_flows, (str, bytes)):
        raise OfflineFlowExportWorkflowError("completed_flows must be an iterable of CompletedFlow objects.")
    try:
        flows = tuple(completed_flows)
    except TypeError as exc:
        raise OfflineFlowExportWorkflowError(
            "completed_flows must be an iterable of CompletedFlow objects."
        ) from exc
    if not flows:
        raise OfflineFlowExportWorkflowError("completed_flows must contain at least one completed flow.")

    # The adapter is intentionally invoked before the exporter so an invalid
    # in-memory batch cannot create a partial session directory.
    records = tuple(
        completed_flow_to_live_flow_v1(flow, collector_metadata)
        for flow in flows
    )
    active_exporter = exporter if exporter is not None else LiveFlowExportStore()
    if not isinstance(active_exporter, LiveFlowExportStore):
        raise OfflineFlowExportWorkflowError("exporter must be LiveFlowExportStore when supplied.")
    destination, summary = active_exporter.export(output_root, session_manifest, records)
    return OfflineFlowExportResult(destination=destination, summary=summary)
