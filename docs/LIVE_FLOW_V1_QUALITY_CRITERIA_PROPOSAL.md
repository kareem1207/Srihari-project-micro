# live_flow_v1 pilot collection-quality criteria proposal

## Status and use

This is a proposal for reviewing a future, explicitly authorized benign-only
pilot. It creates no collection authorization, labels, empirical baseline, or
acceptance result. Suggested numerical thresholds are starting points for human
approval, not measured claims about the laptop, adapter, network, or collector.

The exporter already enforces schema/version matching, timestamp format,
feature order/types, finite numeric values, explicit missingness, safe IDs,
and duplicate flow-ID rejection within one export batch. Those are **code
enforced** checks. The session-level completeness, capture-quality, scenario,
and review decisions below remain **human review criteria**.

## Proposed review criteria

| Area and criterion | What is measured | How it is checked | Suggested threshold or pass/fail rule | Why it matters | Approval needed |
|---|---|---|---|---|---|
| Session completeness | `actual_start`, `actual_end`, required manifest metadata, retention deadline, and per-flow finalization reason | Validate the manifest/exporter report; compare the recorded session boundary procedure with the manifest | **Pass:** all required fields validate; end is not before start; retention deadline is exactly seven days after end; every record has `idle_timeout` or `monitor_stopped`. **Fail/exclude:** any missing or inconsistent item. | Gives each export an interpretable scope and retention clock. | **Yes**: confirm manifest fields and operational owner. |
| Flow identity and integrity | Session ID, 32-character flow ID, records per export, and duplicate flow IDs | Run exporter validation; compare session directories and review duplicate report across sessions | **Pass:** exporter accepts the batch and no duplicate flow ID exists in the session. **Proposed review rule:** exact duplicate feature records across sessions are flagged for review, never silently removed. | Prevents accidental record reuse and preserves auditability. | **Yes**: approve cross-session duplicate policy. |
| Schema/version consistency | Schema, collector, orientation, feature-name order, configuration, and finalization vocabulary | Run exporter validation and retain `export_summary.json` | **Pass:** exact current schema/collector/orientation match and validation error count is zero. **Fail/exclude:** a version/configuration changes during a session or the export is rejected. | Prevents mixing incompatible measurements. | **Yes**: freeze the version/configuration for the pilot. |
| Timestamp quality | Presence, timezone-aware ISO 8601 format (numeric UTC offset or `Z`), ordering, and session/flow timing anomalies | Exporter validation plus review of manifest and completed-flow timing fields | **Pass:** all manifest/deletion timestamps are timezone-aware and ordered. **Proposed review rule:** exclude a session if clock changes, missing timestamps, or unexplained negative/impossible timing values are found. | Enables reliable retention, scenario boundaries, and later grouping. | **Yes**: approve clock source and anomaly-review procedure. |
| Feature type, unit, and missingness quality | Exact schema order, types, finite numbers, nullable fields, and missingness reason per null | Exporter validation; inspect schema version and missingness summary by protocol/session | **Pass:** exporter accepts every record. **Proposed review rule:** any null without a reason, reason for a measured value, NaN/infinity, boolean used as number, or unit/schema mismatch excludes the affected session pending investigation. | Prevents invented zeroes and makes incomplete observation visible. | **No** for code-enforced rules; **Yes** for session-exclusion policy. |
| Missingness rate review | Rate of each nullable feature being `not_applicable`, `not_observed`, or `insufficient_observations` | Calculate per-feature missingness by session and scenario after authorized collection | **Proposed threshold:** no fixed percentage is accepted yet; establish a preapproved per-feature expectation before collection. **Fail/review:** any rate outside that approved range or a sudden protocol-specific change. | Missingness can reveal partial visibility, collector changes, or scenario mismatch. | **Yes**: all numerical ranges are pending. |
| Capture interruption and flow finalization | `monitor_stopped` counts, `idle_timeout` counts, session interruptions, and incomplete flows | Compare flow finalization reasons with operator/session notes and exporter summary | **Proposed rule:** a planned manual stop may be accepted only when documented; an unplanned interruption marks the session uncertain and excludes it until reviewed. Do not treat idle-finalized records as complete connections automatically. | Flow boundaries are observation artifacts, not proof of connection completion. | **Yes**: approve interruption handling. |
| Captured bytes versus wire bytes | Meaning and limitation of `captured_bytes` and rate-derived features | Verify the schema/exporter documentation and session review record | **Pass:** records and reports call these captured `len(packet)` totals. **Fail/review:** any report calls them original wire-byte totals or treats capture gaps as measured packet loss. | Avoids false precision from capture-layer observations. | **No** for terminology; **Yes** for any capture-loss acceptance threshold. |
| Privacy field exclusion | Endpoint IPs, ports, payloads, credentials, labels, free-text notes, and unapproved manifest fields | Inspect export JSON keys and run exporter validation | **Pass:** only schema-defined record fields and allow-listed manifest configuration are present; notes are opaque references only. **Fail/exclude/escalate:** any prohibited identifier or content is retained. | Keeps the benign pilot metadata-only and minimizes personal/network data. | **Yes**: approve separate troubleshooting-identifier policy. |
| Scenario provenance | Approved scenario ID/version, intended activity, boundary evidence, deviations, and uncertainty | Compare manifest with separately controlled scenario log and operator evidence | **Pass:** scenario reference and boundaries are documented. **Rule:** scenario context describes the session only; it does not automatically label every flow benign. | Background activity and connection reuse can make individual flows ambiguous. | **Yes**: approve scenario catalogue and evidence format. |
| Mixed/uncertain sessions | `uncertainty_flag`, deviations, unplanned activity, interface changes, and unknown ownership | Operator review of manifest and separate notes/evidence | **Proposed rule:** mixed, uncertain, unplanned, or scope-ambiguous sessions are excluded from any future supervised use unless a later approved review establishes provenance. | Avoids converting weak assumptions into labels. | **Yes**: approve exclusion/review owner. |
| Output and deletion evidence | Export summary, validation report, output location, deletion receipt, and copied-file inventory | Store review record separately from features; verify receipt only after authorized deletion | **Pass:** successful export has manifest, records, and summary; a deletion receipt is retained only after verified removal. **Fail/escalate:** partial deletion, missing receipt evidence, stale lock, or abandoned staging directory. | Supports accountable retention and recovery without treating temporary data as complete. | **Yes**: approve evidence store, backup/sync policy, and deletion owner. |

## Session disposition rules

The following proposed dispositions are deliberately conservative and require
approval before collection:

| Disposition | Proposed rule | Human decision required |
|---|---|---|
| Accept for pilot-quality review | Exporter validation succeeds, authorization/scope evidence is complete, scenario boundaries are documented, and no exclusion condition applies. | Approve the checklist owner and acceptance thresholds. |
| Hold for review | A session is mixed, uncertain, interrupted, has unexpected missingness, clock issues, duplicate concerns, or incomplete supporting evidence. It is retained only under approved privacy/retention controls. | Decide whether it can be corrected, excluded, or retained for non-modelling audit. |
| Exclude | Export rejection; prohibited content; unauthorized interface/network; invalid timestamps; inconsistent schema/version; unresolved duplicate/ownership issue; or inadequate scenario provenance. | Approve the exclusion owner and evidence-retention handling. |

No disposition creates a flow-level benign label. This proposal does not define
any ML training or evaluation threshold.

## Review evidence to retain separately from features

For every future session, preserve an access-controlled review record that
contains:

- session ID, scenario ID/version, reviewer role, review timestamp, and
  disposition;
- validation result and summary counts, including rejected records;
- authorization reference, selected approved-interface confirmation, and
  documented session boundaries;
- missingness/duplicate/interruption findings and any exclusion rationale;
- privacy finding and any escalation reference; and
- output location, retention deadline, backup/sync inventory, and, after
  authorized deletion, receipt/evidence reference.

Keep labels, if ever separately approved, in a separate store linked by IDs;
do not place them in features or infer them from the scenario name.

## Approval record

| Decision | Proposed value | Approver | Approval date |
|---|---|---|---|
| Session completeness and exclusion rules | **PENDING APPROVAL** |  |  |
| Cross-session duplicate review policy | **PENDING APPROVAL** |  |  |
| Timestamp/clock anomaly process | **PENDING APPROVAL** |  |  |
| Per-feature missingness expectations | **PENDING APPROVAL** |  |  |
| Capture interruption and loss handling | **PENDING APPROVAL** |  |  |
| Scenario provenance and uncertainty review | **PENDING APPROVAL** |  |  |
| Privacy/troubleshooting-identifier policy | **PENDING APPROVAL** |  |  |
| Review evidence, backup/sync, and deletion handling | **PENDING APPROVAL** |  |  |

The readiness checklist remains pending until these decisions and the separate
authorization items are explicitly approved.
