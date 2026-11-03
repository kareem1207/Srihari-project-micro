# live_flow_v1 benign-only pilot plan

## Status

**Planning only. This document does not authorize packet capture, persistence,
labelling, or model training.** The stated laptop, approved external USB Wi-Fi
adapter/interface, and seven-day retention are proposed preferences pending
explicit approval.

This plan supplements the controlled collection protocol. If either document
has stricter requirements, the stricter requirement applies.

## 1. Pilot objective and non-goals

### Objective

Validate the operational procedure for producing metadata-only live_flow_v1
records during small, ordinary, authorized benign sessions on the operator's
Windows laptop through the approved external USB Wi-Fi adapter. The pilot is
intended to review manifest completeness, schema/missingness behaviour,
privacy controls, and data-quality checks before any future dataset study.

### Non-goals

The pilot will not:

- collect traffic in this planning phase;
- establish a labelled benign dataset or label every observed flow as benign;
- train, tune, evaluate, or enable a model;
- enable Phase 4 UNSW-NB15 inference or alter its compatibility gate;
- collect payloads, credentials, application contents, or raw packet files;
- create SQLite events, database tables, or dashboard alerts; or
- test attacks, exploits, malware, packet injection, credential capture, or
  third-party systems.

## 2. Proposed authorized scope

| Item | Proposed value | Status |
|---|---|---|
| Device | Operator-owned Windows laptop | Pending approval |
| Capture interface category | Approved external USB Wi-Fi adapter/interface | Pending confirmation of approved interface selection and scope |
| Network | Network explicitly authorized by its owner for this pilot | Pending owner authorization |
| Traffic | Ordinary benign activity only | Pending scenario approval |
| Retention | Seven days from the recorded session end time | Pending approval |

No device policy, Npcap setting, or automatic capture path is changed by this
plan. A session must stop if the selected interface is not the approved
interface or if the network scope is uncertain.

## 3. Proposed session manifest

Create one separate, access-controlled manifest per capture session. The
manifest is not a model-feature record and must not contain payloads. Use ISO
8601 timestamps with an explicit timezone.

| Field | Example format / rule |
|---|---|
| session_id | Unique opaque ID, for example BENIGN-PILOT-YYYYMMDD-NN |
| scenario_id | Predefined identifier, such as BROWSE-01 or IDLE-01 |
| scenario_definition_version | Numeric version of the approved scenario catalogue entry; scenario IDs may repeat across sessions by design |
| operator_role | Operator identifier or role approved for the pilot |
| schema_version | live_flow_v1 |
| collector_version | Exact live_flow_v1 collector version |
| interface_category | approved_external_usb_wifi |
| adapter_reference | Approved-adapter reference only; no raw device ID in the feature export |
| timestamp_timezone | Timezone-aware ISO 8601 value with numeric UTC offset or `Z`, and the Windows clock timezone recorded at session start |
| planned_start / planned_end | Manual ISO 8601 boundary timestamps with the recorded numeric offset |
| actual_start / actual_end | Manual ISO 8601 boundary timestamps with the recorded numeric offset; actual_end is authoritative for retention |
| collector_configuration | Exported configuration: idle timeout, finalization policy, and optional application version only. Capture settings belong in the separate pilot-control record. |
| finalization_reasons | Count of idle_timeout and monitor_stopped records, if collection is later approved |
| operator_notes_reference | Optional opaque reference to separately controlled notes; no free-text notes in the export manifest |
| uncertainty_flag | true when mixed, unplanned, or uncertain activity occurred |
| retention_delete_after | actual_end plus seven days |
| deletion_verification | Separate pilot-control record: pending method, evidence reference, and responsible role |

The offline exporter's `SessionManifest` contains only its defined fields:
session/scenario IDs and version, actual start/end, interface category, limited
collector configuration, retention deadline, schema/collector/orientation
versions, opaque notes reference, and uncertainty flag. Keep planned boundaries,
operator role, adapter reference, finalization-reason counts, deletion planning,
and other pilot-control metadata in a separate access-controlled control
record. Keep flow features in a separate live_flow_v1 record set. Keep operator
notes and any future labels in separate reviewable stores. Link the stores only
with session_id and flow_id; labels must never be copied into model features.
Do not join endpoint identifiers into the feature export.

## 4. Proposed benign scenarios

Each scenario is a procedure for documenting ordinary activity, not a claim
that all captured flows belong to that activity.

| Scenario ID | Ordinary activity | Boundary procedure |
|---|---|---|
| IDLE-01 | Idle connected period with no intentional foreground network task. | Record actual start/end manually; note unexpected background updates. |
| BROWSE-01 | Ordinary browsing of authorized, non-sensitive sites. | Record browser start/stop and any unrelated applications. |
| DNS-01 | Normal DNS activity caused by an approved benign task. | Record the associated benign task; do not inspect or retain DNS payloads. |
| UPDATE-01 | Approved operating-system or application update. | Record product name/version category and manual start/end; do not retain update content. |
| FILE-01 | Permitted transfer of non-sensitive test files between owned or authorized endpoints. | Record transfer start/end and test-content classification. |

Video calls or other routine tasks can be added only through a documented,
approved scenario ID before a session begins.

## 5. Manual session-boundary procedure

If collection is later authorized, the operator should:

1. Confirm the authorized network scope and refresh the interface list.
   Select only the interface that SecureWork marks approved after matching the
   USB approval check; never choose an unapproved network interface or another
   discovered interface. Stop if no approved interface is shown.
2. Create the manifest with a unique session and preapproved scenario ID.
3. Record the planned start time before any capture action.
4. Record the actual start time manually when the scenario begins.
5. Record material deviations, unrelated applications, connection changes,
   and uncertainty without recording payload content.
6. Stop the approved collection method manually, then immediately record the
   actual end time from the Windows clock using the manifest's numeric offset.
   This timestamp is the authoritative start of the seven-day retention period.
7. Record finalization-reason counts and the seven-day deletion deadline.
8. Mark the manifest as pending quality review; do not assign flow labels
   automatically.

No collection action is authorized by these steps until all approvals below are
explicitly granted.

## 6. Mixed and uncertain activity

Planned benign context is not a flow-level label. Background traffic,
unrelated device activity, software updates, DNS requests, and connection
reuse can make individual flows ambiguous.

- Set uncertainty_flag when a session contains mixed or unplanned activity.
- Do not assign a benign label solely because the scenario ID is benign.
- Preserve uncertainty and deviation notes separately from features.
- Exclude uncertain sessions or flows from any future supervised training or
  evaluation unless a separately approved review process establishes adequate
  provenance.

## 7. Retention and deletion

The exporter requires the proposed retention deadline to be exactly seven
24-hour days after the recorded actual session end timestamp. Before collection
begins, approve:

- the storage location and access roles;
- which records are retained: features, manifests, and any temporary
  troubleshooting metadata;
- deletion method for each retained data class;
- verification evidence, such as a dated deletion record; and
- the responsible operator or reviewer.

At the deadline, delete the session's exported features, manifest, and any
temporary identifying metadata according to the approved method. Record
deletion verification without recreating deleted data. Until the deletion
method is approved, the proposed seven-day retention rule is not operational.

## 8. Data-quality and privacy review

Before treating a future session as usable, check:

- schema version, collector version, feature order, types, and missingness;
- session ID uniqueness and manifest completeness;
- timestamp ordering, non-negative durations, and finalization reasons;
- missingness rates by protocol and scenario;
- duplicate feature records within and across sessions;
- interface changes, capture gaps, restarts, and known clock issues; and
- whether scenario notes show mixed or uncertain activity.

The collector remains payload-free. Do not retain endpoint addresses or ports
in exported feature records. Restrict any temporary, separately retained
endpoint troubleshooting data to approved custodians, remove it as early as
possible, and never use it as a model feature.

Captured-byte fields are Scapy captured len(packet) totals, not asserted
original wire-byte totals. Capture loss, partial observation, and idle-timeout
or monitor-stop flow finalization are unavoidable limitations. Record them as
limitations, not as packet-loss features, wire-byte measurements, or benign
labels.

## 9. Pending approval checklist

Collection cannot begin until each item is explicitly approved:

- [ ] Pilot plan and authorized network scope.
- [ ] Approved interface selection and maximum capture duration per session.
- [ ] Session-manifest format and manual boundary procedure.
- [ ] Seven-day retention period, deletion method, and verification record.
- [ ] Privacy controls and endpoint-identifier handling.
- [ ] Data-quality acceptance criteria and uncertainty exclusion rule.

The Phase 4 model, live IDS compatibility gate, USB policy, Npcap
configuration, event store, and dashboard remain outside this pilot plan.
