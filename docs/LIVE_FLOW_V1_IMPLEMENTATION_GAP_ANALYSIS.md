# live_flow_v1 pre-pilot implementation gap analysis

## Scope and evidence standard

This analysis is based on the current repository code and tests. It does not
authorize capture, export, labelling, training, or deletion. “Demonstrated”
means covered by source inspection and a named test; “unverified” means that no
repository evidence establishes the behavior in the intended Windows storage
environment.

## Findings

| Severity | Finding and evidence | Consequence | Recommended next action |
|---|---|---|---|
| **BLOCKER** | **There is no live capture-to-export path.** `app/security/offline_flow_export_workflow.py` composes explicit in-memory `CompletedFlow` inputs, the adapter, and exporter, but has no production caller and imports no packet-capture, dashboard, IDS, or event-store code. Repository call-site search finds the workflow only in its temporary-directory tests. | The current component cannot conduct an operational pilot by itself. This is a deliberate non-operational boundary, not evidence of a broken capture path. | Before any operational pilot, separately authorize and design an explicit capture-to-completed-flow-to-export integration with lifecycle, scope, and privacy review. Do not connect it under the present approval state. |
| **LOW** | **Live IDS/event persistence is separate from the exporter.** `app/security/ids_service.py` sends `SecurityEvent` objects to `SecurityEventStore.save_event`; `app/security/event_store.py` is SQLite event history. Neither imports the exporter/schema. `tests/test_live_ids.py` confirms the compatibility gate blocks predictions; `tests/test_event_store.py` uses a temporary database. | Pilot export cannot create a security event or production SQLite record through the current code path. | Preserve the separation. Any future integration needs an explicit, separately reviewed design. |
| **LOW** | **Exported records cannot be represented by this schema as verified benign/attack labels.** `LiveFlowV1Record.as_dict()` writes schema/collector/session metadata, flow ID, finalization reason, features, and missingness only. `SessionManifest` has no label field. The protocol, pilot plan, and quality proposal state that scenario context does not label individual flows. | A caller can still store labels in a separate external file, so provenance is a governance process rather than a technical guarantee outside the export format. | Keep labels in a separately approved store. Require review evidence before any future supervised use. |
| **MEDIUM** | **Direct exported fields are tightly validated, while uncommon JSON object behavior remains unverified.** `validate_export()` allow-lists manifest configuration keys; validates strings, integers excluding booleans, finite numeric values, IDs, versions, timestamps, ordered feature names, missingness, and finalization reasons. Exporter and workflow tests cover NaN, malformed metadata, private fields, free-form values, duplicates, failed publication, and a forced record-write failure with staging cleanup and safe retry. | Ordinary dataclass-derived records are constrained to JSON-safe primitives. An unusual caller-supplied `Mapping` implementation is still not independently exercised, though the tested write-failure path does not publish a completed directory. | If the exporter is exposed beyond the current typed record API, add a temporary-directory test for a nonstandard mapping/JSON failure. This is an improvement, not authorization by itself. |
| **MEDIUM** | **Batch duplicate protection is only within one export.** `validate_export()` tracks `seen_flow_ids` in the supplied batch; export rejects an existing session directory. Cross-session duplicate feature vectors are only proposed for manual review in the quality criteria. | Repeated or related observations can remain across sessions and later create leakage or quality concerns. | Approve and implement a review procedure before dataset construction; do not silently deduplicate records. This is not needed merely to preserve an offline pilot export. |
| **HIGH** | **Seven-day retention is recorded, not automatically enforced.** `validate_export()` requires `retention_delete_after == actual_end + timedelta(days=7)`. `delete_export()` only runs when explicitly called with an output root, session ID, and deletion timestamp. There is no scheduler, retention service, or automatic deletion call site. | No code ensures timely deletion. Data remains until an authorized operator invokes deletion, and copied/backed-up data is outside exporter control. | Before pilot authorization, approve a manual deletion owner, calendar/process, evidence location, backup/sync inventory, and escalation path. If policy requires automatic enforcement, it is a later separately authorized implementation requirement. |
| **HIGH** | **Windows reparse-point and interrupted-operation coverage remains incomplete.** The exporter checks reparse-point attributes and `test_junction_output_or_deletion_target_is_rejected` verifies directory-junction rejection in a temporary directory. `test_permission_failures_fail_closed_and_release_no_lock` verifies simulated lock/staging permission failures. Symbolic-link creation is still skipped when Windows denies the privilege; real ACL denial, other reparse types, behavior beyond disposable temporary directories, and process interruption are not runtime-verified. | Path checks and recovery assumptions may still differ with other reparse points, antivirus interference, actual permissions, crashes, or network/removable storage. | Before any future storage component is considered, define and separately approve a safe validation design for the intended storage environment. The current harness must not be used against selected, pilot, or production storage. |
| **MEDIUM** | **Atomic publication is only as strong as the selected filesystem.** `LiveFlowExportStore.export()` writes and flushes a staging directory, then calls `os.replace`; failure cleanup is tested with a simulated rename error. The export design correctly does not claim universal power-loss durability. | A crash or power loss can leave stale staging/locks or filesystem-dependent durability outcomes. | Select and approve local storage characteristics; retain the manual recovery procedure. Treat crash-durability validation as a Windows/storage-environment test, not as a claim already proved by unit tests. |
| **MEDIUM** | **Privacy is enforced for the exported record shape, not all surrounding storage.** The record schema omits endpoint fields; exporter restricts manifest fields/configuration, IDs, protocol vocabulary, and opaque notes references. Exporter tests reject `source_ip` in configuration and free-form values. Separate scenario logs, control records, backups, copied files, and troubleshooting identifiers are outside the exporter. | A compliant export can coexist with non-compliant auxiliary records if people or later components store them without approved controls. | Before collection, approve storage roles, output location, backup/sync handling, troubleshooting-ID policy, and review evidence format. Audit auxiliary stores separately. |
| **LOW** | **Some quality criteria cannot be measured from export data alone.** The export contains no capture-drop count, interface name/device ID, operator identity, authorization evidence, planned boundaries, raw wire length, true connection completion, scenario evidence, or backup/copy inventory. `captured_bytes` is an observed `len(packet)` total, not original wire bytes. | Missingness and finalization reason can signal limited observation but cannot quantify capture loss or prove scenario provenance. | Keep these items in a separate, access-controlled pilot-control/review record. Approve the format before collection; do not invent values in feature data. |

## Question-specific conclusions

### Capture to exporter

No current production path reaches the offline exporter. The offline workflow
can compose supplied flows in temporary-directory tests, while
`LiveFlowAggregator` and `IDSService` support a separate live-flow/IDS path.
This proves production disconnection at repository-call-site level, but it does
not verify that a future capture-facing integration will be safe.

### Retention and deletion

The seven-day value is a validated metadata deadline. The only deletion
mechanism is the caller-invoked `LiveFlowExportStore.delete_export()` method.
There is no automatic retention scheduler or external enforcement in this
repository.

### Locking, publication, deletion, and receipts

The focused exporter tests demonstrate same-session lock rejection, existing
session/receipt collision rejection, simulated publication and permission
failure cleanup, simulated deletion failure without a receipt, malformed-
manifest rejection, and temporary-directory directory-junction rejection.
They do not demonstrate real multi-process contention, symbolic-link creation
in this account, every Windows reparse-point type, real ACL denial, crash
recovery, antivirus locking, or power-loss durability.

### Labels and privacy

The export format does not contain labels and the documents prohibit treating a
scenario as a flow label. Privacy field allow-lists support the format-level
claim. They do not control separately maintained notes, pilot-control records,
backups, sync copies, or any later label store.

## Classification summary

### Pre-pilot blockers

- Explicit authorization, storage/access, retention owner, and quality
  acceptance decisions remain pending.
- A pilot that requires actual live collection needs a separately authorized
  capture-to-export integration; none exists today.
- Windows storage behavior should be verified in an approved non-production
  directory before relying on symlink/reparse-point handling or manual
  interrupted-operation recovery.

### Later improvements

- Broader serialization-failure coverage for nonstandard mapping behavior.
- Cross-session duplicate analysis tooling.
- Automatic retention enforcement, only if the approved policy requires it.
- Additional storage/crash recovery tests for the selected Windows filesystem.

### Approval decisions rather than code defects

- Authorized device, network scope, interface, duration, and responsible
  people.
- Output directory, access roles, backup/sync handling, and deletion evidence.
- Troubleshooting identifier policy and separate review-record format.
- Missingness, interruption, duplicate, and clock-quality thresholds.

Collection remains unauthorized, and the live-inference compatibility gate
remains outside this offline exporter.
