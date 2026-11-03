# live_flow_v1 pilot readiness and export recovery

## Status and scope

**Pilot status: NOT READY.** This document prepares for a future benign-only
pilot. It does **not** approve traffic collection, storage, labelling, or model
training. The exporter accepts explicitly supplied in-memory records only; it
does not start packet capture, select an interface, access SQLite, or enable
live IDS inference. Capture-to-export integration is not implemented.

Status meanings: **PENDING APPROVAL** requires an explicit decision; **NOT VERIFIED** lacks pilot-environment evidence; **READY** has repository evidence; **NOT APPLICABLE** is outside this planning phase.

## A. Authorization

| Item | Status | Evidence or required action |
|---|---|---|
| Approved laptop and network scope | **PENDING APPROVAL** | Record owned laptop, network owner, written scope, and time window. |
| Approved USB Wi-Fi adapter/interface | **PENDING APPROVAL** | Select only the interface SecureWork marks approved after USB device-ID verification; confirm the approved external USB Wi-Fi adapter/interface at pilot time. |
| Maximum duration and manual stop procedure | **PENDING APPROVAL** | Approve duration per session. The pilot plan describes manual stopping but authorizes no duration. |
| Named responsible person and approval date | **PENDING APPROVAL** | Complete the approval record below. |
| No collection before approval | **READY** | The exporter is disconnected from capture and existing pilot documents prohibit collection before explicit approval. |

## B. Privacy and storage

| Item | Status | Evidence or required action |
|---|---|---|
| Approved output directory and permissions | **PENDING APPROVAL** | A future approved design must choose an existing, access-controlled, non-symlink directory outside the production event database path; record owner and permissions. The current exporter and harness are supported only for disposable temporary-directory tests. The harness does not certify a user-selected directory, removable drive, network share, or pilot/production storage; that future validation requires a separately designed, reviewed, and authorized component. |
| Authorized readers, exporters, and deleters | **PENDING APPROVAL** | Define named least-privilege roles. |
| Endpoints, payloads, credentials, and free-text notes excluded | **READY** | The schema/exporter contains no endpoint or payload fields; configuration is allow-listed and notes are only opaque references. |
| Temporary troubleshooting identifiers | **PENDING APPROVAL** | Define purpose, separate storage, custodians, access logging, retention, and deletion. They must not enter features. |
| Seven-day retention clock | **PENDING APPROVAL** | Code validates a deadline exactly seven days after documented `actual_end`; it does not schedule or automatically perform deletion. The process and owner remain unapproved. |
| Deletion verification and receipt evidence | **READY** | A receipt is written only after the session directory is absent; approval is still needed for the responsible operator and evidence store. |
| Backups, sync, and copied files | **PENDING APPROVAL** | Identify all backup, cloud-sync, removable-media, and copied-file locations and apply matching retention/deletion rules. |

## C. Collection quality

| Item | Status | Evidence or required action |
|---|---|---|
| Unique session IDs and versioned scenario IDs | **READY** | Export validates opaque session IDs, numeric scenario versions, and rejects existing session directories. Maintain an approved scenario catalogue. |
| Timezone-aware timestamps | **READY** | Export validation requires timezone-aware ISO 8601 timestamps with a numeric UTC offset or `Z`. |
| Capture interface and session metadata | **PENDING APPROVAL** | Confirm the actual approved interface and collector configuration before collection. |
| Incomplete, mixed, uncertain, or interrupted sessions | **READY** | The schema has explicit missingness and finalization reasons; the manifest has `uncertainty_flag`. Assign an operational reviewer before collecting. |
| Missingness, observation limits, and duplicates | **READY** | Validation checks feature order/types/missingness and rejects duplicate flow IDs within a batch. Capture loss and partial observation remain limitations. |
| Quality acceptance thresholds | **PENDING APPROVAL** | Approve numerical limits for missingness, duplicates, capture gaps, clock drift, and session completeness. |
| Scenario context is not an automatic benign label | **READY** | The exporter has no label field and does not infer labels from scenario IDs. |

## D. Technical readiness

| Item | Status | Evidence or required action |
|---|---|---|
| Exporter disconnected from live capture | **READY** | `live_flow_export.py` has no packet-capture, dashboard, IDS-service, or SQLite dependency. |
| Live-inference gate remains disabled | **READY** | The live schema does not load models or create IDS events; compatibility safeguards remain separate. |
| Existing-session collisions and deletion failures | **READY** | Existing destinations and receipts are rejected; deletion failure writes no receipt. Focused tests cover these paths. |
| Stale lock/staging recovery is manual and reviewed | **READY** | The exporter has no automatic stale-lock or staging cleanup; follow the procedure below. |
| Windows directory-junction rejection | **READY (temporary-directory test only)** | Exporter and harness tests create directory junctions under `TemporaryDirectory` and verify rejection of output roots, deletion targets, and ancestor junctions. Canonicalization and identity checks fail closed when a change is observed; they do not prevent every later pathname replacement. |
| Simulated permission-failure handling | **READY (simulated only)** | `test_permission_failures_fail_closed_and_release_no_lock` simulates denial creating a lock or staging directory and verifies a safe error with no completed export or leftover lock. |
| Windows symlinks, other reparse points, and real ACL denial | **NOT VERIFIED** | Symlink creation is skipped because Windows denied the privilege. Junction coverage does not prove every reparse-point type, behavior on the approved storage volume, or real NTFS ACL denial. Pathlib identity checks also cannot provide a universal guarantee against a privileged replacement after the final check. |
| Handle-bound storage operations | **PARTIALLY IMPLEMENTED** | Windows `ctypes` primitives retain and identify the final output root and create/delete the active session lock by handle. Their narrow behavior is host-tested only. Staging creation, staged writes, publication, recursive deletion, and receipt creation remain pathname based and are not generally resistant to concurrent mutation. A dedicated directory and restrictive ACLs reduce exposure but do not prove handle-bound race resistance. |
| Native helper | **DEFERRED** | No acceptable documented Win32 API combination for the complete workflow was established in the current investigation. This does not claim that one is impossible in general. Development requires an approved API design, compatibility strategy, and maintenance plan. |
| Universal power-loss durability | **NOT APPLICABLE** | The design makes no universal crash/power-loss durability claim; filesystem/device guarantees vary. |
| Required validation commands | **READY** | Run the commands below before pilot authorization and after exporter changes. |

## Manual recovery: stale locks and abandoned staging directories

This is future recovery guidance only. It does not authorize collection,
deletion, or use of the current exporter against a caller-selected pilot output
root.

1. Stop the exporter process and related pilot workflow. Confirm no export or deletion operation is running for the session.
2. Record the output root, session ID, investigator, timestamp, and recovery reason. Never infer ownership from lock age.
3. Inspect without changing data: `.<session-id>.live-flow.lock`, `.<session-id>.staging-*`, the destination session directory, `manifest.json`, `export_summary.json`, `flow_records.ndjson`, and related deletion receipts/temporary receipt files.
4. Preserve evidence and make an access-controlled backup or forensic copy before removal. Record hashes or file listings where privacy rules allow.
5. Treat every staging directory as incomplete. Never present it as completed, move it to a session destination, or use it for modelling.
6. Never overwrite an existing session directory or deletion receipt. Escalate for ownership and integrity review if either exists.
7. Only after confirming no active operation, documented ownership, and preserved evidence may an authorized operator remove that specific stale lock or abandoned staging directory. Never remove a lock merely because it is old.
8. Escalate ambiguous ownership, partial deletion, invalid manifests, unexpected files, symlinks/reparse points, or session-ID/manifest mismatches. Do not guess or continue deletion.
9. Record recovery operator, timestamp, reason, inspected files, evidence/backup reference, action, and outcome.

Automatic lock cleanup and automatic staging deletion are intentionally not implemented.

## Validation checklist

Run from the project root before approval and retain results with the approval record:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_live_flow_export -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q app tests
git diff --check
```

If Windows denies symlink-creation privilege, record symlink/reparse-point behavior as **NOT VERIFIED**, not runtime-verified.

## Required pilot approvals and technical acceptance checklist

Every row must be satisfied before collection. A test result is not a human
approval, and a human approval does not substitute for the listed technical
acceptance criterion.

| Item | Current status | Required approval or evidence |
|---|---|---|
| Network scope | **PENDING APPROVAL** | Network owner, permitted devices, written scope, and collection time window. |
| Device and interface | **PENDING APPROVAL** | Approved laptop and runtime confirmation that SecureWork selects the approved USB Wi-Fi interface. |
| Responsible operator | **PENDING APPROVAL** | Named operator, approval date, and escalation contact. |
| Session duration and stop procedure | **PENDING APPROVAL** | Maximum duration and documented manual stop procedure. |
| Output location | **PENDING APPROVAL** | Existing, access-controlled, non-reparse-point storage root outside the production event database path. |
| Access roles | **PENDING APPROVAL** | Named reader, exporter, deleter, and review roles; backup/sync/copy controls. |
| Quality thresholds | **PENDING APPROVAL** | Approved thresholds for missingness, duplicates, capture limitations, clock quality, uncertainty, and exclusion. |
| Deletion owner | **PENDING APPROVAL** | Owner, seven-day calendar/process, escalation path, and receipt-evidence location. |
| Evidence handling | **PENDING APPROVAL** | Storage and access rules for approvals, manifests, review evidence, deletion receipts, and any separate troubleshooting identifiers. |
| Capture-to-export integration | **NOT IMPLEMENTED** | Separately authorized opt-in integration, review, and tests. No current application call path may be used for a pilot. |
| Storage harness scope | **NOT AUTHORIZED** | The current harness is restricted to disposable temporary test directories. It must not be run against selected, pilot, or production storage. |
| Exporter baseline | **READY** | Temporary-directory tests cover validated input, collisions, active locks, staged-write cleanup, safe retry, deletion receipt behavior, directory-junction rejection, and simulated lock/staging permission failures. |

## Unfilled pilot approval record

| Approval field | Record |
|---|---|
| Network scope and approved device/interface | **PENDING APPROVAL:** |
| Named responsible operator and approval date | **PENDING APPROVAL:** |
| Capture duration and manual stop procedure | **PENDING APPROVAL:** |
| Output directory and authorized reader/exporter/deleter roles | **PENDING APPROVAL:** |
| Retention/deletion owner and receipt-evidence location | **PENDING APPROVAL:** |
| Privacy and troubleshooting-identifier rules | **PENDING APPROVAL:** |
| Collection-quality acceptance thresholds | **PENDING APPROVAL:** |
| Approver and approval timestamp | **PENDING APPROVAL:** |
| Pilot start authorization | **PENDING APPROVAL:** |

No field is approved until completed by an authorized responsible person. This document alone does not start a pilot.
