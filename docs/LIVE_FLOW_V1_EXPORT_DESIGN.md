# live_flow_v1 collection/export design

## Scope and approval boundary

This design provides an offline-safe exporter for explicitly supplied,
in-memory live_flow_v1 records. It has no Scapy, Npcap, network-monitor,
dashboard, IDS-service, or SQLite dependency. It does not start a capture,
select an interface, create labels, or use a default production output path.

Activation against live traffic remains pending approval of authorized network
scope and interface, maximum capture duration, storage/access roles,
seven-day retention and deletion verification, privacy policy, and
data-quality acceptance thresholds.

## Proposed storage layout

A caller supplies an already-existing output root. The exporter atomically
creates one child directory named by the opaque session ID. This describes the
code interface; the current supported-use restriction below limits use to
synthetic, disposable temporary-directory tests:

    caller-selected-output-root/
      SESSION-ID/
        manifest.json
        flow_records.ndjson
        export_summary.json

- manifest.json holds session, scenario, configuration, timestamp, and
  retention metadata. It can contain only an opaque reference to separately
  controlled operator notes; free-text notes are not exported.
- flow_records.ndjson contains one schema-complete feature record per line. It
  contains schema metadata, session ID, flow ID, finalization reason, ordered
  features, and explicit missingness only.
- export_summary.json holds record counts, rejection/error counts, versions,
  and the ordered feature names.

Future labels must reside in a separately access-controlled label store. They
link through session_id and flow_id only and must never become feature columns.
Validation results are represented by the summary on successful export and by
the in-memory ValidationReport on rejection; invalid batches create no dataset
directory.

Endpoint IP addresses and ports are not written. Troubleshooting identifiers
are out of scope for this exporter. If separately authorized later, they need
a stated purpose, separate access control, minimal retention, and documented
deletion verification.

The output root must be an existing directory with no detected symbolic-link or
Windows reparse-point component in its path. It is canonicalized before use.
Session IDs use a restricted opaque-identifier format, so they cannot contain
traversal separators. One create-new lock file per session coordinates
cooperating export or deletion calls. Lock cleanup verifies a unique owner token
and observed file identity; a changed lock is preserved for manual review.

## Validation behavior

Before any write, the exporter validates:

- exact schema, collector, and orientation versions;
- opaque session ID plus non-empty scenario and interface metadata;
- timezone-aware ISO 8601 actual start/end timestamps (numeric UTC offset or
  `Z`);
- actual end not before actual start;
- retention_delete_after exactly seven days after actual end;
- each record's matching session and version metadata;
- exact ordered feature names and one missingness reason per null value; and
- unique, generated 32-character lowercase hexadecimal flow IDs within a
  batch.

Feature validation is schema-driven: strings must be non-empty, integers must
be integers rather than booleans, and numeric values must be finite. The
exporter accepts only the defined manifest fields and feature record structure;
it has no field for endpoints, payloads, credentials, labels, or free-text
operator notes. Scenario-catalogue versions are numeric, finalization policy
uses the current collector's fixed vocabulary, and an optional application
version must use the documented `vMAJOR[.MINOR[.PATCH[.BUILD]]][-TAG]` format.
Collector configuration accepts only idle timeout, finalization policy, and an
optional application version. Protocol values are restricted to tcp, udp,
icmp, or the collector's `ip-0` through `ip-255` representation.

Malformed records, duplicate flow IDs, mismatched metadata, and missingness
errors are rejected unchanged. The ValidationReport includes accepted count,
rejected count, and field-level errors. The exporter neither fills missing
values with zero nor infers labels from scenario names.

## Atomic export and deletion

The exporter writes flushed manifest, record, and summary files to a temporary
directory under the caller's chosen output root. It publishes the completed
directory with a single directory rename. If write or rename fails, the
temporary directory is removed and no completed session directory is reported.
The files are flushed before publish, but directory rename and file flush do
not establish power-loss durability across every Windows filesystem or storage
device. Interrupted-process staging directories and stale locks may remain;
they must be reviewed and removed manually only after confirming no operation
is active.

Deletion is a separately invoked operation with an explicit output root, safe
session ID, and timestamp. It rejects detected reparse-point roots and targets,
rechecks output-root identity during operations, verifies the manifest session
ID, uses the same session lock, and writes the receipt under the output root
only after the directory is absent. The caller must invoke it only after the
approved retention decision; this component does not schedule retention or
delete anything automatically. Path identity checks fail closed when a changed
path is observed, but do not provide a universal Windows handle-based guarantee
against a replacement after the last check.

## Verified tests and Windows limitations

Temporary-directory tests verify rejection of Windows directory junction output
roots, targets, and ancestors; existing-session/receipt collisions; active lock
files; staged-write failure cleanup; safe retry; and simulated lock or staging
directory permission failures. These tests do not verify real NTFS ACL denial,
symbolic-link creation in the current account, every reparse-point type,
multi-process replacement after a final identity check, or the behavior of any
future pilot storage volume. They do not establish crash or power-loss
durability.

## Supported use and concurrent-mutation threat model

The current exporter is supported only for synthetic, disposable
temporary-directory tests. It is not approved for selected pilot storage,
production storage, or any directory that contains valuable data. It does not
provide a general guarantee against concurrent filesystem mutation.

The Windows backend has narrowly scoped, host-tested behavior: it inspects the
final output-root handle, rejects a detected final reparse point, identifies
that handle, and creates/releases an active session lock through its held
handle. The lock test on the current Windows host verified ordinary pathname
rename and deletion attempts are blocked while that lock remains open. These
results do not establish behavior for every Windows filesystem, privileged
process, crashes, or arbitrary concurrent replacement.

Staging-directory creation, staged file writes, directory publication,
recursive deletion, and deletion-receipt publication remain pathname-based.
They are not protected against every time-of-check/time-of-use race. A
dedicated directory and restrictive ACLs can reduce exposure to ordinary
competing processes, but do not by themselves establish handle-bound race
resistance.

## Windows handle-backend increment

On Windows, `windows_handle_fs.py` uses only documented Kernel32 APIs through
the Python standard library's `ctypes`; no third-party dependency or
undocumented NT API is used. The backend uses `CreateFileW` with
`FILE_FLAG_BACKUP_SEMANTICS` and `FILE_FLAG_OPEN_REPARSE_POINT`,
`GetFileInformationByHandleEx(FileIdInfo)` for stable file identity,
`GetFileInformationByHandle` plus `FSCTL_GET_REPARSE_POINT` to reject detected
reparse points, and `SetFileInformationByHandle(FileDispositionInfo)` to delete
the held lock file on normal release. Session locks are created with
`CREATE_NEW`, retain a handle, and do not share write or delete access.

| Operation | Status | Actual guarantee in this increment |
|---|---|---|
| Existing final output root | **IMPLEMENTED** | A retained handle rejects a detected final reparse point and has a stable file ID. |
| Existing ancestor validation | **PARTIALLY IMPLEMENTED** | Existing pathname checks reject known ancestors; a retained handle is not held for every ancestor. |
| Session-lock create/release | **IMPLEMENTED** | `CREATE_NEW` plus the held lock handle blocks ordinary competing rename/delete attempts tested on this Windows host. Lock deletion is handle-bound. |
| Staging creation and cleanup | **UNSUPPORTED** | `tempfile` and `shutil.rmtree` remain pathname based; no handle-bound claim is made. |
| Session publication | **UNSUPPORTED** | `os.replace` remains pathname based. No-replace publication requires verified `FileRenameInfo` or a native helper. |
| Session deletion | **UNSUPPORTED** | Recursive `shutil.rmtree` remains pathname based and is not protected by the retained root handle. |
| Receipt creation | **UNSUPPORTED** | Receipt collision and `os.replace` remain pathname based. |

The retained root handle preserves its stable identity after a pathname rename,
but testing on this Windows 10 host showed that it does not itself prevent the
directory rename. It therefore detects only operations explicitly performed on
the retained handle; it does not bind subsequent `pathlib`, `tempfile`,
`shutil`, or `os.replace` calls to that root.

`FileRenameInfo` and `FileRenameInfoEx` are deliberately not used yet. Their
no-replace semantics and directory-handle-relative behavior must be verified on
the supported Windows 10/11 and NTFS configurations before they can replace
publication or receipt creation. No acceptable documented Win32 API
combination for the complete required workflow was established in the current
investigation. This does not rule out such a combination in general. Native
helper development is deferred pending an approved API design, compatibility
strategy, and maintenance plan. Until then, no staging, publication, deletion,
or receipt operation may claim handle-bound protection.

## Non-operational status

The component is intentionally not wired to packet callbacks, completed flows,
the dashboard, or the event database. Tests use temporary directories and
synthetic in-memory records only; they are not observations or security events.
