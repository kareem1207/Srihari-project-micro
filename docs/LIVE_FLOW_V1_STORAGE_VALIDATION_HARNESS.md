# live_flow_v1 disposable temporary-directory storage-validation harness

## Scope

`app.security.storage_validation_harness` is an opt-in diagnostic for
disposable temporary test directories only. It creates only synthetic
in-memory `live_flow_v1` records and has no capture, Npcap, dashboard, SQLite,
IDS, or model dependency. It does not authorize a pilot, select a storage
location, or validate selected or production storage.
It does not certify user-selected directories, removable drives, network
shares, or any production storage. Future selected-storage validation requires
a separately designed, reviewed, and explicitly authorized component; it is
not implemented by this harness.

## Required invocation boundary

The operator must first create an existing, empty, disposable child directory
outside the SecureWork project. Its name must be:

```text
.securework-storage-validation-<32 lowercase hexadecimal characters>
```

The harness has no default path and requires both the explicit directory and
`--confirm-disposable`:

```powershell
.\.venv\Scripts\python.exe -m app.security.storage_validation_harness `
  --validation-dir "$env:TEMP\.securework-storage-validation-<id>" `
  --confirm-disposable
```

It refuses missing, relative, non-directory, nonempty, incorrectly named, or
project-contained targets. Before use, it checks every existing path component
for a detected symbolic link or Windows reparse point and compares the
canonical target with the canonical project root. It does not change ACLs or
prove that a caller-supplied directory belongs to a Windows temporary root;
the disposable-temporary-directory restriction remains an operator obligation.

## Checks and cleanup

The harness performs a normal synthetic export/deletion, existing-session
collision check, create-new lock-file contention check, and an injected
directory-rename failure to check staging/lock cleanup. A harness-wide root
lock coordinates cooperating runs, and root identity is rechecked before
exporter operations. Cleanup verifies the observed file identity and opaque
contents before removing a harness-created lock or receipt. If unexpected
locks, staging directories, session directories, receipts, or other files
remain, it preserves them and fails for manual review.

The injected rename failure is simulated. The harness does not prove real ACL
denial, multi-process contention, process crash, power-loss durability,
antivirus interference, symbolic links, every reparse-point type, or behavior
on an unapproved volume. These checks reduce pathname races but do not make a
multi-step pathlib workflow universally race-free against a privileged process
that replaces paths after the final identity check. The harness must not be
run against selected, pilot, or production storage. No current test or
documentation authorizes use beyond disposable temporary directories. The
residual Windows risk requires a separately approved design and validation
process before any future storage use is considered.

The current handle increment protects only exporter session locks. It does not
make the harness, staging cleanup, export publication, deletion, or receipt
publication handle-bound. A dedicated directory and restrictive ACLs can
reduce exposure, but do not prove handle-bound race resistance. The harness
remains prohibited from selected, pilot, and production storage and must not
be described as protected from concurrent pathname replacement.

Native helper development is deferred pending an approved API design,
Windows-version/filesystem compatibility strategy, and maintenance plan. The
current investigation did not establish an acceptable documented Win32 API
combination for every required operation; it does not claim that no such
combination exists in general.

Retain the JSON stdout result, command transcript, volume/ACL inspection, and
approval evidence separately from flow features. The harness does not schedule
the seven-day retention process.
