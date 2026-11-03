# Source-only release manifest

## Scope

This manifest describes a shareable source-only SecureWork AI prototype release.
It is not a dataset, trained-model, selected-storage-export, live-inference, or
pilot release.

## Include

- Tracked application source under `app/`.
- Tracked unit tests under `tests/`.
- `README.md`, `PROJECT_CONTEXT.md`, and tracked project documentation under
  `docs/`.
- `.gitignore`, `requirements.txt`, and `requirements-win-cp314-x64.lock`.
- `config/device_policy.example.json`, which contains no approved local device.

## Exclude

The following are local, generated, external, or machine-specific and must not
be included in a source release:

- `.venv/` and other virtual environments.
- `config/device_policy.json`, which is local administrator-managed device
  policy.
- `data/`, account stores, SQLite databases, and other local application data.
- `logs/`.
- `dataset/` and other dataset copies.
- Trained-model artifacts, training metadata, comparison outputs, and other
  files under `models/` that are ignored by Git.
- `app/ui/dashboard_window.py.before_encoding_fix` and
  `app/ui/dashboard_window.py.encoding-backup`, which are local recovery
  snapshots.
- `Start_SecureWork_AI.bat`, which contains a machine-specific absolute path.
- `npcap-1.89.exe`; Npcap is an external prerequisite for optional live packet
  capture and its installer is not bundled with this release.

## Environment and validation

The validated target environment is Windows 10 or 11 x64 with CPython 3.14.4.
Create a fresh local virtual environment and install the target-specific,
hash-checked resolved dependency lock:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements-win-cp314-x64.lock
```

Provision a local account before signing in:

```powershell
.\.venv\Scripts\python.exe -m app.security.provision_account
```

The documented validation commands are:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q app tests
```

`requirements.txt` is the reviewed direct-dependency policy;
`requirements-win-cp314-x64.lock` is the fully resolved lock for this one
Windows x64 / CPython 3.14.4 target. The lock was generated using
`pip-tools 7.6.2`, not raw `pip freeze`.

A fresh short-path Windows x64 / CPython 3.14.4 validator installed the lock
with `--require-hashes`; `pip check`, the complete unit-test suite (155 tests,
one platform-dependent skip), and the compile command above passed. This is
target-specific validation, not a claim of cross-platform reproducibility or
Npcap/live-capture qualification.

Npcap must be separately installed through an authorized external source only
when optional live packet capture is needed. It is not required for the
in-memory and fixture-based automated tests.

## Reproducibility and licensing gaps

- The direct-dependency policy and its resolved lock are qualified only for
  Windows x64 / CPython 3.14.4. Other operating systems, architectures, and
  Python versions require separate resolution and validation.
- Npcap is external to the Python lock and remains unqualified for live capture
  by this source-only release.
- Datasets, model artifacts, experiment outputs, and their acquisition,
  redistribution, provenance, and checksum decisions are outside this release.
- The repository has no declared project license, NOTICE file, or documented
  third-party attribution and redistribution decision. No license is implied by
  this manifest.

## Security and release gates

- Overall system verification is incomplete. An approved USB adapter or active
  monitoring can support only a `Partially verified` dashboard status.
- Live IDS inference remains **DISABLED** by the feature-compatibility gate.
- Selected-storage export remains **BLOCKED**.
- Pilot readiness remains **NOT READY**.
- The offline live-flow/export research components do not authorize live
  capture-to-export integration or collection.
