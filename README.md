# SecureWork AI

SecureWork AI is a final-year B.Tech CSE (AI&ML) project exploring an AI-powered secure BYOD workspace for Windows laptops. This repository implements the Phase 1 foundation, USB verification, network-monitoring foundation, offline Random Forest IDS baseline, and live-feature compatibility audit.

## Current features

- PySide6 sign-in screen and dashboard
- Explicitly provisioned local account with an Argon2id password hash
- Placeholder network connectivity and IDS statuses; USB adapter verification and opt-in packet metadata monitoring
- Basic file and console logging to `logs/securework_ai.log`
- Login → dashboard → logout flow
- USB Wi-Fi adapter status check with a manual dashboard refresh

No account or password is created automatically. Before the first login, create a local account interactively:

```powershell
.\.venv\Scripts\python.exe -m app.security.provision_account
```

The command requests a username and password without echoing the password. It stores only an Argon2id encoded salted hash in `data/accounts.json`; that local file is ignored by Git. Use `--store <path>` only when an explicitly chosen, access-controlled local account-store path is required. Missing, malformed, or inaccessible account storage causes login to fail safely and is never reset by the application.

The Phase 4 Random Forest model is an offline dataset baseline only. Live ML inference, process monitoring, application blocking, VirtualBox integration, and destructive security actions are not implemented.

## Requirements

- Windows 10 or 11
- Python 3.14.4 is the Python version currently used and verified for this project

`requirements.txt` lists the reviewed direct dependencies for the documented
Windows x64 / CPython 3.14.4 target. The fully resolved, hash-checked target
environment is recorded in `requirements-win-cp314-x64.lock`. Dependencies for
later project phases should be added when those features are implemented.

## Setup

Open PowerShell in the project directory. A fresh checkout does not include a
virtual environment; create a local `.venv` with the installed Python
interpreter:

```powershell
python --version
python -m venv .venv
```

The first command should report Python 3.14.4 for the environment documented here. Activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

For the documented Windows x64 / CPython 3.14.4 target, install the validated
resolved environment with hash checking:

```powershell
python -m pip install --upgrade pip
python -m pip install --require-hashes -r requirements-win-cp314-x64.lock
```

`requirements.txt` remains the direct-dependency policy. The lock file is
target-specific and must not be treated as portable to another operating
system, architecture, or Python version.

## Run

From the project root, with `.venv` active:

```powershell
python -m app.main
```

Run the documented provisioning command before signing in. Network connectivity
and IDS status remain placeholders; the System Status card reports only the
limited checks the application actually performs and does not claim full system
verification. Packet metadata capture is a separate opt-in feature.

## USB Wi-Fi adapter verification

The dashboard performs a one-time read-only adapter check when it opens. Use **Refresh** to check again; the application does not continuously poll devices. On Windows, the checker reads the built-in `MSFT_NetAdapter` CIM data for the interface name and description, NDIS physical-medium type, and Plug and Play device ID. Wi-Fi media values and a `USB\...` Plug and Play ID are used to identify a USB Wi-Fi interface. If Windows does not expose enough information, the dashboard reports **UNKNOWN**. This requires no additional Python package.

The shareable source tree includes `config/device_policy.example.json` with no approved adapters. Before monitoring, copy it to the local policy path:

```powershell
Copy-Item config/device_policy.example.json config/device_policy.json
```

Then configure the approved adapter identity values locally. The local `config/device_policy.json` is Git-ignored and is not included in shared source releases. For example:

```json
{
  "approved_usb_wifi_adapters": [
    {
      "name": "Copy the adapter's InterfaceDescription",
      "device_id": "USB\\VID_1234&PID_5678\\DEVICE001"
    }
  ]
}
```

Use the following PowerShell command to inspect the values Windows exposes, then copy the exact interface description and/or Plug and Play device ID into the policy:

```powershell
Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter |
  Select-Object InterfaceName, InterfaceDescription, PNPDeviceID, NdisPhysicalMedium
```

Values are matched case-insensitively. If both `name` and `device_id` are set, both must match. Prefer `device_id` because interface names can be changed. Empty values do not approve any adapter. Treat the policy as a local administrator-managed configuration file.

USB adapter verification is an application-level device control. It does not itself provide cryptographic network authentication or guarantee network security; network-side authentication and other controls are still required.

## Network monitoring foundation

Network monitoring is an opt-in metadata collector. Opening the dashboard only lists interfaces; packet capture starts only after **Start Monitoring** is selected and stops with **Stop Monitoring** or logout. The monitor will not silently switch to another interface. It requires an interface that matches the adapter approved by `config/device_policy.json`.

On Windows, Scapy supplies the interface list and Npcap provides packet capture through its WinPcap-compatible API. Npcap is a separately installed prerequisite for optional live packet capture; its installer is not bundled with this source release. Install it through an authorized external source if it is not already available, then use **Refresh Interface** to reload the available interface list. If Npcap, capture permissions, or the approved interface are unavailable, capture reports an error and remains stopped.

For IPv4 packets, the monitor derives timestamp, source and destination IP, protocol, packet length, TCP/UDP ports when available, and TCP flags. It tracks directional five-tuple flow packet counts, total bytes, first/last seen time, duration, and average packet size. Data is kept in memory for the current application session; raw packets and payload contents are not saved or displayed.

Phase 3 only collects and summarizes network metadata; it is not connected to the Phase 4 offline classifier and does not classify live traffic. Interface/provider behavior and packet visibility depend on Windows, Npcap, driver support, and permissions; automated tests use in-memory packets and do not require a live capture device.

## Phase 4: Random Forest IDS baseline

Phase 4 trains a binary Random Forest pipeline with the supplied UNSW-NB15 official training and testing CSVs. The dataset's `label` field is used as provided (`0 = Normal`, `1 = Attack`); its `attack_cat` values are checked against that mapping. `id` and `attack_cat` are excluded from the model inputs to avoid identifier and target leakage. Numeric fields use median imputation; categorical fields use most-frequent imputation and one-hot encoding. The preprocessing is fit only on training data and saved together with the classifier.

Train and evaluate from the project root using the existing virtual environment:

```powershell
.\.venv\Scripts\python.exe -m app.ml.train
.\.venv\Scripts\python.exe -m app.ml.evaluate
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The trained pipeline is saved as `models/securework_ids.joblib`; `models/training_metadata.json` records the dataset files, feature schema, split, configuration, and measured test metrics. A prediction API is available through `app.ml.predict.load_model`, `predict`, and `predict_proba`; it is not connected to live packet capture. The UNSW-NB15 feature-to-live-monitor comparison is documented in [`docs/UNSW_NB15_FEATURE_MAPPING.md`](docs/UNSW_NB15_FEATURE_MAPPING.md).

Phase 3 currently provides packet metadata and a small set of directional flow statistics, not the full UNSW-NB15 flow extractor. Many training inputs (including TTL/window/handshake details, application service fields, and historical connection counts) cannot be produced by it. Inspection found 8,541 test rows with input-feature vectors also present in training; 296 of those rows have a label not observed for that vector in training. The official split is preserved, and this overlap limits test independence. Metrics describe this dataset partition only and are not a claim of real-world detection accuracy or enterprise-grade security.

## Live IDS compatibility safeguards

The dashboard connects the existing packet monitor to a payload-free bidirectional flow aggregator. A flow is keyed by its endpoint pair and protocol, tracks first/last time, directional packet and byte counts, packet rate, directional load, mean packet size, and observed inter-packet timing. Phase 6 additionally retains IPv4 TTL, TCP window, and first observed TCP sequence metadata per direction. It calculates SYN-to-SYN/ACK, SYN/ACK-to-final-ACK, and full observed handshake timing only when every required handshake packet is observed. Partial captures and retransmitted packets remain explicit; unavailable timings are omitted.

The Phase 4 model still expects 42 UNSW-NB15 fields. Only two individual live inputs have verified compatible semantics (`proto` and `is_sm_ips_ports`). Twenty-four values are available only as non-equivalent approximations, including duration, directional counts, byte totals, timing, TTL, TCP window, sequence, and handshake fields. **Live ML predictions are disabled** by a compatibility gate. The GUI shows model status, capture status, completed flows checked, and that detection counts are unavailable. It does not produce fake predictions or alerts. A model result, when the schema is compatible in a future implementation, is a signal rather than proof of compromise; predicted attacks are represented as `SUSPICIOUS` events.

Model loading runs outside the GUI thread. Missing/corrupt models and capture errors are surfaced as status messages; no packet payloads, credentials, or application contents are stored. Start/stop capture uses the existing monitor lifecycle; IDS analysis controls remain disabled until every required field has verified semantics. The Phase 4 model must not be used directly with these flows. A future phase should train and evaluate a separate model on a small, payload-free schema collected by this exact extractor and a held-out capture set. See [`docs/UNSW_NB15_FEATURE_MAPPING.md`](docs/UNSW_NB15_FEATURE_MAPPING.md) for the full field-by-field status. Run the complete test suite with `.\.venv\Scripts\python.exe -m unittest discover -s tests -v`.

## Source-only release boundaries

This repository can be shared as a source-only prototype. It includes source,
tests, documentation, dependency declarations, and the empty USB-policy example
at `config/device_policy.example.json`. It does not include local device policy,
account or database data, logs, datasets, trained-model artifacts, or experiment
outputs. See [`docs/SOURCE_RELEASE_MANIFEST.md`](docs/SOURCE_RELEASE_MANIFEST.md)
for the complete inclusion and exclusion list.

The offline training and evaluation commands require separately obtained,
authorized datasets and any required model artifacts. Their absence from a
source-only checkout is expected.

The target-specific lock was generated with `pip-tools 7.6.2` from the reviewed
exact direct pins, then installed with `--require-hashes` in a fresh Windows x64
CPython 3.14.4 environment. In that environment, `pip check`, the complete
unit-test suite (155 tests, one platform-dependent skip), and
`python -m compileall -q app tests` passed. This validates only the documented
target environment; it does not establish cross-platform reproducibility or
Npcap/live-capture compatibility.

The dashboard may report `Partially verified` after approved USB-adapter checks,
but overall system verification is not implemented. Live IDS inference remains
**DISABLED**, selected-storage export remains **BLOCKED**, and pilot readiness
remains **NOT READY**.

## Experimental ML scripts

`app/ml/tune_random_forest.py` and `app/ml/evaluate_tuned_rf.py` are offline experiments. Their scope and evaluation limitations are documented in [`docs/ML_EXPERIMENTS.md`](docs/ML_EXPERIMENTS.md). They do not replace `models/securework_ids.joblib` or change the live IDS compatibility gate.


---

## Centralized platform (server, agent, PostgreSQL, ELK) — added

A server-side platform now complements the desktop prototype. See [`docs/AUDIT.md`](docs/AUDIT.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md).

**Scope honesty:** the server IDS scores *NSL-KDD-schema flow records* (flow-export / dataset-replay). It is **not** live packet detection; the desktop app's live gate stays disabled. Live connection scans are stored as `unscored`. Application monitoring is alert-only (no blocking). ELK/Docker/PostgreSQL files were not executed in the dev sandbox.

### Quick start (dev, SQLite)
```bash
pip install -r requirements-server.txt
bash scripts/download_nslkdd.sh
python -m backend.ml.nslkdd                 # trains 5 models, saves best to models/
export SECUREWORK_JWT_SECRET=$(python -c "import secrets;print(secrets.token_hex(32))")
python -m backend.cli admin                 # prompts for password
python -m backend.cli agent1 --role agent
uvicorn backend.api:app --port 8000         # console at http://127.0.0.1:8000/ , API docs at /docs
SECUREWORK_AGENT_USER=agent1 SECUREWORK_AGENT_PASSWORD=... python -m agent.agent --once --replay 300
pytest backend/tests
```
Then allowlist your approved applications as admin via `POST /api/applications/allowlist` — until then every running process is reported.

### Production-style stack
```bash
cp deploy/.env.example deploy/.env   # set strong secrets
docker compose --env-file deploy/.env -f deploy/docker-compose.yml up -d
python -m backend.ml.nslkdd           # model must exist in ./models before using detection
```
PostgreSQL DDL: `db/schema.sql`. Kibana: http://127.0.0.1:5601 → create a data view on `securework-events*`. Config via env: `POSTGRES_*` or `SECUREWORK_DATABASE_URL`, `SECUREWORK_JWT_SECRET`, `SECUREWORK_ES_URL`.
