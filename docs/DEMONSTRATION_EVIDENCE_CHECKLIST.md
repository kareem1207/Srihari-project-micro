# Demonstration evidence checklist

## Purpose and evidence boundary

This checklist supports a final-year project demonstration, report, and viva.
It covers only the implemented prototype behavior and identifies evidence that
can be reproduced safely. It does not authorize packet capture, Npcap
installation, selected-storage export, model training, live IDS inference, or a
pilot.

Before gathering any evidence, redact usernames, adapter names, device IDs,
network addresses, account-store paths, and other personal or machine-specific
information. Do not use a personal account or production data. Do not display
passwords, password hashes, local policy contents, or database contents.

Current gates:

- Live IDS inference is **DISABLED** by the feature-compatibility gate.
- Selected-storage export is **BLOCKED**.
- Overall system verification is **INCOMPLETE**.
- Pilot readiness is **NOT READY**.

## Evidence collection rules

- Save command output and screenshots outside the repository, using a dated
  evidence folder approved by the project owner.
- Use a non-personal, explicitly provisioned local demonstration account only
  when a local GUI demonstration is separately authorized. Do not create or
  replace accounts solely for this checklist.
- Do not select **Start Monitoring** during a routine demonstration. The
  monitoring controls are discussed through tests and code-backed UI state only.
- Do not show a successful IDS alert, a prediction, or a storage export: those
  are not enabled features.
- A screenshot proves only the screen state shown at that time. A unit-test
  result proves the covered synthetic or mocked behavior, not a physical-device
  or production-environment guarantee.

## Evidence checklist

| Topic | Evidence type | Safe command or manual action | Suggested evidence filename | Expected observation | Does not prove |
| --- | --- | --- | --- | --- | --- |
| Login accepts a valid local account | Optional GUI screenshot | With an existing non-personal demo account and no monitoring started, launch `python -m app.main`, sign in, and capture the dashboard after redacting the username. | `01-login-success.png` | Login transitions to the dashboard. | Account-store ACL safety, multi-user access control, or any network security property. |
| Login rejects incorrect credentials | Automated test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_auth -v` | `02-auth-tests.txt` | `test_incorrect_password_is_rejected` and fail-closed storage tests pass. | A real account password, recovery workflow, or protection from local filesystem tampering. |
| Missing or malformed account storage fails closed | Automated test output | Same `tests.test_auth` command. | `02-auth-tests.txt` | Missing, unknown, malformed, and unavailable stores are rejected without authentication. | That a real local account store has correct Windows ACLs. |
| Dashboard rendering | Optional GUI screenshot | In the authorized local GUI session above, capture the dashboard before interacting with monitoring controls; redact all displayed local identifiers. | `03-dashboard-initial.png` | Dashboard cards, USB status area, network controls, IDS status, and System Status are visible. | Real adapter approval, Npcap availability, or active monitoring. |
| System Status semantics | Automated test output and optional GUI screenshot | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_dashboard_interface_selection -v`; optionally capture `Not verified` or `Partially verified` without starting capture. | `04-dashboard-status-tests.txt`, `04-system-status.png` | USB approval and active monitoring alone never produce `Verified`; pending/failed checks show `Not verified`. | Complete system verification or pilot readiness. |
| USB adapter-policy decisions | Automated test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_usb_checker -v` | `05-usb-policy-tests.txt` | Matching test device IDs are approved; empty/mismatched/unknown records fail closed. | Approval of the present physical adapter or correctness of a local policy file. |
| Approved-interface selection | Automated test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_dashboard_interface_selection tests.test_network_monitor -v` | `06-interface-monitor-tests.txt` | Unapproved interfaces are refused and no fallback interface is selected. | Successful physical capture or Npcap driver behavior. |
| Monitoring lifecycle | Mocked automated test output | Same `tests.test_network_monitor` command. | `06-interface-monitor-tests.txt` | Fake-sniffer start/stop state and metadata counters behave as tested. | Capture permissions, packet visibility, driver installation, or traffic safety on a real interface. |
| Packet and flow metadata accounting | Automated test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_network_monitor tests.test_live_ids -v` | `07-flow-accounting-tests.txt` | Constructed packets exercise protocol parsing, payload-free packet metadata, counters, flow aggregation, and partial-handshake handling. | That actual traffic will be fully observed or that a packet is malicious. |
| Offline ML pipeline | Automated test output and documentation reference | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_ml_pipeline tests.test_leakage_evaluation tests.test_ml_comparison -v` | `08-offline-ml-tests.txt` | Dataset/preprocessing, baseline metrics, and artifact-format behavior are tested with test data. | Real-world detection accuracy or a valid live IDS. |
| Live IDS remains gated | Automated test output and optional GUI screenshot | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_live_ids -v`; optionally capture the disabled IDS controls/status. | `09-live-ids-gate-tests.txt`, `09-ids-disabled.png` | Current mapping blocks live prediction; completed flows are reviewed without prediction. | That inference can be safely enabled later. |
| Event-store persistence | Automated test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_event_store -v` | `10-event-store-tests.txt` | Test-owned SQLite data can save/read ordered metadata-only event records. | A live predicted event, database provenance, or tamper-evident audit history. |
| In-memory integrity contract | Automated test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_live_flow_integrity -v` | `11-integrity-contract-tests.txt` | Canonical bytes, hashes, tamper classification, privacy allowlists, and authenticity-unknown behavior are tested. | Authenticity, trusted provenance, selected-storage safety, or durable publication. |
| Offline exporter boundary | Documentation and test output | `.\\.venv\\Scripts\\python.exe -m unittest tests.test_live_flow_export tests.test_offline_flow_export_workflow -v` only when temporary-directory filesystem tests are approved for the demonstration evidence session. | `12-offline-export-tests.txt` | Validation, collision, cleanup, and temporary-directory safeguards are exercised. | Selected-storage authorization, race-free Windows filesystem behavior, or pilot export. |
| Dependency reproducibility | Historical D49 evidence | Cite D49 results: lock installation with `--require-hashes`, `pip check`, 155 tests with one platform-dependent skip, and `compileall` passed on Windows x64 / CPython 3.14.4. | `13-d49-validation-summary.md` | A documented target environment was validated. | Cross-platform support, Npcap qualification, or a new validation run. |

## Minimal viva sequence

1. State the scope: desktop security prototype, offline ML baseline, and
   compatibility audit; not a production IDS.
2. Show the README gates and this checklist before opening the GUI.
3. If a separately authorized non-personal demo account already exists, show
   login and the dashboard. Do not show account-store files or policy values.
4. Explain the System Status card: it can be `Not verified` or `Partially
   verified`; it never establishes complete system verification.
5. Show focused, previously captured test output for USB policy/interface
   refusal, mocked monitor lifecycle, compatibility-gate refusal, and integrity
   checks. Do not start capture to manufacture a demonstration.
6. Close with D49's target-specific dependency evidence and the remaining
   exclusions: live IDS inference, selected-storage export, automatic retention,
   process control, VM integration, and pilot operation.

## Reporting language

Use these formulations in slides and the report:

- “Implemented and unit-tested with synthetic or mocked inputs” for adapter,
  monitor, flow, event-store, and export-contract tests.
- “Offline baseline” for the Random Forest model and its dataset metrics.
- “Disabled by compatibility gate” for live IDS inference.
- “Blocked pending separate filesystem qualification” for selected-storage
  export.
- “Not implemented” for process monitoring, application blocking, and VM
  isolation.

Do not describe a mocked test, a GUI counter, or a dashboard card as evidence
of a real attack detection, approved physical device, production storage safety,
or pilot readiness.
