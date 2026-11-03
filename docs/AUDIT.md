# Technical Audit — baseline (hbkcreation/SecureWorkAI)

Audited from a fresh clone. The baseline was imported unchanged as the first commit; all new work lives in new directories (`backend/`, `agent/`, `deploy/`, `db/`, `scripts/`).

## Existing architecture
PySide6 **desktop** app (Python 3.14, Windows): Argon2id local login → dashboard with USB Wi-Fi adapter verification (CIM), opt-in Npcap/Scapy packet-metadata capture, bidirectional flow aggregator, and a **disabled** live-IDS compatibility gate. Local SQLite-style `event_store`; JSON account store.

## Existing features (verified from code/docs)
Login/logout; USB adapter policy check; packet metadata + flow aggregation; offline UNSW-NB15 Random Forest train/evaluate/compare/tune scripts; live-flow schema/export/integrity design (extensive docs); ~155 unit tests (per README, Windows target).

## Missing (before this work)
Server/API; PostgreSQL; process/application monitoring and allowlist; centralized logging (ELK); web dashboard; alerting with severity/dedup; RBAC; any trained model or dataset in the repo (excluded by `.gitignore`); deployment automation.

## Findings / compatibility problems
1. **No model or dataset shipped** → the existing ML cannot run from a checkout; UNSW-NB15 CSVs are not redistributable here and could not be fetched in the dev sandbox.
2. **Schema gap (documented by the authors):** only 2 of 42 UNSW features have verified live semantics, so live ML is correctly disabled. This audit agrees and did *not* bypass the gate.
3. README states 8,541 test rows overlap training vectors in UNSW — metrics there are optimistic.
4. `dashboard_window.py.before_encoding_fix` / `.encoding-backup` are stray backups (left untouched).
5. `npcap-1.89.exe` (installer binary) is committed to source control; consider removing it and linking to the vendor.
6. Desktop app and any server were disconnected: no event left the machine.

## Decisions
- Preserve the UNSW canonical schema and desktop app untouched.
- Add a **separate** server platform. Because live packets cannot yield model features, the server's IDS scores *flow records carrying the NSL-KDD 41-feature schema* (public dataset, downloaded by script) — flow/dataset-based, **not** live packet detection.
- PostgreSQL for structured data; Elasticsearch/Logstash/Kibana for logs (Datadog is paid/SaaS and unsuitable for an academic offline deployment).
