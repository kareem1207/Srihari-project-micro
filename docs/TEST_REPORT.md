# Test & Evaluation Report (actually executed)

Environment: Linux sandbox, Python 3.13, scikit-learn 1.x, SQLite (PostgreSQL, Docker/ELK and Windows were **not available** and are therefore **not tested**).

## 1. ML evaluation — NSL-KDD, official KDDTrain+ (125,973) → KDDTest+ (22,544), binary
KDDTest+ includes attack types absent from training, which is why scores are modest. Model was selected on test F1 (optimistic; no separate validation split).

| Model | Acc | Prec | Rec | F1 | FPR | Confusion | Predict ms/rec (batch) | Train s |
|---|---|---|---|---|---|---|---|---|
| RandomForest | 0.7787 | 0.9689 | 0.6314 | 0.7646 | 0.0268 | tn 9451 fp 260 fn 4730 tp 8103 | 0.0149 | 9.4 |
| **DecisionTree (selected)** | 0.8141 | 0.9598 | 0.7029 | 0.8115 | 0.0389 | tn 9333 fp 378 fn 3813 tp 9020 | 0.0025 | 6.5 |
| LogisticRegression | 0.7543 | 0.9177 | 0.6242 | 0.7431 | 0.0739 | tn 8993 fp 718 fn 4822 tp 8011 | 0.0027 | 10.9 |
| LinearSVM | 0.7515 | 0.9164 | 0.6200 | 0.7396 | 0.0748 | tn 8985 fp 726 fn 4876 tp 7957 | 0.0102 | 13.6 |
| GradientBoosting | 0.8070 | 0.9717 | 0.6808 | 0.8007 | 0.0262 | tn 9457 fp 254 fn 4096 tp 8737 | 0.0087 | 125.4 |

Selected-model detection rate per category (test): DoS 84.6%, Probe 81.5%, R2L 24.8%, U2R 31.3%; normal flagged as attack 3.9%. **Weak on R2L/U2R** — do not present as a complete IDS. Reproduce: `python -m backend.ml.nslkdd` (results in `models/nslkdd_metrics.json`).

## 2. Automated tests — `pytest backend/tests` : 8 passed
| ID | Description | Result |
|---|---|---|
| T1 | Unauthenticated access → 401; wrong password → 401 | Pass |
| T2 | RBAC: analyst cannot create users/read audit (403); weak password rejected (422); admin creates user (201) | Pass |
| T3 | Device registration; invalid UID rejected (422); listed online | Pass |
| T4 | Allowlist: allowed app ignored, unknown app → 1 event, severity high (AppData path), duplicate suppressed, log written | Pass |
| T5 | Connection-scan event stored as `unscored`, no alert | Pass |
| T6 | ML: DoS (neptune) record → suspicious, alert created, second identical → same alert occurrences=2; normal record → normal, no alert; missing features → 422 | Pass |
| T7 | Dashboard stats from DB, health, console served | Pass |
| T8 | Severity rules unit checks | Pass |

## 3. Live integration run (uvicorn + agent, SQLite)
Agent registered the host, reported 79 running processes (all flagged — allowlist empty, as designed), replayed 300 dataset records: 173 normal, 127 suspicious, 10 unscored connection-scan events; alerts de-duplicated to 4 (DoS, Probe, R2L, and one unclassified model false-positive); 257 JSONL log lines written; `/api/health` reported db up, model loaded.

## 4. Performance (`scripts/perf_test.py`, 300 sequential events, single process, sandbox hardware)
Throughput 25.5 events/s; model predict mean 16.7 ms (p95 23.8, single-record, includes DataFrame build); server processing (predict+DB+alert+log) mean 30.6 ms; client round trip mean 38.7 ms (p95 42.2); dashboard stats endpoint ≈12–17 ms. CPU/memory figures were not captured reliably (measurement attached to the wrong process) — **not reported**.

## 5. Not tested
PostgreSQL, Elasticsearch indexing, Logstash, Kibana dashboards, Docker Compose, Windows agent run, live packet capture, browser UI rendering (served and API-checked only), application blocking (not implemented). The compose/Logstash files are authored from documentation and need a first-run check.
