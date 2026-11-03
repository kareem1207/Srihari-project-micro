# SecureWork AI — Platform Architecture

```
Windows device                         Server (docker compose or bare metal)
┌──────────────────────┐   HTTPS/JWT   ┌───────────────────────────────────────────────┐
│ agent/agent.py       │──────────────▶│ FastAPI  backend/api.py                       │
│  • psutil processes  │               │  auth+RBAC → validation → detection → alerts  │
│  • TCP connections   │               │        │ SQLAlchemy              │ ship()       │
│  • optional replay   │               │        ▼                         ▼              │
└──────────────────────┘               │   PostgreSQL            logs/*.jsonl ─▶ Logstash│
 PySide6 desktop app (app/) — unchanged │   (structured data)     + direct index  ─▶ Elasticsearch ─▶ Kibana
                                        │ Web console  /  (static SPA, reads the API)   │
                                        └───────────────────────────────────────────────┘
```

| Component | Role |
|---|---|
| `agent/` | Collects running applications and established TCP connections; registers device, heartbeat. Needs no admin for listing; some process paths need elevation. |
| `backend/ml/nslkdd.py` | Train/compare 5 algorithms, save best, serve predictions. |
| `backend/alerts.py` | Severity rules, de-duplication, log shipping. |
| `backend/api.py` | REST API, request validation, RBAC, audit records, dashboard stats. |
| PostgreSQL (`db/schema.sql`) | users, devices, applications, network_events, intrusion_alerts, application_events, security_logs, security_policies, audit_records (FKs + indexes). |
| Elasticsearch/Logstash/Kibana | Searchable centralized events. API indexes directly (`SECUREWORK_ES_URL`) and writes JSONL that Logstash tails. |

## Traffic collection modes (honest labelling)
- `connection-scan`: live, **connection-level** (psutil). Stored as `unscored` — no ML (features unavailable).
- `flow-export`: caller supplies NSL-KDD features from an external flow tool.
- `dataset-replay`: NSL-KDD records replayed for demo/testing. **Not live monitoring.**

## Severity rules
| Condition | Severity |
|---|---|
| Intrusion category U2R | critical |
| R2L or DoS | high |
| Probe / unclassified | medium |
| Model confidence < 0.6 | one level lower |
| Unauthorized app under `C:\Program Files` / `C:\Windows` | medium |
| Unauthorized app elsewhere (e.g. AppData) | high |

Dedup: same device + same attack category within `SECUREWORK_DEDUP_SECONDS` (300) increments `occurrences` on the existing alert; the same app per device is not re-reported within the window.
The binary model does not predict attack category; the category is known only for `dataset-replay` (taken from the dataset label). Otherwise alerts are `unclassified`.

## Security controls
Argon2id hashes; JWT (secret from env, ≥32 chars required); roles admin/analyst/agent; pydantic validation; ORM parameterized queries; audit records for logins, user/policy/allowlist changes, reports; no credentials in source. Not implemented: TLS termination (use a reverse proxy), rate limiting, password-reset, application *blocking* (monitoring/alerting only).

## Backup & retention
`pg_dump -Fc securework > backup.dump` nightly; restore with `pg_restore`. Suggested retention: security_logs/network_events 90 days (`DELETE ... WHERE ts < now() - interval '90 days'`), alerts and audit 1 year. Elasticsearch: use an ILM policy for the same horizon.
