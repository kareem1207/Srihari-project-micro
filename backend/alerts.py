"""Severity rules, de-duplication and event shipping to centralised logging."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from . import config
from .models import IntrusionAlert, SecurityLog

# Documented severity rules (also in docs/ARCHITECTURE.md):
#   attack category:  U2R -> critical, R2L -> high, DoS -> high, Probe -> medium, other -> medium
#   confidence < 0.6 downgrades one level; unauthorised application -> medium
#   (high if the executable path is outside Program Files / Windows dirs).
LEVELS = ["info", "low", "medium", "high", "critical"]
CATEGORY_SEVERITY = {"U2R": "critical", "R2L": "high", "DoS": "high", "Probe": "medium"}


def intrusion_severity(category: str, confidence: float | None) -> str:
    sev = CATEGORY_SEVERITY.get(category, "medium")
    if confidence is not None and confidence < 0.6:
        sev = LEVELS[max(LEVELS.index(sev) - 1, 0)]
    return sev


def app_severity(exe_path: str) -> str:
    p = (exe_path or "").lower().replace("/", "\\")
    trusted = ("c:\\program files", "c:\\windows")
    return "medium" if p.startswith(trusted) else "high"


def ship(doc: dict) -> str:
    """Send to Elasticsearch if configured; always append to a JSONL file that
    Filebeat/Logstash can tail (the ELK ingestion path). Returns the sink used."""
    doc = {"@timestamp": datetime.now(timezone.utc).isoformat(), **doc}
    try:
        Path(config.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(config.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(doc, default=str) + "\n")
    except OSError:
        pass
    if config.ES_URL:
        try:
            from elasticsearch import Elasticsearch
            Elasticsearch(config.ES_URL, request_timeout=3).index(index=config.ES_INDEX, document=doc)
            return "elasticsearch"
        except Exception:
            return "file(es-unavailable)"
    return "file"


def log_event(db: Session, device_id, source, event_type, severity, description) -> SecurityLog:
    row = SecurityLog(device_id=device_id, source=source, event_type=event_type,
                      severity=severity, description=description)
    db.add(row)
    db.flush()
    ship({"event_id": row.id, "device_id": device_id, "source": source,
          "event_type": event_type, "severity": severity, "message": description})
    return row


def raise_intrusion_alert(db: Session, device_id: int, event_id: int | None, category: str,
                          confidence: float | None, model: str) -> tuple[IntrusionAlert, bool]:
    """Create an alert, or bump `occurrences` of an identical recent one (dedup)."""
    key = f"{category}"
    since = datetime.now(timezone.utc) - timedelta(seconds=config.DEDUP_WINDOW_SECONDS)
    if db.bind.dialect.name == "sqlite":  # SQLite stores naive datetimes
        since = since.replace(tzinfo=None)
    existing = (db.query(IntrusionAlert)
                .filter(IntrusionAlert.device_id == device_id, IntrusionAlert.dedup_key == key,
                        IntrusionAlert.ts >= since)
                .order_by(IntrusionAlert.ts.desc()).first())
    if existing:
        existing.occurrences += 1
        return existing, False
    sev = intrusion_severity(category, confidence)
    alert = IntrusionAlert(device_id=device_id, network_event_id=event_id, detection_result="attack",
                           attack_category=category, severity=sev, confidence=confidence,
                           model=model, dedup_key=key)
    db.add(alert)
    db.flush()
    log_event(db, device_id, "network", "intrusion_alert", sev,
              f"{category} activity detected by {model} (alert #{alert.id})")
    return alert, True
