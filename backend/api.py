"""SecureWork AI REST API (FastAPI)."""
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from . import alerts, config
from .db import get_db
from .models import (Application, ApplicationEvent, AuditRecord, Device, IntrusionAlert,
                     NetworkEvent, SecurityLog, SecurityPolicy, User)
from .security import ROLES, current_user, hash_password, make_token, require, verify_password

app = FastAPI(title="SecureWork AI API", version="1.0.0")
_detector = None
STATIC = Path(__file__).parent / "static"
UID = re.compile(r"^[A-Za-z0-9._:-]{3,64}$")


def detector():
    """Lazy-load the NIDS model; None if it has not been trained yet."""
    global _detector
    if _detector is None:
        try:
            from .ml.nslkdd import Detector
            _detector = Detector(config.MODEL_PATH)
        except Exception:
            return None
    return _detector


def audit(db: Session, user: Optional[User], action: str, details: str = ""):
    db.add(AuditRecord(user_id=user.id if user else None, action=action, details=details[:1000]))


def iso(d: Optional[datetime]) -> Optional[str]:
    if d is None:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).isoformat()


# ---------- schemas ----------
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{3,64}$")
    password: str = Field(min_length=10, max_length=256)
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def _role(cls, v):
        if v not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        return v


class DeviceIn(BaseModel):
    device_uid: str
    name: str = Field(min_length=1, max_length=128)
    os: str = Field(default="", max_length=128)
    username: Optional[str] = None

    @field_validator("device_uid")
    @classmethod
    def _uid(cls, v):
        if not UID.match(v):
            raise ValueError("invalid device_uid")
        return v


class AppObs(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    exe_path: str = Field(default="", max_length=1024)


class AppReport(BaseModel):
    device_uid: str
    applications: list[AppObs] = Field(max_length=2000)


class NetIn(BaseModel):
    device_uid: str
    src_ip: Optional[str] = Field(default=None, max_length=64)
    dst_ip: Optional[str] = Field(default=None, max_length=64)
    protocol: Optional[str] = Field(default=None, max_length=16)
    source: str = Field(default="flow-export", pattern="^(flow-export|dataset-replay|connection-scan)$")
    features: Optional[dict[str, Any]] = None  # NSL-KDD 41 features; omitted -> 'unscored'


class PolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    policy_type: str = Field(pattern="^(application_allowlist|network|device)$")
    config: dict = {}


class AllowIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    allowlisted: bool = True


# ---------- helpers ----------
def device_by_uid(db: Session, uid: str) -> Device:
    d = db.query(Device).filter_by(device_uid=uid).first()
    if not d:
        raise HTTPException(404, "Unknown device; register it first")
    return d


def touch(d: Device):
    d.last_seen = datetime.now(timezone.utc)
    d.status = "online"


# ---------- auth & users ----------
@app.post("/api/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(username=body.username).first()
    if not u or not u.is_active or not verify_password(u.password_hash, body.password):
        audit(db, None, "login_failed", body.username[:64])
        db.commit()
        raise HTTPException(401, "Invalid credentials")
    audit(db, u, "login")
    db.commit()
    return {"access_token": make_token(u), "token_type": "bearer", "role": u.role}


@app.post("/api/users", status_code=201)
def create_user(body: UserIn, db: Session = Depends(get_db), me: User = Depends(require("admin"))):
    if db.query(User).filter_by(username=body.username).first():
        raise HTTPException(409, "Username exists")
    u = User(username=body.username, password_hash=hash_password(body.password), role=body.role)
    db.add(u)
    audit(db, me, "user_create", f"{body.username}:{body.role}")
    db.commit()
    return {"id": u.id, "username": u.username, "role": u.role}


@app.get("/api/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require("admin"))):
    return [{"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active,
             "created_at": iso(u.created_at)} for u in db.query(User).all()]


# ---------- devices ----------
@app.post("/api/devices/register")
def register_device(body: DeviceIn, db: Session = Depends(get_db),
                    me: User = Depends(require("admin", "agent"))):
    d = db.query(Device).filter_by(device_uid=body.device_uid).first()
    new = d is None
    if new:
        d = Device(device_uid=body.device_uid, name=body.name, os=body.os)
        db.add(d)
    d.name, d.os = body.name, body.os
    if body.username:
        owner = db.query(User).filter_by(username=body.username).first()
        if owner:
            d.user_id = owner.id
    touch(d)
    db.flush()
    if new:
        alerts.log_event(db, d.id, "device", "device_registered", "info", f"Device {d.name} registered")
    audit(db, me, "device_register", body.device_uid)
    db.commit()
    return {"id": d.id, "device_uid": d.device_uid}


@app.post("/api/devices/{uid}/heartbeat")
def heartbeat(uid: str, db: Session = Depends(get_db), _: User = Depends(require("admin", "agent"))):
    d = device_by_uid(db, uid)
    touch(d)
    db.commit()
    return {"ok": True}


def _device_status(d: Device) -> str:
    ls = d.last_seen if d.last_seen.tzinfo else d.last_seen.replace(tzinfo=timezone.utc)
    return "online" if datetime.now(timezone.utc) - ls < timedelta(minutes=5) else "offline"


@app.get("/api/devices")
def list_devices(db: Session = Depends(get_db), _: User = Depends(current_user)):
    counts = dict(db.query(IntrusionAlert.device_id, func.count()).group_by(IntrusionAlert.device_id).all())
    acounts = dict(db.query(ApplicationEvent.device_id, func.count())
                   .filter(ApplicationEvent.status == "unauthorized").group_by(ApplicationEvent.device_id).all())
    return [{"id": d.id, "device_uid": d.device_uid, "name": d.name, "os": d.os,
             "user": d.user.username if d.user else None, "status": _device_status(d),
             "agent_status": d.agent_status, "last_seen": iso(d.last_seen),
             "intrusion_alerts": counts.get(d.id, 0), "app_alerts": acounts.get(d.id, 0)}
            for d in db.query(Device).order_by(Device.id)]


# ---------- applications ----------
def _allowlisted(db: Session, name: str) -> bool:
    row = db.query(Application).filter(func.lower(Application.name) == name.lower(),
                                       Application.allowlisted.is_(True)).first()
    return row is not None


@app.post("/api/applications/report")
def report_apps(body: AppReport, db: Session = Depends(get_db), me: User = Depends(require("admin", "agent"))):
    d = device_by_uid(db, body.device_uid)
    touch(d)
    created = 0
    seen: set[str] = set()
    for obs in body.applications:
        key = obs.name.lower()
        if key in seen:
            continue
        seen.add(key)
        app_row = db.query(Application).filter(func.lower(Application.name) == key).first()
        if not app_row:
            app_row = Application(name=obs.name, exe_path=obs.exe_path)
            db.add(app_row)
            db.flush()
        if app_row.allowlisted:
            continue
        recent = datetime.now(timezone.utc) - timedelta(seconds=config.DEDUP_WINDOW_SECONDS)
        if db.bind.dialect.name == "sqlite":
            recent = recent.replace(tzinfo=None)
        dup = db.query(ApplicationEvent).filter(ApplicationEvent.device_id == d.id,
                                                ApplicationEvent.application_id == app_row.id,
                                                ApplicationEvent.ts >= recent).first()
        if dup:
            continue
        sev = alerts.app_severity(obs.exe_path or app_row.exe_path)
        db.add(ApplicationEvent(device_id=d.id, application_id=app_row.id, status="unauthorized",
                                severity=sev, description=f"Application not in allowlist: {obs.name}"))
        alerts.log_event(db, d.id, "application", "unauthorized_application", sev,
                         f"Unauthorized application '{obs.name}' ({obs.exe_path or 'path unknown'})")
        created += 1
    audit(db, me, "app_report", f"{d.device_uid}: {len(seen)} apps, {created} events")
    db.commit()
    return {"observed": len(seen), "unauthorized_events": created}


@app.get("/api/applications")
def list_apps(db: Session = Depends(get_db), _: User = Depends(current_user)):
    ev = dict(db.query(ApplicationEvent.application_id, func.count()).group_by(ApplicationEvent.application_id).all())
    return [{"id": a.id, "name": a.name, "exe_path": a.exe_path, "allowlisted": a.allowlisted,
             "status": a.status, "events": ev.get(a.id, 0)} for a in db.query(Application).order_by(Application.name)]


@app.post("/api/applications/allowlist")
def set_allowlist(body: AllowIn, db: Session = Depends(get_db), me: User = Depends(require("admin"))):
    a = db.query(Application).filter(func.lower(Application.name) == body.name.lower()).first()
    if not a:
        a = Application(name=body.name)
        db.add(a)
    a.allowlisted = body.allowlisted
    audit(db, me, "allowlist_set", f"{body.name}={body.allowlisted}")
    db.commit()
    return {"name": a.name, "allowlisted": a.allowlisted}


@app.get("/api/application-events")
def app_events(limit: int = Query(100, le=1000), db: Session = Depends(get_db), _: User = Depends(current_user)):
    rows = db.query(ApplicationEvent).order_by(ApplicationEvent.ts.desc()).limit(limit).all()
    return [{"id": r.id, "device_id": r.device_id, "application": r.application.name,
             "exe_path": r.application.exe_path, "description": r.description, "status": r.status,
             "severity": r.severity, "reviewed": r.reviewed, "ts": iso(r.ts)} for r in rows]


# ---------- network + intrusion detection ----------
@app.post("/api/network/events", status_code=201)
def ingest_network(body: NetIn, db: Session = Depends(get_db), me: User = Depends(require("admin", "agent"))):
    t0 = time.perf_counter()
    d = device_by_uid(db, body.device_uid)
    touch(d)
    result = None
    classification = "unscored"
    if body.features is not None:
        det = detector()
        if det is None:
            raise HTTPException(503, "IDS model not trained; run python -m backend.ml.nslkdd")
        try:
            result = det.predict(body.features)
        except ValueError as e:
            raise HTTPException(422, str(e))
        classification = "suspicious" if result["is_attack"] else "normal"
    ev = NetworkEvent(device_id=d.id, src_ip=body.src_ip, dst_ip=body.dst_ip,
                      protocol=body.protocol or (body.features or {}).get("protocol_type"),
                      source=body.source, classification=classification)
    db.add(ev)
    db.flush()
    alert_id = None
    if result and result["is_attack"]:
        category = _category_hint(body)
        alert, _new = alerts.raise_intrusion_alert(db, d.id, ev.id, category, result["confidence"], result["model"])
        alert_id = alert.id
    elif classification == "normal":
        alerts.ship({"device_id": d.id, "source": "network", "event_type": "network_event",
                     "severity": "info", "message": "normal traffic", "protocol": ev.protocol})
    db.commit()
    return {"event_id": ev.id, "classification": classification, "alert_id": alert_id,
            "model": result and result["model"], "confidence": result and result["confidence"],
            "predict_ms": result and result["predict_ms"],
            "processing_ms": round((time.perf_counter() - t0) * 1000, 3)}


def _category_hint(body: NetIn) -> str:
    """The binary model does not predict a category. Use an explicit hint only if the
    sender supplied the true label (dataset replay); otherwise report 'unclassified'."""
    lab = (body.features or {}).get("label") if body.source == "dataset-replay" else None
    from .ml.nslkdd import CATEGORY_MAP
    cat = CATEGORY_MAP.get(lab, "unclassified") if lab else "unclassified"
    # A true 'normal' label here means the model produced a false positive.
    return "unclassified" if cat == "normal" else cat


@app.get("/api/network/events")
def list_net(limit: int = Query(100, le=1000), classification: Optional[str] = None,
             db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(NetworkEvent)
    if classification:
        q = q.filter(NetworkEvent.classification == classification)
    return [{"id": r.id, "device_id": r.device_id, "src_ip": r.src_ip, "dst_ip": r.dst_ip,
             "protocol": r.protocol, "source": r.source, "classification": r.classification,
             "ts": iso(r.ts)} for r in q.order_by(NetworkEvent.ts.desc()).limit(limit)]


@app.get("/api/alerts")
def list_alerts(limit: int = Query(100, le=1000), severity: Optional[str] = None,
                device_id: Optional[int] = None, db: Session = Depends(get_db), _: User = Depends(current_user)):
    q = db.query(IntrusionAlert)
    if severity:
        q = q.filter(IntrusionAlert.severity == severity)
    if device_id:
        q = q.filter(IntrusionAlert.device_id == device_id)
    return [{"id": a.id, "device_id": a.device_id, "detection_result": a.detection_result,
             "attack_category": a.attack_category, "severity": a.severity, "confidence": a.confidence,
             "model": a.model, "occurrences": a.occurrences, "reviewed": a.reviewed, "ts": iso(a.ts)}
            for a in q.order_by(IntrusionAlert.ts.desc()).limit(limit)]


@app.post("/api/alerts/{alert_id}/review")
def review_alert(alert_id: int, db: Session = Depends(get_db), me: User = Depends(require("admin", "analyst"))):
    a = db.get(IntrusionAlert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    a.reviewed = True
    audit(db, me, "alert_review", str(alert_id))
    db.commit()
    return {"id": a.id, "reviewed": True}


# ---------- logs ----------
@app.get("/api/logs")
def logs(limit: int = Query(100, le=1000), offset: int = 0, severity: Optional[str] = None,
         source: Optional[str] = None, device_id: Optional[int] = None, q: Optional[str] = Query(None, max_length=100),
         since: Optional[datetime] = None, until: Optional[datetime] = None,
         db: Session = Depends(get_db), _: User = Depends(current_user)):
    qs = db.query(SecurityLog)
    if severity:
        qs = qs.filter(SecurityLog.severity == severity)
    if source:
        qs = qs.filter(SecurityLog.source == source)
    if device_id:
        qs = qs.filter(SecurityLog.device_id == device_id)
    if q:
        qs = qs.filter(SecurityLog.description.ilike(f"%{q}%"))
    if since:
        qs = qs.filter(SecurityLog.ts >= since.replace(tzinfo=None) if db.bind.dialect.name == "sqlite" else SecurityLog.ts >= since)
    if until:
        qs = qs.filter(SecurityLog.ts <= until.replace(tzinfo=None) if db.bind.dialect.name == "sqlite" else SecurityLog.ts <= until)
    total = qs.count()
    rows = qs.order_by(SecurityLog.ts.desc()).offset(offset).limit(limit).all()
    return {"total": total, "items": [{"id": r.id, "device_id": r.device_id, "source": r.source,
            "event_type": r.event_type, "severity": r.severity, "description": r.description,
            "ts": iso(r.ts)} for r in rows]}


# ---------- policies ----------
@app.post("/api/policies", status_code=201)
def create_policy(body: PolicyIn, db: Session = Depends(get_db), me: User = Depends(require("admin"))):
    if db.query(SecurityPolicy).filter_by(name=body.name).first():
        raise HTTPException(409, "Policy exists")
    p = SecurityPolicy(name=body.name, policy_type=body.policy_type, config=body.config)
    db.add(p)
    audit(db, me, "policy_create", body.name)
    db.commit()
    return {"id": p.id}


@app.get("/api/policies")
def list_policies(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [{"id": p.id, "name": p.name, "policy_type": p.policy_type, "config": p.config,
             "created_at": iso(p.created_at)} for p in db.query(SecurityPolicy)]


@app.get("/api/audit")
def audit_log(limit: int = Query(100, le=1000), db: Session = Depends(get_db), _: User = Depends(require("admin"))):
    return [{"id": a.id, "user_id": a.user_id, "action": a.action, "details": a.details, "ts": iso(a.ts)}
            for a in db.query(AuditRecord).order_by(AuditRecord.ts.desc()).limit(limit)]


# ---------- dashboard ----------
@app.get("/api/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        dbok = True
    except SQLAlchemyError:
        dbok = False
    es = "not_configured"
    if config.ES_URL:
        try:
            from elasticsearch import Elasticsearch
            es = "up" if Elasticsearch(config.ES_URL, request_timeout=2).ping() else "down"
        except Exception:
            es = "down"
    return {"api": "up", "database": "up" if dbok else "down", "elasticsearch": es,
            "ids_model": "loaded" if detector() else "not_trained",
            "log_file": Path(config.LOG_FILE).exists()}


@app.get("/api/dashboard/stats")
def stats(hours: int = Query(24, ge=1, le=24 * 90), db: Session = Depends(get_db), _: User = Depends(current_user)):
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    if db.bind.dialect.name == "sqlite":
        since = since.replace(tzinfo=None)

    def by(col, model, extra=None):
        q = db.query(col, func.count()).filter(model.ts >= since)
        if extra is not None:
            q = q.filter(extra)
        return {k or "unknown": v for k, v in q.group_by(col).all()}

    devices = db.query(Device).all()
    online = sum(1 for d in devices if _device_status(d) == "online")
    timeline: dict[str, int] = {}
    for (ts,) in db.query(SecurityLog.ts).filter(SecurityLog.ts >= since):
        k = ts.strftime("%Y-%m-%d %H:00")
        timeline[k] = timeline.get(k, 0) + 1
    dev_names = {d.id: d.name for d in devices}
    per_dev = {dev_names.get(k, str(k)): v for k, v in
               db.query(SecurityLog.device_id, func.count()).filter(SecurityLog.ts >= since, SecurityLog.device_id.isnot(None))
               .group_by(SecurityLog.device_id).all()}
    return {
        "window_hours": hours,
        "devices_total": len(devices), "devices_online": online,
        "security_events": db.query(SecurityLog).filter(SecurityLog.ts >= since).count(),
        "traffic": by(NetworkEvent.classification, NetworkEvent),
        "intrusion_alerts": db.query(IntrusionAlert).filter(IntrusionAlert.ts >= since).count(),
        "critical_alerts": db.query(IntrusionAlert).filter(IntrusionAlert.ts >= since, IntrusionAlert.severity == "critical").count(),
        "alert_severity": by(IntrusionAlert.severity, IntrusionAlert),
        "attack_categories": by(IntrusionAlert.attack_category, IntrusionAlert),
        "app_events": db.query(ApplicationEvent).filter(ApplicationEvent.ts >= since).count(),
        "app_event_severity": by(ApplicationEvent.severity, ApplicationEvent),
        "events_over_time": [{"t": k, "count": v} for k, v in sorted(timeline.items())],
        "events_per_device": per_dev,
        "recent_events": [{"id": r.id, "severity": r.severity, "source": r.source, "description": r.description, "ts": iso(r.ts)}
                          for r in db.query(SecurityLog).order_by(SecurityLog.ts.desc()).limit(10)],
    }


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC / "index.html")
