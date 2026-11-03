"""Relational schema (SQLAlchemy). Works on PostgreSQL (target) and SQLite (dev)."""
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer,
                        String, Text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin|analyst|agent
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_uid: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    os: Mapped[str] = mapped_column(String(128), default="")
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="online")
    agent_status: Mapped[str] = mapped_column(String(16), default="running")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    user: Mapped["User | None"] = relationship()


class Application(Base):
    __tablename__ = "applications"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    exe_path: Mapped[str] = mapped_column(String(1024), default="")
    status: Mapped[str] = mapped_column(String(16), default="seen")  # seen|blocked
    allowlisted: Mapped[bool] = mapped_column(Boolean, default=False)


class NetworkEvent(Base):
    __tablename__ = "network_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    src_ip: Mapped[str | None] = mapped_column(String(64))
    dst_ip: Mapped[str | None] = mapped_column(String(64))
    protocol: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(32), default="flow-export")  # flow-export|dataset-replay|connection-scan
    classification: Mapped[str] = mapped_column(String(16))  # normal|suspicious|unscored
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (Index("ix_netev_device_ts", "device_id", "ts"),)


class IntrusionAlert(Base):
    __tablename__ = "intrusion_alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    network_event_id: Mapped[int | None] = mapped_column(ForeignKey("network_events.id"))
    detection_result: Mapped[str] = mapped_column(String(16))
    attack_category: Mapped[str] = mapped_column(String(32), default="unknown")
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float | None] = mapped_column(Float)
    model: Mapped[str] = mapped_column(String(64), default="")
    dedup_key: Mapped[str] = mapped_column(String(128), default="")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (Index("ix_alert_ts", "ts"), Index("ix_alert_dedup", "device_id", "dedup_key", "ts"))


class ApplicationEvent(Base):
    __tablename__ = "application_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    application_id: Mapped[int] = mapped_column(ForeignKey("applications.id"))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))  # allowed|unauthorized
    severity: Mapped[str] = mapped_column(String(16), default="info")
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    application: Mapped["Application"] = relationship()
    __table_args__ = (Index("ix_appev_device_ts", "device_id", "ts"),)


class SecurityLog(Base):
    __tablename__ = "security_logs"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"))
    source: Mapped[str] = mapped_column(String(32))   # network|application|device|system
    event_type: Mapped[str] = mapped_column(String(48))
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (Index("ix_log_ts", "ts"), Index("ix_log_sev", "severity"))


class SecurityPolicy(Base):
    __tablename__ = "security_policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    policy_type: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class AuditRecord(Base):
    __tablename__ = "audit_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(64))
    details: Mapped[str] = mapped_column(Text, default="")
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
