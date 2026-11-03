"""SQLite persistence for metadata-only SecureWork AI security events."""
from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from pathlib import Path

from app.security.ids_service import SecurityEvent

logger = logging.getLogger(__name__)

DEFAULT_EVENT_DB_PATH = (
    Path(__file__).resolve().parents[2] / "data" / "security_events.db"
)


class SecurityEventStore:
    """Persist and retrieve security events without storing packet payloads."""

    def __init__(self, database_path: str | Path = DEFAULT_EVENT_DB_PATH) -> None:
        self.database_path = Path(database_path)

    def initialize(self) -> None:
        """Create the database and schema if they do not exist."""
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        prediction TEXT NOT NULL,
                        attack_probability REAL,
                        source_ip TEXT NOT NULL,
                        destination_ip TEXT NOT NULL,
                        source_port INTEGER,
                        destination_port INTEGER,
                        protocol TEXT NOT NULL,
                        flow_duration REAL NOT NULL,
                        packet_count INTEGER NOT NULL,
                        byte_count INTEGER NOT NULL,
                        flow_id TEXT NOT NULL,
                        message TEXT NOT NULL
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
                    ON security_events(timestamp DESC, id DESC)
                    """
                )

    def save_event(self, event: SecurityEvent) -> int:
        """Save one event and return its database ID."""
        if not isinstance(event, SecurityEvent):
            raise TypeError("event must be a SecurityEvent instance.")

        self.initialize()

        with closing(self._connect()) as connection:
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO security_events (
                        timestamp, severity, prediction, attack_probability,
                        source_ip, destination_ip, source_port, destination_port,
                        protocol, flow_duration, packet_count, byte_count,
                        flow_id, message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.timestamp,
                        event.severity,
                        event.prediction,
                        event.attack_probability,
                        event.source_ip,
                        event.destination_ip,
                        event.source_port,
                        event.destination_port,
                        event.protocol,
                        event.flow_duration,
                        event.packet_count,
                        event.byte_count,
                        event.flow_id,
                        event.message,
                    ),
                )
                return int(cursor.lastrowid)

    def get_recent_events(self, limit: int = 100) -> tuple[SecurityEvent, ...]:
        """Return recent events, newest first."""
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer.")

        self.initialize()

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT timestamp, severity, prediction, attack_probability,
                       source_ip, destination_ip, source_port, destination_port,
                       protocol, flow_duration, packet_count, byte_count,
                       flow_id, message
                FROM security_events
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return tuple(SecurityEvent(*row) for row in rows)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, timeout=5.0)
