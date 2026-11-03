
"""Tests for SQLite security event persistence."""
import tempfile
import unittest
from pathlib import Path

from app.security.event_store import SecurityEventStore
from app.security.ids_service import SecurityEvent


def make_event(flow_id: str, timestamp: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp=timestamp,
        severity="SUSPICIOUS",
        prediction="Attack",
        attack_probability=0.85,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        source_port=1234,
        destination_port=443,
        protocol="TCP",
        flow_duration=1.25,
        packet_count=8,
        byte_count=1200,
        flow_id=flow_id,
        message="Detection signal; not confirmation of compromise.",
    )


class SecurityEventStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "events.db"
        self.store = SecurityEventStore(self.database)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_save_and_retrieve_event(self) -> None:
        event = make_event("flow-1", "2026-10-15T10:00:00+00:00")

        event_id = self.store.save_event(event)
        retrieved = self.store.get_recent_events()

        self.assertGreater(event_id, 0)
        self.assertEqual(retrieved, (event,))
        self.assertTrue(self.database.is_file())

    def test_events_are_returned_newest_first(self) -> None:
        older = make_event("flow-old", "2026-10-15T09:00:00+00:00")
        newer = make_event("flow-new", "2026-10-15T11:00:00+00:00")

        self.store.save_event(older)
        self.store.save_event(newer)

        results = self.store.get_recent_events()

        self.assertEqual(
            [event.flow_id for event in results],
            ["flow-new", "flow-old"],
        )

    def test_limit_is_respected(self) -> None:
        self.store.save_event(make_event("flow-1", "2026-10-15T09:00:00+00:00"))
        self.store.save_event(make_event("flow-2", "2026-10-15T10:00:00+00:00"))

        self.assertEqual(len(self.store.get_recent_events(limit=1)), 1)

    def test_invalid_limit_is_rejected(self) -> None:
        for limit in (0, -1, True, 1.5):
            with self.subTest(limit=limit):
                with self.assertRaises(ValueError):
                    self.store.get_recent_events(limit=limit)

    def test_wrong_event_type_is_rejected(self) -> None:
        with self.assertRaises(TypeError):
            self.store.save_event({"flow_id": "not-an-event"})


if __name__ == "__main__":
    unittest.main()
