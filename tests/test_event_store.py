"""Tests for EventStore read/write operations."""

from security_gym.data.event_store import EventStore
from tests.conftest import SAMPLE_EVENTS


class TestEventStore:
    def test_insert_and_count(self, tmp_db):
        store = EventStore(tmp_db, mode="r")
        assert store.count_events() == len(SAMPLE_EVENTS)
        store.close()

    def test_get_events_pagination(self, tmp_db):
        store = EventStore(tmp_db, mode="r")
        batch1 = store.get_events(start_id=0, limit=5)
        assert len(batch1) == 5
        last_id = batch1[-1]["id"]
        batch2 = store.get_events(start_id=last_id, limit=5)
        assert len(batch2) == 5
        assert batch2[0]["id"] > last_id
        store.close()

    def test_get_events_source_filter(self, tmp_db):
        store = EventStore(tmp_db, mode="r")
        events = store.get_events(sources=["auth_log"], limit=100)
        assert len(events) == len(SAMPLE_EVENTS)
        events_none = store.get_events(sources=["web_access"], limit=100)
        assert len(events_none) == 0
        store.close()

    def test_get_time_range(self, tmp_db):
        store = EventStore(tmp_db, mode="r")
        result = store.get_time_range()
        assert result is not None
        assert result[0] <= result[1]
        store.close()

    def test_get_sources(self, tmp_db):
        store = EventStore(tmp_db, mode="r")
        sources = store.get_sources()
        assert "auth_log" in sources
        store.close()

    def test_empty_db(self, empty_db):
        store = EventStore(empty_db, mode="r")
        assert store.count_events() == 0
        assert store.get_time_range() is None
        store.close()

    def test_bulk_insert(self, tmp_path):
        db_path = tmp_path / "bulk.db"
        store = EventStore(db_path, mode="w")
        events = [ev for ev, _ in SAMPLE_EVENTS]
        gts = [gt or {} for _, gt in SAMPLE_EVENTS]
        count = store.bulk_insert(events, gts)
        assert count == len(SAMPLE_EVENTS)
        assert store.count_events() == len(SAMPLE_EVENTS)
        store.close()

    def test_campaign_insert(self, tmp_path):
        db_path = tmp_path / "campaign.db"
        store = EventStore(db_path, mode="w")
        cid = store.insert_campaign({
            "id": "test-campaign-1",
            "name": "SSH Brute Force",
            "start_time": "2026-02-17T10:00:00Z",
            "attack_type": "brute_force",
            "mitre_tactics": "TA0001",
        })
        assert cid == "test-campaign-1"
        campaigns = store.get_campaigns()
        assert len(campaigns) == 1
        assert campaigns[0]["name"] == "SSH Brute Force"
        store.close()

    def test_context_manager(self, tmp_path):
        db_path = tmp_path / "ctx.db"
        with EventStore(db_path, mode="w") as store:
            assert store.count_events() == 0
