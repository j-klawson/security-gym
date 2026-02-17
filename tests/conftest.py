"""Shared fixtures for security-gym tests."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from security_gym.data.event_store import EventStore
from security_gym.parsers.base import ParsedEvent


# ── Sample log lines ──────────────────────────────────────────────────

SAMPLE_AUTH_LINES = [
    "Feb 17 10:15:30 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22345 ssh2",
    "Feb 17 10:15:31 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22345 ssh2",
    "Feb 17 10:15:32 myhost sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
    "Feb 17 10:15:33 myhost sshd[1234]: Invalid user test from 192.168.1.100 port 22345",
    "Feb 17 10:16:00 myhost sshd[1235]: Accepted password for admin from 10.0.0.5 port 54321 ssh2",
    "Feb 17 10:16:01 myhost sshd[1235]: pam_unix(sshd:session): session opened for user admin by (uid=0)",
    "Feb 17 10:20:00 myhost sshd[1235]: pam_unix(sshd:session): session closed for user admin",
    "Feb 17 10:20:01 myhost sshd[1234]: Connection closed by authenticating user admin 192.168.1.100 port 22345 [preauth]",
]

SAMPLE_EVENTS: list[tuple[ParsedEvent, dict | None]] = []

_base_time = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)


def _make_sample_events() -> list[tuple[ParsedEvent, dict | None]]:
    """Create a list of (ParsedEvent, ground_truth) tuples for test fixtures."""
    events = []

    # Benign events
    for i in range(5):
        events.append((
            ParsedEvent(
                timestamp=_base_time + timedelta(seconds=i * 10),
                source="auth_log",
                raw_line=f"Feb 17 10:00:{i*10:02d} myhost sshd[100]: Accepted password for admin from 10.0.0.1 port 5000{i} ssh2",
                event_type="auth_success",
                fields={"auth_method": "password", "port": 50000 + i},
                src_ip="10.0.0.1",
                username="admin",
                service="sshd",
                session_id=f"10.0.0.1:{50000 + i}",
            ),
            {"is_malicious": 0, "severity": 0},
        ))

    # Malicious brute-force events
    campaign_id = str(uuid4())
    for i in range(5):
        events.append((
            ParsedEvent(
                timestamp=_base_time + timedelta(seconds=50 + i),
                source="auth_log",
                raw_line=f"Feb 17 10:00:{50+i:02d} myhost sshd[200]: Failed password for root from 192.168.1.50 port 6000{i} ssh2",
                event_type="auth_failure",
                fields={"auth_method": "password", "port": 60000 + i},
                src_ip="192.168.1.50",
                username="root",
                service="sshd",
                session_id=f"192.168.1.50:{60000 + i}",
            ),
            {
                "is_malicious": 1,
                "campaign_id": campaign_id,
                "attack_type": "brute_force",
                "attack_stage": "initial_access",
                "severity": 2,
            },
        ))

    # Unlabeled events
    for i in range(3):
        events.append((
            ParsedEvent(
                timestamp=_base_time + timedelta(seconds=60 + i * 5),
                source="auth_log",
                raw_line=f"Feb 17 10:01:{i*5:02d} myhost sshd[300]: Connection from 172.16.0.{i} port 7000{i}",
                event_type="connection",
                fields={"port": 70000 + i},
                src_ip=f"172.16.0.{i}",
                service="sshd",
                session_id=f"172.16.0.{i}:{70000 + i}",
            ),
            None,  # unlabeled
        ))

    return events


SAMPLE_EVENTS = _make_sample_events()


@pytest.fixture
def sample_events():
    """Return list of (ParsedEvent, ground_truth) tuples."""
    return SAMPLE_EVENTS


@pytest.fixture
def tmp_db(tmp_path):
    """Create a temporary EventStore populated with sample events."""
    db_path = tmp_path / "test_events.db"
    store = EventStore(db_path, mode="w")
    for event, gt in SAMPLE_EVENTS:
        store.insert_event(event, gt)
    store.flush()
    store.close()
    return db_path


@pytest.fixture
def empty_db(tmp_path):
    """Create an empty EventStore."""
    db_path = tmp_path / "empty.db"
    store = EventStore(db_path, mode="w")
    store.close()
    return db_path
