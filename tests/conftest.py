"""Shared fixtures for security-gym tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
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

SAMPLE_SYSLOG_LINES = [
    "Feb 17 10:00:00 myhost CRON[1234]: (root) CMD (/usr/bin/something)",
    "Feb 17 10:00:01 myhost kernel: [12345.678] TCP: out of memory",
    "Feb 17 10:00:02 myhost systemd[1]: Started Apache HTTP Server.",
]

SAMPLE_WEB_ACCESS_LINES = [
    '192.168.1.100 - - [17/Feb/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"',
    '10.0.0.5 - admin [17/Feb/2026:10:16:00 +0000] "POST /api/login HTTP/1.1" 302 0 "-" "curl/7.68.0"',
]

SAMPLE_WEB_ERROR_LINES = [
    "[Tue Feb 17 10:15:30.123456 2026] [core:error] [pid 1234] [client 192.168.1.100:54321] File does not exist: /var/www/html/missing",
    "[Tue Feb 17 10:15:31 2026] [mpm_prefork:notice] [pid 100] AH00163: Apache/2.4.41 configured",
]

SAMPLE_JOURNAL_LINES = [
    json.dumps({
        "__REALTIME_TIMESTAMP": "1739786130000000",
        "SYSLOG_IDENTIFIER": "systemd",
        "MESSAGE": "Started Apache HTTP Server.",
        "_SYSTEMD_UNIT": "apache2.service",
    }),
    json.dumps({
        "__REALTIME_TIMESTAMP": "1739786131000000",
        "SYSLOG_IDENTIFIER": "cron",
        "MESSAGE": "(root) CMD (test)",
        "_SYSTEMD_UNIT": "cron.service",
    }),
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


def _make_multi_source_events() -> list[tuple[ParsedEvent, dict | None]]:
    """Create events from multiple log sources for integration tests."""
    events = []
    base = datetime(2026, 2, 17, 10, 0, 0, tzinfo=timezone.utc)

    # Auth events
    for i in range(3):
        events.append((
            ParsedEvent(
                timestamp=base + timedelta(seconds=i),
                source="auth_log",
                raw_line=f"Feb 17 10:00:{i:02d} myhost sshd[100]: Failed password for root from 192.168.1.50 port 6000{i} ssh2",
                event_type="auth_failure",
                fields={"pattern": "auth_failed_password"},
                src_ip="192.168.1.50",
                username="root",
                service="sshd",
                session_id=f"192.168.1.50:{60000 + i}",
            ),
            {"is_malicious": 1, "attack_type": "brute_force", "severity": 2},
        ))

    # Syslog events
    events.append((
        ParsedEvent(
            timestamp=base + timedelta(seconds=10),
            source="syslog",
            raw_line="Feb 17 10:00:10 myhost CRON[5678]: (root) CMD (test)",
            event_type="cron",
            fields={"event_type": "cron"},
            service="CRON",
            pid=5678,
        ),
        {"is_malicious": 0, "severity": 0},
    ))

    # Web access events
    events.append((
        ParsedEvent(
            timestamp=base + timedelta(seconds=20),
            source="web_access",
            raw_line='192.168.1.50 - - [17/Feb/2026:10:00:20 +0000] "GET /admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
            event_type="http_request",
            fields={"event_type": "http_request", "method": "GET", "path": "/admin"},
            src_ip="192.168.1.50",
            session_id="192.168.1.50",
        ),
        {"is_malicious": 1, "attack_type": "web_exploit", "severity": 3},
    ))

    # Web error events
    events.append((
        ParsedEvent(
            timestamp=base + timedelta(seconds=30),
            source="web_error",
            raw_line="[Tue Feb 17 10:00:30 2026] [core:error] [pid 1234] [client 192.168.1.50:80] File not found",
            event_type="http_error",
            fields={"event_type": "http_error", "level": "error"},
            src_ip="192.168.1.50",
            session_id="192.168.1.50",
            pid=1234,
        ),
        {"is_malicious": 0, "severity": 0},
    ))

    return events


@pytest.fixture
def multi_source_db(tmp_path):
    """Create a temporary EventStore with events from multiple log sources."""
    db_path = tmp_path / "multi_source.db"
    store = EventStore(db_path, mode="w")
    for event, gt in _make_multi_source_events():
        store.insert_event(event, gt)
    store.flush()
    store.close()
    return db_path
