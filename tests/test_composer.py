"""Tests for StreamComposer — offline stream composition."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
import yaml

from security_gym.data.composer import (
    StreamComposer,
    _cycle_benign,
    _downsample_ebpf,
    _enrich_ebpf_fields,
    _load_config,
    _parse_duration,
    _parse_ts,
    _schedule_attacks,
    _transplant_session,
)
from security_gym.data.event_store import EventStore
from security_gym.parsers.base import ParsedEvent


# ── Fixtures ──────────────────────────────────────────────────────────


def _make_benign_events(n: int = 100) -> list[tuple[ParsedEvent, dict]]:
    """Create n benign events with realistic timestamps."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = []
    for i in range(n):
        ts = base + timedelta(seconds=i * 30)  # 30s apart
        events.append((
            ParsedEvent(
                timestamp=ts,
                source="auth_log",
                raw_line=f"Jan  1 {ts.strftime('%H:%M:%S')} myhost CRON[{1000+i}]: (root) CMD (test)",
                event_type="cron",
                fields={"pattern": "cron_cmd"},
                service="CRON",
            ),
            {"is_malicious": 0, "severity": 0},
        ))
    return events


def _make_attack_events(
    attack_type: str, n: int = 25, offset_minutes: int = 0,
) -> list[tuple[ParsedEvent, dict]]:
    """Create n attack events of a given type."""
    base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(
        minutes=offset_minutes
    )
    events = []
    for i in range(n):
        ts = base + timedelta(seconds=i * 2)
        events.append((
            ParsedEvent(
                timestamp=ts,
                source="auth_log",
                raw_line=f"Mar  1 {ts.strftime('%H:%M:%S')} myhost sshd[{2000+i}]: Failed password for root from 10.0.0.99 port {40000+i} ssh2",
                event_type="auth_failure",
                fields={"pattern": "auth_failed_password"},
                src_ip="10.0.0.99",
                username="root",
                service="sshd",
                session_id=f"10.0.0.99:{40000+i}",
            ),
            {
                "is_malicious": 1,
                "attack_type": attack_type,
                "attack_stage": "initial_access",
                "severity": 2,
            },
        ))
    return events


@pytest.fixture
def benign_db(tmp_path):
    """Create a small benign EventStore."""
    db_path = tmp_path / "benign.db"
    with EventStore(db_path, mode="w") as store:
        for event, gt in _make_benign_events(100):
            store.insert_event(event, gt)
    return db_path


@pytest.fixture
def attack_db(tmp_path):
    """Create an attack EventStore with two attack types."""
    db_path = tmp_path / "attacks.db"
    with EventStore(db_path, mode="w") as store:
        for event, gt in _make_attack_events("brute_force", 25, offset_minutes=0):
            store.insert_event(event, gt)
        for event, gt in _make_attack_events("web_exploit", 25, offset_minutes=10):
            store.insert_event(event, gt)
    return db_path


@pytest.fixture
def compose_config(tmp_path, benign_db, attack_db):
    """Create a composition YAML config file."""
    output_db = tmp_path / "composed.db"
    config = {
        "stream": {
            "duration": "7d",
            "seed": 42,
            "benign": {"db": str(benign_db)},
            "attacks": {
                "db": str(attack_db),
                "campaigns_per_day": 3.0,
                "distribution": {
                    "brute_force": 0.6,
                    "web_exploit": 0.4,
                },
            },
            "output": {"db": str(output_db)},
        }
    }
    config_path = tmp_path / "test_compose.yaml"
    with open(config_path, "w") as f:
        yaml.dump(config, f)
    return config_path, output_db


# ── Duration parsing ──────────────────────────────────────────────────


class TestParseDuration:
    def test_days(self):
        assert _parse_duration("90d") == 90 * 86400

    def test_hours(self):
        assert _parse_duration("24h") == 24 * 3600

    def test_minutes(self):
        assert _parse_duration("60m") == 3600

    def test_seconds(self):
        assert _parse_duration("120s") == 120

    def test_fractional(self):
        assert _parse_duration("1.5d") == 1.5 * 86400

    def test_invalid(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration("abc")

    def test_no_unit(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            _parse_duration("90")


# ── Config loading ────────────────────────────────────────────────────


class TestLoadConfig:
    def test_loads_valid(self, compose_config):
        config_path, output_db = compose_config
        config = _load_config(config_path)
        assert config.duration_seconds == 7 * 86400
        assert config.seed == 42
        assert config.campaigns_per_day == 3.0
        assert "brute_force" in config.distribution
        assert "web_exploit" in config.distribution
        # Weights are normalized
        total = sum(config.distribution.values())
        assert abs(total - 1.0) < 1e-6

    def test_missing_stream(self, tmp_path):
        config_path = tmp_path / "bad.yaml"
        with open(config_path, "w") as f:
            yaml.dump({"other": "stuff"}, f)
        with pytest.raises(ValueError, match="stream"):
            _load_config(config_path)

    def test_missing_distribution(self, tmp_path, benign_db, attack_db):
        config = {
            "stream": {
                "duration": "1d",
                "benign": {"db": str(benign_db)},
                "attacks": {"db": str(attack_db)},
                "output": {"db": str(tmp_path / "out.db")},
            }
        }
        config_path = tmp_path / "no_dist.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)
        with pytest.raises(ValueError, match="distribution"):
            _load_config(config_path)


# ── Benign cycling ────────────────────────────────────────────────────


class TestCycleBenign:
    def test_output_fills_duration(self):
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            {"timestamp": (base + timedelta(seconds=i * 10)).isoformat(), "source": "test", "raw_line": f"line {i}"}
            for i in range(10)
        ]
        duration = 200.0  # 200 seconds, original span is ~90s
        result = _cycle_benign(events, duration)
        # Should have more events than one cycle
        assert len(result) > 10
        # All timestamps should be within duration
        ts_list = [_parse_ts(e["timestamp"]) for e in result]
        span = (max(ts_list) - min(ts_list)).total_seconds()
        assert span <= duration

    def test_single_cycle_short_duration(self):
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            {"timestamp": (base + timedelta(seconds=i * 10)).isoformat(), "source": "test", "raw_line": f"line {i}"}
            for i in range(10)
        ]
        duration = 50.0  # Only part of first cycle
        result = _cycle_benign(events, duration)
        assert 0 < len(result) <= 10

    def test_empty_events(self):
        assert _cycle_benign([], 1000) == []

    def test_source_ids_removed(self):
        events = [{"id": 42, "timestamp": "2026-01-01T00:00:00+00:00", "source": "test", "raw_line": "x"}]
        result = _cycle_benign(events, 10)
        assert all("id" not in e for e in result)


# ── Attack scheduling ─────────────────────────────────────────────────


class TestScheduleAttacks:
    def test_approximate_count(self):
        """Campaign count should be approximately campaigns_per_day * days."""
        duration = 30 * 86400  # 30 days
        schedule = _schedule_attacks(duration, 3.0, {"brute_force": 1.0}, seed=42)
        expected = 3.0 * 30
        # Poisson: accept within 3 standard deviations
        std = (3.0 * 30) ** 0.5
        assert abs(len(schedule) - expected) < 3 * std

    def test_deterministic(self):
        schedule1 = _schedule_attacks(86400 * 7, 5.0, {"a": 0.5, "b": 0.5}, seed=99)
        schedule2 = _schedule_attacks(86400 * 7, 5.0, {"a": 0.5, "b": 0.5}, seed=99)
        assert schedule1 == schedule2

    def test_different_seeds(self):
        schedule1 = _schedule_attacks(86400 * 7, 5.0, {"a": 1.0}, seed=1)
        schedule2 = _schedule_attacks(86400 * 7, 5.0, {"a": 1.0}, seed=2)
        assert schedule1 != schedule2

    def test_respects_distribution(self):
        """Weighted types should appear in roughly correct proportions."""
        duration = 365 * 86400  # 1 year for good statistics
        dist = {"brute_force": 0.7, "web_exploit": 0.3}
        schedule = _schedule_attacks(duration, 10.0, dist, seed=42)
        type_counts = {}
        for _, atype in schedule:
            type_counts[atype] = type_counts.get(atype, 0) + 1
        total = sum(type_counts.values())
        bf_frac = type_counts.get("brute_force", 0) / total
        # Should be close to 0.7 (within 0.1 for large sample)
        assert abs(bf_frac - 0.7) < 0.1

    def test_zero_rate(self):
        schedule = _schedule_attacks(86400, 0.0, {"a": 1.0}, seed=42)
        assert schedule == []

    def test_all_offsets_within_duration(self):
        duration = 86400 * 7
        schedule = _schedule_attacks(duration, 5.0, {"a": 1.0}, seed=42)
        for offset, _ in schedule:
            assert 0 < offset < duration


# ── Session transplanting ─────────────────────────────────────────────


class TestTransplantSession:
    def test_preserves_relative_timing(self):
        base = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            {"timestamp": (base + timedelta(seconds=i * 5)).isoformat(), "source": "test", "raw_line": f"atk {i}"}
            for i in range(5)
        ]
        timeline_start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        insertion_offset = 3600.0  # 1 hour in

        result = _transplant_session(events, insertion_offset, timeline_start)
        assert len(result) == 5

        ts_list = [_parse_ts(e["timestamp"]) for e in result]
        # Check relative timing preserved
        for i in range(1, len(ts_list)):
            dt = (ts_list[i] - ts_list[i - 1]).total_seconds()
            assert abs(dt - 5.0) < 0.01

        # Check absolute placement
        expected_start = timeline_start + timedelta(seconds=insertion_offset)
        assert abs((ts_list[0] - expected_start).total_seconds()) < 0.01

    def test_empty_events(self):
        result = _transplant_session([], 100.0, datetime.now(timezone.utc))
        assert result == []

    def test_source_ids_removed(self):
        events = [{"id": 99, "timestamp": "2026-01-01T00:00:00+00:00", "source": "test", "raw_line": "x"}]
        result = _transplant_session(events, 0, datetime(2026, 1, 1, tzinfo=timezone.utc))
        assert all("id" not in e for e in result)


# ── Full composition ──────────────────────────────────────────────────


class TestStreamComposer:
    def test_compose_creates_output(self, compose_config):
        config_path, output_db = compose_config
        composer = StreamComposer()
        stats = composer.compose(config_path)

        assert output_db.exists()
        assert stats.total > 0
        assert stats.benign_count > 0
        assert stats.attack_count >= 0
        assert stats.total == stats.benign_count + stats.attack_count

    def test_compose_stats(self, compose_config):
        config_path, _ = compose_config
        composer = StreamComposer()
        stats = composer.compose(config_path)

        assert stats.simulated_days == 7.0
        assert isinstance(stats.attack_types_used, dict)

    def test_deterministic(self, compose_config, tmp_path):
        config_path, output_db = compose_config
        composer = StreamComposer()

        stats1 = composer.compose(config_path)

        # Read first output
        conn1 = sqlite3.connect(str(output_db))
        events1 = conn1.execute("SELECT timestamp, raw_line, is_malicious FROM events ORDER BY id").fetchall()
        conn1.close()

        # Compose again (overwrites output)
        stats2 = composer.compose(config_path)

        conn2 = sqlite3.connect(str(output_db))
        events2 = conn2.execute("SELECT timestamp, raw_line, is_malicious FROM events ORDER BY id").fetchall()
        conn2.close()

        assert stats1.total == stats2.total
        assert stats1.attack_count == stats2.attack_count
        assert events1 == events2

    def test_timestamp_monotonicity(self, compose_config):
        config_path, output_db = compose_config
        composer = StreamComposer()
        composer.compose(config_path)

        conn = sqlite3.connect(str(output_db))
        timestamps = [row[0] for row in conn.execute("SELECT timestamp FROM events ORDER BY id")]
        conn.close()

        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1], (
                f"Timestamps not monotonic at index {i}: {timestamps[i-1]} > {timestamps[i]}"
            )

    def test_output_readable_by_stream(self, compose_config):
        """Composed DB should be readable by SecurityGymStream."""
        config_path, output_db = compose_config
        composer = StreamComposer()
        composer.compose(config_path)

        from security_gym.adapters.scan_stream import SecurityGymStream

        stream = SecurityGymStream(output_db)
        observations, ground_truths = stream.collect_numpy()
        assert isinstance(observations, list)
        assert isinstance(ground_truths, list)
        assert len(observations) == len(ground_truths)
        assert len(observations) > 0

    def test_dry_run_no_file(self, compose_config):
        config_path, output_db = compose_config
        composer = StreamComposer()
        stats = composer.compose(config_path, dry_run=True)

        assert stats.total > 0
        assert not output_db.exists()

    def test_composition_metadata_saved(self, compose_config):
        config_path, output_db = compose_config
        composer = StreamComposer()
        composer.compose(config_path)

        conn = sqlite3.connect(str(output_db))
        meta = dict(conn.execute("SELECT key, value FROM composition_meta").fetchall())
        conn.close()

        assert meta["seed"] == "42"
        assert "duration_seconds" in meta
        assert "campaigns_per_day" in meta
        assert "composed_at" in meta

    def test_empty_benign_db_raises(self, tmp_path, attack_db):
        empty_db = tmp_path / "empty.db"
        with EventStore(empty_db, mode="w"):
            pass

        config = {
            "stream": {
                "duration": "1d",
                "seed": 1,
                "benign": {"db": str(empty_db)},
                "attacks": {
                    "db": str(attack_db),
                    "campaigns_per_day": 1.0,
                    "distribution": {"brute_force": 1.0},
                },
                "output": {"db": str(tmp_path / "out.db")},
            }
        }
        config_path = tmp_path / "empty_benign.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)

        composer = StreamComposer()
        with pytest.raises(ValueError, match="No events found"):
            composer.compose(config_path)

    def test_missing_attack_type_warns(self, compose_config, tmp_path, benign_db, attack_db):
        """Requesting a type not in the attack DB should warn but not fail."""
        config = {
            "stream": {
                "duration": "1d",
                "seed": 42,
                "benign": {"db": str(benign_db)},
                "attacks": {
                    "db": str(attack_db),
                    "campaigns_per_day": 5.0,
                    "distribution": {
                        "brute_force": 0.5,
                        "nonexistent_type": 0.5,
                    },
                },
                "output": {"db": str(tmp_path / "missing_type.db")},
            }
        }
        config_path = tmp_path / "missing_type.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)

        composer = StreamComposer()
        stats = composer.compose(config_path)
        assert stats.total > 0  # benign events still present

    def test_short_duration(self, tmp_path, benign_db, attack_db):
        """Very short duration should produce few events."""
        config = {
            "stream": {
                "duration": "60s",
                "seed": 42,
                "benign": {"db": str(benign_db)},
                "attacks": {
                    "db": str(attack_db),
                    "campaigns_per_day": 1.0,
                    "distribution": {"brute_force": 1.0},
                },
                "output": {"db": str(tmp_path / "short.db")},
            }
        }
        config_path = tmp_path / "short.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)

        composer = StreamComposer()
        stats = composer.compose(config_path)
        # Per-source cycling: auth_log spans 2970s, duration 60s
        # → only ~2 events fit per cycle (events 30s apart)
        assert stats.benign_count > 0


# ── Bug fix tests ─────────────────────────────────────────────────────


class TestEnrichEbpfFields:
    """Tests for _enrich_ebpf_fields — Bug 1 fix."""

    def test_propagates_src_ip_from_log_events(self):
        """eBPF events should get src_ip from log siblings in same campaign."""
        by_type = {
            "brute_force": [
                {
                    "source": "auth_log",
                    "campaign_id": "campaign_abc",
                    "src_ip": "10.0.0.99",
                    "session_id": "10.0.0.99:40000",
                    "attack_type": "brute_force",
                },
                {
                    "source": "ebpf_process",
                    "campaign_id": "campaign_abc",
                    "src_ip": None,
                    "session_id": None,
                    "attack_type": "brute_force",
                },
                {
                    "source": "ebpf_file",
                    "campaign_id": "campaign_abc",
                    "src_ip": None,
                    "session_id": None,
                    "attack_type": "brute_force",
                },
            ]
        }
        result = _enrich_ebpf_fields(by_type)
        ebpf_events = [e for e in result["brute_force"] if e["source"].startswith("ebpf_")]
        for e in ebpf_events:
            assert e["src_ip"] == "10.0.0.99"
            assert e["session_id"] is not None
            assert "ebpf_" in e["session_id"]

    def test_replaces_zero_ip(self):
        """eBPF events with 0.0.0.0 should get the real src_ip."""
        by_type = {
            "discovery": [
                {
                    "source": "auth_log",
                    "campaign_id": "campaign_xyz",
                    "src_ip": "192.168.1.50",
                    "session_id": "192.168.1.50:22",
                    "attack_type": "discovery",
                },
                {
                    "source": "ebpf_network",
                    "campaign_id": "campaign_xyz",
                    "src_ip": "0.0.0.0",
                    "session_id": None,
                    "attack_type": "discovery",
                },
            ]
        }
        result = _enrich_ebpf_fields(by_type)
        ebpf = [e for e in result["discovery"] if e["source"] == "ebpf_network"][0]
        assert ebpf["src_ip"] == "192.168.1.50"

    def test_no_log_events_leaves_ebpf_unchanged(self):
        """If no log events have src_ip, eBPF events stay as-is."""
        by_type = {
            "discovery": [
                {
                    "source": "ebpf_process",
                    "campaign_id": "campaign_nolog",
                    "src_ip": None,
                    "session_id": None,
                    "attack_type": "discovery",
                },
            ]
        }
        result = _enrich_ebpf_fields(by_type)
        assert result["discovery"][0]["src_ip"] is None

    def test_multiple_campaigns_get_correct_ips(self):
        """Each campaign's eBPF events get that campaign's src_ip."""
        by_type = {
            "brute_force": [
                {
                    "source": "auth_log",
                    "campaign_id": "campaign_A",
                    "src_ip": "10.0.0.1",
                    "session_id": "10.0.0.1:22",
                    "attack_type": "brute_force",
                },
                {
                    "source": "ebpf_process",
                    "campaign_id": "campaign_A",
                    "src_ip": None,
                    "session_id": None,
                    "attack_type": "brute_force",
                },
                {
                    "source": "auth_log",
                    "campaign_id": "campaign_B",
                    "src_ip": "10.0.0.2",
                    "session_id": "10.0.0.2:22",
                    "attack_type": "brute_force",
                },
                {
                    "source": "ebpf_file",
                    "campaign_id": "campaign_B",
                    "src_ip": None,
                    "session_id": None,
                    "attack_type": "brute_force",
                },
            ]
        }
        result = _enrich_ebpf_fields(by_type)
        events = result["brute_force"]
        ebpf_a = [e for e in events if e["campaign_id"] == "campaign_A" and e["source"] == "ebpf_process"][0]
        ebpf_b = [e for e in events if e["campaign_id"] == "campaign_B" and e["source"] == "ebpf_file"][0]
        assert ebpf_a["src_ip"] == "10.0.0.1"
        assert ebpf_b["src_ip"] == "10.0.0.2"


class TestPerSourceCycling:
    """Tests for per-source cycling in _cycle_benign — Bug 2 fix."""

    def test_different_spans_both_fill_duration(self):
        """Sources with different spans each fill the full duration."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = []
        # Source A: 5 events spanning 4 hours
        for i in range(5):
            events.append({
                "timestamp": (base + timedelta(hours=i)).isoformat(),
                "source": "auth_log",
                "raw_line": f"auth {i}",
            })
        # Source B: 3 events spanning 30 minutes
        for i in range(3):
            events.append({
                "timestamp": (base + timedelta(minutes=i * 15)).isoformat(),
                "source": "ebpf_process",
                "raw_line": f"exec {i}",
            })

        # 24-hour composition
        duration = 24 * 3600.0
        result = _cycle_benign(events, duration)

        auth_events = [e for e in result if e["source"] == "auth_log"]
        ebpf_events = [e for e in result if e["source"] == "ebpf_process"]

        # auth_log spans 4h → cycles ~6x in 24h → ~30 events
        assert len(auth_events) >= 25
        # ebpf spans 30min → cycles ~48x in 24h → ~144 events
        assert len(ebpf_events) >= 100
        # Both sources present throughout
        assert len(auth_events) > 0
        assert len(ebpf_events) > 0

    def test_wide_span_difference_all_sources_survive(self):
        """Sources from different eras both fill the duration."""
        base_old = datetime(2012, 1, 1, tzinfo=timezone.utc)
        base_new = datetime(2026, 3, 20, tzinfo=timezone.utc)
        events = []
        # Old web logs spanning 4 hours
        for i in range(5):
            events.append({
                "timestamp": (base_old + timedelta(hours=i)).isoformat(),
                "source": "web_access",
                "raw_line": f"GET /page{i}",
            })
        # Recent eBPF spanning 40 seconds
        for i in range(5):
            events.append({
                "timestamp": (base_new + timedelta(seconds=i * 10)).isoformat(),
                "source": "ebpf_process",
                "raw_line": f"execve pid={i}",
            })

        duration = 7 * 86400.0  # 7 days
        result = _cycle_benign(events, duration)

        sources = {e["source"] for e in result}
        assert "web_access" in sources
        assert "ebpf_process" in sources
        # eBPF spans 40s, cycles ~15,000x in 7d → many events
        ebpf_count = sum(1 for e in result if e["source"] == "ebpf_process")
        assert ebpf_count > 100

    def test_single_source_still_cycles(self):
        """Single source type cycles normally."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            {
                "timestamp": (base + timedelta(seconds=i * 60)).isoformat(),
                "source": "auth_log",
                "raw_line": f"event {i}",
            }
            for i in range(10)
        ]
        # 10 events spanning 540s, compose to 1200s → should cycle ~2x
        result = _cycle_benign(events, 1200.0)
        assert len(result) > 10
        assert len(result) <= 22

    def test_timestamps_within_duration(self):
        """All output timestamps fall within the target duration."""
        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        events = [
            {"timestamp": base.isoformat(), "source": "web_access", "raw_line": "a"},
            {"timestamp": (base + timedelta(hours=1)).isoformat(), "source": "ebpf_file", "raw_line": "b"},
        ]
        duration = 3600.0  # 1 hour
        result = _cycle_benign(events, duration)
        t_min = min(_parse_ts(e["timestamp"]) for e in result)
        t_max = max(_parse_ts(e["timestamp"]) for e in result)
        span = (t_max - t_min).total_seconds()
        assert span <= duration


class TestDownsampleEbpf:
    """Tests for deterministic eBPF downsampling."""

    def test_reduces_ebpf_preserves_logs(self):
        """Downsampling reduces eBPF events but keeps all log events."""
        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "source": "auth_log", "raw_line": f"log{i}"}
            for i in range(100)
        ] + [
            {"timestamp": "2026-01-01T00:00:00Z", "source": "ebpf_file", "raw_line": f"open{i}"}
            for i in range(1000)
        ]
        result = _downsample_ebpf(events, sample_rate=0.242)
        log_count = sum(1 for e in result if e["source"] == "auth_log")
        ebpf_count = sum(1 for e in result if e["source"] == "ebpf_file")
        assert log_count == 100  # all log events preserved
        assert 180 < ebpf_count < 300  # ~242 ± statistical variation

    def test_deterministic(self):
        """Same events produce same sample both times."""
        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "source": "ebpf_process", "raw_line": f"exec{i}"}
            for i in range(500)
        ]
        r1 = _downsample_ebpf(events, sample_rate=0.5)
        r2 = _downsample_ebpf(events, sample_rate=0.5)
        assert len(r1) == len(r2)
        assert all(a["raw_line"] == b["raw_line"] for a, b in zip(r1, r2))

    def test_rate_1_keeps_all(self):
        """Sample rate 1.0 keeps everything."""
        events = [
            {"timestamp": "2026-01-01T00:00:00Z", "source": "ebpf_file", "raw_line": f"f{i}"}
            for i in range(100)
        ]
        result = _downsample_ebpf(events, sample_rate=1.0)
        assert len(result) == 100
