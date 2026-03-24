"""StreamComposer — offline composition of benign + attack event streams.

Reads benign and attack source EventStore DBs, interleaves them according
to a YAML config (Poisson attack schedule, weighted type distribution),
and writes a composed EventStore suitable for continual learning experiments.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

import numpy as np
import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CompositionStats:
    """Summary statistics from a stream composition run."""

    benign_count: int
    attack_count: int
    total: int
    attack_campaigns: int
    simulated_days: float
    attack_types_used: dict[str, int]


@dataclass(frozen=True)
class CompositionConfig:
    """Parsed YAML composition config."""

    duration_seconds: float
    seed: int
    benign_db: Path
    attack_db: Path
    campaigns_per_day: float
    distribution: dict[str, float]
    output_db: Path
    ebpf_sample_rate: float  # 0.0–1.0, fraction of benign eBPF events to keep

    @property
    def duration_days(self) -> float:
        return self.duration_seconds / 86400.0


def _parse_duration(raw: str) -> float:
    """Parse a duration string like '90d', '7d', '24h' into seconds."""
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([dhms])$", str(raw).strip())
    if not match:
        raise ValueError(f"Invalid duration: {raw!r} (expected e.g. '90d', '24h')")
    value = float(match.group(1))
    unit = match.group(2)
    multipliers = {"d": 86400, "h": 3600, "m": 60, "s": 1}
    return value * multipliers[unit]


def _load_config(path: str | Path) -> CompositionConfig:
    """Parse and validate a composition YAML config."""
    path = Path(path)
    with open(path) as f:
        raw = yaml.safe_load(f)

    stream = raw.get("stream", {})
    if not stream:
        raise ValueError("Config must have a 'stream' top-level key")

    duration_seconds = _parse_duration(stream["duration"])
    seed = int(stream.get("seed", 42))

    benign = stream.get("benign", {})
    benign_db = Path(benign["db"])
    if not benign_db.is_absolute():
        benign_db = path.parent / benign_db

    attacks = stream.get("attacks", {})
    attack_db = Path(attacks["db"])
    if not attack_db.is_absolute():
        attack_db = path.parent / attack_db

    campaigns_per_day = float(attacks.get("campaigns_per_day", 3.0))

    distribution = attacks.get("distribution", {})
    if not distribution:
        raise ValueError("Config must specify attacks.distribution")

    # Normalize weights to probabilities
    total_weight = sum(distribution.values())
    if total_weight <= 0:
        raise ValueError("Distribution weights must sum to a positive value")
    distribution = {k: v / total_weight for k, v in distribution.items()}

    output = stream.get("output", {})
    output_db = Path(output["db"])
    if not output_db.is_absolute():
        output_db = path.parent / output_db

    ebpf_sample_rate = float(benign.get("ebpf_sample_rate", 1.0))
    if not 0.0 < ebpf_sample_rate <= 1.0:
        raise ValueError(
            f"ebpf_sample_rate must be in (0, 1.0], got {ebpf_sample_rate}"
        )

    return CompositionConfig(
        duration_seconds=duration_seconds,
        seed=seed,
        benign_db=benign_db,
        attack_db=attack_db,
        campaigns_per_day=campaigns_per_day,
        distribution=distribution,
        output_db=output_db,
        ebpf_sample_rate=ebpf_sample_rate,
    )


def _read_all_events(db_path: Path) -> list[dict[str, Any]]:
    """Read all events from a DB as dicts, ordered by timestamp."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT * FROM events ORDER BY timestamp, id")
    rows = [dict(row) for row in cursor]
    conn.close()
    return rows


def _read_attack_events_by_type(db_path: Path) -> dict[str, list[dict[str, Any]]]:
    """Read attack events grouped by attack_type."""
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT * FROM events WHERE is_malicious = 1 ORDER BY timestamp, id"
    )
    by_type: dict[str, list[dict[str, Any]]] = {}
    for row in cursor:
        d = dict(row)
        atype = d.get("attack_type") or "unknown"
        by_type.setdefault(atype, []).append(d)
    conn.close()
    return by_type


_EBPF_SOURCES = {"ebpf_process", "ebpf_network", "ebpf_file"}


def _downsample_ebpf(
    events: list[dict[str, Any]],
    sample_rate: float,
) -> list[dict[str, Any]]:
    """Deterministically downsample eBPF events to simulate a single server.

    Uses SHA-256 hash of (timestamp, source, raw_line) for stable,
    reproducible selection. Non-eBPF events pass through unchanged.
    """
    if sample_rate >= 1.0:
        return events

    threshold = int(sample_rate * 1000)
    result = []
    ebpf_total = 0
    ebpf_kept = 0

    for event in events:
        if event.get("source") not in _EBPF_SOURCES:
            result.append(event)
            continue

        ebpf_total += 1
        # Stable hash on content — same event always gets same decision
        key = f"{event['timestamp']}|{event['source']}|{event['raw_line']}"
        h = hashlib.sha256(key.encode()).hexdigest()
        if int(h, 16) % 1000 < threshold:
            result.append(event)
            ebpf_kept += 1

    if ebpf_total > 0:
        actual_rate = ebpf_kept / ebpf_total
        logger.info(
            "eBPF downsample: kept %d/%d (%.1f%%, target %.1f%%)",
            ebpf_kept, ebpf_total, actual_rate * 100, sample_rate * 100,
        )

    return result


def _enrich_ebpf_fields(
    by_type: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    """Propagate src_ip and session_id from log events to eBPF events.

    Within each attack_type pool, groups events by campaign_id, finds the
    dominant src_ip from log events in the same campaign, and assigns it
    to eBPF events that lack src_ip/session_id.
    """
    for attack_type, events in by_type.items():
        # Group by campaign_id
        by_campaign: dict[str, list[dict[str, Any]]] = {}
        for e in events:
            cid = e.get("campaign_id") or "unknown"
            by_campaign.setdefault(cid, []).append(e)

        for campaign_id, campaign_events in by_campaign.items():
            # Find the most common non-null, non-0.0.0.0 src_ip from log events
            ips = [
                e["src_ip"]
                for e in campaign_events
                if e.get("src_ip")
                and e["src_ip"] != "0.0.0.0"  # nosec B104
                and e.get("source") not in _EBPF_SOURCES
            ]
            if not ips:
                continue

            dominant_ip = Counter(ips).most_common(1)[0][0]

            # Generate a synthetic eBPF session_id for this campaign
            short_cid = campaign_id[-8:] if len(campaign_id) > 8 else campaign_id
            ebpf_session_id = f"{dominant_ip}:ebpf_{short_cid}"

            # Apply to eBPF events missing these fields
            enriched = 0
            for e in campaign_events:
                if e.get("source") in _EBPF_SOURCES:
                    if not e.get("src_ip") or e["src_ip"] == "0.0.0.0":  # nosec B104
                        e["src_ip"] = dominant_ip
                    if not e.get("session_id"):
                        e["session_id"] = ebpf_session_id
                    enriched += 1

            if enriched:
                logger.debug(
                    "Enriched %d eBPF events in campaign %s with src_ip=%s",
                    enriched, campaign_id, dominant_ip,
                )

    return by_type


def _parse_ts(ts_str: str) -> datetime:
    """Parse an ISO timestamp string to a datetime."""
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _cycle_source(
    events: list[dict[str, Any]],
    ts_list: list[datetime],
    duration_seconds: float,
    timeline_start: datetime,
) -> Iterator[dict[str, Any]]:
    """Cycle one source type's events to fill the target duration.

    Preserves intra-source inter-event timing. If the source spans less
    than the duration, events are repeated with advancing timestamps.
    If it spans more, events are used once with no repetition.

    Yields events one at a time to avoid building a large list in memory.
    """
    if not events:
        return

    t_min = min(ts_list)
    t_max = max(ts_list)
    span = (t_max - t_min).total_seconds()
    if span <= 0:
        span = 1.0

    cycle_span = span + 1.0  # small gap between cycles
    cycle = 0
    while True:
        cycle_offset = cycle * cycle_span
        for event, ts in zip(events, ts_list):
            relative = (ts - t_min).total_seconds()
            elapsed = cycle_offset + relative
            if elapsed > duration_seconds:
                return
            new_event = dict(event)
            new_event["timestamp"] = (
                timeline_start + timedelta(seconds=elapsed)
            ).isoformat()
            new_event.pop("id", None)
            yield new_event
        cycle += 1


def _event_to_row(event: dict[str, Any]) -> tuple[Any, ...]:
    """Convert an event dict to a tuple for SQLite insertion."""
    return (
        event["timestamp"],
        event["source"],
        event["raw_line"],
        event.get("parsed"),
        event.get("is_malicious"),
        event.get("campaign_id"),
        event.get("attack_type"),
        event.get("attack_stage"),
        event.get("severity"),
        event.get("session_id"),
        event.get("src_ip"),
        event.get("username"),
        event.get("service"),
    )


_INSERT_SQL = """INSERT INTO events
    (timestamp, source, raw_line, parsed,
     is_malicious, campaign_id, attack_type, attack_stage, severity,
     session_id, src_ip, username, service)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""

_WRITE_BATCH_SIZE = 50_000
_COMMIT_INTERVAL = 500_000


def _group_by_source(
    events: list[dict[str, Any]],
) -> tuple[datetime, dict[str, tuple[list[dict[str, Any]], list[datetime]]]]:
    """Parse timestamps, find timeline start, and group events by source.

    Returns (timeline_start, by_source) where by_source maps source name
    to (events_list, parsed_timestamps_list).
    """
    all_ts = [_parse_ts(e["timestamp"]) for e in events]
    timeline_start = min(all_ts)

    by_source: dict[str, tuple[list[dict[str, Any]], list[datetime]]] = {}
    for event, ts in zip(events, all_ts):
        src = event["source"]
        if src not in by_source:
            by_source[src] = ([], [])
        by_source[src][0].append(event)
        by_source[src][1].append(ts)

    return timeline_start, by_source


def _count_cycled(
    events: list[dict[str, Any]],
    ts_list: list[datetime],
    duration_seconds: float,
) -> int:
    """Count how many events cycling would produce without materializing them."""
    if not events:
        return 0

    t_min = min(ts_list)
    t_max = max(ts_list)
    span = (t_max - t_min).total_seconds()
    if span <= 0:
        span = 1.0

    cycle_span = span + 1.0
    # Full cycles that fit
    full_cycles = int(duration_seconds / cycle_span)
    remaining = duration_seconds - full_cycles * cycle_span

    # Count events in partial last cycle
    partial = 0
    for ts in ts_list:
        relative = (ts - t_min).total_seconds()
        if relative <= remaining:
            partial += 1
        else:
            break

    return full_cycles * len(events) + partial


def _stream_compose_to_db(
    benign_events: list[dict[str, Any]],
    attack_events: list[dict[str, Any]],
    duration_seconds: float,
    conn: sqlite3.Connection,
) -> int:
    """Stream-compose benign + attack events directly to SQLite.

    Merge-sorts per-source benign generators with sorted attack events
    so events are inserted in timestamp order (preserving the id==timestamp
    ordering invariant required by EventStore's cursor-based reads).

    Writes in batches to limit memory. The benign_events list is consumed
    by grouping and can be freed by the caller after this returns.

    Returns total number of events written.
    """
    timeline_start, by_source = _group_by_source(benign_events)

    # Build per-source generators and log stats
    generators: list[Iterator[dict[str, Any]]] = []
    for source, (src_events, src_ts) in by_source.items():
        src_min = min(src_ts)
        src_max = max(src_ts)
        src_span = (src_max - src_min).total_seconds()
        if src_span <= 0:
            src_span = 1.0
        cycles_needed = max(1, duration_seconds / (src_span + 1.0))
        logger.debug(
            "Source %s: %d events, span %.1f days, ~%dx cycles",
            source, len(src_events), src_span / 86400, int(cycles_needed),
        )
        generators.append(
            _cycle_source(src_events, src_ts, duration_seconds, timeline_start)
        )

    # Sort attack events by timestamp and add as another generator
    if attack_events:
        attack_events.sort(key=lambda e: e["timestamp"])
        generators.append(iter(attack_events))

    # Merge-sort all generators by timestamp, write in batches
    merged = heapq.merge(*generators, key=lambda e: e["timestamp"])

    total_written = 0
    since_last_commit = 0
    batch: list[tuple[Any, ...]] = []
    for event in merged:
        batch.append(_event_to_row(event))
        total_written += 1
        since_last_commit += 1
        if len(batch) >= _WRITE_BATCH_SIZE:
            conn.executemany(_INSERT_SQL, batch)
            batch.clear()
            if since_last_commit >= _COMMIT_INTERVAL:
                conn.commit()
                since_last_commit = 0
                logger.info("Committed %d events so far", total_written)

    if batch:
        conn.executemany(_INSERT_SQL, batch)

    conn.commit()
    return total_written


def _cycle_benign(
    events: list[dict[str, Any]], duration_seconds: float
) -> list[dict[str, Any]]:
    """Cycle benign events per source type to fill the target duration.

    Each source type (auth_log, syslog, ebpf_process, etc.) is cycled
    independently based on its own time span, then all are merged and
    sorted. This ensures sources with different collection durations
    (e.g. 28h of eBPF vs 68 days of syslog) each fill the entire
    composition window with realistic per-source cadence.

    NOTE: This in-memory version is retained for dry_run mode and tests.
    For actual writes, use _cycle_benign_to_db() which streams to SQLite.
    """
    if not events:
        return []

    timeline_start, by_source = _group_by_source(events)

    result: list[dict[str, Any]] = []
    for source, (src_events, src_ts) in by_source.items():
        src_min = min(src_ts)
        src_max = max(src_ts)
        src_span = (src_max - src_min).total_seconds()
        if src_span <= 0:
            src_span = 1.0
        cycles_needed = max(1, duration_seconds / (src_span + 1.0))
        cycled = list(_cycle_source(
            src_events, src_ts, duration_seconds, timeline_start,
        ))
        logger.debug(
            "Source %s: %d events, span %.1f days, cycled %dx → %d events",
            source, len(src_events), src_span / 86400,
            int(cycles_needed), len(cycled),
        )
        result.extend(cycled)

    # Merge all sources by timestamp
    result.sort(key=lambda e: e["timestamp"])
    return result


def _schedule_attacks(
    duration_seconds: float,
    campaigns_per_day: float,
    distribution: dict[str, float],
    seed: int,
) -> list[tuple[float, str]]:
    """Generate attack schedule: (offset_seconds, attack_type) pairs.

    Uses a Poisson process for campaign arrival times and weighted random
    selection for attack types.
    """
    rng = np.random.default_rng(seed)

    # Poisson inter-arrival times (exponential distribution)
    rate_per_second = campaigns_per_day / 86400.0
    if rate_per_second <= 0:
        return []

    types = list(distribution.keys())
    weights = np.array([distribution[t] for t in types])

    schedule: list[tuple[float, str]] = []
    t = 0.0
    while True:
        dt = rng.exponential(1.0 / rate_per_second)
        t += dt
        if t >= duration_seconds:
            break
        # Select attack type by weighted random choice
        attack_type = rng.choice(types, p=weights)
        schedule.append((t, str(attack_type)))

    return schedule


def _transplant_session(
    attack_events: list[dict[str, Any]],
    insertion_offset: float,
    timeline_start: datetime,
) -> list[dict[str, Any]]:
    """Rewrite attack event timestamps to place them at the insertion point.

    Preserves intra-session relative timing.
    """
    if not attack_events:
        return []

    ts_list = [_parse_ts(e["timestamp"]) for e in attack_events]
    session_start = min(ts_list)

    result: list[dict[str, Any]] = []
    for event, ts in zip(attack_events, ts_list):
        relative = (ts - session_start).total_seconds()
        new_ts = timeline_start + timedelta(seconds=insertion_offset + relative)
        new_event = dict(event)
        new_event["timestamp"] = new_ts.isoformat()
        new_event.pop("id", None)
        result.append(new_event)

    return result


class StreamComposer:
    """Compose interleaved benign + attack streams from source DBs.

    Reads a YAML config specifying data sources, attack distribution,
    and duration, then writes a composed EventStore DB.
    """

    def compose(self, config_path: str | Path, dry_run: bool = False) -> CompositionStats:
        """Compose a mixed stream from a YAML config.

        Args:
            config_path: Path to composition YAML config.
            dry_run: If True, compute stats without writing the output DB.

        Returns:
            CompositionStats with counts and distribution info.
        """
        config = _load_config(config_path)

        logger.info("Loading benign events from %s", config.benign_db)
        benign_events = _read_all_events(config.benign_db)
        if not benign_events:
            raise ValueError(f"No events found in benign DB: {config.benign_db}")
        logger.info("Loaded %d benign source events", len(benign_events))

        # Downsample eBPF events to simulate single-server volume
        if config.ebpf_sample_rate < 1.0:
            benign_events = _downsample_ebpf(
                benign_events, config.ebpf_sample_rate,
            )

        logger.info("Loading attack events from %s", config.attack_db)
        attacks_by_type = _read_attack_events_by_type(config.attack_db)

        # Enrich eBPF events with src_ip/session_id from campaign siblings
        attacks_by_type = _enrich_ebpf_fields(attacks_by_type)

        available_types = set(attacks_by_type.keys())
        requested_types = set(config.distribution.keys())
        missing = requested_types - available_types
        if missing:
            logger.warning(
                "Requested attack types not in DB (will skip): %s. Available: %s",
                missing, available_types,
            )
        logger.info(
            "Loaded attack types: %s",
            {k: len(v) for k, v in attacks_by_type.items()},
        )

        # Determine timeline start for attack transplanting
        all_ts = [_parse_ts(e["timestamp"]) for e in benign_events]
        timeline_start = min(all_ts)
        del all_ts

        # Generate attack schedule
        schedule = _schedule_attacks(
            config.duration_seconds,
            config.campaigns_per_day,
            config.distribution,
            config.seed,
        )
        logger.info("Scheduled %d attack campaigns", len(schedule))

        # Transplant attack sessions
        rng = np.random.default_rng(config.seed + 1)
        transplanted_attacks: list[dict[str, Any]] = []
        type_counts: dict[str, int] = {}

        for offset, attack_type in schedule:
            if attack_type not in attacks_by_type:
                continue
            pool = attacks_by_type[attack_type]
            session_size = min(len(pool), max(1, len(pool) // 3))
            start_idx = rng.integers(0, max(1, len(pool) - session_size + 1))
            session_events = pool[start_idx : start_idx + session_size]
            transplanted = _transplant_session(session_events, offset, timeline_start)
            transplanted_attacks.extend(transplanted)
            type_counts[attack_type] = type_counts.get(attack_type, 0) + 1

        logger.info(
            "Transplanted %d attack events across %d campaigns",
            len(transplanted_attacks), len(schedule),
        )

        # Free attack source data
        del attacks_by_type

        if dry_run:
            # Use in-memory cycling for dry run (small enough for count)
            logger.info("Cycling benign events to fill %.1f days (dry run)", config.duration_days)
            _, by_source = _group_by_source(benign_events)
            benign_count = 0
            for _src, (src_events, src_ts) in by_source.items():
                benign_count += _count_cycled(
                    src_events, src_ts, config.duration_seconds,
                )
            stats = CompositionStats(
                benign_count=benign_count,
                attack_count=len(transplanted_attacks),
                total=benign_count + len(transplanted_attacks),
                attack_campaigns=len(schedule),
                simulated_days=config.duration_days,
                attack_types_used=type_counts,
            )
            logger.info("Dry run — not writing output. Stats: %s", stats)
            return stats

        # --- Streaming write path: merge-sort and write directly to SQLite ---
        conn = self._open_output_db(config.output_db, config)

        logger.info("Cycling benign events to fill %.1f days", config.duration_days)
        attack_count_expected = len(transplanted_attacks)
        total_written = _stream_compose_to_db(
            benign_events, transplanted_attacks,
            config.duration_seconds, conn,
        )
        del benign_events, transplanted_attacks

        benign_count = total_written - attack_count_expected

        stats = CompositionStats(
            benign_count=benign_count,
            attack_count=attack_count_expected,
            total=total_written,
            attack_campaigns=len(schedule),
            simulated_days=config.duration_days,
            attack_types_used=type_counts,
        )

        conn.close()

        logger.info(
            "Composed %d events (%.0f days, %d campaigns) → %s",
            stats.total, stats.simulated_days, stats.attack_campaigns, config.output_db,
        )
        return stats

    def _open_output_db(
        self, output_path: Path, config: CompositionConfig,
    ) -> sqlite3.Connection:
        """Create and initialize the output DB, returning an open connection."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists():
            output_path.unlink()

        from security_gym.data.schema import SCHEMA_SQL, SCHEMA_VERSION

        conn = sqlite3.connect(str(output_path))
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
        )

        meta = {
            "seed": str(config.seed),
            "duration_seconds": str(config.duration_seconds),
            "campaigns_per_day": str(config.campaigns_per_day),
            "distribution": json.dumps(config.distribution),
            "benign_db": str(config.benign_db),
            "attack_db": str(config.attack_db),
            "composed_at": datetime.now(timezone.utc).isoformat(),
        }
        conn.executemany(
            "INSERT INTO composition_meta (key, value) VALUES (?, ?)",
            list(meta.items()),
        )
        conn.commit()
        return conn
