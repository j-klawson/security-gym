"""StreamComposer — offline composition of benign + attack event streams.

Reads benign and attack source EventStore DBs, interleaves them according
to a YAML config (Poisson attack schedule, weighted type distribution),
and writes a composed EventStore suitable for continual learning experiments.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

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

    return CompositionConfig(
        duration_seconds=duration_seconds,
        seed=seed,
        benign_db=benign_db,
        attack_db=attack_db,
        campaigns_per_day=campaigns_per_day,
        distribution=distribution,
        output_db=output_db,
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


def _parse_ts(ts_str: str) -> datetime:
    """Parse an ISO timestamp string to a datetime."""
    dt = datetime.fromisoformat(ts_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _cycle_benign(
    events: list[dict[str, Any]], duration_seconds: float
) -> list[dict[str, Any]]:
    """Repeat benign events with advancing timestamps to fill duration.

    Each cycle shifts timestamps forward by the benign time span.
    """
    if not events:
        return []

    ts_list = [_parse_ts(e["timestamp"]) for e in events]
    t_min = min(ts_list)
    t_max = max(ts_list)
    span = (t_max - t_min).total_seconds()
    if span <= 0:
        span = 1.0  # degenerate case: all same timestamp

    # Add a small gap between cycles to avoid exact overlap
    cycle_span = span + 1.0

    result: list[dict[str, Any]] = []
    cycle = 0
    while True:
        offset = timedelta(seconds=cycle * cycle_span)
        for event, ts in zip(events, ts_list):
            new_ts = ts - t_min + offset  # timedelta relative to epoch
            elapsed = new_ts.total_seconds()
            if elapsed > duration_seconds:
                return result
            new_event = dict(event)
            # Compute new absolute timestamp
            new_event["timestamp"] = (t_min + new_ts).isoformat()
            new_event.pop("id", None)  # remove source ID
            result.append(new_event)
        cycle += 1


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

        logger.info("Loading attack events from %s", config.attack_db)
        attacks_by_type = _read_attack_events_by_type(config.attack_db)
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

        # Step 1: Cycle benign events to fill duration
        logger.info("Cycling benign events to fill %.1f days", config.duration_days)
        cycled_benign = _cycle_benign(benign_events, config.duration_seconds)
        logger.info("Cycled to %d benign events", len(cycled_benign))

        # Determine timeline start from cycled benign
        if cycled_benign:
            timeline_start = _parse_ts(cycled_benign[0]["timestamp"])
        else:
            timeline_start = datetime.now(timezone.utc)

        # Step 2: Generate attack schedule
        schedule = _schedule_attacks(
            config.duration_seconds,
            config.campaigns_per_day,
            config.distribution,
            config.seed,
        )
        logger.info("Scheduled %d attack campaigns", len(schedule))

        # Step 3: Transplant attack sessions into timeline
        rng = np.random.default_rng(config.seed + 1)  # separate RNG for session selection
        transplanted_attacks: list[dict[str, Any]] = []
        type_counts: dict[str, int] = {}

        for offset, attack_type in schedule:
            if attack_type not in attacks_by_type:
                continue

            pool = attacks_by_type[attack_type]
            # Pick a random subset of attack events (simulate one campaign session)
            # Use all events of that type (they represent one campaign's worth)
            # If the pool has sessions, pick a random starting point
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

        # Step 4: Merge and sort by timestamp
        all_events = cycled_benign + transplanted_attacks
        all_events.sort(key=lambda e: e["timestamp"])

        stats = CompositionStats(
            benign_count=len(cycled_benign),
            attack_count=len(transplanted_attacks),
            total=len(all_events),
            attack_campaigns=len(schedule),
            simulated_days=config.duration_days,
            attack_types_used=type_counts,
        )

        if dry_run:
            logger.info("Dry run — not writing output. Stats: %s", stats)
            return stats

        # Step 5: Write output DB
        self._write_output(all_events, config.output_db, config)

        logger.info(
            "Composed %d events (%.0f days, %d campaigns) → %s",
            stats.total, stats.simulated_days, stats.attack_campaigns, config.output_db,
        )
        return stats

    def _write_output(
        self,
        events: list[dict[str, Any]],
        output_path: Path,
        config: CompositionConfig,
    ) -> None:
        """Write composed events to a new EventStore DB."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove existing DB to start fresh
        if output_path.exists():
            output_path.unlink()

        from security_gym.data.schema import SCHEMA_SQL, SCHEMA_VERSION

        conn = sqlite3.connect(str(output_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
        )

        # Bulk insert events
        rows = []
        for event in events:
            rows.append((
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
            ))

        conn.executemany(
            """INSERT INTO events
               (timestamp, source, raw_line, parsed,
                is_malicious, campaign_id, attack_type, attack_stage, severity,
                session_id, src_ip, username, service)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )

        # Write composition metadata
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
        conn.close()
