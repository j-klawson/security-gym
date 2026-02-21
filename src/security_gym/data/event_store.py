"""SQLite event storage with WAL mode for concurrent access."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_gym.data.schema import SCHEMA_SQL, SCHEMA_VERSION
from security_gym.parsers.base import ParsedEvent


class EventStore:
    """SQLite-backed event storage for security log data.

    Uses WAL mode for concurrent read-during-write access.
    ID-based cursor for resumable reads.
    """

    def __init__(self, db_path: str | Path, mode: str = "a"):
        """Open or create an event database.

        Args:
            db_path: Path to SQLite database file.
            mode: 'a' (append/read-write), 'r' (read-only), 'w' (overwrite).
        """
        self.db_path = Path(db_path)
        self.mode = mode

        if mode == "r":
            uri = f"file:{self.db_path}?mode=ro"
            self.conn = sqlite3.connect(uri, uri=True)
        else:
            self.conn = sqlite3.connect(str(self.db_path))

        self.conn.row_factory = sqlite3.Row

        if mode != "r":
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")

        if mode in ("a", "w"):
            if mode == "w":
                self.conn.executescript(
                    "DROP TABLE IF EXISTS events;"
                    "DROP TABLE IF EXISTS campaigns;"
                    "DROP TABLE IF EXISTS sessions;"
                    "DROP TABLE IF EXISTS schema_version;"
                )
            self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(SCHEMA_SQL)
        cursor = self.conn.execute(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
        )
        if cursor.fetchone() is None:
            self.conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, datetime.now(timezone.utc).isoformat()),
            )
        self.conn.commit()

    # ── Write ──────────────────────────────────────────────────────────

    def insert_event(
        self,
        event: ParsedEvent,
        ground_truth: dict[str, Any] | None = None,
    ) -> int:
        """Insert a single parsed event. Returns the new row id."""
        gt = ground_truth or {}
        parsed_json = json.dumps(event.fields) if event.fields else None
        cursor = self.conn.execute(
            """INSERT INTO events
               (timestamp, source, raw_line, parsed,
                is_malicious, campaign_id, attack_type, attack_stage, severity,
                session_id, src_ip, username, service)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.timestamp.isoformat(),
                event.source,
                event.raw_line,
                parsed_json,
                gt.get("is_malicious"),
                gt.get("campaign_id"),
                gt.get("attack_type"),
                gt.get("attack_stage"),
                gt.get("severity"),
                event.session_id,
                event.src_ip,
                event.username,
                event.service,
            ),
        )
        self.conn.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def insert_campaign(self, campaign: dict[str, Any]) -> str:
        """Insert a campaign record. Returns campaign id."""
        self.conn.execute(
            """INSERT INTO campaigns
               (id, name, start_time, end_time, attack_type,
                mitre_tactics, description, parameters)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign["id"],
                campaign["name"],
                campaign["start_time"],
                campaign.get("end_time"),
                campaign["attack_type"],
                campaign.get("mitre_tactics"),
                campaign.get("description"),
                json.dumps(campaign.get("parameters")) if campaign.get("parameters") else None,
            ),
        )
        self.conn.commit()
        return str(campaign["id"])

    def bulk_insert(self, events: list[ParsedEvent], ground_truths: list[dict] | None = None) -> int:
        """Insert multiple events in a single transaction. Returns count inserted."""
        gts = ground_truths or [{}] * len(events)
        rows = []
        for event, gt in zip(events, gts):
            parsed_json = json.dumps(event.fields) if event.fields else None
            rows.append((
                event.timestamp.isoformat(),
                event.source,
                event.raw_line,
                parsed_json,
                gt.get("is_malicious"),
                gt.get("campaign_id"),
                gt.get("attack_type"),
                gt.get("attack_stage"),
                gt.get("severity"),
                event.session_id,
                event.src_ip,
                event.username,
                event.service,
            ))
        self.conn.executemany(
            """INSERT INTO events
               (timestamp, source, raw_line, parsed,
                is_malicious, campaign_id, attack_type, attack_stage, severity,
                session_id, src_ip, username, service)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        self.conn.commit()
        return len(rows)

    # ── Read ───────────────────────────────────────────────────────────

    def get_events(
        self,
        start_id: int = 0,
        limit: int = 1000,
        sources: list[str] | None = None,
    ) -> list[sqlite3.Row]:
        """Fetch events with id > start_id, ordered by id."""
        if sources:
            placeholders = ",".join("?" for _ in sources)
            cursor = self.conn.execute(
                f"""SELECT * FROM events
                    WHERE id > ? AND source IN ({placeholders})
                    ORDER BY id LIMIT ?""",
                [start_id, *sources, limit],
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?",
                (start_id, limit),
            )
        return cursor.fetchall()

    def count_events(self) -> int:
        cursor = self.conn.execute("SELECT COUNT(*) FROM events")
        return int(cursor.fetchone()[0])

    def get_time_range(self) -> tuple[str, str] | None:
        """Return (min_timestamp, max_timestamp) or None if empty."""
        cursor = self.conn.execute(
            "SELECT MIN(timestamp), MAX(timestamp) FROM events"
        )
        row = cursor.fetchone()
        if row[0] is None:
            return None
        return (row[0], row[1])

    def get_sources(self) -> list[str]:
        cursor = self.conn.execute("SELECT DISTINCT source FROM events ORDER BY source")
        return [row[0] for row in cursor]

    def get_campaigns(self) -> list[dict]:
        cursor = self.conn.execute("SELECT * FROM campaigns ORDER BY start_time")
        return [dict(row) for row in cursor]

    # ── Lifecycle ──────────────────────────────────────────────────────

    def flush(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        if self.mode != "r":
            self.flush()
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __len__(self) -> int:
        return self.count_events()
