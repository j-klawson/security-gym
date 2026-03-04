#!/usr/bin/env python3
"""Migrate existing EventStore databases to include event_type in parsed JSON.

Fixes two issues in auth_log events:
1. event_type missing from parsed JSON (all auth_log events)
2. session_id and src_ip NULL on PAM session open/close events

Also adds event_type to any non-auth_log events that are missing it
(shouldn't happen, but safety net).

Usage:
    python scripts/migrate_event_type.py data/campaigns_v2.db
    python scripts/migrate_event_type.py data/exp_365d_realistic.db
    python scripts/migrate_event_type.py data/*.db  # all at once
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path

# Same mapping used by auth_log parser
_EVENT_TYPE_MAP = {
    "auth_publickey": "auth_success",
    "auth_password": "auth_success",
    "auth_failed_password": "auth_failure",
    "invalid_user": "auth_invalid_user",
    "connection_closed_preauth": "session_close",
    "disconnected": "session_close",
    "session_open": "session_open",
    "session_close": "session_close",
    "connection": "connection",
    "max_auth_attempts": "auth_failure",
}

# Extract PID from sshd[1234] in raw_line
_PID_RE = re.compile(r"sshd\[(\d+)\]")


def migrate_db(db_path: Path) -> dict[str, int]:
    """Migrate a single database. Returns counts of changes made."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    stats = {
        "event_type_added": 0,
        "session_enriched": 0,
        "non_auth_patched": 0,
        "total_auth_log": 0,
    }

    # --- Pass 1: Build PID → (src_ip, session_id) cache from auth events ---
    pid_cache: dict[int, tuple[str, str]] = {}
    auth_rows = conn.execute(
        "SELECT id, raw_line, parsed, session_id, src_ip "
        "FROM events WHERE source = 'auth_log' ORDER BY id"
    ).fetchall()
    stats["total_auth_log"] = len(auth_rows)

    for row in auth_rows:
        parsed = json.loads(row["parsed"]) if row["parsed"] else {}
        pattern = parsed.get("pattern", "")

        # Extract PID from raw_line
        m = _PID_RE.search(row["raw_line"])
        if not m:
            continue
        pid = int(m.group(1))

        # Cache PID → (ip, session_id) from events that have them
        if row["src_ip"] and row["session_id"]:
            pid_cache[pid] = (row["src_ip"], row["session_id"])

    # --- Pass 2: Update auth_log events ---
    updates_parsed = []  # (new_parsed_json, event_id)
    updates_session = []  # (session_id, src_ip, event_id)

    for row in auth_rows:
        parsed = json.loads(row["parsed"]) if row["parsed"] else {}
        pattern = parsed.get("pattern", "")
        changed = False

        # Fix 1: Add event_type if missing
        if "event_type" not in parsed and pattern in _EVENT_TYPE_MAP:
            parsed["event_type"] = _EVENT_TYPE_MAP[pattern]
            changed = True
            stats["event_type_added"] += 1

        # Fix 2: Enrich session events with src_ip/session_id from PID cache
        enriched_ip = None
        enriched_session = None
        if row["src_ip"] is None and row["session_id"] is None:
            m = _PID_RE.search(row["raw_line"])
            if m:
                pid = int(m.group(1))
                if pid in pid_cache:
                    enriched_ip, enriched_session = pid_cache[pid]
                    stats["session_enriched"] += 1

        if changed:
            updates_parsed.append((json.dumps(parsed), row["id"]))
        if enriched_ip:
            updates_session.append((enriched_session, enriched_ip, row["id"]))

    # --- Pass 3: Patch non-auth_log events missing event_type (safety net) ---
    other_rows = conn.execute(
        "SELECT id, parsed, source FROM events WHERE source != 'auth_log' AND parsed IS NOT NULL"
    ).fetchall()

    for row in other_rows:
        parsed = json.loads(row["parsed"])
        if "event_type" not in parsed:
            # Try to infer from source
            source_defaults = {
                "web_access": "http_request",
                "web_error": "http_error",
            }
            if row["source"] in source_defaults:
                parsed["event_type"] = source_defaults[row["source"]]
                updates_parsed.append((json.dumps(parsed), row["id"]))
                stats["non_auth_patched"] += 1

    # --- Apply updates ---
    if updates_parsed:
        conn.executemany(
            "UPDATE events SET parsed = ? WHERE id = ?",
            updates_parsed,
        )
    if updates_session:
        conn.executemany(
            "UPDATE events SET session_id = ?, src_ip = ? WHERE id = ?",
            updates_session,
        )
    conn.commit()
    conn.close()

    return stats


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <db_path> [db_path ...]")
        sys.exit(1)

    for path_str in sys.argv[1:]:
        db_path = Path(path_str)
        if not db_path.exists():
            print(f"SKIP {db_path} (not found)")
            continue
        if not db_path.suffix == ".db":
            print(f"SKIP {db_path} (not a .db file)")
            continue

        print(f"\nMigrating {db_path}...")
        stats = migrate_db(db_path)
        print(f"  auth_log events:    {stats['total_auth_log']}")
        print(f"  event_type added:   {stats['event_type_added']}")
        print(f"  sessions enriched:  {stats['session_enriched']}")
        print(f"  non-auth patched:   {stats['non_auth_patched']}")

    print("\nDone. Re-compose experiment streams to propagate fixes.")


if __name__ == "__main__":
    main()
