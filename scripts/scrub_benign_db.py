#!/usr/bin/env python3
"""Scrub identifying information from benign.db before publishing.

Replaces hostnames, domains, and vhost names with generic equivalents.

Mapping:
  server1 (its3, *.lhsc vhosts) → server1 / domain1.example.com
  ktl-dev (deb12test)            → server2 / domain2.example.com
  isildur                        → server3 / domain3.example.com
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path("data/benign.db")

# Ordered replacements — more specific patterns first to avoid partial matches.
# Each tuple: (old, new)
REPLACEMENTS = [
    # === ktl-dev / server2 ===
    # Full domain (must come before bare lhsc.on.ca)
    ("deb12test.lhsc.on.ca", "domain2.example.com"),
    ("ktl-dev", "server2"),

    # === server1 / its3 ===
    # Vhost names in filenames/logs (e.g. adum.lhsc_access.log patterns in parsed JSON)
    ("adum.lhsc", "app1.domain1.example"),
    ("its.lhsc", "app2.domain1.example"),
    ("itsn.lhsc", "app3.domain1.example"),
    ("pdm.lhsc", "app4.domain1.example"),
    # Remaining lhsc.on.ca occurrences (generic fallback)
    ("lhsc.on.ca", "domain1.example.com"),
    # URL path patterns
    ("egpage-lhsc", "egpage-domain1"),
    ("lhsc-status", "domain1-status"),
    # SSO module reference
    ("Site::SSO", "Site::Auth"),
    # Syslog hostname
    ("its3", "server1"),

    # === isildur / server3 ===
    ("isildur", "server3"),
]


def scrub_db(db_path: Path, dry_run: bool = False) -> None:
    """Apply all replacements to raw_line and parsed columns."""
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")

    # Count total rows
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"Database: {db_path} ({total} events)")

    if dry_run:
        # Just count affected rows per replacement
        for old, new in REPLACEMENTS:
            raw_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE raw_line LIKE ?",
                (f"%{old}%",),
            ).fetchone()[0]
            parsed_count = conn.execute(
                "SELECT COUNT(*) FROM events WHERE parsed LIKE ?",
                (f"%{old}%",),
            ).fetchone()[0]
            if raw_count or parsed_count:
                print(f"  {old!r} → {new!r}: {raw_count} raw_line, {parsed_count} parsed")
        conn.close()
        return

    # Apply replacements
    for old, new in REPLACEMENTS:
        # Update raw_line
        cursor = conn.execute(
            "UPDATE events SET raw_line = REPLACE(raw_line, ?, ?) WHERE raw_line LIKE ?",
            (old, new, f"%{old}%"),
        )
        raw_changed = cursor.rowcount

        # Update parsed JSON
        cursor = conn.execute(
            "UPDATE events SET parsed = REPLACE(parsed, ?, ?) WHERE parsed LIKE ?",
            (old, new, f"%{old}%"),
        )
        parsed_changed = cursor.rowcount

        if raw_changed or parsed_changed:
            print(f"  {old!r} → {new!r}: {raw_changed} raw_line, {parsed_changed} parsed")

    conn.commit()

    # Verify no remaining references
    print("\nVerification — searching for remaining references:")
    check_patterns = ["lhsc", "ktl-dev", "isildur", "its3", "deb12test"]
    clean = True
    for pattern in check_patterns:
        count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE raw_line LIKE ? OR parsed LIKE ?",
            (f"%{pattern}%", f"%{pattern}%"),
        ).fetchone()[0]
        if count:
            print(f"  WARNING: {count} rows still contain {pattern!r}")
            clean = False

    if clean:
        print("  All clean — no identifying strings remain.")

    # Compact
    print("\nVACUUMing database...")
    conn.execute("VACUUM")
    conn.close()
    print("Done.")


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    if not DB_PATH.exists():
        print(f"Error: {DB_PATH} not found")
        sys.exit(1)
    scrub_db(DB_PATH, dry_run=dry_run)
