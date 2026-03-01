#!/usr/bin/env python3
"""Insert manually-collected eBPF baseline events into benign_v2.db.

Use this when the eBPF collector was run by hand (e.g. in tmux) rather
than through the orchestrator. Parses the raw output file and inserts
all events as benign (is_malicious=0).

Usage:
    python scripts/insert_ebpf_baseline.py /tmp/ebpf_baseline.log
    python scripts/insert_ebpf_baseline.py /tmp/ebpf_baseline.log --db data/benign_v2.db
    python scripts/insert_ebpf_baseline.py /tmp/ebpf_baseline.log --dry-run
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from security_gym.data.event_store import EventStore
from security_gym.parsers.ebpf import EbpfParser

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_DB = "data/benign_v2.db"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Insert manually-collected eBPF baseline into benign_v2.db",
    )
    parser.add_argument(
        "events_file", type=Path,
        help="Path to raw eBPF collector output file",
    )
    parser.add_argument(
        "--db", type=Path, default=Path(DEFAULT_DB),
        help=f"Target database (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Parse and count events without inserting",
    )
    args = parser.parse_args()

    if not args.events_file.exists():
        logger.error("Events file not found: %s", args.events_file)
        return 1

    if not args.db.exists():
        logger.error("Database not found: %s (run collect_ebpf_baseline.py first to create it)", args.db)
        return 1

    # Parse events
    ebpf_parser = EbpfParser()
    parsed_events = []
    skipped = 0

    with open(args.events_file) as f:
        for line in f:
            event = ebpf_parser.parse_line(line)
            if event is not None:
                parsed_events.append(event)
            else:
                skipped += 1

    logger.info("Parsed %d events (%d lines skipped) from %s",
                len(parsed_events), skipped, args.events_file)

    if not parsed_events:
        logger.warning("No events to insert")
        return 0

    # Source breakdown
    sources: dict[str, int] = {}
    for e in parsed_events:
        sources[e.source] = sources.get(e.source, 0) + 1
    for source, count in sorted(sources.items()):
        logger.info("  %s: %d events", source, count)

    if args.dry_run:
        logger.info("DRY RUN — would insert %d events into %s", len(parsed_events), args.db)
        return 0

    # Insert as benign
    benign_gts = [{"is_malicious": 0, "severity": 0}] * len(parsed_events)

    with EventStore(args.db, mode="a") as store:
        count = store.bulk_insert(parsed_events, benign_gts)

    logger.info("Inserted %d benign eBPF events into %s", count, args.db)
    return 0


if __name__ == "__main__":
    sys.exit(main())
