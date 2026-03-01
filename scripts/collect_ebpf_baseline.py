#!/usr/bin/env python3
"""Collect benign eBPF kernel events from Isildur and append to benign_v2.db.

Copies the existing benign.db (log events) then runs the eBPF collector on
Isildur for a configurable duration to capture baseline kernel activity.
All eBPF events are labeled benign (is_malicious=0) since no attacks run
during collection.

Usage:
    python scripts/collect_ebpf_baseline.py --duration 3600 --output data/benign_v2.db
    python scripts/collect_ebpf_baseline.py --duration 300 --output data/benign_v2.db --dry-run
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import time
from pathlib import Path

# Add src/ to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attacks.collection.ebpf_collector import EbpfOrchestrator
from security_gym.data.event_store import EventStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DEFAULT_SOURCE_DB = "data/benign.db"
DEFAULT_OUTPUT_DB = "data/benign_v2.db"
DEFAULT_HOST = "192.168.2.201"
DEFAULT_SSH_USER = "researcher"
DEFAULT_SSH_KEY = "~/.ssh/isildur_research"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect benign eBPF baseline from Isildur",
    )
    parser.add_argument(
        "--duration", type=int, default=3600,
        help="Collection duration in seconds (default: 3600)",
    )
    parser.add_argument(
        "--source", type=Path, default=Path(DEFAULT_SOURCE_DB),
        help=f"Source benign DB to copy (default: {DEFAULT_SOURCE_DB})",
    )
    parser.add_argument(
        "--output", type=Path, default=Path(DEFAULT_OUTPUT_DB),
        help=f"Output DB path (default: {DEFAULT_OUTPUT_DB})",
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Target host (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--ssh-user", default=DEFAULT_SSH_USER,
        help=f"SSH user (default: {DEFAULT_SSH_USER})",
    )
    parser.add_argument(
        "--ssh-key", default=DEFAULT_SSH_KEY,
        help=f"SSH key path (default: {DEFAULT_SSH_KEY})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would happen without executing",
    )
    args = parser.parse_args()

    if args.dry_run:
        logger.info("DRY RUN — no changes will be made")
        logger.info("Would copy %s → %s", args.source, args.output)
        logger.info("Would collect eBPF events for %ds from %s", args.duration, args.host)
        logger.info("Would insert events into %s with is_malicious=0", args.output)
        return 0

    # Step 1: Copy source DB
    if not args.source.exists():
        logger.error("Source DB not found: %s", args.source)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        logger.warning("Output DB already exists: %s (will append eBPF events)", args.output)
    else:
        logger.info("Copying %s → %s", args.source, args.output)
        shutil.copy2(args.source, args.output)

    # Step 2: Start eBPF collector
    logger.info("Starting eBPF collector on %s", args.host)
    ebpf = EbpfOrchestrator(
        host=args.host,
        ssh_user=args.ssh_user,
        ssh_key=args.ssh_key,
    )

    try:
        ebpf.start()
        logger.info("Collecting baseline eBPF events for %ds...", args.duration)
        time.sleep(args.duration)

        # Step 3: Stop and retrieve events
        ebpf.stop()
        parsed_events = ebpf.get_parsed_events()
        logger.info("Collected %d eBPF events", len(parsed_events))

        if not parsed_events:
            logger.warning("No eBPF events collected — check collector on %s", args.host)
            return 0

        # Step 4: Insert into DB as benign
        benign_gts = [{"is_malicious": 0, "severity": 0}] * len(parsed_events)

        with EventStore(args.output, mode="a") as store:
            count = store.bulk_insert(parsed_events, benign_gts)

        logger.info("Stored %d benign eBPF events in %s", count, args.output)

    finally:
        ebpf.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
