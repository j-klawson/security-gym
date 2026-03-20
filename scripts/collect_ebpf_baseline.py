#!/usr/bin/env python3
"""Collect benign eBPF kernel events from a remote server.

Runs the eBPF collector on a remote host for a configurable duration to
capture baseline kernel activity. All eBPF events are labeled benign
(is_malicious=0) since no attacks run during collection.

If --source is given, copies that DB first and appends eBPF events to it.
If --source is omitted, creates a fresh empty EventStore DB.

Usage:
    # Fresh DB (standalone eBPF collection)
    python scripts/collect_ebpf_baseline.py --duration 86400 --host 10.0.0.1 --output data/ebpf_server.db

    # Append to existing DB
    python scripts/collect_ebpf_baseline.py --source data/benign.db --duration 3600 --output data/benign_v2.db

    # Non-standard SSH port
    python scripts/collect_ebpf_baseline.py --duration 3600 --host 10.0.0.1 --ssh-port 2222 --output data/ebpf.db

    # Dry run
    python scripts/collect_ebpf_baseline.py --duration 300 --output data/ebpf.db --dry-run
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
        description="Collect benign eBPF baseline from a remote server",
    )
    parser.add_argument(
        "--duration", type=int, default=3600,
        help="Collection duration in seconds (default: 3600)",
    )
    parser.add_argument(
        "--source", type=Path, default=None,
        help="Source benign DB to copy as base. If omitted, creates a fresh empty DB.",
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
        "--ssh-port", type=int, default=22,
        help="SSH port (default: 22)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would happen without executing",
    )
    args = parser.parse_args()

    if args.dry_run:
        logger.info("DRY RUN — no changes will be made")
        if args.source:
            logger.info("Would copy %s → %s", args.source, args.output)
        else:
            logger.info("Would create fresh DB at %s", args.output)
        logger.info("Would collect eBPF events for %ds from %s:%d",
                     args.duration, args.host, args.ssh_port)
        logger.info("Would insert events into %s with is_malicious=0", args.output)
        return 0

    # Step 1: Prepare output DB
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        logger.warning("Output DB already exists: %s (will append eBPF events)", args.output)
    elif args.source:
        if not args.source.exists():
            logger.error("Source DB not found: %s", args.source)
            return 1
        logger.info("Copying %s → %s", args.source, args.output)
        shutil.copy2(args.source, args.output)
    else:
        logger.info("Creating fresh EventStore at %s", args.output)
        store = EventStore(args.output, mode="w")
        store.close()

    # Step 2: Start eBPF collector
    logger.info("Starting eBPF collector on %s", args.host)
    ebpf = EbpfOrchestrator(
        host=args.host,
        ssh_user=args.ssh_user,
        ssh_key=args.ssh_key,
        ssh_port=args.ssh_port,
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
