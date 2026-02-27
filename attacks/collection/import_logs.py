"""Import benign log files (tarballs or directories) into EventStore."""

from __future__ import annotations

import gzip
import logging
import tarfile
import tempfile
from pathlib import Path

from security_gym.data.event_store import EventStore
from security_gym.parsers.base import ParsedEvent
from security_gym.parsers.registry import ParserRegistry

logger = logging.getLogger(__name__)

# Maps filename patterns to parser names.
# Matched by checking if the file's relative path contains the pattern.
FILE_ROUTES: list[tuple[str, str]] = [
    ("auth.log", "auth_log"),
    ("syslog", "syslog"),
    ("nginx/access.log", "web_access"),
    ("apache2/access.log", "web_access"),
    ("nginx/error.log", "web_error"),
    ("apache2/error.log", "web_error"),
]

# Files/directories to always skip (binary or unsupported formats).
SKIP_NAMES = {"journal", "btmp", "wtmp", "lastlog", "faillog"}

BATCH_SIZE = 5000


def _route_file(rel_path: str) -> str | None:
    """Return the parser name for a file based on its relative path, or None to skip."""
    name = Path(rel_path).name

    # Skip known binary/unsupported files
    if name in SKIP_NAMES:
        return None

    # Skip files inside journal/ directories
    if "/journal/" in rel_path or rel_path.startswith("journal/"):
        return None

    for pattern, parser_name in FILE_ROUTES:
        if pattern in rel_path:
            return parser_name

    # Apache vhost-named logs (e.g. apache2/mysite.com_access.log.1.gz)
    if "apache2/" in rel_path:
        if "_access.log" in name:
            return "web_access"
        if "_error.log" in name:
            return "web_error"

    return None


def _is_gz(path: Path) -> bool:
    return path.suffix == ".gz"


def _open_log_file(path: Path):
    """Open a log file, handling .gz compression transparently."""
    if _is_gz(path):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")  # noqa: SIM115


def _parse_file(path: Path, parser_name: str, source_host: str | None) -> list[ParsedEvent]:
    """Parse a single log file and return events."""
    parser = ParserRegistry.get(parser_name)
    events: list[ParsedEvent] = []
    errors = 0

    with _open_log_file(path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.rstrip("\n\r")
            if not line:
                continue
            try:
                event = parser.parse_line(line)
                if event is not None:
                    if source_host:
                        event.fields["source_host"] = source_host
                    events.append(event)
            except Exception:
                errors += 1
                if errors <= 5:
                    logger.debug("Parse error in %s line %d", path.name, line_num)

    if errors:
        logger.warning("%d parse errors in %s", errors, path.name)

    return events


class BenignLogImporter:
    """Import local log files into EventStore with benign labels."""

    def __init__(self, db_path: str | Path, source_host: str | None = None):
        self.db_path = Path(db_path)
        self.source_host = source_host

        # Counters
        self.total_events = 0
        self.total_errors = 0
        self.files_processed = 0
        self.files_skipped = 0
        self.events_by_source: dict[str, int] = {}

    def import_path(self, path: str | Path) -> int:
        """Import logs from a tarball or directory. Returns total events inserted."""
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        if path.is_dir():
            return self._import_directory(path)
        elif tarfile.is_tarfile(str(path)):
            return self._import_tarball(path)
        else:
            raise ValueError(f"Path must be a directory or tarball: {path}")

    def _import_tarball(self, tar_path: Path) -> int:
        """Extract tarball to temp dir and import."""
        logger.info("Extracting %s ...", tar_path.name)
        with tempfile.TemporaryDirectory(prefix="benign_import_") as tmp_dir:
            with tarfile.open(tar_path) as tf:
                tf.extractall(tmp_dir, filter="data")  # noqa: S202
            return self._import_directory(Path(tmp_dir))

    def _import_directory(self, root: Path) -> int:
        """Walk a directory, route files to parsers, and insert into EventStore."""
        # Discover files and their parsers
        file_plan: list[tuple[Path, str, str]] = []  # (path, rel_path, parser_name)

        for file_path in sorted(root.rglob("*")):
            if not file_path.is_file():
                continue

            rel = str(file_path.relative_to(root))
            parser_name = _route_file(rel)

            if parser_name is None:
                self.files_skipped += 1
                logger.debug("Skipping: %s", rel)
                continue

            file_plan.append((file_path, rel, parser_name))

        logger.info("Found %d parseable files (%d skipped)", len(file_plan), self.files_skipped)

        # Parse and batch-insert
        with EventStore(self.db_path, mode="a") as store:
            batch: list[ParsedEvent] = []

            for file_path, rel, parser_name in file_plan:
                logger.info("Parsing: %s → %s", rel, parser_name)
                events = _parse_file(file_path, parser_name, self.source_host)

                self.files_processed += 1
                count = len(events)
                self.events_by_source[parser_name] = (
                    self.events_by_source.get(parser_name, 0) + count
                )

                batch.extend(events)

                # Flush when batch is large enough
                while len(batch) >= BATCH_SIZE:
                    self._flush_batch(store, batch[:BATCH_SIZE])
                    batch = batch[BATCH_SIZE:]

            # Final partial batch
            if batch:
                self._flush_batch(store, batch)

        self._log_summary()
        return self.total_events

    def _flush_batch(self, store: EventStore, batch: list[ParsedEvent]) -> None:
        """Sort a batch by timestamp and insert with benign labels."""
        batch.sort(key=lambda e: e.timestamp)
        ground_truths = [{"is_malicious": 0}] * len(batch)
        store.bulk_insert(batch, ground_truths)
        self.total_events += len(batch)
        logger.debug("Inserted batch of %d events (total: %d)", len(batch), self.total_events)

    def _log_summary(self) -> None:
        logger.info("─── Import Summary ───")
        logger.info("Files processed: %d", self.files_processed)
        logger.info("Files skipped:   %d", self.files_skipped)
        logger.info("Total events:    %d", self.total_events)
        for source, count in sorted(self.events_by_source.items()):
            logger.info("  %-15s %d", source, count)
        if self.source_host:
            logger.info("Source host:     %s", self.source_host)
