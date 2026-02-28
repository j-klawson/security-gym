"""SSH/SFTP log collection from target VM."""

from __future__ import annotations

import logging
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import paramiko

from attacks.config import CollectionConfig, LogSourceConfig, TargetConfig
from security_gym.parsers.base import ParsedEvent
from security_gym.parsers.registry import ParserRegistry

logger = logging.getLogger(__name__)


def _parse_utc_offset(offset_str: str) -> timedelta:
    """Parse a UTC offset string like '+0530' or '-0500' into a timedelta."""
    offset_str = offset_str.strip()
    sign = 1 if offset_str[0] == "+" else -1
    digits = offset_str.lstrip("+-")
    hours = int(digits[:2])
    minutes = int(digits[2:4]) if len(digits) >= 4 else 0
    return timedelta(hours=sign * hours, minutes=sign * minutes)


class LogCollector:
    """Collects logs from target VM via SSH/SFTP and parses them."""

    def __init__(
        self,
        target: TargetConfig,
        collection: CollectionConfig,
        campaign_start: datetime,
        campaign_end: datetime,
    ) -> None:
        self.target = target
        self.collection = collection
        # Add time buffer around campaign window
        buffer = timedelta(seconds=collection.time_buffer_seconds)
        self.start_time = campaign_start - buffer
        self.end_time = campaign_end + buffer
        self._client: paramiko.SSHClient | None = None
        self._sftp: paramiko.SFTPClient | None = None
        self._target_tz_offset: timedelta = timedelta(0)

    def connect(self) -> None:
        """Establish SSH connection to target and detect its timezone."""
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key_path = Path(self.target.ssh_key).expanduser()

        logger.info(
            "Connecting to %s@%s:%d",
            self.target.ssh_user, self.target.host, self.target.ssh_port,
        )
        self._client.connect(
            hostname=self.target.host,
            port=self.target.ssh_port,
            username=self.target.ssh_user,
            key_filename=str(key_path),
            timeout=30,
        )
        self._sftp = self._client.open_sftp()
        logger.info("Connected to %s", self.target.host)

        # Detect target timezone offset
        self._target_tz_offset = self._detect_timezone()

    def _detect_timezone(self) -> timedelta:
        """Detect the target's UTC offset via SSH."""
        assert self._client is not None
        try:
            _, stdout, _ = self._client.exec_command("date +%z", timeout=10)
            offset_str = stdout.read().decode().strip()
            if offset_str:
                offset = _parse_utc_offset(offset_str)
                logger.info("Target timezone offset: %s", offset_str)
                return offset
        except Exception as e:
            logger.warning("Could not detect target timezone: %s (assuming UTC)", e)
        return timedelta(0)

    def close(self) -> None:
        """Close SSH connection."""
        if self._sftp:
            self._sftp.close()
        if self._client:
            self._client.close()
        logger.info("Disconnected from %s", self.target.host)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def collect_all(self) -> list[ParsedEvent]:
        """Collect and parse all configured log sources."""
        all_events: list[ParsedEvent] = []
        for source in self.collection.log_sources:
            try:
                events = list(self._collect_source(source))
                logger.info("Collected %d events from %s", len(events), source.name)
                all_events.extend(events)
            except Exception as e:
                logger.error("Failed to collect %s: %s", source.name, e)
        # Sort by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        logger.info("Total: %d events collected", len(all_events))
        return all_events

    def _collect_source(self, source: LogSourceConfig) -> Iterator[ParsedEvent]:
        """Collect and parse a single log source."""
        if source.remote_path:
            yield from self._collect_file(source)
        elif source.remote_command:
            yield from self._collect_command(source)

    # Parsers that produce BSD syslog timestamps (local time without timezone).
    # These need offset correction; other parsers (web_access, web_error, journal)
    # either include timezone info or use epoch timestamps.
    _BSD_SYSLOG_PARSERS = frozenset({"auth_log", "syslog"})

    def _collect_file(self, source: LogSourceConfig) -> Iterator[ParsedEvent]:
        """Download and parse a remote log file."""
        assert self._sftp is not None
        assert source.parser is not None
        assert source.remote_path is not None

        parser = ParserRegistry.get(source.parser)

        # BSD syslog timestamps are local time with no timezone info.
        # The parser assumes UTC, so we convert our UTC window to the
        # target's local time for correct comparison, then fix the
        # timestamps back to real UTC after matching.
        needs_tz_fix = source.parser in self._BSD_SYSLOG_PARSERS
        if needs_tz_fix:
            window_start = self.start_time + self._target_tz_offset
            window_end = self.end_time + self._target_tz_offset
        else:
            window_start = self.start_time
            window_end = self.end_time

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            logger.debug("Downloading %s → %s", source.remote_path, tmp_path)
            self._sftp.get(source.remote_path, str(tmp_path))

            for event in parser.parse_file(tmp_path):
                if window_start <= event.timestamp <= window_end:
                    if needs_tz_fix:
                        # Convert from pseudo-UTC (actually local) to real UTC
                        event.timestamp = event.timestamp - self._target_tz_offset
                    yield event
        finally:
            tmp_path.unlink(missing_ok=True)

    def _collect_command(self, source: LogSourceConfig) -> Iterator[ParsedEvent]:
        """Run a remote command and parse its output."""
        assert self._client is not None
        assert source.remote_command is not None

        # Format time placeholders in command
        cmd = source.remote_command.format(
            start_time=self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            end_time=self.end_time.strftime("%Y-%m-%d %H:%M:%S"),
            start_time_audit=self.start_time.strftime("%m/%d/%Y %H:%M:%S"),
            end_time_audit=self.end_time.strftime("%m/%d/%Y %H:%M:%S"),
        )

        logger.debug("Running remote command: %s", cmd)
        _, stdout, stderr = self._client.exec_command(cmd, timeout=120)
        stdout.channel.settimeout(120)
        stderr.channel.settimeout(120)
        output = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")

        if err.strip():
            logger.warning("Command stderr for %s: %s", source.name, err[:500])

        if source.parser:
            parser = ParserRegistry.get(source.parser)
            for line in output.splitlines():
                event = parser.parse_line(line)
                if event is not None:
                    yield event
        else:
            # Raw output (e.g., auditd) — store as-is for later processing
            logger.debug("Raw output from %s: %d bytes", source.name, len(output))
            # Store raw output in metadata for labeler
            self._last_raw_output = output
