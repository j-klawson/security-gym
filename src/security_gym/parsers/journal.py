"""Parser for journalctl JSON output (journalctl -o json).

Handles systemd journal entries as JSON lines. Skips sshd entries
to avoid duplicates with auth_log parser.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry


def _classify_journal_event(unit: str, identifier: str, message: str) -> str:
    """Classify a journal entry into an event type."""
    ident_lower = identifier.lower() if identifier else ""
    unit_lower = unit.lower() if unit else ""

    if "cron" in ident_lower or "cron" in unit_lower:
        return "cron"

    if ident_lower == "kernel":
        return "kernel"

    if "systemd" in ident_lower or unit_lower.endswith(".service"):
        if "Started" in message or "Starting" in message:
            return "service_start"
        if "Stopped" in message or "Stopping" in message:
            return "service_stop"

    if ident_lower == "sudo":
        return "other"

    return "other"


@ParserRegistry.register("journal")
class JournalParser(Parser):
    """Parser for journalctl -o json output."""

    name = "journal"

    def parse_line(self, line: str) -> ParsedEvent | None:
        line = line.strip()
        if not line:
            return None

        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return None

        if not isinstance(entry, dict):
            return None

        # Skip sshd entries to avoid duplicates with auth_log
        identifier = entry.get("SYSLOG_IDENTIFIER", "")
        if identifier == "sshd":
            return None

        # Parse timestamp from __REALTIME_TIMESTAMP (microseconds since epoch)
        ts_str = entry.get("__REALTIME_TIMESTAMP")
        if ts_str is not None:
            try:
                ts_us = int(ts_str)
                timestamp = datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        unit = entry.get("_SYSTEMD_UNIT", "")
        message = entry.get("MESSAGE", "")
        if isinstance(message, list):
            # journald can encode binary messages as byte arrays
            message = str(message)

        event_type = _classify_journal_event(unit, identifier, message)

        priority = entry.get("PRIORITY")
        if priority is not None:
            try:
                priority = int(priority)
            except (ValueError, TypeError):
                priority = None

        pid = entry.get("_PID") or entry.get("SYSLOG_PID")
        if pid is not None:
            try:
                pid = int(pid)
            except (ValueError, TypeError):
                pid = None

        fields = {
            "event_type": event_type,
            "unit": unit,
            "message": message,
        }
        if priority is not None:
            fields["priority"] = priority

        return ParsedEvent(
            timestamp=timestamp,
            source="journal",
            raw_line=line,
            event_type=event_type,
            fields=fields,
            service=identifier or None,
            pid=pid,
        )
