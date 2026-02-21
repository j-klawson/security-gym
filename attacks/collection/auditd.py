"""Parse ausearch output for exploit ground truth confirmation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditEvent:
    """A parsed auditd event indicating confirmed exploit execution."""

    timestamp: datetime
    event_type: str  # e.g., "EXECVE", "SYSCALL"
    pid: int | None = None
    uid: int | None = None
    exe: str | None = None
    command: str | None = None
    key: str | None = None
    raw: str = ""
    fields: dict[str, Any] = field(default_factory=dict)


# Pattern for ausearch --interpret output timestamps
# Example: type=SYSCALL msg=audit(01/15/2026 14:23:45.123:456)
_TS_PATTERN = re.compile(
    r"msg=audit\((\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+):\d+\)"
)

# Pattern for key-value pairs in ausearch output
_KV_PATTERN = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_ausearch_output(text: str) -> list[AuditEvent]:
    """Parse ausearch --interpret --format text output into AuditEvents.

    Looks for events tagged with 'research_exploit' key, which confirms
    actual exploit execution (wget, curl, sh, bash spawned by exploit).
    """
    events: list[AuditEvent] = []

    # Split into records (separated by ---- or blank lines)
    records = re.split(r"\n----\n|\n\n", text.strip())

    for record in records:
        if not record.strip():
            continue

        event = _parse_record(record.strip())
        if event is not None:
            events.append(event)

    return events


def _parse_record(record: str) -> AuditEvent | None:
    """Parse a single ausearch record."""
    fields: dict[str, Any] = {}
    timestamp = None
    event_type = None

    for line in record.splitlines():
        line = line.strip()
        if not line:
            continue

        # Extract type
        type_match = re.match(r"type=(\w+)", line)
        if type_match and event_type is None:
            event_type = type_match.group(1)

        # Extract timestamp
        ts_match = _TS_PATTERN.search(line)
        if ts_match and timestamp is None:
            try:
                timestamp = datetime.strptime(
                    ts_match.group(1).split(".")[0],
                    "%m/%d/%Y %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # Extract all key=value pairs
        for key, value in _KV_PATTERN.findall(line):
            # Strip quotes
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            fields[key] = value

    if timestamp is None or event_type is None:
        return None

    return AuditEvent(
        timestamp=timestamp,
        event_type=event_type,
        pid=int(fields["pid"]) if "pid" in fields else None,
        uid=int(fields["uid"]) if "uid" in fields and fields["uid"].isdigit() else None,
        exe=fields.get("exe"),
        command=fields.get("a0"),  # First argument in EXECVE
        key=fields.get("key"),
        raw=record,
        fields=fields,
    )


def filter_exploit_events(events: list[AuditEvent], key: str = "research_exploit") -> list[AuditEvent]:
    """Filter to only events with the specified audit key."""
    return [e for e in events if e.key == key]
