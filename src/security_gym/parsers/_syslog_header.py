"""Shared syslog header parsing for auth_log and syslog parsers."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import NamedTuple

# BSD syslog header: "Mon DD HH:MM:SS hostname service[PID]: message"
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\w+)"
    r"(?:\[(?P<pid>\d+)\])?\s*:\s*"
    r"(?P<message>.*)$"
)

# RFC 3339 syslog header: "2026-02-22T00:55:01.662021-05:00 hostname service[PID]: message"
RFC3339_SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\w+)"
    r"(?:\[(?P<pid>\d+)\])?\s*:\s*"
    r"(?P<message>.*)$"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class SyslogHeader(NamedTuple):
    """Parsed syslog header fields."""

    timestamp: datetime
    hostname: str
    service: str
    pid: int | None
    message: str


def parse_syslog_timestamp(
    month: str, day: int, time_str: str, year: int,
) -> datetime:
    """Parse BSD syslog timestamp components into a datetime.

    If the resulting timestamp is in the future, rolls back to the previous year.
    """
    month_num = MONTH_MAP.get(month, 1)
    hour, minute, second = map(int, time_str.split(":"))
    ts = datetime(year, month_num, day, hour, minute, second, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if ts > now:
        ts = ts.replace(year=year - 1)
    return ts


def _parse_rfc3339_timestamp(ts_str: str) -> datetime:
    """Parse an RFC 3339 timestamp string into a UTC datetime."""
    # datetime.fromisoformat handles RFC 3339 (Python 3.11+)
    dt = datetime.fromisoformat(ts_str)
    # Convert to UTC
    return dt.astimezone(timezone.utc)


def parse_syslog_header(line: str, year: int | None = None) -> SyslogHeader | None:
    """Parse a syslog line header, supporting both BSD and RFC 3339 formats.

    Tries BSD format first, falls back to RFC 3339.
    Returns SyslogHeader or None if neither format matches.
    """
    # Try BSD format first
    m = SYSLOG_PATTERN.match(line)
    if m:
        if year is None:
            year = datetime.now(timezone.utc).year
        timestamp = parse_syslog_timestamp(
            m.group("month"), int(m.group("day")), m.group("time"), year,
        )
        pid = int(m.group("pid")) if m.group("pid") else None
        return SyslogHeader(
            timestamp=timestamp,
            hostname=m.group("hostname"),
            service=m.group("service"),
            pid=pid,
            message=m.group("message"),
        )

    # Try RFC 3339 format
    m = RFC3339_SYSLOG_PATTERN.match(line)
    if m:
        timestamp = _parse_rfc3339_timestamp(m.group("timestamp"))
        pid = int(m.group("pid")) if m.group("pid") else None
        return SyslogHeader(
            timestamp=timestamp,
            hostname=m.group("hostname"),
            service=m.group("service"),
            pid=pid,
            message=m.group("message"),
        )

    return None
