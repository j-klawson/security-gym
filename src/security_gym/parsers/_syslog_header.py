"""Shared syslog header parsing for auth_log and syslog parsers."""

from __future__ import annotations

import re
from datetime import datetime, timezone

# Syslog header: "Mon DD HH:MM:SS hostname service[PID]: message"
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
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


def parse_syslog_timestamp(
    month: str, day: int, time_str: str, year: int,
) -> datetime:
    """Parse syslog timestamp components into a datetime.

    If the resulting timestamp is in the future, rolls back to the previous year.
    """
    month_num = MONTH_MAP.get(month, 1)
    hour, minute, second = map(int, time_str.split(":"))
    ts = datetime(year, month_num, day, hour, minute, second, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if ts > now:
        ts = ts.replace(year=year - 1)
    return ts
