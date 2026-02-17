"""Parser for Apache error logs.

Format: [DOW Mon DD HH:MM:SS.USEC YYYY] [module:level] [pid PID] [client IP:PORT] message
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry

# Apache error log regex
_ERROR_PATTERN = re.compile(
    r'^\[(?P<dow>\w{3})\s+'
    r'(?P<month>\w{3})\s+'
    r'(?P<day>\d{1,2})\s+'
    r'(?P<time>\d{2}:\d{2}:\d{2})'
    r'(?:\.(?P<usec>\d+))?\s+'
    r'(?P<year>\d{4})\]\s+'
    r'\[(?:(?P<module>[^:]+):)?(?P<level>\w+)\]\s+'
    r'\[pid\s+(?P<pid>\d+)\]\s*'
    r'(?:\[client\s+(?P<client_ip>[\d.]+):(?P<client_port>\d+)\]\s*)?'
    r'(?P<message>.*)'
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_error_timestamp(
    month: str, day: int, time_str: str, year: int,
) -> datetime:
    """Parse Apache error log timestamp components."""
    month_num = _MONTH_MAP.get(month, 1)
    hour, minute, second = map(int, time_str.split(":"))
    return datetime(year, month_num, day, hour, minute, second, tzinfo=timezone.utc)


@ParserRegistry.register("web_error")
class WebErrorParser(Parser):
    """Parser for Apache error logs."""

    name = "web_error"

    def parse_line(self, line: str) -> ParsedEvent | None:
        m = _ERROR_PATTERN.match(line)
        if not m:
            return None

        timestamp = _parse_error_timestamp(
            m.group("month"), int(m.group("day")),
            m.group("time"), int(m.group("year")),
        )

        client_ip = m.group("client_ip")
        client_port = m.group("client_port")
        pid = int(m.group("pid"))

        fields = {
            "event_type": "http_error",
            "level": m.group("level"),
            "module": m.group("module") or "",
            "error_message": m.group("message").strip(),
        }
        if client_port:
            fields["client_port"] = int(client_port)

        return ParsedEvent(
            timestamp=timestamp,
            source="web_error",
            raw_line=line,
            event_type="http_error",
            fields=fields,
            src_ip=client_ip,
            session_id=client_ip,
            pid=pid,
        )
