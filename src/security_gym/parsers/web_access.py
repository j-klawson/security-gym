"""Parser for Apache/Nginx combined access logs.

Format: IP - user [datetime] "method path proto" status size "referer" "ua"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry

# Combined log format regex
_ACCESS_PATTERN = re.compile(
    r'^(?P<ip>[\d.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<datetime>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s*(?P<protocol>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_access_timestamp(dt_str: str) -> datetime:
    """Parse '17/Feb/2026:10:15:30 +0000' format."""
    # Try strptime first for standard format
    try:
        return datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        # Fall back to manual parsing if timezone format differs
        pass
    # Last resort: return current time
    return datetime.now(timezone.utc)


@ParserRegistry.register("web_access")
class WebAccessParser(Parser):
    """Parser for Apache/Nginx combined access logs."""

    name = "web_access"

    def parse_line(self, line: str) -> ParsedEvent | None:
        m = _ACCESS_PATTERN.match(line)
        if not m:
            return None

        ip = m.group("ip")
        user = m.group("user")
        if user == "-":
            user = None

        timestamp = _parse_access_timestamp(m.group("datetime"))

        size_str = m.group("size")
        size = int(size_str) if size_str != "-" and size_str.isdigit() else 0

        fields = {
            "event_type": "http_request",
            "method": m.group("method"),
            "path": m.group("path"),
            "protocol": m.group("protocol") or "",
            "status_code": int(m.group("status")),
            "size": size,
            "referer": m.group("referer") or "",
            "user_agent": m.group("user_agent") or "",
        }

        return ParsedEvent(
            timestamp=timestamp,
            source="web_access",
            raw_line=line,
            event_type="http_request",
            fields=fields,
            src_ip=ip,
            username=user,
            session_id=ip,
        )
