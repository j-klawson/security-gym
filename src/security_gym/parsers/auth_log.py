"""Parser for /var/log/auth.log (sshd + PAM events).

Handles sshd authentication success/failure, session open/close,
invalid user attempts, and connection events. Regex patterns adapted
from chronos-sec agent/log_sources/auth_log.py.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry

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

# SSHD message patterns
PATTERNS = {
    "auth_publickey": re.compile(
        r"^Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    "auth_password": re.compile(
        r"^Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    "auth_failed_password": re.compile(
        r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) "
        r"port (?P<port>\d+)"
    ),
    "invalid_user": re.compile(
        r"^Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?"
    ),
    "connection_closed_preauth": re.compile(
        r"^Connection closed by (?:authenticating user \S+ )?(?P<ip>[\d.]+) "
        r"port (?P<port>\d+) \[preauth\]"
    ),
    "disconnected": re.compile(
        r"^Disconnected from (?:authenticating user \S+ )?(?P<ip>[\d.]+) "
        r"port (?P<port>\d+)"
    ),
    "session_open": re.compile(
        r"^pam_unix\(sshd:session\): session opened for user (?P<user>\S+)"
    ),
    "session_close": re.compile(
        r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)"
    ),
    "connection": re.compile(
        r"^Connection from (?P<ip>[\d.]+) port (?P<port>\d+)"
    ),
    "max_auth_attempts": re.compile(
        r"^error: maximum authentication attempts exceeded for "
        r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
}

# Map pattern names → event_type strings
_EVENT_TYPE_MAP = {
    "auth_publickey": "auth_success",
    "auth_password": "auth_success",
    "auth_failed_password": "auth_failure",
    "invalid_user": "auth_invalid_user",
    "connection_closed_preauth": "session_close",
    "disconnected": "session_close",
    "session_open": "session_open",
    "session_close": "session_close",
    "connection": "connection",
    "max_auth_attempts": "auth_failure",
}


@ParserRegistry.register("auth_log")
class AuthLogParser(Parser):
    """Parser for /var/log/auth.log sshd events."""

    name = "auth_log"

    def __init__(self, year: int | None = None):
        self.year = year or datetime.now(timezone.utc).year

    def parse_line(self, line: str) -> ParsedEvent | None:
        header = SYSLOG_PATTERN.match(line)
        if not header:
            return None

        service = header.group("service")
        if service != "sshd":
            return None

        timestamp = self._parse_timestamp(
            header.group("month"), int(header.group("day")), header.group("time")
        )
        message = header.group("message")
        pid = int(header.group("pid")) if header.group("pid") else None

        for pattern_name, regex in PATTERNS.items():
            m = regex.match(message)
            if m:
                groups = m.groupdict()
                port_str = groups.get("port")
                ip = groups.get("ip")
                user = groups.get("user")
                port = int(port_str) if port_str else None
                session_id = f"{ip}:{port}" if ip and port else None

                fields = {"message": message, "pattern": pattern_name}
                if "publickey" in pattern_name:
                    fields["auth_method"] = "publickey"
                elif "password" in pattern_name:
                    fields["auth_method"] = "password"
                if port:
                    fields["port"] = port
                if pattern_name == "max_auth_attempts":
                    fields["max_attempts_exceeded"] = True
                if pattern_name == "connection_closed_preauth":
                    fields["preauth"] = True

                return ParsedEvent(
                    timestamp=timestamp,
                    source="auth_log",
                    raw_line=line,
                    event_type=_EVENT_TYPE_MAP[pattern_name],
                    fields=fields,
                    src_ip=ip,
                    username=user,
                    service="sshd",
                    session_id=session_id,
                    pid=pid,
                )

        return None

    def _parse_timestamp(self, month: str, day: int, time_str: str) -> datetime:
        month_num = MONTH_MAP.get(month, 1)
        hour, minute, second = map(int, time_str.split(":"))
        year = self.year
        ts = datetime(year, month_num, day, hour, minute, second, tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if ts > now:
            ts = ts.replace(year=year - 1)
        return ts
