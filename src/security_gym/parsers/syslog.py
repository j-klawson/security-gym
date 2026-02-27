"""Parser for /var/log/syslog (non-sshd system messages).

Handles cron, kernel, systemd, sudo, and other system service messages.
Rejects sshd lines (those belong to auth_log parser).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from security_gym.parsers._syslog_header import parse_syslog_header
from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry

# Extract username from sudo lines: "username : TTY=..."
_SUDO_USER_PATTERN = re.compile(r"^(?P<user>\S+)\s*:")


def _classify_event(service: str, message: str) -> tuple[str, dict]:
    """Classify a syslog message into event_type and extra fields."""
    svc_lower = service.lower()
    fields: dict = {}

    if svc_lower in ("cron", "crond"):
        return "cron", fields

    if svc_lower == "kernel":
        return "kernel", fields

    if svc_lower == "systemd":
        if "Started" in message or "Starting" in message:
            return "service_start", fields
        if "Stopped" in message or "Stopping" in message:
            return "service_stop", fields
        return "other", fields

    if svc_lower == "sudo":
        fields["sudo"] = True
        m = _SUDO_USER_PATTERN.match(message)
        if m:
            fields["sudo_user"] = m.group("user")
        return "other", fields

    return "other", fields


@ParserRegistry.register("syslog")
class SyslogParser(Parser):
    """Parser for /var/log/syslog (non-sshd events)."""

    name = "syslog"

    def __init__(self, year: int | None = None):
        self.year = year or datetime.now(timezone.utc).year

    def parse_line(self, line: str) -> ParsedEvent | None:
        header = parse_syslog_header(line, self.year)
        if not header:
            return None

        # Reject sshd / sshd-session — those belong to auth_log
        if header.service.startswith("sshd"):
            return None

        event_type, extra_fields = _classify_event(header.service, header.message)

        fields = {"message": header.message, "event_type": event_type, **extra_fields}

        return ParsedEvent(
            timestamp=header.timestamp,
            source="syslog",
            raw_line=line,
            event_type=event_type,
            fields=fields,
            service=header.service,
            pid=header.pid,
        )
