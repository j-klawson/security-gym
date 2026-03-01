"""Parser for eBPF collector output format.

Handles timestamped kernel event lines produced by server/ebpf_collector.py:
  2026-02-22T12:00:01.123456Z execve pid=1234 uid=1000 comm=wget args=wget,...
  2026-02-22T12:00:01.234567Z connect pid=1234 comm=wget dst=93.184.216.34:80
  2026-02-22T12:00:01.345678Z open pid=1234 comm=wget path=/tmp/payload.sh flags=O_WRONLY|O_CREAT
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry

# Event line pattern: ISO timestamp, event type, key=value pairs
_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+"
    r"(?P<event_type>\w+)\s+"
    r"(?P<rest>.+)$"
)

# Source mapping: event_type → source category
_SOURCE_MAP = {
    "execve": "ebpf_process",
    "exit": "ebpf_process",
    "fork": "ebpf_process",
    "connect": "ebpf_network",
    "accept": "ebpf_network",
    "bind": "ebpf_network",
    "close": "ebpf_network",
    "open": "ebpf_file",
    "write": "ebpf_file",
    "unlink": "ebpf_file",
}


@ParserRegistry.register("ebpf")
class EbpfParser(Parser):
    """Parser for eBPF collector output lines."""

    name = "ebpf"

    def parse_line(self, line: str) -> ParsedEvent | None:
        line = line.strip()
        if not line:
            return None

        m = _LINE_RE.match(line)
        if not m:
            return None

        ts_str = m.group("timestamp")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            return None

        event_type = m.group("event_type")
        source = _SOURCE_MAP.get(event_type, "ebpf_process")

        # Parse key=value fields from the rest of the line
        rest = m.group("rest")
        fields: dict[str, Any] = {"event_type": event_type}
        for kv_match in re.finditer(r"(\w+)=(\S+)", rest):
            key, value = kv_match.group(1), kv_match.group(2)
            try:
                fields[key] = int(value)
            except ValueError:
                fields[key] = value

        # Extract pid
        pid = fields.get("pid")
        if isinstance(pid, str):
            try:
                pid = int(pid)
            except ValueError:
                pid = None

        # Extract IP from network events
        src_ip = None
        if "src" in fields:
            src_val = str(fields["src"])
            src_ip = src_val.rsplit(":", 1)[0] if ":" in src_val else src_val
        elif "dst" in fields:
            dst_val = str(fields["dst"])
            src_ip = dst_val.rsplit(":", 1)[0] if ":" in dst_val else dst_val

        return ParsedEvent(
            timestamp=ts,
            source=source,
            raw_line=line,
            event_type=event_type,
            fields=fields,
            src_ip=src_ip,
            pid=pid if isinstance(pid, int) else None,
        )
