"""Orchestration wrapper for the remote eBPF collector daemon.

Manages the lifecycle of the eBPF collector on the target VM via SSH:
start daemon, stop daemon, collect output, parse events into categories.

Uses a single persistent SSH connection with ControlMaster multiplexing
to avoid polluting auth.log with multiple sessions.
"""

from __future__ import annotations

import logging
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from security_gym.parsers.base import ParsedEvent

logger = logging.getLogger(__name__)

# Path to the eBPF collector script (deployed to target)
COLLECTOR_SCRIPT = Path(__file__).resolve().parent.parent.parent / "server" / "ebpf_collector.py"
REMOTE_COLLECTOR_PATH = "/tmp/security_gym_ebpf_collector.py"
REMOTE_OUTPUT_PATH = "/tmp/security_gym_events.log"

# eBPF event line pattern: timestamp event_type key=value pairs
_EVENT_LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+"
    r"(?P<event_type>\w+)\s+"
    r"(?P<fields>.+)$"
)

# Source category mapping
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


@dataclass
class KernelEvent:
    """A single parsed kernel event from the eBPF collector."""

    timestamp: datetime
    event_type: str
    source: str  # ebpf_process, ebpf_network, or ebpf_file
    fields: dict[str, Any]
    raw_line: str
    pid: int | None = None
    src_ip: str | None = None


def parse_ebpf_line(line: str) -> KernelEvent | None:
    """Parse a single line from the eBPF collector output.

    Returns None if the line cannot be parsed.
    """
    line = line.strip()
    if not line:
        return None

    m = _EVENT_LINE_RE.match(line)
    if not m:
        return None

    ts_str = m.group("timestamp")
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except ValueError:
        return None

    event_type = m.group("event_type")
    source = _SOURCE_MAP.get(event_type, "ebpf_process")

    # Parse key=value fields
    fields_str = m.group("fields")
    fields: dict[str, Any] = {}
    for part in re.finditer(r"(\w+)=(\S+)", fields_str):
        key, value = part.group(1), part.group(2)
        # Try to parse numeric values
        try:
            fields[key] = int(value)
        except ValueError:
            fields[key] = value

    pid = fields.get("pid")
    if isinstance(pid, str):
        try:
            pid = int(pid)
        except ValueError:
            pid = None

    # Extract source IP from network events
    src_ip = None
    if "src" in fields:
        src_val = str(fields["src"])
        if ":" in src_val:
            src_ip = src_val.rsplit(":", 1)[0]
        else:
            src_ip = src_val
    elif "dst" in fields:
        # For connect events, dst contains the remote IP
        dst_val = str(fields["dst"])
        if ":" in dst_val:
            src_ip = dst_val.rsplit(":", 1)[0]

    return KernelEvent(
        timestamp=ts,
        event_type=event_type,
        source=source,
        fields=fields,
        raw_line=line,
        pid=pid if isinstance(pid, int) else None,
        src_ip=src_ip,
    )


def parse_ebpf_output(content: str) -> list[KernelEvent]:
    """Parse the full output of the eBPF collector.

    Args:
        content: Raw text output from the eBPF collector.

    Returns:
        List of parsed KernelEvent objects.
    """
    events = []
    for line in content.splitlines():
        event = parse_ebpf_line(line)
        if event is not None:
            events.append(event)
    return events


def kernel_event_to_parsed_event(ke: KernelEvent) -> ParsedEvent:
    """Convert a KernelEvent to a ParsedEvent for EventStore insertion."""
    fields = dict(ke.fields)
    fields["event_type"] = ke.event_type

    return ParsedEvent(
        timestamp=ke.timestamp,
        source=ke.source,
        raw_line=ke.raw_line,
        event_type=ke.event_type,
        fields=fields,
        src_ip=ke.src_ip,
        pid=ke.pid,
    )


def categorize_events(
    events: list[KernelEvent],
) -> dict[str, list[KernelEvent]]:
    """Categorize kernel events by source type.

    Returns:
        Dict mapping source names to event lists:
        - "ebpf_process": execve, exit, fork events
        - "ebpf_network": connect, accept, bind, close events
        - "ebpf_file": open, write, unlink events
    """
    categorized: dict[str, list[KernelEvent]] = {
        "ebpf_process": [],
        "ebpf_network": [],
        "ebpf_file": [],
    }
    for event in events:
        categorized.setdefault(event.source, []).append(event)
    return categorized


class EbpfOrchestrator:
    """Manages the remote eBPF collector daemon via SSH.

    Uses a single persistent SSH connection with Transport reuse
    to minimize auth.log footprint.
    """

    def __init__(
        self,
        host: str,
        ssh_user: str = "researcher",
        ssh_key: str = "~/.ssh/isildur_research",
        ssh_port: int = 22,
    ):
        self.host = host
        self.ssh_user = ssh_user
        self.ssh_key = Path(ssh_key).expanduser()
        self.ssh_port = ssh_port
        self._transport = None
        self._events: list[KernelEvent] = []

    def _get_transport(self):
        """Get or create a persistent SSH transport."""
        try:
            import paramiko  # type: ignore[import-not-found]
        except ImportError:
            raise ImportError(
                "paramiko is required for eBPF orchestration. "
                "Install with: pip install 'security-gym[attacks]'"
            )

        if self._transport is None or not self._transport.is_active():
            self._transport = paramiko.Transport((self.host, self.ssh_port))
            key = paramiko.Ed25519Key.from_private_key_file(str(self.ssh_key))
            self._transport.connect(username=self.ssh_user, pkey=key)
            logger.info("SSH transport established to %s@%s", self.ssh_user, self.host)

        return self._transport

    def _exec_command(self, command: str) -> tuple[str, str]:
        """Execute a command over the persistent SSH transport."""
        transport = self._get_transport()
        channel = transport.open_session()
        channel.exec_command(command)

        stdout = channel.makefile("r").read()
        stderr = channel.makefile_stderr("r").read()
        channel.close()
        return stdout, stderr

    def start(self) -> None:
        """Deploy and start the eBPF collector on the remote host."""
        import paramiko  # type: ignore[import-not-found]

        transport = self._get_transport()

        # Upload collector script via SFTP
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.put(str(COLLECTOR_SCRIPT), REMOTE_COLLECTOR_PATH)
        sftp.close()
        logger.info("Deployed eBPF collector to %s:%s", self.host, REMOTE_COLLECTOR_PATH)

        # Start the daemon in background with sudo
        # nohup must wrap sudo (not the other way around) so sudo sees
        # python3 as the command and matches the NOPASSWD sudoers rule.
        self._exec_command(
            f"nohup sudo /usr/bin/python3 {REMOTE_COLLECTOR_PATH} "
            f"--output {REMOTE_OUTPUT_PATH} "
            f"> /dev/null 2>&1 & echo $!"
        )
        logger.info("eBPF collector started on %s", self.host)

    def stop(self) -> list[KernelEvent]:
        """Stop the eBPF collector and retrieve collected events.

        Returns:
            List of parsed KernelEvent objects.
        """
        import paramiko  # type: ignore[import-not-found]

        # Signal the collector to stop
        self._exec_command(
            f"sudo /usr/bin/pkill -f security_gym_ebpf_collector || true"
        )
        logger.info("eBPF collector stopped on %s", self.host)

        # Retrieve output via SFTP
        transport = self._get_transport()
        sftp = paramiko.SFTPClient.from_transport(transport)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tmp:
            local_path = tmp.name

        try:
            sftp.get(REMOTE_OUTPUT_PATH, local_path)
            with open(local_path) as f:
                content = f.read()
            self._events = parse_ebpf_output(content)
            logger.info("Retrieved %d eBPF events from %s", len(self._events), self.host)
        except FileNotFoundError:
            logger.warning("No eBPF output found on %s", self.host)
            self._events = []
        finally:
            sftp.close()
            Path(local_path).unlink(missing_ok=True)

        return self._events

    def get_parsed_events(self) -> list[ParsedEvent]:
        """Convert collected KernelEvents to ParsedEvents for EventStore."""
        return [kernel_event_to_parsed_event(ke) for ke in self._events]

    def close(self) -> None:
        """Close the SSH transport."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
