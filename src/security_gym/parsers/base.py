"""Shared types for log parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator


@dataclass
class ParsedEvent:
    """A single parsed log event."""

    timestamp: datetime
    source: str
    raw_line: str
    event_type: str
    fields: dict[str, Any] = field(default_factory=dict)
    src_ip: str | None = None
    username: str | None = None
    service: str | None = None
    session_id: str | None = None
    pid: int | None = None


class Parser(ABC):
    """Base class for log parsers."""

    name: str

    @abstractmethod
    def parse_line(self, line: str) -> ParsedEvent | None:
        """Parse a single log line. Returns None if unparseable."""
        ...

    def parse_file(self, path: Path) -> Iterator[ParsedEvent]:
        """Parse all lines in a file, yielding ParsedEvent for each recognized line."""
        with open(path) as f:
            for line in f:
                event = self.parse_line(line.rstrip("\n"))
                if event is not None:
                    yield event
