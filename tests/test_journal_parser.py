"""Tests for journalctl JSON parser."""

import json
from datetime import timezone

from security_gym.parsers.journal import JournalParser
from security_gym.parsers.registry import ParserRegistry


class TestJournalParser:
    def setup_method(self):
        self.parser = JournalParser()

    def _make_entry(self, **overrides):
        """Build a minimal journal JSON entry."""
        entry = {
            "__REALTIME_TIMESTAMP": "1739786130000000",  # 2025-02-17 10:15:30 UTC
            "SYSLOG_IDENTIFIER": "systemd",
            "MESSAGE": "Test message",
            "_SYSTEMD_UNIT": "test.service",
        }
        entry.update(overrides)
        return json.dumps(entry)

    def test_systemd_start(self):
        line = self._make_entry(MESSAGE="Started Apache HTTP Server.")
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "service_start"
        assert event.source == "journal"

    def test_systemd_stop(self):
        line = self._make_entry(MESSAGE="Stopped Apache HTTP Server.")
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "service_stop"

    def test_cron_event(self):
        line = self._make_entry(SYSLOG_IDENTIFIER="cron", MESSAGE="(root) CMD (test)")
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "cron"

    def test_kernel_event(self):
        line = self._make_entry(SYSLOG_IDENTIFIER="kernel", MESSAGE="TCP: out of memory")
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "kernel"

    def test_sshd_rejected(self):
        """sshd entries should be skipped (handled by auth_log)."""
        line = self._make_entry(SYSLOG_IDENTIFIER="sshd", MESSAGE="Failed password for root")
        event = self.parser.parse_line(line)
        assert event is None

    def test_timestamp_from_realtime(self):
        # 1739786130000000 us = 2025-02-17 10:15:30 UTC
        line = self._make_entry(__REALTIME_TIMESTAMP="1739786130000000")
        event = self.parser.parse_line(line)
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.year == 2025
        assert event.timestamp.second == 30

    def test_priority_parsed(self):
        line = self._make_entry(PRIORITY="3")
        event = self.parser.parse_line(line)
        assert event.fields["priority"] == 3

    def test_pid_parsed(self):
        line = self._make_entry(_PID="1234")
        event = self.parser.parse_line(line)
        assert event.pid == 1234

    def test_garbage_returns_none(self):
        assert self.parser.parse_line("not json") is None
        assert self.parser.parse_line("") is None

    def test_non_dict_returns_none(self):
        assert self.parser.parse_line('"just a string"') is None
        assert self.parser.parse_line("[1, 2, 3]") is None

    def test_registered(self):
        assert "journal" in ParserRegistry.available()
        parser = ParserRegistry.get("journal")
        assert parser.name == "journal"

    def test_event_type_in_fields(self):
        line = self._make_entry(MESSAGE="Started Apache HTTP Server.")
        event = self.parser.parse_line(line)
        assert event.fields["event_type"] == "service_start"

    def test_binary_message_handled(self):
        """journald can encode binary messages as byte arrays."""
        line = self._make_entry(MESSAGE=[72, 101, 108, 108, 111])
        event = self.parser.parse_line(line)
        assert event is not None
        assert "72" in event.fields["message"]
