"""Tests for syslog parser."""

from datetime import timezone

from security_gym.parsers.registry import ParserRegistry
from security_gym.parsers.syslog import SyslogParser


class TestSyslogParser:
    def setup_method(self):
        self.parser = SyslogParser(year=2026)

    def test_cron_event(self):
        line = "Feb 17 10:00:00 myhost CRON[1234]: (root) CMD (/usr/bin/something)"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "cron"
        assert event.source == "syslog"
        assert event.service == "CRON"
        assert event.pid == 1234

    def test_kernel_event(self):
        line = "Feb 17 10:00:01 myhost kernel: [12345.678] TCP: out of memory"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "kernel"
        assert event.service == "kernel"
        assert event.pid is None

    def test_systemd_start(self):
        line = "Feb 17 10:00:02 myhost systemd[1]: Started Apache HTTP Server."
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "service_start"
        assert event.service == "systemd"

    def test_systemd_stop(self):
        line = "Feb 17 10:00:03 myhost systemd[1]: Stopped Apache HTTP Server."
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "service_stop"

    def test_systemd_other(self):
        line = "Feb 17 10:00:04 myhost systemd[1]: Reached target Multi-User System."
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "other"

    def test_sudo_event(self):
        line = "Feb 17 10:00:05 myhost sudo[5678]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/ls"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "other"
        assert event.fields.get("sudo") is True
        assert event.fields.get("sudo_user") == "admin"

    def test_sshd_rejected(self):
        """sshd lines should be rejected (handled by auth_log parser)."""
        line = "Feb 17 10:15:30 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22345 ssh2"
        event = self.parser.parse_line(line)
        assert event is None

    def test_unknown_service(self):
        line = "Feb 17 10:00:06 myhost rsyslogd[999]: start"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "other"

    def test_garbage_returns_none(self):
        assert self.parser.parse_line("not a log line") is None
        assert self.parser.parse_line("") is None

    def test_timestamp_utc(self):
        line = "Feb 17 10:00:00 myhost CRON[1234]: (root) CMD (test)"
        event = self.parser.parse_line(line)
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.hour == 10

    def test_registered(self):
        assert "syslog" in ParserRegistry.available()
        parser = ParserRegistry.get("syslog")
        assert parser.name == "syslog"

    def test_event_type_in_fields(self):
        line = "Feb 17 10:00:00 myhost CRON[1234]: (root) CMD (test)"
        event = self.parser.parse_line(line)
        assert event.fields["event_type"] == "cron"
