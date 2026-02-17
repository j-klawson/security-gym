"""Tests for log parsers."""

from datetime import timezone

from security_gym.parsers.auth_log import AuthLogParser
from security_gym.parsers.registry import ParserRegistry


class TestAuthLogParser:
    def setup_method(self):
        self.parser = AuthLogParser(year=2026)

    def test_password_auth_success(self):
        line = "Feb 17 10:16:00 myhost sshd[1235]: Accepted password for admin from 10.0.0.5 port 54321 ssh2"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "auth_success"
        assert event.src_ip == "10.0.0.5"
        assert event.username == "admin"
        assert event.service == "sshd"
        assert event.fields["auth_method"] == "password"
        assert event.session_id == "10.0.0.5:54321"

    def test_publickey_auth_success(self):
        line = "Feb 17 10:16:00 myhost sshd[1235]: Accepted publickey for deploy from 10.0.0.5 port 54321 ssh2: RSA SHA256:abc"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "auth_success"
        assert event.fields["auth_method"] == "publickey"

    def test_failed_password(self):
        line = "Feb 17 10:15:30 myhost sshd[1234]: Failed password for admin from 192.168.1.100 port 22345 ssh2"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "auth_failure"
        assert event.src_ip == "192.168.1.100"
        assert event.username == "admin"

    def test_failed_password_invalid_user(self):
        line = "Feb 17 10:15:30 myhost sshd[1234]: Failed password for invalid user test from 192.168.1.100 port 22345 ssh2"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "auth_failure"
        assert event.username == "test"

    def test_invalid_user(self):
        line = "Feb 17 10:15:33 myhost sshd[1234]: Invalid user test from 192.168.1.100 port 22345"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "auth_invalid_user"
        assert event.username == "test"

    def test_session_open(self):
        line = "Feb 17 10:16:01 myhost sshd[1235]: pam_unix(sshd:session): session opened for user admin by (uid=0)"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "session_open"
        assert event.username == "admin"

    def test_session_close(self):
        line = "Feb 17 10:20:00 myhost sshd[1235]: pam_unix(sshd:session): session closed for user admin"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "session_close"

    def test_connection_closed_preauth(self):
        line = "Feb 17 10:20:01 myhost sshd[1234]: Connection closed by authenticating user admin 192.168.1.100 port 22345 [preauth]"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "session_close"
        assert event.fields.get("preauth") is True

    def test_max_auth_attempts(self):
        line = "Feb 17 10:15:35 myhost sshd[1234]: error: maximum authentication attempts exceeded for admin from 192.168.1.100 port 22345 ssh2"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "auth_failure"
        assert event.fields.get("max_attempts_exceeded") is True

    def test_connection(self):
        line = "Feb 17 10:15:00 myhost sshd[1234]: Connection from 192.168.1.100 port 22345 on 10.0.0.1 port 22"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "connection"

    def test_non_sshd_returns_none(self):
        line = "Feb 17 10:15:00 myhost cron[5678]: (root) CMD (/usr/bin/something)"
        event = self.parser.parse_line(line)
        assert event is None

    def test_garbage_returns_none(self):
        assert self.parser.parse_line("not a log line") is None
        assert self.parser.parse_line("") is None

    def test_timestamp_utc(self):
        line = "Feb 17 10:16:00 myhost sshd[1235]: Accepted password for admin from 10.0.0.5 port 54321 ssh2"
        event = self.parser.parse_line(line)
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.hour == 10
        assert event.timestamp.month == 2


class TestParserRegistry:
    def test_auth_log_registered(self):
        assert "auth_log" in ParserRegistry.available()

    def test_get_auth_log(self):
        parser = ParserRegistry.get("auth_log")
        assert parser.name == "auth_log"

    def test_unknown_parser_raises(self):
        import pytest
        with pytest.raises(KeyError):
            ParserRegistry.get("nonexistent")
