"""Tests for web error log parser."""

from datetime import timezone

from security_gym.parsers.registry import ParserRegistry
from security_gym.parsers.web_error import WebErrorParser


class TestWebErrorParser:
    def setup_method(self):
        self.parser = WebErrorParser()

    def test_standard_error(self):
        line = "[Tue Feb 17 10:15:30.123456 2026] [core:error] [pid 1234] [client 192.168.1.100:54321] File does not exist: /var/www/html/missing"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "http_error"
        assert event.source == "web_error"
        assert event.src_ip == "192.168.1.100"
        assert event.session_id == "192.168.1.100"
        assert event.pid == 1234
        assert event.fields["level"] == "error"
        assert event.fields["module"] == "core"
        assert event.fields["client_port"] == 54321

    def test_no_client(self):
        line = "[Tue Feb 17 10:15:31 2026] [mpm_prefork:notice] [pid 100] AH00163: Apache/2.4.41 configured"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.src_ip is None
        assert event.session_id is None
        assert event.fields["level"] == "notice"

    def test_timestamp_parsed(self):
        line = "[Tue Feb 17 10:15:30 2026] [core:error] [pid 1234] [client 10.0.0.1:80] test"
        event = self.parser.parse_line(line)
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp.year == 2026
        assert event.timestamp.month == 2
        assert event.timestamp.hour == 10

    def test_warn_level(self):
        line = "[Tue Feb 17 10:15:30 2026] [ssl:warn] [pid 1234] AH01909: RSA certificate configured"
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.fields["level"] == "warn"
        assert event.fields["module"] == "ssl"

    def test_error_message_content(self):
        line = "[Tue Feb 17 10:15:30 2026] [core:error] [pid 1234] [client 10.0.0.1:80] Something went wrong"
        event = self.parser.parse_line(line)
        assert event.fields["error_message"] == "Something went wrong"

    def test_garbage_returns_none(self):
        assert self.parser.parse_line("not a log line") is None
        assert self.parser.parse_line("") is None

    def test_registered(self):
        assert "web_error" in ParserRegistry.available()
        parser = ParserRegistry.get("web_error")
        assert parser.name == "web_error"

    def test_event_type_in_fields(self):
        line = "[Tue Feb 17 10:15:30 2026] [core:error] [pid 1234] [client 10.0.0.1:80] test"
        event = self.parser.parse_line(line)
        assert event.fields["event_type"] == "http_error"
