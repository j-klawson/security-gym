"""Tests for web access log parser."""

from security_gym.parsers.registry import ParserRegistry
from security_gym.parsers.web_access import WebAccessParser


class TestWebAccessParser:
    def setup_method(self):
        self.parser = WebAccessParser()

    def test_standard_get(self):
        line = '192.168.1.100 - - [17/Feb/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "http_request"
        assert event.source == "web_access"
        assert event.src_ip == "192.168.1.100"
        assert event.username is None
        assert event.session_id == "192.168.1.100"
        assert event.fields["method"] == "GET"
        assert event.fields["path"] == "/index.html"
        assert event.fields["status_code"] == 200
        assert event.fields["size"] == 1234

    def test_post_with_user(self):
        line = '10.0.0.5 - admin [17/Feb/2026:10:16:00 +0000] "POST /api/login HTTP/1.1" 302 0 "-" "curl/7.68.0"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.username == "admin"
        assert event.fields["method"] == "POST"
        assert event.fields["status_code"] == 302

    def test_404_error(self):
        line = '192.168.1.50 - - [17/Feb/2026:10:17:00 +0000] "GET /nonexistent HTTP/1.1" 404 196 "-" "Mozilla/5.0"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.fields["status_code"] == 404

    def test_dash_size(self):
        line = '10.0.0.1 - - [17/Feb/2026:10:18:00 +0000] "HEAD / HTTP/1.1" 200 - "-" "curl/7.68.0"'
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.fields["size"] == 0

    def test_timestamp_parsed(self):
        line = '10.0.0.1 - - [17/Feb/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 100 "-" "test"'
        event = self.parser.parse_line(line)
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.year == 2026
        assert event.timestamp.month == 2
        assert event.timestamp.hour == 10

    def test_referer_and_ua(self):
        line = '10.0.0.1 - - [17/Feb/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 100 "http://referrer.com/page" "CustomBot/1.0"'
        event = self.parser.parse_line(line)
        assert event.fields["referer"] == "http://referrer.com/page"
        assert event.fields["user_agent"] == "CustomBot/1.0"

    def test_garbage_returns_none(self):
        assert self.parser.parse_line("not a log line") is None
        assert self.parser.parse_line("") is None

    def test_registered(self):
        assert "web_access" in ParserRegistry.available()
        parser = ParserRegistry.get("web_access")
        assert parser.name == "web_access"

    def test_event_type_in_fields(self):
        line = '10.0.0.1 - - [17/Feb/2026:10:15:30 +0000] "GET / HTTP/1.1" 200 100 "-" "test"'
        event = self.parser.parse_line(line)
        assert event.fields["event_type"] == "http_request"
