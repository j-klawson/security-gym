"""Tests for eBPF output format parsing."""

from datetime import timezone

from security_gym.parsers.registry import ParserRegistry
from security_gym.parsers.ebpf import EbpfParser
from tests.conftest import (
    SAMPLE_EBPF_PROCESS_LINES,
    SAMPLE_EBPF_NETWORK_LINES,
    SAMPLE_EBPF_FILE_LINES,
)


class TestEbpfParserRegistration:
    def test_registered(self):
        assert "ebpf" in ParserRegistry.available()

    def test_get_parser(self):
        parser = ParserRegistry.get("ebpf")
        assert isinstance(parser, EbpfParser)


class TestProcessEvents:
    def test_parse_execve(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_PROCESS_LINES[0])
        assert event is not None
        assert event.event_type == "execve"
        assert event.source == "ebpf_process"
        assert event.pid == 1234
        assert event.fields["ppid"] == 1200
        assert event.fields["uid"] == 1000
        assert event.fields["comm"] == "wget"
        assert event.fields["parent_comm"] == "apache2"
        assert event.timestamp.tzinfo is not None

    def test_parse_exit(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_PROCESS_LINES[1])
        assert event is not None
        assert event.event_type == "exit"
        assert event.source == "ebpf_process"
        assert event.pid == 1234
        assert event.fields["code"] == 0


class TestNetworkEvents:
    def test_parse_connect(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_NETWORK_LINES[0])
        assert event is not None
        assert event.event_type == "connect"
        assert event.source == "ebpf_network"
        assert event.pid == 1234
        assert event.fields["uid"] == 1000
        assert event.src_ip == "93.184.216.34"

    def test_parse_accept(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_NETWORK_LINES[1])
        assert event is not None
        assert event.event_type == "accept"
        assert event.source == "ebpf_network"
        assert event.pid == 5678
        assert event.fields["uid"] == 0


class TestFileEvents:
    def test_parse_open(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_FILE_LINES[0])
        assert event is not None
        assert event.event_type == "open"
        assert event.source == "ebpf_file"
        assert event.pid == 1234
        assert "payload.sh" in event.fields.get("path", "")

    def test_parse_unlink(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_FILE_LINES[1])
        assert event is not None
        assert event.event_type == "unlink"
        assert event.source == "ebpf_file"
        assert event.pid == 5678
        assert "payload.sh" in event.fields.get("path", "")


class TestEdgeCases:
    def test_empty_line(self):
        parser = EbpfParser()
        assert parser.parse_line("") is None

    def test_garbage_line(self):
        parser = EbpfParser()
        assert parser.parse_line("not a valid ebpf line at all") is None

    def test_partial_line(self):
        parser = EbpfParser()
        assert parser.parse_line("2026-02-17T10:00:00.000Z") is None

    def test_timestamp_timezone(self):
        parser = EbpfParser()
        event = parser.parse_line(SAMPLE_EBPF_PROCESS_LINES[0])
        assert event is not None
        assert event.timestamp.tzinfo == timezone.utc

    def test_raw_line_preserved(self):
        parser = EbpfParser()
        line = SAMPLE_EBPF_PROCESS_LINES[0]
        event = parser.parse_line(line)
        assert event is not None
        assert event.raw_line == line
