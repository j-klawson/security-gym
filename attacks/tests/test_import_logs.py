"""Tests for benign log import tool."""

from __future__ import annotations

import gzip
import tarfile
from pathlib import Path

import pytest

from attacks.collection.import_logs import (
    BATCH_SIZE,
    BenignLogImporter,
    _is_gz,
    _parse_file,
    _route_file,
)


class TestFileRouting:
    def test_auth_log(self):
        assert _route_file("auth.log") == "auth_log"

    def test_auth_log_rotated(self):
        assert _route_file("auth.log.1") == "auth_log"

    def test_syslog(self):
        assert _route_file("syslog") == "syslog"

    def test_syslog_rotated(self):
        assert _route_file("syslog.3") == "syslog"

    def test_nginx_access(self):
        assert _route_file("nginx/access.log") == "web_access"

    def test_nginx_access_rotated(self):
        assert _route_file("nginx/access.log.1") == "web_access"

    def test_nginx_error(self):
        assert _route_file("nginx/error.log") == "web_error"

    def test_apache_access(self):
        assert _route_file("apache2/access.log") == "web_access"

    def test_apache_error(self):
        assert _route_file("apache2/error.log") == "web_error"

    def test_skip_btmp(self):
        assert _route_file("btmp") is None

    def test_skip_wtmp(self):
        assert _route_file("wtmp") is None

    def test_skip_lastlog(self):
        assert _route_file("lastlog") is None

    def test_skip_faillog(self):
        assert _route_file("faillog") is None

    def test_skip_journal_dir(self):
        assert _route_file("journal/system.journal") is None

    def test_skip_journal_nested(self):
        assert _route_file("log/journal/abc123/system.journal") is None

    def test_skip_unknown(self):
        assert _route_file("kern.log") is None

    def test_nested_path(self):
        assert _route_file("var/log/auth.log") == "auth_log"

    def test_apache_vhost_access(self):
        assert _route_file("apache2/deb12test.lhsc.on.ca_access.log") == "web_access"

    def test_apache_vhost_access_rotated(self):
        assert _route_file("apache2/deb12test.lhsc.on.ca_access.log.1") == "web_access"

    def test_apache_vhost_access_gz(self):
        assert _route_file("apache2/mysite.com_access.log.2.gz") == "web_access"

    def test_apache_vhost_error(self):
        assert _route_file("apache2/deb12test.lhsc.on.ca_error.log") == "web_error"

    def test_apache_vhost_error_rotated(self):
        assert _route_file("apache2/mysite.com_error.log.3.gz") == "web_error"

    def test_apache_vhost_nested(self):
        assert _route_file("var/log/apache2/site_access.log") == "web_access"

    def test_gz_still_routes(self):
        """GZ files route to a parser (caller handles decompression)."""
        assert _route_file("auth.log.1.gz") == "auth_log"
        assert _route_file("syslog.2.gz") == "syslog"


class TestIsGz:
    def test_gz(self):
        assert _is_gz(Path("auth.log.1.gz")) is True

    def test_not_gz(self):
        assert _is_gz(Path("auth.log")) is False

    def test_log_extension(self):
        assert _is_gz(Path("syslog.3")) is False


class TestParseFile:
    def test_parses_auth_log_lines(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
            "Feb 17 10:15:31 testhost sshd[1234]: pam_unix(sshd:session): "
            "session opened for user alice(uid=1000) by (uid=0)\n"
        )
        events = _parse_file(log, "auth_log", None)
        assert len(events) >= 1
        assert events[0].source == "auth_log"

    def test_source_host_injected(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )
        events = _parse_file(log, "auth_log", "hopper")
        assert len(events) >= 1
        assert events[0].fields["source_host"] == "hopper"

    def test_source_host_not_injected_when_none(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text(
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )
        events = _parse_file(log, "auth_log", None)
        assert len(events) >= 1
        assert "source_host" not in events[0].fields

    def test_gz_file(self, tmp_path):
        log = tmp_path / "auth.log.1.gz"
        content = (
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )
        with gzip.open(log, "wt") as f:
            f.write(content)

        events = _parse_file(log, "auth_log", None)
        assert len(events) >= 1

    def test_empty_file(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("")
        events = _parse_file(log, "auth_log", None)
        assert events == []

    def test_unparseable_lines_skipped(self, tmp_path):
        log = tmp_path / "auth.log"
        log.write_text("this is not a valid log line\nanother bad line\n")
        events = _parse_file(log, "auth_log", None)
        assert events == []


class TestBenignLogImporter:
    def test_import_directory(self, tmp_path):
        # Create a fake log directory
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        auth = log_dir / "auth.log"
        auth.write_text(
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path, source_host="test")
        total = importer.import_path(log_dir)

        assert total >= 1
        assert importer.files_processed == 1
        assert "auth_log" in importer.events_by_source

        # Verify DB contents
        from security_gym.data.event_store import EventStore

        with EventStore(str(db_path), mode="r") as store:
            assert store.count_events() == total
            events = store.get_events(start_id=0, limit=10)
            assert events[0]["is_malicious"] == 0

    def test_import_tarball(self, tmp_path):
        # Create a log directory and tar it
        log_dir = tmp_path / "var" / "log"
        log_dir.mkdir(parents=True)
        auth = log_dir / "auth.log"
        auth.write_text(
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )

        tar_path = tmp_path / "logs.tar"
        with tarfile.open(tar_path, "w") as tf:
            tf.add(log_dir, arcname="var/log")

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        total = importer.import_path(tar_path)

        assert total >= 1

    def test_import_tar_gz(self, tmp_path):
        log_dir = tmp_path / "var" / "log"
        log_dir.mkdir(parents=True)
        auth = log_dir / "auth.log"
        auth.write_text(
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )

        tar_path = tmp_path / "logs.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(log_dir, arcname="var/log")

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        total = importer.import_path(tar_path)

        assert total >= 1

    def test_skips_binary_files(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        (log_dir / "btmp").write_bytes(b"\x00\x01\x02")
        (log_dir / "wtmp").write_bytes(b"\x00\x01\x02")

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        total = importer.import_path(log_dir)

        assert total == 0
        assert importer.files_skipped == 2
        assert importer.files_processed == 0

    def test_gz_log_files(self, tmp_path):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        content = (
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )
        gz_path = log_dir / "auth.log.1.gz"
        with gzip.open(gz_path, "wt") as f:
            f.write(content)

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        total = importer.import_path(gz_path.parent)

        assert total >= 1

    def test_path_not_found(self, tmp_path):
        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        with pytest.raises(FileNotFoundError):
            importer.import_path(tmp_path / "nonexistent")

    def test_invalid_file(self, tmp_path):
        bad_file = tmp_path / "not_a_tar.txt"
        bad_file.write_text("hello")

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        with pytest.raises(ValueError, match="tarball"):
            importer.import_path(bad_file)

    def test_batch_flushing(self, tmp_path):
        """Verify batching works with more events than BATCH_SIZE."""
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        # Generate enough lines to exceed one batch
        line = (
            "Feb 17 10:15:30 testhost sshd[1234]: Accepted password "
            "for alice from 192.168.1.10 port 54321 ssh2\n"
        )
        auth = log_dir / "auth.log"
        auth.write_text(line * (BATCH_SIZE + 100))

        db_path = tmp_path / "test.db"
        importer = BenignLogImporter(db_path)
        total = importer.import_path(log_dir)

        # Parser may not parse every duplicate line, but we should get many
        assert total > 0

        from security_gym.data.event_store import EventStore

        with EventStore(str(db_path), mode="r") as store:
            assert store.count_events() == total
