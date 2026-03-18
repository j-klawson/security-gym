"""Tests for eBPF event encoding functions."""

import math

import numpy as np
import pytest

from security_gym.envs.ebpf_encoding import (
    FILE_COLS,
    NETWORK_COLS,
    PROCESS_COLS,
    SEED_COMM,
    SEED_IP,
    SEED_PATH,
    encode_flags,
    encode_syscall,
    extract_file_row,
    extract_network_row,
    extract_process_row,
    hash_string,
    log_delta,
    parse_ip_port,
)


class TestHashString:
    def test_deterministic(self):
        h1 = hash_string("test", seed=0)
        h2 = hash_string("test", seed=0)
        assert h1 == h2

    def test_per_field_seed_isolation(self):
        """Different seeds produce different hashes for same input."""
        h_comm = hash_string("wget", seed=SEED_COMM)
        h_ip = hash_string("wget", seed=SEED_IP)
        h_path = hash_string("wget", seed=SEED_PATH)
        # With different seeds, extremely unlikely to be equal
        assert h_comm != h_ip or h_comm != h_path

    def test_unsigned_output(self):
        h = hash_string("anything", seed=0)
        assert h >= 0.0

    def test_returns_float32(self):
        h = hash_string("test", seed=0)
        assert h.dtype == np.float32


class TestEncodeSyscall:
    def test_known_syscalls(self):
        assert encode_syscall("execve") == 1.0
        assert encode_syscall("connect") == 4.0
        assert encode_syscall("open") == 8.0
        assert encode_syscall("unlink") == 10.0

    def test_unknown_syscall(self):
        assert encode_syscall("unknown_call") == 0.0

    def test_none(self):
        assert encode_syscall(None) == 0.0


class TestParseIpPort:
    def test_valid_ip_port(self):
        ip_hash, port = parse_ip_port("93.184.216.34:80")
        assert ip_hash.dtype == np.float32
        assert ip_hash != 0.0
        assert port == 80.0

    def test_none_input(self):
        ip_hash, port = parse_ip_port(None)
        assert ip_hash == 0.0
        assert port == 0.0

    def test_empty_string(self):
        ip_hash, port = parse_ip_port("")
        assert ip_hash == 0.0
        assert port == 0.0

    def test_ip_only_no_port(self):
        ip_hash, port = parse_ip_port("10.0.0.1")
        # No colon → whole string is hashed, port=0
        assert ip_hash != 0.0
        assert port == 0.0


class TestEncodeFlags:
    def test_single_flag(self):
        assert encode_flags("O_WRONLY") == 1.0

    def test_combined_flags(self):
        result = encode_flags("O_WRONLY|O_CREAT")
        assert result == float(1 | 64)  # 65.0

    def test_none(self):
        assert encode_flags(None) == 0.0

    def test_empty(self):
        assert encode_flags("") == 0.0

    def test_unknown_flag(self):
        assert encode_flags("O_UNKNOWN") == 0.0


class TestLogDelta:
    def test_zero(self):
        assert log_delta(0.0) == 0.0

    def test_positive(self):
        assert log_delta(1.0) == pytest.approx(math.log(2.0))

    def test_large(self):
        # log(1 + 1000) ≈ 6.91
        assert log_delta(1000.0) == pytest.approx(math.log(1001.0))

    def test_negative_clamped(self):
        assert log_delta(-5.0) == 0.0


class TestExtractProcessRow:
    def test_shape(self):
        parsed = {
            "event_type": "execve",
            "pid": 1234,
            "ppid": 1200,
            "uid": 1000,
            "comm": "wget",
            "parent_comm": "apache2",
        }
        row = extract_process_row(parsed, ts_delta=0.5, depth=2)
        assert row.shape == (PROCESS_COLS,)
        assert row.dtype == np.float32

    def test_values(self):
        parsed = {
            "event_type": "execve",
            "pid": 100,
            "ppid": 50,
            "uid": 0,
            "comm": "bash",
            "parent_comm": "sshd",
        }
        row = extract_process_row(parsed, ts_delta=1.0, depth=3)
        assert row[0] == pytest.approx(math.log(2.0))  # log_delta
        assert row[1] == 100.0  # pid
        assert row[2] == 50.0   # ppid
        assert row[3] == 0.0    # uid
        assert row[4] == 1.0    # execve
        assert row[5] != 0.0    # comm_hash
        assert row[6] != 0.0    # parent_comm_hash
        assert row[7] == 3.0    # depth

    def test_missing_fields_default_zero(self):
        row = extract_process_row({}, ts_delta=0.0)
        np.testing.assert_array_equal(row, 0.0)


class TestExtractNetworkRow:
    def test_shape(self):
        parsed = {
            "event_type": "connect",
            "pid": 5678,
            "uid": 1000,
            "comm": "wget",
            "dst": "93.184.216.34:80",
        }
        row = extract_network_row(parsed, ts_delta=0.1)
        assert row.shape == (NETWORK_COLS,)
        assert row.dtype == np.float32

    def test_values(self):
        parsed = {
            "event_type": "connect",
            "pid": 5678,
            "uid": 1000,
            "comm": "wget",
            "dst": "93.184.216.34:80",
        }
        row = extract_network_row(parsed, ts_delta=0.1)
        assert row[1] == 5678.0
        assert row[2] == 1000.0
        assert row[3] == 4.0  # connect
        assert row[4] != 0.0  # ip_hash
        assert row[5] == 80.0  # port
        assert row[6] != 0.0  # comm_hash

    def test_missing_fields_default_zero(self):
        row = extract_network_row({}, ts_delta=0.0)
        np.testing.assert_array_equal(row, 0.0)


class TestExtractFileRow:
    def test_shape(self):
        parsed = {
            "event_type": "open",
            "pid": 1234,
            "uid": 0,
            "flags": "O_WRONLY|O_CREAT",
            "path": "/tmp/payload.sh",
        }
        row = extract_file_row(parsed, ts_delta=0.2)
        assert row.shape == (FILE_COLS,)
        assert row.dtype == np.float32

    def test_values(self):
        parsed = {
            "event_type": "open",
            "pid": 1234,
            "uid": 0,
            "flags": "O_WRONLY|O_CREAT",
            "path": "/tmp/payload.sh",
        }
        row = extract_file_row(parsed, ts_delta=0.2)
        assert row[1] == 1234.0
        assert row[2] == 0.0
        assert row[3] == 8.0  # open
        assert row[4] == 65.0  # O_WRONLY|O_CREAT
        assert row[5] != 0.0  # path_hash

    def test_missing_fields_default_zero(self):
        row = extract_file_row({}, ts_delta=0.0)
        np.testing.assert_array_equal(row, 0.0)
