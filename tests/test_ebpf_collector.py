"""Tests for the eBPF collector's pure formatting helpers.

The collector daemon itself needs BCC and root, neither of which is available
off a collection host, so only the byte-order and flag-decoding helpers are
exercised here. They are importable because the BCC import failure is reported
by ``main()`` rather than raised at import time.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))

from ebpf_collector import _ip_str  # noqa: E402


def _as_daddr(dotted: str) -> int:
    """The u32 the collector receives for ``dotted``.

    ``bpf_probe_read_user`` copies the four on-the-wire (network-order) bytes of
    ``sin_addr`` into a u32 and BCC decodes that field natively, so the value
    arriving in Python is those bytes read in host order.
    """
    return struct.unpack("=I", bytes(int(o) for o in dotted.split(".")))[0]


class TestIpStr:
    @pytest.mark.parametrize("dotted", [
        "192.168.2.20",
        "172.18.0.3",     # Log4Shell container; shipped as 3.0.18.172
        "203.0.113.9",
        "10.0.0.5",
        "255.254.253.252",
    ])
    def test_roundtrips_non_palindromic_addresses(self, dotted):
        """Regression guard for the 2026-08-28 byte-order fix.

        These addresses are not invariant under octet reversal, so a reversed
        implementation fails here. The pre-fix code emitted 3.0.18.172 for the
        Log4Shell container at 172.18.0.3.
        """
        assert _ip_str(_as_daddr(dotted)) == dotted

    @pytest.mark.parametrize("dotted", ["0.0.0.0", "8.8.8.8", "1.2.2.1"])
    def test_palindromic_addresses_are_no_guard(self, dotted):
        """Invariant under reversal, so they passed before the fix too.

        Kept to document why the shipped data looked partly correct: 0.0.0.0 and
        8.8.8.8 masked the defect in every spot check.
        """
        assert _ip_str(_as_daddr(dotted)) == dotted
        assert ".".join(reversed(dotted.split("."))) == dotted

    def test_matches_inet_ntoa(self):
        import socket
        for dotted in ("192.168.2.113", "172.18.0.3", "8.8.4.4"):
            addr = _as_daddr(dotted)
            assert _ip_str(addr) == socket.inet_ntoa(struct.pack("=I", addr))
