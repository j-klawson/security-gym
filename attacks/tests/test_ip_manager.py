"""Tests for IP manager (spoofed generation only — aliasing requires root)."""

from __future__ import annotations

import random

import pytest

from attacks.config import IPSourceConfig
from attacks.network.ip_manager import IPManager


class TestSpoofedIPs:
    def test_generate_correct_count(self):
        mgr = IPManager()
        config = IPSourceConfig(strategy="spoofed", count=50, subnet="10.0.0.0/16")
        rng = random.Random(42)

        ips = mgr.allocate(config, rng)
        assert len(ips) == 50

    def test_ips_in_subnet(self):
        mgr = IPManager()
        config = IPSourceConfig(strategy="spoofed", count=10, subnet="192.168.1.0/24")
        rng = random.Random(42)

        ips = mgr.allocate(config, rng)
        for ip in ips:
            parts = ip.split(".")
            assert parts[0] == "192"
            assert parts[1] == "168"
            assert parts[2] == "1"
            assert 1 <= int(parts[3]) <= 254

    def test_unique_ips(self):
        mgr = IPManager()
        config = IPSourceConfig(strategy="spoofed", count=100, subnet="10.0.0.0/16")
        rng = random.Random(42)

        ips = mgr.allocate(config, rng)
        assert len(set(ips)) == 100

    def test_reproducible_with_seed(self):
        config = IPSourceConfig(strategy="spoofed", count=20, subnet="10.0.0.0/16")

        mgr1 = IPManager()
        ips1 = mgr1.allocate(config, random.Random(42))

        mgr2 = IPManager()
        ips2 = mgr2.allocate(config, random.Random(42))

        assert ips1 == ips2

    def test_different_seeds_different_ips(self):
        config = IPSourceConfig(strategy="spoofed", count=20, subnet="10.0.0.0/16")

        mgr1 = IPManager()
        ips1 = mgr1.allocate(config, random.Random(42))

        mgr2 = IPManager()
        ips2 = mgr2.allocate(config, random.Random(99))

        assert ips1 != ips2

    def test_subnet_too_small(self):
        mgr = IPManager()
        # /30 only has 2 usable hosts
        config = IPSourceConfig(strategy="spoofed", count=10, subnet="10.0.0.0/30")
        rng = random.Random(42)

        with pytest.raises(ValueError, match="hosts"):
            mgr.allocate(config, rng)

    def test_cleanup_spoofed_is_noop(self):
        """Spoofed IPs don't need cleanup (no OS state)."""
        mgr = IPManager()
        config = IPSourceConfig(strategy="spoofed", count=5, subnet="10.0.0.0/16")
        mgr.allocate(config, random.Random(42))

        # Should not raise
        mgr.cleanup_all()
        assert len(mgr.active_allocations) == 0


class TestTimingProfile:
    """Test the timing profile system for non-stationary attack cadence."""

    def test_constant_profile(self):
        from attacks.config import TimingConfig
        from attacks.modules.base import TimingProfile

        tc = TimingConfig(duration_seconds=60, profile="constant", jitter_ms=(100, 200))
        tp = TimingProfile(tc)
        rng = random.Random(42)

        # Should always return values in [100, 200]
        for progress in [0.0, 0.25, 0.5, 0.75, 1.0]:
            jitter = tp.get_jitter_ms(progress, rng)
            assert 100 <= jitter <= 200

    def test_accelerating_profile(self):
        from attacks.config import TimingConfig
        from attacks.modules.base import TimingProfile

        tc = TimingConfig(
            duration_seconds=600,
            profile="accelerating",
            profile_params={
                "phases": [
                    {"label": "slow", "fraction": 0.5, "jitter_ms": [2000, 5000]},
                    {"label": "fast", "fraction": 0.5, "jitter_ms": [50, 200]},
                ]
            },
        )
        tp = TimingProfile(tc)
        rng = random.Random(42)

        # Early progress → slow segment
        early_jitter = tp.get_jitter_ms(0.1, rng)
        assert 2000 <= early_jitter <= 5000

        # Late progress → fast segment
        late_jitter = tp.get_jitter_ms(0.9, rng)
        assert 50 <= late_jitter <= 200

    def test_segment_labels(self):
        from attacks.config import TimingConfig
        from attacks.modules.base import TimingProfile

        tc = TimingConfig(
            duration_seconds=600,
            profile="custom",
            profile_params={
                "phases": [
                    {"label": "cautious", "fraction": 0.3, "jitter_ms": [2000, 5000]},
                    {"label": "aggressive", "fraction": 0.5, "jitter_ms": [100, 500]},
                    {"label": "burst", "fraction": 0.2, "jitter_ms": [20, 100]},
                ]
            },
        )
        tp = TimingProfile(tc)

        assert tp.get_segment_label(0.1) == "cautious"
        assert tp.get_segment_label(0.5) == "aggressive"
        assert tp.get_segment_label(0.9) == "burst"

    def test_progress_clamping(self):
        from attacks.config import TimingConfig
        from attacks.modules.base import TimingProfile

        tc = TimingConfig(duration_seconds=60, profile="constant", jitter_ms=(100, 200))
        tp = TimingProfile(tc)
        rng = random.Random(42)

        # Out-of-range progress should be clamped
        jitter_neg = tp.get_jitter_ms(-0.5, rng)
        assert 100 <= jitter_neg <= 200

        jitter_over = tp.get_jitter_ms(1.5, rng)
        assert 100 <= jitter_over <= 200
