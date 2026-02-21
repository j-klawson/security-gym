"""Tests for campaign config loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from attacks.config import (
    CampaignConfig,
    IPSourceConfig,
    LogSourceConfig,
    PhaseConfig,
    TimingConfig,
    TimingSegment,
    load_campaign,
    validate_campaign,
)

CAMPAIGNS_DIR = Path(__file__).parent.parent / "campaigns"


# ── TimingSegment ──────────────────────────────────────────────────────

class TestTimingSegment:
    def test_valid_segment(self):
        seg = TimingSegment("test", 0.5, (100, 500))
        assert seg.label == "test"
        assert seg.fraction == 0.5
        assert seg.jitter_ms == (100, 500)

    def test_invalid_fraction_zero(self):
        with pytest.raises(ValueError, match="fraction"):
            TimingSegment("bad", 0.0, (100, 500))

    def test_invalid_fraction_negative(self):
        with pytest.raises(ValueError, match="fraction"):
            TimingSegment("bad", -0.1, (100, 500))

    def test_invalid_jitter_inverted(self):
        with pytest.raises(ValueError, match="jitter_ms"):
            TimingSegment("bad", 0.5, (500, 100))

    def test_invalid_jitter_negative(self):
        with pytest.raises(ValueError, match="jitter_ms"):
            TimingSegment("bad", 0.5, (-1, 100))


# ── TimingConfig ───────────────────────────────────────────────────────

class TestTimingConfig:
    def test_constant_default_jitter(self):
        tc = TimingConfig(duration_seconds=60, profile="constant")
        assert tc.jitter_ms == (100, 500)
        assert len(tc.segments) == 1
        assert tc.segments[0].label == "constant"

    def test_constant_explicit_jitter(self):
        tc = TimingConfig(duration_seconds=60, profile="constant", jitter_ms=(50, 200))
        assert tc.jitter_ms == (50, 200)

    def test_accelerating_default_segments(self):
        tc = TimingConfig(duration_seconds=600, profile="accelerating")
        assert len(tc.segments) == 3
        assert tc.segments[0].label == "slow"
        assert tc.segments[-1].label == "fast"

    def test_decelerating_default_segments(self):
        tc = TimingConfig(duration_seconds=600, profile="decelerating")
        assert len(tc.segments) == 3
        assert tc.segments[0].label == "fast"
        assert tc.segments[-1].label == "slow"

    def test_custom_segments(self):
        tc = TimingConfig(
            duration_seconds=600,
            profile="custom",
            profile_params={
                "phases": [
                    {"label": "a", "fraction": 0.5, "jitter_ms": [100, 200]},
                    {"label": "b", "fraction": 0.5, "jitter_ms": [300, 400]},
                ]
            },
        )
        assert len(tc.segments) == 2
        assert tc.segments[0].label == "a"

    def test_custom_fractions_must_sum_to_one(self):
        with pytest.raises(ValueError, match="sum to 1.0"):
            TimingConfig(
                duration_seconds=600,
                profile="custom",
                profile_params={
                    "phases": [
                        {"label": "a", "fraction": 0.3, "jitter_ms": [100, 200]},
                        {"label": "b", "fraction": 0.3, "jitter_ms": [300, 400]},
                    ]
                },
            )

    def test_invalid_profile_name(self):
        with pytest.raises(ValueError, match="Unknown timing profile"):
            TimingConfig(duration_seconds=60, profile="invalid")


# ── IPSourceConfig ─────────────────────────────────────────────────────

class TestIPSourceConfig:
    def test_valid_spoofed(self):
        ip = IPSourceConfig(strategy="spoofed", count=100, subnet="10.0.0.0/8")
        assert ip.strategy == "spoofed"

    def test_valid_aliased(self):
        ip = IPSourceConfig(
            strategy="aliased", count=10, subnet="192.168.2.0/24",
            start_offset=100, interface="en0",
        )
        assert ip.interface == "en0"

    def test_invalid_strategy(self):
        with pytest.raises(ValueError, match="Unknown IP strategy"):
            IPSourceConfig(strategy="magic", count=10, subnet="10.0.0.0/8")

    def test_invalid_count(self):
        with pytest.raises(ValueError, match="count"):
            IPSourceConfig(strategy="spoofed", count=0, subnet="10.0.0.0/8")


# ── PhaseConfig ────────────────────────────────────────────────────────

class TestPhaseConfig:
    def _make_phase(self, **overrides):
        defaults = {
            "name": "Test Phase",
            "module": "ssh_brute_force",
            "mitre_technique": "T1110.001",
            "mitre_tactic": "TA0006",
            "attack_type": "brute_force",
            "attack_stage": "initial_access",
            "severity": 2,
            "params": {},
            "ip_source": IPSourceConfig("aliased", 10, "192.168.2.0/24"),
            "timing": TimingConfig(60),
        }
        defaults.update(overrides)
        return PhaseConfig(**defaults)

    def test_valid_phase(self):
        phase = self._make_phase()
        assert phase.name == "Test Phase"

    def test_invalid_attack_type(self):
        with pytest.raises(ValueError, match="Unknown attack_type"):
            self._make_phase(attack_type="unknown")

    def test_invalid_attack_stage(self):
        with pytest.raises(ValueError, match="Unknown attack_stage"):
            self._make_phase(attack_stage="unknown")

    def test_invalid_severity(self):
        with pytest.raises(ValueError, match="Severity"):
            self._make_phase(severity=5)


# ── LogSourceConfig ────────────────────────────────────────────────────

class TestLogSourceConfig:
    def test_valid_file(self):
        ls = LogSourceConfig("auth_log", parser="auth_log", remote_path="/var/log/auth.log")
        assert ls.remote_path is not None

    def test_valid_command(self):
        ls = LogSourceConfig("journal", parser="journal", remote_command="journalctl -o json")
        assert ls.remote_command is not None

    def test_invalid_no_source(self):
        with pytest.raises(ValueError, match="need remote_path or remote_command"):
            LogSourceConfig("bad")


# ── YAML Loading ───────────────────────────────────────────────────────

class TestLoadCampaign:
    def test_load_ssh_brute_only(self):
        config = load_campaign(CAMPAIGNS_DIR / "ssh_brute_only.yaml")
        assert isinstance(config, CampaignConfig)
        assert config.name == "SSH Brute Force Only"
        assert len(config.phases) == 1
        assert config.phases[0].module == "ssh_brute_force"
        assert config.seed == 42

    def test_load_full_campaign(self):
        config = load_campaign(CAMPAIGNS_DIR / "recon_ssh_log4shell.yaml")
        assert len(config.phases) == 3
        assert config.phases[0].module == "recon"
        assert config.phases[1].module == "ssh_brute_force"
        assert config.phases[2].module == "log4shell"

    def test_full_campaign_timing_profiles(self):
        config = load_campaign(CAMPAIGNS_DIR / "recon_ssh_log4shell.yaml")
        # Phase 0: constant
        assert config.phases[0].timing.profile == "constant"
        # Phase 1: accelerating with custom segments
        assert config.phases[1].timing.profile == "accelerating"
        assert len(config.phases[1].timing.segments) == 3
        assert config.phases[1].timing.segments[0].label == "cautious"
        # Phase 2: decelerating with custom segments
        assert config.phases[2].timing.profile == "decelerating"
        assert config.phases[2].timing.segments[0].label == "spray"

    def test_full_campaign_ip_strategies(self):
        config = load_campaign(CAMPAIGNS_DIR / "recon_ssh_log4shell.yaml")
        assert config.phases[0].ip_source.strategy == "spoofed"
        assert config.phases[0].ip_source.count == 500
        assert config.phases[1].ip_source.strategy == "aliased"
        assert config.phases[2].ip_source.strategy == "aliased"

    def test_full_campaign_collection(self):
        config = load_campaign(CAMPAIGNS_DIR / "recon_ssh_log4shell.yaml")
        assert len(config.collection.log_sources) == 6
        source_names = [s.name for s in config.collection.log_sources]
        assert "auth_log" in source_names
        assert "auditd" in source_names


# ── Validation ─────────────────────────────────────────────────────────

class TestValidateCampaign:
    def test_valid_campaign(self):
        errors = validate_campaign(CAMPAIGNS_DIR / "ssh_brute_only.yaml")
        assert errors == []

    def test_valid_full_campaign(self):
        errors = validate_campaign(CAMPAIGNS_DIR / "recon_ssh_log4shell.yaml")
        assert errors == []
