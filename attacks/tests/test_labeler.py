"""Tests for campaign labeling."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from attacks.collection.auditd import AuditEvent
from attacks.collection.labeler import CampaignLabeler
from attacks.config import IPSourceConfig, PhaseConfig, TimingConfig
from attacks.modules.base import AttackResult
from security_gym.parsers.base import ParsedEvent


def _make_result(
    phase_name: str = "Test Phase",
    module_name: str = "ssh_brute_force",
    start_offset_s: int = 0,
    duration_s: int = 60,
    ips: list[str] | None = None,
) -> AttackResult:
    base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    return AttackResult(
        phase_name=phase_name,
        module_name=module_name,
        start_time=base + timedelta(seconds=start_offset_s),
        end_time=base + timedelta(seconds=start_offset_s + duration_s),
        source_ips=ips or ["192.168.2.100", "192.168.2.101"],
        attempts=10,
        successes=0,
    )


def _make_phase(
    name: str = "Test Phase",
    attack_type: str = "brute_force",
    attack_stage: str = "initial_access",
    severity: int = 2,
) -> PhaseConfig:
    return PhaseConfig(
        name=name,
        module="ssh_brute_force",
        mitre_technique="T1110.001",
        mitre_tactic="TA0006",
        attack_type=attack_type,
        attack_stage=attack_stage,
        severity=severity,
        params={},
        ip_source=IPSourceConfig("aliased", 2, "192.168.2.0/24"),
        timing=TimingConfig(60),
    )


def _make_event(
    offset_s: int = 30,
    src_ip: str = "192.168.2.100",
    source: str = "auth_log",
) -> ParsedEvent:
    base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    return ParsedEvent(
        timestamp=base + timedelta(seconds=offset_s),
        source=source,
        raw_line="test log line",
        event_type="ssh_auth_failure",
        src_ip=src_ip,
    )


class TestCampaignLabeler:
    def test_malicious_event_in_window(self):
        result = _make_result()
        phase = _make_phase()
        labeler = CampaignLabeler("test_campaign", [result], [phase])

        event = _make_event(offset_s=30, src_ip="192.168.2.100")
        gt = labeler.label_event(event)

        assert gt["is_malicious"] == 1
        assert gt["campaign_id"] == "test_campaign"
        assert gt["attack_type"] == "brute_force"
        assert gt["attack_stage"] == "initial_access"
        assert gt["severity"] == 2

    def test_benign_event_wrong_ip(self):
        result = _make_result()
        phase = _make_phase()
        labeler = CampaignLabeler("test_campaign", [result], [phase])

        event = _make_event(offset_s=30, src_ip="10.0.0.1")
        gt = labeler.label_event(event)

        assert gt["is_malicious"] == 0
        assert gt["campaign_id"] == "test_campaign"
        assert gt["attack_type"] is None

    def test_benign_event_outside_window(self):
        result = _make_result()
        phase = _make_phase()
        labeler = CampaignLabeler("test_campaign", [result], [phase])

        event = _make_event(offset_s=120, src_ip="192.168.2.100")
        gt = labeler.label_event(event)

        assert gt["is_malicious"] == 0

    def test_event_no_src_ip_matches_on_time(self):
        """Events without src_ip match on time window alone."""
        result = _make_result()
        phase = _make_phase()
        labeler = CampaignLabeler("test_campaign", [result], [phase])

        event = _make_event(offset_s=30, src_ip="192.168.2.100")
        event.src_ip = None
        gt = labeler.label_event(event)

        assert gt["is_malicious"] == 1

    def test_multiple_phases(self):
        results = [
            _make_result("Phase1", "recon", 0, 60, ["10.0.0.1"]),
            _make_result("Phase2", "ssh_brute_force", 120, 60, ["192.168.2.100"]),
        ]
        phases = [
            _make_phase("Phase1", "discovery", "recon", 1),
            _make_phase("Phase2", "brute_force", "initial_access", 2),
        ]
        labeler = CampaignLabeler("test_campaign", results, phases)

        # Event in phase 1
        event1 = _make_event(offset_s=30, src_ip="10.0.0.1")
        gt1 = labeler.label_event(event1)
        assert gt1["is_malicious"] == 1
        assert gt1["attack_type"] == "discovery"

        # Event in phase 2
        event2 = _make_event(offset_s=150, src_ip="192.168.2.100")
        gt2 = labeler.label_event(event2)
        assert gt2["is_malicious"] == 1
        assert gt2["attack_type"] == "brute_force"

    def test_auditd_enrichment(self):
        result = _make_result()
        phase = _make_phase(severity=1)
        base = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

        auditd_event = AuditEvent(
            timestamp=base + timedelta(seconds=30),
            event_type="EXECVE",
            key="research_exploit",
        )
        labeler = CampaignLabeler("test_campaign", [result], [phase], [auditd_event])

        event = _make_event(offset_s=30, src_ip="192.168.2.100")
        gt = labeler.label_event(event)

        assert gt["is_malicious"] == 1
        assert gt["severity"] == 3  # Elevated from 1 to 3

    def test_label_all(self):
        result = _make_result()
        phase = _make_phase()
        labeler = CampaignLabeler("test_campaign", [result], [phase])

        events = [
            _make_event(30, "192.168.2.100"),  # malicious
            _make_event(30, "10.0.0.1"),        # benign
            _make_event(120, "192.168.2.100"),   # benign (outside window)
        ]
        gts = labeler.label_all(events)

        assert len(gts) == 3
        assert gts[0]["is_malicious"] == 1
        assert gts[1]["is_malicious"] == 0
        assert gts[2]["is_malicious"] == 0

    def test_stats(self):
        result = _make_result()
        phase = _make_phase()
        labeler = CampaignLabeler("test_campaign", [result], [phase])

        events = [
            _make_event(30, "192.168.2.100"),
            _make_event(30, "192.168.2.101"),
            _make_event(30, "10.0.0.1"),
        ]
        labeler.label_all(events)

        stats = labeler.stats
        assert stats["malicious"] == 2
        assert stats["benign"] == 1
