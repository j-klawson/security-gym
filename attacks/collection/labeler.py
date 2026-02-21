"""Ground truth labeling: match events to campaign phases via time + IP."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from attacks.collection.auditd import AuditEvent
from attacks.modules.base import AttackResult
from security_gym.parsers.base import ParsedEvent

logger = logging.getLogger(__name__)


@dataclass
class PhaseWindow:
    """Time window and IP set for a single attack phase."""

    phase_name: str
    module_name: str
    start_time: datetime
    end_time: datetime
    source_ips: set[str]
    attack_type: str
    attack_stage: str
    severity: int
    mitre_technique: str
    mitre_tactic: str


class CampaignLabeler:
    """Label parsed events as malicious/benign using campaign metadata.

    Labeling strategy:
    - Event is malicious if its timestamp falls within a phase window
      AND its src_ip is in that phase's IP set.
    - Isildur is isolated (no real traffic), so non-attack events are
      known-benign by construction.
    - auditd events provide additional enrichment for confirmed exploits.
    """

    def __init__(
        self,
        campaign_id: str,
        attack_results: list[AttackResult],
        phase_configs: list[Any],  # PhaseConfig list
        auditd_events: list[AuditEvent] | None = None,
    ) -> None:
        self.campaign_id = campaign_id
        self._windows = self._build_windows(attack_results, phase_configs)
        self._auditd_times = self._index_auditd(auditd_events or [])
        self._stats = {"malicious": 0, "benign": 0, "auditd_enriched": 0}

    def _build_windows(
        self,
        results: list[AttackResult],
        configs: list[Any],
    ) -> list[PhaseWindow]:
        """Build phase windows from attack results and configs."""
        windows = []
        for result, config in zip(results, configs):
            windows.append(PhaseWindow(
                phase_name=result.phase_name,
                module_name=result.module_name,
                start_time=result.start_time,
                end_time=result.end_time,
                source_ips=set(result.source_ips),
                attack_type=config.attack_type,
                attack_stage=config.attack_stage,
                severity=config.severity,
                mitre_technique=config.mitre_technique,
                mitre_tactic=config.mitre_tactic,
            ))
        return windows

    def _index_auditd(self, events: list[AuditEvent]) -> set[str]:
        """Create a set of ISO timestamps from auditd events for fast lookup."""
        return {e.timestamp.isoformat() for e in events}

    def label_event(self, event: ParsedEvent) -> dict[str, Any]:
        """Label a single event. Returns ground truth dict for EventStore.

        Returns:
            dict with keys: is_malicious, campaign_id, attack_type,
            attack_stage, severity. Always includes campaign_id.
        """
        for window in self._windows:
            if self._event_matches_window(event, window):
                self._stats["malicious"] += 1

                gt = {
                    "is_malicious": 1,
                    "campaign_id": self.campaign_id,
                    "attack_type": window.attack_type,
                    "attack_stage": window.attack_stage,
                    "severity": window.severity,
                }

                # Enrich with auditd confirmation
                ts_iso = event.timestamp.isoformat()
                if ts_iso in self._auditd_times:
                    severity: int = gt["severity"]  # type: ignore[assignment]
                    gt["severity"] = max(severity, 3)
                    self._stats["auditd_enriched"] += 1

                return gt

        # Benign event (no matching phase)
        self._stats["benign"] += 1
        return {
            "is_malicious": 0,
            "campaign_id": self.campaign_id,
            "attack_type": None,
            "attack_stage": None,
            "severity": None,
        }

    def _event_matches_window(self, event: ParsedEvent, window: PhaseWindow) -> bool:
        """Check if event falls within a phase's time window and IP set."""
        # Time check
        if not (window.start_time <= event.timestamp <= window.end_time):
            return False
        # IP check — if event has no src_ip, match on time window alone
        if event.src_ip is not None:
            return event.src_ip in window.source_ips
        return True

    def label_all(self, events: list[ParsedEvent]) -> list[dict[str, Any]]:
        """Label a batch of events."""
        return [self.label_event(e) for e in events]

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)
