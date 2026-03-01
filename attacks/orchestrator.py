"""Campaign orchestrator: load YAML → execute phases → collect → label → store."""

from __future__ import annotations

import logging
import random
import time
import uuid
from pathlib import Path
from typing import Any

from attacks.collection.auditd import filter_exploit_events, parse_ausearch_output
from attacks.collection.collector import LogCollector
from attacks.collection.ebpf_collector import EbpfOrchestrator
from attacks.collection.labeler import CampaignLabeler
from attacks.config import CampaignConfig
from attacks.modules.base import AttackModuleRegistry, AttackResult
from attacks.network.ip_manager import IPManager

# Trigger module registration
import attacks.modules  # noqa: F401

from security_gym.data.event_store import EventStore

logger = logging.getLogger(__name__)


class CampaignOrchestrator:
    """Execute a full campaign: attack phases → collect logs → label → store."""

    def __init__(self, config: CampaignConfig) -> None:
        self.config = config
        self.rng = random.Random(config.seed)
        self.ip_manager = IPManager()
        self.campaign_id = f"campaign_{uuid.uuid4().hex[:12]}"
        self._results: list[AttackResult] = []
        self._ebpf: EbpfOrchestrator | None = None

    def run(self) -> str:
        """Execute the full campaign pipeline. Returns campaign_id."""
        logger.info("=" * 60)
        logger.info("Campaign: %s", self.config.name)
        logger.info("ID: %s", self.campaign_id)
        logger.info("Phases: %d", len(self.config.phases))
        logger.info("=" * 60)

        try:
            # Start eBPF collection if configured
            self._start_ebpf()

            # Phase 1: Execute attacks
            self._execute_phases()

            # Phase 2: Stop eBPF and collect kernel events
            ebpf_events = self._stop_ebpf()

            # Phase 3: Collect logs
            events = self._collect_logs()

            # Phase 4: Label events
            labeled = self._label_events(events)

            # Phase 5: Store in EventStore (logs + eBPF events)
            self._store(events, labeled, ebpf_events)

        finally:
            self.ip_manager.cleanup_all()
            if self._ebpf is not None:
                self._ebpf.close()

        logger.info("Campaign %s complete", self.campaign_id)
        return self.campaign_id

    def dry_run(self) -> dict[str, Any]:
        """Preview the campaign without executing."""
        plan: dict[str, Any] = {
            "campaign_id": self.campaign_id,
            "name": self.config.name,
            "target": self.config.target.host,
            "seed": self.config.seed,
            "phases": [],
        }

        for phase in self.config.phases:
            module = AttackModuleRegistry.get(phase.module)
            # Generate IPs for preview (no OS changes)
            ips = self.ip_manager.generate_ips(phase.ip_source, self.rng)
            phase_plan = module.dry_run(phase, ips)
            phase_plan["ips_sample"] = ips[:5]
            phase_plan["mitre"] = f"{phase.mitre_tactic}/{phase.mitre_technique}"
            plan["phases"].append(phase_plan)

        return plan

    def collect_only(self) -> str:
        """Re-collect and re-label from a previous campaign run.

        Useful if log collection failed but attacks completed.
        Uses the full time range and all phase IPs for labeling.
        """
        if not self._results:
            raise RuntimeError("No attack results — run the campaign first or load results")

        events = self._collect_logs()
        labeled = self._label_events(events)
        self._store(events, labeled)
        return self.campaign_id

    # ── eBPF ──────────────────────────────────────────────────────────

    def _start_ebpf(self) -> None:
        """Start eBPF collector on target if configured."""
        if not self.config.collection.ebpf.enabled:
            return

        self._ebpf = EbpfOrchestrator(
            host=self.config.target.host,
            ssh_user=self.config.target.ssh_user,
            ssh_key=self.config.target.ssh_key,
            ssh_port=self.config.target.ssh_port,
        )
        self._ebpf.start()
        logger.info("eBPF collector started on %s", self.config.target.host)

        # Baseline collection period
        baseline = self.config.collection.ebpf.baseline_seconds
        if baseline > 0:
            logger.info("Collecting %ds baseline eBPF data...", baseline)
            time.sleep(baseline)

    def _stop_ebpf(self) -> list:
        """Stop eBPF collector and return parsed events."""
        if self._ebpf is None:
            return []

        # Post-attack baseline collection
        baseline = self.config.collection.ebpf.baseline_seconds
        if baseline > 0:
            logger.info("Collecting %ds post-attack eBPF baseline...", baseline)
            time.sleep(baseline)

        self._ebpf.stop()
        parsed_events = self._ebpf.get_parsed_events()
        logger.info("Collected %d eBPF kernel events", len(parsed_events))
        return parsed_events

    # ── Internal ───────────────────────────────────────────────────────

    def _execute_phases(self) -> None:
        """Execute all attack phases sequentially."""
        for i, phase in enumerate(self.config.phases):
            logger.info("")
            logger.info("─── Phase %d/%d: %s ───", i + 1, len(self.config.phases), phase.name)
            logger.info("Module: %s | MITRE: %s/%s", phase.module, phase.mitre_tactic, phase.mitre_technique)

            # Allocate IPs
            ips = self.ip_manager.allocate(phase.ip_source, self.rng)
            logger.info("IPs: %d (%s strategy)", len(ips), phase.ip_source.strategy)

            # Get module and execute
            module = AttackModuleRegistry.get(phase.module)
            result = module.execute(
                target=self.config.target.host,
                phase=phase,
                ips=ips,
                rng=self.rng,
                logger=logger,
            )
            self._results.append(result)

            logger.info(
                "Phase complete: %d attempts, %d successes",
                result.attempts, result.successes,
            )

            # Clean up aliased IPs for this phase
            if phase.ip_source.strategy == "aliased":
                for alloc in self.ip_manager.active_allocations:
                    if alloc.ips == ips:
                        self.ip_manager.cleanup_allocation(alloc)
                        break

            # Inter-phase delay
            if phase.timing.delay_after_seconds > 0 and i < len(self.config.phases) - 1:
                logger.info("Waiting %ds before next phase...", phase.timing.delay_after_seconds)
                time.sleep(phase.timing.delay_after_seconds)

    def _collect_logs(self) -> list[Any]:
        """Collect logs from target VM."""
        if not self._results:
            raise RuntimeError("No attack results to determine collection window")

        campaign_start = min(r.start_time for r in self._results)
        campaign_end = max(r.end_time for r in self._results)

        logger.info("")
        logger.info("─── Collecting Logs ───")
        logger.info("Window: %s → %s", campaign_start.isoformat(), campaign_end.isoformat())

        with LogCollector(
            target=self.config.target,
            collection=self.config.collection,
            campaign_start=campaign_start,
            campaign_end=campaign_end,
        ) as collector:
            events: list[Any] = collector.collect_all()

        return events

    def _label_events(self, events: list) -> list[dict[str, Any]]:
        """Label collected events with ground truth."""
        logger.info("")
        logger.info("─── Labeling Events ───")

        # Try to get auditd events
        auditd_events = []
        for source in self.config.collection.log_sources:
            if source.name == "auditd" and hasattr(self, "_auditd_raw"):
                parsed = parse_ausearch_output(self._auditd_raw)
                auditd_events = filter_exploit_events(parsed)
                logger.info("Found %d confirmed exploit events via auditd", len(auditd_events))

        labeler = CampaignLabeler(
            campaign_id=self.campaign_id,
            attack_results=self._results,
            phase_configs=self.config.phases,
            auditd_events=auditd_events,
        )

        ground_truths = labeler.label_all(events)
        stats = labeler.stats
        logger.info(
            "Labeled: %d malicious, %d benign, %d auditd-enriched",
            stats["malicious"], stats["benign"], stats["auditd_enriched"],
        )

        return ground_truths

    def _store(
        self,
        events: list,
        ground_truths: list[dict[str, Any]],
        ebpf_events: list | None = None,
    ) -> None:
        """Store events, eBPF events, and campaign metadata in EventStore."""
        db_path = Path(self.config.collection.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("")
        logger.info("─── Storing to %s ───", db_path)

        with EventStore(db_path, mode="a") as store:
            # Insert campaign record
            mitre_tactics = ", ".join(
                f"{p.mitre_tactic}/{p.mitre_technique}" for p in self.config.phases
            )
            store.insert_campaign({
                "id": self.campaign_id,
                "name": self.config.name,
                "start_time": min(r.start_time for r in self._results).isoformat(),
                "end_time": max(r.end_time for r in self._results).isoformat(),
                "attack_type": ", ".join(p.attack_type for p in self.config.phases),
                "mitre_tactics": mitre_tactics,
                "description": self.config.description,
                "parameters": {
                    "seed": self.config.seed,
                    "phases": [
                        {
                            "name": r.phase_name,
                            "module": r.module_name,
                            "attempts": r.attempts,
                            "successes": r.successes,
                            "ip_count": len(r.source_ips),
                        }
                        for r in self._results
                    ],
                },
            })

            # Bulk insert log events with ground truth
            count = store.bulk_insert(events, ground_truths)

            # Insert eBPF kernel events (labeled via CampaignLabeler)
            if ebpf_events:
                ebpf_labeler = CampaignLabeler(
                    campaign_id=self.campaign_id,
                    attack_results=self._results,
                    phase_configs=self.config.phases,
                )
                ebpf_gts = ebpf_labeler.label_all(ebpf_events)
                ebpf_count = store.bulk_insert(ebpf_events, ebpf_gts)
                ebpf_stats = ebpf_labeler.stats
                logger.info(
                    "Stored %d eBPF events (%d malicious, %d benign)",
                    ebpf_count, ebpf_stats["malicious"], ebpf_stats["benign"],
                )
                count += ebpf_count

        logger.info("Stored %d total events + campaign record", count)
