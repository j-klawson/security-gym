"""SYN scanning reconnaissance module using scapy."""

from __future__ import annotations

import logging
import random
import time
from datetime import datetime, timezone

from attacks.config import PhaseConfig
from attacks.modules.base import AttackModule, AttackModuleRegistry, AttackResult, TimingProfile


@AttackModuleRegistry.register("recon")
class ReconModule(AttackModule):
    """Network reconnaissance via SYN scanning with spoofed source IPs.

    Uses scapy to send raw SYN packets from random spoofed IPs.
    Requires root privileges for raw socket access.
    """

    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        from scapy.all import IP, TCP, conf, send  # type: ignore[attr-defined]

        # Suppress scapy verbosity
        conf.verb = 0

        ports = phase.params.get("ports", [22, 80, 443, 8080])
        scan_type = phase.params.get("scan_type", "syn")
        timing = TimingProfile(phase.timing)
        duration = phase.timing.duration_seconds

        start_time = datetime.now(timezone.utc)
        deadline = time.monotonic() + duration
        attempts = 0
        errors: list[str] = []

        logger.info(
            "Starting %s scan of %s ports %s from %d spoofed IPs (duration: %ds)",
            scan_type, target, ports, len(ips), duration,
        )

        while time.monotonic() < deadline:
            elapsed = time.monotonic() - (deadline - duration)
            progress = min(elapsed / duration, 1.0)

            src_ip = rng.choice(ips)
            port = rng.choice(ports)

            try:
                pkt = IP(src=src_ip, dst=target) / TCP(
                    sport=rng.randint(1024, 65535),
                    dport=port,
                    flags="S",
                )
                send(pkt, verbose=0)
                attempts += 1
            except Exception as e:
                errors.append(f"SYN to {target}:{port} from {src_ip}: {e}")
                if len(errors) > 100:
                    logger.warning("Too many errors, stopping scan early")
                    break

            # Apply timing profile delay
            delay_ms = timing.get_jitter_ms(progress, rng)
            time.sleep(delay_ms / 1000.0)

        end_time = datetime.now(timezone.utc)
        logger.info(
            "Recon complete: %d SYN packets sent, %d errors",
            attempts, len(errors),
        )

        return AttackResult(
            phase_name=phase.name,
            module_name=self.name,
            start_time=start_time,
            end_time=end_time,
            source_ips=ips,
            attempts=attempts,
            successes=0,
            errors=errors[:10],
            metadata={"scan_type": scan_type, "ports": ports},
        )
