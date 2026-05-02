"""Tests for SecurityLogStreamHybridEnv: hybrid text + structured observations."""

import numpy as np
import pytest
import gymnasium as gym

from security_gym.envs.log_stream_env import (
    SecurityLogStreamEnv,
    ACTION_PASS,
    ACTION_BLOCK_SOURCE,
    ACTION_THROTTLE,
    ACTION_ISOLATE,
)
from security_gym.envs.log_stream_env_hybrid import (
    SecurityLogStreamHybridEnv,
    _STRUCTURED_CHANNELS,
    _TEXT_CHANNELS,
)
from security_gym.envs.ebpf_encoding import FILE_COLS, NETWORK_COLS, PROCESS_COLS


def _make_action(action: int = ACTION_PASS, risk_score: float = 0.0) -> dict:
    """Helper to create a valid action dict."""
    return {
        "action": action,
        "risk_score": np.array([risk_score], dtype=np.float32),
    }


class TestResetObservation:
    def test_reset_returns_hybrid_obs(self, tmp_db_with_ebpf):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf))
        obs, info = env.reset()

        # Text channels are strings
        for ch in _TEXT_CHANNELS:
            assert isinstance(obs[ch], str), f"{ch} should be str"

        # eBPF channels are ndarrays
        for ch in _STRUCTURED_CHANNELS:
            assert isinstance(obs[ch], np.ndarray), f"{ch} should be ndarray"

        assert "system_stats" in obs
        assert obs["system_stats"].shape == (3,)
        env.close()

    def test_ebpf_channels_shape(self, tmp_db_with_ebpf):
        tail = 20
        env = SecurityLogStreamHybridEnv(
            db_path=str(tmp_db_with_ebpf), tail_events=tail,
        )
        obs, _ = env.reset()
        assert obs["process_events"].shape == (tail, PROCESS_COLS)
        assert obs["network_events"].shape == (tail, NETWORK_COLS)
        assert obs["file_events"].shape == (tail, FILE_COLS)
        env.close()

    def test_text_channels_unchanged(self, tmp_db_with_ebpf):
        """Text channels still work as plain strings."""
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf))
        obs, _ = env.reset()
        # First event is auth_log, so auth_log should have content
        assert len(obs["auth_log"]) > 0
        env.close()


class TestStepObservation:
    def test_ebpf_events_populate_arrays(self, tmp_db_with_ebpf):
        """After stepping through eBPF events, structured channels have data."""
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf))
        env.reset()

        # Step through all events, keeping last non-truncated obs
        last_obs = None
        for _ in range(25):
            obs, _, _, truncated, _ = env.step(_make_action())
            if truncated:
                break
            last_obs = obs

        assert last_obs is not None, "No non-truncated observations"

        # At least one structured channel should have non-zero rows
        has_data = False
        for ch in _STRUCTURED_CHANNELS:
            if np.any(last_obs[ch] != 0):
                has_data = True
                break
        assert has_data, "No eBPF data found in structured channels after stepping"
        env.close()

    def test_timestamp_deltas(self, tmp_db_with_ebpf):
        """Verify delta computation produces non-zero values after first event."""
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf))
        env.reset()

        # Step through all events, keeping last non-truncated obs
        last_obs = None
        for _ in range(25):
            obs, _, _, truncated, _ = env.step(_make_action())
            if truncated:
                break
            last_obs = obs

        assert last_obs is not None

        # Process events has 2 events in fixture; second should have non-zero delta
        proc = last_obs["process_events"]
        non_zero_rows = proc[proc[:, 0] > 0]  # log_delta > 0
        # With 2 process events, at least the second has dt > 0
        assert len(non_zero_rows) >= 1, "Expected non-zero timestamp deltas"
        env.close()


class TestEmptyDB:
    def test_empty_db_zeros(self, empty_db):
        env = SecurityLogStreamHybridEnv(db_path=str(empty_db))
        obs, info = env.reset()
        for ch in _TEXT_CHANNELS:
            assert obs[ch] == ""
        for ch, n_cols in _STRUCTURED_CHANNELS.items():
            np.testing.assert_array_equal(
                obs[ch], np.zeros((env.tail_events, n_cols)),
            )
        env.close()


class TestTextModeUnaffected:
    def test_text_mode_still_works(self, tmp_db_with_ebpf):
        """Text-mode env is unaffected by Hybrid-mode logic."""
        env = SecurityLogStreamEnv(db_path=tmp_db_with_ebpf)
        obs, info = env.reset()
        # Text mode returns strings for all channels including eBPF
        assert isinstance(obs["process_events"], str)
        assert isinstance(obs["network_events"], str)
        assert isinstance(obs["file_events"], str)
        env.close()


class TestGymnasiumMake:
    def test_gymnasium_make_hybrid(self, tmp_db_with_ebpf):
        env = gym.make(
            "SecurityLogStream-Hybrid-v0", db_path=str(tmp_db_with_ebpf),
        )
        obs, info = env.reset()
        assert isinstance(obs["auth_log"], str)
        assert isinstance(obs["process_events"], np.ndarray)
        env.close()


class TestDefenseActionsInherited:
    def test_block_throttle_isolate(self, tmp_db_with_ebpf):
        """Defense actions inherited from the Text-mode env work in Hybrid mode."""
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf))
        env.reset()

        # Block source
        obs, r, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE))
        assert len(info["blocked_ips"]) > 0 or info["src_ip"] is None

        # Throttle
        obs, r, _, _, info = env.step(_make_action(ACTION_THROTTLE))

        # Isolate
        obs, r, _, _, info = env.step(_make_action(ACTION_ISOLATE))
        assert info["is_isolated"] is True
        env.close()


class TestRewardUnchanged:
    def test_reward_matches_text_mode(self, tmp_db_with_ebpf):
        """Hybrid-mode reward logic is inherited from Text mode: identical values."""
        env_text = SecurityLogStreamEnv(db_path=tmp_db_with_ebpf)
        env_hybrid = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf))

        env_text.reset(seed=42)
        env_hybrid.reset(seed=42)

        action = _make_action(ACTION_PASS, risk_score=5.0)

        _, r1, _, _, _ = env_text.step(action)
        _, r2, _, _, _ = env_hybrid.step(action)

        assert r1 == pytest.approx(r2)

        env_text.close()
        env_hybrid.close()
