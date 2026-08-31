"""Tests for SecurityLogStreamHybridEnv: hybrid text + structured observations."""

import numpy as np
import pytest
import gymnasium as gym

from security_gym.envs.log_stream_env import (
    SecurityLogStreamEnv,
    DEFENSE_STATE_COLS,
    TARGET_SLATE_COLS,
    ACTION_PASS,
    ACTION_BLOCK_SOURCE,
    ACTION_THROTTLE,
    ACTION_ISOLATE,
    ACTION_UNBLOCK,
    DENY_LOG_PREFIX,
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


class TestBlockRecovery:
    """block_visibility / block_ttl thread through to the hybrid env."""

    def test_hybrid_deny_log_threads_params(self, single_ip_db):
        """deny_log surfaces a blocked IP in the auth_log TEXT channel.

        The structured eBPF channels carry no deny marker, so the deny-log
        annotation is asserted on the text channel. This also guards the
        hybrid-reset trap: _block_times / _current_denied must be initialized.
        """
        env = SecurityLogStreamHybridEnv(
            db_path=str(single_ip_db), block_visibility="deny_log", block_ttl=2.0,
        )
        env.reset()
        obs, reward, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE))
        assert "10.9.9.9" in info["blocked_ips"]
        assert DENY_LOG_PREFIX in obs["auth_log"]
        # Consequence-only reward (action suppressed on the denied step).
        assert reward == pytest.approx(-0.5)
        # Unblock restores normal delivery (state survives across the hybrid path).
        obs, reward, _, _, info = env.step(_make_action(ACTION_UNBLOCK))
        assert "10.9.9.9" not in info["blocked_ips"]
        env.close()

    def test_hybrid_default_drop_unchanged(self, single_ip_db):
        """Default hybrid env keeps permanent-block semantics (no deny prefix)."""
        env = SecurityLogStreamHybridEnv(db_path=str(single_ip_db))
        env.reset()
        obs, _, term, trunc, info = env.step(_make_action(ACTION_BLOCK_SOURCE))
        assert term is False
        assert trunc is True  # single IP blocked → stream exhausts
        assert info["events_dropped"] == 7
        assert DENY_LOG_PREFIX not in obs["auth_log"]
        env.close()


class TestHybridDefenseStateObservation:
    """Structured counterpart to the text mode's defense-state rendering.

    Columns: [n_blocked, n_throttled, is_isolated, current_src_blocked,
    current_src_throttled, seconds_since_last_change].
    """

    def test_can_be_switched_off(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db), defense_state_obs=False)
        obs, _ = env.reset()
        assert "defense_state" not in obs
        assert "defense_state" not in env.observation_space.spaces
        env.close()

    def test_present_by_default(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db))
        obs, _ = env.reset()
        assert "defense_state" in obs
        assert obs["defense_state"].shape == (DEFENSE_STATE_COLS,)
        env.close()

    def test_shape_and_dtype(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db), defense_state_obs=True)
        obs, _ = env.reset()
        vec = obs["defense_state"]
        assert vec.shape == (DEFENSE_STATE_COLS,)
        assert vec.dtype == np.float32
        assert env.observation_space["defense_state"].shape == (DEFENSE_STATE_COLS,)
        np.testing.assert_array_equal(vec, np.zeros(DEFENSE_STATE_COLS, dtype=np.float32))
        env.close()

    def test_counts_track_defense_state(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db), defense_state_obs=True)
        env.reset()
        obs, _, _, _, _ = env.step(_make_action(ACTION_BLOCK_SOURCE))
        assert obs["defense_state"][0] == 1.0  # n_blocked
        obs, _, _, _, _ = env.step(_make_action(ACTION_THROTTLE))
        assert obs["defense_state"][1] == 1.0  # n_throttled
        obs, _, _, _, _ = env.step(_make_action(ACTION_ISOLATE))
        assert obs["defense_state"][2] == 1.0  # is_isolated
        env.close()

    def test_current_src_flag_under_deny_log(self, tmp_db):
        env = SecurityLogStreamHybridEnv(
            db_path=str(tmp_db), defense_state_obs=True, block_visibility="deny_log",
        )
        obs, info = env.reset()
        src = info["src_ip"]
        obs, _, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE))
        flagged = obs["defense_state"][3] == 1.0
        for _ in range(10):
            if flagged:
                break
            obs, _, _, truncated, info = env.step(_make_action(ACTION_PASS))
            flagged = obs["defense_state"][3] == 1.0
            if truncated:
                break
        assert flagged, f"current_src_blocked never set for {src}"
        env.close()

    def test_reset_clears_vector(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db), defense_state_obs=True)
        env.reset()
        env.step(_make_action(ACTION_ISOLATE))
        obs, _ = env.reset()
        np.testing.assert_array_equal(
            obs["defense_state"], np.zeros(DEFENSE_STATE_COLS, dtype=np.float32),
        )
        env.close()


class TestHybridExplicitTargeting:
    """Structured counterpart to the text mode's target slate.

    Hybrid duplicates `reset` and `step` rather than calling `super()`, so the
    slate bookkeeping added to those methods needs coverage of its own.
    """

    def test_slate_shape_and_dtype(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db), target_slate_size=8)
        obs, _ = env.reset()
        slate = obs["target_slate"]
        assert slate.shape == (8, TARGET_SLATE_COLS)
        assert slate.dtype == np.float32
        assert env.observation_space["target_slate"].shape == (8, TARGET_SLATE_COLS)
        assert env.action_space["target"].n == 9
        env.close()

    def test_can_be_switched_off(self, tmp_db):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db), target_slate_size=0)
        obs, _ = env.reset()
        assert "target" not in env.action_space.spaces
        assert "target_slate" not in obs
        env.close()

    def test_slate_populates_through_hybrid_reset_and_step(self, tmp_db_with_ebpf):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf), target_slate_size=8)
        obs, info = env.reset()
        assert obs["target_slate"][0, 0] != 0.0, "reset should seed the slate"
        for _ in range(10):
            obs, _, _, truncated, _ = env.step(_make_action(ACTION_PASS))
            if truncated:
                break
        occupied = int((obs["target_slate"][:, 0] != 0.0).sum())
        assert occupied >= 2, "step should keep feeding the slate"
        env.close()

    def test_hash_agrees_with_the_network_channel(self, tmp_db_with_ebpf):
        """A slate slot and a kernel event must hash one host identically.

        This is what lets the agent associate an address in the slate with the
        `dst_ip_hash` column of `network_events`. A different seed here would
        make the association unlearnable.
        """
        from security_gym.envs.ebpf_encoding import SEED_IP, hash_string

        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf), target_slate_size=8)
        obs, info = env.reset()
        first = info["src_ip"]
        assert first
        assert obs["target_slate"][0, 0] == pytest.approx(
            float(hash_string(first, seed=SEED_IP)),
        )
        env.close()

    def test_control_flags_track_defense_state(self, tmp_db_with_ebpf):
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf), target_slate_size=8)
        obs, info = env.reset()
        first = info["src_ip"]
        obs, _, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE))
        assert first in info["blocked_ips"]
        blocked_rows = obs["target_slate"][:, 1]
        assert blocked_rows.sum() == 1.0, "exactly one slot should be marked blocked"
        env.close()

    def test_block_by_slate_index_from_an_address_less_event(self, tmp_db_with_ebpf):
        """The cross-channel capability, exercised through the hybrid path."""
        env = SecurityLogStreamHybridEnv(db_path=str(tmp_db_with_ebpf), target_slate_size=8)
        obs, info = env.reset()
        first = info["src_ip"]

        for _ in range(20):
            obs, _, _, truncated, info = env.step(_make_action(ACTION_PASS))
            if truncated:
                pytest.fail("stream exhausted before an address-less event")
            if info.get("src_ip") is None:
                break
        assert info["src_ip"] is None

        action = _make_action(ACTION_BLOCK_SOURCE)
        action["target"] = 1  # slot 0 holds the first address seen
        obs, _, _, _, info = env.step(action)
        assert info["blocked_ips"] == [first]
        assert info["action_target"] == first
        assert info["action_target_explicit"] is True
        assert info["action_effective"] is True
        env.close()
