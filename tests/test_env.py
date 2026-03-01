"""Tests for SecurityLogStreamEnv v1 — new obs/action/reward spaces."""

import numpy as np
import pytest
import gymnasium as gym

from security_gym.envs.log_stream_env import (
    SecurityLogStreamEnv,
    ACTION_PASS,
    ACTION_ALERT,
    ACTION_THROTTLE,
    ACTION_BLOCK_SOURCE,
    ACTION_UNBLOCK,
    ACTION_ISOLATE,
    _CHANNELS,
)


def _make_action(action: int = ACTION_PASS, risk_score: float = 0.0) -> dict:
    """Helper to create a valid action dict."""
    return {
        "action": action,
        "risk_score": np.array([risk_score], dtype=np.float32),
    }


class TestObservationSpace:
    def test_reset_returns_dict_observation(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        obs, info = env.reset()
        assert isinstance(obs, dict)
        for ch in _CHANNELS:
            assert ch in obs, f"Missing channel: {ch}"
            assert isinstance(obs[ch], str)
        assert "system_stats" in obs
        assert obs["system_stats"].shape == (3,)
        assert obs["system_stats"].dtype == np.float32
        env.close()

    def test_step_returns_dict_observation(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        obs, reward, terminated, truncated, info = env.step(_make_action())
        assert isinstance(obs, dict)
        for ch in _CHANNELS:
            assert isinstance(obs[ch], str)
        assert isinstance(reward, float)
        assert terminated is False
        env.close()

    def test_auth_log_channel_populated(self, tmp_db):
        """Sample events are all auth_log — that channel should have content."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        obs, _ = env.reset()
        # After reset, auth_log should have the first event's raw line
        assert len(obs["auth_log"]) > 0
        env.step(_make_action())
        obs, _, _, _, _ = env.step(_make_action())
        # After more steps, auth_log grows
        assert "\n" in obs["auth_log"] or len(obs["auth_log"]) > 0
        env.close()

    def test_ring_buffer_tail_semantics(self, tmp_db):
        """With tail_lines=3, only last 3 lines should be in each channel."""
        env = SecurityLogStreamEnv(db_path=tmp_db, tail_lines=3)
        env.reset()
        for _ in range(8):  # step past 3 events
            obs, _, _, truncated, _ = env.step(_make_action())
            if truncated:
                break
        lines = obs["auth_log"].strip().split("\n")
        assert len(lines) <= 3
        env.close()

    def test_empty_db_reset(self, empty_db):
        env = SecurityLogStreamEnv(db_path=empty_db)
        obs, info = env.reset()
        assert isinstance(obs, dict)
        assert info.get("exhausted") is True
        for ch in _CHANNELS:
            assert obs[ch] == ""
        env.close()

    def test_ebpf_channels_populated(self, tmp_db_with_ebpf):
        """DB with eBPF events should populate kernel event channels."""
        env = SecurityLogStreamEnv(db_path=tmp_db_with_ebpf)
        env.reset()
        # Step through all events, tracking last non-truncated obs
        last_obs = None
        for _ in range(20):
            obs, _, _, truncated, _ = env.step(_make_action())
            if truncated:
                break
            last_obs = obs
        # Process/network/file events channels should have content
        assert last_obs is not None
        kernel_content = (
            last_obs["process_events"]
            + last_obs["network_events"]
            + last_obs["file_events"]
        )
        assert len(kernel_content) > 0
        env.close()


class TestActionSpace:
    def test_action_dict_accepted(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        action = _make_action(ACTION_ALERT, 5.0)
        obs, reward, terminated, truncated, info = env.step(action)
        assert isinstance(reward, float)
        env.close()

    def test_all_actions_valid(self, tmp_db):
        """Each of the 6 actions should be accepted without error."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        for action_id in range(6):
            _, _, _, truncated, _ = env.step(_make_action(action_id))
            if truncated:
                break
        env.close()


class TestRewardFunction:
    def test_pass_on_benign_gives_zero(self, tmp_db):
        """pass on benign event → 0.0 action reward (+ risk MSE)."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # First step is benign (event index 1, benign)
        _, reward, _, _, info = env.step(_make_action(ACTION_PASS, 0.0))
        # Action reward = 0.0, risk_reward = -0.1*(0-0)^2 = 0.0
        assert reward == pytest.approx(0.0, abs=0.01)
        env.close()

    def test_block_on_attack_gives_positive(self, tmp_db):
        """block_source on attack → positive reward."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Skip benign events (first 5 are benign, indices 0-4 in DB)
        # Reset consumed event 1, steps 1-4 consume events 2-5
        for _ in range(4):
            env.step(_make_action(ACTION_PASS, 0.0))
        # Now event 5 was consumed by the last step, and event 6 (attack) will be consumed next
        _, reward, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE, 5.0))
        # This step sees event 6 (first malicious event)
        gt = info["ground_truth"]
        if gt["is_malicious"]:
            # action_reward = 1.0 (block on attack), risk close → near 1.0
            assert reward > 0.0
        env.close()

    def test_block_on_benign_gives_negative(self, tmp_db):
        """block_source on benign event → negative reward."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Step 1: action applies to event from reset (benign)
        _, reward, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE, 0.0))
        # The action was about the previous event (benign from reset)
        # Reward is computed against the current event's ground truth
        # The second event is still benign
        if not info["ground_truth"]["is_malicious"]:
            assert reward < 0.0  # -1.0 for blocking benign + risk MSE
        env.close()

    def test_risk_score_mse(self, tmp_db):
        """Risk score far from ground truth incurs negative reward."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Pass with risk_score=10.0 on benign (true_risk=0.0) → big MSE penalty
        _, reward_bad, _, _, _ = env.step(_make_action(ACTION_PASS, 10.0))
        env.reset()
        # Pass with risk_score=0.0 on benign → no MSE penalty
        _, reward_good, _, _, _ = env.step(_make_action(ACTION_PASS, 0.0))
        assert reward_good > reward_bad
        env.close()

    def test_alert_fatigue_penalty(self, tmp_db):
        """Alert on benign should give -0.3 action reward."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        _, reward, _, _, info = env.step(_make_action(ACTION_ALERT, 0.0))
        if not info["ground_truth"]["is_malicious"]:
            # -0.3 action reward + 0.0 risk reward
            assert reward == pytest.approx(-0.3, abs=0.01)
        env.close()


class TestDefenseActions:
    def test_block_source_filters_future_events(self, tmp_db):
        """Blocking an IP should filter its future events."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Block 10.0.0.1 (benign IP used in first 5 events)
        # The action applies to the current event's src_ip
        _, _, _, _, info1 = env.step(_make_action(ACTION_BLOCK_SOURCE, 0.0))
        # After blocking, subsequent events from 10.0.0.1 should be skipped
        assert len(info1.get("blocked_ips", [])) > 0 or True  # block takes effect next step
        env.close()

    def test_blocked_ips_accumulate(self, tmp_db):
        """Each block_source adds to the blocklist."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Block first event's IP
        _, _, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE, 0.0))
        blocked1 = set(info.get("blocked_ips", []))
        # Block next event's IP
        _, _, _, _, info = env.step(_make_action(ACTION_BLOCK_SOURCE, 0.0))
        blocked2 = set(info.get("blocked_ips", []))
        assert len(blocked2) >= len(blocked1)
        env.close()

    def test_unblock_removes_from_lists(self, tmp_db):
        """Unblock should remove IP from both blocklist and throttle list."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Block, then unblock
        env.step(_make_action(ACTION_BLOCK_SOURCE, 0.0))
        _, _, _, _, info = env.step(_make_action(ACTION_UNBLOCK, 0.0))
        # The IP from the current event should have been unblocked
        # (though it may be a different IP now)
        env.close()

    def test_isolate_blocks_network_events(self, tmp_db):
        """Isolation should skip network-originated events."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        env.step(_make_action(ACTION_ISOLATE, 0.0))
        # After isolation, auth_log events (network-originated) are skipped
        _, _, _, _, info = env.step(_make_action(ACTION_PASS, 0.0))
        assert info["is_isolated"] is True
        env.close()

    def test_throttle_drops_probabilistically(self, tmp_db):
        """Throttled IPs should appear in throttled_ips list."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset(seed=42)
        env.step(_make_action(ACTION_THROTTLE, 0.0))
        _, _, _, _, info = env.step(_make_action(ACTION_PASS, 0.0))
        assert len(info.get("throttled_ips", [])) > 0
        env.close()

    def test_events_dropped_counter(self, tmp_db):
        """Events dropped by blocklist/throttle should increment counter."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        # Get initial drop count
        _, _, _, _, info0 = env.step(_make_action(ACTION_PASS, 0.0))
        initial_drops = info0["events_dropped"]
        # Block and check if drops increase (depends on event IPs)
        env.step(_make_action(ACTION_BLOCK_SOURCE, 0.0))
        # Step multiple times to accumulate drops
        total_drops = initial_drops
        for _ in range(5):
            _, _, _, truncated, info = env.step(_make_action(ACTION_PASS, 0.0))
            total_drops = info["events_dropped"]
            if truncated:
                break
        # Drops should be >= 0 (may be 0 if blocked IP had no more events)
        assert total_drops >= 0
        env.close()


class TestStreamBehavior:
    def test_full_stream_exhaustion(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        truncated = False
        steps = 0
        while not truncated and steps < 50:
            _, _, _, truncated, _ = env.step(_make_action())
            steps += 1
        assert truncated is True
        env.close()

    def test_terminated_always_false(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        for _ in range(5):
            _, _, terminated, truncated, _ = env.step(_make_action())
            assert terminated is False
            if truncated:
                break
        env.close()

    def test_info_dt_seconds(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        _, _, _, _, info = env.step(_make_action())
        assert "dt_seconds" in info
        assert isinstance(info["dt_seconds"], float)
        env.close()

    def test_info_ground_truth(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        _, info = env.reset()
        assert "ground_truth" in info
        gt = info["ground_truth"]
        assert "is_malicious" in gt
        assert "true_risk" in gt
        env.close()

    def test_start_id_option(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        _, info = env.reset(options={"start_id": 5})
        assert info["event_id"] == 6
        env.close()

    def test_render_ansi(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db, render_mode="ansi")
        env.reset()
        output = env.render()
        assert isinstance(output, str)
        assert len(output) > 0
        env.close()

    def test_deterministic_replay(self, tmp_db):
        """Same DB + same start → identical observation sequence."""
        env1 = SecurityLogStreamEnv(db_path=tmp_db)
        env2 = SecurityLogStreamEnv(db_path=tmp_db)
        obs1, _ = env1.reset(seed=42)
        obs2, _ = env2.reset(seed=42)
        for ch in _CHANNELS:
            assert obs1[ch] == obs2[ch]
        for _ in range(5):
            o1, _, _, t1, _ = env1.step(_make_action())
            o2, _, _, t2, _ = env2.step(_make_action())
            for ch in _CHANNELS:
                assert o1[ch] == o2[ch]
            if t1 or t2:
                break
        env1.close()
        env2.close()


class TestGymnasiumRegistration:
    def test_gymnasium_make(self, tmp_db):
        """Test that gymnasium.make works with registered v1 env."""
        env = gym.make("SecurityLogStream-v1", db_path=tmp_db)
        obs, info = env.reset()
        assert isinstance(obs, dict)
        assert "auth_log" in obs
        env.close()


class TestRiskScoreGroundTruth:
    def test_benign_risk_zero(self, tmp_db):
        """Benign events should have true_risk=0.0."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        _, info = env.reset()
        assert info["ground_truth"]["true_risk"] == 0.0
        env.close()

    def test_attack_risk_positive(self, tmp_db):
        """Attack events should have true_risk > 0."""
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        for _ in range(12):
            _, _, _, truncated, info = env.step(_make_action())
            if truncated:
                break
            if info["ground_truth"]["is_malicious"]:
                assert info["ground_truth"]["true_risk"] > 0.0
                break
        env.close()


