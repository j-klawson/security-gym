"""Tests for SecurityLogStreamEnv — Gymnasium compliance + step/reset."""

import numpy as np
import gymnasium as gym
from gymnasium.utils.env_checker import check_env

from security_gym.envs.log_stream_env import SecurityLogStreamEnv
from security_gym.features.extractors import FEATURE_DIM
from security_gym.targets.builder import N_HEADS
from tests.conftest import SAMPLE_EVENTS


class TestSecurityLogStreamEnv:
    def test_gymnasium_check_env(self, tmp_db):
        """Gymnasium's built-in compliance checker."""
        env = SecurityLogStreamEnv(db_path=tmp_db, feature_mode="event")
        check_env(env.unwrapped, skip_render_check=True)
        env.close()

    def test_reset_returns_correct_shapes(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        obs, info = env.reset()
        assert obs.shape == (FEATURE_DIM,)
        assert obs.dtype == np.float32
        assert "targets" in info
        assert info["targets"].shape == (N_HEADS,)
        assert "event_id" in info
        env.close()

    def test_step_returns_correct_shapes(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        obs, reward, terminated, truncated, info = env.step(0)
        assert obs.shape == (FEATURE_DIM,)
        assert isinstance(reward, float)
        assert terminated is False  # never terminates
        assert isinstance(truncated, bool)
        assert info["targets"].shape == (N_HEADS,)
        env.close()

    def test_full_stream_exhaustion(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        n_events = len(SAMPLE_EVENTS)
        truncated = False
        steps = 0
        while not truncated and steps < n_events + 5:
            _, _, _, truncated, _ = env.step(0)
            steps += 1
        # reset consumed 1 event, steps 1..(n-1) consumed remaining data,
        # final step discovers exhaustion → total = n_events steps
        assert truncated is True
        assert steps == n_events
        env.close()

    def test_reward_is_malicious(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        rewards = []
        for _ in range(len(SAMPLE_EVENTS) - 1):
            _, reward, _, truncated, _ = env.step(0)
            rewards.append(reward)
            if truncated:
                break
        assert 0.0 in rewards
        assert 1.0 in rewards
        env.close()

    def test_info_dt_seconds(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        env.reset()
        _, _, _, _, info = env.step(0)
        assert "dt_seconds" in info
        assert isinstance(info["dt_seconds"], float)
        env.close()

    def test_hashed_feature_mode(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db, feature_mode="hashed", hash_dim=64)
        obs, info = env.reset()
        assert obs.shape == (64,)
        obs2, _, _, _, _ = env.step(0)
        assert obs2.shape == (64,)
        env.close()

    def test_start_id_option(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db)
        _, info1 = env.reset(options={"start_id": 5})
        assert info1["event_id"] == 6
        env.close()

    def test_render_ansi(self, tmp_db):
        env = SecurityLogStreamEnv(db_path=tmp_db, render_mode="ansi")
        env.reset()
        output = env.render()
        assert isinstance(output, str)
        assert len(output) > 0
        env.close()

    def test_empty_db_reset(self, empty_db):
        env = SecurityLogStreamEnv(db_path=empty_db)
        obs, info = env.reset()
        assert obs.shape == (FEATURE_DIM,)
        assert info.get("exhausted") is True
        env.close()

    def test_gymnasium_make(self, tmp_db):
        """Test that gymnasium.make works with registered env."""
        env = gym.make("SecurityLogStream-v0", db_path=tmp_db)
        obs, info = env.reset()
        assert obs.shape == (FEATURE_DIM,)
        env.close()

    def test_deterministic_replay(self, tmp_db):
        """Same DB + same start → identical observation sequence."""
        env1 = SecurityLogStreamEnv(db_path=tmp_db)
        env2 = SecurityLogStreamEnv(db_path=tmp_db)
        obs1, _ = env1.reset(seed=42)
        obs2, _ = env2.reset(seed=42)
        np.testing.assert_array_equal(obs1, obs2)
        for _ in range(5):
            o1, _, _, t1, _ = env1.step(0)
            o2, _, _, t2, _ = env2.step(0)
            np.testing.assert_array_equal(o1, o2)
            if t1 or t2:
                break
        env1.close()
        env2.close()
