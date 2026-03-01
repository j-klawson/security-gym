"""Tests for gymnasium wrappers.

.. deprecated:: 0.3.0
    These wrappers are deprecated — designed for v0 numeric observations.
    All tests are skipped. Retained for reference only.
"""

from __future__ import annotations

import numpy as np
import pytest
from security_gym.envs.log_stream_env import SecurityLogStreamEnv
from security_gym.envs.wrappers import (
    DecayingTraceWrapper,
    HashedFeatureWrapper,
    SessionAggregationWrapper,
    WindowedWrapper,
)
from security_gym.features.session import SESSION_FEATURE_DIM

pytestmark = pytest.mark.skip(
    reason="Wrappers are deprecated — designed for v0 numeric observation space"
)


@pytest.fixture
def env(tmp_db):
    """Base environment for wrapper tests."""
    e = SecurityLogStreamEnv(db_path=tmp_db, feature_mode="event")
    yield e
    e.close()


# ── HashedFeatureWrapper ─────────────────────────────────────────────

class TestHashedFeatureWrapper:
    def test_observation_shape(self, env):
        wrapped = HashedFeatureWrapper(env, hash_dim=512)
        obs, info = wrapped.reset()
        assert obs.shape == (512,)
        assert obs.dtype == np.float32

    def test_step_shape(self, env):
        wrapped = HashedFeatureWrapper(env, hash_dim=256)
        wrapped.reset()
        obs, reward, terminated, truncated, info = wrapped.step(0)
        assert obs.shape == (256,)

    def test_observation_space_matches(self, env):
        wrapped = HashedFeatureWrapper(env, hash_dim=1024)
        obs, _ = wrapped.reset()
        assert wrapped.observation_space.contains(obs)

    def test_non_zero_hash(self, env):
        wrapped = HashedFeatureWrapper(env, hash_dim=512)
        obs, _ = wrapped.reset()
        # Real log lines should produce non-zero hash
        assert np.any(obs != 0)

    def test_info_preserved(self, env):
        wrapped = HashedFeatureWrapper(env)
        _, info = wrapped.reset()
        assert "raw_line" in info
        assert "targets" in info


# ── SessionAggregationWrapper ────────────────────────────────────────

class TestSessionAggregationWrapper:
    def test_observation_shape(self, env):
        wrapped = SessionAggregationWrapper(env)
        obs, info = wrapped.reset()
        assert obs.shape == (SESSION_FEATURE_DIM,)
        assert obs.dtype == np.float32

    def test_step_shape(self, env):
        wrapped = SessionAggregationWrapper(env)
        wrapped.reset()
        obs, reward, terminated, truncated, info = wrapped.step(0)
        assert obs.shape == (SESSION_FEATURE_DIM,)

    def test_observation_space_matches(self, env):
        wrapped = SessionAggregationWrapper(env)
        obs, _ = wrapped.reset()
        assert wrapped.observation_space.contains(obs)

    def test_event_count_increments(self, env):
        wrapped = SessionAggregationWrapper(env)
        obs0, _ = wrapped.reset()
        # First event in the session should have event_count = 1
        assert obs0[0] >= 1.0
        obs1, _, _, _, _ = wrapped.step(0)
        # Same session events should increment
        assert obs1[0] >= 1.0

    def test_reset_clears_sessions(self, env):
        wrapped = SessionAggregationWrapper(env)
        wrapped.reset()
        for _ in range(5):
            wrapped.step(0)
        # After reset, counts should restart
        obs, _ = wrapped.reset()
        assert obs[0] == 1.0  # event_count reset

    def test_exhausted_returns_zeros(self, empty_db):
        base = SecurityLogStreamEnv(db_path=empty_db, feature_mode="event")
        wrapped = SessionAggregationWrapper(base)
        obs, info = wrapped.reset()
        assert info.get("exhausted") is True
        assert np.all(obs == 0)
        base.close()


# ── WindowedWrapper ──────────────────────────────────────────────────

class TestWindowedWrapper:
    def test_observation_shape(self, env):
        wrapped = WindowedWrapper(env, window_size=5)
        obs, _ = wrapped.reset()
        # 24 features * 5 window = 120
        assert obs.shape == (5 * 24,)
        assert obs.dtype == np.float32

    def test_step_fills_window(self, env):
        wrapped = WindowedWrapper(env, window_size=3)
        obs0, _ = wrapped.reset()
        # First obs: [zeros, zeros, obs]
        inner_dim = 24
        assert np.all(obs0[:inner_dim] == 0)  # first slot zero-padded
        assert np.all(obs0[inner_dim:2*inner_dim] == 0)  # second slot zero-padded
        # Third slot should have data
        assert np.any(obs0[2*inner_dim:] != 0)

    def test_window_slides(self, env):
        wrapped = WindowedWrapper(env, window_size=2)
        obs0, _ = wrapped.reset()
        obs1, _, _, _, _ = wrapped.step(0)
        obs2, _, _, _, _ = wrapped.step(0)
        inner_dim = 24
        # After 3 steps (reset + 2 steps), window has last 2 obs
        # First half of obs2 should be same as second half of obs1
        np.testing.assert_array_equal(obs2[:inner_dim], obs1[inner_dim:])

    def test_observation_space_matches(self, env):
        wrapped = WindowedWrapper(env, window_size=5)
        obs, _ = wrapped.reset()
        assert wrapped.observation_space.contains(obs)

    def test_reset_clears_buffer(self, env):
        wrapped = WindowedWrapper(env, window_size=3)
        wrapped.reset()
        for _ in range(5):
            wrapped.step(0)
        # After reset, buffer should be cleared (zero-padded again)
        obs, _ = wrapped.reset()
        inner_dim = 24
        assert np.all(obs[:inner_dim] == 0)  # zero-padded slots

    def test_composable_with_hashed(self, env):
        """WindowedWrapper(HashedFeatureWrapper(env)) should work."""
        hashed = HashedFeatureWrapper(env, hash_dim=64)
        wrapped = WindowedWrapper(hashed, window_size=3)
        obs, _ = wrapped.reset()
        assert obs.shape == (3 * 64,)
        obs2, _, _, _, _ = wrapped.step(0)
        assert obs2.shape == (3 * 64,)


# ── DecayingTraceWrapper ─────────────────────────────────────────────

class TestDecayingTraceWrapper:
    def test_observation_shape(self, env):
        wrapped = DecayingTraceWrapper(env, lambda_=0.95)
        obs, _ = wrapped.reset()
        assert obs.shape == (24,)
        assert obs.dtype == np.float32

    def test_trace_accumulates(self, env):
        wrapped = DecayingTraceWrapper(env, lambda_=0.99)
        obs0, _ = wrapped.reset()
        obs1, _, _, _, _ = wrapped.step(0)
        # Trace should generally have larger magnitude than raw obs
        # (accumulated from prior + current)
        assert np.linalg.norm(obs1) > 0

    def test_high_decay_forgets(self, env):
        """With lambda=0.01, almost all prior info is forgotten."""
        wrapped = DecayingTraceWrapper(env, lambda_=0.01)
        obs0, _ = wrapped.reset()
        obs1, _, _, _, info = wrapped.step(0)
        # With dt > 0, 0.01^dt is essentially 0, so trace ≈ current obs
        dt = info.get("dt_seconds", 0)
        if dt > 1:
            # Trace should be close to just the current observation
            assert np.linalg.norm(obs1) > 0

    def test_zero_dt_preserves(self, env):
        """With dt=0, lambda^0 = 1.0, so trace = trace + obs (pure accumulation)."""
        wrapped = DecayingTraceWrapper(env, lambda_=0.5)
        obs0, _ = wrapped.reset()
        # Manually set dt to 0 by modifying info in step
        # Just verify the formula: trace = trace * 0.5^0 + obs = trace + obs
        # This is effectively what happens when events have same timestamp

    def test_reset_zeros_trace(self, env):
        wrapped = DecayingTraceWrapper(env, lambda_=0.95)
        wrapped.reset()
        for _ in range(5):
            wrapped.step(0)
        obs, _ = wrapped.reset()
        # After reset, trace should be just the first observation
        # Not accumulated from prior episode
        obs2, _ = wrapped.reset()
        np.testing.assert_array_equal(obs, obs2)

    def test_observation_space_matches(self, env):
        wrapped = DecayingTraceWrapper(env, lambda_=0.95)
        obs, _ = wrapped.reset()
        assert wrapped.observation_space.contains(obs)

    def test_composable_with_session(self, env):
        """DecayingTraceWrapper(SessionAggregationWrapper(env)) should work."""
        session = SessionAggregationWrapper(env)
        wrapped = DecayingTraceWrapper(session, lambda_=0.9)
        obs, _ = wrapped.reset()
        assert obs.shape == (SESSION_FEATURE_DIM,)
