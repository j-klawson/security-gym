"""Tests for SecurityGymStream Alberta adapter."""

from __future__ import annotations

from unittest.mock import patch

import numpy as np
import pytest

from security_gym.adapters.scan_stream import SecurityGymStream, HAS_JAX
from security_gym.features.extractors import FEATURE_DIM
from security_gym.targets.builder import N_HEADS


# ── Properties ─────────────────────────────────────────────────────────


class TestProperties:
    def test_feature_dim_event(self, tmp_db):
        stream = SecurityGymStream(tmp_db, feature_mode="event")
        assert stream.feature_dim == FEATURE_DIM == 24

    def test_feature_dim_hashed(self, tmp_db):
        stream = SecurityGymStream(tmp_db, feature_mode="hashed", hash_dim=512)
        assert stream.feature_dim == 512

    def test_n_heads(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        assert stream.n_heads == N_HEADS == 5

    def test_len(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        assert len(stream) == 13

    def test_remaining_all(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=0)
        assert stream.remaining() == 13

    def test_remaining_partial(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=5)
        assert stream.remaining() == 8

    def test_remaining_past_end(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=100)
        assert stream.remaining() == 0

    def test_unknown_feature_mode(self, tmp_db):
        with pytest.raises(ValueError, match="Unknown feature_mode"):
            SecurityGymStream(tmp_db, feature_mode="unknown")


# ── collect_numpy ──────────────────────────────────────────────────────


class TestCollectNumpy:
    def test_shapes(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs, tgt = stream.collect_numpy()
        assert obs.shape == (13, 24)
        assert tgt.shape == (13, 5)

    def test_dtypes(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs, tgt = stream.collect_numpy()
        assert obs.dtype == np.float32
        assert tgt.dtype == np.float32

    def test_hashed_shapes(self, tmp_db):
        stream = SecurityGymStream(tmp_db, feature_mode="hashed", hash_dim=256)
        obs, tgt = stream.collect_numpy()
        assert obs.shape == (13, 256)
        assert tgt.shape == (13, 5)

    def test_nan_masking_unlabeled(self, tmp_db):
        """Unlabeled events (last 3) should have all-NaN targets."""
        stream = SecurityGymStream(tmp_db)
        _, tgt = stream.collect_numpy()
        # Events 11-13 are unlabeled (indices 10-12)
        for i in range(10, 13):
            assert np.all(np.isnan(tgt[i])), f"Event {i} should be all-NaN"

    def test_nan_masking_benign(self, tmp_db):
        """Benign events have is_malicious=0, severity=0, other heads NaN."""
        stream = SecurityGymStream(tmp_db)
        _, tgt = stream.collect_numpy()
        for i in range(5):
            assert tgt[i, 0] == 0.0  # is_malicious
            assert np.isnan(tgt[i, 1])  # attack_type (not set for benign)
            assert np.isnan(tgt[i, 2])  # attack_stage (not set for benign)
            assert tgt[i, 3] == 0.0  # severity=0 → 0/3 = 0.0
            assert np.isnan(tgt[i, 4])  # session_value (not set)

    def test_nan_masking_malicious(self, tmp_db):
        """Malicious events have all attack heads filled."""
        stream = SecurityGymStream(tmp_db)
        _, tgt = stream.collect_numpy()
        for i in range(5, 10):
            assert tgt[i, 0] == 1.0  # is_malicious
            assert not np.isnan(tgt[i, 1])  # attack_type is set
            assert not np.isnan(tgt[i, 2])  # attack_stage is set
            assert not np.isnan(tgt[i, 3])  # severity is set
            assert np.isnan(tgt[i, 4])  # session_value not set

    def test_empty_db(self, empty_db):
        stream = SecurityGymStream(empty_db)
        obs, tgt = stream.collect_numpy()
        assert obs.shape == (0, 24)
        assert tgt.shape == (0, 5)
        assert obs.dtype == np.float32
        assert tgt.dtype == np.float32

    def test_start_id_filtering(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=10)
        obs, tgt = stream.collect_numpy()
        assert obs.shape[0] == 3  # only last 3 events

    def test_limit(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs, tgt = stream.collect_numpy(limit=5)
        assert obs.shape == (5, 24)
        assert tgt.shape == (5, 5)

    def test_deterministic(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs1, tgt1 = stream.collect_numpy()
        obs2, tgt2 = stream.collect_numpy()
        np.testing.assert_array_equal(obs1, obs2)
        # Use assert_equal for NaN-safe comparison
        np.testing.assert_array_equal(tgt1, tgt2)


# ── Features match env ─────────────────────────────────────────────────


class TestFeaturesMatchEnv:
    def test_features_identical_to_env(self, tmp_db):
        """Verify the adapter produces identical features to the gymnasium env."""
        from security_gym.envs.log_stream_env import SecurityLogStreamEnv

        # Collect from adapter
        stream = SecurityGymStream(tmp_db)
        stream_obs, _ = stream.collect_numpy()

        # Collect from env
        env = SecurityLogStreamEnv(tmp_db)
        obs, info = env.reset()
        env_obs = [obs]
        for _ in range(12):
            obs, _, _, truncated, _ = env.step(0)
            if truncated:
                break
            env_obs.append(obs)
        env.close()

        env_arr = np.stack(env_obs)
        np.testing.assert_array_almost_equal(stream_obs, env_arr)


# ── iter_batches ───────────────────────────────────────────────────────


class TestIterBatches:
    def test_chunk_sizes(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        sizes = []
        for obs_batch, tgt_batch in stream.iter_batches(size=4):
            assert obs_batch.shape[1] == 24
            assert tgt_batch.shape[1] == 5
            assert obs_batch.shape[0] == tgt_batch.shape[0]
            sizes.append(obs_batch.shape[0])
        assert sizes == [4, 4, 4, 1]

    def test_total_events(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        total = sum(obs.shape[0] for obs, _ in stream.iter_batches(size=3))
        assert total == 13

    def test_empty_db(self, empty_db):
        stream = SecurityGymStream(empty_db)
        batches = list(stream.iter_batches(size=10))
        assert batches == []

    def test_matches_collect(self, tmp_db):
        """iter_batches should produce the same data as collect_numpy."""
        stream = SecurityGymStream(tmp_db)
        full_obs, full_tgt = stream.collect_numpy()

        batch_obs = []
        batch_tgt = []
        for obs, tgt in stream.iter_batches(size=4):
            batch_obs.append(obs)
            batch_tgt.append(tgt)

        concat_obs = np.concatenate(batch_obs)
        concat_tgt = np.concatenate(batch_tgt)
        np.testing.assert_array_equal(full_obs, concat_obs)
        np.testing.assert_array_equal(full_tgt, concat_tgt)


# ── collect (JAX-conditional) ──────────────────────────────────────────


@pytest.mark.skipif(not HAS_JAX, reason="JAX not installed")
class TestCollectJAX:
    def test_returns_jax_arrays(self, tmp_db):
        import jax.numpy as jnp

        stream = SecurityGymStream(tmp_db)
        obs, tgt = stream.collect()
        assert isinstance(obs, jnp.ndarray)
        assert isinstance(tgt, jnp.ndarray)

    def test_shapes(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs, tgt = stream.collect()
        assert obs.shape == (13, 24)
        assert tgt.shape == (13, 5)


# ── Iterator (JAX-conditional) ─────────────────────────────────────────


@pytest.mark.skipif(not HAS_JAX, reason="JAX not installed")
class TestIteratorJAX:
    def test_yields_timesteps(self, tmp_db):
        from security_gym.adapters.scan_stream import TimeStep

        stream = SecurityGymStream(tmp_db)
        step = next(iter(stream))
        assert isinstance(step, TimeStep)
        assert step.observation.shape == (24,)
        assert step.target.shape == (5,)

    def test_count_matches_remaining(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=0)
        count = sum(1 for _ in stream)
        assert count == stream.remaining()

    def test_count_with_start_id(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=5)
        count = sum(1 for _ in stream)
        assert count == 8


@pytest.mark.skipif(HAS_JAX, reason="Test requires JAX to NOT be installed")
class TestIteratorNoJAX:
    def test_raises_import_error(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        with pytest.raises(ImportError, match="JAX is required"):
            next(iter(stream))


# ── collect without JAX ────────────────────────────────────────────────


@pytest.mark.skipif(HAS_JAX, reason="Test requires JAX to NOT be installed")
class TestCollectNoJAX:
    def test_returns_numpy(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs, tgt = stream.collect()
        assert isinstance(obs, np.ndarray)
        assert isinstance(tgt, np.ndarray)


# ── Loop mode ─────────────────────────────────────────────────────────


class TestLoopMode:
    def test_loop_wraps_around(self, tmp_db):
        """With loop=True, stream should wrap and yield more events than exist."""
        stream = SecurityGymStream(tmp_db, loop=True)
        count = 0
        for row in stream._iter_rows(limit=26):  # 2x the 13 events
            count += 1
        assert count == 26

    def test_loop_false_stops(self, tmp_db):
        """Without loop, stream stops after all events."""
        stream = SecurityGymStream(tmp_db, loop=False)
        count = 0
        for row in stream._iter_rows(limit=100):
            count += 1
        assert count == 13

    def test_loop_collect_numpy_ignores_loop(self, tmp_db):
        """collect_numpy always reads once (no looping)."""
        stream = SecurityGymStream(tmp_db, loop=True)
        obs, tgt = stream.collect_numpy()
        assert obs.shape[0] == 13  # Not infinite

    def test_loop_iter_batches(self, tmp_db):
        """iter_batches respects loop=False."""
        stream = SecurityGymStream(tmp_db, loop=False)
        total = sum(obs.shape[0] for obs, _ in stream.iter_batches(size=5))
        assert total == 13


# ── Speed mode ────────────────────────────────────────────────────────


class TestSpeedMode:
    def test_speed_zero_no_sleep(self, tmp_db):
        """Full speed (speed=0) should not call time.sleep."""
        stream = SecurityGymStream(tmp_db, speed=0)
        with patch("security_gym.adapters.scan_stream.time.sleep") as mock_sleep:
            list(stream._iter_rows())
            mock_sleep.assert_not_called()

    def test_speed_realtime_sleeps(self, tmp_db):
        """Realtime (speed=1.0) should call time.sleep with dt values."""
        stream = SecurityGymStream(tmp_db, speed=1.0)
        with patch("security_gym.adapters.scan_stream.time.sleep") as mock_sleep:
            list(stream._iter_rows(limit=5))
            # Events are 10 seconds apart in test fixtures
            assert mock_sleep.call_count > 0
            # Check that sleep was called with positive values
            for call in mock_sleep.call_args_list:
                assert call[0][0] > 0

    def test_speed_10x_sleeps_less(self, tmp_db):
        """10x speed should sleep 1/10th of realtime dt."""
        stream = SecurityGymStream(tmp_db, speed=10.0)
        with patch("security_gym.adapters.scan_stream.time.sleep") as mock_sleep:
            list(stream._iter_rows(limit=3))
            if mock_sleep.call_count > 0:
                # Events are 10s apart → at 10x speed, sleep should be ~1s
                for call in mock_sleep.call_args_list:
                    assert call[0][0] <= 2.0  # 10s / 10 = 1s, some tolerance

    def test_speed_does_not_affect_collect(self, tmp_db):
        """collect_numpy should work even with speed set (no loop interference)."""
        stream = SecurityGymStream(tmp_db, speed=0, loop=False)
        obs, tgt = stream.collect_numpy()
        assert obs.shape[0] == 13
