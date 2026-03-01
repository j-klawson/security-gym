"""Tests for SecurityGymStream adapter (v1 — text observations)."""

from __future__ import annotations

from unittest.mock import patch

import numpy as np
import pytest

from security_gym.adapters.scan_stream import SecurityGymStream, HAS_JAX
from security_gym.envs.log_stream_env import _CHANNELS


# ── Properties ─────────────────────────────────────────────────────────


class TestProperties:
    def test_channels(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        assert stream.channels == list(_CHANNELS)

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


# ── collect_numpy ──────────────────────────────────────────────────────


class TestCollectNumpy:
    def test_returns_lists(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        observations, ground_truths = stream.collect_numpy()
        assert isinstance(observations, list)
        assert isinstance(ground_truths, list)
        assert len(observations) == 13
        assert len(ground_truths) == 13

    def test_observation_has_channels(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        observations, _ = stream.collect_numpy()
        obs = observations[0]
        for ch in _CHANNELS:
            assert ch in obs
            assert isinstance(obs[ch], str)
        assert "system_stats" in obs
        assert obs["system_stats"].dtype == np.float32

    def test_ground_truth_structure(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        _, ground_truths = stream.collect_numpy()
        gt = ground_truths[0]
        assert "is_malicious" in gt
        assert "attack_type" in gt
        assert "true_risk" in gt

    def test_benign_ground_truth(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        _, ground_truths = stream.collect_numpy()
        # First 5 events are benign
        for i in range(5):
            assert ground_truths[i]["is_malicious"] is False
            assert ground_truths[i]["true_risk"] == 0.0

    def test_malicious_ground_truth(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        _, ground_truths = stream.collect_numpy()
        # Events 5-9 are malicious (brute_force, initial_access)
        for i in range(5, 10):
            assert ground_truths[i]["is_malicious"] is True
            assert ground_truths[i]["true_risk"] > 0.0
            assert ground_truths[i]["attack_type"] == "brute_force"

    def test_empty_db(self, empty_db):
        stream = SecurityGymStream(empty_db)
        observations, ground_truths = stream.collect_numpy()
        assert observations == []
        assert ground_truths == []

    def test_start_id_filtering(self, tmp_db):
        stream = SecurityGymStream(tmp_db, start_id=10)
        observations, _ = stream.collect_numpy()
        assert len(observations) == 3

    def test_limit(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        observations, ground_truths = stream.collect_numpy(limit=5)
        assert len(observations) == 5
        assert len(ground_truths) == 5

    def test_deterministic(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs1, gt1 = stream.collect_numpy()
        obs2, gt2 = stream.collect_numpy()
        for o1, o2 in zip(obs1, obs2):
            for ch in _CHANNELS:
                assert o1[ch] == o2[ch]

    def test_auth_log_grows(self, tmp_db):
        """Text observations should accumulate as events are processed."""
        stream = SecurityGymStream(tmp_db)
        observations, _ = stream.collect_numpy()
        # First observation has 1 line, last has up to tail_lines
        first_len = len(observations[0]["auth_log"])
        last_len = len(observations[-1]["auth_log"])
        assert last_len >= first_len


# ── iter_batches ───────────────────────────────────────────────────────


class TestIterBatches:
    def test_chunk_sizes(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        sizes = []
        for obs_batch, gt_batch in stream.iter_batches(size=4):
            assert len(obs_batch) == len(gt_batch)
            sizes.append(len(obs_batch))
        assert sizes == [4, 4, 4, 1]

    def test_total_events(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        total = sum(len(obs) for obs, _ in stream.iter_batches(size=3))
        assert total == 13

    def test_empty_db(self, empty_db):
        stream = SecurityGymStream(empty_db)
        batches = list(stream.iter_batches(size=10))
        assert batches == []

    def test_matches_collect(self, tmp_db):
        """iter_batches should produce the same data as collect_numpy."""
        stream = SecurityGymStream(tmp_db)
        full_obs, full_gt = stream.collect_numpy()

        batch_obs = []
        batch_gt = []
        for obs, gt in stream.iter_batches(size=4):
            batch_obs.extend(obs)
            batch_gt.extend(gt)

        assert len(batch_obs) == len(full_obs)
        for i in range(len(full_obs)):
            for ch in _CHANNELS:
                assert batch_obs[i][ch] == full_obs[i][ch]


# ── collect (delegates to collect_numpy) ──────────────────────────────


class TestCollect:
    def test_returns_same_as_numpy(self, tmp_db):
        stream = SecurityGymStream(tmp_db)
        obs1, gt1 = stream.collect()
        obs2, gt2 = stream.collect_numpy()
        assert len(obs1) == len(obs2)


# ── Iterator (JAX-conditional) ─────────────────────────────────────────


@pytest.mark.skipif(not HAS_JAX, reason="JAX not installed")
class TestIteratorJAX:
    def test_yields_timesteps(self, tmp_db):
        from security_gym.adapters.scan_stream import TimeStep

        stream = SecurityGymStream(tmp_db)
        step = next(iter(stream))
        assert isinstance(step, TimeStep)
        assert isinstance(step.observation, dict)
        assert isinstance(step.ground_truth, dict)

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


# ── Loop mode ─────────────────────────────────────────────────────────


class TestLoopMode:
    def test_loop_wraps_around(self, tmp_db):
        """With loop=True, stream should wrap and yield more events than exist."""
        stream = SecurityGymStream(tmp_db, loop=True)
        count = 0
        for row in stream._iter_rows(limit=26):
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
        obs, gt = stream.collect_numpy()
        assert len(obs) == 13

    def test_loop_iter_batches(self, tmp_db):
        """iter_batches respects loop=False."""
        stream = SecurityGymStream(tmp_db, loop=False)
        total = sum(len(obs) for obs, _ in stream.iter_batches(size=5))
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
            assert mock_sleep.call_count > 0
            for call in mock_sleep.call_args_list:
                assert call[0][0] > 0

    def test_speed_10x_sleeps_less(self, tmp_db):
        """10x speed should sleep 1/10th of realtime dt."""
        stream = SecurityGymStream(tmp_db, speed=10.0)
        with patch("security_gym.adapters.scan_stream.time.sleep") as mock_sleep:
            list(stream._iter_rows(limit=3))
            if mock_sleep.call_count > 0:
                for call in mock_sleep.call_args_list:
                    assert call[0][0] <= 2.0

    def test_speed_does_not_affect_collect(self, tmp_db):
        """collect_numpy should work even with speed set."""
        stream = SecurityGymStream(tmp_db, speed=0, loop=False)
        obs, gt = stream.collect_numpy()
        assert len(obs) == 13


# ── eBPF source integration ──────────────────────────────────────────


class TestEbpfSources:
    def test_ebpf_events_in_stream(self, tmp_db_with_ebpf):
        """Stream with eBPF events should include kernel event channels."""
        stream = SecurityGymStream(tmp_db_with_ebpf)
        observations, ground_truths = stream.collect_numpy()
        # 13 regular + 3 eBPF = 16 events
        assert len(observations) == 16

    def test_kernel_channels_populated(self, tmp_db_with_ebpf):
        """eBPF events should populate process/network/file channels."""
        stream = SecurityGymStream(tmp_db_with_ebpf)
        observations, _ = stream.collect_numpy()
        last_obs = observations[-1]
        # At least one kernel channel should have content
        kernel_content = (
            last_obs["process_events"]
            + last_obs["network_events"]
            + last_obs["file_events"]
        )
        assert len(kernel_content) > 0
