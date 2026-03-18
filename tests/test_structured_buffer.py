"""Tests for StructuredRingBuffer."""

import numpy as np

from security_gym.envs.structured_buffer import StructuredRingBuffer


class TestStructuredRingBuffer:
    def test_empty_snapshot_zeros(self):
        buf = StructuredRingBuffer(max_rows=5, n_cols=3)
        snap = buf.snapshot()
        assert snap.shape == (5, 3)
        assert snap.dtype == np.float32
        np.testing.assert_array_equal(snap, 0.0)

    def test_single_append(self):
        buf = StructuredRingBuffer(max_rows=5, n_cols=3)
        row = np.array([1.0, 2.0, 3.0], dtype=np.float32)
        buf.append(row)
        snap = buf.snapshot()
        np.testing.assert_array_equal(snap[0], row)
        # Remaining rows are zero
        np.testing.assert_array_equal(snap[1:], 0.0)

    def test_fill_to_capacity(self):
        buf = StructuredRingBuffer(max_rows=3, n_cols=2)
        for i in range(3):
            buf.append(np.array([float(i), float(i * 10)], dtype=np.float32))
        snap = buf.snapshot()
        assert snap.shape == (3, 2)
        np.testing.assert_array_equal(snap[0], [0.0, 0.0])
        np.testing.assert_array_equal(snap[1], [1.0, 10.0])
        np.testing.assert_array_equal(snap[2], [2.0, 20.0])

    def test_overflow_drops_oldest(self):
        buf = StructuredRingBuffer(max_rows=3, n_cols=1)
        for i in range(5):
            buf.append(np.array([float(i)], dtype=np.float32))
        snap = buf.snapshot()
        # Should have [2, 3, 4] — oldest (0, 1) dropped
        np.testing.assert_array_equal(snap[:, 0], [2.0, 3.0, 4.0])

    def test_chronological_ordering(self):
        buf = StructuredRingBuffer(max_rows=4, n_cols=1)
        for i in range(6):
            buf.append(np.array([float(i)], dtype=np.float32))
        snap = buf.snapshot()
        # [2, 3, 4, 5] — chronological
        np.testing.assert_array_equal(snap[:, 0], [2.0, 3.0, 4.0, 5.0])

    def test_clear_resets(self):
        buf = StructuredRingBuffer(max_rows=3, n_cols=2)
        buf.append(np.array([1.0, 2.0], dtype=np.float32))
        buf.clear()
        assert buf.count == 0
        np.testing.assert_array_equal(buf.snapshot(), 0.0)

    def test_count_property(self):
        buf = StructuredRingBuffer(max_rows=5, n_cols=2)
        assert buf.count == 0
        buf.append(np.zeros(2, dtype=np.float32))
        assert buf.count == 1
        buf.append(np.zeros(2, dtype=np.float32))
        assert buf.count == 2
        # Fill past capacity
        for _ in range(10):
            buf.append(np.zeros(2, dtype=np.float32))
        assert buf.count == 5  # capped at max_rows

    def test_snapshot_is_copy(self):
        buf = StructuredRingBuffer(max_rows=3, n_cols=2)
        buf.append(np.array([1.0, 2.0], dtype=np.float32))
        snap = buf.snapshot()
        snap[0, 0] = 999.0
        # Internal buffer should be unmodified
        snap2 = buf.snapshot()
        assert snap2[0, 0] == 1.0
