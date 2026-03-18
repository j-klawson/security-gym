"""Ring buffer for structured (numeric) eBPF observations.

Pre-allocated numpy array with O(1) append and chronological snapshot.
"""

from __future__ import annotations

import numpy as np


class StructuredRingBuffer:
    """Circular buffer storing fixed-width float32 rows.

    Args:
        max_rows: Maximum number of rows (ring capacity).
        n_cols: Number of columns per row.
    """

    def __init__(self, max_rows: int, n_cols: int) -> None:
        self._max_rows = max_rows
        self._n_cols = n_cols
        self._buf = np.zeros((max_rows, n_cols), dtype=np.float32)
        self._head = 0
        self._count = 0

    def append(self, row: np.ndarray) -> None:
        """Write a single row at the current head position."""
        self._buf[self._head % self._max_rows] = row
        self._head += 1
        if self._count < self._max_rows:
            self._count += 1

    def snapshot(self) -> np.ndarray:
        """Return (max_rows, n_cols) array in chronological order, zero-padded."""
        if self._count == 0:
            return np.zeros((self._max_rows, self._n_cols), dtype=np.float32)
        if self._count < self._max_rows:
            # Not yet full — data is at indices [0, count), rest is zeros
            out = np.zeros((self._max_rows, self._n_cols), dtype=np.float32)
            out[:self._count] = self._buf[:self._count]
            return out
        # Full — roll so oldest is first
        start = self._head % self._max_rows
        return np.roll(self._buf, -start, axis=0).copy()

    def clear(self) -> None:
        """Reset buffer to empty state."""
        self._buf[:] = 0.0
        self._head = 0
        self._count = 0

    @property
    def count(self) -> int:
        """Number of rows currently stored."""
        return self._count
