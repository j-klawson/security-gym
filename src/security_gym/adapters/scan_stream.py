"""Alberta framework adapter — reads EventStore directly for batch learning.

Provides SecurityGymStream, which bypasses the gymnasium env overhead and
feeds observations directly. Supports both the new v1 text observation
format and legacy numeric feature modes.

JAX is optional: collect_numpy() always works, collect() upgrades to JAX
arrays when available, and the iterator requires JAX for TimeStep.
"""

from __future__ import annotations

import collections
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from security_gym.data.event_store import EventStore
from security_gym.envs.log_stream_env import (
    _CHANNELS,
    _RISK_MAP,
    _SOURCE_TO_CHANNEL,
    DEFAULT_MAX_CHARS,
    DEFAULT_TAIL_LINES,
)

try:
    import importlib.util
    HAS_JAX = importlib.util.find_spec("jax") is not None
except (ImportError, ModuleNotFoundError):
    HAS_JAX = False

if HAS_JAX:
    from typing import NamedTuple

    class TimeStep(NamedTuple):
        observation: dict[str, Any]
        ground_truth: dict[str, Any]


class SecurityGymStream:
    """Stream adapter for raw text observations from EventStore.

    Reads directly from EventStore, maintaining ring buffers per channel
    (same as SecurityLogStreamEnv), and yields text observations with
    ground truth metadata.

    Args:
        db_path: Path to SQLite event database.
        tail_lines: Number of lines per channel ring buffer.
        max_chars: Maximum characters per channel in observation.
        start_id: Resume cursor — only read events with id > start_id.
        batch_size: Number of rows per SQLite fetch (internal pagination).
        speed: Pacing multiplier. 0 = full speed, 1.0 = realtime, 10.0 = 10x.
        loop: When True, wrap cursor to 0 on exhaustion (never-ending stream).
    """

    def __init__(
        self,
        db_path: str | Path,
        tail_lines: int = DEFAULT_TAIL_LINES,
        max_chars: int = DEFAULT_MAX_CHARS,
        start_id: int = 0,
        batch_size: int = 5000,
        speed: float = 0,
        loop: bool = False,
    ):
        self.db_path = Path(db_path)
        self.tail_lines = tail_lines
        self.max_chars = max_chars
        self.start_id = start_id
        self.batch_size = batch_size
        self.speed = speed
        self.loop = loop

    @property
    def channels(self) -> list[str]:
        """Observation channel names."""
        return list(_CHANNELS)

    def __len__(self) -> int:
        """Total number of events in the store."""
        with EventStore(self.db_path, mode="r") as store:
            return int(store.count_events())

    def remaining(self) -> int:
        """Number of events with id > start_id."""
        with EventStore(self.db_path, mode="r") as store:
            cursor = store.conn.execute(
                "SELECT COUNT(*) FROM events WHERE id > ?",
                (self.start_id,),
            )
            return int(cursor.fetchone()[0])

    # ── Internal pipeline ──────────────────────────────────────────────

    def _route_event(self, source: str) -> str:
        """Map event source to observation channel."""
        return _SOURCE_TO_CHANNEL.get(source, "syslog")

    def _build_observation(
        self, buffers: dict[str, collections.deque],
    ) -> dict[str, Any]:
        """Build text observation from ring buffers."""
        obs: dict[str, Any] = {}
        for ch in _CHANNELS:
            lines = list(buffers.get(ch, []))
            text = "\n".join(lines)
            if len(text) > self.max_chars:
                text = text[-self.max_chars:]
            obs[ch] = text
        obs["system_stats"] = np.array([0.5, 0.3, 0.2], dtype=np.float32)
        return obs

    def _build_ground_truth(self, row: dict[str, Any]) -> dict[str, Any]:
        """Extract ground truth from a database row."""
        is_mal = row.get("is_malicious")
        attack_stage = row.get("attack_stage")
        return {
            "is_malicious": bool(is_mal) if is_mal is not None else False,
            "attack_type": row.get("attack_type"),
            "attack_stage": attack_stage,
            "campaign_id": row.get("campaign_id"),
            "true_risk": _RISK_MAP.get(attack_stage if is_mal else None, 0.0),
        }

    def _parse_row_timestamp(self, row: dict[str, Any]) -> datetime | None:
        """Parse timestamp from a row dict."""
        ts_str = row.get("timestamp")
        if not ts_str:
            return None
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts
        except ValueError:
            return None

    def _iter_rows(
        self, limit: int | None = None, *, allow_loop: bool = True,
    ) -> Iterator[dict[str, Any]]:
        """Paginated EventStore reads. Yields dict rows.

        Args:
            limit: Maximum number of rows to yield.
            allow_loop: If False, ignore self.loop (used by batch methods).
        """
        loop = self.loop and allow_loop

        with EventStore(self.db_path, mode="r") as store:
            cursor = self.start_id
            count = 0
            prev_ts: datetime | None = None

            while True:
                page_limit = self.batch_size
                if limit is not None:
                    page_limit = min(page_limit, limit - count)
                    if page_limit <= 0:
                        break

                rows = store.get_events(start_id=cursor, limit=page_limit)
                if not rows:
                    if loop and (limit is None or count < limit):
                        cursor = 0
                        prev_ts = None
                        continue
                    break

                for row in rows:
                    row_dict = dict(row)

                    # Speed-based pacing
                    if self.speed > 0:
                        cur_ts = self._parse_row_timestamp(row_dict)
                        if prev_ts is not None and cur_ts is not None:
                            dt = (cur_ts - prev_ts).total_seconds()
                            if dt > 0:
                                time.sleep(dt / self.speed)
                        prev_ts = cur_ts

                    yield row_dict
                    cursor = row["id"]
                    count += 1

                    if limit is not None and count >= limit:
                        return

    # ── Batch interface ────────────────────────────────────────────────

    def collect_numpy(
        self, limit: int | None = None,
    ) -> tuple[dict[str, list], list[dict[str, Any]]]:
        """Collect all events as observation dicts + ground truth lists.

        Returns:
            (observations, ground_truths) where observations is a dict
            mapping channel names to lists of strings, and ground_truths
            is a list of ground truth dicts.
        """
        buffers = {ch: collections.deque(maxlen=self.tail_lines) for ch in _CHANNELS}
        observations: list[dict[str, Any]] = []
        ground_truths: list[dict[str, Any]] = []

        for row in self._iter_rows(limit=limit, allow_loop=False):
            # Add to buffer
            channel = self._route_event(row.get("source", ""))
            buffers[channel].append(row["raw_line"])

            # Build observation snapshot
            obs = self._build_observation(buffers)
            observations.append(obs)
            ground_truths.append(self._build_ground_truth(row))

        return observations, ground_truths

    def collect(
        self, limit: int | None = None,
    ) -> tuple[Any, Any]:
        """Collect events. Returns same format as collect_numpy."""
        return self.collect_numpy(limit=limit)

    # ── Streaming interface ────────────────────────────────────────────

    def iter_batches(
        self, size: int = 1000,
    ) -> Iterator[tuple[list[dict[str, Any]], list[dict[str, Any]]]]:
        """Yield (obs_batch, gt_batch) of at most `size` events.

        Each batch contains lists of observation dicts and ground truth dicts.
        """
        buffers = {ch: collections.deque(maxlen=self.tail_lines) for ch in _CHANNELS}
        obs_buf: list[dict[str, Any]] = []
        gt_buf: list[dict[str, Any]] = []

        for row in self._iter_rows(allow_loop=False):
            channel = self._route_event(row.get("source", ""))
            buffers[channel].append(row["raw_line"])

            obs_buf.append(self._build_observation(buffers))
            gt_buf.append(self._build_ground_truth(row))

            if len(obs_buf) >= size:
                yield obs_buf, gt_buf
                obs_buf = []
                gt_buf = []

        if obs_buf:
            yield obs_buf, gt_buf

    def __iter__(self) -> Iterator:
        """Yield TimeStep(observation, ground_truth) for each event. Requires JAX."""
        if not HAS_JAX:
            raise ImportError(
                "JAX is required for the iterator interface. "
                "Install with: pip install 'security-gym[alberta]'"
            )
        buffers = {ch: collections.deque(maxlen=self.tail_lines) for ch in _CHANNELS}
        for row in self._iter_rows():
            channel = self._route_event(row.get("source", ""))
            buffers[channel].append(row["raw_line"])
            obs = self._build_observation(buffers)
            gt = self._build_ground_truth(row)
            yield TimeStep(observation=obs, ground_truth=gt)
