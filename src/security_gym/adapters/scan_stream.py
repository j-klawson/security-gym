"""Alberta framework adapter — reads EventStore directly for batch learning.

Provides SecurityGymStream, which bypasses the gymnasium env overhead and
feeds observations directly. Supports both the new v1 text observation
format and legacy numeric feature modes.

JAX is optional: collect_numpy() always works, collect() upgrades to JAX
arrays when available, and the iterator requires JAX for TimeStep.
"""

from __future__ import annotations

import collections
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from security_gym.data.event_store import EventStore
from security_gym.envs.ebpf_encoding import (
    extract_file_row,
    extract_network_row,
    extract_process_row,
)
from security_gym.envs.log_stream_env import (
    _CHANNELS,
    _RISK_MAP,
    _SOURCE_TO_CHANNEL,
    DEFAULT_MAX_CHARS,
    DEFAULT_TAIL_LINES,
)
from security_gym.envs.log_stream_env_v2 import (
    DEFAULT_TAIL_EVENTS,
    _EBPF_SOURCE_MAP,
    _STRUCTURED_CHANNELS,
    _TEXT_CHANNELS,
)
from security_gym.envs.structured_buffer import StructuredRingBuffer

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
        structured: bool = False,
        tail_events: int = DEFAULT_TAIL_EVENTS,
    ):
        self.db_path = Path(db_path)
        self.tail_lines = tail_lines
        self.max_chars = max_chars
        self.start_id = start_id
        self.batch_size = batch_size
        self.speed = speed
        self.loop = loop
        self.structured = structured
        self.tail_events = tail_events

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

    def _make_buffers(
        self,
    ) -> tuple[
        dict[str, collections.deque[str]],
        dict[str, StructuredRingBuffer] | None,
    ]:
        """Create buffer dicts based on structured mode."""
        if self.structured:
            text_bufs: dict[str, collections.deque[str]] = {
                ch: collections.deque(maxlen=self.tail_lines)
                for ch in _TEXT_CHANNELS
            }
            struct_bufs = {
                ch: StructuredRingBuffer(self.tail_events, n_cols)
                for ch, n_cols in _STRUCTURED_CHANNELS.items()
            }
            return text_bufs, struct_bufs
        else:
            all_bufs: dict[str, collections.deque[str]] = {
                ch: collections.deque(maxlen=self.tail_lines) for ch in _CHANNELS
            }
            return all_bufs, None

    def _buffer_event(
        self,
        row: dict[str, Any],
        text_buffers: dict[str, collections.deque[str]],
        struct_buffers: dict[str, StructuredRingBuffer] | None,
        pid_depth: dict[int, int],
        ebpf_last_ts: dict[str, float | None],
    ) -> None:
        """Route event to text or structured buffer."""
        source = row.get("source", "")

        if self.structured and source in _EBPF_SOURCE_MAP:
            struct_channel = _EBPF_SOURCE_MAP[source]
            assert struct_buffers is not None

            parsed_str = row.get("parsed")
            if parsed_str:
                try:
                    parsed = json.loads(parsed_str)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
            else:
                parsed = {}

            # Timestamp delta
            ts = self._parse_row_timestamp(row)
            ts_epoch = ts.timestamp() if ts else None
            last = ebpf_last_ts.get(struct_channel)
            dt = (ts_epoch - last) if (last is not None and ts_epoch is not None) else 0.0
            if ts_epoch is not None:
                ebpf_last_ts[struct_channel] = ts_epoch

            if source == "ebpf_process":
                pid = parsed.get("pid", 0)
                ppid = parsed.get("ppid", 0)
                depth = pid_depth.get(ppid, 0) + 1 if ppid else 0
                pid_depth[pid] = depth
                encoded = extract_process_row(parsed, dt, depth=depth)
            elif source == "ebpf_network":
                encoded = extract_network_row(parsed, dt)
            else:
                encoded = extract_file_row(parsed, dt)

            struct_buffers[struct_channel].append(encoded)
        else:
            channel = self._route_event(source)
            if channel in text_buffers:
                text_buffers[channel].append(row["raw_line"])

    def _build_observation(
        self,
        buffers: dict[str, collections.deque[str]],
        struct_buffers: dict[str, StructuredRingBuffer] | None = None,
    ) -> dict[str, Any]:
        """Build observation from ring buffers."""
        obs: dict[str, Any] = {}

        if self.structured and struct_buffers is not None:
            for ch in _TEXT_CHANNELS:
                lines = list(buffers.get(ch, []))
                text = "\n".join(lines)
                if len(text) > self.max_chars:
                    text = text[-self.max_chars:]
                obs[ch] = text
            for ch in _STRUCTURED_CHANNELS:
                obs[ch] = struct_buffers[ch].snapshot()
        else:
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
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Collect all events as observation dicts + ground truth lists.

        Returns:
            (observations, ground_truths) where observations is a list
            of observation dicts, and ground_truths is a list of ground
            truth dicts.
        """
        text_bufs, struct_bufs = self._make_buffers()
        pid_depth: dict[int, int] = {}
        ebpf_last_ts: dict[str, float | None] = {
            ch: None for ch in _STRUCTURED_CHANNELS
        }
        observations: list[dict[str, Any]] = []
        ground_truths: list[dict[str, Any]] = []

        for row in self._iter_rows(limit=limit, allow_loop=False):
            self._buffer_event(row, text_bufs, struct_bufs, pid_depth, ebpf_last_ts)

            obs = self._build_observation(text_bufs, struct_bufs)
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
        text_bufs, struct_bufs = self._make_buffers()
        pid_depth: dict[int, int] = {}
        ebpf_last_ts: dict[str, float | None] = {
            ch: None for ch in _STRUCTURED_CHANNELS
        }
        obs_buf: list[dict[str, Any]] = []
        gt_buf: list[dict[str, Any]] = []

        for row in self._iter_rows(allow_loop=False):
            self._buffer_event(row, text_bufs, struct_bufs, pid_depth, ebpf_last_ts)

            obs_buf.append(self._build_observation(text_bufs, struct_bufs))
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
        text_bufs, struct_bufs = self._make_buffers()
        pid_depth: dict[int, int] = {}
        ebpf_last_ts: dict[str, float | None] = {
            ch: None for ch in _STRUCTURED_CHANNELS
        }
        for row in self._iter_rows():
            self._buffer_event(row, text_bufs, struct_bufs, pid_depth, ebpf_last_ts)
            obs = self._build_observation(text_bufs, struct_bufs)
            gt = self._build_ground_truth(row)
            yield TimeStep(observation=obs, ground_truth=gt)
