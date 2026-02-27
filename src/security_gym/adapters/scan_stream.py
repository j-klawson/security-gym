"""Alberta framework adapter — reads EventStore directly for batch learning.

Provides SecurityGymStream, which bypasses the gymnasium env overhead and
feeds (observations, targets) arrays directly to run_multi_head_learning_loop.

JAX is optional: collect_numpy() always works, collect() upgrades to JAX
arrays when available, and the iterator requires JAX for TimeStep.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import numpy as np

from security_gym.data.event_store import EventStore
from security_gym.features.extractors import EventFeatureExtractor, FEATURE_DIM
from security_gym.features.hasher import FeatureHasher
from security_gym.parsers.base import ParsedEvent
from security_gym.targets.builder import N_HEADS, TargetBuilder

try:
    import jax.numpy as jnp
    from typing import NamedTuple

    class TimeStep(NamedTuple):
        observation: jnp.ndarray
        target: jnp.ndarray

    HAS_JAX = True
except ImportError:
    HAS_JAX = False


class SecurityGymStream:
    """Stream adapter for Alberta framework's run_multi_head_learning_loop.

    Reads directly from EventStore using the same feature extraction and
    target building pipeline as SecurityLogStreamEnv, but bypasses gymnasium
    overhead. NaN targets are preserved natively (no -1.0 sentinel conversion).

    Args:
        db_path: Path to SQLite event database.
        feature_mode: "event" (24-dim) or "hashed" (hash_dim).
        hash_dim: Dimension for hashed features (only used when feature_mode="hashed").
        sources: Optional list of source types to filter by.
        start_id: Resume cursor — only read events with id > start_id.
        batch_size: Number of rows per SQLite fetch (internal pagination).
        speed: Pacing multiplier for server-speed mode. 0 = full speed (no sleeping,
            default), 1.0 = realtime, 10.0 = 10x faster than realtime.
        loop: When True, wrap cursor to 0 on exhaustion (never-ending stream).
    """

    def __init__(
        self,
        db_path: str | Path,
        feature_mode: str = "event",
        hash_dim: int = 1024,
        sources: list[str] | None = None,
        start_id: int = 0,
        batch_size: int = 5000,
        speed: float = 0,
        loop: bool = False,
    ):
        self.db_path = Path(db_path)
        self.feature_mode = feature_mode
        self.sources = sources
        self.start_id = start_id
        self.batch_size = batch_size
        self.speed = speed
        self.loop = loop

        if feature_mode == "event":
            self._extractor = EventFeatureExtractor()
            self._feature_dim = FEATURE_DIM
        elif feature_mode == "hashed":
            self._hasher = FeatureHasher(dim=hash_dim)
            self._feature_dim = hash_dim
        else:
            raise ValueError(f"Unknown feature_mode: {feature_mode!r}")

        self._target_builder = TargetBuilder()

    @property
    def feature_dim(self) -> int:
        return self._feature_dim

    @property
    def n_heads(self) -> int:
        return N_HEADS

    def __len__(self) -> int:
        """Total number of events in the store."""
        with EventStore(self.db_path, mode="r") as store:
            return int(store.count_events())

    def remaining(self) -> int:
        """Number of events with id > start_id."""
        with EventStore(self.db_path, mode="r") as store:
            if self.sources:
                placeholders = ",".join("?" for _ in self.sources)
                cursor = store.conn.execute(
                    f"SELECT COUNT(*) FROM events WHERE id > ? AND source IN ({placeholders})",  # nosec B608
                    [self.start_id, *self.sources],
                )
            else:
                cursor = store.conn.execute(
                    "SELECT COUNT(*) FROM events WHERE id > ?",
                    (self.start_id,),
                )
            return int(cursor.fetchone()[0])

    # ── Internal pipeline ──────────────────────────────────────────────

    def _row_to_parsed_event(self, row: dict[str, Any]) -> ParsedEvent:
        """Convert a database row to a ParsedEvent for feature extraction."""
        ts_str = row["timestamp"]
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            ts = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        parsed = json.loads(row["parsed"]) if row.get("parsed") else {}

        return ParsedEvent(
            timestamp=ts,
            source=row["source"],
            raw_line=row["raw_line"],
            event_type=parsed.get("pattern", "other"),
            fields=parsed,
            src_ip=row.get("src_ip"),
            username=row.get("username"),
            service=row.get("service"),
            session_id=row.get("session_id"),
        )

    def _extract_features(self, event: ParsedEvent, raw_line: str) -> np.ndarray:
        if self.feature_mode == "event":
            return self._extractor.extract(event)
        elif self.feature_mode == "hashed":
            return self._hasher.hash(raw_line)
        raise ValueError(f"Unknown feature_mode: {self.feature_mode!r}")

    def _build_targets(self, row: dict[str, Any]) -> np.ndarray:
        """Build target array from a database row. NaN for inactive heads."""
        if row.get("is_malicious") is None:
            return self._target_builder.build_targets(None)
        gt = {
            "is_malicious": row["is_malicious"],
            "attack_type": row.get("attack_type"),
            "attack_stage": row.get("attack_stage"),
            "severity": row.get("severity"),
        }
        return self._target_builder.build_targets(gt)

    def _parse_row_timestamp(self, row: dict[str, Any]) -> datetime | None:
        """Parse timestamp from a row dict, returning None on failure."""
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

        Supports speed-based pacing (sleep between events based on timestamp
        deltas) and loop mode (cursor wraps to 0 on exhaustion).

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

                rows = store.get_events(
                    start_id=cursor, limit=page_limit, sources=self.sources,
                )
                if not rows:
                    if loop and (limit is None or count < limit):
                        # Wrap around to beginning
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
    ) -> tuple[np.ndarray, np.ndarray]:
        """Collect all events as numpy arrays.

        Args:
            limit: Maximum number of events to collect. Useful for train/test splits.

        Returns:
            (observations, targets) — shapes (N, feature_dim) and (N, n_heads).
        """
        obs_list: list[np.ndarray] = []
        tgt_list: list[np.ndarray] = []

        for row in self._iter_rows(limit=limit, allow_loop=False):
            event = self._row_to_parsed_event(row)
            obs_list.append(self._extract_features(event, row["raw_line"]))
            tgt_list.append(self._build_targets(row))

        if not obs_list:
            return (
                np.empty((0, self._feature_dim), dtype=np.float32),
                np.empty((0, N_HEADS), dtype=np.float32),
            )

        return np.stack(obs_list), np.stack(tgt_list)

    def collect(
        self, limit: int | None = None,
    ) -> tuple[Any, Any]:
        """Collect events as JAX arrays if available, else numpy.

        Args:
            limit: Maximum number of events to collect.

        Returns:
            (observations, targets) as jnp.ndarray (if JAX available) or np.ndarray.
        """
        obs, tgt = self.collect_numpy(limit=limit)
        if HAS_JAX:
            return jnp.asarray(obs), jnp.asarray(tgt)
        return obs, tgt

    # ── Streaming interface ────────────────────────────────────────────

    def iter_batches(
        self, size: int = 1000,
    ) -> Iterator[tuple[np.ndarray, np.ndarray]]:
        """Yield (obs_batch, targets_batch) numpy arrays of at most `size` events.

        Keeps memory footprint constant regardless of database size.
        """
        obs_buf: list[np.ndarray] = []
        tgt_buf: list[np.ndarray] = []

        for row in self._iter_rows(allow_loop=False):
            event = self._row_to_parsed_event(row)
            obs_buf.append(self._extract_features(event, row["raw_line"]))
            tgt_buf.append(self._build_targets(row))

            if len(obs_buf) >= size:
                yield np.stack(obs_buf), np.stack(tgt_buf)
                obs_buf.clear()
                tgt_buf.clear()

        if obs_buf:
            yield np.stack(obs_buf), np.stack(tgt_buf)

    def __iter__(self) -> Iterator:
        """Yield TimeStep(observation, target) for each event. Requires JAX."""
        if not HAS_JAX:
            raise ImportError(
                "JAX is required for the iterator interface. "
                "Install with: pip install 'security-gym[alberta]'"
            )
        for row in self._iter_rows():
            event = self._row_to_parsed_event(row)
            obs = self._extract_features(event, row["raw_line"])
            tgt = self._build_targets(row)
            yield TimeStep(
                observation=jnp.asarray(obs),
                target=jnp.asarray(tgt),
            )
