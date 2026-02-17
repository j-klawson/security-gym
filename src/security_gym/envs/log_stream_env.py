"""Continuous log stream Gymnasium environment for security prediction research."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gymnasium
import numpy as np
from gymnasium import spaces

from security_gym.data.event_store import EventStore
from security_gym.features.extractors import EventFeatureExtractor, FEATURE_DIM
from security_gym.features.hasher import FeatureHasher
from security_gym.parsers.base import ParsedEvent
from security_gym.targets.builder import N_HEADS, TargetBuilder

# Sentinel for inactive/unknown heads in info["targets"].
# All valid target values are in [0, 1], so -1.0 is unambiguous.
# NaN is used internally by TargetBuilder but replaced here because
# gymnasium's check_env uses np.allclose which treats NaN != NaN.
INACTIVE_HEAD = -1.0


class SecurityLogStreamEnv(gymnasium.Env):
    """Continuous log stream environment for security prediction research.

    Replays labeled events from a SQLite database. Each step advances the
    cursor to the next event and returns extracted features as the observation.

    There are no MDP terminal states — ``terminated`` is always ``False``.
    ``truncated`` becomes ``True`` when the event stream is exhausted.
    """

    metadata = {"render_modes": ["ansi"]}

    def __init__(
        self,
        db_path: str | Path,
        feature_mode: str = "event",
        feature_dim: int | None = None,
        hash_dim: int = 1024,
        sources: list[str] | None = None,
        render_mode: str | None = None,
    ):
        super().__init__()
        self.db_path = Path(db_path)
        self.feature_mode = feature_mode
        self.sources = sources
        self.render_mode = render_mode

        # Feature extractor
        if feature_mode == "event":
            self._extractor = EventFeatureExtractor()
            self._feature_dim = feature_dim or FEATURE_DIM
        elif feature_mode == "hashed":
            self._hasher = FeatureHasher(dim=hash_dim)
            self._feature_dim = feature_dim or hash_dim
        else:
            raise ValueError(f"Unknown feature_mode: {feature_mode!r}")

        self._target_builder = TargetBuilder()

        # Spaces
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf,
            shape=(self._feature_dim,), dtype=np.float32,
        )
        self.action_space = spaces.Discrete(1)  # Prediction-only: single no-op

        # State
        self._store: EventStore | None = None
        self._cursor: int = 0
        self._current_row: dict[str, Any] | None = None
        self._prev_timestamp: datetime | None = None
        self._batch: list = []
        self._batch_idx: int = 0
        self._batch_size: int = 1000
        self._exhausted: bool = False

    def _ensure_store(self) -> EventStore:
        if self._store is None:
            self._store = EventStore(self.db_path, mode="r")
        return self._store

    def _fetch_batch(self) -> None:
        """Fetch the next batch of events from the store."""
        store = self._ensure_store()
        self._batch = store.get_events(
            start_id=self._cursor, limit=self._batch_size, sources=self.sources,
        )
        self._batch_idx = 0

    def _next_row(self) -> dict[str, Any] | None:
        """Advance to the next event row, fetching batches as needed."""
        if self._batch_idx >= len(self._batch):
            self._fetch_batch()
            if not self._batch:
                return None
        row = self._batch[self._batch_idx]
        self._batch_idx += 1
        self._cursor = row["id"]
        return dict(row)

    def _row_to_parsed_event(self, row: dict[str, Any]) -> ParsedEvent:
        """Convert a database row back to a ParsedEvent for feature extraction."""
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

    @staticmethod
    def _targets_for_info(targets: np.ndarray) -> np.ndarray:
        """Replace NaN with INACTIVE_HEAD sentinel for info dict compatibility."""
        return np.where(np.isnan(targets), INACTIVE_HEAD, targets).astype(np.float32)

    def _build_ground_truth(self, row: dict[str, Any]) -> dict[str, Any] | None:
        """Extract ground truth fields from a database row."""
        if row.get("is_malicious") is None:
            return None
        return {
            "is_malicious": row["is_malicious"],
            "attack_type": row.get("attack_type"),
            "attack_stage": row.get("attack_stage"),
            "severity": row.get("severity"),
        }

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        super().reset(seed=seed)
        options = options or {}

        self._ensure_store()
        self._exhausted = False
        self._prev_timestamp = None

        # Determine start position
        if "start_id" in options:
            self._cursor = int(options["start_id"])
        elif "shuffle" in options and options["shuffle"]:
            store = self._ensure_store()
            n = store.count_events()
            if n > 0:
                self._cursor = self.np_random.integers(0, n)
            else:
                self._cursor = 0
        else:
            self._cursor = 0

        # Clear batch cache
        self._batch = []
        self._batch_idx = 0

        # Fetch first event
        row = self._next_row()
        if row is None:
            self._exhausted = True
            obs = np.zeros(self._feature_dim, dtype=np.float32)
            return obs, {"exhausted": True}

        self._current_row = row
        event = self._row_to_parsed_event(row)
        self._prev_timestamp = event.timestamp
        obs = self._extract_features(event, row["raw_line"])

        gt = self._build_ground_truth(row)
        targets = self._target_builder.build_targets(gt)

        info = {
            "targets": self._targets_for_info(targets),
            "ground_truth": gt,
            "event_id": row["id"],
            "timestamp": row["timestamp"],
            "dt_seconds": 0.0,
            "source": row["source"],
            "raw_line": row["raw_line"],
            "session_id": row.get("session_id"),
            "campaign_id": row.get("campaign_id"),
        }

        return obs, info

    def step(
        self, action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        row = self._next_row()

        if row is None:
            self._exhausted = True
            obs = np.zeros(self._feature_dim, dtype=np.float32)
            info = {
                "targets": np.full(N_HEADS, INACTIVE_HEAD, dtype=np.float32),
                "ground_truth": None,
                "event_id": self._cursor,
                "timestamp": "",
                "dt_seconds": 0.0,
                "source": "",
                "raw_line": "",
                "session_id": None,
                "campaign_id": None,
            }
            return obs, 0.0, False, True, info

        self._current_row = row
        event = self._row_to_parsed_event(row)

        # Compute dt
        dt = 0.0
        if self._prev_timestamp is not None:
            dt = (event.timestamp - self._prev_timestamp).total_seconds()
        self._prev_timestamp = event.timestamp

        # Features
        obs = self._extract_features(event, row["raw_line"])

        # Targets
        gt = self._build_ground_truth(row)
        targets = self._target_builder.build_targets(gt)

        # Reward: is_malicious (0.0 or 1.0)
        reward = float(row["is_malicious"]) if row.get("is_malicious") is not None else 0.0

        info = {
            "targets": self._targets_for_info(targets),
            "ground_truth": gt,
            "event_id": row["id"],
            "timestamp": row["timestamp"],
            "dt_seconds": dt,
            "source": row["source"],
            "raw_line": row["raw_line"],
            "session_id": row.get("session_id"),
            "campaign_id": row.get("campaign_id"),
        }

        return obs, reward, False, False, info

    def render(self) -> str | None:
        if self.render_mode != "ansi" or self._current_row is None:
            return None
        row = self._current_row
        is_mal = row.get("is_malicious")
        if is_mal == 1:
            prefix = "\033[91m[MALICIOUS]\033[0m"
        elif is_mal == 0:
            prefix = "\033[92m[BENIGN]\033[0m"
        else:
            prefix = "\033[93m[UNKNOWN]\033[0m"
        return f"{prefix} {row['raw_line']}"

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
