"""Gymnasium wrappers for feature transformation and temporal aggregation.

Four wrappers that can be composed around SecurityLogStreamEnv:

- HashedFeatureWrapper: replaces observations with hashed raw log text
- SessionAggregationWrapper: replaces observations with 20-dim session features
- WindowedWrapper: stacks a sliding window of observations into a flat vector
- DecayingTraceWrapper: eligibility-trace inspired time-based accumulation
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any

import gymnasium
import numpy as np
from gymnasium import spaces

from security_gym.features.hasher import FeatureHasher
from security_gym.features.session import SESSION_FEATURE_DIM, SessionFeatureExtractor
from security_gym.parsers.base import ParsedEvent


class HashedFeatureWrapper(gymnasium.Wrapper):
    """Replace observations with feature-hashed raw log text.

    Uses `info["raw_line"]` to produce a fixed-size hashed vector.
    """

    def __init__(self, env: gymnasium.Env, hash_dim: int = 1024):
        super().__init__(env)
        self._hasher = FeatureHasher(dim=hash_dim)
        self._hash_dim = hash_dim
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf,
            shape=(hash_dim,), dtype=np.float32,
        )

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        obs, info = self.env.reset(seed=seed, options=options)
        raw_line = info.get("raw_line", "")
        hashed = self._hasher.hash(raw_line) if raw_line else np.zeros(
            self._hash_dim, dtype=np.float32,
        )
        return hashed, info

    def step(
        self, action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        obs, reward, terminated, truncated, info = self.env.step(action)
        raw_line = info.get("raw_line", "")
        hashed = self._hasher.hash(raw_line) if raw_line else np.zeros(
            self._hash_dim, dtype=np.float32,
        )
        return hashed, reward, terminated, truncated, info


class SessionAggregationWrapper(gymnasium.Wrapper):
    """Replace observations with 20-dim session-aggregated features.

    Reconstructs a ParsedEvent from info dict fields and feeds it
    to a SessionFeatureExtractor.
    """

    def __init__(self, env: gymnasium.Env):
        super().__init__(env)
        self._extractor = SessionFeatureExtractor()
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf,
            shape=(SESSION_FEATURE_DIM,), dtype=np.float32,
        )

    def _info_to_event(self, info: dict[str, Any]) -> ParsedEvent:
        """Reconstruct a ParsedEvent from info dict fields."""
        ts_str = info.get("timestamp", "")
        if ts_str:
            try:
                ts = datetime.fromisoformat(ts_str)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                ts = datetime.now(timezone.utc)
        else:
            ts = datetime.now(timezone.utc)

        return ParsedEvent(
            timestamp=ts,
            source=info.get("source", ""),
            raw_line=info.get("raw_line", ""),
            event_type=info.get("event_type", "other"),
            fields={},
            src_ip=info.get("src_ip"),
            username=info.get("username"),
            session_id=info.get("session_id"),
        )

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        self._extractor.reset()
        obs, info = self.env.reset(seed=seed, options=options)
        if info.get("exhausted"):
            return np.zeros(SESSION_FEATURE_DIM, dtype=np.float32), info
        event = self._info_to_event(info)
        return self._extractor.extract(event), info

    def step(
        self, action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        obs, reward, terminated, truncated, info = self.env.step(action)
        if truncated and not info.get("raw_line"):
            return np.zeros(SESSION_FEATURE_DIM, dtype=np.float32), reward, terminated, truncated, info
        event = self._info_to_event(info)
        return self._extractor.extract(event), reward, terminated, truncated, info


class WindowedWrapper(gymnasium.Wrapper):
    """Stack a sliding window of observations into a flat vector.

    Maintains a FIFO deque of the last `window_size` observations.
    Zero-padded when the buffer is not full. Concatenates to a flat vector.

    Composable: e.g. WindowedWrapper(HashedFeatureWrapper(env))
    """

    def __init__(self, env: gymnasium.Env, window_size: int = 10):
        super().__init__(env)
        self._window_size = window_size
        inner_dim = int(np.prod(env.observation_space.shape))
        self._inner_dim = inner_dim
        self._buffer: deque[np.ndarray] = deque(maxlen=window_size)

        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf,
            shape=(window_size * inner_dim,), dtype=np.float32,
        )

    def _get_windowed_obs(self) -> np.ndarray:
        """Concatenate buffer into flat vector, zero-padding if needed."""
        pad_count = self._window_size - len(self._buffer)
        parts = [np.zeros(self._inner_dim, dtype=np.float32)] * pad_count
        parts.extend(self._buffer)
        return np.concatenate(parts).astype(np.float32)

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        self._buffer.clear()
        obs, info = self.env.reset(seed=seed, options=options)
        self._buffer.append(obs.flatten())
        return self._get_windowed_obs(), info

    def step(
        self, action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        obs, reward, terminated, truncated, info = self.env.step(action)
        self._buffer.append(obs.flatten())
        return self._get_windowed_obs(), reward, terminated, truncated, info


class DecayingTraceWrapper(gymnasium.Wrapper):
    """Eligibility-trace inspired time-based accumulation.

    Maintains a decaying trace vector: trace = trace * lambda^dt + obs
    where dt is the time in seconds between events (from info["dt_seconds"]).

    Rapid bursts accumulate while idle periods decay naturally.
    Observation space shape is unchanged from the inner environment.
    """

    def __init__(
        self, env: gymnasium.Env, lambda_: float = 0.95, dt_key: str = "dt_seconds",
    ):
        super().__init__(env)
        self._lambda = lambda_
        self._dt_key = dt_key
        inner_dim = int(np.prod(env.observation_space.shape))
        self._trace = np.zeros(inner_dim, dtype=np.float32)

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[np.ndarray, dict[str, Any]]:
        self._trace = np.zeros_like(self._trace)
        obs, info = self.env.reset(seed=seed, options=options)
        self._trace = obs.flatten().copy()
        return self._trace.copy(), info

    def step(
        self, action: int,
    ) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        obs, reward, terminated, truncated, info = self.env.step(action)
        dt = info.get(self._dt_key, 0.0)
        decay = self._lambda ** dt
        self._trace = self._trace * decay + obs.flatten()
        return self._trace.copy(), reward, terminated, truncated, info
