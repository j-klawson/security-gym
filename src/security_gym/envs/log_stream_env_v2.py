"""V2 log stream environment with structured eBPF observation channels.

Text channels for human-readable logs; fixed-width float32 arrays for
kernel events. Subclasses SecurityLogStreamEnv — all defense logic,
reward computation, and ground truth are inherited.
"""

from __future__ import annotations

import collections
import json
from typing import Any

import numpy as np
from gymnasium import spaces

from security_gym.envs.ebpf_encoding import (
    FILE_COLS,
    NETWORK_COLS,
    PROCESS_COLS,
    extract_file_row,
    extract_network_row,
    extract_process_row,
)
from security_gym.envs.log_stream_env import (
    SecurityLogStreamEnv,
    _SOURCE_TO_CHANNEL,
)
from security_gym.envs.structured_buffer import StructuredRingBuffer

# Channel classifications
_TEXT_CHANNELS = ["auth_log", "syslog", "web_log"]
_STRUCTURED_CHANNELS = {
    "process_events": PROCESS_COLS,
    "network_events": NETWORK_COLS,
    "file_events": FILE_COLS,
}

# eBPF source → structured channel
_EBPF_SOURCE_MAP = {
    "ebpf_process": "process_events",
    "ebpf_network": "network_events",
    "ebpf_file": "file_events",
}

DEFAULT_TAIL_EVENTS = 50


class SecurityLogStreamEnvV2(SecurityLogStreamEnv):
    """V2 environment with hybrid text + structured observations.

    Log channels (auth_log, syslog, web_log) remain as Text spaces.
    eBPF channels (process_events, network_events, file_events) become
    Box(shape=(tail_events, N)) float32 arrays via StructuredRingBuffer.

    Args:
        db_path: Path to SQLite event database.
        tail_lines: Lines per text channel ring buffer.
        max_chars: Max characters per text channel.
        tail_events: Rows per structured eBPF channel ring buffer.
        throttle_drop_rate: Probability of dropping throttled events.
        reward_config: Optional reward weight overrides.
        render_mode: Gymnasium render mode.
    """

    def __init__(
        self,
        db_path: str,
        tail_lines: int = 500,
        max_chars: int = 50_000,
        tail_events: int = DEFAULT_TAIL_EVENTS,
        throttle_drop_rate: float = 0.9,
        reward_config: dict[str, Any] | None = None,
        render_mode: str | None = None,
    ):
        self.tail_events = tail_events

        super().__init__(
            db_path=db_path,
            tail_lines=tail_lines,
            max_chars=max_chars,
            throttle_drop_rate=throttle_drop_rate,
            reward_config=reward_config,
            render_mode=render_mode,
        )

        # Rebuild observation space with structured eBPF channels
        _printable = "".join(chr(i) for i in range(32, 127))
        text_space = spaces.Text(
            min_length=0, max_length=max_chars, charset=_printable,
        )
        self.observation_space = spaces.Dict({
            "auth_log": text_space,
            "syslog": text_space,
            "web_log": text_space,
            "process_events": spaces.Box(
                0, np.finfo(np.float32).max,
                shape=(tail_events, PROCESS_COLS), dtype=np.float32,
            ),
            "network_events": spaces.Box(
                0, np.finfo(np.float32).max,
                shape=(tail_events, NETWORK_COLS), dtype=np.float32,
            ),
            "file_events": spaces.Box(
                0, np.finfo(np.float32).max,
                shape=(tail_events, FILE_COLS), dtype=np.float32,
            ),
            "system_stats": spaces.Box(0, np.inf, shape=(3,), dtype=np.float32),
        })

        # Process tree depth tracker
        self._pid_depth: dict[int, int] = {}

        # Per-channel last timestamp for delta computation
        self._ebpf_last_ts: dict[str, float | None] = {
            ch: None for ch in _STRUCTURED_CHANNELS
        }

        # Structured ring buffers (initialized in _init_buffers)
        self._structured_buffers: dict[str, StructuredRingBuffer] = {}

    # ── Buffer management ───────────────────────────────────────────────

    def _init_buffers(self) -> None:
        """Initialize text deques + structured ring buffers."""
        self._buffers = {
            ch: collections.deque(maxlen=self.tail_lines)
            for ch in _TEXT_CHANNELS
        }
        self._structured_buffers = {
            ch: StructuredRingBuffer(self.tail_events, n_cols)
            for ch, n_cols in _STRUCTURED_CHANNELS.items()
        }
        self._pid_depth = {}
        self._ebpf_last_ts = {ch: None for ch in _STRUCTURED_CHANNELS}

    def _buffer_event(self, row: dict[str, Any]) -> None:
        """Route event to the appropriate text or structured buffer."""
        source = row.get("source", "")
        channel = _SOURCE_TO_CHANNEL.get(source, "syslog")

        if source in _EBPF_SOURCE_MAP:
            struct_channel = _EBPF_SOURCE_MAP[source]
            # Parse the JSON fields
            parsed_str = row.get("parsed")
            if parsed_str:
                try:
                    parsed = json.loads(parsed_str)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
            else:
                parsed = {}

            # Compute timestamp delta
            ts_epoch = self._row_ts_epoch(row)
            last = self._ebpf_last_ts.get(struct_channel)
            if last is not None and ts_epoch is not None:
                dt = ts_epoch - last
            else:
                dt = 0.0
            if ts_epoch is not None:
                self._ebpf_last_ts[struct_channel] = ts_epoch

            # Extract and append row
            if source == "ebpf_process":
                pid = parsed.get("pid", 0)
                ppid = parsed.get("ppid", 0)
                depth = self._pid_depth.get(ppid, 0) + 1 if ppid else 0
                self._pid_depth[pid] = depth
                encoded = extract_process_row(parsed, dt, depth=depth)
            elif source == "ebpf_network":
                encoded = extract_network_row(parsed, dt)
            else:  # ebpf_file
                encoded = extract_file_row(parsed, dt)

            self._structured_buffers[struct_channel].append(encoded)
        else:
            # Text channel
            if channel in self._buffers:
                self._buffers[channel].append(row["raw_line"])

    def _row_ts_epoch(self, row: dict[str, Any]) -> float | None:
        """Parse row timestamp to epoch seconds."""
        ts = self._parse_timestamp(row)
        return ts.timestamp()

    # ── Observation building ────────────────────────────────────────────

    def _build_observation(self) -> dict[str, Any]:
        """Build hybrid text + structured observation."""
        obs: dict[str, Any] = {}

        # Text channels
        for ch in _TEXT_CHANNELS:
            lines = list(self._buffers.get(ch, []))
            text = "\n".join(lines)
            if len(text) > self.max_chars:
                text = text[-self.max_chars:]
            obs[ch] = text

        # Structured eBPF channels
        for ch in _STRUCTURED_CHANNELS:
            obs[ch] = self._structured_buffers[ch].snapshot()

        # System stats placeholder
        obs["system_stats"] = np.array([0.5, 0.3, 0.2], dtype=np.float32)
        return obs

    def _empty_observation(self) -> dict[str, Any]:
        """Build empty observation with zero arrays for structured channels."""
        obs: dict[str, Any] = {ch: "" for ch in _TEXT_CHANNELS}
        for ch, n_cols in _STRUCTURED_CHANNELS.items():
            obs[ch] = np.zeros((self.tail_events, n_cols), dtype=np.float32)
        obs["system_stats"] = np.zeros(3, dtype=np.float32)
        return obs

    # ── Gymnasium interface overrides ───────────────────────────────────

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        # Duplicated from v1 with _buffer_event instead of inline append
        super(SecurityLogStreamEnv, self).reset(seed=seed)
        options = options or {}

        self._ensure_store()
        self._exhausted = False
        self._prev_timestamp = None
        self._init_buffers()

        # Reset defense state
        self._blocked_ips = set()
        self._throttled_ips = set()
        self._is_isolated = False
        self._events_dropped = 0
        self._ongoing_reward = 0.0

        # Seed throttle RNG
        self._throttle_rng = np.random.default_rng(seed)

        # Determine start position
        if "start_id" in options:
            self._cursor = int(options["start_id"])
        else:
            self._cursor = 0

        # Clear batch cache
        self._batch = []
        self._batch_idx = 0

        # Fetch first event
        row = self._advance()
        if row is None:
            self._exhausted = True
            return self._empty_observation(), {"exhausted": True}

        self._current_row = row
        ts = self._parse_timestamp(row)
        self._prev_timestamp = ts

        # Route to appropriate buffer
        self._buffer_event(row)

        obs = self._build_observation()
        gt = self._build_ground_truth(row)
        info = self._build_info(row, gt, 0.0)

        return obs, info

    def step(
        self, action: dict[str, Any],
    ) -> tuple[dict[str, Any], float, bool, bool, dict[str, Any]]:
        # Apply agent's action from previous observation
        if self._current_row is not None:
            src_ip = self._current_row.get("src_ip")
            self._apply_action(action, src_ip)

        # Advance to next visible event
        row = self._advance()

        if row is None:
            self._exhausted = True
            obs = self._empty_observation()
            gt = {
                "is_malicious": False, "attack_type": None,
                "attack_stage": None, "campaign_id": None, "true_risk": 0.0,
            }
            info = self._build_info(
                {"id": self._cursor, "timestamp": "", "source": "", "src_ip": None},
                gt, 0.0,
            )
            reward = self._compute_reward(action, gt)
            return obs, reward, False, True, info

        self._current_row = row
        ts = self._parse_timestamp(row)

        # Compute dt
        dt = 0.0
        if self._prev_timestamp is not None:
            dt = (ts - self._prev_timestamp).total_seconds()
        self._prev_timestamp = ts

        # Route to appropriate buffer
        self._buffer_event(row)

        # Build observation
        obs = self._build_observation()

        # Ground truth and reward
        gt = self._build_ground_truth(row)
        reward = self._compute_reward(action, gt)

        info = self._build_info(row, gt, dt)

        return obs, reward, False, False, info
