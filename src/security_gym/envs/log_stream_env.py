"""Continuous log stream Gymnasium environment for security defense research.

The agent observes raw text streams (like `tail -N` of log files and kernel
event channels) and takes defensive actions (block, throttle, alert, isolate)
that causally affect future observations.
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import gymnasium
import numpy as np
from gymnasium import spaces

from security_gym.data.event_store import EventStore

# ── Constants ────────────────────────────────────────────────────────

DEFAULT_TAIL_LINES = 500
DEFAULT_MAX_CHARS = 50_000
DEFAULT_THROTTLE_DROP_RATE = 0.9

# Action indices
ACTION_PASS = 0
ACTION_ALERT = 1
ACTION_THROTTLE = 2
ACTION_BLOCK_SOURCE = 3
ACTION_UNBLOCK = 4
ACTION_ISOLATE = 5

# Ground truth risk score mapping: attack_stage → risk value
_RISK_MAP = {
    None: 0.0,           # benign
    "recon": 3.0,        # reconnaissance
    "initial_access": 5.0,  # brute force / credential stuffing
    "execution": 8.0,    # active exploitation
    "persistence": 9.0,  # establishing persistence
    "exfiltration": 10.0,  # data exfiltration
}

# Action reward tables
_ATTACK_REWARDS = {
    ACTION_PASS: -0.5,
    ACTION_ALERT: 0.5,
    ACTION_THROTTLE: 0.75,
    ACTION_BLOCK_SOURCE: 1.0,
    ACTION_UNBLOCK: -0.5,  # unblocking during attack is bad
    ACTION_ISOLATE: 0.25,
}

_BENIGN_REWARDS = {
    ACTION_PASS: 0.0,
    ACTION_ALERT: -0.3,
    ACTION_THROTTLE: -0.5,
    ACTION_BLOCK_SOURCE: -1.0,
    ACTION_UNBLOCK: 0.0,  # unblocking during benign is neutral
    ACTION_ISOLATE: -2.0,
}

# Map event sources → observation channels
_SOURCE_TO_CHANNEL = {
    "auth_log": "auth_log",
    "syslog": "syslog",
    "web_access": "web_log",
    "web_error": "web_log",
    "ebpf_process": "process_events",
    "ebpf_network": "network_events",
    "ebpf_file": "file_events",
    "journal": "syslog",  # journal events go to syslog channel
}

# All observation channels
_CHANNELS = [
    "auth_log", "syslog", "web_log",
    "process_events", "network_events", "file_events",
]


class SecurityLogStreamEnv(gymnasium.Env):
    """Continuous log stream environment for security defense research.

    The agent observes raw text streams (log files + kernel events) and
    takes defensive actions that causally affect future observations.

    Observation: Dict of Text channels (tail of recent events) + Box system stats.
    Action: Dict of Discrete(6) action + Box(1) risk score.
    Reward: Asymmetric action costs + risk score MSE + ongoing consequence feedback.

    There are no MDP terminal states — ``terminated`` is always ``False``.
    ``truncated`` becomes ``True`` when the event stream is exhausted.
    """

    metadata = {"render_modes": ["ansi"]}

    def __init__(
        self,
        db_path: str | Path,
        tail_lines: int = DEFAULT_TAIL_LINES,
        max_chars: int = DEFAULT_MAX_CHARS,
        throttle_drop_rate: float = DEFAULT_THROTTLE_DROP_RATE,
        reward_config: dict[str, Any] | None = None,
        render_mode: str | None = None,
    ):
        super().__init__()
        self.db_path = Path(db_path)
        self.tail_lines = tail_lines
        self.max_chars = max_chars
        self.throttle_drop_rate = throttle_drop_rate
        self.render_mode = render_mode

        # Optional reward weight overrides
        self._reward_config = reward_config or {}

        # ── Observation space ────────────────────────────────────────
        # Use printable ASCII charset (log lines contain spaces, punctuation, etc.)
        _printable = "".join(chr(i) for i in range(32, 127))
        text_space = spaces.Text(min_length=0, max_length=max_chars, charset=_printable)
        self.observation_space = spaces.Dict({
            # Log event streams
            "auth_log": text_space,
            "syslog": text_space,
            "web_log": text_space,
            # Kernel event streams
            "process_events": text_space,
            "network_events": text_space,
            "file_events": text_space,
            # Lightweight numeric stats
            "system_stats": spaces.Box(0, np.inf, shape=(3,), dtype=np.float32),
        })

        # ── Action space ─────────────────────────────────────────────
        self.action_space = spaces.Dict({
            "action": spaces.Discrete(6),
            "risk_score": spaces.Box(0.0, 10.0, shape=(1,), dtype=np.float32),
        })

        # ── Internal state ───────────────────────────────────────────
        self._store: EventStore | None = None
        self._cursor: int = 0
        self._current_row: dict[str, Any] | None = None
        self._prev_timestamp: datetime | None = None
        self._batch: list = []
        self._batch_idx: int = 0
        self._batch_size: int = 1000
        self._exhausted: bool = False

        # Ring buffers for each channel (tail of recent lines)
        self._buffers: dict[str, collections.deque] = {}

        # Defense state
        self._blocked_ips: set[str] = set()
        self._throttled_ips: set[str] = set()
        self._is_isolated: bool = False
        self._events_dropped: int = 0

        # Ongoing consequence accumulator for blocked/throttled events
        self._ongoing_reward: float = 0.0

        # RNG for throttle probabilistic dropping
        self._throttle_rng = np.random.default_rng()

    def _ensure_store(self) -> EventStore:
        if self._store is None:
            self._store = EventStore(self.db_path, mode="r")
        return self._store

    def _init_buffers(self) -> None:
        """Initialize empty ring buffers for each observation channel."""
        self._buffers = {
            ch: collections.deque(maxlen=self.tail_lines) for ch in _CHANNELS
        }

    def _fetch_batch(self) -> None:
        """Fetch the next batch of events from the store."""
        store = self._ensure_store()
        self._batch = store.get_events(
            start_id=self._cursor, limit=self._batch_size,
        )
        self._batch_idx = 0

    def _next_raw_row(self) -> dict[str, Any] | None:
        """Get the next raw row from the DB (before filtering)."""
        if self._batch_idx >= len(self._batch):
            self._fetch_batch()
            if not self._batch:
                return None
        row = self._batch[self._batch_idx]
        self._batch_idx += 1
        self._cursor = row["id"]
        return dict(row)

    def _advance(self) -> dict[str, Any] | None:
        """Advance to next visible event, applying blocklist/throttle/isolation.

        Skipped events contribute to ongoing_reward (consequence feedback).
        """
        while True:
            row = self._next_raw_row()
            if row is None:
                return None

            src_ip = row.get("src_ip")
            source = row.get("source", "")
            is_network_event = source in (
                "ebpf_network", "web_access", "web_error", "auth_log",
            )

            # Check isolation — blocks all network-originated events
            if self._is_isolated and is_network_event:
                self._events_dropped += 1
                self._accumulate_consequence(row)
                continue

            # Check blocklist — 100% drop
            if src_ip and src_ip in self._blocked_ips:
                self._events_dropped += 1
                self._accumulate_consequence(row)
                continue

            # Check throttle list — probabilistic drop
            if src_ip and src_ip in self._throttled_ips:
                if self._throttle_rng.random() < self.throttle_drop_rate:
                    self._events_dropped += 1
                    self._accumulate_consequence(row)
                    continue

            return row

    def _accumulate_consequence(self, row: dict[str, Any]) -> None:
        """Accumulate ongoing reward/penalty for dropped events."""
        is_mal = row.get("is_malicious")
        if is_mal == 1:
            self._ongoing_reward += 0.05  # confirmed mitigation
        elif is_mal == 0:
            self._ongoing_reward -= 0.1  # service impact — legit user denied

    def _route_event(self, source: str) -> str:
        """Map event source to observation channel name."""
        return _SOURCE_TO_CHANNEL.get(source, "syslog")

    def _build_observation(self) -> dict[str, Any]:
        """Build the observation dict from current ring buffers."""
        obs: dict[str, Any] = {}
        for ch in _CHANNELS:
            lines = list(self._buffers.get(ch, []))
            text = "\n".join(lines)
            # Truncate to max_chars (keep most recent = end of string)
            if len(text) > self.max_chars:
                text = text[-self.max_chars:]
            obs[ch] = text

        # System stats: [load_avg, mem_used_frac, disk_used_frac]
        # In replay mode these are synthetic/placeholder
        obs["system_stats"] = np.array([0.5, 0.3, 0.2], dtype=np.float32)

        return obs

    def _empty_observation(self) -> dict[str, Any]:
        """Build an empty observation for exhausted/reset states."""
        obs: dict[str, Any] = {ch: "" for ch in _CHANNELS}
        obs["system_stats"] = np.zeros(3, dtype=np.float32)
        return obs

    @staticmethod
    def _ground_truth_risk(attack_stage: str | None) -> float:
        """Map attack_stage to ground truth risk score [0, 10]."""
        return _RISK_MAP.get(attack_stage, 0.0)

    def _build_ground_truth(self, row: dict[str, Any]) -> dict[str, Any]:
        """Extract ground truth fields from a database row."""
        is_mal = row.get("is_malicious")
        attack_stage = row.get("attack_stage")
        return {
            "is_malicious": bool(is_mal) if is_mal is not None else False,
            "attack_type": row.get("attack_type"),
            "attack_stage": attack_stage,
            "campaign_id": row.get("campaign_id"),
            "true_risk": self._ground_truth_risk(attack_stage if is_mal else None),
        }

    def _compute_reward(
        self,
        action_dict: dict[str, Any],
        ground_truth: dict[str, Any],
    ) -> float:
        """Compute combined reward: action + risk_score MSE + ongoing consequences."""
        action = int(action_dict["action"])
        risk_pred = float(action_dict["risk_score"][0])

        # 1. Action reward (asymmetric)
        is_mal = ground_truth["is_malicious"]
        if is_mal:
            action_reward = _ATTACK_REWARDS.get(action, 0.0)
        else:
            action_reward = _BENIGN_REWARDS.get(action, 0.0)

        # 2. Risk score reward (negative MSE)
        true_risk = float(ground_truth["true_risk"])
        risk_reward = -0.1 * (risk_pred - true_risk) ** 2

        # 3. Ongoing consequence reward (from dropped events since last step)
        consequence_reward = self._ongoing_reward
        self._ongoing_reward = 0.0  # reset accumulator

        return action_reward + risk_reward + consequence_reward

    def _apply_action(self, action_dict: dict[str, Any], src_ip: str | None) -> None:
        """Apply the agent's action to update defense state."""
        action = int(action_dict["action"])

        if action == ACTION_THROTTLE and src_ip:
            self._throttled_ips.add(src_ip)
        elif action == ACTION_BLOCK_SOURCE and src_ip:
            self._blocked_ips.add(src_ip)
        elif action == ACTION_UNBLOCK and src_ip:
            self._blocked_ips.discard(src_ip)
            self._throttled_ips.discard(src_ip)
        elif action == ACTION_ISOLATE:
            self._is_isolated = True

    def _build_info(
        self,
        row: dict[str, Any],
        ground_truth: dict[str, Any],
        dt: float,
    ) -> dict[str, Any]:
        """Build the info dict for a step."""
        return {
            "event_id": row["id"],
            "timestamp": row["timestamp"],
            "dt_seconds": dt,
            "source": row.get("source", ""),
            "src_ip": row.get("src_ip"),
            "ground_truth": ground_truth,
            "throttled_ips": sorted(self._throttled_ips),
            "blocked_ips": sorted(self._blocked_ips),
            "is_isolated": self._is_isolated,
            "events_dropped": self._events_dropped,
        }

    def _parse_timestamp(self, row: dict[str, Any]) -> datetime:
        """Parse timestamp from a DB row."""
        ts_str = row.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str)
        except ValueError:
            ts = datetime.now(timezone.utc)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts

    # ── Gymnasium interface ──────────────────────────────────────────

    def reset(
        self, *, seed: int | None = None, options: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        super().reset(seed=seed)
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

        # Add to ring buffer
        channel = self._route_event(row.get("source", ""))
        self._buffers[channel].append(row["raw_line"])

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
            gt = {"is_malicious": False, "attack_type": None,
                  "attack_stage": None, "campaign_id": None, "true_risk": 0.0}
            info = self._build_info(
                {"id": self._cursor, "timestamp": "", "source": "", "src_ip": None},
                gt, 0.0,
            )
            # Compute reward for the action on the last event
            reward = self._compute_reward(action, gt)
            return obs, reward, False, True, info

        self._current_row = row
        ts = self._parse_timestamp(row)

        # Compute dt
        dt = 0.0
        if self._prev_timestamp is not None:
            dt = (ts - self._prev_timestamp).total_seconds()
        self._prev_timestamp = ts

        # Add to ring buffer
        channel = self._route_event(row.get("source", ""))
        self._buffers[channel].append(row["raw_line"])

        # Build observation
        obs = self._build_observation()

        # Ground truth and reward
        gt = self._build_ground_truth(row)
        reward = self._compute_reward(action, gt)

        info = self._build_info(row, gt, dt)

        return obs, reward, False, False, info

    def render(self) -> str | None:  # type: ignore[override]
        if self.render_mode != "ansi" or self._current_row is None:
            return None
        row = self._current_row
        is_mal = row.get("is_malicious")
        source = row.get("source", "")
        if is_mal == 1:
            prefix = "\033[91m[MALICIOUS]\033[0m"
        elif is_mal == 0:
            prefix = "\033[92m[BENIGN]\033[0m"
        else:
            prefix = "\033[93m[UNKNOWN]\033[0m"

        blocked = f" blocked={len(self._blocked_ips)}" if self._blocked_ips else ""
        throttled = f" throttled={len(self._throttled_ips)}" if self._throttled_ips else ""
        isolated = " [ISOLATED]" if self._is_isolated else ""

        return f"{prefix} [{source}]{blocked}{throttled}{isolated} {row['raw_line']}"

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
