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

# Block visibility modes (governs how a blocked IP's events are handled)
BLOCK_VISIBILITY_DROP = "drop"          # default: 100% invisible (legacy behavior)
BLOCK_VISIBILITY_DENY_LOG = "deny_log"  # surface as firewall deny-log entries
_VALID_BLOCK_VISIBILITY = (BLOCK_VISIBILITY_DROP, BLOCK_VISIBILITY_DENY_LOG)

# Prefix applied to a blocked IP's surfaced events under deny_log visibility.
# Ground-truth-blind: identical for benign and malicious events, so it leaks
# no is_malicious signal into the observation (models a real firewall deny-log).
DENY_LOG_PREFIX = "[FIREWALL DENY] "

# Defense-state observation channel (opt-in via defense_state_obs=True).
# Reports the agent's own control state: which sources it has blocked or
# throttled, whether the host is isolated, how much traffic those controls
# have suppressed, and whether the source of the current event is already
# under a control. Every field is a consequence of the agent's own actions,
# so the channel leaks no ground truth. Text mode renders operator-style
# status output; hybrid mode encodes the same facts as a fixed-width vector.
DEFENSE_STATE_COLS = 6
DEFENSE_STATE_MAX_LISTED = 20  # addresses enumerated in the text rendering

# Explicit action targeting (on by default since 0.6.0; target_slate_size=0 disables it).
#
# Without it every stateful action binds to the current event's src_ip, so the
# agent can only act on the host the stream happens to be showing it. That makes
# two things impossible: acting on evidence in a channel that carries no address
# (a suspicious execve in process_events, attributable to a host seen earlier in
# auth_log), and naming an already-blocked address for release, since a blocked
# host's events stop arriving.
#
# Targeting adds a `target` component to the action: index 0 keeps the current
# event's source, and 1..N name a slot in an observable slate of addresses seen
# anywhere in the stream. Addresses under a control are pinned in their slot, so
# they stay nameable for as long as they are blocked or throttled.
TARGET_CURRENT_EVENT = 0  # target index meaning "the source of the current event"
TARGET_SLATE_COLS = 3     # structured encoding: [addr_hash, is_blocked, is_throttled]

# Defaults for the two observability/targeting features. Both are on: an agent
# that cannot see its own controls has no state space, and one that cannot name
# a host cannot act on the 93.5% of events that carry no address. The
# pre-targeting contract is preserved by the `rlc2026-camera-ready` tag rather
# than by a flag. Pass 0 / False to reconstruct it.
#
# 64 slots is sized from the corpus: 200 to 400 distinct addresses are live per
# 5,000-addressed-event window, so 64 slots hold roughly 600 to 1,300 addressed
# events of history, about 10,000 to 20,000 stream steps. Wide enough for
# cross-channel correlation inside an attack episode, narrow enough to keep the
# action head at Discrete(65).
DEFAULT_TARGET_SLATE_SIZE = 64
DEFAULT_DEFENSE_STATE_OBS = True

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

    Observation: Dict of Text channels (tail of recent events) + Box system stats,
    plus a ``defense_state`` Text channel (``defense_state_obs``, default True)
    reporting the agent's own control state: blocked and throttled sources,
    isolation, suppressed-event count, event-seconds since the state last
    changed, and whether the source of the current event is already under a
    control. On by default since 0.6.0; ``defense_state_obs=False`` restores
    the pre-0.6.0 observation space. Every field except ``current_src`` is a
    consequence of the agent's own actions; ``current_src`` renders the current
    event's address, which on legacy kernel events is a label proxy
    (specs/SPEC-ENV.md ENV-R-060). Without it the agent has no observable record of what it has
    already done and must carry that state internally.
    Action: Dict of Discrete(6) action + Box(1) risk score.
    Reward: Asymmetric action costs + risk score MSE + ongoing consequence feedback.

    There are no MDP terminal states — ``terminated`` is always ``False``.
    ``truncated`` becomes ``True`` when the event stream is exhausted.

    Block recovery (opt-in, default-off; both compose):

    - ``block_visibility`` controls how a blocked IP's events are handled.
      ``"drop"`` (default) makes them 100% invisible for the rest of the
      episode (legacy behavior). ``"deny_log"`` keeps the firewall drop (the
      events still do not reach the server, so the consequence reward still
      fires) but *surfaces* each blocked event in the observation as a
      ground-truth-blind firewall deny-log line (prefixed ``DENY_LOG_PREFIX``).
      This lets the agent see a wrongly-blocked benign IP still hammering and
      issue an ``unblock`` on it (``unblock`` targets the current event's
      ``src_ip``), making the block→unblock loop reachable. ``block_visibility``
      governs only the 100%-block path, not isolation or throttle.

    - ``block_ttl`` (event-time seconds, ``None`` = permanent) auto-expires a
      block fail2ban-style: once ``block_ttl`` seconds of event-time have
      elapsed since the ban started, the IP is removed from the blocklist and
      its next event re-surfaces for a fresh decision.

    Reward/step accounting under ``deny_log``: when the current observation is
    a surfaced deny-log entry, the firewall (not the agent's live decision) is
    acting on that event, so the per-step action reward and risk term are zero
    and the event contributes only the consequence term
    (``+malicious_drop_reward`` / ``-benign_drop_penalty``). This avoids
    double-counting a single event under both the consequence and action terms.
    The agent's action on a denied event (e.g. ``unblock``) is graded on the
    next *live* event it produces. Consequence reward over an episode is
    identical to ``drop`` mode; ``deny_log`` only redistributes it across steps
    (one step per blocked event instead of accumulating into one) and increases
    episode length accordingly.
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
        block_visibility: str = BLOCK_VISIBILITY_DROP,
        block_ttl: float | None = None,
        defense_state_obs: bool = DEFAULT_DEFENSE_STATE_OBS,
        target_slate_size: int = DEFAULT_TARGET_SLATE_SIZE,
    ):
        super().__init__()
        self.db_path = Path(db_path)
        self.tail_lines = tail_lines
        self.max_chars = max_chars
        self.throttle_drop_rate = throttle_drop_rate
        self.render_mode = render_mode

        # Block-recovery configuration (opt-in; defaults preserve legacy semantics)
        if block_visibility not in _VALID_BLOCK_VISIBILITY:
            raise ValueError(
                f"block_visibility must be one of {_VALID_BLOCK_VISIBILITY}, "
                f"got {block_visibility!r}"
            )
        self.block_visibility = block_visibility
        self.block_ttl = float(block_ttl) if block_ttl is not None else None

        # Defense-state observability (on by default since 0.6.0; False restores
        # the pre-0.6.0 observation space)
        self.defense_state_obs = bool(defense_state_obs)

        # Explicit action targeting (default 64 slots since 0.6.0; 0 keeps the
        # implicit current-event binding and the pre-0.6.0 action space)
        if target_slate_size < 0:
            raise ValueError(f"target_slate_size must be >= 0, got {target_slate_size}")
        self.target_slate_size = int(target_slate_size)

        # Optional reward weight overrides
        self._reward_config = reward_config or {}
        self._include_risk_reward: bool = self._reward_config.get("include_risk_reward", False)
        self._risk_weight: float = float(self._reward_config.get("risk_weight", 0.1))
        self._benign_drop_penalty: float = float(self._reward_config.get("benign_drop_penalty", 0.5))
        self._malicious_drop_reward: float = float(self._reward_config.get("malicious_drop_reward", 0.1))

        # ── Observation space ────────────────────────────────────────
        # Use printable ASCII charset (log lines contain spaces, punctuation, etc.)
        # Printable ASCII plus newline: every text channel joins its ring buffer
        # with "\n", so a charset without it makes observation_space.contains()
        # false for any multi-line channel (the passive env checker warns on it).
        _printable = "\n" + "".join(chr(i) for i in range(32, 127))
        text_space = spaces.Text(min_length=0, max_length=max_chars, charset=_printable)
        obs_spaces: dict[str, spaces.Space] = {
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
        }
        if self.defense_state_obs:
            # The agent's own control state, rendered as command-style output
            obs_spaces["defense_state"] = text_space
        if self.target_slate_size:
            # The addressable slate. Observable by construction: an index into a
            # list the agent cannot see would not be learnable.
            obs_spaces["target_slate"] = text_space
        self.observation_space = spaces.Dict(obs_spaces)

        # ── Action space ─────────────────────────────────────────────
        action_spaces: dict[str, spaces.Space] = {
            "action": spaces.Discrete(6),
            "risk_score": spaces.Box(0.0, 10.0, shape=(1,), dtype=np.float32),
        }
        if self.target_slate_size:
            action_spaces["target"] = spaces.Discrete(self.target_slate_size + 1)
        self.action_space = spaces.Dict(action_spaces)

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

        # Per-IP ban start timestamp (event-time), for block_ttl expiry
        self._block_times: dict[str, datetime] = {}

        # Whether the current observation is a surfaced firewall deny-log entry
        # (deny_log visibility). Drives the reward double-count suppression.
        self._current_denied: bool = False

        # Event-time of the most recent defense-state change, for the
        # "time under the current controls" field of the defense-state channel
        self._last_defense_change: datetime | None = None

        # Addressable target slate (empty unless target_slate_size > 0)
        self._target_slate: list[str | None] = [None] * self.target_slate_size
        self._slate_seen: dict[str, int] = {}      # address -> recency tick
        self._addr_label: dict[str, bool] = {}     # address -> last observed is_malicious
        self._slate_tick: int = 0
        self._resolved_target: str | None = None   # address the last action acted on
        self._target_explicit: bool = False        # last action named a slate slot
        self._target_effective: bool = False       # last action changed the defense state

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

        Sets ``self._current_denied`` for every event returned: ``True`` only
        when a blocked IP's event is surfaced under ``deny_log`` visibility,
        ``False`` otherwise (including the exhaustion ``None`` return). The flag
        drives the reward double-count suppression in ``_compute_reward``.
        """
        while True:
            row = self._next_raw_row()
            if row is None:
                self._current_denied = False
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

            # Blocklist handling, with optional fail2ban-style TTL expiry.
            if src_ip and src_ip in self._blocked_ips:
                if self._block_expired(src_ip, row):
                    # Ban lapsed: release the IP and deliver this event live.
                    self._blocked_ips.discard(src_ip)
                    self._block_times.pop(src_ip, None)
                    self._stamp_defense_change()
                else:
                    self._events_dropped += 1
                    self._accumulate_consequence(row)
                    if self.block_visibility == BLOCK_VISIBILITY_DENY_LOG:
                        # Firewall still drops the event (consequence reward
                        # fired above), but it stays observable as a deny-log
                        # line so the agent can react (e.g. unblock the IP).
                        row["raw_line"] = self._render_denied_line(row)
                        self._current_denied = True
                        return row
                    # Default "drop" visibility: 100% invisible.
                    continue

            # Check throttle list — probabilistic drop
            if src_ip and src_ip in self._throttled_ips:
                if self._throttle_rng.random() < self.throttle_drop_rate:
                    self._events_dropped += 1
                    self._accumulate_consequence(row)
                    continue

            self._current_denied = False
            return row

    def _block_expired(self, src_ip: str, row: dict[str, Any]) -> bool:
        """Whether ``src_ip``'s ban has lapsed by ``block_ttl`` event-seconds.

        Returns ``False`` when no TTL is configured or no ban start time is
        recorded. Compares the candidate row's own timestamp against the ban
        start time stamped in ``_apply_action``.
        """
        if self.block_ttl is None:
            return False
        start = self._block_times.get(src_ip)
        if start is None:
            return False
        return (self._parse_timestamp(row) - start).total_seconds() >= self.block_ttl

    def _render_denied_line(self, row: dict[str, Any]) -> str:
        """Render a blocked event as a ground-truth-blind firewall deny-log line.

        A pure function of agent-observable fields (a static prefix plus the
        original raw line). It never references is_malicious, attack_type, or
        attack_stage, so the surfaced observation leaks no label.
        """
        return f"{DENY_LOG_PREFIX}{row.get('raw_line', '')}"

    def _accumulate_consequence(self, row: dict[str, Any]) -> None:
        """Accumulate ongoing reward/penalty for dropped events."""
        is_mal = row.get("is_malicious")
        if is_mal == 1:
            self._ongoing_reward += self._malicious_drop_reward
        elif is_mal == 0:
            self._ongoing_reward -= self._benign_drop_penalty

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

        if self.defense_state_obs:
            obs["defense_state"] = self._render_defense_state()
        if self.target_slate_size:
            obs["target_slate"] = self._render_target_slate()

        return obs

    def _empty_observation(self) -> dict[str, Any]:
        """Build an empty observation for exhausted/reset states."""
        obs: dict[str, Any] = {ch: "" for ch in _CHANNELS}
        obs["system_stats"] = np.zeros(3, dtype=np.float32)
        if self.defense_state_obs:
            obs["defense_state"] = self._render_defense_state()
        if self.target_slate_size:
            obs["target_slate"] = self._render_target_slate()
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
        """Compute combined reward: action + risk_score MSE + ongoing consequences.

        When the current observation is a surfaced firewall deny-log entry
        (``self._current_denied``), the firewall, not the agent's live decision,
        is acting on that event. The action and risk terms are zeroed so the
        event contributes only the consequence term, avoiding double-counting it
        under both the consequence reward (accrued when it was dropped) and the
        per-step action reward. The agent's action on a denied event is graded
        on the next live event it produces.
        """
        action = int(action_dict["action"])
        risk_pred = float(action_dict["risk_score"][0])

        if self._current_denied:
            # Denied (surfaced-blocked) step: only the consequence term applies.
            action_reward = 0.0
            risk_reward = 0.0
        else:
            # 1. Action reward (asymmetric)
            action_reward = self._action_reward(action, ground_truth)

            # 2. Risk score reward (negative MSE)
            true_risk = float(ground_truth["true_risk"])
            if self._include_risk_reward:
                risk_reward = -self._risk_weight * (risk_pred - true_risk) ** 2
            else:
                risk_reward = 0.0

        # 3. Ongoing consequence reward (from dropped events since last step)
        consequence_reward = self._ongoing_reward
        self._ongoing_reward = 0.0  # reset accumulator

        return action_reward + risk_reward + consequence_reward

    def _observe_address(self, row: dict[str, Any]) -> None:
        """Record an observed event's source address in the target slate.

        Called for every event that becomes visible to the agent, so the slate
        holds addresses seen anywhere in the stream rather than only the current
        one. Slots are stable: an address keeps its index until evicted, so the
        index the agent learns keeps its referent.

        Eviction is least-recently-seen among addresses that are *not* under a
        control. Blocked and throttled addresses are pinned, which is what keeps
        an already-blocked host nameable for release even under ``"drop"``
        visibility, where its events no longer arrive. If every slot is pinned,
        a newly seen address simply does not enter the slate; it remains
        reachable through target 0 while it is the current event.

        Also records the last observed ``is_malicious`` per address, which
        ``_compute_reward`` uses to grade an action aimed at a host other than
        the one on screen.
        """
        if not self.target_slate_size:
            return
        ip = row.get("src_ip")
        if not ip:
            return
        ip = str(ip)

        self._slate_tick += 1
        self._slate_seen[ip] = self._slate_tick
        is_mal = row.get("is_malicious")
        if is_mal is not None:
            self._addr_label[ip] = bool(is_mal)

        if ip in self._target_slate:
            return
        for i, slot in enumerate(self._target_slate):
            if slot is None:
                self._target_slate[i] = ip
                return
        evictable = [
            (self._slate_seen.get(addr, 0), i)
            for i, addr in enumerate(self._target_slate)
            if addr is not None
            and addr not in self._blocked_ips
            and addr not in self._throttled_ips
        ]
        if not evictable:
            return
        self._target_slate[min(evictable)[1]] = ip

    def _resolve_target(
        self, action_dict: dict[str, Any], src_ip: str | None,
    ) -> tuple[str | None, bool]:
        """Resolve an action's target address.

        Returns ``(address, explicit)``. Target 0 (and any action taken with
        targeting disabled) resolves to the current event's source, which is the
        legacy binding. A slate index resolves to whatever occupies that slot,
        or ``None`` if the slot is empty.
        """
        if not self.target_slate_size:
            return src_ip, False
        idx = int(action_dict.get("target", TARGET_CURRENT_EVENT))
        if idx == TARGET_CURRENT_EVENT:
            return src_ip, False
        slot = idx - 1
        if 0 <= slot < len(self._target_slate):
            return self._target_slate[slot], True
        return None, True

    def _render_target_slate(self) -> str:
        """Render the addressable slate as a numbered list.

        Index 0 is listed explicitly because it is the legacy binding and is
        always available. Control marks let the agent distinguish a host it has
        already acted on from one it has merely seen.
        """
        src = self._current_src_ip()
        lines = ["=== targets ===", f"  0 current_src: {src if src else 'none'}"]
        for i, addr in enumerate(self._target_slate, start=1):
            if addr is None:
                lines.append(f"  {i} -")
                continue
            marks = []
            if addr in self._blocked_ips:
                marks.append("BLOCKED")
            if addr in self._throttled_ips:
                marks.append("THROTTLED")
            suffix = f" [{'+'.join(marks)}]" if marks else ""
            lines.append(f"  {i} {addr}{suffix}")
        text = "\n".join(lines)
        return text[-self.max_chars:] if len(text) > self.max_chars else text

    def _target_slate_matrix(self) -> np.ndarray:
        """Encode the slate as ``(target_slate_size, TARGET_SLATE_COLS)`` float32.

        Columns: ``[addr_hash, is_blocked, is_throttled]``. Empty slots are all
        zero. The hash uses the same mmh3 seed as the structured eBPF channels'
        IP encoding, so an address hashes identically in both places and the
        agent can associate a slate slot with kernel telemetry.
        """
        from security_gym.envs.ebpf_encoding import SEED_IP, hash_string

        mat = np.zeros((self.target_slate_size, TARGET_SLATE_COLS), dtype=np.float32)
        for i, addr in enumerate(self._target_slate):
            if addr is None:
                continue
            mat[i, 0] = hash_string(addr, seed=SEED_IP)
            mat[i, 1] = 1.0 if addr in self._blocked_ips else 0.0
            mat[i, 2] = 1.0 if addr in self._throttled_ips else 0.0
        return mat

    def _action_reward(self, action: int, ground_truth: dict[str, Any]) -> float:
        """Action-term reward, graded against whatever the action acted on.

        Two rules apply to the three address-taking actions.

        An action that changed nothing scores 0.0. Paying a block in full when it
        dropped no traffic decouples reward from effect, and on these streams that
        is the common case rather than the corner case: 93.5% of `exp_30d_heavy_v4`
        events carry no address, almost all of them eBPF file and process events
        that have no peer address to record. Expect the action term to be zero on
        most steps; that is the intended semantics, not an anomaly.

        An action aimed at a slate address is graded on that address's last
        observed label rather than on whatever event happens to be on screen,
        which is what makes it coherent to block a host named from kernel
        evidence while looking at an unrelated event. The grading is causal: it
        uses only a label the agent has already been shown, and falls back to the
        current event when the address has never been seen labeled.
        """
        targeted = action in (ACTION_THROTTLE, ACTION_BLOCK_SOURCE, ACTION_UNBLOCK)
        if targeted:
            if not self._target_effective:
                return 0.0
            if self._target_explicit and self._resolved_target is not None:
                known = self._addr_label.get(self._resolved_target)
                if known is not None:
                    table = _ATTACK_REWARDS if known else _BENIGN_REWARDS
                    return table.get(action, 0.0)
        table = _ATTACK_REWARDS if ground_truth["is_malicious"] else _BENIGN_REWARDS
        return table.get(action, 0.0)

    def _apply_action(self, action_dict: dict[str, Any], src_ip: str | None) -> None:
        """Apply the agent's action to update defense state.

        With targeting enabled the acted-on address comes from ``_resolve_target``
        rather than always being the current event's source. ``_target_effective``
        records whether the action actually changed anything, which
        ``_compute_reward`` uses to avoid paying for an action that did nothing.
        """
        action = int(action_dict["action"])
        target, explicit = self._resolve_target(action_dict, src_ip)
        self._resolved_target = target
        self._target_explicit = explicit
        self._target_effective = False

        if action == ACTION_THROTTLE and target:
            if target not in self._throttled_ips:
                self._throttled_ips.add(target)
                self._stamp_defense_change()
            self._target_effective = True
        elif action == ACTION_BLOCK_SOURCE and target:
            if target not in self._blocked_ips:
                self._blocked_ips.add(target)
                self._stamp_defense_change()
            # Stamp (or restamp) the ban start time for block_ttl expiry. At
            # this point _prev_timestamp is the time of the event being acted
            # on, the correct fail2ban "ban start" anchor.
            if self._prev_timestamp is not None:
                self._block_times[target] = self._prev_timestamp
            self._target_effective = True
        elif action == ACTION_UNBLOCK and target:
            if target in self._blocked_ips or target in self._throttled_ips:
                self._stamp_defense_change()
                self._target_effective = True
            self._blocked_ips.discard(target)
            self._throttled_ips.discard(target)
            self._block_times.pop(target, None)
        elif action == ACTION_ISOLATE:
            if not self._is_isolated:
                self._stamp_defense_change()
            self._is_isolated = True
            self._target_effective = True

    def _stamp_defense_change(self) -> None:
        """Record the event-time at which the defense state last changed.

        Anchored on ``_prev_timestamp`` (the time of the event being acted on),
        the same anchor ``_apply_action`` uses for ``block_ttl`` ban starts.
        """
        if self._prev_timestamp is not None:
            self._last_defense_change = self._prev_timestamp

    def _seconds_under_current_state(self) -> float:
        """Event-seconds elapsed since the defense state last changed.

        Zero when the state has never changed, so a fresh episode and a
        just-changed state read alike (both are "no elapsed time under these
        controls"). Never negative.
        """
        if self._last_defense_change is None or self._prev_timestamp is None:
            return 0.0
        return max(0.0, (self._prev_timestamp - self._last_defense_change).total_seconds())

    def _current_src_ip(self) -> str | None:
        """Source IP of the event currently being observed, if any."""
        if self._current_row is None:
            return None
        ip = self._current_row.get("src_ip")
        return str(ip) if ip else None

    def _render_defense_state(self) -> str:
        """Render the defense state as operator-style status output.

        Models what an operator would learn from `fail2ban-client status` and
        `iptables -L`: what is currently blocked or throttled, whether the host
        is isolated, and how much traffic those controls have suppressed. The
        ``current_src`` line reports whether the source of the event now being
        observed is already under a control, which is what makes de-escalation
        (`unblock`) decidable from the observation rather than from agent memory.

        Ground-truth-blind: every field is a consequence of the agent's own
        actions. Address lists are sorted for determinism and truncated to
        ``DEFENSE_STATE_MAX_LISTED`` entries.
        """
        def _fmt(label: str, ips: set[str]) -> str:
            listed = sorted(ips)
            shown = listed[:DEFENSE_STATE_MAX_LISTED]
            more = len(listed) - len(shown)
            body = ", ".join(shown) if shown else "none"
            if more > 0:
                body += f", +{more} more"
            return f"{label} ({len(listed)}): {body}"

        src = self._current_src_ip()
        if src is None:
            current = "current_src: none"
        else:
            marks = []
            if src in self._blocked_ips:
                marks.append("BLOCKED")
            if src in self._throttled_ips:
                marks.append("THROTTLED")
            current = f"current_src: {src}" + (f" [{'+'.join(marks)}]" if marks else "")

        lines = [
            "=== defense state ===",
            _fmt("blocked", self._blocked_ips),
            _fmt("throttled", self._throttled_ips),
            f"isolation: {'on' if self._is_isolated else 'off'}",
            f"events_suppressed: {self._events_dropped}",
            f"seconds_since_change: {self._seconds_under_current_state():.0f}",
            current,
        ]
        text = "\n".join(lines)
        return text[-self.max_chars:] if len(text) > self.max_chars else text

    def _defense_state_vector(self) -> np.ndarray:
        """Encode the defense state as a fixed-width float32 vector.

        Columns: [n_blocked, n_throttled, is_isolated, current_src_blocked,
        current_src_throttled, seconds_since_last_change]. Carries the same
        facts as the text rendering minus the address list, which has no
        fixed-width encoding; the two membership flags preserve the part that
        bears on the current decision.
        """
        src = self._current_src_ip()
        return np.array([
            len(self._blocked_ips),
            len(self._throttled_ips),
            1.0 if self._is_isolated else 0.0,
            1.0 if (src is not None and src in self._blocked_ips) else 0.0,
            1.0 if (src is not None and src in self._throttled_ips) else 0.0,
            self._seconds_under_current_state(),
        ], dtype=np.float32)

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
            # What the last action actually bound to. Needed by an evaluation
            # harness to tell a targeted block from a hit on an empty slot;
            # without it, containment metrics cannot attribute an action.
            "action_target": self._resolved_target,
            "action_target_explicit": self._target_explicit,
            "action_effective": self._target_effective,
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
        self._block_times = {}
        self._current_denied = False
        self._last_defense_change = None
        self._target_slate = [None] * self.target_slate_size
        self._slate_seen = {}
        self._addr_label = {}
        self._slate_tick = 0
        self._resolved_target = None
        self._target_explicit = False
        self._target_effective = False

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
            self._current_row = None
            return self._empty_observation(), {"exhausted": True}

        self._current_row = row
        self._observe_address(row)
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
        self._observe_address(row)
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
