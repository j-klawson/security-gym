"""Session-aggregated feature extraction (20-dim).

Maintains per-session state and produces a 20-dimensional feature vector
per event. Raw counts are unnormalized — Alberta's online normalizer handles
scaling during training.

Feature layout:
  0: event_count           Total events in this session
  1: auth_success_count    Auth successes
  2: auth_failure_count    Auth failures
  3: auth_invalid_count    Invalid user attempts
  4: connection_count      Connection events
  5: session_open_count    Session opens
  6: session_close_count   Session closes
  7: http_request_count    HTTP requests
  8: http_error_count      HTTP errors
  9: other_event_count     Other events
 10: unique_usernames      Distinct usernames seen
 11: unique_ips            Distinct source IPs seen
 12: subnet_entropy        Shannon entropy of /24 subnets
 13: auth_failure_ratio    failures / max(auth_attempts, 1)
 14: session_duration      Seconds since first event
 15: mean_inter_event_dt   Mean seconds between events
 16: hour_sin              Cyclic hour encoding (sin)
 17: hour_cos              Cyclic hour encoding (cos)
 18: day_sin               Cyclic day-of-week encoding (sin)
 19: day_cos               Cyclic day-of-week encoding (cos)
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np

from security_gym.parsers.base import ParsedEvent

SESSION_FEATURE_DIM = 20

# Event type -> counter index mapping
_TYPE_COUNTER_MAP = {
    "auth_success": "auth_success",
    "auth_failure": "auth_failure",
    "auth_invalid_user": "auth_invalid",
    "connection": "connection",
    "session_open": "session_open",
    "session_close": "session_close",
    "http_request": "http_request",
    "http_error": "http_error",
}


@dataclass
class SessionState:
    """Per-session accumulated state."""

    event_count: int = 0
    auth_success_count: int = 0
    auth_failure_count: int = 0
    auth_invalid_count: int = 0
    connection_count: int = 0
    session_open_count: int = 0
    session_close_count: int = 0
    http_request_count: int = 0
    http_error_count: int = 0
    other_event_count: int = 0

    usernames: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    subnets: Counter = field(default_factory=Counter)

    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    dt_sum: float = 0.0
    dt_count: int = 0


def _subnet_entropy(subnets: Counter) -> float:
    """Shannon entropy of /24 subnet distribution."""
    total = sum(subnets.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in subnets.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def _extract_subnet(ip: str) -> str:
    """Extract /24 subnet prefix (first 3 octets)."""
    parts = ip.split(".")
    if len(parts) >= 3:
        return ".".join(parts[:3])
    return ip


class SessionFeatureExtractor:
    """Extract 20-dim session-aggregated features from log events.

    Maintains per-session state keyed by session_id -> src_ip -> "unknown".
    """

    feature_dim: int = SESSION_FEATURE_DIM

    def __init__(self):
        self._sessions: dict[str, SessionState] = {}

    def _get_session_key(self, event: ParsedEvent) -> str:
        if event.session_id:
            return event.session_id
        if event.src_ip:
            return event.src_ip
        return "unknown"

    def _get_session(self, key: str) -> SessionState:
        if key not in self._sessions:
            self._sessions[key] = SessionState()
        return self._sessions[key]

    def extract(self, event: ParsedEvent) -> np.ndarray:
        """Extract 20-dim feature vector, updating session state."""
        key = self._get_session_key(event)
        state = self._get_session(key)

        # Update counts
        state.event_count += 1

        counter_key = _TYPE_COUNTER_MAP.get(event.event_type)
        if counter_key == "auth_success":
            state.auth_success_count += 1
        elif counter_key == "auth_failure":
            state.auth_failure_count += 1
        elif counter_key == "auth_invalid":
            state.auth_invalid_count += 1
        elif counter_key == "connection":
            state.connection_count += 1
        elif counter_key == "session_open":
            state.session_open_count += 1
        elif counter_key == "session_close":
            state.session_close_count += 1
        elif counter_key == "http_request":
            state.http_request_count += 1
        elif counter_key == "http_error":
            state.http_error_count += 1
        else:
            state.other_event_count += 1

        # Update sets
        if event.username:
            state.usernames.add(event.username)
        if event.src_ip:
            state.ips.add(event.src_ip)
            state.subnets[_extract_subnet(event.src_ip)] += 1

        # Update timing
        ts = event.timestamp
        if state.first_timestamp is None:
            state.first_timestamp = ts
        else:
            if state.last_timestamp is not None:
                dt = (ts - state.last_timestamp).total_seconds()
                state.dt_sum += dt
                state.dt_count += 1
        state.last_timestamp = ts

        # Build feature vector
        vec = np.zeros(SESSION_FEATURE_DIM, dtype=np.float32)

        # Dims 0-9: counts
        vec[0] = state.event_count
        vec[1] = state.auth_success_count
        vec[2] = state.auth_failure_count
        vec[3] = state.auth_invalid_count
        vec[4] = state.connection_count
        vec[5] = state.session_open_count
        vec[6] = state.session_close_count
        vec[7] = state.http_request_count
        vec[8] = state.http_error_count
        vec[9] = state.other_event_count

        # Dim 10-11: unique counts
        vec[10] = len(state.usernames)
        vec[11] = len(state.ips)

        # Dim 12: subnet entropy
        vec[12] = _subnet_entropy(state.subnets)

        # Dim 13: auth failure ratio
        auth_attempts = state.auth_success_count + state.auth_failure_count
        vec[13] = state.auth_failure_count / max(auth_attempts, 1)

        # Dim 14: session duration
        if state.first_timestamp is not None and state.last_timestamp is not None:
            vec[14] = (state.last_timestamp - state.first_timestamp).total_seconds()

        # Dim 15: mean inter-event dt
        if state.dt_count > 0:
            vec[15] = state.dt_sum / state.dt_count

        # Dims 16-17: hour sin/cos
        hour = ts.hour + ts.minute / 60.0
        vec[16] = math.sin(2 * math.pi * hour / 24.0)
        vec[17] = math.cos(2 * math.pi * hour / 24.0)

        # Dims 18-19: day-of-week sin/cos
        dow = ts.weekday()
        vec[18] = math.sin(2 * math.pi * dow / 7.0)
        vec[19] = math.cos(2 * math.pi * dow / 7.0)

        return vec

    def reset(self) -> None:
        """Clear all session state."""
        self._sessions.clear()
