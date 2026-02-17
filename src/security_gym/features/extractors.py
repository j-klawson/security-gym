"""Per-event feature extraction."""

from __future__ import annotations

import math

import numpy as np

from security_gym.parsers.base import ParsedEvent

# Categorical mappings for one-hot encoding
SOURCE_TYPES = ["auth_log", "syslog", "web_access", "web_error", "journal"]
EVENT_TYPES = [
    "auth_success", "auth_failure", "auth_invalid_user",
    "session_open", "session_close", "connection",
    "http_request", "http_error",
    "service_start", "service_stop", "cron", "kernel",
    "other",
]
SERVICE_TYPES = ["sshd", "apache2", "nginx", "mysql", "cron", "systemd", "sudo", "other"]

# Feature layout:
#   source one-hot:     5
#   event_type one-hot: 13
#   hour sin/cos:       2
#   day sin/cos:        2
#   has_ip:             1
#   has_username:       1
# Total:               24
FEATURE_DIM = 24


class EventFeatureExtractor:
    """Extract a fixed-size feature vector from a single ParsedEvent."""

    feature_dim: int = FEATURE_DIM

    def extract(self, event: ParsedEvent) -> np.ndarray:
        """Returns float32 array of shape (feature_dim,)."""
        vec = np.zeros(self.feature_dim, dtype=np.float32)
        offset = 0

        # Source one-hot (5)
        if event.source in SOURCE_TYPES:
            vec[offset + SOURCE_TYPES.index(event.source)] = 1.0
        offset += len(SOURCE_TYPES)

        # Event type one-hot (13)
        if event.event_type in EVENT_TYPES:
            vec[offset + EVENT_TYPES.index(event.event_type)] = 1.0
        else:
            vec[offset + EVENT_TYPES.index("other")] = 1.0
        offset += len(EVENT_TYPES)

        # Hour sin/cos (2)
        hour = event.timestamp.hour + event.timestamp.minute / 60.0
        vec[offset] = math.sin(2 * math.pi * hour / 24.0)
        vec[offset + 1] = math.cos(2 * math.pi * hour / 24.0)
        offset += 2

        # Day-of-week sin/cos (2)
        dow = event.timestamp.weekday()
        vec[offset] = math.sin(2 * math.pi * dow / 7.0)
        vec[offset + 1] = math.cos(2 * math.pi * dow / 7.0)
        offset += 2

        # has_ip (1)
        vec[offset] = 1.0 if event.src_ip else 0.0
        offset += 1

        # has_username (1)
        vec[offset] = 1.0 if event.username else 0.0

        return vec
