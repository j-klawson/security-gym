"""Ground truth → multi-head target arrays with NaN masking.

.. deprecated:: 0.3.0
    The v1 environment uses an integrated reward function instead of
    multi-head target arrays. This module is retained for backwards
    compatibility only.

Produces target arrays compatible with MultiHeadMLPLearner.
NaN signals "skip update for this head" — the learner ignores
inactive heads during gradient computation.
"""

from __future__ import annotations

from typing import Any

import numpy as np

HEAD_NAMES = [
    "is_malicious",   # Head 0: binary (0/1)
    "attack_type",    # Head 1: categorical (0-7)
    "attack_stage",   # Head 2: ordinal (0-4)
    "severity",       # Head 3: ordinal (0-3)
    "session_value",  # Head 4: continuous
]
N_HEADS = 5

ATTACK_TYPES = {
    "brute_force": 0,
    "credential_stuffing": 1,
    "web_exploit": 2,
    "execution": 3,
    "persistence": 4,
    "privilege_escalation": 5,
    "discovery": 6,
    "exfiltration": 7,
}
N_ATTACK_TYPES = 8

ATTACK_STAGES = {
    "recon": 0,
    "initial_access": 1,
    "execution": 2,
    "persistence": 3,
    "exfiltration": 4,
}
N_ATTACK_STAGES = 5

MAX_SEVERITY = 3


class TargetBuilder:
    """Convert ground truth dicts to multi-head target arrays."""

    def __init__(self, value_scale: float = 100.0):
        self.value_scale = value_scale

    def build_targets(self, ground_truth: dict[str, Any] | None) -> np.ndarray:
        """Returns float32 array (N_HEADS,). NaN for unknown/inactive heads."""
        targets = np.full(N_HEADS, np.nan, dtype=np.float32)

        if ground_truth is None:
            return targets

        # Head 0: is_malicious (binary)
        is_mal = ground_truth.get("is_malicious")
        if is_mal is not None:
            targets[0] = float(is_mal)

        # Head 1: attack_type (categorical, normalized to [0, 1])
        attack_type = ground_truth.get("attack_type")
        if attack_type is not None:
            if isinstance(attack_type, str):
                idx = ATTACK_TYPES.get(attack_type)
                if idx is not None:
                    targets[1] = idx / max(N_ATTACK_TYPES - 1, 1)
            else:
                targets[1] = float(attack_type) / max(N_ATTACK_TYPES - 1, 1)

        # Head 2: attack_stage (ordinal, normalized to [0, 1])
        attack_stage = ground_truth.get("attack_stage")
        if attack_stage is not None:
            if isinstance(attack_stage, str):
                idx = ATTACK_STAGES.get(attack_stage)
                if idx is not None:
                    targets[2] = idx / max(N_ATTACK_STAGES - 1, 1)
            else:
                targets[2] = float(attack_stage) / max(N_ATTACK_STAGES - 1, 1)

        # Head 3: severity (ordinal, normalized to [0, 1])
        severity = ground_truth.get("severity")
        if severity is not None:
            targets[3] = float(severity) / max(MAX_SEVERITY, 1)

        # Head 4: session_value (continuous, scaled)
        session_value = ground_truth.get("session_value")
        if session_value is not None:
            targets[4] = float(session_value) / self.value_scale

        return targets
