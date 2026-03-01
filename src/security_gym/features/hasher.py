"""Feature hashing for raw log text via mmh3.

.. deprecated:: 0.3.0
    The v1 environment presents raw text observations. The agent learns
    its own representations. This module is retained for backwards
    compatibility only.

Converts raw log lines to fixed-size vectors using the hashing trick
(Weinberger et al. 2009). Signed hashing reduces collision bias.
L2-normalized output stabilizes MLP training.

Adapted from chronos-sec agent/feature_hasher.py.
"""

from __future__ import annotations

import re

import mmh3
import numpy as np

_SPLIT_PATTERN = re.compile(r'[\s\[\]\(\):=,"\'{}]+')


class FeatureHasher:
    """Hash raw log text to fixed-size feature vectors."""

    def __init__(
        self,
        dim: int = 1024,
        use_bigrams: bool = True,
        seed_bucket: int = 0,
        seed_sign: int = 1,
    ):
        self.dim = dim
        self.use_bigrams = use_bigrams
        self.seed_bucket = seed_bucket
        self.seed_sign = seed_sign

    def tokenize(self, text: str) -> list[str]:
        tokens = _SPLIT_PATTERN.split(text)
        return [t for t in tokens if t]

    def hash(self, text: str) -> np.ndarray:
        """Hash a single log line. Returns L2-normalized float32 (dim,)."""
        tokens = self.tokenize(text)
        vec = np.zeros(self.dim, dtype=np.float32)

        if not tokens:
            return vec

        for token in tokens:
            bucket = mmh3.hash(token, seed=self.seed_bucket, signed=False) % self.dim
            sign = 1 if mmh3.hash(token, seed=self.seed_sign, signed=False) % 2 == 0 else -1
            vec[bucket] += sign

        if self.use_bigrams and len(tokens) >= 2:
            for i in range(len(tokens) - 1):
                bigram = tokens[i] + " " + tokens[i + 1]
                bucket = mmh3.hash(bigram, seed=self.seed_bucket, signed=False) % self.dim
                sign = (
                    1 if mmh3.hash(bigram, seed=self.seed_sign, signed=False) % 2 == 0 else -1
                )
                vec[bucket] += sign

        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm

        return vec
