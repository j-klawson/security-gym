"""Attack module ABC and registry (mirrors ParserRegistry pattern)."""

from __future__ import annotations

import logging
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from attacks.config import PhaseConfig, TimingConfig, TimingSegment


# ── Timing Profile ─────────────────────────────────────────────────────

class TimingProfile:
    """Computes inter-event delay based on progress through a phase.

    Supports constant, accelerating, decelerating, and custom profiles
    where attack cadence changes over time — creating distribution shifts
    in timing features for demonstrating Autostep's adaptive step-sizes.
    """

    def __init__(self, timing: TimingConfig) -> None:
        self.segments = timing.segments
        self._boundaries = self._compute_boundaries()

    def _compute_boundaries(self) -> list[float]:
        """Pre-compute cumulative fraction boundaries."""
        boundaries: list[float] = []
        cumulative = 0.0
        for seg in self.segments:
            cumulative += seg.fraction
            boundaries.append(cumulative)
        return boundaries

    def _find_segment(self, progress: float) -> TimingSegment:
        """Find the active segment for a given progress value."""
        progress = max(0.0, min(1.0, progress))
        for i, boundary in enumerate(self._boundaries):
            if progress <= boundary:
                return self.segments[i]
        return self.segments[-1]

    def get_jitter_ms(self, progress: float, rng: random.Random) -> float:
        """Return delay in ms for the current progress (0.0 to 1.0)."""
        segment = self._find_segment(progress)
        return rng.uniform(segment.jitter_ms[0], segment.jitter_ms[1])

    def get_segment_label(self, progress: float) -> str:
        """Return the label of the active segment."""
        return self._find_segment(progress).label


# ── Attack Result ──────────────────────────────────────────────────────

@dataclass
class AttackResult:
    """Result from executing an attack module."""

    phase_name: str
    module_name: str
    start_time: datetime
    end_time: datetime
    source_ips: list[str]
    attempts: int = 0
    successes: int = 0
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Attack Module ABC ──────────────────────────────────────────────────

class AttackModule(ABC):
    """Abstract base class for attack modules."""

    name: str

    @abstractmethod
    def execute(
        self,
        target: str,
        phase: PhaseConfig,
        ips: list[str],
        rng: random.Random,
        logger: logging.Logger,
    ) -> AttackResult:
        """Execute the attack against target using the given IPs.

        Args:
            target: Target host IP/hostname.
            phase: Phase configuration with params, timing, etc.
            ips: List of source IPs to use for the attack.
            rng: Seeded random instance for reproducibility.
            logger: Logger for progress output.

        Returns:
            AttackResult with timing and outcome data.
        """
        ...

    def dry_run(self, phase: PhaseConfig, ips: list[str]) -> dict[str, Any]:
        """Preview what the module would do without executing."""
        return {
            "module": self.name,
            "phase": phase.name,
            "ip_count": len(ips),
            "params": phase.params,
            "timing_profile": phase.timing.profile,
            "duration_seconds": phase.timing.duration_seconds,
        }


# ── Registry ───────────────────────────────────────────────────────────

class AttackModuleRegistry:
    """Registry mapping module names to AttackModule classes."""

    _modules: dict[str, type[AttackModule]] = {}

    @classmethod
    def register(cls, name: str) -> Callable:
        """Decorator to register an attack module class under a name."""
        def decorator(module_cls: type[AttackModule]) -> type[AttackModule]:
            module_cls.name = name
            cls._modules[name] = module_cls
            return module_cls
        return decorator

    @classmethod
    def get(cls, name: str) -> AttackModule:
        """Instantiate and return a registered module by name."""
        if name not in cls._modules:
            raise KeyError(
                f"Unknown attack module: {name!r}. Available: {cls.available()}"
            )
        return cls._modules[name]()

    @classmethod
    def available(cls) -> list[str]:
        """Return list of registered module names."""
        return sorted(cls._modules.keys())
