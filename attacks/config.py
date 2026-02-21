"""Campaign configuration dataclasses and YAML loading/validation."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Import target taxonomy for validation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from security_gym.targets.builder import ATTACK_STAGES, ATTACK_TYPES


# ── Timing ─────────────────────────────────────────────────────────────

TIMING_PROFILES = {"constant", "accelerating", "decelerating", "custom"}


@dataclass
class TimingSegment:
    """A named segment within a timing profile."""

    label: str
    fraction: float
    jitter_ms: tuple[float, float]

    def __post_init__(self) -> None:
        if self.fraction <= 0 or self.fraction > 1:
            raise ValueError(f"Segment {self.label!r}: fraction must be in (0, 1], got {self.fraction}")
        lo, hi = self.jitter_ms
        if lo < 0 or hi < lo:
            raise ValueError(f"Segment {self.label!r}: jitter_ms must be [lo, hi] with 0 <= lo <= hi")


@dataclass
class TimingConfig:
    """Timing configuration for a phase."""

    duration_seconds: int
    profile: str = "constant"
    jitter_ms: tuple[float, float] | None = None
    delay_after_seconds: int = 0
    profile_params: dict[str, Any] = field(default_factory=dict)
    segments: list[TimingSegment] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.profile not in TIMING_PROFILES:
            raise ValueError(
                f"Unknown timing profile {self.profile!r}. "
                f"Available: {sorted(TIMING_PROFILES)}"
            )
        if self.profile == "constant" and self.jitter_ms is None:
            self.jitter_ms = (100, 500)  # Default jitter
        if self.profile in ("accelerating", "decelerating", "custom"):
            self._build_segments()
        elif self.profile == "constant" and self.jitter_ms is not None:
            self.segments = [TimingSegment("constant", 1.0, self.jitter_ms)]

    def _build_segments(self) -> None:
        """Build segments from profile_params or generate defaults."""
        if "phases" in self.profile_params:
            self.segments = [
                TimingSegment(
                    label=s["label"],
                    fraction=s["fraction"],
                    jitter_ms=tuple(s["jitter_ms"]),
                )
                for s in self.profile_params["phases"]
            ]
        elif self.profile == "accelerating":
            self.segments = [
                TimingSegment("slow", 0.3, (2000, 5000)),
                TimingSegment("medium", 0.4, (500, 1500)),
                TimingSegment("fast", 0.3, (50, 200)),
            ]
        elif self.profile == "decelerating":
            self.segments = [
                TimingSegment("fast", 0.3, (50, 200)),
                TimingSegment("medium", 0.4, (500, 1500)),
                TimingSegment("slow", 0.3, (2000, 5000)),
            ]
        else:
            raise ValueError(f"Profile {self.profile!r} requires profile_params.phases")
        total = sum(s.fraction for s in self.segments)
        if abs(total - 1.0) > 0.01:
            raise ValueError(
                f"Segment fractions must sum to 1.0, got {total:.3f}"
            )


# ── IP Source ──────────────────────────────────────────────────────────

IP_STRATEGIES = {"spoofed", "aliased"}


@dataclass
class IPSourceConfig:
    """IP source strategy configuration."""

    strategy: str
    count: int
    subnet: str
    start_offset: int = 0
    interface: str = "en0"

    def __post_init__(self) -> None:
        if self.strategy not in IP_STRATEGIES:
            raise ValueError(
                f"Unknown IP strategy {self.strategy!r}. Available: {sorted(IP_STRATEGIES)}"
            )
        if self.count < 1:
            raise ValueError(f"IP count must be >= 1, got {self.count}")


# ── Phase ──────────────────────────────────────────────────────────────

@dataclass
class PhaseConfig:
    """Single attack phase configuration."""

    name: str
    module: str
    mitre_technique: str
    mitre_tactic: str
    attack_type: str
    attack_stage: str
    severity: int
    params: dict[str, Any]
    ip_source: IPSourceConfig
    timing: TimingConfig

    def __post_init__(self) -> None:
        if self.attack_type not in ATTACK_TYPES:
            raise ValueError(
                f"Unknown attack_type {self.attack_type!r}. "
                f"Available: {sorted(ATTACK_TYPES.keys())}"
            )
        if self.attack_stage not in ATTACK_STAGES:
            raise ValueError(
                f"Unknown attack_stage {self.attack_stage!r}. "
                f"Available: {sorted(ATTACK_STAGES.keys())}"
            )
        if not 0 <= self.severity <= 3:
            raise ValueError(f"Severity must be 0-3, got {self.severity}")


# ── Log Source ─────────────────────────────────────────────────────────

@dataclass
class LogSourceConfig:
    """A remote log source to collect."""

    name: str
    parser: str | None = None
    remote_path: str | None = None
    remote_command: str | None = None

    def __post_init__(self) -> None:
        if self.remote_path is None and self.remote_command is None:
            raise ValueError(f"Log source {self.name!r}: need remote_path or remote_command")


# ── Collection ─────────────────────────────────────────────────────────

@dataclass
class CollectionConfig:
    """Post-campaign log collection settings."""

    log_sources: list[LogSourceConfig]
    db_path: str = "data/campaigns.db"
    time_buffer_seconds: int = 60


# ── Target ─────────────────────────────────────────────────────────────

@dataclass
class TargetConfig:
    """Target VM connection info."""

    host: str
    ssh_user: str = "researcher"
    ssh_key: str = "~/.ssh/isildur_research"
    ssh_port: int = 22


# ── Campaign ───────────────────────────────────────────────────────────

@dataclass
class CampaignConfig:
    """Top-level campaign configuration."""

    name: str
    phases: list[PhaseConfig]
    target: TargetConfig
    collection: CollectionConfig
    description: str = ""
    seed: int = 42


# ── YAML Loading ───────────────────────────────────────────────────────

def _parse_timing(raw: dict[str, Any]) -> TimingConfig:
    return TimingConfig(
        duration_seconds=raw["duration_seconds"],
        profile=raw.get("profile", "constant"),
        jitter_ms=tuple(raw["jitter_ms"]) if "jitter_ms" in raw else None,
        delay_after_seconds=raw.get("delay_after_seconds", 0),
        profile_params=raw.get("profile_params", {}),
    )


def _parse_ip_source(raw: dict[str, Any]) -> IPSourceConfig:
    return IPSourceConfig(
        strategy=raw["strategy"],
        count=raw["count"],
        subnet=raw["subnet"],
        start_offset=raw.get("start_offset", 0),
        interface=raw.get("interface", "en0"),
    )


def _parse_phase(raw: dict[str, Any]) -> PhaseConfig:
    return PhaseConfig(
        name=raw["name"],
        module=raw["module"],
        mitre_technique=raw["mitre_technique"],
        mitre_tactic=raw["mitre_tactic"],
        attack_type=raw["attack_type"],
        attack_stage=raw["attack_stage"],
        severity=raw["severity"],
        params=raw.get("params", {}),
        ip_source=_parse_ip_source(raw["ip_source"]),
        timing=_parse_timing(raw["timing"]),
    )


def _parse_log_source(raw: dict[str, Any]) -> LogSourceConfig:
    return LogSourceConfig(
        name=raw["name"],
        parser=raw.get("parser"),
        remote_path=raw.get("remote_path"),
        remote_command=raw.get("remote_command"),
    )


def _parse_collection(raw: dict[str, Any]) -> CollectionConfig:
    output = raw.get("output", {})
    return CollectionConfig(
        log_sources=[_parse_log_source(s) for s in raw.get("log_sources", [])],
        db_path=output.get("db_path", "data/campaigns.db"),
        time_buffer_seconds=output.get("time_buffer_seconds", 60),
    )


def load_campaign(path: Path) -> CampaignConfig:
    """Load and validate a campaign YAML file."""
    with open(path) as f:
        raw = yaml.safe_load(f)

    campaign = raw["campaign"]

    target = TargetConfig(
        host=campaign["target"]["host"],
        ssh_user=campaign["target"].get("ssh_user", "researcher"),
        ssh_key=campaign["target"].get("ssh_key", "~/.ssh/isildur_research"),
        ssh_port=campaign["target"].get("ssh_port", 22),
    )

    phases = [_parse_phase(p) for p in campaign["phases"]]

    collection = _parse_collection(campaign.get("collection", {}))

    return CampaignConfig(
        name=campaign["name"],
        description=campaign.get("description", ""),
        seed=campaign.get("seed", 42),
        target=target,
        phases=phases,
        collection=collection,
    )


def validate_campaign(path: Path) -> list[str]:
    """Validate a YAML campaign file, returning a list of errors (empty = valid)."""
    errors: list[str] = []
    try:
        load_campaign(path)
    except KeyError as e:
        errors.append(f"Missing required key: {e}")
    except (ValueError, TypeError) as e:
        errors.append(str(e))
    except yaml.YAMLError as e:
        errors.append(f"YAML parse error: {e}")
    return errors
