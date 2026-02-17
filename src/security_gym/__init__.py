"""security-gym: Gymnasium environments for cybersecurity threat detection."""

from security_gym.envs import register_envs

register_envs()

from security_gym.data.event_store import EventStore
from security_gym.envs.log_stream_env import SecurityLogStreamEnv
from security_gym.features.extractors import EventFeatureExtractor
from security_gym.features.hasher import FeatureHasher
from security_gym.parsers.base import ParsedEvent, Parser
from security_gym.parsers.registry import ParserRegistry
from security_gym.targets.builder import HEAD_NAMES, N_HEADS, TargetBuilder
from security_gym.adapters.scan_stream import SecurityGymStream

__all__ = [
    "EventStore",
    "SecurityLogStreamEnv",
    "SecurityGymStream",
    "EventFeatureExtractor",
    "FeatureHasher",
    "ParsedEvent",
    "Parser",
    "ParserRegistry",
    "TargetBuilder",
    "HEAD_NAMES",
    "N_HEADS",
]
