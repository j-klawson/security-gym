"""security-gym: Gymnasium environments for cybersecurity threat detection."""

from security_gym.envs import register_envs

register_envs()

from security_gym.data.event_store import EventStore  # noqa: E402
from security_gym.envs.log_stream_env import SecurityLogStreamEnv  # noqa: E402
from security_gym.envs.wrappers import (  # noqa: E402
    DecayingTraceWrapper,
    HashedFeatureWrapper,
    SessionAggregationWrapper,
    WindowedWrapper,
)
from security_gym.features.extractors import EventFeatureExtractor  # noqa: E402
from security_gym.features.hasher import FeatureHasher  # noqa: E402
from security_gym.features.session import SESSION_FEATURE_DIM, SessionFeatureExtractor  # noqa: E402
from security_gym.parsers.base import ParsedEvent, Parser  # noqa: E402
from security_gym.parsers.registry import ParserRegistry  # noqa: E402
from security_gym.targets.builder import HEAD_NAMES, N_HEADS, TargetBuilder  # noqa: E402
from security_gym.adapters.scan_stream import SecurityGymStream  # noqa: E402

__all__ = [
    "EventStore",
    "SecurityLogStreamEnv",
    "SecurityGymStream",
    "DecayingTraceWrapper",
    "HashedFeatureWrapper",
    "SessionAggregationWrapper",
    "WindowedWrapper",
    "EventFeatureExtractor",
    "FeatureHasher",
    "SessionFeatureExtractor",
    "SESSION_FEATURE_DIM",
    "ParsedEvent",
    "Parser",
    "ParserRegistry",
    "TargetBuilder",
    "HEAD_NAMES",
    "N_HEADS",
]
