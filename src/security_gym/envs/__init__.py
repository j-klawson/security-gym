import importlib
import warnings

from gymnasium import register

_TEXT_ENTRY_POINT = "security_gym.envs.log_stream_env:SecurityLogStreamEnv"
_HYBRID_ENTRY_POINT = "security_gym.envs.log_stream_env_v2:SecurityLogStreamEnvV2"

_DEPRECATED_ALIASES = {
    "SecurityLogStream-v1": ("SecurityLogStream-Text-v0", _TEXT_ENTRY_POINT),
    "SecurityLogStream-v2": ("SecurityLogStream-Hybrid-v0", _HYBRID_ENTRY_POINT),
}


def _make_deprecated_entry_point(old_id: str, new_id: str, target: str):
    """Wrap an entry point so that resolving it emits a DeprecationWarning.

    The old IDs continue to work but warn the caller to migrate to the
    Text/Hybrid mode names. Scheduled for removal in security-gym 0.5.0.
    """

    def _entry_point(**kwargs):
        warnings.warn(
            f"Gymnasium id '{old_id}' is deprecated and will be removed in "
            f"security-gym 0.5.0; use '{new_id}' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        module_path, _, class_name = target.partition(":")
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        return cls(**kwargs)

    return _entry_point


def register_envs():
    """Called automatically by gymnasium when security-gym is pip-installed.

    Two observation modes are registered:

    - ``SecurityLogStream-Text-v0`` — all telemetry channels exposed as text.
    - ``SecurityLogStream-Hybrid-v0`` — log channels as text, eBPF channels as
      fixed-width float32 arrays.

    The legacy IDs ``SecurityLogStream-v1`` and ``SecurityLogStream-v2`` remain
    registered as deprecated aliases and will be removed in 0.5.0.
    """
    register(id="SecurityLogStream-Text-v0", entry_point=_TEXT_ENTRY_POINT)
    register(id="SecurityLogStream-Hybrid-v0", entry_point=_HYBRID_ENTRY_POINT)

    for old_id, (new_id, target) in _DEPRECATED_ALIASES.items():
        register(
            id=old_id,
            entry_point=_make_deprecated_entry_point(old_id, new_id, target),
        )


__all__ = ["register_envs"]
