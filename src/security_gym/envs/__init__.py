from gymnasium import register


def register_envs():
    """Called automatically by gymnasium when security-gym is pip-installed.

    Two observation modes are registered:

    - ``SecurityLogStream-Text-v0`` — all telemetry channels exposed as text.
    - ``SecurityLogStream-Hybrid-v0`` — log channels as text, eBPF channels as
      fixed-width float32 arrays.
    """
    register(
        id="SecurityLogStream-Text-v0",
        entry_point="security_gym.envs.log_stream_env:SecurityLogStreamEnv",
    )
    register(
        id="SecurityLogStream-Hybrid-v0",
        entry_point="security_gym.envs.log_stream_env_hybrid:SecurityLogStreamHybridEnv",
    )


__all__ = ["register_envs"]
