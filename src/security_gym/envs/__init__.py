from gymnasium import register


def register_envs():
    """Called automatically by gymnasium when security-gym is pip-installed."""
    register(
        id="SecurityLogStream-v1",
        entry_point="security_gym.envs.log_stream_env:SecurityLogStreamEnv",
    )
