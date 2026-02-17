# security-gym

Gymnasium-compatible environments for cybersecurity threat detection with continual learning.

Replays labeled Linux log streams from a purpose-built vulnerable server. Scripted attacks mixed with real admin traffic produce ground-truth-labeled data for continual learning research.

## Install

```bash
pip install security-gym
```

## Quick Start

```python
import gymnasium as gym
import security_gym

env = gym.make("SecurityLogStream-v0", db_path="data/events.db")
obs, info = env.reset()

while True:
    obs, reward, terminated, truncated, info = env.step(0)
    if truncated:
        break
```

## License

Apache-2.0
