# security-gym

Gymnasium-compatible environment that replays labeled Linux log streams for continual learning research. Scripted attacks mixed with real server traffic produce ground-truth-labeled data — no episodes, no resets, just a continuous stream of observations and multi-head prediction targets.

Built for the [Alberta Plan](https://arxiv.org/abs/2208.11173) vision of long-lived agents that continually learn from non-stationary sensory streams.

## Features

- **Continuous stream** — `terminated` is always `False`; the log stream never ends (just like a real server)
- **Multi-head targets** — 5 prediction heads (malicious?, attack type, attack stage, severity, session value) with NaN masking for inactive heads
- **Three feature modes** — event (24-dim one-hot/cyclic), hashed (configurable MurmurHash3), session (20-dim with per-session state tracking)
- **Composable wrappers** — `HashedFeatureWrapper`, `SessionAggregationWrapper`, `WindowedWrapper`, `DecayingTraceWrapper`
- **Attack framework** — YAML-driven campaign orchestrator with SSH brute force, Log4Shell, and port scan modules
- **Stream composition** — offline mixing of benign + attack data with Poisson-scheduled campaigns and MITRE ATT&CK-weighted type distributions

## Supported Attacks

| Attack Type | Module | MITRE Technique | MITRE Tactic | Description |
|---|---|---|---|---|
| `discovery` | `recon` | [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery | TA0007 — Discovery | SYN port scan via scapy raw sockets |
| `brute_force` | `ssh_brute_force` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) — Password Guessing | TA0006 — Credential Access | SSH password brute force via paramiko with IP aliasing |
| `web_exploit` | `log4shell` | [T1190](https://attack.mitre.org/techniques/T1190/) — Exploit Public-Facing Application | TA0001 — Initial Access | Log4Shell (CVE-2021-44228) JNDI injection via HTTP |
| `credential_stuffing` | — | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) — Credential Stuffing | TA0006 — Credential Access | Planned |
| `execution` | — | [T1059](https://attack.mitre.org/techniques/T1059/) — Command and Scripting Interpreter | TA0002 — Execution | Planned |
| `persistence` | — | — | TA0003 — Persistence | Planned |
| `privilege_escalation` | — | — | TA0004 — Privilege Escalation | Planned |
| `exfiltration` | — | — | TA0010 — Exfiltration | Planned |

The first three attacks have implemented modules and campaign configs. The remaining five are defined in the target taxonomy (Head 1 of the multi-head target system) for future expansion.

## Install

```bash
pip install security-gym
```

Or from source:

```bash
git clone https://github.com/j-klawson/security-gym.git
cd security-gym
pip install -e ".[dev]"
```

Optional extras:

```bash
pip install -e ".[alberta]"   # JAX + alberta-framework for RL experiments
pip install -e ".[attacks]"   # paramiko, requests, scapy for attack generation
pip install -e ".[all]"       # Everything
```

## Quick Start

### Basic Gymnasium Usage

```python
import gymnasium as gym
import security_gym

env = gym.make("SecurityLogStream-v0", db_path="data/events.db")
obs, info = env.reset()

while True:
    obs, reward, terminated, truncated, info = env.step(0)

    # Multi-head targets for supervised learning
    targets = info["targets"]      # shape (5,), -1.0 = inactive head
    is_malicious = targets[0]      # 0.0 = benign, 1.0 = malicious

    # Rich metadata
    print(f"{info['timestamp']} | {info['event_type']:20s} | "
          f"src={info['src_ip']}  user={info['username']}")

    if truncated:  # End of data
        break
```

### Feature Modes

The environment supports three feature representations:

```python
# Event features (24-dim): one-hot source/event_type + cyclic time + binary flags
env = gym.make("SecurityLogStream-v0", db_path="data/events.db", feature_mode="event")

# Hashed features (configurable dim): MurmurHash3 of raw log text
env = gym.make("SecurityLogStream-v0", db_path="data/events.db",
               feature_mode="hashed", hash_dim=512)
```

### Composing Wrappers

Wrappers stack like any Gymnasium wrappers:

```python
from security_gym.envs.wrappers import (
    SessionAggregationWrapper,
    WindowedWrapper,
    DecayingTraceWrapper,
)

# Session features (20-dim) with per-IP/session state tracking
env = gym.make("SecurityLogStream-v0", db_path="data/events.db")
env = SessionAggregationWrapper(env)

# Sliding window: stack last 10 observations into a flat vector
env = WindowedWrapper(env, window_size=10)  # 20 * 10 = 200-dim

# Or use decaying traces for eligibility-trace-style accumulation
env = gym.make("SecurityLogStream-v0", db_path="data/events.db")
env = DecayingTraceWrapper(env, lambda_=0.95)
```

### ANSI Rendering

```python
env = gym.make("SecurityLogStream-v0", db_path="data/events.db", render_mode="ansi")
obs, info = env.reset()
for _ in range(20):
    obs, reward, terminated, truncated, info = env.step(0)
    print(env.render())  # Color-coded: red=malicious, green=benign
```

### SecurityGymStream (Batch/Streaming Adapter)

For direct integration with learning frameworks (bypasses Gymnasium overhead):

```python
from security_gym.adapters.scan_stream import SecurityGymStream

stream = SecurityGymStream("data/events.db", feature_mode="event")

# Batch: load everything into arrays
obs, targets = stream.collect_numpy()        # (N, 24), (N, 5)
print(f"{len(stream)} events, {stream.feature_dim}-dim features, {stream.n_heads} heads")

# Constant-memory streaming
for obs_batch, tgt_batch in stream.iter_batches(size=1000):
    print(obs_batch.shape, tgt_batch.shape)  # (1000, 24), (1000, 5)

# JAX arrays (requires pip install security-gym[alberta])
obs_jax, tgt_jax = stream.collect()          # jnp.ndarray if JAX available

# Server-speed evaluation mode
stream = SecurityGymStream("data/events.db", speed=10.0, loop=True)
for timestep in stream:  # Never-ending, 10x realtime pacing
    ...
```

## Multi-Head Target System

Each event produces a 5-head target array for multi-task continual learning:

| Head | Name | Type | Range | Description |
|------|------|------|-------|-------------|
| 0 | `is_malicious` | binary | {0, 1} | Benign vs. malicious |
| 1 | `attack_type` | categorical | [0, 1] | brute_force, web_exploit, discovery, ... (8 types) |
| 2 | `attack_stage` | ordinal | [0, 1] | recon → initial_access → execution → persistence → exfiltration |
| 3 | `severity` | ordinal | [0, 1] | 0 (info) to 3 (critical) |
| 4 | `session_value` | continuous | [0, 1] | Scaled session value |

Inactive heads use `NaN` internally (or `-1.0` in the Gymnasium info dict). This lets learners like [alberta-framework](https://github.com/j-klawson/alberta-framework)'s `MultiHeadMLPLearner` skip gradient updates for heads without labels.

## Generating Data

### Running Attack Campaigns

The attack framework generates labeled data by executing scripted attacks against a target VM and collecting the resulting logs:

```bash
# List available attack modules
python -m attacks list-modules

# Validate a campaign config
python -m attacks validate campaigns/ssh_brute_only.yaml

# Dry run (preview without executing)
python -m attacks run campaigns/ssh_brute_only.yaml --dry-run

# Execute (requires network access to target VM)
sudo python -m attacks run campaigns/ssh_brute_only.yaml
```

Campaign configs are YAML files defining attack phases, timing profiles, IP strategies, and log collection:

```yaml
campaign:
  name: "SSH Brute Force Only"
  seed: 42
  target:
    host: 192.168.2.201
    ssh_user: researcher
    ssh_key: ~/.ssh/isildur_research
  phases:
    - name: "SSH Brute Force"
      module: ssh_brute_force
      mitre_technique: "T1110.001"
      params:
        usernames: ["root", "admin", "ubuntu"]
        passwords: ["password", "123456", "admin"]
        target_port: 22
        max_attempts_per_ip: 10
      ip_source:
        strategy: aliased
        count: 5
        subnet: "192.168.2.0/24"
      timing:
        duration_seconds: 300
        profile: constant
        jitter_ms: [200, 800]
```

### Importing Benign Logs

Import real server logs as baseline benign data:

```bash
python -m attacks import-logs server_logs.tar --db data/benign.db --host myserver
```

### Composing Experiment Streams

Combine benign and attack data into reproducible experiment streams:

```bash
# Preview composition plan
python -m attacks compose configs/stream_90d_mixed.yaml --dry-run

# Generate composed stream
python -m attacks compose configs/stream_90d_mixed.yaml
```

Composition configs control duration, attack frequency, and MITRE ATT&CK-weighted type distributions:

```yaml
stream:
  duration: 90d
  seed: 42
  benign:
    db: data/benign.db
  attacks:
    db: data/campaigns.db
    campaigns_per_day: 3.0
    distribution:
      discovery: 0.35
      brute_force: 0.30
      web_exploit: 0.20
      credential_stuffing: 0.10
      execution: 0.05
  output:
    db: data/exp01_90d.db
```

## Project Structure

```
security-gym/
├── src/security_gym/          # Installable package
│   ├── adapters/              # SecurityGymStream (batch/streaming adapter)
│   ├── data/                  # EventStore (SQLite), StreamComposer
│   ├── envs/                  # SecurityLogStreamEnv, wrappers
│   ├── features/              # Event (24-dim), hashed, session (20-dim) extractors
│   ├── parsers/               # auth_log, syslog, web_access, web_error, journal
│   └── targets/               # Multi-head target builder
├── attacks/                   # Attack framework (NOT pip-installed)
│   ├── modules/               # ssh_brute_force, log4shell, recon
│   ├── collection/            # SSH/SFTP log collector, benign log importer
│   ├── labeling/              # Time+IP campaign labeler
│   └── tests/                 # Attack framework tests
├── campaigns/                 # YAML campaign configs
├── configs/                   # YAML composition configs
├── server/                    # Target VM provisioning docs
└── tests/                     # Core package tests
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/                     # Core tests (226 tests)
pytest attacks/tests/             # Attack framework tests (90 tests)
ruff check src/ tests/ attacks/   # Lint
```

## Requirements

- Python >= 3.11
- gymnasium >= 1.0.0
- numpy >= 1.24.0

## License

Apache-2.0
