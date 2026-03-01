# security-gym

[![CI](https://github.com/j-klawson/security-gym/actions/workflows/ci.yml/badge.svg)](https://github.com/j-klawson/security-gym/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Gymnasium](https://img.shields.io/badge/Gymnasium-%E2%89%A51.0.0-blue)](https://gymnasium.farama.org/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18810299.svg)](https://doi.org/10.5281/zenodo.18810299)

Gymnasium-compatible environment for security defense research. The agent observes raw text streams — like `tail -N` on log files and kernel event channels — and takes defensive actions (block, throttle, alert, isolate) that causally affect future observations.

Built for the [Alberta Plan](https://arxiv.org/abs/2208.11173) vision of long-lived agents that continually learn from non-stationary sensory streams.

## Features

- **Raw text observations** — 6 text channels (auth\_log, syslog, web\_log, process\_events, network\_events, file\_events) + numeric system stats. The agent learns its own representations.
- **Defensive action space** — 6 actions (pass / alert / throttle / block\_source / unblock / isolate) + continuous risk score. Actions causally affect future observations.
- **Asymmetric rewards** — blocking an attacker earns +1.0, blocking a legitimate user costs -1.0. Ongoing consequence feedback from blocked/throttled events accumulates between steps.
- **Continuous stream** — `terminated` is always `False`; the log stream never ends (just like a real server)
- **eBPF kernel events** — process execution, network connections, and file access captured via BPF tracepoints. Mirrors how modern EDR agents work.
- **Attack framework** — YAML-driven campaign orchestrator with 5 modules: SSH brute force, credential stuffing, Log4Shell, port scan, post-auth execution
- **Stream composition** — offline mixing of benign + attack data with Poisson-scheduled campaigns and MITRE ATT&CK-weighted type distributions

## Observation Space

The agent sees the same data a security analyst would — raw log files and kernel event streams:

```
Dict({
    "auth_log":         Text    # SSH auth events (tail of /var/log/auth.log)
    "syslog":           Text    # System events (tail of /var/log/syslog)
    "web_log":          Text    # Combined web access/error logs
    "process_events":   Text    # eBPF: execve/exit/fork kernel events
    "network_events":   Text    # eBPF: connect/accept/bind socket events
    "file_events":      Text    # eBPF: open/write/unlink file events
    "system_stats":     Box(3)  # [load_avg, mem_used_frac, disk_used_frac]
})
```

Each text channel is a ring buffer of recent lines (configurable `tail_lines` and `max_chars`), updated on every step.

## Action Space

```
Dict({
    "action":     Discrete(6)   # 0=pass, 1=alert, 2=throttle, 3=block_source, 4=unblock, 5=isolate
    "risk_score": Box(0, 10)    # Agent's estimate of current threat level (auxiliary prediction)
})
```

| Action | Effect |
|--------|--------|
| `pass` | Continue monitoring |
| `alert` | Flag for human review |
| `throttle` | Rate-limit source IP (~90% drop) |
| `block_source` | Add source IP to firewall blocklist (100% drop) |
| `unblock` | Remove source IP from blocklist/throttle list |
| `isolate` | Quarantine server (block all network events) |

IP-targeted actions use the current event's source IP. The agent can escalate and de-escalate: throttle -> block -> unblock.

## Reward Function

Three components combined:

**Action reward** (asymmetric — mistakes in both directions are costly):

| Action | During Attack | During Benign |
|--------|--------------|---------------|
| `block_source` | +1.0 | -1.0 |
| `throttle` | +0.75 | -0.5 |
| `alert` | +0.5 | -0.3 |
| `pass` | -0.5 | 0.0 |
| `isolate` | +0.25 | -2.0 |
| `unblock` | -0.5 | 0.0 |

**Risk score MSE**: `-0.1 * (predicted_risk - true_risk)^2` — penalizes inaccurate threat assessment.

**Ongoing consequences**: blocked/throttled events accumulate reward between steps (+0.05 per blocked attack event, -0.1 per blocked benign event). The agent feels the sustained cost of false positives.

## Supported Attacks

| Attack Type | Module | MITRE Technique | MITRE Tactic | Description |
|---|---|---|---|---|
| `discovery` | `recon` | [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery | TA0007 — Discovery | SYN port scan via scapy raw sockets |
| `brute_force` | `ssh_brute_force` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) — Password Guessing | TA0006 — Credential Access | SSH password brute force via paramiko with IP aliasing |
| `web_exploit` | `log4shell` | [T1190](https://attack.mitre.org/techniques/T1190/) — Exploit Public-Facing Application | TA0001 — Initial Access | Log4Shell (CVE-2021-44228) JNDI injection via HTTP |
| `credential_stuffing` | `credential_stuffing` | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) — Credential Stuffing | TA0006 — Credential Access | Breach dump credentials, each tried once via SSH |
| `execution` | `ssh_post_auth` | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) — Unix Shell | TA0002 — Execution | Post-auth command execution + optional payload download |
| `persistence` | — | — | TA0003 — Persistence | Planned |
| `privilege_escalation` | — | — | TA0004 — Privilege Escalation | Planned |
| `exfiltration` | — | — | TA0010 — Exfiltration | Planned |

The first five attacks have implemented modules and campaign configs (including a full kill chain campaign: recon -> credential stuffing -> post-auth execution).

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

## Dataset

Pre-built datasets (SQLite databases with labeled log events) are available from [GitHub Releases](https://github.com/j-klawson/security-gym/releases) and archived on [Zenodo](https://doi.org/10.5281/zenodo.18810299).

Download the latest dataset:

```bash
# Via CLI (after pip install)
security-gym download

# Or list available releases first
security-gym list
```

Or manually download `campaigns.db` from the [Releases page](https://github.com/j-klawson/security-gym/releases) and place it in `data/`.

## Quick Start

### Basic Gymnasium Usage

```python
import gymnasium as gym
import numpy as np
import security_gym

env = gym.make("SecurityLogStream-v1", db_path="data/campaigns.db")
obs, info = env.reset()

# obs is a dict of text channels + system stats
print(obs["auth_log"][:200])   # Raw auth log lines
print(obs["system_stats"])     # [load_avg, mem_used, disk_used]

while True:
    # Choose an action
    action = {
        "action": 0,  # pass (monitor only)
        "risk_score": np.array([0.0], dtype=np.float32),
    }

    obs, reward, terminated, truncated, info = env.step(action)

    # Ground truth (for evaluation, not visible to agent)
    gt = info["ground_truth"]
    print(f"{info['timestamp']} | malicious={gt['is_malicious']} | "
          f"risk={gt['true_risk']:.1f} | reward={reward:.2f}")

    if truncated:  # End of data
        break
```

### Defensive Actions

```python
import numpy as np

# Block the current event's source IP (100% drop)
block = {"action": 3, "risk_score": np.array([8.0], dtype=np.float32)}

# Throttle (90% drop rate)
throttle = {"action": 2, "risk_score": np.array([5.0], dtype=np.float32)}

# Alert with high risk estimate
alert = {"action": 1, "risk_score": np.array([7.0], dtype=np.float32)}

# Undo a block (correct false positive)
unblock = {"action": 4, "risk_score": np.array([1.0], dtype=np.float32)}

# Quarantine server (blocks all network events)
isolate = {"action": 5, "risk_score": np.array([10.0], dtype=np.float32)}
```

After blocking an IP, future events from that IP are silently dropped. The agent observes the absence of those events and receives ongoing consequence feedback:
- Dropped attack events: +0.05 per event (confirmed mitigation)
- Dropped benign events: -0.1 per event (service impact)

### ANSI Rendering

```python
env = gym.make("SecurityLogStream-v1", db_path="data/campaigns.db", render_mode="ansi")
obs, info = env.reset()
for _ in range(20):
    action = {"action": 0, "risk_score": np.array([0.0], dtype=np.float32)}
    obs, reward, terminated, truncated, info = env.step(action)
    print(env.render())  # Color-coded: red=malicious, green=benign
```

### SecurityGymStream (Batch/Streaming Adapter)

For direct integration with learning frameworks (bypasses Gymnasium overhead):

```python
from security_gym.adapters.scan_stream import SecurityGymStream

stream = SecurityGymStream("data/campaigns.db")

# Batch: load all observations and ground truth
observations, ground_truths = stream.collect_numpy()
# observations: list of dicts (one per event, each with text channels + system_stats)
# ground_truths: list of dicts (is_malicious, attack_type, true_risk, ...)

# Constant-memory streaming
for obs_batch, gt_batch in stream.iter_batches(size=1000):
    for obs, gt in zip(obs_batch, gt_batch):
        print(obs["auth_log"][:80], gt["is_malicious"])

# Server-speed evaluation mode (never-ending, paced stream)
stream = SecurityGymStream("data/campaigns.db", speed=10.0, loop=True)
for timestep in stream:  # Requires JAX
    ...
```

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
  collection:
    ebpf:
      enabled: true           # Collect kernel events via eBPF
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
│   ├── envs/                  # SecurityLogStreamEnv (v1), deprecated wrappers
│   ├── features/              # Deprecated (v0 numeric extractors)
│   ├── parsers/               # auth_log, syslog, web_access, web_error, journal, ebpf
│   └── targets/               # Deprecated (v0 multi-head target builder)
├── attacks/                   # Attack framework (NOT pip-installed)
│   ├── modules/               # recon, ssh_brute_force, credential_stuffing, ssh_post_auth, log4shell
│   ├── collection/            # SSH/SFTP log collector, benign log importer, eBPF orchestrator
│   ├── labeling/              # Time+IP campaign labeler
│   └── tests/                 # Attack framework tests
├── campaigns/                 # YAML campaign configs
├── configs/                   # YAML composition configs
├── server/                    # Target VM provisioning docs, eBPF collector daemon
└── tests/                     # Core package tests
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/                     # Core tests (227 tests)
pytest attacks/tests/             # Attack framework tests (90 tests)
ruff check src/ tests/ attacks/   # Lint
```

## Requirements

- Python >= 3.11
- gymnasium >= 1.0.0
- numpy >= 1.24.0

## Author

Keith Lawson

## License

Apache-2.0
