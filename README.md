# security-gym

[![CI](https://github.com/j-klawson/security-gym/actions/workflows/ci.yml/badge.svg)](https://github.com/j-klawson/security-gym/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/security-gym)](https://pypi.org/project/security-gym/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Gymnasium](https://img.shields.io/badge/Gymnasium-%E2%89%A51.0.0-blue)](https://gymnasium.farama.org/)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18810298.svg)](https://doi.org/10.5281/zenodo.18810298)
[![Dataset DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.18901542.svg)](https://doi.org/10.5281/zenodo.18901542)

Gymnasium-compatible environment for security defense research. The agent observes raw text streams — like `tail -N` on log files and kernel event channels — and takes defensive actions (block, throttle, alert, isolate) that causally affect future observations.

Built for the [Alberta Plan](https://arxiv.org/abs/2208.11173) vision of long-lived agents that continually learn from non-stationary sensory streams.

## Features

- **Raw text observations (v1)** — 6 text channels (auth\_log, syslog, web\_log, process\_events, network\_events, file\_events) + numeric system stats. The agent learns its own representations.
- **Hybrid text + structured observations (v2)** — 3 text channels for logs + 3 fixed-width float32 arrays for eBPF kernel events. Matches how real SOC tooling consumes data: text for human-readable logs, structured arrays for kernel telemetry.
- **Defensive action space** — 6 actions (pass / alert / throttle / block\_source / unblock / isolate) + continuous risk score. Actions causally affect future observations.
- **Asymmetric rewards** — blocking an attacker earns +1.0, blocking a legitimate user costs -1.0. Ongoing consequence feedback from blocked/throttled events accumulates between steps.
- **Continuous stream** — `terminated` is always `False`; the log stream never ends (just like a real server)
- **eBPF kernel events** — process execution, network connections, and file access captured via BPF tracepoints. Mirrors how modern EDR agents work.
- **Attack framework** — YAML-driven campaign orchestrator with 6 modules: SSH brute force, credential stuffing, Log4Shell, Redis Lua sandbox escape (CVE-2022-0543), port scan, post-auth execution
- **Stream composition** — offline mixing of benign + attack data with Poisson-scheduled campaigns and MITRE ATT&CK-weighted type distributions

## Observation Space

### V1 — All Text (`SecurityLogStream-v1`)

The agent sees the same data a security analyst would — raw log files and kernel event streams:

```
Dict({
    "auth_log":         Text    # SSH auth events (tail of /var/log/auth.log)
    "syslog":           Text    # System events (tail of /var/log/syslog)
    "web_log":          Text    # Combined web access/error logs
    "process_events":   Text    # eBPF: execve/exit kernel events
    "network_events":   Text    # eBPF: connect/accept socket events
    "file_events":      Text    # eBPF: open/unlink file events
    "system_stats":     Box(3)  # [load_avg, mem_used_frac, disk_used_frac]
})
```

Each text channel is a ring buffer of recent lines (configurable `tail_lines` and `max_chars`), updated on every step.

### V2 — Hybrid Text + Structured (`SecurityLogStream-v2`)

Log channels remain as text; eBPF kernel events become fixed-width float32 arrays:

```
Dict({
    "auth_log":         Text              # Unchanged — raw log text
    "syslog":           Text              # Unchanged
    "web_log":          Text              # Unchanged
    "process_events":   Box(50, 8)        # [log_dt, pid, ppid, uid, syscall, comm_hash, parent_hash, tree_depth]
    "network_events":   Box(50, 7)        # [log_dt, pid, uid, syscall, dst_ip_hash, dst_port, comm_hash]
    "file_events":      Box(50, 6)        # [log_dt, pid, uid, syscall, flags, path_hash]
    "system_stats":     Box(3)            # Unchanged
})
```

Each structured channel is a ring buffer of `tail_events` rows (default 50). String fields (comm, IP, path) are hashed via mmh3 with per-field seeds. Timestamp deltas are log-scaled (`log(1 + dt)`) for gradient stability. Process events track tree depth from pid/ppid ancestry.

```python
env = gym.make("SecurityLogStream-v2", db_path="data/exp_7d_brute_v4.db", tail_events=50)
obs, info = env.reset()
print(obs["auth_log"][:100])            # str — raw log text
print(obs["process_events"].shape)      # (50, 8) — float32 array
```

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

**Ongoing consequences**: blocked/throttled events accumulate reward between steps (+0.1 per blocked attack event, -0.5 per blocked benign event). The agent feels the sustained cost of false positives.

## Supported Attacks

| Attack Type | Module | MITRE Technique | MITRE Tactic | Description |
|---|---|---|---|---|
| `discovery` | `recon` | [T1046](https://attack.mitre.org/techniques/T1046/) — Network Service Discovery | TA0007 — Discovery | SYN port scan via scapy raw sockets |
| `brute_force` | `ssh_brute_force` | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) — Password Guessing | TA0006 — Credential Access | SSH password brute force via paramiko with IP aliasing |
| `web_exploit` | `log4shell` | [T1190](https://attack.mitre.org/techniques/T1190/) — Exploit Public-Facing Application | TA0001 — Initial Access | Log4Shell (CVE-2021-44228) JNDI injection via HTTP |
| `credential_stuffing` | `credential_stuffing` | [T1110.004](https://attack.mitre.org/techniques/T1110/004/) — Credential Stuffing | TA0006 — Credential Access | Breach dump credentials, each tried once via SSH |
| `web_exploit` | `redis_lua_escape` | [T1190](https://attack.mitre.org/techniques/T1190/) — Exploit Public-Facing Application | TA0001 — Initial Access | Redis Lua sandbox escape ([CVE-2022-0543](https://nvd.nist.gov/vuln/detail/CVE-2022-0543), CVSS 10.0) — 3-stage: enum → Lua sandbox escape via `package.loadlib()` → post-exploit RCE |
| `execution` | `ssh_post_auth` | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) — Unix Shell | TA0002 — Execution | Post-auth command execution + optional payload download |
| `persistence` | — | — | TA0003 — Persistence | Planned |
| `privilege_escalation` | — | — | TA0004 — Privilege Escalation | Planned |
| `exfiltration` | — | — | TA0010 — Exfiltration | Planned |

The first six attacks have implemented modules, campaign configs, and validated datasets. Two kill chain campaigns combine multiple phases: recon -> credential stuffing -> post-auth execution, and recon -> Redis exploit -> SSH pivot.

### Redis Lua Sandbox Escape (CVE-2022-0543)

The `redis_lua_escape` module exploits a Debian-specific vulnerability where Redis is dynamically linked against liblua5.1, allowing `package.loadlib()` to escape the Lua sandbox for unauthenticated RCE. The attack runs in three stages:

1. **Enumeration** — fingerprint Redis via `INFO`, `CONFIG GET *`, `DBSIZE`, `CLIENT LIST`
2. **Exploitation** — Lua sandbox escape via `EVAL` + `package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io")`
3. **Post-exploitation** — system commands via repeated `EVAL` calls (`id`, `whoami`, then configurable command profiles)

**Key eBPF detection signal:** `execve` events where `parent_comm=redis-server` — Redis spawning shell commands (`sh`, `bash`, `id`, `cat`) is highly anomalous. The eBPF collector captures `ppid` + `parent_comm` on every process event, so this parent-child relationship appears directly in the `process_events` text channel.

## Baselines

Baseline agents establish performance bounds for the environment. See `examples/` for runnable scripts. Results below are from `exp_30d_heavy_v4.db` (1M steps, all 5 attack types).

| Agent | Description | Precision | Recall | F1 | Mean Reward |
|-------|-------------|----------:|-------:|---:|------------:|
| **pass-only** | Never acts — always passes | 0.000 | 0.000 | 0.000 | -0.073 |
| **random** | Uniform random action + risk score | 0.003 | 0.665 | 0.005 | -3.985 |
| **threshold(5)** | Block IP after 5 failed SSH auths in 5 min | 1.000 | 0.005 | 0.011 | -0.084 |
| **keyword** | Multi-channel SIEM-style pattern matching | 0.987 | 0.013 | 0.025 | -0.073 |
| **rlsecd** | 5-head MLP continual learner ([rlsecd](https://github.com/j-klawson/rlsecd)) | 0.979 | 0.979 | 0.979 | — |

Both heuristic agents achieve high precision but near-zero recall. The threshold agent only sees SSH brute force in auth\_log text. The keyword agent adds rules for Log4Shell, process ancestry, and file access across all channels, doubling F1 — but still catches only 1.3% of attacks because most malicious events are eBPF kernel telemetry (file opens, process exits, network accepts) that don't match static signatures. Only a learning agent can generalize across the full observation space.

```bash
# Run all baselines on an experiment stream
python examples/benchmark.py data/exp_7d_brute_v4.db

# Individual agents
python examples/random_agent.py data/exp_7d_brute_v4.db
python examples/threshold_agent.py data/exp_7d_brute_v4.db --threshold 5
python examples/keyword_agent.py data/exp_7d_brute_v4.db
python examples/streaming_demo.py data/exp_7d_brute_v4.db --mode gym
```

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

Pre-built datasets (SQLite databases with labeled log and eBPF kernel events) are available from [Zenodo](https://doi.org/10.5281/zenodo.18901542) and [GitHub Releases](https://github.com/j-klawson/security-gym/releases).

The v4 dataset includes 11.2M benign events (7.9M logs + 3.24M eBPF from 3 servers) and 60K attack events across 5 attack types. Pre-composed experiment streams range from 4.9M events (7-day) to 257.7M events (365-day).

Download the latest dataset:

```bash
# Via CLI (after pip install)
security-gym download

# Or list available releases first
security-gym list
```

Or download from [Zenodo](https://doi.org/10.5281/zenodo.18901542) and decompress with `zstd -d <file>.zst` into `data/`.

## Quick Start

### Basic Gymnasium Usage

```python
import gymnasium as gym
import numpy as np
import security_gym

env = gym.make("SecurityLogStream-v1", db_path="data/exp_7d_brute_v4.db")
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
- Dropped attack events: +0.1 per event (confirmed mitigation)
- Dropped benign events: -0.5 per event (service impact)

### ANSI Rendering

```python
env = gym.make("SecurityLogStream-v1", db_path="data/exp_7d_brute_v4.db", render_mode="ansi")
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

stream = SecurityGymStream("data/exp_7d_brute_v4.db")

# Batch: load all observations and ground truth
observations, ground_truths = stream.collect_numpy()
# observations: list of dicts (one per event, each with text channels + system_stats)
# ground_truths: list of dicts (is_malicious, attack_type, true_risk, ...)

# Constant-memory streaming
for obs_batch, gt_batch in stream.iter_batches(size=1000):
    for obs, gt in zip(obs_batch, gt_batch):
        print(obs["auth_log"][:80], gt["is_malicious"])

# Server-speed evaluation mode (never-ending, paced stream)
stream = SecurityGymStream("data/exp_7d_brute_v4.db", speed=10.0, loop=True)
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
    ssh_key: ~/.ssh/your_public_key
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

### Collecting eBPF Kernel Events

The three kernel observation channels (`process_events`, `network_events`, `file_events`) are populated by an eBPF collector daemon that attaches to Linux kernel tracepoints via [BCC](https://github.com/iovisor/bcc). This captures syscall-level activity invisible to traditional log files — the agent sees process execution chains, network connections, and file access as they happen in the kernel.

**What's captured:**

| Channel | Tracepoints | Fields |
|---------|------------|--------|
| `process_events` | `sys_enter_execve`, `sched_process_exit` | pid, ppid, uid, comm, parent\_comm, args, exit code |
| `network_events` | `sys_enter_connect`, `sys_enter_accept4` | pid, uid, comm, dst IP:port |
| `file_events` | `sys_enter_openat`, `sys_enter_unlinkat` | pid, comm, path, flags |

Process events include **parent process ancestry** (ppid + parent\_comm), allowing the agent to learn causal chains — e.g., `apache2 → wget` is suspicious while `cron → wget` may be routine. Network events include the **effective UID**, so the agent can learn user-identity-aware policies.

**Benign baseline collection:**

eBPF kernel events are collected from the target server during normal operation (no attacks running) to establish a baseline of benign system activity:

```bash
# Collect 1 hour of benign kernel events from the target server
python scripts/collect_ebpf_baseline.py --duration 3600

# Preview without collecting
python scripts/collect_ebpf_baseline.py --duration 3600 --dry-run
```

This SSHs into the target, deploys the eBPF collector, runs for the specified duration, retrieves the events, and inserts them as benign (`is_malicious=0`). The v4 benign dataset includes 3.24M eBPF events from 24-hour collections on 3 servers.

**During attack campaigns:**

When `ebpf: {enabled: true}` is set in a campaign YAML, the orchestrator automatically starts the eBPF collector before the attack begins and stops it after. Kernel events captured during attack windows are labeled malicious through the same time+IP matching used for log events — an `execve wget` from the attacker's IP during an attack phase is correctly labeled as part of the attack.

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
    db: data/benign_v4.db
    ebpf_sample_rate: 0.242    # 24.2% — simulates single busy server
  attacks:
    db: data/campaigns_v2.db
    campaigns_per_day: 3.0
    distribution:
      discovery: 0.35
      brute_force: 0.30
      web_exploit: 0.20
      credential_stuffing: 0.10
      execution: 0.05
  output:
    db: data/exp01_90d_v4.db
```

## Project Structure

```
security-gym/
├── src/security_gym/          # Installable package
│   ├── adapters/              # SecurityGymStream (batch/streaming adapter)
│   ├── data/                  # EventStore (SQLite), StreamComposer
│   ├── envs/                  # SecurityLogStreamEnv (v1, v2), deprecated wrappers
│   ├── features/              # Deprecated (v0 numeric extractors)
│   ├── parsers/               # auth_log, syslog, web_access, web_error, journal, ebpf
│   └── targets/               # Deprecated (v0 multi-head target builder)
├── examples/                  # Baseline agents and usage demos
├── attacks/                   # Attack framework (NOT pip-installed)
│   ├── modules/               # recon, ssh_brute_force, credential_stuffing, ssh_post_auth, log4shell, redis_lua_escape
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
pytest tests/                     # Core tests (339 tests)
pytest attacks/tests/             # Attack framework tests (120 tests)
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
