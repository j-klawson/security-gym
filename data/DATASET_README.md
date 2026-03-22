# Security-Gym Dataset: Labeled Linux Log Streams for Continual Learning

Ground-truth-labeled Linux server log and eBPF kernel event streams for cybersecurity continual learning research. Designed for use with the [security-gym](https://github.com/j-klawson/security-gym) Gymnasium environment.

## Overview

These datasets contain real benign server traffic mixed with scripted attack campaigns executed against a purpose-built vulnerable Linux server. All events are stored in SQLite databases with WAL mode, sorted by timestamp, and labeled with ground truth (benign/malicious, attack type, campaign ID, MITRE ATT&CK stage).

All files are compressed with [Zstandard](https://facebook.github.io/zstd/). Decompress with `zstd -d <file>.zst`.

## Files

### Source Databases

| File | Decompressed | Events | Description |
|------|-------------|--------|-------------|
| `benign_v4.db.zst` | 5.8 GB | 11,159,241 | Real benign server traffic (auth.log, syslog, nginx) + 3.24M eBPF kernel events from 3 servers. PII-scrubbed: server hostnames and IPs normalized to a single target host. |
| `campaigns_v2.db.zst` | 41 MB | 60,468 | 10 attack campaigns across 5 attack types with log + eBPF kernel events. |

### Pre-Composed Experiment Streams

Composed from `benign_v4.db` + `campaigns_v2.db` using StreamComposer with Poisson-scheduled attack insertion. Ready for direct use with `SecurityGymStream` or `SecurityLogStream-v1`.

| File | Decompressed | Events | Malicious | Campaigns | Duration |
|------|-------------|--------|-----------|-----------|----------|
| `exp_7d_brute_v4.db.zst` | 101 MB | 140,315 | 25,980 (18.5%) | SSH brute force only | 7 days |
| `exp_30d_heavy_v4.db.zst` | 692 MB | 1,103,255 | 609,520 (55.2%) | Mixed, heavy attack rate | 30 days |
| `exp01_90d_v4.db.zst` | 1.4 GB | 1,996,031 | 549,787 (27.5%) | Mixed, moderate rate | 90 days |
| `exp_365d_realistic_v4.db.zst` | 6.6 GB | 9,624,112 | 1,857,178 (19.3%) | Mixed, realistic rate | 365 days |

## Attack Types

| Type | MITRE ATT&CK | Description |
|------|--------------|-------------|
| `brute_force` | T1110 | SSH password brute force (paramiko) |
| `credential_stuffing` | T1110.004 | SSH credential stuffing with unique credential pairs |
| `discovery` | T1046 | SYN port scanning (scapy) |
| `web_exploit` | T1190 | Log4Shell (CVE-2021-44228) JNDI injection |
| `execution` | T1059 | Post-authentication command execution and Redis Lua sandbox escape (CVE-2022-0543) |

## Event Sources

- `auth_log` — SSH authentication, PAM sessions
- `syslog` — system daemon messages
- `web_access` — nginx/apache access logs (Combined Log Format)
- `journal` — systemd journal entries (JSON)
- `ebpf_process` — kernel process exec/exit events
- `ebpf_network` — kernel connect/accept events
- `ebpf_file` — kernel file open/unlink events

## Schema

```sql
CREATE TABLE events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,       -- ISO 8601 UTC
    source        TEXT NOT NULL,       -- event source (see above)
    raw_line      TEXT NOT NULL,       -- original log line or eBPF event text
    parsed        TEXT,                -- JSON parsed fields

    -- Ground truth
    is_malicious  INTEGER,             -- 0=benign, 1=malicious
    campaign_id   TEXT,                -- attack campaign identifier
    attack_type   TEXT,                -- see attack types above
    attack_stage  TEXT,                -- MITRE ATT&CK stage
    severity      INTEGER,             -- 1-5

    -- Session linkage
    session_id    TEXT,
    src_ip        TEXT,
    username      TEXT,
    service       TEXT
);
```

## Quick Start

```python
pip install security-gym

from security_gym import SecurityGymStream

# Stream events from a dataset
stream = SecurityGymStream("exp_7d_brute.db", speed=0)  # full speed
for obs, info in stream:
    print(obs["auth_log"])  # ring-buffered text channels
    print(info["is_malicious"])  # ground truth
```

## Data Provenance

- **Benign traffic**: Collected from personal Linux servers running standard services (SSH, nginx, syslog). Hostnames, domains, and server IPs scrubbed to a single normalized target.
- **Attack traffic**: Scripted campaigns executed against a purpose-built Debian 11 VM with intentionally vulnerable services (OpenSSH, Log4Shell via Docker, Redis CVE-2022-0543). Each campaign is labeled via time-window + source-IP matching.
- **eBPF events**: Collected via BCC tracepoints (execve, connect, accept, openat, unlinkat) on the target VM during attack campaigns.

## Citation

```bibtex
@software{lawson_security_gym_2026,
  author    = {Lawson, Keith},
  title     = {Security-Gym: Gymnasium Environments for Cybersecurity Threat Detection with Continual Learning},
  version   = {0.3.3},
  year      = {2026},
  doi       = {10.5281/zenodo.18901542},
  url       = {https://doi.org/10.5281/zenodo.18901542},
  license   = {Apache-2.0}
}
```

## License

Apache-2.0. See [LICENSE](https://github.com/j-klawson/security-gym/blob/main/LICENSE).
