# Security-Gym Dataset: Labeled Linux Log Streams for Continual Learning

Ground-truth-labeled Linux server log and eBPF kernel event streams for cybersecurity continual learning research. Designed for use with the [security-gym](https://github.com/j-klawson/security-gym) Gymnasium environment.

## Overview

These datasets contain real benign server traffic mixed with scripted attack campaigns executed against a purpose-built vulnerable Linux server. All events are stored in SQLite databases with WAL mode, sorted by timestamp, and labeled with ground truth (benign/malicious, attack type, campaign ID, MITRE ATT&CK stage).

All files are compressed with [Zstandard](https://facebook.github.io/zstd/). Decompress with `zstd -d <file>.zst`.

## Files

### Source Databases

| File | Compressed | Decompressed | Events | Description |
|------|-----------|-------------|--------|-------------|
| `benign_v4.db.zst` | 434 MB | 5.8 GB | 11,159,241 | Real benign server traffic (auth.log, syslog, nginx) + 3.24M eBPF kernel events from 3 servers. PII-scrubbed: server hostnames and IPs normalized to a single target host. |
| `campaigns_v2.db.zst` | 4.2 MB | 41 MB | 60,468 | 10 attack campaigns across 5 attack types with log + eBPF kernel events. |

### Pre-Composed Experiment Streams

Composed from `benign_v4.db` + `campaigns_v2.db` using StreamComposer with Poisson-scheduled attack insertion and 24.2% eBPF downsampling (simulates single busy server). Ready for direct use with `SecurityGymStream` or either observation mode (`SecurityLogStream-Text-v0`, `SecurityLogStream-Hybrid-v0`). eBPF events dominate volume (~93% of events are ebpf_file/process/network).

| File | Compressed | Decompressed | Events | Malicious | Campaigns | Duration |
|------|-----------|-------------|--------|-----------|-----------|----------|
| `exp_7d_brute_v4.db.zst` | 8.5 MB | 1.9 GB | 4,891,541 | 25,980 | SSH brute force only | 7 days |
| `exp_30d_heavy_v4.db.zst` | 64 MB | 8.5 GB | 21,511,208 | 609,520 | Mixed, heavy attack rate | 30 days |
| `exp01_90d_v4.db.zst` | 116 MB | 25 GB | 63,212,997 | 549,787 | Mixed, moderate rate | 90 days |
| `exp_365d_realistic_v4.db.zst` | 12.7 GB | 101 GB | 257,654,256 | 1,857,178 | Mixed, realistic rate | 365 days |

## Attack Types

| Type | MITRE ATT&CK | Description |
|------|--------------|-------------|
| `brute_force` | T1110.001 | SSH password brute force (paramiko) |
| `credential_stuffing` | T1110.004 | SSH credential stuffing with unique credential pairs |
| `discovery` | T1046 | SYN port scanning (scapy) |
| `web_exploit` | T1190 | Log4Shell (CVE-2021-44228) JNDI injection; Redis Lua sandbox escape (CVE-2022-0543) |
| `execution` | T1059.004 | Post-authentication Unix shell command execution |

## Event Sources

- `auth_log` — SSH authentication, PAM sessions
- `syslog` — system daemon messages
- `web_access` — nginx/apache access logs (Combined Log Format)
- `web_error` — nginx/apache error logs
- `journal` — systemd journal entries (JSON)
- `ebpf_process` — kernel process exec/exit events (includes ppid + parent_comm)
- `ebpf_network` — kernel connect/accept events (includes uid)
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

```bash
pip install security-gym
```

```python
from security_gym import SecurityGymStream

# Stream events from a dataset
stream = SecurityGymStream("exp_7d_brute_v4.db", speed=0)  # full speed
for obs, info in stream:
    print(obs["auth_log"])  # ring-buffered text channels
    print(info["is_malicious"])  # ground truth
```

## Baselines

Evaluated on `exp_30d_heavy_v4.db` (1M steps, all 5 attack types):

| Agent | Precision | Recall | F1 | Mean Reward |
|-------|----------:|-------:|---:|------------:|
| pass-only | 0.000 | 0.000 | 0.000 | -0.073 |
| random | 0.003 | 0.665 | 0.005 | -3.985 |
| threshold(5) | 1.000 | 0.005 | 0.011 | -0.084 |
| keyword | 0.987 | 0.013 | 0.025 | -0.073 |
| rlsecd (MLP) | 0.979 | 0.979 | 0.979 | — |

See `examples/` in the [source repository](https://github.com/j-klawson/security-gym) for runnable baseline agents.

## Labeling Methodology

### Attack labeling (campaigns_v2.db)

Each attack campaign is executed against the target VM by the campaign orchestrator, which records the start time, end time, and source IPs for every attack phase. The `CampaignLabeler` then labels collected events using **time-window + source-IP matching**:

1. An event is labeled **malicious** if its timestamp falls within a phase's time window AND its `src_ip` matches one of that phase's attacker IPs.
2. Events with no `src_ip` (e.g., syslog daemon messages during an attack window) match on time window alone.
3. eBPF kernel events use the identical labeler — there is no separate labeling path for kernel telemetry.

Malicious events receive five ground truth fields: `is_malicious=1`, `campaign_id`, `attack_type`, `attack_stage`, and `severity` (1-5). Benign events have `is_malicious=0` with the remaining fields NULL.

### Benign data filtering (benign_v4.db)

Real server logs are filtered to remove attack traffic before inclusion as benign data. The `MaliciousFilter` applies:

- **Web rules** (auth.log, web_access, web_error): path traversal, SQL injection, XSS, JNDI injection, shell access, RFI, known exploit paths, scanner user-agents, suspicious HTTP methods
- **Auth rules** (auth_log): failed passwords, invalid users, authentication failures, preauth disconnects, max auth attempts exceeded
- **IP tracking**: source IPs from filtered events are accumulated and used to filter eBPF network events from the same IPs during eBPF carryover

Syslog and eBPF process/file events pass through unfiltered — they contain no attacker-identifiable content in benign baseline collections.

### PII scrubbing

All benign data is scrubbed before release: server hostnames, domain names, and IP addresses are normalized to a single target host (`isildur` / `192.168.2.201`) so all benign and attack data appears to originate from one server. Scrubbing is case-insensitive and applied across all event sources.

### Validation

The `validate_labels.py` script runs 9 automated checks:

| # | Check | Description |
|---|-------|-------------|
| 1 | Label consistency | `is_malicious=1` requires non-NULL attack_type/stage/severity; `is_malicious=0` requires NULL |
| 2 | Raw line spot-checks | Regex patterns per attack_type against sampled malicious events |
| 3 | Campaign boundaries | All malicious events fall within their campaign's start/end times |
| 4 | Campaign type cross-validation | Event attack_type matches campaign's declared type |
| 5 | Target array consistency | SecurityGymStream round-trip: NaN masking, array shape |
| 6 | Attack type distribution | Actual proportions vs composition config weights (WARN-only) |
| 7 | Temporal order | Events sorted by timestamp (monotonically non-decreasing by id) |
| 8 | No unlabeled events | `is_malicious` is never NULL |
| 9 | Session coherence | All events in a session share the same `is_malicious` label |

### Known data quality

- **campaigns_v2.db**: 24 temporal order violations (multi-server import boundary) and 3 mixed-label sessions (labeler edge cases at phase boundaries). These are in the source campaigns only — composed experiment streams are clean because StreamComposer re-sorts by timestamp.
- **benign_v3.db / benign_v4.db**: Zero temporal order violations (build script sorts after multi-server merge).
- **Check 2 limitation**: Raw line spot-checks cannot pattern-match eBPF kernel event lines (file opens, process exits). These events are correctly labeled by time+IP matching but fail the regex-based spot-check.

## Data Provenance

- **Benign traffic**: Collected from 4 personal Linux servers (can, dallas, isildur, sak) running standard services (SSH, nginx, syslog). 7,915,858 log events. Hostnames, domains, and server IPs scrubbed to a single normalized target.
- **Benign eBPF**: 24-hour baseline collections from 3 Debian 13 servers (frodo: 2,355,832 events; 9600baud: 785,473; hopper: 102,078). 3,243,383 total kernel events.
- **Attack traffic**: 10 scripted campaigns executed against a purpose-built Debian 11 VM (Isildur) with intentionally vulnerable services (OpenSSH, Log4Shell via Docker, Redis CVE-2022-0543). 60,468 events (30,436 malicious) labeled via time-window + source-IP matching.
- **eBPF kernel events**: Collected via BCC tracepoints (`sys_enter_execve`, `sched_process_exit`, `sys_enter_connect`, `sys_enter_accept4`, `sys_enter_openat`, `sys_enter_unlinkat`) on the target VM during both benign baseline collection and attack campaigns.

## Citation

The dataset has a Zenodo **concept DOI** ([10.5281/zenodo.18901627](https://doi.org/10.5281/zenodo.18901627)) that always resolves to the latest version, and per-version DOIs for reproducibility (v3: [10.5281/zenodo.18901542](https://doi.org/10.5281/zenodo.18901542); v4: [10.5281/zenodo.19482383](https://doi.org/10.5281/zenodo.19482383)). Cite the version-specific DOI in papers.

```bibtex
@dataset{lawson_security_gym_dataset_2026,
  author    = {Lawson, Keith},
  title     = {Security-Gym Dataset: Labeled Linux Log and eBPF
               Streams for Continual Learning Research},
  version   = {4.0},
  year      = {2026},
  doi       = {10.5281/zenodo.19482383},
  url       = {https://doi.org/10.5281/zenodo.19482383},
  license   = {Apache-2.0}
}

@software{lawson_security_gym_2026,
  author    = {Lawson, Keith},
  title     = {Security-Gym: Gymnasium Environments for Cybersecurity
               Threat Detection with Continual Learning},
  version   = {0.3.12},
  year      = {2026},
  doi       = {10.5281/zenodo.18810298},
  url       = {https://github.com/j-klawson/security-gym},
  license   = {Apache-2.0}
}
```

## License

Apache-2.0. See [LICENSE](https://github.com/j-klawson/security-gym/blob/main/LICENSE).
