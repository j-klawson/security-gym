# security-gym

Gymnasium-compatible environment that replays labeled Linux log streams for continual learning research.

## Architecture

- `src/security_gym/` — installable package (`pip install -e .`)
- `attacks/` — attack scripts for data generation (NOT pip-installed)
- `server/` — target VM provisioning docs and Docker Compose for vulnerable services
- `data/` — runtime data directory (gitignored)
- `tests/` — pytest test suite

## Key Patterns

- **Parsers**: decorator-based registry (`@ParserRegistry.register('auth_log')`); five parsers: `auth_log`, `syslog`, `web_access`, `web_error`, `journal`. Shared syslog header in `_syslog_header.py`. Each parser stores `event_type` in `fields["event_type"]` for DB round-trip.
- **EventStore**: SQLite with WAL mode, ID-based cursor for resumable reads
- **Features**: three modes — `event` (24-dim), `hashed` (configurable), `session` (20-dim with subnet entropy, per-session state tracking)
- **Wrappers**: `HashedFeatureWrapper`, `SessionAggregationWrapper`, `WindowedWrapper`, `DecayingTraceWrapper` — composable gymnasium wrappers in `envs/wrappers.py`
- **Targets**: multi-head arrays (5 heads), compatible with Alberta MultiHeadMLPLearner. NaN used internally by TargetBuilder; info dict uses -1.0 sentinel (`INACTIVE_HEAD`) for gymnasium compatibility.
- **Environment**: continuous stream (terminated=False always, truncated=True at end of data)
- **Adapter**: `SecurityGymStream` reads EventStore directly (bypasses gym overhead), provides `collect_numpy()`/`collect()` for batch learning and `iter_batches()` for constant-memory streaming. JAX optional — `collect_numpy()` always works.
- **Registration**: belt+suspenders — `__init__.py` calls `register_envs()` on import AND `pyproject.toml` entry point for auto-discovery
- **Attack Modules**: decorator-based registry (`@AttackModuleRegistry.register('ssh_brute_force')`); three modules: `recon` (scapy SYN scan), `ssh_brute_force` (paramiko), `log4shell` (requests + JNDI injection). Non-stationary `TimingProfile` with constant/accelerating/decelerating/custom profiles.
- **Campaign Framework**: YAML-driven orchestrator — load config → execute phases → SSH collect logs → label (time+IP matching) → bulk insert into EventStore. CLI: `python -m attacks run/validate/list-modules`.
- **CI**: GitHub Actions — test, lint (ruff), security (pip-audit + bandit) jobs on push/PR to main

## Commands

```bash
pip install -e ".[dev]"          # Install with dev deps
pip install -e ".[attacks]"      # Install with attack deps
pytest tests/                     # Run all tests
pytest attacks/tests/             # Run attack framework tests
pytest tests/test_env.py -v       # Run env tests only
ruff check src/ tests/ attacks/   # Lint
python -m attacks validate campaigns/ssh_brute_only.yaml  # Validate campaign
python -m attacks run campaigns/ssh_brute_only.yaml --dry-run  # Preview campaign
python -m attacks list-modules    # Show available attack modules
python -m build                   # Build wheel
```

## Implementation Status

- **Phase 1 (Foundation)**: COMPLETE — package skeleton, data layer, auth_log parser, event/hashed feature extractors, target builder, SecurityLogStreamEnv, 58 tests passing, `gymnasium.utils.check_env` passes
- **Phase 2 (Alberta Integration)**: COMPLETE — `SecurityGymStream` adapter (`adapters/scan_stream.py`), GitHub Actions CI (test + lint + security), 86 tests passing
- **Phase 3 (Parsers + Wrappers)**: COMPLETE — syslog, web_access, web_error, journal parsers; SessionFeatureExtractor (20-dim); HashedFeatureWrapper, SessionAggregationWrapper, WindowedWrapper, DecayingTraceWrapper; enriched env info dict (event_type, src_ip, username); 172 tests passing
- **Phase 4 (Attack Scripts)**: COMPLETE — YAML-driven campaign framework, MITRE ATT&CK-aligned phases, AttackModuleRegistry (recon/ssh_brute_force/log4shell), non-stationary timing profiles, IPManager (spoofed + aliased), LogCollector (SSH/SFTP), CampaignLabeler (time+IP matching), auditd parser, CampaignOrchestrator, CLI (`python -m attacks`), 49 tests passing
- **Phase 5 (Data Collection)**: IN PROGRESS — Isildur VM provisioned (Debian 11 on Frodo hypervisor), Log4Shell + Nginx containers running, auditd ground truth labeling configured. Remaining: run campaigns, publish dataset

## Server Infrastructure (Isildur)

- **Host:** Debian 11.11 VM (192.168.2.201) on Frodo hypervisor, frozen (APT disabled, packages held)
- **Services:** Log4Shell (CVE-2021-44228) on :8080, Nginx 1.21.0 on :80, SSH on :22
- **Log sources:** auth.log, syslog, nginx access/error logs, journalctl, Docker JSON logs
- **Ground truth:** auditd rules track wget/curl/sh/bash execution with `research_exploit` key
- **Snapshot:** `ISILDUR_READY_V1` golden state on Frodo

## Sibling Projects

- `chronos-sec` — Cowrie honeypot agent (source of parser/hasher/target patterns)
- `alberta-framework` — JAX learning framework (ScanStream protocol)
