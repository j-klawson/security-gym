# security-gym

Gymnasium-compatible environment that replays labeled Linux log streams for continual learning research.

See `ROADMAP.md` for project phases and `TODO.md` for current action items.

## Architecture

- `src/security_gym/` — installable package (`pip install -e .`)
- `attacks/` — attack scripts for data generation (NOT pip-installed)
- `campaigns/` — YAML campaign configs for Isildur (ssh_brute_only, log4shell_only, recon_only, recon_ssh_log4shell, credential_stuffing_only, post_auth_only, full_killchain)
- `configs/` — YAML composition configs for StreamComposer (stream_90d_mixed, stream_7d_brute_only, stream_30d_heavy)
- `server/` — target VM provisioning docs and Docker Compose for vulnerable services
- `data/` — runtime data directory (gitignored)
- `tests/` — pytest test suite

## Key Patterns

- **Parsers**: decorator-based registry (`@ParserRegistry.register('auth_log')`); five parsers: `auth_log`, `syslog`, `web_access`, `web_error`, `journal`. Shared syslog header in `_syslog_header.py` with `parse_syslog_header()` supporting both BSD (`Feb 22 00:55:01`) and RFC 3339 (`2026-02-22T00:55:01.662021-05:00`) timestamp formats; RFC 3339 offsets are converted to UTC. Each parser stores `event_type` in `fields["event_type"]` for DB round-trip.
- **EventStore**: SQLite with WAL mode, ID-based cursor for resumable reads
- **Features**: three modes — `event` (24-dim), `hashed` (configurable), `session` (20-dim with subnet entropy, per-session state tracking)
- **Wrappers**: `HashedFeatureWrapper`, `SessionAggregationWrapper`, `WindowedWrapper`, `DecayingTraceWrapper` — composable gymnasium wrappers in `envs/wrappers.py`
- **Targets**: multi-head arrays (5 heads), compatible with Alberta MultiHeadMLPLearner. NaN used internally by TargetBuilder; info dict uses -1.0 sentinel (`INACTIVE_HEAD`) for gymnasium compatibility.
- **Environment**: continuous stream (terminated=False always, truncated=True at end of data)
- **Adapter**: `SecurityGymStream` reads EventStore directly (bypasses gym overhead), provides `collect_numpy()`/`collect()` for batch learning and `iter_batches()` for constant-memory streaming. JAX optional — `collect_numpy()` always works. Supports `speed` (0=full, 1.0=realtime, 10.0=10x) and `loop` (never-ending wrap-around) parameters for server-speed evaluation mode; batch methods always run single-pass at full speed.
- **StreamComposer**: offline composition of benign + attack EventStore DBs into experiment streams (`data/composer.py`). YAML config specifies duration, seed, Poisson attack schedule (`campaigns_per_day`), and MITRE ATT&CK-weighted type distribution. Cycles benign events to fill duration, transplants attack sessions preserving intra-session timing. Deterministic given seed. CLI: `python -m attacks compose configs/stream_90d_mixed.yaml [--dry-run]`.
- **Registration**: belt+suspenders — `__init__.py` calls `register_envs()` on import AND `pyproject.toml` entry point for auto-discovery
- **Attack Modules**: decorator-based registry (`@AttackModuleRegistry.register('ssh_brute_force')`); five modules: `recon` (scapy SYN scan), `ssh_brute_force` (paramiko), `log4shell` (requests + JNDI injection), `credential_stuffing` (paramiko, unique cred pairs tried once each), `ssh_post_auth` (paramiko, post-auth command execution with 4 command profiles + optional payload download). Non-stationary `TimingProfile` with constant/accelerating/decelerating/custom profiles. Full kill chain campaign: recon → credential stuffing → post-auth execution.
- **Campaign Framework**: YAML-driven orchestrator — load config → execute phases → SSH collect logs → label (time+IP matching) → bulk insert into EventStore. CLI: `python -m attacks run/validate/list-modules/compose`.
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
python -m attacks import-logs real_logs/hopper.tar --db data/campaigns.db --host hopper  # Import benign logs
python -m attacks list-modules    # Show available attack modules
python -m attacks compose configs/stream_90d_mixed.yaml  # Compose experiment stream
python -m attacks compose configs/stream_90d_mixed.yaml --dry-run  # Preview composition
python -m build                   # Build wheel
```

## Server Infrastructure (Isildur)

- **Host:** Debian 11.11 VM (192.168.2.201) on Frodo hypervisor, frozen (APT disabled, packages held)
- **Docker:** v20.10.5 with docker-compose v1.25 (requires `version: "3"` in compose files, use `docker-compose` not `docker compose`)
- **Services:** Log4Shell (CVE-2021-44228) on :8080 (`ghcr.io/christophetd/log4shell-vulnerable-app`), Nginx 1.21.0 reverse proxy on :80, SSH on :22
- **Users:** `researcher` (adm, systemd-journal groups) for log collection via SSH key `~/.ssh/isildur_research`; `keith` (sudo, docker groups) for administration
- **Log sources:** auth.log, syslog, nginx access/error logs, journalctl, Docker JSON logs
- **Ground truth:** auditd rules track wget/curl/sh/bash execution with `research_exploit` key; researcher has NOPASSWD sudo for `ausearch`
- **Snapshot:** `ISILDUR_READY_V1` golden state on Frodo

## Sibling Projects

- `chronos-sec` — Cowrie honeypot agent (source of parser/hasher/target patterns)
- `alberta-framework` — JAX learning framework (ScanStream protocol)
