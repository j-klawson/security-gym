# security-gym

Gymnasium-compatible environment that replays labeled Linux log streams for continual learning research.

See `ROADMAP.md` for project phases and `TODO.md` for current action items.

## Architecture

- `src/security_gym/` — installable package (`pip install -e .`)
- `attacks/` — attack scripts for data generation (NOT pip-installed)
- `campaigns/` — YAML campaign configs for Isildur (ssh_brute_only, log4shell_only, recon_only, recon_ssh_log4shell, credential_stuffing_only, post_auth_only, full_killchain)
- `configs/` — YAML composition configs for StreamComposer (stream_7d_brute_only, stream_30d_heavy, stream_90d_mixed, stream_365d_realistic)
- `server/` — target VM provisioning docs, Docker Compose for vulnerable services, and eBPF collector daemon
- `data/` — runtime data directory (gitignored)
- `tests/` — pytest test suite

## Key Patterns

- **Parsers**: decorator-based registry (`@ParserRegistry.register('auth_log')`); six parsers: `auth_log`, `syslog`, `web_access`, `web_error`, `journal`, `ebpf`. Shared syslog header in `_syslog_header.py` with `parse_syslog_header()` supporting both BSD (`Feb 22 00:55:01`) and RFC 3339 (`2026-02-22T00:55:01.662021-05:00`) timestamp formats; RFC 3339 offsets are converted to UTC. All parsers store `event_type` in `fields["event_type"]` for DB round-trip. EventStore also injects `event_type` into the parsed JSON as a safety net if a parser omits it. The `auth_log` parser is stateful — it caches PID→(src_ip, session_id) from auth events to enrich PAM session open/close events that lack IP/port info.
- **EventStore**: SQLite with WAL mode, ID-based cursor for resumable reads. Schema version 2. Valid sources: `auth_log`, `syslog`, `web_access`, `web_error`, `journal`, `ebpf_process`, `ebpf_network`, `ebpf_file`.
- **Environment (v1)**: `SecurityLogStream-v1` — agent sees raw text streams (like `tail -N` of log files and kernel event channels) and takes defensive actions that causally affect future observations.
  - **Observation**: `Dict` of 6 `Text` channels (`auth_log`, `syslog`, `web_log`, `process_events`, `network_events`, `file_events`) + `Box(3)` system stats. Ring buffer per channel (configurable `tail_lines`, `max_chars`).
  - **Action**: `Dict` of `Discrete(6)` (pass/alert/throttle/block_source/unblock/isolate) + `Box(1)` risk_score (0-10, GVF-like auxiliary prediction).
  - **Reward**: asymmetric action costs (block benign = -1.0, block attacker = +1.0, pass benign = 0.0) + risk score MSE + ongoing consequence feedback from blocked/throttled events.
  - **Defense state**: blocklist (100% drop), throttle list (90% drop), isolation mode (blocks all network events). Agent can escalate/de-escalate: throttle → block → unblock.
  - **Continuous stream**: `terminated=False` always, `truncated=True` at end of data.
- **eBPF Collector**: `server/ebpf_collector.py` — BCC daemon attaching to kernel tracepoints (execve, connect, accept, openat, unlinkat). Deployed on Isildur (Debian 11, kernel 5.10, BCC 0.18). Output: timestamped text lines with enriched fields — process events include `ppid` + `parent_comm` (via `task->real_parent`), network events include `uid`. Self-PID filtering to avoid feedback loops. Orchestration wrapper: `attacks/collection/ebpf_collector.py` (paramiko Ed25519 SSH transport with keepalive).
- **Adapter**: `SecurityGymStream` reads EventStore directly, maintains ring buffers per channel (same as env), yields text observations + ground truth dicts. Supports `speed` (0=full, 1.0=realtime, 10.0=10x) and `loop` (never-ending wrap-around) parameters.
- **StreamComposer**: offline composition of benign + attack EventStore DBs into experiment streams (`data/composer.py`). Handles both log and eBPF events (all use same events table). YAML config specifies duration, seed, Poisson attack schedule (`campaigns_per_day`), and MITRE ATT&CK-weighted type distribution. Cycles benign events to fill duration, transplants attack sessions preserving intra-session timing. Deterministic given seed.
- **Registration**: belt+suspenders — `__init__.py` calls `register_envs()` on import AND `pyproject.toml` entry point for auto-discovery
- **Attack Modules**: decorator-based registry (`@AttackModuleRegistry.register('ssh_brute_force')`); five modules: `recon` (scapy SYN scan), `ssh_brute_force` (paramiko), `log4shell` (requests + JNDI injection), `credential_stuffing` (paramiko, unique cred pairs tried once each), `ssh_post_auth` (paramiko, post-auth command execution with 4 command profiles + optional payload download). Non-stationary `TimingProfile` with constant/accelerating/decelerating/custom profiles. Full kill chain campaign: recon → credential stuffing → post-auth execution.
- **Campaign Framework**: YAML-driven orchestrator — load config → start eBPF collector (if enabled) → execute phases → stop eBPF → SSH collect logs → label (time+IP matching) → bulk insert into EventStore. CLI: `python -m attacks run/validate/list-modules/compose`. eBPF collection configured via `collection.ebpf.enabled: true` in campaign YAML. eBPF events are routed through the same `CampaignLabeler` as log events (time+IP matching), so kernel events during attack windows are correctly labeled malicious.
- **Label Validation**: `scripts/validate_labels.py` — 9 checks (label consistency, raw line spot-checks, campaign boundaries, campaign type cross-val, target array NaN masking, attack type distribution, temporal order, no unlabeled events, session coherence). Supports `--check NAME` to run subset, `--spot-check N`, `--sample-size N`, `--verbose`. Exit 0 = all pass/skip, exit 1 = any FAIL. Distribution check is WARN-only (campaign weights control frequency, not event count — brute_force generates ~40x more events per campaign than discovery).
- **Deprecated (v0)**: Feature extractors (`features/extractors.py`, `features/hasher.py`, `features/session.py`), wrappers (`envs/wrappers.py`), and target builder (`targets/builder.py`) are retained for backwards compatibility but no longer used by the v1 environment. The agent now learns its own representations from raw text.
- **Data Versions**: v1 databases (`benign.db`, `campaigns.db`) contain log events only. v2 databases (`benign_v2.db`, `campaigns_v2.db`) added eBPF kernel events. **v3 database** (`benign_v3.db`) is a clean rebuild from personal server logs (no hospital PII) — built via `scripts/build_benign_v3.py` which accepts any server log tarballs containing auth.log, syslog, nginx, or apache2 logs. Malicious traffic (SSH brute force, scanner probes, SQLi, XSS, JNDI) is automatically filtered; PII (hostnames, domains, IPs) is scrubbed to match the campaign target server (`isildur` / `192.168.2.201`) so all benign + attack data appears to come from one host. Scrubbing is configurable via JSON config (`--scrub-config`) or disabled with `--no-scrub`. Build report at `data/build_benign_report.json`. Composition configs and experiment streams now use `benign_v3.db`.
- **Known Data Quality**: campaigns.db has 87 temporal order violations (multi-server import boundary) and 6 mixed-label sessions (labeler edge cases). campaigns_v2.db has 20 temporal order violations and 3 mixed-label sessions. Composed experiment streams are clean — StreamComposer sorts by timestamp. **benign_v3.db has zero temporal order violations** — the build script sorts all events by timestamp after multi-server merge. Check 2 (raw line spot-checks) fails on eBPF events because the spot-checker can't pattern-match kernel event lines (file opens, accepts, exits) — these are correctly labeled by time+IP window matching. **Note:** Existing v2 databases were generated before the event_type/session-enrichment fixes; re-composing will pick up the fixes for newly parsed data, but already-serialized events in campaigns_v2.db and benign_v2.db retain the old parsed JSON.
- **v3 Experiment Streams** (composed from benign_v3.db + campaigns_v2.db, 2026-03-06): exp_7d_brute.db (140K events, 6 campaigns, 101MB), exp_30d_heavy.db (1.0M events, 284 campaigns, 643MB), exp01_90d.db (1.9M events, 277 campaigns, 1.3GB), exp_365d_realistic.db (9.4M events, 897 campaigns, 6.5GB). All 4 validated: temporal order PASS, label consistency PASS, session coherence PASS. Composition must run sequentially on systems with ≤24GB RAM — parallel compose OOMs because benign_v3.db (4.9GB) is loaded into memory per process.
- **CI/CD**: GitHub Actions — test, lint (ruff), security (pip-audit + bandit) jobs on push/PR to main; publish workflow (OIDC trusted publishing: build → TestPyPI → PyPI) triggered on `v*` tags or manual dispatch
- **PyPI**: Published as `security-gym` on PyPI (v0.3.1). OIDC trusted publishing via GitHub environments (`testpypi`, `pypi`). PEP 561 `py.typed` marker included.

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
python -m attacks import-logs real_logs/server1-var-log.tar --db data/benign.db --host server1  # Import benign logs
python -m attacks list-modules    # Show available attack modules
python -m attacks compose configs/stream_90d_mixed.yaml  # Compose experiment stream
python -m attacks compose configs/stream_90d_mixed.yaml --dry-run  # Preview composition
python scripts/validate_labels.py data/campaigns_v2.db -v         # Validate label accuracy
python scripts/validate_labels.py data/exp01_90d.db --spot-check 20  # Spot-check composed stream
python scripts/collect_ebpf_baseline.py --duration 3600            # Collect benign eBPF baseline
python scripts/insert_ebpf_baseline.py /tmp/ebpf_baseline.log      # Insert manual eBPF baseline
sudo ./scripts/run_all_campaigns.sh                                # Run all 7 campaigns (needs sudo for IP aliasing)
python scripts/build_benign_v3.py --source myserver:/path/to/logs.tar --output data/benign.db  # Build benign dataset from server logs
python scripts/build_benign_v3.py --source web1:web1.tar --source db1:db1.tar --no-scrub --output data/benign.db  # Multiple servers, no PII scrub
python scripts/build_benign_v3.py --source web1:web1.tar --scrub-config my_scrub.json --output data/benign.db --compose  # Custom scrub + re-compose
python -m build                   # Build wheel
```

## Server Infrastructure (Isildur)

- **Host:** Debian 11.11 VM (192.168.2.201) on Frodo hypervisor, frozen (APT disabled, packages held)
- **Docker:** v20.10.5 with docker-compose v1.25 (requires `version: "3"` in compose files, use `docker-compose` not `docker compose`)
- **Services:** Log4Shell (CVE-2021-44228) on :8080 (`ghcr.io/christophetd/log4shell-vulnerable-app`), Nginx 1.21.0 reverse proxy on :80, SSH on :22
- **Users:** `researcher` (adm, systemd-journal groups) for log collection via SSH key `~/.ssh/isildur_research`, password auth enabled for attack modules; `keith` (sudo, docker groups) for administration
- **Log sources:** auth.log, syslog, nginx access/error logs, journalctl, Docker JSON logs
- **eBPF:** BCC 0.18 installed (manual .deb for kernel 5.10). Collector daemon at `server/ebpf_collector.py`. Sudoers rules grant researcher NOPASSWD for collector, pkill, python3.
- **Ground truth:** auditd rules track wget/curl/sh/bash execution with `research_exploit` key; researcher has NOPASSWD sudo for `ausearch`
- **Snapshots:** `ISILDUR_READY_V1` golden state on Frodo; `ISILDUR_READY_V2` after BCC install + eBPF sudoers (see `server/BUILD.md` section 5)

## Sibling Projects

- `chronos-sec` — Cowrie honeypot agent (source of parser/hasher/target patterns)
- `alberta-framework` — JAX learning framework (ScanStream protocol)
