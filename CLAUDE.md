# security-gym

Gymnasium-compatible environment that replays labeled Linux log streams for continual learning research.

## Architecture

- `src/security_gym/` — installable package (`pip install -e .`)
- `attacks/` — attack scripts for data generation (NOT pip-installed)
- `data/` — runtime data directory (gitignored)
- `tests/` — pytest test suite

## Key Patterns

- **Parsers**: decorator-based registry (`@ParserRegistry.register('auth_log')`)
- **EventStore**: SQLite with WAL mode, ID-based cursor for resumable reads
- **Features**: three modes — `event` (24-dim), `hashed` (configurable), `session` (20-dim, Phase 3)
- **Targets**: multi-head arrays (5 heads), compatible with Alberta MultiHeadMLPLearner. NaN used internally by TargetBuilder; info dict uses -1.0 sentinel (`INACTIVE_HEAD`) for gymnasium compatibility.
- **Environment**: continuous stream (terminated=False always, truncated=True at end of data)
- **Adapter**: `SecurityGymStream` reads EventStore directly (bypasses gym overhead), provides `collect_numpy()`/`collect()` for batch learning and `iter_batches()` for constant-memory streaming. JAX optional — `collect_numpy()` always works.
- **Registration**: belt+suspenders — `__init__.py` calls `register_envs()` on import AND `pyproject.toml` entry point for auto-discovery
- **CI**: GitHub Actions — test, lint (ruff), security (pip-audit + bandit) jobs on push/PR to main

## Commands

```bash
pip install -e ".[dev]"          # Install with dev deps
pytest tests/                     # Run all tests
pytest tests/test_env.py -v       # Run env tests only
ruff check src/ tests/            # Lint
python -m build                   # Build wheel
```

## Implementation Status

- **Phase 1 (Foundation)**: COMPLETE — package skeleton, data layer, auth_log parser, event/hashed feature extractors, target builder, SecurityLogStreamEnv, 58 tests passing, `gymnasium.utils.check_env` passes
- **Phase 2 (Alberta Integration)**: COMPLETE — `SecurityGymStream` adapter (`adapters/scan_stream.py`), GitHub Actions CI (test + lint + security), 86 tests passing
- **Phase 3 (Parsers + Wrappers)**: TODO — syslog, web_access, web_error, journal parsers; session features; HashedFeatureWrapper, SessionAggregationWrapper, WindowedWrapper
- **Phase 4 (Attack Scripts)**: TODO — run_campaign orchestrator, individual attack scripts, collect_logs daemon
- **Phase 5 (Data Collection)**: TODO — deploy Debian server, run campaigns, publish dataset

## Sibling Projects

- `chronos-sec` — Cowrie honeypot agent (source of parser/hasher/target patterns)
- `alberta-framework` — JAX learning framework (ScanStream protocol)
