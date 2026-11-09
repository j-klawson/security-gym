---
id: D7
title: Defense-state field set and hybrid address encoding
status: open
affects: [SPEC-ENV 5.5, SPEC-ENV 5.7]
related: [D11, D8]
---
# D7. Defense-state field set and hybrid address encoding

## Context

The `defense_state` channel is on by default since 0.6.0 (`DEFAULT_DEFENSE_STATE_OBS = True`, `envs/log_stream_env.py:75`; pinned by `tests/test_env.py:672`). CLAUDE.md and the docstrings at `:144` and `envs/log_stream_env_hybrid.py:78` described it as default-off until they were corrected on 2026-11-09 (SPEC-ENV ENV-R-231). Text mode renders operator-style status (`=== defense state ===`, blocked and throttled lists capped at 20 entries, isolation, `events_suppressed`, `seconds_since_change`, and a `current_src` line; `:737-781`). Hybrid mode encodes `Box(6)` = `[n_blocked, n_throttled, is_isolated, current_src_blocked, current_src_throttled, seconds_since_last_change]` (`:783-800`).

The channel was intended to be label-blind by construction, since every field is a consequence of the agent's own actions. That holds for the hybrid vector but not for the text rendering on the legacy streams: the `current_src` line prints the current event's `src_ip`, which on kernel events exists only when the composer enriched an attack event (SPEC-ENV ENV-R-060; D3 Context).

## Options

- Freeze the six fields as they are.
- Add per-address TTL remaining under `block_ttl`.
- Add an action-history count (controls applied and reverted).
- Add a repeat-offender flag (whether the current source has been blocked before).
- For hybrid: accept that the two membership flags carry the decision-relevant part, or add a hashed blocklist-membership feature over recent addresses.

Each addition widens the published observation contract. Under D11 (decided) the channel must also report the typed-target controls (blocked processes, closed ports, disabled accounts).

## Recommendation

The analysis recommended freezing the six fields plus TTL remaining before the benchmark run.

## Decision

Open.

## Consequences

Blocks the observation-space freeze (SPEC-ENV 5) and the benchmark configuration (SPEC-BENCH 4). The `current_src` line must not render an address whose presence correlates with the label by construction (SPEC-ENV 5.7); on the corrected corpus this holds by construction.
