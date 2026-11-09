---
id: D4
title: The system_stats channel
status: open
affects: [SPEC-ENV 5.4]
related: [D7]
---
# D4. The `system_stats` channel

## Context

`system_stats` returns the constant `[0.5, 0.3, 0.2]` on every step (`envs/log_stream_env.py:451`; hybrid `envs/log_stream_env_hybrid.py:254`) and zeros on the exhaustion observation (`:463`). It carries no information and is the only non-event channel. No benign or attack database carries load, memory, or disk series (no such source in `event_store.VALID_SOURCES`, `data/event_store.py:15-18`).

## Options

- **(a) Populate it from the replayed host.** Requires a new capture source; under the 2026-11-09 capture architecture the recorder could sample host load, memory, and disk on the reference target, and the series would have to be generated symmetrically for both classes.
- **(b) Remove it** before the observation space is frozen.

## Recommendation

The analysis recommended removal unless a real series is captured, since a constant channel adds width for no signal and is a liability under the label-blindness principle.

## Decision

Open.

## Consequences

Blocks the freeze of the observation space (SPEC-ENV 5) and therefore the benchmark configuration (SPEC-BENCH 4). If (a) is chosen, the recorder specification (SPEC-CORPUS 5) gains a host-metrics source.
