---
id: D9
title: Configurable reward matrix
status: open
affects: [SPEC-ENV 8.7, SPEC-ENV 8, SPEC-BENCH 6]
related: [D10, D11, D6]
---
# D9. Configurable reward matrix

## Context

The twelve action-term constants are hardcoded (`envs/log_stream_env.py:96-112`):

| Action | During attack | During benign |
|---|---:|---:|
| `block_source` | +1.0 | -1.0 |
| `throttle` | +0.75 | -0.5 |
| `alert` | +0.5 | -0.3 |
| `pass` | -0.5 | 0.0 |
| `isolate` | +0.25 | -2.0 |
| `unblock` | -0.5 | 0.0 |

A control benchmark whose baseline ordering is an artifact of these constants will not survive review. Under D11 (decided) the table gains rows for kill process, close port, and disable account.

**Defects found 2026-11-08 that precede any regenerated baseline** (TODO.md, Action Space section; SPEC-ENV ENV-R-130 and ENV-R-150):

1. Reward alignment. `step()` applies the action to the event the agent was shown and then grades the action and risk terms against the next visible event's label (`:904-951`; hybrid `:339-387`). Under the default `"drop"` visibility a first-sight block of an attacker is graded benign in 669 of 1,223 attacker runs (54.7%) in `exp_7d_brute_v4` and 13,643 of 29,583 (46.1%) in `exp_30d_heavy_v4` (census counts, no sampling; TODO.md). Pinned by strict-xfail tests in `tests/test_reward_alignment.py`.
2. Repeated controls are paid in full. Re-blocking or re-throttling an already-controlled address is marked effective (`:682-696`); a policy naming a blocked attacker's pinned slot collects +1.0 every step.

## Options

- Make the twelve values (and the D11 rows) a configuration overlay read at construction, with the default overlay recorded with every result.
- Keep the constants hardcoded.

## Recommendation

The analysis recommended the overlay as a prerequisite of the control benchmark, so that the sensitivity of any baseline ordering to the reward specification can be measured.

## Decision

Open.

## Consequences

D10 depends on it. The alignment and repeated-control fixes change which event and which action receive the values, not the values themselves, so they are independent of the overlay and must land before the baselines are regenerated once.
