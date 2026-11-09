---
id: D6
title: Status of the risk_score action component
status: open
affects: [SPEC-ENV 6, SPEC-ENV 8.5]
related: [D9]
---
# D6. Status of the `risk_score` action component

## Context

The action `Dict` has three components since 0.6.0: `action`, `risk_score` (`Box(1)` in [0, 10]), and `target` (`envs/log_stream_env.py:262-268`). `include_risk_reward` defaults to False (`:228`, commit a5ceae9), so `risk_score` carries no reward signal in the default configuration. When enabled, the term is `-risk_weight * (predicted_risk - true_risk)^2` with `risk_weight` 0.1 (`:229`, `:515-516`), and `true_risk` comes from `_RISK_MAP` on `attack_stage` (benign 0, recon 3, initial_access 5, execution 8, persistence 9, exfiltration 10; `:86-93`); the campaign configurations use only recon, initial_access, and execution. The term was disabled because, accruing against every event, it can make observation-suppressing actions rationally dominant (commit a5ceae9). The risk term is also graded on the next visible event rather than the event acted on (`tests/test_reward_alignment.py`; TODO.md, Action Space section).

## Options

- Restore the risk term in the published configuration.
- Remove `risk_score` from the action space.
- Keep it as an opt-in auxiliary prediction task (a GVF-like target), declared outside the control objective.

## Recommendation

The analysis recommended the opt-in auxiliary, kept in the action space but declared not part of the control objective, so the default reward is purely about control.

## Decision

Open.

## Consequences

Blocks the action-space freeze (SPEC-ENV 6) and the statement of the reward specification under which baselines are reported (SPEC-BENCH 8). Whatever is chosen, the risk term must be graded on the event the prediction was made for (SPEC-ENV 8.2).
