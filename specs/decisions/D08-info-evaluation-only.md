---
id: D8
title: Declaring info evaluation-only
status: open
affects: [SPEC-ENV 10]
related: [D7, D13]
---
# D8. Declaring `info` evaluation-only

## Context

`info` carries, per step (`envs/log_stream_env.py:802-826`): `event_id`, `timestamp`, `dt_seconds`, `source`, `src_ip`, a `ground_truth` sub-dict (`is_malicious`, `attack_type`, `attack_stage`, `campaign_id`, `true_risk`), the defense-state fields (`blocked_ips`, `throttled_ips`, `is_isolated`, `events_dropped`), and three action-attribution fields (`action_target`, `action_target_explicit`, `action_effective`) that an evaluation harness needs to attribute containment. On exhaustion `ground_truth` is a synthetic benign dict (`:918-923`); a `reset` on an empty store returns `{"exhausted": True}` (`:887`). `info` therefore mixes ground truth with fields an agent might legitimately consume. With defense state available as an observation channel, the reason for an agent to read `info` is gone.

## Options

- Declare `info` evaluation-only; any field intended for the agent is mirrored into an observation channel.
- Leave `info` undeclared (status quo).

## Recommendation

The analysis recommended declaring `info` evaluation-only and mirroring any agent-usable field into an observation channel.

## Decision

Open.

## Consequences

If adopted, the protocol (SPEC-BENCH 6) forbids policies from reading `info`, and any instance identifier adopted under D13 reaches the evaluator through `info` only.
